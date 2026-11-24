'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { scoreReportFindings } = require('./scoring');
const { finding, check } = require('./finding');
const { collectSecurity } = require('./security');
const { ps, psChecked, run, isAdmin, POWER_PLANS, parseTcpLevel } = require('./commands');

const APP_VERSION = require('../package.json').version;

function hash(value) {
  return crypto.createHash('sha1').update(String(value)).digest('hex').slice(0, 10);
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 Б';
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / Math.pow(1024, index);
  const rendered = Number.isInteger(value) ? String(value) : value.toFixed(1);
  return `${rendered} ${units[index]}`;
}

function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return { text: `${days} д ${hours} ч ${minutes} мин`, seconds };
}

async function parseJsonPs(script, label, fallback) {
  try {
    const raw = await psChecked(script, label, 25000);
    return JSON.parse(raw);
  } catch (error) {
    return fallback;
  }
}

function safeLastLine(value) {
  const lines = String(value || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  return lines.length ? lines[lines.length - 1] : '';
}

function scanDirectory(root, cutoff = 0) {
  let bytes = 0;
  let files = 0;
  let matchedFiles = 0;
  let oldest = 0;
  let errors = 0;

  function visit(dir, depth) {
    if (depth > 12) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      errors += 1;
      return;
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      try {
        if (entry.isDirectory()) {
          visit(full, depth + 1);
        } else if (entry.isFile()) {
          const stat = fs.lstatSync(full);
          files += 1;
          if (stat.mtimeMs < oldest || oldest === 0) oldest = stat.mtimeMs;
          if (stat.mtimeMs < cutoff) {
            bytes += stat.size;
            matchedFiles += 1;
          }
        }
      } catch (error) {
        errors += 1;
      }
    }
  }

  visit(root, 0);
  return { bytes, files, matchedFiles, oldest, errors };
}

async function collectSystemInfo() {
  const [gpuRaw, diskRaw, ramRaw, osRaw, tempRaw, bootRaw] = await Promise.all([
    psChecked("Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name | Select-Object -First 1", 'GPU', 12000).catch(() => ''),
    psChecked('Get-CimInstance Win32_DiskDrive | Select-Object -ExpandProperty Model | Select-Object -First 1', 'Disk model', 12000).catch(() => ''),
    psChecked('Get-CimInstance Win32_PhysicalMemory | Select-Object -ExpandProperty Speed | Select-Object -First 1', 'RAM speed', 12000).catch(() => ''),
    psChecked('Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption', 'OS caption', 12000).catch(() => ''),
    psChecked('Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature | Select-Object -ExpandProperty CurrentTemperature | Select-Object -First 1', 'Temperature', 12000).catch(() => ''),
    psChecked(`
      $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational'; Id=100} -MaxEvents 10 -ErrorAction SilentlyContinue
      foreach ($event in $events) {
        [pscustomobject]@{
          time = $event.TimeCreated.ToString('o')
          values = @($event.Properties | ForEach-Object { $_.Value }) | Where-Object { $_ -is [int] -or $_ -is [long] } | Select-Object -First 12
        }
      } | ConvertTo-Json -Compress -Depth 5
    `, 'Boot events', 15000).catch(() => '[]'),
  ]);

  let disk = { total: 0, used: 0, free: 0, freePercent: 0 };
  try {
    const stat = fs.statfsSync('C:\\');
    disk.total = Math.round((stat.blocks * stat.bsize) / 1024 ** 3);
    disk.free = Math.round((stat.bavail * stat.bsize) / 1024 ** 3);
    disk.used = disk.total - disk.free;
    disk.freePercent = disk.total > 0 ? Math.round((disk.free / disk.total) * 100) : 0;
  } catch (error) {
    disk = { total: 0, used: 0, free: 0, freePercent: 0, error: error.message };
  }

  const cpu = os.cpus();
  const ramSpeed = parseInt(ramRaw, 10);
  const temperatureRaw = parseInt(tempRaw, 10);
  const uptime = formatUptime(os.uptime());

  let bootSeconds = null;
  try {
    const events = JSON.parse(bootRaw || '[]');
    const list = Array.isArray(events) ? events : [events];
    const values = [];
    for (const event of list) {
      for (const value of event.values || []) {
        const number = Number(value);
        if (Number.isFinite(number) && number > 5000 && number < 900000) values.push(number / 1000);
      }
    }
    if (values.length) bootSeconds = Math.round(values.reduce((a, b) => a + b, 0) / values.length);
  } catch (error) {
    bootSeconds = null;
  }

  return {
    cpu: cpu[0]?.model || 'Неизвестно',
    cpuCores: cpu.length,
    ramTotalGb: Math.round(os.totalmem() / 1024 ** 3),
    ramUsedGb: Math.round(((os.totalmem() - os.freemem()) / 1024 ** 3) * 10) / 10,
    ramUsedPercent: Math.round(((os.totalmem() - os.freemem()) / os.totalmem()) * 100),
    ram: ramSpeed ? `${ramSpeed >= 4800 ? 'DDR5' : 'DDR4'} ${ramSpeed} MHz` : '—',
    gpu: safeLastLine(gpuRaw) || 'Неизвестно',
    diskModel: safeLastLine(diskRaw) || 'Неизвестно',
    os: safeLastLine(osRaw) || `${os.type()} ${os.release()}`,
    osRelease: os.release(),
    arch: os.arch(),
    hostname: os.hostname(),
    disk,
    temperatureC: Number.isFinite(temperatureRaw) ? Math.round(temperatureRaw / 10 - 273.15) : null,
    uptime,
    bootSeconds,
    isAdmin: isAdmin(),
    appVersion: APP_VERSION,
  };
}

async function collectStartup() {
  const script = `
    $items = @()
    $paths = @(
      'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
    )
    foreach ($p in $paths) {
      if (-not (Test-Path -LiteralPath $p)) { continue }
      $key = Get-Item -LiteralPath $p
      foreach ($name in $key.GetValueNames()) {
        $command = [string]$key.GetValue($name)
        $exe = $command -replace '^"([^"]+)".*$', '$1'
        $exe = ($exe -split ' -', 2)[0]
        $exe = ($exe -split ' /', 2)[0]
        $exe = $exe.Trim('"', ' ')
        $signer = ''
        $status = 'missing'
        $publisher = ''
        if ($exe -and (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue)) {
          try {
            $sig = Get-AuthenticodeSignature -FilePath $exe -ErrorAction Stop
            $status = $sig.Status.ToString()
            if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
            $publisher = (Get-Item -LiteralPath $exe).VersionInfo.CompanyName
          } catch { }
        }
        $items += [pscustomobject]@{
          source = 'registry'
          hive = ($p -split '\\\\')[0]
          path = $p
          name = $name
          command = $command
          location = $p
          signer = $signer
          publisher = $publisher
          signature = $status
        }
      }
    }
    $folder = [Environment]::GetFolderPath('Startup')
    if (Test-Path -LiteralPath $folder) {
      Get-ChildItem -LiteralPath $folder -File | ForEach-Object {
        $exe = $_.FullName
        $signer = ''
        $status = 'missing'
        $publisher = ''
        try {
          $target = (New-Object -ComObject WScript.Shell).CreateShortcut($exe).TargetPath
          if ($target -and (Test-Path -LiteralPath $target)) {
            $exe = $target
            $sig = Get-AuthenticodeSignature -FilePath $exe -ErrorAction SilentlyContinue
            if ($sig) { $status = $sig.Status.ToString() }
            if ($sig -and $sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
            $publisher = (Get-Item -LiteralPath $exe).VersionInfo.CompanyName
          }
        } catch { }
        $items += [pscustomobject]@{
          source = 'folder'
          hive = 'HKCU'
          path = $_.FullName
          name = $_.BaseName
          command = $exe
          location = $folder
          signer = $signer
          publisher = $publisher
          signature = $status
        }
      }
    }
    $items | ConvertTo-Json -Compress -Depth 5
  `;

  const items = await parseJsonPs(script, 'Автозагрузка', []);
  const list = Array.isArray(items) ? items : items ? [items] : [];
  const findings = [];
  const protectedPattern = /(defender| antivirus|antivirus|kaspersky|avast|avg|norton|mcafee|eset|bitdefender|security|firewall|driver|updat)/i;

  let thirdParty = 0;
  let unsigned = 0;

  for (const item of list) {
    const publisher = String(item.publisher || item.signer || '');
    const isMicrosoft = /microsoft/i.test(publisher) || /\\Windows\\/i.test(String(item.command || ''));
    if (!isMicrosoft) thirdParty += 1;
    if (item.signature && !/valid/i.test(item.signature) && item.signature !== 'missing') unsigned += 1;
    if (isMicrosoft || protectedPattern.test(`${item.name} ${publisher} ${item.command}`)) continue;

    findings.push(
      finding({
        id: `startup-${hash(`${item.path}|${item.name}`)}`,
        category: 'startup',
        title: `Автозагрузка: ${item.name}`,
        summary: `При входе в систему запускается ${item.name}${publisher ? ` (${publisher})` : ''}.`,
        details: [
          'Каждая запись автозагрузки увеличивает работу системы при входе.',
          'Отключение сохраняет исходное значение и может быть отменено одной кнопкой.',
          'Проверьте название: если программа нужна, оставьте её включённой.',
        ],
        evidence: [
          `Команда: ${item.command || '—'}`,
          `Издатель: ${publisher || 'не определён'}`,
          `Подпись: ${item.signature || 'не проверена'}`,
          `Расположение: ${item.location}`,
        ],
        severity: /valid/i.test(item.signature) ? 'low' : 'medium',
        risk: 'low',
        reversible: true,
        recommended: true,
        presets: ['balanced', 'performance', 'gaming'],
        action: {
          commandId: 'disable-startup',
          params: {
            source: item.source,
            hive: item.hive,
            path: item.path,
            name: item.name,
          },
          requiresAdmin: item.hive === 'HKLM',
        },
      }),
    );
  }

  return {
    metrics: { startupTotal: list.length, startupThirdParty: thirdParty, startupUnsigned: unsigned },
    autorun: list,
    findings,
    checks: [
      check({
        id: 'startup',
        category: 'startup',
        title: 'Автозагрузка',
        status: findings.length ? 'issue' : 'ok',
        summary: 'Проверены записи автозагрузки в реестре и папке Startup.',
        result: `Всего записей: ${list.length}; сторонних: ${thirdParty}; без действительной подписи: ${unsigned}; предложено отключить: ${findings.length}.`,
        evidence: ['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKLM\\...\\Run', 'Папка автозагрузки пользователя'],
      }),
    ],
  };
}

async function collectStorage(system) {
  const now = Date.now();
  const tempRoot = process.env.TEMP || path.join(process.env.USERPROFILE || 'C:\\', 'AppData', 'Local', 'Temp');
  const tempAll = fs.existsSync(tempRoot) ? scanDirectory(tempRoot, Number.POSITIVE_INFINITY) : { bytes: 0, files: 0, matchedFiles: 0, oldest: 0, errors: 1 };
  const tempOld = fs.existsSync(tempRoot) ? scanDirectory(tempRoot, now - 7 * 86400000) : { bytes: 0, files: 0, matchedFiles: 0, oldest: 0, errors: 0 };
  const updateRoot = 'C:\\Windows\\SoftwareDistribution\\Download';
  const updateOld = fs.existsSync(updateRoot) ? scanDirectory(updateRoot, now - 30 * 86400000) : { bytes: 0, files: 0, matchedFiles: 0, oldest: 0, errors: 0 };

  const [mediaRaw, trimRaw, fragRaw] = await Promise.all([
    psChecked('Get-PhysicalDisk | Select-Object -ExpandProperty MediaType', 'Disk type', 15000).catch(() => ''),
    run('fsutil.exe', ['behavior', 'query', 'DisableDeleteNotify'], 10000),
    psChecked('$out = Optimize-Volume -DriveLetter C -Analyze -Verbose 4>&1 | Out-String; $out', 'Fragmentation', 90000).catch(() => ''),
  ]);

  const mediaLines = String(mediaRaw || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const mediaType = mediaLines.find((line) => !/unspecified/i.test(line)) || mediaLines[0] || 'Unknown';
  const trimDisabled = /DisableDeleteNotify\s*=\s*1/i.test(trimRaw.stdout || '');
  const trimEnabled = /DisableDeleteNotify\s*=\s*0/i.test(trimRaw.stdout || '');
  const fragmentationMatch = (fragRaw || '').match(/(\d+)\s*%/);
  const fragmentation = fragmentationMatch ? Number(fragmentationMatch[1]) : null;
  const findings = [];

  if (tempOld.bytes > 100 * 1024 ** 2) {
    findings.push(
      finding({
        id: 'storage-temp',
        category: 'storage',
        title: 'Старые временные файлы',
        summary: `Во временных папках накопилось ${formatBytes(tempOld.bytes)} файлов старше 7 дней.`,
        details: [
          'SteadyPC удалит только файлы старше выбранного возраста.',
          'Файлы, используемые программами, будут пропущены.',
          'Операция не обратима: убедитесь, что вам не нужны старые временные файлы.',
        ],
        evidence: [
          `Всего файлов: ${tempAll.files.toLocaleString('ru-RU')}`,
          `Старше 7 дней: ${tempOld.matchedFiles.toLocaleString('ru-RU')} на ${formatBytes(tempOld.bytes)}`,
          `Папка: ${tempRoot}`,
        ],
        severity: tempOld.bytes > 1024 ** 3 ? 'medium' : 'low',
        risk: 'low',
        reversible: false,
        recommended: true,
        presets: ['balanced', 'performance', 'gaming', 'saver'],
        action: {
          commandId: 'clean-temp',
          params: { maxAgeDays: 7 },
          requiresAdmin: false,
        },
      }),
    );
  }

  if (updateOld.bytes > 500 * 1024 ** 2) {
    findings.push(
      finding({
        id: 'storage-update-cache',
        category: 'storage',
        title: 'Старый кэш обновлений Windows',
        summary: `В кэше Windows Update найдено ${formatBytes(updateOld.bytes)} файлов старше 30 дней.`,
        details: [
          'Кэш используется для повторной установки обновлений.',
          'Удаление старых файлов освобождает место, но может замедлить повторную установку обновления.',
          'Для большинства пользователей операция безопасна, но нет необходимости делать её по умолчанию.',
        ],
        evidence: [`Папка: ${updateRoot}`, `Файлов старше 30 дней: ${updateOld.matchedFiles.toLocaleString('ru-RU')}`],
        severity: 'low',
        risk: 'medium',
        reversible: false,
        recommended: false,
        presets: ['advanced'],
        action: {
          commandId: 'clear-update-cache',
          params: { maxAgeDays: 30 },
          requiresAdmin: true,
        },
      }),
    );
  }

  if (/ssd/i.test(mediaType) && trimDisabled) {
    findings.push(
      finding({
        id: 'disk-trim-disabled',
        category: 'disk',
        title: 'TRIM для SSD отключён',
        summary: 'На SSD отключена команда TRIM. Это снижает эффективность удаления данных с течением времени.',
        details: [
          'TRIM помогает SSD поддерживать скорость записи.',
          'SteadyPC выполнит однократную оптимизацию тома без дефрагментации.',
          'Статус в системе останется прежним: изменение влияет на саму операцию, а не на глобальный параметр.',
        ],
        evidence: [`Тип диска: ${mediaType}`, `DisableDeleteNotify: 1`],
        severity: 'medium',
        risk: 'low',
        reversible: false,
        recommended: true,
        presets: ['balanced', 'performance', 'gaming'],
        action: { commandId: 'trim-ssd', params: { drive: 'C' }, requiresAdmin: true },
      }),
    );
  }

  if (/hdd/i.test(mediaType) && fragmentation !== null && fragmentation >= 10) {
    findings.push(
      finding({
        id: 'disk-fragmentation',
        category: 'disk',
        title: `Фрагментация диска C: ${fragmentation}%`,
        summary: 'На жёстком диске обнаружен высокий уровень фрагментации.',
        details: [
          'Дефрагментация может улучшить последовательное чтение на HDD.',
          'На SSD эта операция не выполняется.',
          'Во время работы диск будет занят, лучше не прерывать процесс.',
        ],
        evidence: [`Тип диска: ${mediaType}`, `Фрагментация: ${fragmentation}%`],
        severity: fragmentation >= 20 ? 'medium' : 'low',
        risk: 'low',
        reversible: false,
        recommended: true,
        presets: ['balanced', 'performance'],
        action: { commandId: 'defrag-hdd', params: { drive: 'C' }, requiresAdmin: true },
      }),
    );
  }

  if (system.disk.total > 0 && system.disk.freePercent < 15) {
    findings.push(
      finding({
        id: 'storage-low-space',
        category: 'storage',
        title: 'Мало свободного места на диске C:',
        summary: `Свободно ${system.disk.freePercent}% диска (${formatBytes(system.disk.free * 1024 ** 3)}).`,
        details: [
          'Нехватка места замедляет работу системы и может мешать обновлениям.',
          'SteadyPC предложит безопасную очистку временных файлов выше.',
          'Очистка личных файлов и программ выполняется вручную.',
        ],
        evidence: [`Всего: ${system.disk.total} ГБ`, `Свободно: ${system.disk.free} ГБ`],
        severity: 'high',
        risk: 'low',
        reversible: false,
        recommended: false,
        presets: [],
      }),
    );
  }

  return {
    metrics: {
      tempBytes: tempAll.bytes,
      tempOldBytes: tempOld.bytes,
      tempFiles: tempAll.files,
      tempOldFiles: tempOld.matchedFiles,
      updateCacheOldBytes: updateOld.bytes,
      diskType: mediaType,
      trimEnabled: trimEnabled && !trimDisabled,
      fragmentation,
    },
    findings,
    checks: [
      check({
        id: 'storage-temp',
        category: 'storage',
        title: 'Временные файлы',
        status: tempOld.bytes > 100 * 1024 ** 2 ? 'issue' : 'ok',
        summary: 'Проверены файлы старше 7 дней во временных папках.',
        result: `Всего файлов: ${tempAll.files.toLocaleString('ru-RU')} (${formatBytes(tempAll.bytes)}); старше 7 дней: ${tempOld.matchedFiles.toLocaleString('ru-RU')} (${formatBytes(tempOld.bytes)}); порог: 100 МБ.`,
        evidence: [`Папка: ${tempRoot}`, `Ошибок чтения: ${tempAll.errors}`],
      }),
      check({
        id: 'storage-update-cache',
        category: 'storage',
        title: 'Кэш обновлений Windows',
        status: updateOld.bytes > 500 * 1024 ** 2 ? 'issue' : 'ok',
        summary: 'Проверены файлы кэша Windows Update старше 30 дней.',
        result: `Найдено ${formatBytes(updateOld.bytes)} в ${updateOld.matchedFiles.toLocaleString('ru-RU')} файлах старше 30 дней; порог: 500 МБ.`,
        evidence: [`Папка: ${updateRoot}`],
      }),
      check({
        id: 'disk-trim',
        category: 'disk',
        title: 'TRIM на SSD',
        status: /ssd/i.test(mediaType) && trimDisabled ? 'issue' : 'ok',
        summary: 'Проверено состояние команды TRIM для SSD.',
        result: `Тип диска: ${mediaType}; DisableDeleteNotify: ${trimDisabled ? '1 (отключён)' : trimEnabled ? '0 (включён)' : 'не определён'}.`,
        evidence: ['fsutil behavior query DisableDeleteNotify'],
      }),
      check({
        id: 'disk-fragmentation',
        category: 'disk',
        title: 'Фрагментация диска C:',
        status: /hdd/i.test(mediaType) && fragmentation !== null && fragmentation >= 10 ? 'issue' : 'ok',
        summary: 'Проверен уровень фрагментации. Дефрагментация предлагается только для HDD.',
        result: `Тип диска: ${mediaType}; фрагментация: ${fragmentation === null ? 'не определена' : `${fragmentation}%`}; порог: 10%.`,
        evidence: ['Optimize-Volume -DriveLetter C -Analyze'],
      }),
      check({
        id: 'storage-free-space',
        category: 'storage',
        title: 'Свободное место на диске C:',
        status: system.disk.total > 0 && system.disk.freePercent < 15 ? 'issue' : 'ok',
        summary: 'Проверён запас свободного места на системном диске.',
        result: `Свободно ${system.disk.freePercent}% (${system.disk.free} ГБ из ${system.disk.total} ГБ); порог: 15%.`,
        evidence: ['C:\\'],
      }),
    ],
  };
}

async function collectPower() {
  const activeRaw = (await run('powercfg.exe', ['/getactivescheme'], 10000)).stdout || '';
  const guid = (activeRaw.match(/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i) || [])[1] || '';
  const listRaw = (await run('powercfg.exe', ['/list'], 10000)).stdout || '';
  const names = new Map();
  for (const line of listRaw.split(/\r?\n/)) {
    const match = line.match(/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s+\*\s+(.+)/i);
    if (match) names.set(match[1].toLowerCase(), match[2].trim());
  }

  const planKey = Object.keys(POWER_PLANS).find((key) => POWER_PLANS[key].toLowerCase() === guid.toLowerCase()) || 'unknown';
  const planName = names.get(guid.toLowerCase()) || planKey;
  const hasBattery = /yes|true/i.test(await psChecked('if (Get-CimInstance Win32_Battery) { "yes" } else { "no" }', 'Battery', 10000).catch(() => 'no'));
  const findings = [];

  if (planKey === 'saver') {
    findings.push(
      finding({
        id: 'power-saver-limits-cpu',
        category: 'power',
        title: 'План питания ограничивает производительность',
        summary: `Сейчас активен план «${planName}». Он может ограничивать частоту процессора.`,
        details: [
          'Переход на сбалансированный план снимает искусственные ограничения частоты.',
          'Компромисс: возрастёт энергопотребление и нагрев.',
          'На ноутбуке это сократит время работы от батареи.',
        ],
        evidence: [`Текущий GUID: ${guid || 'не определён'}`, `План: ${planName}`],
        severity: 'medium',
        risk: 'medium',
        reversible: true,
        recommended: true,
        presets: ['balanced', 'performance', 'gaming'],
        action: { commandId: 'set-power-plan', params: { plan: 'balanced' }, requiresAdmin: true },
      }),
    );
  }

  if (planKey === 'high' && hasBattery) {
    findings.push(
      finding({
        id: 'power-high-on-battery',
        category: 'power',
        title: 'Максимальная производительность на ноутбуке',
        summary: 'На устройстве с батареей активен план максимальной производительности.',
        details: [
          'Такой план увеличивает расход энергии и нагрев.',
          'Сбалансированный план обычно даёт близкую производительность в повседневных задачах.',
        ],
        evidence: [`План: ${planName}`, 'Батарея обнаружена'],
        severity: 'low',
        risk: 'low',
        reversible: true,
        recommended: false,
        presets: ['saver', 'balanced'],
        action: { commandId: 'set-power-plan', params: { plan: 'balanced' }, requiresAdmin: true },
      }),
    );
  }

  return {
    metrics: { powerPlan: planName, powerPlanGuid: guid, hasBattery },
    findings,
    checks: [
      check({
        id: 'power-plan',
        category: 'power',
        title: 'План питания',
        status: planKey === 'saver' || (planKey === 'high' && hasBattery) ? 'issue' : 'ok',
        summary: 'Проверен активный план питания и наличие батареи.',
        result: `План: ${planName} (${guid || 'не определён'}); батарея: ${hasBattery ? 'есть' : 'нет'}.`,
        evidence: ['powercfg /getactivescheme', 'Win32_Battery'],
      }),
    ],
  };
}

async function collectProcesses(system) {
  const script = `
    Get-Process | Where-Object { $_.WorkingSet64 -gt 20MB } |
      Sort-Object WorkingSet64 -Descending |
      Select-Object -First 8 Name, Id, @{n='MemoryMB';e={[math]::Round($_.WorkingSet64/1MB)}}, @{n='Path';e={$_.Path}} |
      ConvertTo-Json -Compress -Depth 3
  `;
  const raw = await parseJsonPs(script, 'Процессы', []);
  const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
  const findings = [];

  if (system.ramUsedPercent >= 80 && list.length) {
    findings.push(
      finding({
        id: 'processes-memory-pressure',
        category: 'processes',
        title: 'Высокая загрузка оперативной памяти',
        summary: `Использовано ${system.ramUsedPercent}% ОЗУ. SteadyPC не завершает процессы автоматически.`,
        details: [
          'Ниже — процессы с наибольшим потреблением памяти.',
          'Закройте ненужные программы вручную или перезагрузите систему.',
          'Автоматическое завершение процессов может привести к потере данных.',
        ],
        evidence: list.slice(0, 6).map((item) => `${item.Name} — ${item.MemoryMB} МБ${item.Path ? ` (${item.Path})` : ''}`),
        severity: system.ramUsedPercent >= 90 ? 'medium' : 'low',
        risk: 'low',
        reversible: false,
        recommended: false,
        presets: [],
      }),
    );
  }

  return {
    metrics: { topProcesses: list },
    findings,
    checks: [
      check({
        id: 'processes-memory',
        category: 'processes',
        title: 'Загрузка оперативной памяти',
        status: system.ramUsedPercent >= 80 ? 'issue' : 'ok',
        summary: 'Проверено использование ОЗУ. Процессы не завершаются автоматически.',
        result: `Использовано ${system.ramUsedPercent}% (${system.ramUsedGb} из ${system.ramTotalGb} ГБ); порог: 80%. Крупнейших процессов: ${list.length}.`,
        evidence: list.slice(0, 3).map((item) => `${item.Name} — ${item.MemoryMB} МБ`),
      }),
    ],
  };
}

async function collectNetwork() {
  const tcpRaw = (await run('netsh.exe', ['int', 'tcp', 'show', 'global'], 15000)).stdout || '';
  const level = parseTcpLevel(tcpRaw) || 'unknown';
  const line = tcpRaw.split(/\r?\n/).find((item) => new RegExp(`:\\s*${level}\\s*$`, 'i').test(item)) || '';
  const dnsRaw = (await run('ipconfig.exe', ['/displaydns'], 15000)).stdout || '';
  const dnsEntries = (dnsRaw.match(/Record Name/gi) || []).length;
  const findings = [];

  if (level !== 'normal' && level !== 'unknown') {
    findings.push(
      finding({
        id: 'network-tcp-autotuning',
        category: 'network',
        title: 'Нестандартная автонастройка TCP',
        summary: `Receive Window Auto-Tuning Level = ${level}.`,
        details: [
          'Нестандартное значение может ухудшать пропускную способность на некоторых соединениях.',
          'SteadyPC вернёт значение normal и сохранит прежнее состояние для отката.',
          'Это исправление настроек, а не «ускоритель интернета».',
        ],
        evidence: [line.trim() || `level: ${level}`],
        severity: 'low',
        risk: 'medium',
        reversible: true,
        recommended: false,
        presets: ['advanced'],
        action: { commandId: 'reset-tcp-autotuning', params: {}, requiresAdmin: true },
      }),
    );
  }

  if (dnsEntries > 200) {
    findings.push(
      finding({
        id: 'network-dns-cache',
        category: 'network',
        title: 'Большой DNS-кэш',
        summary: `В кэше DNS найдено ${dnsEntries} записей.`,
        details: [
          'Устаревшие записи могут вызывать ошибки открытия сайтов.',
          'Очистка кэша не увеличивает скорость соединения, но может исправить разрешение имён.',
        ],
        evidence: [`Записей: ${dnsEntries}`],
        severity: 'low',
        risk: 'low',
        reversible: false,
        recommended: false,
        presets: ['advanced'],
        action: { commandId: 'flush-dns', params: {}, requiresAdmin: false },
      }),
    );
  }

  return {
    metrics: { tcpAutoTuning: level, dnsCacheEntries: dnsEntries },
    findings,
    checks: [
      check({
        id: 'network-tcp',
        category: 'network',
        title: 'Автонастройка TCP',
        status: level !== 'normal' && level !== 'unknown' ? 'issue' : 'ok',
        summary: 'Проверен параметр Receive Window Auto-Tuning Level.',
        result: `Значение: ${level}; ожидаемое: normal.`,
        evidence: [line.trim() || 'netsh int tcp show global'],
      }),
      check({
        id: 'network-dns',
        category: 'network',
        title: 'Кэш DNS',
        status: dnsEntries > 200 ? 'issue' : 'ok',
        summary: 'Проверен размер кэша DNS.',
        result: `Записей: ${dnsEntries}; порог: 200. Очистка кэша не ускоряет соединение.`,
        evidence: ['ipconfig /displaydns'],
      }),
    ],
  };
}

async function collectVisual() {
  const script = `
    function GetVal($p, $n) {
      try {
        $item = Get-ItemProperty -LiteralPath $p -Name $n -ErrorAction Stop
        [pscustomobject]@{ exists = $true; value = [string]$item.$n }
      } catch {
        [pscustomobject]@{ exists = $false; value = '' }
      }
    }
    [pscustomobject]@{
      fx = GetVal 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects' 'VisualFXSetting'
      minAnimate = GetVal 'HKCU:\\Control Panel\\Desktop\\WindowMetrics' 'MinAnimate'
      taskbarAnimations = GetVal 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' 'TaskbarAnimations'
    } | ConvertTo-Json -Compress -Depth 4
  `;
  const state = await parseJsonPs(script, 'Визуальные эффекты', {});
  const enabled = state?.minAnimate?.value !== '0' || state?.taskbarAnimations?.value !== '0';
  const findings = [];

  if (enabled) {
    findings.push(
      finding({
        id: 'visual-animations',
        category: 'visual',
        title: 'Включены анимации интерфейса',
        summary: 'Анимация окон и панели задач включена.',
        details: [
          'На слабых видеокартах и при удалённом доступе анимации снижают отзывчивость.',
          'Интерфейс станет более строгим.',
          'Настройки сохраняются и восстанавливаются при откате.',
        ],
        evidence: [
          `MinAnimate: ${state?.minAnimate?.value || 'не задано'}`,
          `TaskbarAnimations: ${state?.taskbarAnimations?.value || 'не задано'}`,
        ],
        severity: 'low',
        risk: 'low',
        reversible: true,
        recommended: false,
        presets: ['performance', 'gaming'],
        action: { commandId: 'set-visual-effects', params: {}, requiresAdmin: false },
      }),
    );
  }

  return {
    metrics: { visualAnimationsEnabled: enabled },
    findings,
    checks: [
      check({
        id: 'visual-animations',
        category: 'visual',
        title: 'Анимации интерфейса',
        status: enabled ? 'issue' : 'ok',
        summary: 'Проверены настройки анимации окон и панели задач.',
        result: `MinAnimate: ${state?.minAnimate?.value || 'не задано'}; TaskbarAnimations: ${state?.taskbarAnimations?.value || 'не задано'}.`,
        evidence: ['HKCU\\Control Panel\\Desktop\\WindowMetrics', 'HKCU\\...\\Explorer\\Advanced'],
      }),
    ],
  };
}

async function collectUpdates(system) {
  const script = `
    $reasons = @()
    if (Test-Path -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') { $reasons += 'Component Based Servicing' }
    if (Test-Path -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') { $reasons += 'Windows Update' }
    if (Test-Path -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' ) {
      $pending = Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
      if ($pending) { $reasons += 'Pending file rename' }
    }
    [pscustomobject]@{ count = $reasons.Count; reasons = $reasons } | ConvertTo-Json -Compress -Depth 4
  `;
  const state = await parseJsonPs(script, 'Ожидающая перезагрузка', { count: 0, reasons: [] });
  const findings = [];

  if (state.count > 0) {
    findings.push(
      finding({
        id: 'updates-reboot-pending',
        category: 'updates',
        title: 'Требуется перезагрузка',
        summary: 'Система ожидает перезагрузки для завершения установки обновлений.',
        details: [
          'Некоторые изменения вступают в силу только после перезагрузки.',
          'SteadyPC предложит перезагрузку отдельно и не выполнит её без подтверждения.',
          'Сохраните открытые документы перед перезагрузкой.',
        ],
        evidence: (state.reasons || []).map((reason) => `Причина: ${reason}`),
        severity: 'medium',
        risk: 'low',
        reversible: false,
        recommended: false,
        presets: [],
      }),
    );
  }

  return {
    metrics: {
      rebootPending: state.count > 0,
      rebootReasons: state.reasons || [],
      lastBoot: system.uptime.text,
    },
    findings,
    checks: [
      check({
        id: 'updates-reboot',
        category: 'updates',
        title: 'Ожидающая перезагрузка',
        status: state.count > 0 ? 'issue' : 'ok',
        summary: 'Проверены признаки незавершённой установки обновлений.',
        result: state.count > 0
          ? `Причин: ${state.count}. ${(state.reasons || []).join('; ')}.`
          : 'Признаков ожидающей перезагрузки нет.',
        evidence: ['Component Based Servicing', 'Windows Update', 'PendingFileRenameOperations'],
      }),
    ],
  };
}

async function collectPrivacy() {
  const script = `
    $value = (Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry
    if ($null -eq $value) { 'not-configured' } else { [string]$value }
  `;
  const raw = (await psChecked(script, 'Телеметрия', 10000).catch(() => 'not-configured')).trim();
  const findings = [];

  if (raw !== '0') {
    findings.push(
      finding({
        id: 'privacy-telemetry',
        category: 'privacy',
        title: 'Уровень телеметрии Windows',
        summary: raw === 'not-configured' ? 'Политика телеметрии Windows явно не задана.' : `AllowTelemetry = ${raw}.`,
        details: [
          'SteadyPC не отправляет данные и не изменяет эту настройку автоматически.',
          'Это справочная информация: решение принимаете вы.',
        ],
        evidence: [`AllowTelemetry: ${raw}`],
        severity: 'low',
        risk: 'low',
        reversible: false,
        recommended: false,
        presets: [],
      }),
    );
  }

  return {
    metrics: { allowTelemetry: raw },
    findings,
    checks: [
      check({
        id: 'privacy-telemetry',
        category: 'privacy',
        title: 'Телеметрия Windows',
        status: raw === '0' ? 'ok' : 'info',
        summary: 'Проверена политика телеметрии Windows. SteadyPC не изменяет её.',
        result: `AllowTelemetry: ${raw}. Это справочная информация, а не проблема производительности.`,
        evidence: ['HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection'],
      }),
    ],
  };
}

async function runScan() {
  const started = Date.now();
  const system = await collectSystemInfo();
  const startupPromise = collectStartup();
  const collectors = [
    startupPromise,
    collectStorage(system),
    collectPower(),
    collectProcesses(system),
    collectNetwork(),
    collectVisual(),
    collectUpdates(system),
    collectPrivacy(),
    startupPromise.then((value) => collectSecurity(value.autorun || []), () => collectSecurity([])),
  ];

  const results = await Promise.allSettled(collectors);
  const findings = [];
  const checks = [];
  const metrics = { ...system };
  const warnings = [];

  for (const result of results) {
    if (result.status === 'fulfilled') {
      findings.push(...(result.value.findings || []));
      checks.push(...(result.value.checks || []));
      Object.assign(metrics, result.value.metrics || {});
      warnings.push(...(result.value.warnings || []));
    } else {
      warnings.push(result.reason?.message || String(result.reason));
    }
  }

  return {
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    appVersion: APP_VERSION,
    system,
    metrics,
    findings,
    checks,
    score: scoreReportFindings(findings),
    warnings,
  };
}

module.exports = { runScan, formatBytes, collectSystemInfo, check };
