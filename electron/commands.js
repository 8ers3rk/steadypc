'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile, execFileSync } = require('child_process');
const { promisify } = require('util');
const { validateCommandParams } = require('./validation');

const execFileAsync = promisify(execFile);

const POWER_PLANS = Object.freeze({
  balanced: '381b4222-f694-41f0-9685-ff5bb260df2e',
  high: '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c',
  saver: 'a1841308-3541-4fab-bc81-f71556f20b4a',
});

const TCP_LEVELS = new Set(['normal', 'disabled', 'highlyrestricted', 'restricted', 'experimental']);

function psq(value) {
  return String(value).replace(/'/g, "''");
}

function parseTcpLevel(text) {
  const allowed = ['normal', 'disabled', 'highlyrestricted', 'restricted', 'experimental'];
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = line.match(/:\s*([a-z]+)\s*$/i);
    if (match && allowed.includes(match[1].toLowerCase())) return match[1].toLowerCase();
  }
  return '';
}

async function run(executable, args, timeout = 20000) {
  try {
    const { stdout, stderr } = await execFileAsync(executable, args, {
      windowsHide: true,
      timeout,
      maxBuffer: 12 * 1024 * 1024,
      encoding: 'utf8',
    });
    return { ok: true, stdout: stdout || '', stderr: stderr || '' };
  } catch (error) {
    return {
      ok: false,
      stdout: error.stdout || '',
      stderr: error.stderr || '',
      message: error.message || String(error),
    };
  }
}

function ps(script, timeout = 20000) {
  return run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], timeout);
}

async function runChecked(executable, args, label, timeout = 20000) {
  const result = await run(executable, args, timeout);
  if (!result.ok) {
    throw new Error(`${label}: ${result.message || result.stderr || 'unknown error'}`);
  }
  return result.stdout.trim();
}

async function psChecked(script, label, timeout = 20000) {
  return runChecked('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], label, timeout);
}

function isAdmin() {
  try {
    execFileSync('net', ['session'], { stdio: 'ignore', windowsHide: true, timeout: 5000 });
    return true;
  } catch (error) {
    return false;
  }
}

function readRegistryValue(registryPath, name) {
  const script = `
    $key = Get-Item -LiteralPath '${psq(registryPath)}' -ErrorAction Stop
    if ($key.GetValueNames() -contains '${psq(name)}') {
      [pscustomobject]@{
        exists = $true
        value = [string]$key.GetValue('${psq(name)}')
        kind = $key.GetValueKind('${psq(name)}').ToString()
      } | ConvertTo-Json -Compress
    } else {
      '{"exists":false}'
    }
  `;
  return ps(script, 10000).then((result) => {
    if (!result.ok) return { exists: false, error: result.message };
    try {
      return JSON.parse(result.stdout.trim());
    } catch (error) {
      return { exists: false, error: 'Не удалось прочитать значение реестра' };
    }
  });
}

function walkOldFiles(root, cutoff, onFile) {
  let scanned = 0;
  let matched = 0;
  let freed = 0;
  let skipped = 0;

  function visit(dir, depth) {
    if (depth > 12) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      skipped += 1;
      return;
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      try {
        if (entry.isDirectory()) {
          visit(full, depth + 1);
        } else if (entry.isFile()) {
          const stat = fs.lstatSync(full);
          scanned += 1;
          if (stat.mtimeMs < cutoff) {
            matched += 1;
            freed += stat.size;
            try {
              fs.unlinkSync(full);
              onFile('removed');
            } catch (error) {
              skipped += 1;
              onFile('skipped');
            }
          }
        }
      } catch (error) {
        skipped += 1;
      }
    }
  }

  visit(root, 0);
  return { scanned, matched, freed, skipped };
}

const commands = {
  'disable-startup': {
    title: 'Отключить запись автозагрузки',
    requiresAdmin: false,
    reversible: true,
    risk: 'low',
    describe: (params) => `Отключить «${params.name}» в автозагрузке. Исходное значение сохраняется.`,
    rollbackText: 'Восстановить исходную запись автозагрузки.',

    async execute(params) {
      if (params.source === 'folder') {
        const target = params.path;
        const disabled = `${target}.steadypc-disabled`;
        if (!fs.existsSync(target)) throw new Error('Ярлык автозагрузки не найден');
        if (fs.existsSync(disabled)) throw new Error('Файл уже отключён ранее');
        fs.renameSync(target, disabled);
        return { rollbackData: { source: 'folder', path: target, disabled } };
      }

      const registryPath = params.path;
      const original = await readRegistryValue(registryPath, params.name);
      if (!original.exists) throw new Error('Запись реестра уже отсутствует');

      const script = `Remove-ItemProperty -LiteralPath '${psq(registryPath)}' -Name '${psq(params.name)}' -ErrorAction Stop`;
      const result = await ps(script, 10000);
      if (!result.ok) throw new Error(result.message || result.stderr || 'Не удалось отключить запись');
      return {
        rollbackData: {
          source: 'registry',
          registryPath,
          name: params.name,
          value: original.value,
          kind: String(original.kind || 'String'),
        },
      };
    },

    async rollback(info) {
      if (info.source === 'folder') {
        if (!fs.existsSync(info.disabled)) throw new Error('Отключённый ярлык не найден');
        fs.renameSync(info.disabled, info.path);
        return;
      }
      const kind = String(info.kind || 'String');
      const safeKind = ['String', 'ExpandString', 'DWord', 'QWord', 'Binary'].includes(kind) ? kind : 'String';
      const script = `New-ItemProperty -LiteralPath '${psq(info.registryPath)}' -Name '${psq(info.name)}' -Value '${psq(info.value)}' -PropertyType ${safeKind} -Force -ErrorAction Stop | Out-Null`;
      const result = await ps(script, 10000);
      if (!result.ok) throw new Error(result.message || result.stderr || 'Не удалось восстановить запись');
    },
  },

  'clean-temp': {
    title: 'Удалить старые временные файлы',
    requiresAdmin: false,
    reversible: false,
    risk: 'low',
    describe: (params) => `Удалить файлы старше ${params.maxAgeDays} дней из временных папок. Занятые файлы будут пропущены.`,
    rollbackText: 'Временные файлы не восстанавливаются.',

    async execute(params) {
      const days = Math.max(1, Number(params.maxAgeDays) || 7);
      const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
      const locations = [];

      const userTemp = process.env.TEMP || path.join(process.env.USERPROFILE || 'C:\\', 'AppData', 'Local', 'Temp');
      if (fs.existsSync(userTemp)) {
        locations.push({ name: 'TEMP пользователя', ...walkOldFiles(userTemp, cutoff, () => {}) });
      }

      const windowsTemp = 'C:\\Windows\\Temp';
      if (fs.existsSync(windowsTemp)) {
        locations.push({ name: 'C:\\Windows\\Temp', ...walkOldFiles(windowsTemp, cutoff, () => {}) });
      }

      const freed = locations.reduce((sum, item) => sum + item.freed, 0);
      const removed = locations.reduce((sum, item) => sum + item.matched, 0);
      if (removed === 0) throw new Error('Старых файлов для удаления не найдено');

      return { data: { freedBytes: freed, filesRemoved: removed, locations }, rollbackData: null };
    },
  },

  'set-power-plan': {
    title: 'Сменить план питания',
    requiresAdmin: true,
    reversible: true,
    risk: 'medium',
    describe: (params) => `Установить план питания: ${params.plan}.`,
    rollbackText: 'Вернуть предыдущий план питания.',

    async execute(params) {
      const guid = POWER_PLANS[params.plan];
      if (!guid) throw new Error('Неизвестный план питания');
      const current = (await run('powercfg.exe', ['/getactivescheme'], 10000)).stdout;
      const previous = (current.match(/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i) || [])[1];
      const output = await runChecked('powercfg.exe', ['/setactive', guid], 'Смена плана питания', 15000);
      return {
        data: { previous, next: guid },
        rollbackData: previous ? { previous } : null,
      };
    },

    async rollback(info) {
      if (!info.previous) throw new Error('Предыдущий план неизвестен');
      await runChecked('powercfg.exe', ['/setactive', info.previous], 'Возврат плана питания', 15000);
    },
  },

  'trim-ssd': {
    title: 'Выполнить TRIM для SSD',
    requiresAdmin: true,
    reversible: false,
    risk: 'low',
    describe: () => 'Выполнить однократную оптимизацию SSD через TRIM. Дефрагментация не выполняется.',
    rollbackText: 'Операция не требует отката.',

    async execute(params) {
      const drive = String(params.drive || 'C').replace(/[^A-Za-z]/g, '').toUpperCase();
      const script = `Optimize-Volume -DriveLetter '${drive}' -ReTrim -ErrorAction Stop`;
      const result = await ps(script, 120000);
      if (!result.ok) throw new Error(result.message || result.stderr || 'TRIM не выполнен');
      return { data: { output: result.stdout.trim().slice(0, 2000) }, rollbackData: null };
    },
  },

  'defrag-hdd': {
    title: 'Дефрагментировать HDD',
    requiresAdmin: true,
    reversible: false,
    risk: 'low',
    describe: () => 'Дефрагментировать жесткий диск. Применяется только к HDD.',
    rollbackText: 'Операция не требует отката.',

    async execute(params) {
      const drive = String(params.drive || 'C').replace(/[^A-Za-z]/g, '').toUpperCase();
      const script = `Optimize-Volume -DriveLetter '${drive}' -Defrag -ErrorAction Stop`;
      const result = await ps(script, 300000);
      if (!result.ok) throw new Error(result.message || result.stderr || 'Дефрагментация не выполнена');
      return { data: { output: result.stdout.trim().slice(0, 2000) }, rollbackData: null };
    },
  },

  'flush-dns': {
    title: 'Очистить DNS-кэш',
    requiresAdmin: false,
    reversible: false,
    risk: 'low',
    describe: () => 'Очистить кэш DNS. Полезно при устаревших записях и ошибках разрешения имён.',
    rollbackText: 'Кэш будет пересоздан системой автоматически.',

    async execute() {
      const result = await run('ipconfig.exe', ['/flushdns'], 15000);
      if (!result.ok) throw new Error(result.message || result.stderr || 'Не удалось очистить DNS-кэш');
      return { data: {}, rollbackData: null };
    },
  },

  'reset-tcp-autotuning': {
    title: 'Вернуть автонастройку TCP к значению по умолчанию',
    requiresAdmin: true,
    reversible: true,
    risk: 'medium',
    describe: () => 'Установить Receive Window Auto-Tuning Level = normal.',
    rollbackText: 'Вернуть предыдущее значение автонастройки TCP.',

    async execute() {
      const before = (await run('netsh.exe', ['int', 'tcp', 'show', 'global'], 15000)).stdout;
      const previous = parseTcpLevel(before);
      const result = await run('netsh.exe', ['int', 'tcp', 'set', 'global', 'autotuninglevel=normal'], 15000);
      if (!result.ok) throw new Error(result.message || result.stderr || 'Не удалось изменить настройки TCP');
      return {
        data: { previous: previous || 'unknown' },
        rollbackData: TCP_LEVELS.has(previous) ? { previous } : null,
      };
    },

    async rollback(info) {
      if (!TCP_LEVELS.has(info.previous)) throw new Error('Предыдущее значение неизвестно');
      const result = await run('netsh.exe', ['int', 'tcp', 'set', 'global', `autotuninglevel=${info.previous}`], 15000);
      if (!result.ok) throw new Error(result.message || result.stderr || 'Не удалось восстановить настройки TCP');
    },
  },

  'set-visual-effects': {
    title: 'Отключить анимации интерфейса',
    requiresAdmin: false,
    reversible: true,
    risk: 'low',
    describe: () => 'Отключить анимацию окон и панели задач. Внешний вид станет более строгим.',
    rollbackText: 'Вернуть предыдущие настройки анимации.',

    async execute() {
      const script = `
        $fxPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects'
        $wmPath = 'HKCU:\\Control Panel\\Desktop\\WindowMetrics'
        $adPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced'
        function GetVal($p, $n) {
          try {
            $item = Get-ItemProperty -LiteralPath $p -Name $n -ErrorAction Stop
            [pscustomobject]@{ exists = $true; value = [string]$item.$n }
          } catch {
            [pscustomobject]@{ exists = $false; value = '' }
          }
        }
        [pscustomobject]@{
          fx = GetVal $fxPath 'VisualFXSetting'
          minAnimate = GetVal $wmPath 'MinAnimate'
          taskbarAnimations = GetVal $adPath 'TaskbarAnimations'
        } | ConvertTo-Json -Compress -Depth 4
      `;
      const raw = await psChecked(script, 'Чтение настроек эффектов', 10000);
      const state = JSON.parse(raw);
      const apply = `
        New-ItemProperty -LiteralPath '${psq('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects')}' -Name 'VisualFXSetting' -Value 2 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -LiteralPath '${psq('HKCU:\\Control Panel\\Desktop\\WindowMetrics')}' -Name 'MinAnimate' -Value '0' -PropertyType String -Force | Out-Null
        New-ItemProperty -LiteralPath '${psq('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced')}' -Name 'TaskbarAnimations' -Value 0 -PropertyType DWord -Force | Out-Null
      `;
      const result = await ps(apply, 10000);
      if (!result.ok) throw new Error(result.message || result.stderr || 'Не удалось изменить настройки эффектов');
      return { data: {}, rollbackData: state };
    },

    async rollback(info) {
      const fxPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects';
      const wmPath = 'HKCU:\\Control Panel\\Desktop\\WindowMetrics';
      const adPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced';
      const lines = [];

      function restore(pathValue, name, item, type) {
        if (!item || !item.exists) {
          lines.push(`Remove-ItemProperty -LiteralPath '${psq(pathValue)}' -Name '${name}' -ErrorAction SilentlyContinue`);
        } else {
          lines.push(`New-ItemProperty -LiteralPath '${psq(pathValue)}' -Name '${name}' -Value '${psq(item.value)}' -PropertyType ${type} -Force | Out-Null`);
        }
      }

      restore(fxPath, 'VisualFXSetting', info.fx, 'DWord');
      restore(wmPath, 'MinAnimate', info.minAnimate, 'String');
      restore(adPath, 'TaskbarAnimations', info.taskbarAnimations, 'DWord');

      const result = await ps(lines.join('\n'), 10000);
      if (!result.ok) throw new Error(result.message || result.stderr || 'Не удалось восстановить эффекты');
    },
  },

  'clear-update-cache': {
    title: 'Очистить старый кэш обновлений',
    requiresAdmin: true,
    reversible: false,
    risk: 'medium',
    describe: (params) => `Удалить файлы кэша Windows Update старше ${params.maxAgeDays} дней. Занятые файлы будут пропущены.`,
    rollbackText: 'Удалённые файлы кэша не восстанавливаются.',

    async execute(params) {
      const days = Math.max(1, Number(params.maxAgeDays) || 30);
      const root = 'C:\\Windows\\SoftwareDistribution\\Download';
      if (!fs.existsSync(root)) throw new Error('Кэш обновлений не найден');
      const result = walkOldFiles(root, Date.now() - days * 24 * 60 * 60 * 1000, () => {});
      if (result.matched === 0) throw new Error('Старых файлов кэша не найдено');
      return {
        data: { freedBytes: result.freed, filesRemoved: result.matched, skipped: result.skipped },
        rollbackData: null,
      };
    },
  },
};

const TOOL_DEFINITIONS = Object.freeze([
  { id: 'clean-temp', category: 'storage', params: { maxAgeDays: 7 } },
  { id: 'clear-update-cache', category: 'storage', params: { maxAgeDays: 30 } },
  { id: 'trim-ssd', category: 'disk', params: { drive: 'C' }, diskType: 'ssd' },
  { id: 'defrag-hdd', category: 'disk', params: { drive: 'C' }, diskType: 'hdd' },
  { id: 'set-power-plan', category: 'power', params: { plan: 'balanced' } },
  { id: 'flush-dns', category: 'network', params: {} },
  { id: 'reset-tcp-autotuning', category: 'network', params: {} },
  { id: 'set-visual-effects', category: 'visual', params: {} },
  { id: 'disable-startup', category: 'startup', params: {}, requiresSelection: true },
]);

function listTools() {
  return TOOL_DEFINITIONS.map((definition) => {
    const command = commands[definition.id];
    return {
      id: definition.id,
      title: command.title,
      description: definition.requiresSelection
        ? 'Отключить конкретную запись автозагрузки. Выберите запись на экране диагностики.'
        : command.describe(definition.params),
      risk: command.risk,
      reversible: command.reversible,
      requiresAdmin: command.requiresAdmin,
      category: definition.category,
      params: definition.params,
      diskType: definition.diskType || 'any',
      requiresSelection: Boolean(definition.requiresSelection),
    };
  });
}

async function executeCommand(commandId, params) {
  const command = commands[commandId];
  if (!command) throw new Error(`Неизвестная команда: ${commandId}`);
  const result = await command.execute(validateCommandParams(commandId, params || {}));
  return {
    commandId,
    title: command.title,
    risk: command.risk,
    reversible: command.reversible,
    data: result.data || {},
    rollbackData: result.rollbackData || null,
  };
}

async function rollbackCommand(commandId, rollbackData) {
  const command = commands[commandId];
  if (!command || !command.rollback || !rollbackData) {
    throw new Error('Для этого изменения откат недоступен');
  }
  await command.rollback(rollbackData);
}

async function createRestorePoint() {
  const script = `Checkpoint-Computer -Description 'SteadyPC - before changes' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop`;
  const result = await ps(script, 120000);
  return { success: result.ok, error: result.ok ? null : result.message || result.stderr || 'Неизвестная ошибка' };
}

function restartAsAdmin() {
  if (!require('electron').app.isPackaged) {
    return { started: false, reason: 'В режиме разработки перезапуск от имени администратора недоступен.' };
  }

  const exe = process.execPath;
  const args = process.argv.slice(1);
  const argList = args.map((item) => `'${psq(item)}'`).join(',');
  const script = argList
    ? `Start-Process -FilePath '${psq(exe)}' -ArgumentList @(${argList}) -Verb RunAs`
    : `Start-Process -FilePath '${psq(exe)}' -Verb RunAs`;

  try {
    const child = require('child_process').spawn('powershell.exe', ['-NoProfile', '-Command', script], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    });
    child.unref();
    return { started: true, reason: null };
  } catch (error) {
    return { started: false, reason: error.message || String(error) };
  }
}

module.exports = {
  commands,
  listTools,
  executeCommand,
  rollbackCommand,
  isAdmin,
  createRestorePoint,
  restartAsAdmin,
  ps,
  psChecked,
  run,
  runChecked,
  psq,
  parseTcpLevel,
  POWER_PLANS,
};
