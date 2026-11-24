'use strict';

const { finding, check } = require('./finding');
const BUILTIN_SIGNATURES = require('./security-signatures.json');

function lower(value) {
  return String(value ?? '').toLowerCase();
}

function uniqueStrings(values) {
  return [...new Set((Array.isArray(values) ? values : []).map((value) => String(value)))];
}

function uniqueNumbers(values) {
  const result = [];
  for (const value of Array.isArray(values) ? values : []) {
    const number = Number(value);
    if (Number.isFinite(number) && !result.includes(number)) result.push(number);
  }
  return result;
}

function normalizeRanges(values) {
  return (Array.isArray(values) ? values : [])
    .map((range) => (Array.isArray(range) ? range.map(Number) : []))
    .filter((range) => range.length === 2 && range.every(Number.isFinite) && range[0] <= range[1]);
}

function loadSignatures(override = null) {
  const extra = override && typeof override === 'object' ? override : {};
  const mergeStrings = (key) => uniqueStrings([...(BUILTIN_SIGNATURES[key] || []), ...(extra[key] || [])]);

  return {
    minerNames: mergeStrings('minerNames'),
    minerCommandPatterns: mergeStrings('minerCommandPatterns'),
    minerPorts: uniqueNumbers([...(BUILTIN_SIGNATURES.minerPorts || []), ...(extra.minerPorts || [])]),
    minerPortRanges: normalizeRanges([
      ...(BUILTIN_SIGNATURES.minerPortRanges || []),
      ...(extra.minerPortRanges || []),
    ]),
    suspiciousCommandPatterns: mergeStrings('suspiciousCommandPatterns'),
    suspiciousPathFragments: mergeStrings('suspiciousPathFragments'),
    systemProcessNames: mergeStrings('systemProcessNames'),
    systemProcessDirectories: uniqueStrings([
      ...(BUILTIN_SIGNATURES.systemProcessDirectories || []),
      ...(extra.systemProcessDirectories || []),
    ]).map((value) => lower(value).replace(/\\+$/, '')),
  };
}

function includesAny(text, patterns) {
  const value = lower(text);
  return patterns.some((pattern) => value.includes(lower(pattern)));
}

function isPortMiner(port, signatures) {
  const number = Number(port);
  if (!Number.isFinite(number)) return false;
  return (
    signatures.minerPorts.includes(number) ||
    signatures.minerPortRanges.some(([from, to]) => number >= from && number <= to)
  );
}

function isValidStatus(status) {
  return /^valid$/i.test(String(status || '').trim());
}

function hasValidSignature(pathValue, states) {
  return isValidStatus(states?.[pathValue]?.status);
}

function isMicrosoftSigned(pathValue, states) {
  const state = states?.[pathValue] || {};
  return isValidStatus(state.status) && /microsoft/i.test(String(state.signer || ''));
}

function isUnderSystemDirectory(pathValue, signatures) {
  const value = lower(pathValue);
  return signatures.systemProcessDirectories.some(
    (directory) => value === directory || value.startsWith(`${directory}\\`),
  );
}

function nameMatchesMiner(name, signatures) {
  const value = lower(name).replace(/\.exe$/, '');
  return signatures.minerNames.some((candidate) => {
    const base = lower(candidate).replace(/\.exe$/, '');
    return value === base || value.startsWith(`${base}-`) || value.startsWith(`${base}_`);
  });
}

function commandMatchesMiner(commandLine, signatures) {
  return includesAny(commandLine, signatures.minerCommandPatterns);
}

function hasMinerIndicators(process, signatures) {
  return nameMatchesMiner(process.name, signatures) || commandMatchesMiner(process.commandLine, signatures);
}

function isRiskyProcess(process, signatures, states) {
  return (
    includesAny(process.path, signatures.suspiciousPathFragments) && !hasValidSignature(process.path, states)
  );
}

function truncate(value, limit = 220) {
  const text = String(value || '');
  return text.length <= limit ? text : `${text.slice(0, limit)}…`;
}

function processEvidence(process, extra = []) {
  return [
    `PID: ${process.pid ?? '—'}`,
    `Родитель: ${process.parentPid ?? '—'}`,
    `Имя: ${process.name || '—'}`,
    `Путь: ${process.path || '—'}`,
    `Командная строка: ${truncate(process.commandLine || '—')}`,
    ...extra,
  ];
}

function groupByPid(connections) {
  const result = new Map();
  for (const connection of connections) {
    const pid = Number(connection.pid);
    if (!Number.isFinite(pid)) continue;
    if (!result.has(pid)) result.set(pid, []);
    result.get(pid).push(connection);
  }
  return result;
}

function analyzeSecurity(snapshot, signatures = loadSignatures()) {
  const data = { processes: [], connections: [], tasks: [], autorun: [], defender: null, signatureStates: {}, ...snapshot };
  const states = data.signatureStates || {};
  const findings = [];
  const checks = [];
  const byPid = new Map(data.processes.map((process) => [Number(process.pid), process]));
  const connectionsByPid = groupByPid(data.connections);
  const poolConnections = data.connections.filter((connection) => isPortMiner(connection.port, signatures));

  function portsFor(pid) {
    return (connectionsByPid.get(Number(pid)) || [])
      .filter((connection) => isPortMiner(connection.port, signatures))
      .map((connection) => connection.port)
      .join(', ');
  }

  // Miner processes: a miner name or a pool command line is the primary signal.
  const minerProcesses = data.processes
    .filter((process) => hasMinerIndicators(process, signatures))
    .map((process) => ({ process, ports: portsFor(process.pid) }));
  if (minerProcesses.length) {
    const high = minerProcesses.some(
      (item) => nameMatchesMiner(item.process.name, signatures) && commandMatchesMiner(item.process.commandLine, signatures),
    ) || minerProcesses.some((item) => item.ports);
    findings.push(
      finding({
        id: 'security-miner-process',
        category: 'security',
        title: 'Индикатор майнера в процессах',
        summary: `Обнаружены признаки майнинга в ${minerProcesses.length} процессе(ах). Это индикатор, а не приговор.`,
        details: [
          'Имя процесса или командная строка совпали с локальным списком признаков майнеров.',
          'Майнеры часто используют пулы и адреса кошельков в параметрах запуска.',
          'SteadyPC не завершает процессы. Проверьте путь, подпись и командную строку самостоятельно.',
        ],
        evidence: minerProcesses.slice(0, 5).flatMap((item) =>
          processEvidence(item.process, item.ports ? [`Порт пула: ${item.ports}`] : []),
        ),
        severity: high ? 'high' : 'medium',
        risk: 'low',
        confidence: high ? 'high' : 'medium',
      }),
    );
  }
  checks.push(
    check({
      id: 'security-miner-process',
      category: 'security',
      title: 'Майнеры в процессах',
      status: minerProcesses.length ? 'issue' : 'ok',
      summary: 'Сопоставление имен процессов и командных строк с локальным списком признаков майнеров.',
      result: `Подозрительных процессов: ${minerProcesses.length}.`,
      evidence: minerProcesses.slice(0, 5).map((item) => `${item.process.name} (PID ${item.process.pid})`),
    }),
  );

  // A pool port is only a finding when the owning process has another signal.
  const explainedConnections = poolConnections.filter((connection) => {
    const process = byPid.get(Number(connection.pid));
    if (!process) return false;
    return hasMinerIndicators(process, signatures) || isRiskyProcess(process, signatures, states);
  });
  if (explainedConnections.length) {
    const high = explainedConnections.some((connection) => {
      const process = byPid.get(Number(connection.pid));
      return process && hasMinerIndicators(process, signatures);
    });
    findings.push(
      finding({
        id: 'security-miner-network',
        category: 'security',
        title: 'Подключение к порту пула',
        summary: `Обнаружено ${explainedConnections.length} подключение(й) к портам, типичным для пулов майнинга.`,
        details: [
          'Сам по себе порт ничего не доказывает: многие программы используют те же диапазоны.',
          'Подключение помечено только потому, что у процесса есть и другой индикатор.',
          'Сопоставление выполнено локально по PID без запросов к внешним базам.',
        ],
        evidence: explainedConnections.slice(0, 5).map((connection) => {
          const process = byPid.get(Number(connection.pid));
          return `PID ${connection.pid} → ${connection.address || '—'}:${connection.port} · ${process?.name || 'процесс не найден'}`;
        }),
        severity: high ? 'high' : 'medium',
        risk: 'low',
        confidence: high ? 'high' : 'medium',
      }),
    );
  }
  checks.push(
    check({
      id: 'security-miner-network',
      category: 'security',
      title: 'Сетевые признаки майнинга',
      status: explainedConnections.length ? 'issue' : poolConnections.length ? 'info' : 'ok',
      summary: 'Проверка установленных подключений на порты пулов с привязкой к PID.',
      result: explainedConnections.length
        ? `Подключений с дополнительными признаками: ${explainedConnections.length}.`
        : poolConnections.length
          ? `Порты пулов замечены ${poolConnections.length} раз, но других признаков у процессов нет.`
          : 'Подключений к портам пулов не обнаружено.',
      evidence: (explainedConnections.length ? explainedConnections : poolConnections)
        .slice(0, 5)
        .map((connection) => `PID ${connection.pid} → порт ${connection.port}`),
    }),
  );

  // User-writable location plus a missing valid signature are two independent signals.
  const suspiciousProcesses = data.processes.filter((process) => isRiskyProcess(process, signatures, states));
  if (suspiciousProcesses.length) {
    const high = suspiciousProcesses.some(
      (process) => hasMinerIndicators(process, signatures) || portsFor(process.pid),
    );
    findings.push(
      finding({
        id: 'security-suspicious-process-path',
        category: 'security',
        title: 'Процессы из пользовательских каталогов',
        summary: `Найдено ${suspiciousProcesses.length} процессов без действительной подписи в пользовательских каталогах.`,
        details: [
          'Многие легальные программы тоже запускаются из AppData или Temp — это не вирус.',
          'Подозрение возникает только из сочетания пользовательского пути и отсутствия подписи.',
          'Проверьте источник файла перед любыми действиями.',
        ],
        evidence: suspiciousProcesses.slice(0, 5).flatMap((process) =>
          processEvidence(process, [`Подпись: ${states?.[process.path]?.status || 'не проверена'}`]),
        ),
        severity: high ? 'high' : 'medium',
        risk: 'low',
        confidence: high ? 'high' : 'medium',
      }),
    );
  }
  checks.push(
    check({
      id: 'security-suspicious-process-path',
      category: 'security',
      title: 'Расположение процессов',
      status: suspiciousProcesses.length ? 'issue' : 'ok',
      summary: 'Поиск процессов в пользовательских каталогах без действительной подписи.',
      result: `Таких процессов: ${suspiciousProcesses.length}.`,
      evidence: suspiciousProcesses.slice(0, 5).map((process) => `${process.name} — ${process.path}`),
    }),
  );

  // System process names outside system directories with no Microsoft signature.
  const masquerades = data.processes.filter(
    (process) =>
      signatures.systemProcessNames.includes(lower(process.name)) &&
      !isUnderSystemDirectory(process.path, signatures) &&
      !isMicrosoftSigned(process.path, states),
  );
  if (masquerades.length) {
    findings.push(
      finding({
        id: 'security-process-masquerade',
        category: 'security',
        title: 'Маскировка под системный процесс',
        summary: `Обнаружено ${masquerades.length} процессов с системными именами вне системных каталогов.`,
        details: [
          'Системные процессы обычно находятся в System32 или SysWOW64 и подписаны Microsoft.',
          'Исключения возможны для легальных копий, поэтому проверьте путь и подпись вручную.',
          'SteadyPC не завершает такие процессы автоматически.',
        ],
        evidence: masquerades.slice(0, 5).flatMap((process) =>
          processEvidence(process, [
            `Подпись: ${states?.[process.path]?.status || 'не проверена'}`,
            `Издатель: ${states?.[process.path]?.signer || 'не определён'}`,
          ]),
        ),
        severity: 'high',
        risk: 'low',
        confidence: 'high',
      }),
    );
  }
  checks.push(
    check({
      id: 'security-process-masquerade',
      category: 'security',
      title: 'Маскировка под систему',
      status: masquerades.length ? 'issue' : 'ok',
      summary: 'Сравнение имен системных процессов с их расположением и подписью.',
      result: masquerades.length ? `Подозрительных имен: ${masquerades.length}.` : 'Системные имена расположены ожидаемо.',
      evidence: masquerades.slice(0, 5).map((process) => `${process.name} — ${process.path}`),
    }),
  );

  // Encoded PowerShell is only meaningful for a shell process.
  const encodedShells = data.processes.filter(
    (process) => /powershell|pwsh/i.test(String(process.name || '')) && includesAny(process.commandLine, signatures.suspiciousCommandPatterns),
  );
  const otherEncoded = data.processes.filter(
    (process) => !/powershell|pwsh/i.test(String(process.name || '')) && includesAny(process.commandLine, signatures.suspiciousCommandPatterns),
  );
  if (encodedShells.length) {
    const high = encodedShells.some(
      (process) => includesAny(process.path, signatures.suspiciousPathFragments) || portsFor(process.pid),
    );
    findings.push(
      finding({
        id: 'security-encoded-powershell',
        category: 'security',
        title: 'Закодированная команда PowerShell',
        summary: `Обнаружено ${encodedShells.length} процессов PowerShell с закодированными или загружающими командами.`,
        details: [
          'Такие параметры часто используются в сценариях атаки, но встречаются и в легальных инструментах.',
          'Проверьте родительский процесс и полный текст команды.',
          'SteadyPC только показывает данные и не выполняет команды.',
        ],
        evidence: encodedShells.slice(0, 5).flatMap((process) => processEvidence(process)),
        severity: high ? 'high' : 'medium',
        risk: 'low',
        confidence: high ? 'high' : 'medium',
      }),
    );
  }
  checks.push(
    check({
      id: 'security-encoded-powershell',
      category: 'security',
      title: 'Командные строки PowerShell',
      status: encodedShells.length ? 'issue' : otherEncoded.length ? 'info' : 'ok',
      summary: 'Поиск признаков закодированных команд и загрузки кода в командных строках.',
      result: encodedShells.length
        ? `Подозрительных процессов PowerShell: ${encodedShells.length}.`
        : otherEncoded.length
          ? 'Подобные строки найдены у процессов не-PowerShell; это не считается индикатором.'
          : 'Подозрительных командных строк не найдено.',
      evidence: encodedShells.slice(0, 5).map((process) => `PID ${process.pid} — ${truncate(process.commandLine, 120)}`),
    }),
  );

  // Autorun anomaly requires all three signals to reduce false positives.
  const randomName = /^[a-z0-9]{8,}$/i;
  function autorunPath(item) {
    return String(item.path || item.command || '');
  }
  function autorunUnsigned(item) {
    return !isValidStatus(item.signature || states?.[autorunPath(item)]?.status);
  }
  const autorunAnomalies = data.autorun.filter(
    (item) =>
      includesAny(autorunPath(item), signatures.suspiciousPathFragments) &&
      autorunUnsigned(item) &&
      randomName.test(String(item.name || '').replace(/\.[^.]+$/, '')),
  );
  const autorunPartial = data.autorun.filter(
    (item) =>
      includesAny(autorunPath(item), signatures.suspiciousPathFragments) &&
      (autorunUnsigned(item) || randomName.test(String(item.name || '').replace(/\.[^.]+$/, ''))),
  );
  if (autorunAnomalies.length) {
    findings.push(
      finding({
        id: 'security-autorun-anomaly',
        category: 'security',
        title: 'Необычная запись автозагрузки',
        summary: `Найдено ${autorunAnomalies.length} записей автозагрузки с набором подозрительных признаков.`,
        details: [
          'Учтены сразу три признака: пользовательский путь, отсутствие подписи и случайное имя.',
          'Одного или двух признаков недостаточно для находки — они попадают только в проверки.',
          'Отключение записи остаётся решением пользователя.',
        ],
        evidence: autorunAnomalies.slice(0, 5).flatMap((item) =>
          [
            `Запись: ${item.name || '—'}`,
            `Команда: ${truncate(item.command || '—')}`,
            `Подпись: ${item.signature || 'не проверена'}`,
            `Источник: ${item.source || '—'}`,
          ],
        ),
        severity: 'medium',
        risk: 'low',
        confidence: 'medium',
      }),
    );
  }
  checks.push(
    check({
      id: 'security-autorun-anomaly',
      category: 'security',
      title: 'Автозагрузка',
      status: autorunAnomalies.length ? 'issue' : autorunPartial.length ? 'info' : 'ok',
      summary: 'Анализ уже собранных записей автозагрузки по пути, подписи и имени.',
      result: autorunAnomalies.length
        ? `Записей со всеми признаками: ${autorunAnomalies.length}.`
        : autorunPartial.length
          ? `Частичные признаки есть у ${autorunPartial.length} записей; находки не созданы.`
          : 'Необычных записей не найдено.',
      evidence: (autorunAnomalies.length ? autorunAnomalies : autorunPartial)
        .slice(0, 5)
        .map((item) => `${item.name || '—'} — ${autorunPath(item)}`),
    }),
  );

  // Scheduled tasks are checked by their action, not by the task name.
  const taskHits = data.tasks.filter((task) => {
    const action = `${task.execute || ''} ${task.arguments || ''}`;
    return (
      includesAny(action, signatures.suspiciousPathFragments) ||
      (includesAny(action, signatures.suspiciousCommandPatterns) && /powershell|cmd/i.test(action))
    );
  });
  if (taskHits.length) {
    findings.push(
      finding({
        id: 'security-scheduled-task',
        category: 'security',
        title: 'Подозрительное задание планировщика',
        summary: `Найдено ${taskHits.length} заданий с действием из пользовательского каталога или через командную оболочку.`,
        details: [
          'Проверяется действие задания, а не его название.',
          'Многие установщики создают такие задания, поэтому проверьте путь и издателя.',
          'SteadyPC не отключает задания.',
        ],
        evidence: taskHits.slice(0, 5).flatMap((task) =>
          [
            `Задача: ${task.name || '—'}${task.path || ''}`,
            `Действие: ${truncate(`${task.execute || '—'} ${task.arguments || ''}`)}`,
            `Состояние: ${task.state || '—'}`,
          ],
        ),
        severity: 'medium',
        risk: 'low',
        confidence: 'medium',
      }),
    );
  }
  checks.push(
    check({
      id: 'security-scheduled-task',
      category: 'security',
      title: 'Задания планировщика',
      status: taskHits.length ? 'issue' : 'ok',
      summary: 'Проверка действий заданий планировщика на подозрительные пути и команды.',
      result: `Таких заданий: ${taskHits.length}.`,
      evidence: taskHits.slice(0, 5).map((task) => `${task.name || '—'} — ${truncate(task.execute || '—', 120)}`),
    }),
  );

  // Defender is reported as neutral information, never as a threat finding.
  const defender = data.defender;
  checks.push(
    check({
      id: 'security-defender-status',
      category: 'security',
      title: 'Состояние Defender',
      status: 'info',
      summary: 'Локальная информация о встроенной защите. Это не оценка безопасности системы.',
      result: defender
        ? `Защита в реальном времени: ${defender.realTimeProtectionEnabled ? 'включена' : 'отключена'}.`
        : 'Не удалось получить состояние Defender.',
      evidence: [],
    }),
  );

  return { findings, checks };
}

module.exports = { loadSignatures, analyzeSecurity };
