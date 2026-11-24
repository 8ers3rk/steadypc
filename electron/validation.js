'use strict';

const path = require('path');

const POWER_PLAN_KEYS = new Set(['balanced', 'high', 'saver']);

const STARTUP_REGISTRY_PATHS = new Set([
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
]);

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/;
const TEXT_CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/;
const WINDOWS_PATH = /^[A-Za-z]:\\/;
const WINDOWS_PATH_FORBIDDEN = /[*?"<>|]|\.\./;
const SAFE_NAME = /^[^\\/:*?"<>|;'$`\r\n]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_ID = /^[a-z0-9][a-z0-9._:-]{0,127}$/i;

function fail(message) {
  throw new Error(message);
}

function plainText(value, maxLength, label, multiline = false) {
  if (typeof value !== 'string') fail(`${label}: ожидается строка`);
  const text = value.trim();
  if (!text) fail(`${label}: значение пусто`);
  if (text.length > maxLength) fail(`${label}: слишком длинное значение`);
  const forbidden = multiline ? TEXT_CONTROL_CHARACTERS : CONTROL_CHARACTERS;
  if (forbidden.test(text)) fail(`${label}: недопустимые символы`);
  return text;
}

function ownKeys(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value) : [];
}

function assertOnlyKeys(params, allowed) {
  const allowedKeys = new Set(allowed);
  for (const key of ownKeys(params)) {
    if (!allowedKeys.has(key)) fail(`Недопустимый параметр: ${key}`);
  }
}

function integerInRange(value, min, max, label) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) {
    fail(`${label}: ожидается целое число от ${min} до ${max}`);
  }
  return number;
}

function startupFolderRoots() {
  const roots = [];
  if (process.env.APPDATA) {
    roots.push(path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'));
  }
  roots.push('C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup');
  return roots.map((root) => root.replace(/\//g, '\\').toLowerCase());
}

function validateStartupParams(params) {
  assertOnlyKeys(params, ['source', 'hive', 'path', 'name']);
  const source = plainText(params.source, 16, 'Источник');
  const name = plainText(params.name, 256, 'Имя записи');
  const target = plainText(params.path, 512, 'Путь');
  if (!SAFE_NAME.test(name)) fail('Недопустимое имя записи автозагрузки');
  if (source !== 'folder' && source !== 'registry') fail('Неизвестный источник автозагрузки');

  if (source === 'folder') {
    if (!WINDOWS_PATH.test(target) || WINDOWS_PATH_FORBIDDEN.test(target)) {
      fail('Недопустимый путь ярлыка автозагрузки');
    }
    if (!/\.lnk$/i.test(target)) fail('Путь должен указывать на ярлык автозагрузки');
    const normalized = target.toLowerCase();
    const allowedRoot = startupFolderRoots().some(
      (root) => normalized === root || normalized.startsWith(`${root}\\`),
    );
    if (!allowedRoot) fail('Ярлык находится вне папки автозагрузки');
  } else {
    if (!STARTUP_REGISTRY_PATHS.has(target)) fail('Путь реестра не разрешён');
    const hive = plainText(params.hive, 8, 'Раздел реестра');
    if (hive !== 'HKCU' && hive !== 'HKLM') fail('Неизвестный раздел реестра');
    if (!target.startsWith(`${hive}:\\`)) fail('Раздел реестра не совпадает с путём');
  }

  return { source, path: target, name };
}

function validateCommandParams(commandId, params) {
  const values = params && typeof params === 'object' && !Array.isArray(params) ? params : {};
  if (commandId === 'disable-startup') return validateStartupParams(values);

  switch (commandId) {
    case 'clean-temp':
    case 'clear-update-cache':
      assertOnlyKeys(values, ['maxAgeDays']);
      return { maxAgeDays: integerInRange(values.maxAgeDays, 1, 3650, 'Возраст файлов') };

    case 'trim-ssd':
    case 'defrag-hdd': {
      assertOnlyKeys(values, ['drive']);
      const drive = plainText(values.drive || 'C', 1, 'Буква диска');
      if (!/^[A-Za-z]$/.test(drive)) fail('Недопустимая буква диска');
      return { drive: drive.toUpperCase() };
    }

    case 'set-power-plan': {
      assertOnlyKeys(values, ['plan']);
      const plan = plainText(values.plan, 16, 'План питания');
      if (!POWER_PLAN_KEYS.has(plan)) fail('Неизвестный план питания');
      return { plan };
    }

    case 'flush-dns':
    case 'reset-tcp-autotuning':
    case 'set-visual-effects':
      assertOnlyKeys(values, []);
      return {};

    default:
      fail(`Неизвестная команда: ${commandId}`);
  }
}

function validatePresetId(value, presets) {
  const id = plainText(value, 32, 'Пресет');
  const known = new Set([...presets.map((preset) => preset.id), 'none', 'all']);
  if (!known.has(id)) fail('Неизвестный пресет');
  return id;
}

function validateIds(value, allowedIds, max = 200) {
  if (!Array.isArray(value)) fail('Ожидается список идентификаторов');
  if (value.length > max) fail('Слишком много идентификаторов');
  const allowed = new Set(allowedIds);
  const result = [];
  for (const item of value) {
    const id = plainText(item, 128, 'Идентификатор');
    if (!SAFE_ID.test(id)) fail('Недопустимый идентификатор');
    if (!allowed.has(id)) fail('Идентификатор не найден в отчёте');
    if (result.includes(id)) fail('Идентификатор повторяется');
    result.push(id);
  }
  return result;
}

function validateToolId(value, tools) {
  const id = plainText(value, 64, 'Инструмент');
  if (!SAFE_ID.test(id) || !tools.some((tool) => tool.id === id)) fail('Неизвестный инструмент');
  return id;
}

function validateEntryId(value) {
  const id = plainText(value, 64, 'Запись журнала');
  if (!UUID.test(id)) fail('Некорректный идентификатор записи');
  return id;
}

function validateSecurityPath(value, maxLength = 512) {
  const text = plainText(value, maxLength, 'Путь');
  if (!WINDOWS_PATH.test(text) || WINDOWS_PATH_FORBIDDEN.test(text)) {
    fail('Некорректный путь для безопасного действия');
  }
  if (/[. ]$/.test(text)) fail('Некорректный путь для безопасного действия');
  return text;
}

function validateSecurityText(value, maxLength = 8192) {
  return plainText(value, maxLength, 'Текст', true);
}

module.exports = {
  POWER_PLAN_KEYS,
  STARTUP_REGISTRY_PATHS,
  validateCommandParams,
  validatePresetId,
  validateIds,
  validateToolId,
  validateEntryId,
  validateSecurityPath,
  validateSecurityText,
};
