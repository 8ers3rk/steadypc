'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const {
  POWER_PLAN_KEYS,
  validateCommandParams,
  validatePresetId,
  validateIds,
  validateToolId,
  validateEntryId,
  validateSecurityPath,
  validateSecurityText,
} = require('../electron/validation');
const { PRESETS } = require('../electron/plan');
const { POWER_PLANS, listTools } = require('../electron/commands');

const startupFolder = path.join(
  process.env.APPDATA || 'C:\\Users\\tester\\AppData\\Roaming',
  'Microsoft',
  'Windows',
  'Start Menu',
  'Programs',
  'Startup',
  'Example.lnk',
);

const registryPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';

test('command parameter schemas match the command registry', () => {
  assert.deepEqual([...POWER_PLAN_KEYS].sort(), Object.keys(POWER_PLANS).sort());
});

test('valid command parameters are normalized', () => {
  assert.deepEqual(validateCommandParams('clean-temp', { maxAgeDays: '14' }), { maxAgeDays: 14 });
  assert.deepEqual(validateCommandParams('trim-ssd', { drive: 'd' }), { drive: 'D' });
  assert.deepEqual(validateCommandParams('set-power-plan', { plan: 'balanced' }), { plan: 'balanced' });
  assert.deepEqual(validateCommandParams('flush-dns', {}), {});
  assert.deepEqual(
    validateCommandParams('disable-startup', { source: 'registry', hive: 'HKCU', path: registryPath, name: 'Example' }),
    { source: 'registry', path: registryPath, name: 'Example' },
  );
  assert.deepEqual(
    validateCommandParams('disable-startup', { source: 'folder', path: startupFolder, name: 'Example' }),
    { source: 'folder', path: startupFolder, name: 'Example' },
  );
});

test('command parameters reject injection and out-of-range values', () => {
  assert.throws(() => validateCommandParams('unknown-command', {}), /Неизвестная команда/);
  assert.throws(() => validateCommandParams('clean-temp', { maxAgeDays: 99999 }), /Возраст файлов/);
  assert.throws(() => validateCommandParams('trim-ssd', { drive: "C'; calc" }), /диска/);
  assert.throws(() => validateCommandParams('set-power-plan', { plan: "balanced'; calc" }), /план питания/i);
  assert.throws(() => validateCommandParams('flush-dns', { unexpected: 'value' }), /Недопустимый параметр/);
  assert.throws(
    () => validateCommandParams('disable-startup', { source: 'registry', hive: 'HKCU', path: 'HKCU:\\Evil', name: 'x' }),
    /не разрешён/,
  );
  assert.throws(
    () => validateCommandParams('disable-startup', { source: 'folder', path: 'C:\\Temp\\evil.lnk', name: 'x' }),
    /вне папки автозагрузки/,
  );
  assert.throws(
    () => validateCommandParams('disable-startup', { source: 'registry', hive: 'HKCU', path: registryPath, name: "x'; calc" }),
    /имя записи/i,
  );
  assert.throws(
    () => validateCommandParams('disable-startup', { source: 'registry', hive: 'HKLM', path: registryPath, name: 'x' }),
    /не совпадает/,
  );
});

test('preset, plan and tool identifiers are restricted to known values', () => {
  assert.equal(validatePresetId('balanced', PRESETS), 'balanced');
  assert.equal(validatePresetId('none', PRESETS), 'none');
  assert.throws(() => validatePresetId('drop-table', PRESETS), /Неизвестный пресет/);

  assert.deepEqual(validateIds(['startup-1', 'storage-2'], ['startup-1', 'storage-2']), ['startup-1', 'storage-2']);
  assert.throws(() => validateIds('startup-1', ['startup-1']), /список идентификаторов/);
  assert.throws(() => validateIds(['missing'], ['startup-1']), /не найден/);
  assert.throws(() => validateIds(['a', 'a'], ['a']), /повторяется/);

  const tools = listTools();
  assert.equal(validateToolId('clean-temp', tools), 'clean-temp');
  assert.throws(() => validateToolId('shutdown', tools), /Неизвестный инструмент/);
});

test('journal identifiers and safe actions reject malformed input', () => {
  const id = '0b1d3a20-6f1c-4e2b-8a4d-3f2c1b0a9d8e';
  assert.equal(validateEntryId(id), id);
  assert.throws(() => validateEntryId('../../journal'), /идентификатор записи/i);

  assert.equal(validateSecurityPath('C:\\Users\\Public\\file.exe'), 'C:\\Users\\Public\\file.exe');
  assert.throws(() => validateSecurityPath('..\\Windows\\file.exe'), /Некорректный путь/);
  assert.throws(() => validateSecurityPath('C:\\Temp\\file.exe\u0000'), /символы/);
  assert.equal(validateSecurityText('PID: 42\nПуть: C:\\file.exe'), 'PID: 42\nПуть: C:\\file.exe');
  assert.throws(() => validateSecurityText('x'.repeat(9000)), /слишком длинное/);
});
