'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeRegistryHive, buildStartupAction } = require('../electron/collectors');
const { validateCommandParams } = require('../electron/validation');

const HKCU_RUN = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
const HKLM_RUN = 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
const ONE_DRIVE_STARTUP = 'C:\\Users\\tester\\OneDrive\\Microsoft\\Windows\\Start Menu\\Programs\\Startup';

test('collector normalizes registry hives that include a trailing colon', () => {
  assert.equal(normalizeRegistryHive('HKCU:'), 'HKCU');
  assert.equal(normalizeRegistryHive('HKLM:'), 'HKLM');
  assert.equal(normalizeRegistryHive('HKCU'), 'HKCU');
});

test('registry startup actions from the collector pass command validation', () => {
  const cases = [
    ['HKCU:', HKCU_RUN, false],
    ['HKLM:', HKLM_RUN, true],
  ];

  for (const [hive, registryPath, requiresAdmin] of cases) {
    const action = buildStartupAction({
      source: 'registry',
      hive,
      path: registryPath,
      name: "Example's app",
    });

    assert.equal(action.requiresAdmin, requiresAdmin);
    assert.deepEqual(validateCommandParams('disable-startup', action.params), {
      source: 'registry',
      path: registryPath,
      name: "Example's app",
    });
  }
});

test('folder startup actions keep the real startup root from the collector', () => {
  const target = `${ONE_DRIVE_STARTUP}\\Example.lnk`;
  const action = buildStartupAction({
    source: 'folder',
    hive: 'HKCU',
    path: target,
    name: 'Example',
    location: ONE_DRIVE_STARTUP,
  });

  assert.deepEqual(validateCommandParams('disable-startup', action.params), {
    source: 'folder',
    path: target,
    name: 'Example',
  });
});
