'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { PRESETS, selectedForPreset, buildPreview, actionableFindings } = require('../electron/plan');

const findings = [
  {
    id: 'startup-1',
    title: 'Startup item',
    category: 'startup',
    risk: 'low',
    reversible: true,
    summary: 'Disable startup item',
    presets: ['balanced', 'performance'],
    action: {
      commandId: 'disable-startup',
      params: { name: 'Example' },
      requiresAdmin: false,
    },
  },
  {
    id: 'privacy-1',
    title: 'Information only',
    category: 'privacy',
    risk: 'low',
    reversible: false,
    summary: 'No action',
    presets: [],
    action: null,
  },
];

test('presets are unique and non-empty', () => {
  const ids = PRESETS.map((preset) => preset.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(ids.length > 0);
});

test('preset selection includes only actionable findings with matching preset', () => {
  assert.deepEqual(selectedForPreset(findings, 'balanced'), ['startup-1']);
  assert.deepEqual(selectedForPreset(findings, 'gaming'), []);
  assert.deepEqual(selectedForPreset(findings, 'none'), []);
  assert.deepEqual(selectedForPreset(findings, 'all'), ['startup-1']);
});

test('preview contains only requested actionable findings', () => {
  const preview = buildPreview(findings, ['startup-1', 'privacy-1', 'missing']);

  assert.equal(preview.length, 1);
  assert.equal(preview[0].id, 'startup-1');
  assert.equal(preview[0].commandId, 'disable-startup');
  assert.deepEqual(preview[0].params, { name: 'Example' });
});

test('actionableFindings filters out advisory findings', () => {
  assert.deepEqual(
    actionableFindings(findings).map((item) => item.id),
    ['startup-1'],
  );
});
