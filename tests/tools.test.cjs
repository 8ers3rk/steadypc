'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { listTools, commands } = require('../electron/commands');
const { check } = require('../electron/collectors');

test('listTools exposes implemented commands only', () => {
  const tools = listTools();
  const ids = tools.map((tool) => tool.id);

  assert.equal(new Set(ids).size, ids.length);
  assert.ok(tools.length >= 8);
  for (const tool of tools) {
    assert.ok(commands[tool.id], `unknown command: ${tool.id}`);
    assert.ok(tool.title);
    assert.ok(tool.description);
    assert.ok(['low', 'medium', 'high'].includes(tool.risk));
    assert.equal(typeof tool.reversible, 'boolean');
    assert.equal(typeof tool.requiresAdmin, 'boolean');
  }
});

test('disk-specific tools are marked for the right media type', () => {
  const tools = listTools();
  const byId = new Map(tools.map((tool) => [tool.id, tool]));

  assert.equal(byId.get('trim-ssd').diskType, 'ssd');
  assert.equal(byId.get('defrag-hdd').diskType, 'hdd');
  assert.equal(byId.get('clean-temp').diskType, 'any');
  assert.equal(byId.get('disable-startup').requiresSelection, true);
});

test('check produces a complete status record', () => {
  const item = check({
    id: 'storage-temp',
    category: 'storage',
    title: 'Temporary files',
    status: 'ok',
    summary: 'Checked old files',
    result: 'Nothing found',
    evidence: ['C:\\Temp'],
  });

  assert.deepEqual(item, {
    id: 'storage-temp',
    category: 'storage',
    title: 'Temporary files',
    status: 'ok',
    summary: 'Checked old files',
    result: 'Nothing found',
    evidence: ['C:\\Temp'],
  });
  assert.deepEqual(check({ id: 'x' }).evidence, []);
  assert.equal(check({ id: 'x' }).status, 'ok');
});
