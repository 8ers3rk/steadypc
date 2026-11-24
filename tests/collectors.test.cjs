'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { formatBytes } = require('../electron/collectors');

test('formatBytes handles empty and small values', () => {
  assert.equal(formatBytes(0), '0 Б');
  assert.equal(formatBytes(-10), '0 Б');
  assert.equal(formatBytes(512), '512 Б');
});

test('formatBytes uses expected units', () => {
  assert.equal(formatBytes(1024), '1 КБ');
  assert.equal(formatBytes(2 * 1024 ** 2), '2 МБ');
  assert.equal(formatBytes(3 * 1024 ** 3), '3 ГБ');
});
