'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { scoreFindings, CATEGORY_CAP } = require('../electron/scoring');

function fakeFinding(category, severity, id) {
  return { id: id || `${category}-${severity}`, category, severity };
}

test('empty scan produces a perfect score', () => {
  const result = scoreFindings([]);
  assert.equal(result.value, 100);
  assert.equal(result.status, 'excellent');
  assert.equal(result.penalty, 0);
});

test('findings are capped per category', () => {
  const findings = Array.from({ length: 8 }, (_, index) => fakeFinding('startup', 'high', `startup-${index}`));
  const result = scoreFindings(findings);
  const startup = result.breakdown.find((item) => item.category === 'startup');

  assert.equal(startup.raw, 8 * 14);
  assert.equal(startup.applied, CATEGORY_CAP.startup);
  assert.equal(startup.capped, true);
});

test('score never drops below the configured floor', () => {
  const categories = Object.keys(CATEGORY_CAP);
  const findings = categories.flatMap((category) =>
    Array.from({ length: 4 }, (_, index) => fakeFinding(category, 'high', `${category}-${index}`)),
  );
  const result = scoreFindings(findings);

  assert.ok(result.value >= 10 && result.value <= 20);
  assert.equal(result.status, 'poor');
});

test('breakdown is sorted by applied penalty', () => {
  const findings = [
    fakeFinding('privacy', 'low'),
    fakeFinding('storage', 'high'),
    fakeFinding('power', 'medium'),
  ];
  const result = scoreFindings(findings);

  assert.deepEqual(
    result.breakdown.map((item) => item.applied),
    [...result.breakdown.map((item) => item.applied)].sort((a, b) => b - a),
  );
});
