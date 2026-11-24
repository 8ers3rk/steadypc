'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { appendLog, logPath, MAX_LOG_BYTES } = require('../electron/log');
const { exportReport, buildHtml } = require('../electron/export');
const { validateExportFormat, validateLanguage } = require('../electron/validation');

function tempApp() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'steadypc-report-'));
  const userData = path.join(root, 'userData');
  const downloads = path.join(root, 'downloads');
  fs.mkdirSync(userData, { recursive: true });
  fs.mkdirSync(downloads, { recursive: true });
  return {
    root,
    getPath: (name) => (name === 'downloads' ? downloads : userData),
  };
}

const report = {
  scannedAt: '2026-11-24T10:00:00.000Z',
  score: { value: 82, status: 'good', penalty: 18, breakdown: [] },
  findings: [{ id: 'startup-1', title: 'Startup item', category: 'startup', severity: 'low' }],
  checks: [{ id: 'storage-temp', status: 'ok', title: 'Temporary files', result: 'Empty' }],
  warnings: ['Signature file was ignored'],
};

test('local logs are structured, sanitized and contain no raw control characters', () => {
  const app = tempApp();
  appendLog(app, 'info', 'scan:complete', { findings: 1, title: 'line\nbreak\u0000value' });

  const lines = fs.readFileSync(logPath(app), 'utf8').trim().split('\n');
  const entry = JSON.parse(lines[0]);

  assert.equal(entry.level, 'info');
  assert.equal(entry.event, 'scan:complete');
  assert.equal(entry.findings, 1);
  assert.match(entry.title, /line break/);
  assert.doesNotMatch(entry.title, /[\u0000]/);
  assert.ok(Number.isNaN(Date.parse(entry.at)) === false);
});

test('logs rotate after exceeding the size limit', () => {
  const app = tempApp();
  const file = logPath(app);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, 'x'.repeat(MAX_LOG_BYTES + 1), 'utf8');

  appendLog(app, 'warn', 'rotate:check');

  assert.ok(fs.existsSync(`${file}.1`));
  assert.equal(fs.readFileSync(`${file}.1`, 'utf8').startsWith('x'), true);
  assert.match(fs.readFileSync(file, 'utf8'), /rotate:check/);
});

test('JSON export writes a self-contained report with the local journal', () => {
  const app = tempApp();
  const result = exportReport(app, { report, format: 'json' });

  assert.equal(result.format, 'json');
  assert.equal(path.dirname(result.path), path.join(app.root, 'downloads'));
  const payload = JSON.parse(fs.readFileSync(result.path, 'utf8'));
  assert.equal(payload.report.score.value, 82);
  assert.equal(payload.report.findings.length, 1);
  assert.deepEqual(payload.journal, []);
  assert.ok(payload.exportedAt);
  assert.equal(payload.appVersion, require('../package.json').version);
});

test('HTML export escapes untrusted text and contains no external resources', () => {
  const hostile = {
    ...report,
    warnings: ['<script>alert(1)</script>'],
    findings: [{ ...report.findings[0], title: '"quoted" & <tag>' }],
  };
  const comparison = {
    before: report,
    after: { ...report, score: { ...report.score, value: 91 } },
    results: [{ id: 'startup-1', title: '<result>', success: true, message: 'done' }],
    restorePoint: { success: true },
  };
  const html = buildHtml({
    report: hostile,
    comparison,
    language: 'en',
    logPath: 'C:\\Users\\tester\\AppData\\Roaming\\SteadyPC\\logs\\steadypc.log',
    journal: [{ createdAt: 'now', title: '<bad>', risk: 'low' }],
  });

  assert.match(html, /<html lang="en">/);
  assert.match(html, /Log path: C:\\Users\\tester\\AppData\\Roaming\\SteadyPC\\logs\\steadypc\.log/);
  assert.match(html, /<h2>Comparison<\/h2>/);
  assert.match(html, /Score before: 82 · after: 91/);
  assert.match(html, /&lt;result&gt;/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&quot;quoted&quot; &amp; &lt;tag&gt;/);
  assert.doesNotMatch(html, /https?:\/\//);
  assert.match(html, /Local report only/);
});

test('export options are restricted to supported formats and languages', () => {
  assert.equal(validateExportFormat('json'), 'json');
  assert.equal(validateExportFormat('html'), 'html');
  assert.throws(() => validateExportFormat('exe'), /формат экспорта/i);
  assert.equal(validateLanguage('ru'), 'ru');
  assert.equal(validateLanguage('en'), 'en');
  assert.throws(() => validateLanguage('de'), /язык/i);
});
