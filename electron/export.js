'use strict';

const fs = require('fs');
const path = require('path');
const { readJournal } = require('./journal');
const { logPath } = require('./log');

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function downloadsDir(app) {
  try {
    return app.getPath('downloads');
  } catch (error) {
    return app.getPath('userData');
  }
}

function createExportName(stamp) {
  return `SteadyPC-report-${stamp}.json`;
}

function writeTextFile(filePath, content) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath) || filePath.length > 512) {
    throw new Error('Недопустимый путь экспорта');
  }
  if (/[\u0000-\u001f]/.test(filePath)) throw new Error('Недопустимый путь экспорта');

  const normalized = path.resolve(filePath);
  fs.mkdirSync(path.dirname(normalized), { recursive: true });
  fs.writeFileSync(normalized, content, 'utf8');
  return normalized;
}

function buildHtml(payload) {
  const score = payload.report?.score?.value ?? '—';
  const findings = Array.isArray(payload.report?.findings) ? payload.report.findings.length : 0;
  const checks = Array.isArray(payload.report?.checks) ? payload.report.checks.length : 0;
  const warnings = (payload.report?.warnings || []).map((item) => `<li>${escapeHtml(item)}</li>`).join('');
  const findingRows = (Array.isArray(payload.report?.findings) ? payload.report.findings : [])
    .slice(0, 200)
    .map(
      (item) =>
        `<tr><td>${escapeHtml(item.id || '')}</td><td>${escapeHtml(item.title || '')}</td><td>${escapeHtml(item.category || '')}</td><td>${escapeHtml(item.risk || item.severity || '')}</td><td>${escapeHtml(item.summary || '')}</td></tr>`,
    )
    .join('');
  const journalRows = (payload.journal || [])
    .slice(0, 200)
    .map(
      (entry) =>
        `<tr><td>${escapeHtml(entry.createdAt || '')}</td><td>${escapeHtml(entry.title || '')}</td><td>${escapeHtml(entry.risk || '')}</td><td>${escapeHtml(entry.rolledBackAt ? 'rolled-back' : 'applied')}</td></tr>`,
    )
    .join('');

  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SteadyPC report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#111;background:#fff;line-height:1.45}
h1,h2{margin:0 0 12px} .muted{color:#555} .card{border:1px solid #ddd;border-radius:10px;padding:16px;margin:16px 0}
table{width:100%;border-collapse:collapse} th,td{border-bottom:1px solid #eee;padding:8px;text-align:left;font-size:13px;vertical-align:top}
code{background:#f5f5f5;padding:2px 4px;border-radius:4px}
</style>
</head>
<body>
<h1>SteadyPC report</h1>
<p class="muted">Exported: ${escapeHtml(payload.exportedAt || '')}</p>
<div class="card">
<h2>Scan</h2>
<p>Score: <strong>${escapeHtml(score)}</strong></p>
<p>Findings: ${escapeHtml(findings)} · Checks: ${escapeHtml(checks)}</p>
<p>Scanned at: ${escapeHtml(payload.report?.scannedAt || '—')}</p>
<p class="muted">The score is an author-made scale for the settings found, not a Windows health measurement.</p>
</div>
<div class="card">
<h2>Findings</h2>
<table><thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Risk</th><th>Summary</th></tr></thead><tbody>${findingRows || '<tr><td colspan="5" class="muted">No findings.</td></tr>'}</tbody></table>
<p class="muted">Risk indicators are not an antivirus. SteadyPC does not delete files or terminate processes.</p>
</div>
<div class="card">
<h2>Warnings</h2>
${warnings ? `<ul>${warnings}</ul>` : '<p class="muted">No warnings.</p>'}
</div>
<div class="card">
<h2>Journal</h2>
<table><thead><tr><th>Time</th><th>Action</th><th>Risk</th><th>Status</th></tr></thead><tbody>${journalRows || '<tr><td colspan="4" class="muted">No journal entries.</td></tr>'}</tbody></table>
</div>
<p class="muted">Local report only. No data was sent anywhere.</p>
</body>
</html>`;
}

function exportReport(app, { report, comparison, format = 'json', language = 'ru', targetPath }) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const ext = format === 'html' ? 'html' : 'json';
  const filePath = targetPath || path.join(downloadsDir(app), createExportName(stamp).replace(/\.json$/, `.${ext}`));

  const payload = {
    exportedAt: new Date().toISOString(),
    appVersion: require('../package.json').version,
    language,
    logPath: logPath(app),
    report: report || null,
    comparison: comparison || null,
    journal: readJournal(app),
  };

  const content = ext === 'html' ? buildHtml(payload) : JSON.stringify(payload, null, 2);
  const written = writeTextFile(filePath, content);
  return { path: written, format: ext };
}

module.exports = { exportReport, buildHtml, createExportName };
