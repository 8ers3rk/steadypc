'use strict';

const fs = require('fs');
const path = require('path');

const MAX_LOG_FILES = 10;
const MAX_LOG_BYTES = 1024 * 1024;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g;

function logPath(app) {
  return path.join(app.getPath('userData'), 'logs', 'steadypc.log');
}

function safeValue(value, depth = 0) {
  if (depth > 4) return '[truncated]';
  if (typeof value === 'string') {
    return value.replace(CONTROL_CHARACTERS, ' ').slice(0, 600);
  }
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 30).map((item) => safeValue(item, depth + 1));
  if (value && typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value).slice(0, 40)) {
      result[safeValue(key, depth + 1)] = safeValue(item, depth + 1);
    }
    return result;
  }
  return String(value).slice(0, 600);
}

function rotate(file) {
  for (let index = MAX_LOG_FILES - 1; index >= 1; index -= 1) {
    const from = index === 1 ? file : `${file}.${index - 1}`;
    const to = `${file}.${index}`;
    if (fs.existsSync(from)) fs.renameSync(from, to);
  }
}

function appendLog(app, level, event, details = {}) {
  const file = logPath(app);
  fs.mkdirSync(path.dirname(file), { recursive: true });

  try {
    if (fs.statSync(file).size > MAX_LOG_BYTES) rotate(file);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const record = {
    at: new Date().toISOString(),
    level: ['info', 'warn', 'error'].includes(level) ? level : 'info',
    event: safeValue(event),
    ...safeValue(details),
  };
  fs.appendFileSync(file, `${JSON.stringify(record)}\n`, 'utf8');
  return record;
}

module.exports = { logPath, appendLog, safeValue, MAX_LOG_FILES, MAX_LOG_BYTES };
