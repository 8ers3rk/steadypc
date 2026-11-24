'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function journalPath(app) {
  return path.join(app.getPath('userData'), 'journal.json');
}

function readJournal(app) {
  const file = journalPath(app);
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return Array.isArray(parsed.entries) ? parsed.entries : [];
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    return [];
  }
}

function writeJournal(app, entries) {
  const file = journalPath(app);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temp, JSON.stringify({ version: 1, entries }, null, 2), 'utf8');
  fs.renameSync(temp, file);
}

function addEntry(app, entry) {
  const entries = readJournal(app);
  const record = {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    rolledBackAt: null,
    ...entry,
  };
  entries.unshift(record);
  writeJournal(app, entries.slice(0, 200));
  return record;
}

function markRolledBack(app, id) {
  const entries = readJournal(app);
  const entry = entries.find((item) => item.id === id);
  if (!entry) return null;
  entry.rolledBackAt = new Date().toISOString();
  writeJournal(app, entries);
  return entry;
}

module.exports = { readJournal, addEntry, markRolledBack };
