'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');

test('release documentation matches the package version', () => {
  const version = require('../package.json').version;
  const changelog = read('CHANGELOG.md');
  const readme = read('README.md');

  assert.match(changelog, new RegExp(`## \\[${version.replace(/\./g, '\\.')}\\]`));
  assert.ok(readme.includes(`SteadyPC-Setup-${version}.exe`));
});

test('README describes local-only reporting and avoids confidence claims', () => {
  const readme = read('README.md');

  assert.ok(readme.includes('%APPDATA%\\SteadyPC\\logs\\steadypc.log'));
  assert.ok(readme.includes('Экспорт JSON'));
  assert.ok(readme.includes('Экспорт HTML'));
  assert.ok(readme.includes('авторская шкала'));
  assert.doesNotMatch(readme, /Уверенность: высокая/);
  assert.doesNotMatch(readme, /Уверенность \(`high`/);
});

test('security policy documents the new trust boundaries', () => {
  const policy = read('SECURITY.md');

  assert.ok(policy.includes('electron/validation.js'));
  assert.ok(policy.includes('Content Security Policy'));
  assert.ok(policy.includes('unsigned'));
});
