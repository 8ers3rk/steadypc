'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');

const HANDLE = '8ers3rk';

test('build metadata carries the GitHub handle', () => {
  const pkg = require('../package.json');
  const builder = JSON.parse(read('electron-builder.json'));

  assert.equal(pkg.author, HANDLE);
  assert.ok(builder.copyright.includes(HANDLE));
  assert.ok(read('LICENSE').includes(HANDLE));
});

test('the handle is visible in both languages and in the layout', () => {
  const i18n = read('src/i18n.ts');
  const layout = read('src/components/Layout.tsx');

  assert.match(i18n, /'footer\.author': 'Автор: @8ers3rk'/);
  assert.match(i18n, /'footer\.author': 'Author: @8ers3rk'/);
  assert.match(layout, /t\('footer\.author'\)/);
});

test('documentation and built-in FAQ identify the author', () => {
  const readme = read('README.md');
  const faq = JSON.parse(read('src/faq-content.json'));

  assert.ok(readme.includes(`@${HANDLE}`));
  for (const lang of ['ru', 'en']) {
    assert.ok(
      faq[lang]
        .find((section) => section.id === 'about')
        .items.some((item) => item.includes(`@${HANDLE}`)),
      `FAQ ${lang} is missing the author handle`,
    );
  }
});
