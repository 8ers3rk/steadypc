'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const content = require('../src/faq-content.json');

const REQUIRED_SECTIONS = ['about', 'expectations', 'claims', 'indicators', 'not-antivirus', 'signatures'];
const BRANDS = ['norton', 'mcafee', 'kaspersky', 'avast', 'avg', 'iobit', 'ccleaner', 'glary', 'wise cleaner'];

for (const lang of ['ru', 'en']) {
  test(`FAQ ${lang} covers the promised topics`, () => {
    assert.ok(Array.isArray(content[lang]), `FAQ for ${lang} must be an array`);

    const ids = content[lang].map((section) => section.id);
    for (const id of REQUIRED_SECTIONS) {
      assert.ok(ids.includes(id), `FAQ ${lang} is missing the section "${id}"`);
    }

    for (const section of content[lang]) {
      assert.ok(section.title && section.title.length > 3);
      assert.ok(Array.isArray(section.items) && section.items.length >= 2);
      assert.ok(section.items.every((item) => typeof item === 'string' && item.length > 10));
    }
  });

  test(`FAQ ${lang} has no external links or antivirus brand names`, () => {
    const text = JSON.stringify(content[lang]).toLowerCase();
    assert.equal(/https?:\/\//.test(text), false, 'FAQ must work fully offline');
    for (const brand of BRANDS) {
      assert.equal(text.includes(brand), false, `FAQ ${lang} must not mention ${brand}`);
    }
  });
}
