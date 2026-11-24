'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

function policy() {
  const match = html.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/);
  assert.ok(match, 'CSP meta tag is missing');
  return match[1];
}

test('CSP blocks external scripts, frames, objects and network destinations', () => {
  const csp = policy();

  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self' 'sha256-[A-Za-z0-9+/=]+'/);
  assert.match(csp, /style-src 'self' 'unsafe-inline'/);
  assert.match(csp, /img-src 'self' data:/);
  assert.match(csp, /font-src 'self'/);
  assert.match(csp, /worker-src 'none'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /frame-src 'none'/);
  assert.match(csp, /form-action 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.doesNotMatch(csp, /unsafe-eval/);
  assert.doesNotMatch(csp, /https?:\/\//);
  assert.match(csp, /connect-src 'self' ws:\/\/127\.0\.0\.1:\* ws:\/\/localhost:\*/);
});

test('CSP script hash matches the inline theme script', () => {
  const csp = policy();
  const script = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(script, 'inline theme script is missing');

  const hash = crypto.createHash('sha256').update(script[1], 'utf8').digest('base64');
  assert.ok(csp.includes(`'sha256-${hash}'`));
});
