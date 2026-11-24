'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const policies = require('../csp.json');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const viteConfig = fs.readFileSync(path.join(root, 'vite.config.js'), 'utf8');

test('the HTML template uses a build-time CSP placeholder', () => {
  assert.match(html, /__STEADYPC_CSP__/);
  assert.doesNotMatch(html, /ws:\/\/127\.0\.0\.1/);
});

test('production CSP has no network or local WebSocket destinations', () => {
  const csp = policies.prod;

  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self' 'sha256-[A-Za-z0-9+/=]+'/);
  assert.match(csp, /style-src 'self' 'unsafe-inline'/);
  assert.match(csp, /img-src 'self' data:/);
  assert.match(csp, /font-src 'self'/);
  assert.match(csp, /connect-src 'none'/);
  assert.match(csp, /worker-src 'none'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /frame-src 'none'/);
  assert.match(csp, /form-action 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.doesNotMatch(csp, /unsafe-eval/);
  assert.doesNotMatch(csp, /https?:\/\//);
  assert.doesNotMatch(csp, /ws:\/\//);
});

test('development CSP allows only the local Vite WebSocket', () => {
  assert.match(policies.dev, /connect-src 'self' ws:\/\/127\.0\.0\.1:\* ws:\/\/localhost:\*/);
});

test('both policies hash the inline theme script', () => {
  const script = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(script, 'inline theme script is missing');

  const hash = crypto.createHash('sha256').update(script[1], 'utf8').digest('base64');
  for (const [name, csp] of Object.entries(policies)) {
    assert.ok(csp.includes(`'sha256-${hash}'`), `${name} CSP is missing the theme script hash`);
  }
});

test('Vite replaces the placeholder with the prod policy outside dev mode', () => {
  assert.match(viteConfig, /command === 'serve'/);
  assert.match(viteConfig, /csp\.dev/);
  assert.match(viteConfig, /csp\.prod/);
  assert.match(viteConfig, /__STEADYPC_CSP__/);
});
