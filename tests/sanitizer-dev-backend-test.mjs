import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { DEV_BACKEND, devServerFetch } from '../src/build-flavor.ts';
import { shouldUseBackendProxy } from '../src/sample-io.ts';

// The Sample Sanitizer's community copy ships no development server, so its routes to one
// (`/api/pack-generator/*`) must be unreachable there. This file runs in both trees: the
// development repository (DEV_BACKEND true) and the generated community repo (false).

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** The sanitizer's own source files: a walk of relative imports from its entry point. */
function sanitizerSources() {
  const seen = new Set();
  const walk = file => {
    if (seen.has(file) || !existsSync(file)) return;
    seen.add(file);
    for (const m of readFileSync(file, 'utf8').matchAll(/from\s+['"](\.\.?\/[^'"]+)['"]/g)) {
      const base = resolve(dirname(file), m[1]);
      const hit = [base, `${base}.ts`, `${base}.tsx`].find(p => existsSync(p) && /\.tsx?$/.test(p));
      if (hit) walk(hit);
    }
  };
  walk(join(root, 'src', 'sanitizer-main.tsx'));
  return [...seen];
}

test('every development-server call in the sanitizer goes through devServerFetch or proxyFetch', () => {
  const direct = [];
  for (const file of sanitizerSources()) {
    readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
      if (/\bfetch\(\s*[`'"]\/api\/pack-generator/.test(line) && !/(devServerFetch|proxyFetch)\(/.test(line)) direct.push(`${file.slice(root.length + 1)}:${i + 1}`);
    });
  }
  assert.deepEqual(direct, []);
});

test('without the development server nothing reaches the network', async () => {
  const realFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response('{}', { status: 200 }); };
  try {
    const resp = await devServerFetch('/api/pack-generator/groups');
    assert.equal(called, DEV_BACKEND, 'only a build with the server calls fetch');
    if (!DEV_BACKEND) {
      assert.equal(resp.status, 404);
      assert.match((await resp.json()).error, /not part of this build/);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('standalone routes to the development server only when it exists', () => {
  assert.equal(shouldUseBackendProxy('standalone', 'anthropic'), DEV_BACKEND);
  assert.equal(shouldUseBackendProxy('iframe', 'anthropic'), false);
});

test('the sanitizer publish switches the development server off', async t => {
  const script = join(root, 'scripts', 'publish-sanitizer-dist.mjs');
  if (!existsSync(script)) { t.skip('publish script is not part of the community repo'); return; }
  const { applySanitizerRewrites } = await import(script);
  const dir = mkdtempSync(join(tmpdir(), 'sanitizer-rewrite-'));
  try {
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src', 'build-flavor.ts'), readFileSync(join(root, 'src', 'build-flavor.ts'), 'utf8'));
    applySanitizerRewrites(dir);
    const out = readFileSync(join(dir, 'src', 'build-flavor.ts'), 'utf8');
    assert.match(out, /export const DEV_BACKEND = false;/);
    assert.doesNotMatch(out, /export const DEV_BACKEND = true;/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
