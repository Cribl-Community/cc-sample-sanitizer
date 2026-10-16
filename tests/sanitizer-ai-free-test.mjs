import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

// The Sample Sanitizer is a second build target of this repo (sanitizer.html →
// src/sanitizer-main.tsx) and MUST stay provably free of AI usage — no provider
// clients, no budget/dispatch logic, no schematizer. That is a property of the
// SOURCE import graph reachable from the sanitizer entry, not a substring scan: a
// `provider` string or a `devProxyUrl` default living in settings-store.ts is fine;
// an `import … from './ai-client'` anywhere in the reachable set is not.
//
// This walk is multi-line-import safe (anchored on `from '…'`, not a same-line
// regex) — an earlier hand-rolled walker missed sanitize-wizard's multi-line import
// and gave a false all-clear. It follows static, dynamic and side-effect imports.

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, '..', 'src');
const ENTRY = resolve(SRC, 'sanitizer-main.tsx');

// Relative modules that carry executable AI code. ai-samples.ts is deliberately NOT
// here — despite the name it is a pure data module (sourcetype catalog + curated
// fallback samples, zero imports) and is a legitimate sanitiser sample tier.
const FORBIDDEN_LOCAL = /\/src\/(ai-client|ai-budget)\.[jt]sx?$/;
// Bare specifiers for LLM provider SDKs — none of these belong in the sanitizer.
const FORBIDDEN_PKG = /^(@anthropic-ai\/|@google\/gen|@google\/generative|openai$|openai\/|@mistralai\/|mistral$)/;

function importSpecs(src) {
  const out = [];
  for (const m of src.matchAll(/\bfrom\s*["']([^"']+)["']/g)) out.push(m[1]);       // import/export … from '…'
  for (const m of src.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/g)) out.push(m[1]); // dynamic import('…')
  for (const m of src.matchAll(/\bimport\s+["']([^"']+)["']/g)) out.push(m[1]);      // side-effect import '…'
  return out;
}

function reachable(entry) {
  const seen = new Set();
  const violations = [];
  const walk = (file, importer) => {
    if (seen.has(file)) return;
    seen.add(file);
    if (FORBIDDEN_LOCAL.test(file)) {
      violations.push(`${relative(SRC, file)} (imported by ${importer ? relative(SRC, importer) : 'entry'})`);
    }
    let src;
    try { src = readFileSync(file, 'utf8'); } catch { return; }
    for (const spec of importSpecs(src)) {
      if (!spec.startsWith('.')) {
        if (FORBIDDEN_PKG.test(spec)) {
          violations.push(`${relative(SRC, file)} imports provider SDK "${spec}"`);
        }
        continue;
      }
      const base = resolve(dirname(file), spec);
      for (const c of [base, base + '.ts', base + '.tsx', base + '/index.ts', base + '/index.tsx']) {
        try { readFileSync(c); walk(c, file); break; } catch { /* try next candidate */ }
      }
    }
  };
  walk(entry, null);
  return { seen, violations };
}

test('the sanitizer entry reaches NO ai-client / ai-budget / provider SDK', () => {
  const { seen, violations } = reachable(ENTRY);
  assert.ok(seen.size > 5, `walk should reach the sanitiser graph, got ${seen.size} files`);
  assert.deepEqual(violations, [], `sanitizer must stay AI-free; found:\n  ${violations.join('\n  ')}`);
});

test('the walk actually reaches the sanitise wizard (guards against a broken walker)', () => {
  const { seen } = reachable(ENTRY);
  const names = [...seen].map((f) => relative(SRC, f));
  for (const must of ['sanitize-wizard.tsx', 'sample-io.ts', 'sanitised-sample-workflow.ts']) {
    assert.ok(names.includes(must), `expected the walk to reach ${must}`);
  }
});

test('sanitizer settings do not reach background batch orchestration', () => {
  const { seen } = reachable(ENTRY);
  const names = [...seen].map((f) => relative(SRC, f));
  assert.ok(names.includes('settings-store.ts'), 'guard must inspect the shared settings store');
  assert.ok(
    !names.includes('background-batch.ts'),
    'settings-store must own the AI snapshot type instead of importing background orchestration',
  );
});

test('a planted ai-client import in a reached file WOULD be caught (walker is not vacuous)', () => {
  // Mutation check: prove the detector fires. sample-io.ts is reached; a relative
  // import of ./ai-client from it must be flagged. We test the matcher directly
  // rather than editing a file on disk.
  assert.match(resolve(SRC, 'ai-client.ts'), FORBIDDEN_LOCAL);
  assert.match(resolve(SRC, 'ai-budget.ts'), FORBIDDEN_LOCAL);
  assert.ok(!FORBIDDEN_LOCAL.test(resolve(SRC, 'ai-samples.ts')), 'ai-samples is data, must not be forbidden');
  assert.match('@anthropic-ai/sdk', FORBIDDEN_PKG);
  assert.match('@google/genai', FORBIDDEN_PKG);
  assert.ok(!FORBIDDEN_PKG.test('./settings-store'), 'relative modules are not provider SDKs');
});
