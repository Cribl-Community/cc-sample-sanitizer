import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  buildSanitisedSampleDoc,
  SANITISED_SAMPLE_MAX_BYTES,
  SANITISE_INPUT_MAX_BYTES,
} from '../src/sanitised-sample-store.ts';

// The 1 MB limit is a STORAGE limit. It used to apply to every output, so a sample just over it
// could not even be downloaded, and the user only found out after sanitising the whole file.

const args = events => ({
  sourcetype: 'syslog',
  events,
  verification: { verdict: 'pass', method: 'parser-emulation', eventsChecked: events.length, eventsParsed: events.length, fields: [], reasons: [] },
  provenance: { sourceMode: 'upload', replacementsApplied: 1, structurePreserved: true, coverage: { total: 1, replaced: 1, ok: true, blind: false }, sanitisedAt: '2026-11-02T00:00:00.000Z' },
});
const big = Array.from({ length: 12_000 }, (_, i) => `<134>Nov  2 10:00:00 host-a01 app[${i}]: ${'x'.repeat(80)}`);

test('a sample over the storage limit cannot be stored', () => {
  assert.throws(() => buildSanitisedSampleDoc(args(big)), /storage limit/);
});

test('the same sample can still be built for a download', () => {
  const doc = buildSanitisedSampleDoc(args(big), { enforceStorageLimit: false });
  assert.ok(JSON.stringify(doc).length > SANITISED_SAMPLE_MAX_BYTES);
  assert.equal(doc.events.length, big.length);
});

test('the wizard refuses an oversized file before reading it', () => {
  const wizard = readFileSync(new URL('../src/sanitize-wizard.tsx', import.meta.url), 'utf8');
  const sizeCheck = wizard.indexOf('file.size > SANITISE_INPUT_MAX_BYTES');
  assert.ok(sizeCheck > 0);
  assert.ok(sizeCheck < wizard.indexOf('file.text()'), 'the size check runs before the read');
  assert.ok(SANITISE_INPUT_MAX_BYTES > SANITISED_SAMPLE_MAX_BYTES);
});
