import assert from 'node:assert/strict';
import { mock, test } from 'node:test';

import { buildSanitisedSampleDoc } from '../src/sanitised-sample-store.ts';
import {
  diffSanitisedOverlay,
  loadSanitisedOverlay,
  mergeSanitisedOverlay,
  parseSanitisedOverlay,
  saveSanitisedOverlay,
  SANITISED_OVERLAY_KV_KEY,
  SANITISED_OVERLAY_LS_KEY,
  SANITISED_OVERLAY_MAX_BYTES,
} from '../src/sanitised-sample-overlay.ts';

const verification = {
  verdict: 'pass',
  method: 'parser-emulation',
  eventsChecked: 1,
  eventsParsed: 1,
  fields: ['srcip'],
  reasons: [],
};

function doc(sourcetype, event, at = '2026-08-24T14:00:00.000Z') {
  return buildSanitisedSampleDoc({
    sourcetype,
    events: [event],
    verification,
    provenance: {
      sourceMode: 'paste',
      sourceLabel: 'pasted events',
      replacementsApplied: 1,
      structurePreserved: true,
      coverage: { total: 1, replaced: 1, ok: true, blind: false },
      sanitisedAt: at,
    },
  });
}

function fakeBrowser() {
  const store = new Map();
  const oldStorage = globalThis.localStorage;
  const oldWindow = globalThis.window;
  const oldFetch = globalThis.fetch;
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: key => store.get(key) ?? null,
      setItem: (key, value) => store.set(key, String(value)),
      removeItem: key => store.delete(key),
    },
  });
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: { CRIBL_API_URL: 'https://cribl.example.com/api/v1' },
  });
  return {
    store,
    restore() {
      if (oldStorage === undefined) delete globalThis.localStorage;
      else Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: oldStorage });
      if (oldWindow === undefined) delete globalThis.window;
      else Object.defineProperty(globalThis, 'window', { configurable: true, value: oldWindow });
      globalThis.fetch = oldFetch;
    },
  };
}

test('merges an overlay over bundled samples and keeps removals', () => {
  const bundledA = doc('source_a', 'srcip=192.0.2.1');
  const bundledB = doc('source_b', 'srcip=192.0.2.2');
  const changedA = doc('source_a', 'srcip=198.51.100.1', '2026-08-24T15:00:00.000Z');
  const localC = doc('source_c', 'srcip=203.0.113.3');
  const overlay = {
    samples: { [changedA.key]: changedA, [localC.key]: localC },
    removed: [bundledB.key],
    updatedAt: 'now',
  };

  assert.deepEqual(
    Object.keys(mergeSanitisedOverlay(
      { [bundledA.key]: bundledA, [bundledB.key]: bundledB },
      overlay,
    )).sort(),
    ['source_a', 'source_c'],
  );
});

test('diffing against the bundled baseline is idempotent', () => {
  const bundled = doc('source_a', 'srcip=192.0.2.1');
  const local = doc('source_b', 'srcip=198.51.100.2');
  const next = { [bundled.key]: bundled, [local.key]: local };
  const first = diffSanitisedOverlay({ [bundled.key]: bundled }, next, { now: 'now' });
  const merged = mergeSanitisedOverlay({ [bundled.key]: bundled }, first);
  const second = diffSanitisedOverlay({ [bundled.key]: bundled }, merged, { now: 'now' });
  assert.deepEqual(second, first);
});

test('parses raw, stringified and KV-wrapped overlays', () => {
  const sample = doc('source_a', 'srcip=192.0.2.1');
  const overlay = { samples: { [sample.key]: sample }, removed: [], updatedAt: 'now' };
  assert.deepEqual(parseSanitisedOverlay(overlay), overlay);
  assert.deepEqual(parseSanitisedOverlay(JSON.stringify(overlay)), overlay);
  assert.deepEqual(parseSanitisedOverlay(JSON.stringify({ items: [{ value: overlay }] })), overlay);
  assert.equal(parseSanitisedOverlay('{}'), null);
  assert.equal(parseSanitisedOverlay('not json'), null);
});

test('saves browser backup first and app KV when available', async () => {
  const browser = fakeBrowser();
  const calls = [];
  globalThis.fetch = mock.fn(async (url, init) => {
    calls.push({ url, ...init });
    return new Response('', { status: 200 });
  });
  try {
    const sample = doc('source_a', 'srcip=192.0.2.1');
    const overlay = { samples: { [sample.key]: sample }, removed: [], updatedAt: 'now' };
    const saved = await saveSanitisedOverlay(overlay);
    assert.equal(saved.storedIn, 'app-kv');
    assert.ok(browser.store.has(SANITISED_OVERLAY_LS_KEY));
    assert.equal(calls[0].method, 'PUT');
    assert.match(calls[0].url, new RegExp(SANITISED_OVERLAY_KV_KEY));
  } finally {
    browser.restore();
  }
});

test('falls back to browser copy when KV is unavailable', async () => {
  const browser = fakeBrowser();
  globalThis.fetch = mock.fn(async () => { throw new Error('offline'); });
  try {
    const sample = doc('source_a', 'srcip=192.0.2.1');
    const overlay = { samples: { [sample.key]: sample }, removed: [], updatedAt: 'now' };
    assert.deepEqual(await saveSanitisedOverlay(overlay), { storedIn: 'browser' });
    assert.deepEqual(await loadSanitisedOverlay(), overlay);
  } finally {
    browser.restore();
  }
});

test('refuses an overlay larger than the app-state cap', async () => {
  const browser = fakeBrowser();
  try {
    const huge = {
      samples: Object.fromEntries(Array.from({ length: 20 }, (_, i) => [
        `source_${i}`,
        { ...doc(`source_${i}`, `raw=${'x'.repeat(60_000)}`), key: `source_${i}`, sourcetype: `source_${i}` },
      ])),
      removed: [],
      updatedAt: 'now',
    };
    assert.ok(JSON.stringify(huge).length > SANITISED_OVERLAY_MAX_BYTES);
    await assert.rejects(() => saveSanitisedOverlay(huge), /KB|storage limit/i);
  } finally {
    browser.restore();
  }
});
