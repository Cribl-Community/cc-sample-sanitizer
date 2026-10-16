// AI settings were lost on every visit for users whose browser drops iframe storage
// (2026-10-08 report): localStorage/cookies are third-party inside Cribl, and the
// /lib/vars fallback never created its variable. The durable copy is now App KV.
// Node has no localStorage or document.cookie, so these runs are that browser.

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  SETTINGS_KV_KEY, setSettingsKvTransportForTests, platformSettingsFlushed,
  loadSettingsAsync, saveSettings, loadQualitySettingsAsync, saveQualitySettings,
} from '../src/settings-store.ts';

const BASE = 'https://org.example/api/v1/a/pack-generator';
const KV_URL = `${BASE}/kvstore/${SETTINGS_KV_KEY}`;
const VAR_URL = `${BASE}/m/default/lib/vars/pack_generator_settings`;

function fakeKv(initial = {}) {
  const store = new Map(Object.entries(initial));
  const puts = [];
  const f = async (url, init = {}) => {
    const method = init.method || 'GET';
    if (method === 'PUT') { puts.push({ url, init }); store.set(url, init.body); return new Response('', { status: 200 }); }
    if (method !== 'GET') return new Response('', { status: 405 });
    return store.has(url) ? new Response(store.get(url), { status: 200 }) : new Response('not found', { status: 404 });
  };
  return { f, store, puts };
}

// Outside the iframe saveSettings also posts the secrets to the dev server's
// creds-save; answer that here (the KV transport is separate).
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => String(url).startsWith('/api/pack-generator/')
  ? new Response('{"saved":true}', { status: 200, headers: { 'Content-Type': 'application/json' } })
  : realFetch(url, init);

const restart = kv => setSettingsKvTransportForTests(kv.f, BASE);

test('AI settings survive a restart with no localStorage or cookies', async () => {
  const kv = fakeKv();
  await restart(kv);
  await saveSettings({ provider: 'openai', model: 'gpt-x', anthropicApiKey: 'sk-ant-SECRET', openaiApiKey: 'sk-SECRET' });
  await platformSettingsFlushed();
  await restart(kv);                                  // a new visit
  const s = await loadSettingsAsync();
  assert.equal(s.provider, 'openai');
  assert.equal(s.model, 'gpt-x');
});

test('secrets never reach the unencrypted key; the PUT is text/plain', async () => {
  const kv = fakeKv();
  await restart(kv);
  await saveSettings({ provider: 'anthropic', anthropicApiKey: 'sk-ant-SECRET', openaiApiKey: 'sk-SECRET' });
  saveQualitySettings({ lakeToken: 'LAKE-SECRET', goldenToken: 'GOLD-SECRET' });
  await platformSettingsFlushed();
  assert.ok(kv.puts.length > 0);
  for (const p of kv.puts) {
    assert.equal(p.url, KV_URL);
    assert.equal(p.init.headers['Content-Type'], 'text/plain');
    assert.doesNotMatch(p.init.body, /SECRET/);
  }
});

test('a quality save keeps the AI settings, and the reverse', async () => {
  const kv = fakeKv();
  await restart(kv);
  await saveSettings({ provider: 'mistral', model: 'm-1' });
  saveQualitySettings({ ...(await loadQualitySettingsAsync()), qualityThreshold: 77 });
  await saveSettings({ provider: 'mistral', model: 'm-2' });
  await platformSettingsFlushed();
  const blob = JSON.parse(kv.store.get(KV_URL));
  assert.equal(blob.aiSettings.model, 'm-2');
  assert.equal(blob.qualitySettings.qualityThreshold, 77);
});

test('a save made before the stored copy loaded does not wipe the other half', async () => {
  const kv = fakeKv({ [KV_URL]: JSON.stringify({ qualitySettings: { qualityThreshold: 61 } }) });
  setSettingsKvTransportForTests(kv.f, BASE);         // not awaited: load still in flight
  await saveSettings({ provider: 'openai', model: 'early' });
  await platformSettingsFlushed();
  const blob = JSON.parse(kv.store.get(KV_URL));
  assert.equal(blob.aiSettings.model, 'early');
  assert.equal(blob.qualitySettings.qualityThreshold, 61);
});

test('the old lib/vars copy is read once and moved to App KV', async () => {
  const legacy = { aiSettings: { provider: 'gemini', model: 'g-legacy' } };
  const kv = fakeKv({ [VAR_URL]: JSON.stringify({ items: [{ id: 'pack_generator_settings', value: JSON.stringify(legacy) }] }) });
  await restart(kv);
  assert.equal((await loadSettingsAsync()).model, 'g-legacy');
  assert.equal(JSON.parse(kv.store.get(KV_URL)).aiSettings.model, 'g-legacy');
});

test('a KV value wrapped as a JSON string or items[0].value still loads', async () => {
  const doc = { aiSettings: { provider: 'openai', model: 'wrapped' } };
  for (const body of [JSON.stringify(JSON.stringify(doc)), JSON.stringify({ items: [{ value: JSON.stringify(doc) }] })]) {
    await restart(fakeKv({ [KV_URL]: body }));
    assert.equal((await loadSettingsAsync()).model, 'wrapped');
  }
});

test('nothing stored anywhere gives the defaults, without errors', async () => {
  await restart(fakeKv());
  const s = await loadSettingsAsync();
  assert.ok(s && typeof s.provider === 'string');
});
