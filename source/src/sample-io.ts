// ============================================================================
// sample-io.ts — AI-FREE Cribl transport + sample I/O + sanitised-sample library
// ============================================================================
//
// This module is the lean, provably AI-free half of the old `api.ts`. It holds
// the HTTP transport primitives, the worker-group sample read/write path, and
// the sanitised-sample library. It is the ONLY api-layer module the sanitise
// screens (`sanitize-wizard.tsx`) and the standalone "Sample Sanitizer" build
// import — so its import graph must never reach `ai-client`/`ai-budget`/the
// schematizer or any provider SDK. `tests/sanitizer-ai-free-test.mjs` enforces
// that by a static reachability walk.
//
// `api.ts` re-exports every symbol here, so existing importers (App.tsx,
// pack-orchestrator, etc.) are unchanged, and `api.ts` itself imports the
// transport primitives back for its own AI-coupled functions.
//
// The settings reads below (`loadSettings`/`loadQualitySettings`) come from the
// AI-free `settings-store.ts`, NOT `ai-client.ts` — that extraction is what let
// this module be AI-free at all.

import { getRunMode, type RunMode } from './run-mode';
import { loadSettings, loadQualitySettings } from './settings-store';
import type { SanitisedSampleDoc, SanitisedSampleIndexRow } from './sanitised-sample-store';
import { parseSanitisedSampleDoc, sanitisedSampleIndexRow } from './sanitised-sample-store';
import {
  diffSanitisedOverlay, loadSanitisedOverlay, mergeSanitisedOverlay, saveSanitisedOverlay,
  sanitisedOverlayStoredIn,
  type SanitisedSampleOverlay,
} from './sanitised-sample-overlay';
import { sanitisedSampleRepoError } from './sanitised-sample-github';

/**
 * The curated sanitised-sample BASELINE lives in `bundled-data`, which also carries
 * the whole reference catalogue / source-sample corpus / golden bundle. That is
 * pack-generator baggage the standalone Sample Sanitizer must never ship, so this
 * shared module does NOT statically or dynamically import `bundled-data`. Instead the
 * baseline is an injected hook (same pattern as `setGoldenPathPredicate`): the
 * pack-generator registers the real loader from `api.ts` at module init, and the
 * sanitizer leaves it at the empty default. This keeps the `import('./bundled-data')`
 * edge — and its ai-core/source-samples/golden preload tail — out of the sanitizer
 * chunk entirely (Hard Rule 25).
 */
let bundledSanitisedBaselineLoader:
  () => Promise<Record<string, SanitisedSampleDoc>> = async () => ({});

export function setBundledSanitisedBaselineLoader(
  loader: () => Promise<Record<string, SanitisedSampleDoc>>,
): void {
  bundledSanitisedBaselineLoader = loader;
}

// --- Transport ---

export const getApiBase = (): string => {
  const fromWindow = typeof window !== 'undefined' ? window.CRIBL_API_URL : undefined;
  if (fromWindow && fromWindow.length > 0) return fromWindow.replace(/\/+$/, '');
  return '/api/v1';
};

// Ceiling for a single Cribl API call. Generous — a pack deploy or a preview over
// a large sample is legitimately slow — but bounded: without it a hung TCP
// connection wedges the caller forever. In a batch run that meant one dead
// connection parked a row permanently with no recovery but the manual Rerun
// button, because nothing downstream ever rejects.
const CRIBL_REQUEST_TIMEOUT_MS = 120_000;

// fetch() with an AbortController deadline. Respects a caller-supplied signal:
// if the caller already passed one, theirs wins and we add no deadline (so an
// explicit cancel/abort path is never silently overridden).
export async function fetchWithDeadline(
  url: string,
  init: RequestInit = {},
  timeoutMs = CRIBL_REQUEST_TIMEOUT_MS,
): Promise<Response> {
  if (init.signal) return fetch(url, init);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new Error(`Cribl request timed out after ${Math.round(timeoutMs / 1000)}s: ${url.replace(/\?.*$/, '')}. The worker group may be unreachable or overloaded.`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// Backend-proxy endpoints that legitimately run long: anything that calls an AI
// provider, runs the repair/quality loop, or drives a full deploy. These get the
// AI-scale ceiling; everything else (list groups, fetch a sample, preview) gets
// the standard one. Matched as substrings of the request path.
const SLOW_PROXY_ENDPOINTS = [
  'ai-validate', 'ai-samples', 'ai-mapping', 'ai-parse', 'ai-advise',
  'schematizer', 'hybrid-samples', 'fetch-public-samples',
  'repair-pipeline', 'repair-quality', 'pre-deploy-validate', 'validate-pipeline',
  'deploy', 'commit-deploy',
];
const SLOW_PROXY_TIMEOUT_MS = 300_000;

// fetch() for the standalone backend-proxy handlers, with a path-aware deadline.
// Standalone routes EVERY Cribl call through these handlers (run-mode rule 17),
// so an un-bounded hang here parks a whole batch row indefinitely.
export function proxyFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const slow = SLOW_PROXY_ENDPOINTS.some((e) => path.includes(e));
  return fetchWithDeadline(path, init, slow ? SLOW_PROXY_TIMEOUT_MS : CRIBL_REQUEST_TIMEOUT_MS);
}

/** True for browser/Node transport drops that are safe to retry once or twice. */
export function isTransientFetchError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /failed to fetch|networkerror|network request failed|load failed|fetch failed|timed out|econnreset|econnrefused|etimedout|socket hang up|aborted/i.test(msg);
}

/**
 * Retry a Cribl/proxy call on transient network drops. Batch staging does dozens
 * of patch+preview cycles per row; one TypeError: Failed to fetch used to abort
 * the whole pack after extraction had already scored (E set, M/O blank).
 */
export async function withTransientRetry<T>(
  fn: () => Promise<T>,
  opts: { attempts?: number; label?: string; delayMs?: number } = {},
): Promise<T> {
  const attempts = Math.max(1, opts.attempts ?? 3);
  const delayMs = opts.delayMs ?? 400;
  let last: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      last = err;
      if (!isTransientFetchError(err) || i === attempts - 1) throw err;
      await new Promise((r) => setTimeout(r, delayMs * (i + 1)));
    }
  }
  throw last;
}

export async function criblFetch<T = unknown>(path: string, opts: RequestInit = {}): Promise<T> {
  const url = path.startsWith('http') ? path : `${getApiBase()}${path}`;
  const resp = await fetchWithDeadline(url, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    },
  });
  if (!resp.ok) {
    const text = await resp.text();
    let msg: string;
    try { msg = JSON.parse(text).message || text; } catch { msg = text; }
    // Name the request. An upstream sentence on its own ("Group seLab not
    // found") cannot be acted on when the caller made three calls — and a
    // background tick reports it to a manifest nobody can cross-reference.
    const method = String(opts.method || 'GET').toUpperCase();
    throw new Error(`${method} ${path} failed (${resp.status}): ${msg || resp.statusText}`);
  }
  const ct = resp.headers.get('content-type') || '';
  if (ct.includes('application/json')) return resp.json();
  return resp.text() as unknown as T;
}

export function shouldUseBackendProxy(
  mode: RunMode = getRunMode(),
  provider: string = loadSettings().provider,
): boolean {
  // A deployed Backend Function has no local Vite middleware. Its Cribl calls
  // go directly to /api/v1 and its external AI calls use declared proxy hosts.
  if (mode === 'backend') return false;
  // STANDALONE ALWAYS uses the backend. This is the single architectural rule:
  //   • standalone → all Cribl API calls go through the .mjs handlers, and all
  //     AI goes through Tailscale/Aperture (the backend reaches http://ai/bedrock;
  //     the browser cannot resolve that host). NEVER client-side.
  //   • iframe → never backend: AI runs client-side via the configured provider,
  //     Cribl via criblFetch (platform injects auth).
  // The old `&& !isAiConfigured()` clause was the bug: configuring an AI key
  // flipped standalone OFF the backend → preview/validate fell to the iframe
  // browser-direct path (criblFetch to Cribl Cloud, no auth) → "No sample found"
  // and E0. Standalone routing must not depend on whether an AI key is set.
  if (mode === 'standalone') return true;
  // Dev Proxy uses backend handlers only where those handlers actually exist.
  if (provider === 'devproxy') return true;
  return false;
}

// --- Worker Groups ---

export async function listGroups(): Promise<{ id: string; name: string; description: string; type: string; workerCount: number }[]> {
  if (shouldUseBackendProxy()) {
    const resp = await proxyFetch('/api/pack-generator/groups');
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Failed to list groups');
    return (data.groups || []).map((g: any) => ({ ...g, workerCount: g.workerCount ?? 0 }));
  }
  const data = await criblFetch<{ items: any[] }>('/master/groups');
  // Live capture needs a connected worker in the group; annotate each group with its worker
  // count so callers can hide empty groups. A failed /master/workers call must not sink the
  // group list — fall back to 0 (unknown), which the picker treats as "no workers".
  const counts = await workerCountsByGroup();
  return (data.items || []).map((g: any) => ({
    id: g.id,
    name: g.name || g.id,
    description: g.description || '',
    type: g.type || 'stream',
    workerCount: counts[g.id] ?? 0,
  }));
}

// Connected-worker count per group, from /master/workers. Best-effort: on any error we return
// an empty map so listGroups still succeeds (groups just show as having 0 workers).
async function workerCountsByGroup(): Promise<Record<string, number>> {
  try {
    const data = await criblFetch<{ items: any[] }>('/master/workers');
    const counts: Record<string, number> = {};
    for (const w of data.items || []) {
      const g = w.group || 'unknown';
      counts[g] = (counts[g] || 0) + 1;
    }
    return counts;
  } catch {
    return {};
  }
}

// --- Live Capture ---

export async function liveCapture(workerGroup: string, filter: string, maxEvents: number, durationMs: number): Promise<{ events: string[]; count: number }> {
  if (shouldUseBackendProxy()) {
    const resp = await proxyFetch('/api/pack-generator/live-capture', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ workerGroup, filter, maxEvents, durationMs }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Live capture failed');
    return data;
  }
  const resp = await criblFetch<string>(`/m/${workerGroup}/system/capture`, {
    method: 'POST',
    body: JSON.stringify({
      filter: filter || 'true',
      maxEvents: Math.min(maxEvents, 500),
      duration: Math.min(Math.round(durationMs / 1000), 30),
    }),
  });
  // Response is NDJSON
  const rawText = typeof resp === 'string' ? resp : JSON.stringify(resp);
  const lines = rawText.trim().split('\n').filter(Boolean);
  const events: string[] = [];
  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      if (obj._raw) {
        events.push(obj._raw);
      } else {
        const { __criblEventType, __ctrlFields, __final, __cloneCount, __eventId, __inputId, ...fields } = obj;
        events.push(JSON.stringify(fields));
      }
    } catch { /* skip */ }
  }
  return { events, count: events.length };
}

// --- Samples ---

export async function listSamples(group: string): Promise<{ id: string; name: string; size: number; numEvents: number }[]> {
  if (shouldUseBackendProxy()) {
    const resp = await fetch(`/api/pack-generator/samples?group=${encodeURIComponent(group)}`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Failed to list samples');
    return data.samples;
  }
  const data = await criblFetch<{ items: any[] }>(`/m/${group}/system/samples`);
  return (data.items || []).map((s: any) => ({
    id: s.id,
    name: s.sampleName || s.id,
    size: s.size || 0,
    numEvents: s.numEvents || 0,
  }));
}

export async function downloadSample(workerGroup: string, sampleId: string): Promise<{ events: string[]; count: number }> {
  if (shouldUseBackendProxy()) {
    const resp = await proxyFetch('/api/pack-generator/download-sample', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ workerGroup, sampleId }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Failed to download sample');
    return data;
  }
  const content = await criblFetch<any[]>(`/m/${workerGroup}/system/samples/${encodeURIComponent(sampleId)}/content`);
  const events = (Array.isArray(content) ? content : []).map((evt: any) => {
    if (evt._raw) return evt._raw;
    const { __criblEventType, __ctrlFields, __final, __cloneCount, ...fields } = evt;
    return JSON.stringify(fields);
  });
  return { events, count: events.length };
}

// --- Pack-scoped samples (read-only) ---
//
// Samples also live inside packs installed in a worker group. The sample picker
// searches these alongside worker-group system samples. These are READ-ONLY paths
// (list + content); the sanitizer never writes to a pack. Endpoint shapes mirror the
// pack-generator's src/api.ts, but are re-implemented here on purpose: src/api.ts is
// NOT in the sanitizer's AI-free import graph (Hard Rule 25), so it must not be pulled
// in. Standalone/backend-proxy dev mode has no route for these, so it returns [] —
// the feature is in-platform (iframe) only, which is the real deployment.

type PackRef = { id: string; displayName: string };

async function listPacks(group: string): Promise<PackRef[]> {
  if (shouldUseBackendProxy()) return [];
  const data = await criblFetch<{ items: any[] }>(`/m/${group}/packs`);
  return (data.items || []).map((p: any) => ({ id: p.id, displayName: p.displayName || p.id }));
}

async function listPackSamples(group: string, packId: string): Promise<{ id: string; name: string; size: number; numEvents: number }[]> {
  if (shouldUseBackendProxy()) return [];
  const data = await criblFetch<{ items: any[] }>(`/m/${group}/p/${packId}/system/samples`);
  return (data.items || []).map((s: any) => ({
    id: s.id,
    name: s.sampleName || s.id,
    size: s.size || 0,
    numEvents: s.numEvents || 0,
  }));
}

export async function downloadPackSample(workerGroup: string, packId: string, sampleId: string): Promise<{ events: string[]; count: number }> {
  const content = await criblFetch<any[]>(`/m/${workerGroup}/p/${packId}/system/samples/${encodeURIComponent(sampleId)}/content`);
  const events = (Array.isArray(content) ? content : []).map((evt: any) => {
    if (evt?._raw != null) return String(evt._raw);
    const { __criblEventType, __ctrlFields, __final, __cloneCount, ...fields } = evt || {};
    return JSON.stringify(fields);
  });
  return { events, count: events.length };
}

/** Worker-group system samples plus every installed pack's samples, tagged with origin.
 *  Pack enumeration is best-effort: a failure listing packs (or one pack's samples) must
 *  never sink the worker-group system-sample list, so each pack read is caught.
 *
 *  Most packs ship Cribl's identical default datagen set (weblog.log, syslog.log,
 *  apache_common.log…), which is ALSO present at worker-group scope — on an org with
 *  dozens of packs that means the same name repeated dozens of times, burying the
 *  pack-unique samples a user actually came to sanitise. So a pack sample is dropped
 *  when its name already exists as a worker-group system sample (the group copy is shown
 *  anyway); pack-unique samples (e.g. PSOsample) are kept. */
export async function listGroupAndPackSamples(
  group: string,
): Promise<{ id: string; name: string; size: number; numEvents: number; packId?: string; packName?: string }[]> {
  const system = await listSamples(group);
  let packs: PackRef[] = [];
  try {
    packs = await listPacks(group);
  } catch {
    return system; // no packs / not permitted — group samples still work
  }
  const systemNames = new Set(system.map(s => s.name));
  const packResults = await Promise.all(
    packs.map(async pack => {
      try {
        const items = await listPackSamples(group, pack.id);
        return items
          .filter(s => !systemNames.has(s.name)) // drop default samples that duplicate a group sample
          .map(s => ({ ...s, packId: pack.id, packName: pack.displayName }));
      } catch {
        return [];
      }
    }),
  );
  return [...system, ...packResults.flat()];
}

/** Save a sample at worker-group scope, replacing a same-name file. */
export function workerGroupSamplesPath(workerGroup: string): string {
  if (!workerGroup || /[/\\]/.test(workerGroup)) throw new Error('Invalid worker group.');
  return `/m/${workerGroup}/system/samples`;
}

export async function uploadWorkerGroupSample(
  workerGroup: string,
  sampleName: string,
  events: string[],
): Promise<string> {
  if (!workerGroup || !sampleName || !events.length) throw new Error('Worker group, sample name and events are required.');
  if (shouldUseBackendProxy()) {
    const response = await proxyFetch('/api/pack-generator/group-sample', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ workerGroup, sampleName, events }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Failed to upload worker-group sample');
    return data.sampleId || sampleName;
  }
  const base = workerGroupSamplesPath(workerGroup);
  const listed = await criblFetch<{ items: any[] }>(base).catch(() => ({ items: [] }));
  const existing = (listed.items || []).find((sample: any) => sample.sampleName === sampleName);
  const sampleBody = {
    sampleName,
    context: { events: events.map(raw => ({ _raw: raw, _time: Date.now() / 1000 })) },
  };
  if (existing?.id) {
    await criblFetch(`${base}/${encodeURIComponent(existing.id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ id: existing.id, ...sampleBody }),
    });
    return existing.id;
  }
  const uploaded = await criblFetch<any>(base, { method: 'POST', body: JSON.stringify(sampleBody) });
  return uploaded?.items?.[0]?.id || uploaded?.id || sampleName;
}

// --- Sanitised sample library ---

export interface SanitisedSampleLibraryState {
  available: boolean;
  samples: SanitisedSampleIndexRow[];
  documents: Record<string, SanitisedSampleDoc>;
  storedIn: 'config' | 'app-kv' | 'browser';
  error?: string;
}

async function iframeSanitisedOverlay(): Promise<SanitisedSampleOverlay> {
  return await loadSanitisedOverlay()
    || { samples: {}, removed: [], updatedAt: '' };
}

async function iframeSanitisedStore(): Promise<{
  bundled: Record<string, SanitisedSampleDoc>;
  overlay: SanitisedSampleOverlay;
  documents: Record<string, SanitisedSampleDoc>;
}> {
  const [baseline, overlay] = await Promise.all([
    bundledSanitisedBaselineLoader(),
    iframeSanitisedOverlay(),
  ]);
  return { bundled: baseline, overlay, documents: mergeSanitisedOverlay(baseline, overlay) };
}

export async function fetchSanitisedSamples(): Promise<SanitisedSampleLibraryState> {
  if (getRunMode() === 'iframe') {
    const { documents } = await iframeSanitisedStore();
    return {
      available: true,
      samples: Object.values(documents).map(sanitisedSampleIndexRow)
        .sort((a, b) => a.key.localeCompare(b.key)),
      documents,
      storedIn: sanitisedOverlayStoredIn(),
    };
  }
  try {
    const response = await proxyFetch('/api/pack-generator/sanitised-samples');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Failed to list sanitised samples');
    return {
      available: data.available !== false,
      samples: data.samples || [],
      documents: {},
      storedIn: 'config',
      error: data.error,
    };
  } catch (error) {
    return {
      available: false, samples: [], documents: {}, storedIn: 'config',
      error: error instanceof Error ? error.message : 'unknown error',
    };
  }
}

export async function fetchSanitisedSample(key: string): Promise<SanitisedSampleDoc | null> {
  if (getRunMode() === 'iframe') return (await iframeSanitisedStore()).documents[key] || null;
  const response = await proxyFetch(`/api/pack-generator/sanitised-samples?key=${encodeURIComponent(key)}`);
  if (!response.ok) return null;
  return (await response.json()).sample || null;
}

export async function saveSanitisedSample(
  doc: SanitisedSampleDoc,
): Promise<{ ok: boolean; storedIn: 'config' | 'app-kv' | 'browser'; error?: string }> {
  if (getRunMode() === 'iframe') {
    const safeDoc = parseSanitisedSampleDoc(doc);
    if (!safeDoc) return { ok: false, storedIn: 'browser', error: 'Invalid sanitised sample document.' };
    const current = await iframeSanitisedStore();
    const next = { ...current.documents, [safeDoc.key]: safeDoc };
    const delta = diffSanitisedOverlay(current.bundled, next);
    const result = await saveSanitisedOverlay(delta);
    return { ok: true, storedIn: result.storedIn };
  }
  const response = await proxyFetch('/api/pack-generator/sanitised-samples/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ doc }),
  });
  const data = await response.json();
  return response.ok && data.ok
    ? { ok: true, storedIn: 'config' }
    : { ok: false, storedIn: 'config', error: data.error || 'Save failed' };
}

export async function deleteSanitisedSample(
  key: string,
): Promise<{ ok: boolean; storedIn: 'config' | 'app-kv' | 'browser'; error?: string }> {
  if (getRunMode() === 'iframe') {
    const current = await iframeSanitisedStore();
    const next = { ...current.documents };
    delete next[key];
    const result = await saveSanitisedOverlay(diffSanitisedOverlay(current.bundled, next));
    return { ok: true, storedIn: result.storedIn };
  }
  const response = await proxyFetch('/api/pack-generator/sanitised-samples/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ keys: [key] }),
  });
  const data = await response.json();
  const result = data.results?.[0];
  return response.ok && result?.ok
    ? { ok: true, storedIn: 'config' }
    : { ok: false, storedIn: 'config', error: result?.reason || data.error || 'Delete failed' };
}

export function suitableSanitisedSampleRepo(repo: string, goldenRepo: string): boolean {
  return !sanitisedSampleRepoError(repo, 'shared-sanitised-samples', goldenRepo);
}

export async function publishSanitisedSample(
  doc: SanitisedSampleDoc,
): Promise<{ published: boolean; reason?: string; error?: string }> {
  if (getRunMode() !== 'standalone') return { published: false, error: 'Publishing is standalone-only.' };
  const settings = loadQualitySettings();
  if (!settings.shareSanitisedSamples || !settings.sanitisedSampleTokenSet
    || sanitisedSampleRepoError(
      settings.sanitisedSampleRepo, settings.sanitisedSampleBranch, settings.goldenRepo,
    )) {
    return { published: false, error: 'Configure a separate sanitised-sample repository and token in Settings.' };
  }
  const response = await proxyFetch('/api/pack-generator/sanitised-samples/publish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      repo: settings.sanitisedSampleRepo,
      branch: settings.sanitisedSampleBranch,
      goldenRepo: settings.goldenRepo,
      doc,
    }),
  });
  const data = await response.json();
  return response.ok ? data : { published: false, error: data.error || 'Publish failed' };
}

export async function testSanitisedSampleAccess(
  repo: string,
  branch: string,
  goldenRepo: string,
): Promise<{ ok: boolean; message: string }> {
  const error = sanitisedSampleRepoError(repo, branch, goldenRepo);
  if (error) return { ok: false, message: error };
  if (getRunMode() !== 'standalone') return { ok: false, message: 'Publishing is standalone-only.' };
  const response = await proxyFetch('/api/pack-generator/sanitised-samples/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo, branch, goldenRepo }),
  });
  const data = await response.json();
  return { ok: response.ok && !!data.ok, message: data.message || data.error || `GitHub ${response.status}` };
}

// ============================================================================
// Shared sanitised-sample library — worker-group backed (`/m/:gid/system/samples`)
// ============================================================================
//
// The pack generator and the standalone "Sample Sanitizer" share one library so a
// sample sanitised in either is reusable in both, and so a Stream pipeline can use
// the same sample directly. App KV is app-SCOPED, so it cannot carry cross-app
// data; the shared sample RECORD is the only cross-app carrier. Wire layout of one
// library entry:
//
//   sampleName     = "sanitised__" + key.replace('::','__')   (sanitised__cisco_asa__cim)
//   context.events = the sanitised _raw lines (pipeline-safe, carry no metadata)
//   description    = JSON of the doc MINUS events (fingerprint/verification/provenance)
//
// Reading prefers the record's `description` (works cross-app with no extra fetch);
// if the org drops that custom field it falls back to THIS app's own sanitised
// store (the write-through mirror below), then to a DEGRADED index row synthesised
// from the sample alone — the events are always shared; only the human evidence is
// app-local until the entry is re-opened and re-saved.

export const SANITISED_LIBRARY_PREFIX = 'sanitised__';

/** Worker-group sample name for a library key (`cisco_asa::cim` → `sanitised__cisco_asa__cim`). */
export function sanitisedLibrarySampleName(key: string): string {
  return SANITISED_LIBRARY_PREFIX + key.replace(/::/g, '__');
}

/**
 * Is this worker-group sample a SANITISED LIBRARY entry?
 *
 * Public because provenance is what the wizard's sanitise gate needs: a
 * `sanitised__*` record only exists because it passed the library's strict gates
 * (structure preserved, parser verification non-failing, identity coverage proven),
 * so loading one back and asking the user to sanitise it again is nagging about data
 * this app already proved clean. The name is the durable marker — it is the record's
 * primary key in the library and survives an org that drops `description`.
 */
export function isSanitisedLibrarySampleName(name: string): boolean {
  return typeof name === 'string' && name.startsWith(SANITISED_LIBRARY_PREFIX);
}

function isLibrarySampleName(name: string): boolean {
  return isSanitisedLibrarySampleName(name);
}

// Best-effort inverse — only reached when a record has neither a `description` nor a
// local mirror, so the true key (carried verbatim in both of those) is unavailable.
// `::`→`__` is lossy if a sourcetype itself contains `__`, which is why it is the
// last resort, never the primary key source.
function keyFromLibrarySampleName(name: string): string {
  return name.slice(SANITISED_LIBRARY_PREFIX.length).replace(/__/g, '::');
}

interface LibrarySampleRecord {
  id: string;
  name: string;
  description?: string;
  numEvents?: number;
  size?: number;
}

/**
 * The doc MINUS its events — the cross-app metadata that rides in the sample record's
 * `description`. Events live in the record's `context.events` (pipeline-safe, carry no
 * metadata), so they are stripped here to avoid shipping them twice and to keep the
 * description small.
 */
export function sanitisedLibraryMeta(doc: SanitisedSampleDoc): string {
  const meta = { ...doc };
  delete (meta as { events?: string[] }).events;
  return JSON.stringify(meta);
}

/**
 * Rebuild a document from a record's `description` + its events, re-validated through
 * `parseSanitisedSampleDoc` (which re-checks the fingerprint against the events, so a
 * tampered description or mismatched events is rejected). Returns null on any mismatch.
 */
export function parseSanitisedLibraryMeta(description: string, events: string[]): SanitisedSampleDoc | null {
  let meta: unknown;
  try { meta = JSON.parse(description); } catch { return null; }
  if (!meta || typeof meta !== 'object') return null;
  return parseSanitisedSampleDoc({ ...(meta as Record<string, unknown>), events });
}

// List the library's raw records (id/name/description/count) in either run mode.
// Standalone reads through the backend proxy (which now echoes `description`);
// iframe reads `/m/:gid/system/samples` directly.
async function listLibraryRecords(gid: string): Promise<LibrarySampleRecord[]> {
  if (shouldUseBackendProxy()) {
    const resp = await proxyFetch(`/api/pack-generator/samples?group=${encodeURIComponent(gid)}`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Failed to list samples');
    return (data.samples || [])
      .filter((s: any) => isLibrarySampleName(s.name || ''))
      .map((s: any) => ({ id: s.id, name: s.name, description: s.description, numEvents: s.numEvents, size: s.size }));
  }
  const data = await criblFetch<{ items: any[] }>(workerGroupSamplesPath(gid));
  return (data.items || [])
    .filter((s: any) => isLibrarySampleName(s.sampleName || s.id || ''))
    .map((s: any) => ({ id: s.id, name: s.sampleName || s.id, description: s.description, numEvents: s.numEvents, size: s.size }));
}

// Upsert-by-name (the same list→PATCH→POST path as uploadWorkerGroupSample) but
// carrying the `description` metadata alongside the events.
async function upsertLibrarySample(gid: string, sampleName: string, events: string[], description: string): Promise<string> {
  if (shouldUseBackendProxy()) {
    const resp = await proxyFetch('/api/pack-generator/group-sample', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ workerGroup: gid, sampleName, events, description }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Failed to save library sample');
    return data.sampleId || sampleName;
  }
  const base = workerGroupSamplesPath(gid);
  const listed = await criblFetch<{ items: any[] }>(base).catch(() => ({ items: [] as any[] }));
  const existing = (listed.items || []).find((s: any) => s.sampleName === sampleName);
  const sampleBody = {
    sampleName,
    description,
    context: { events: events.map(raw => ({ _raw: raw, _time: Date.now() / 1000 })) },
  };
  if (existing?.id) {
    await criblFetch(`${base}/${encodeURIComponent(existing.id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ id: existing.id, ...sampleBody }),
    });
    return existing.id;
  }
  const uploaded = await criblFetch<any>(base, { method: 'POST', body: JSON.stringify(sampleBody) });
  return uploaded?.items?.[0]?.id || uploaded?.id || sampleName;
}

async function deleteLibraryRecord(gid: string, id: string): Promise<void> {
  if (shouldUseBackendProxy()) {
    const resp = await proxyFetch('/api/pack-generator/group-sample', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ workerGroup: gid, sampleId: id }),
    });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error || 'Failed to delete library sample');
    }
    return;
  }
  await criblFetch(`${workerGroupSamplesPath(gid)}/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

// An index row straight from the cross-app `description` — no content fetch needed.
function libraryIndexRow(rec: LibrarySampleRecord): SanitisedSampleIndexRow | null {
  if (!rec.description) return null;
  let meta: any;
  try { meta = JSON.parse(rec.description); } catch { return null; }
  if (!meta || meta.sanitised !== true || typeof meta.key !== 'string' || typeof meta.sourcetype !== 'string') return null;
  return {
    key: meta.key,
    sourcetype: meta.sourcetype,
    ...(meta.format ? { format: meta.format } : {}),
    events: typeof rec.numEvents === 'number' ? rec.numEvents
      : (Array.isArray(meta.events) ? meta.events.length : 0),
    fingerprint: typeof meta.fingerprint === 'string' ? meta.fingerprint : '',
    sanitisedAt: meta.provenance?.sanitisedAt || '',
    verdict: ['pass', 'fail', 'unverified'].includes(meta.verification?.verdict) ? meta.verification.verdict : 'unverified',
    method: ['parser-emulation', 'source-expectation', 'structure', 'none'].includes(meta.verification?.method) ? meta.verification.method : 'none',
  };
}

// The row we can still show when a record carries no usable metadata: the events
// are shared and countable, but the evidence is unknown until it is re-opened.
function degradedIndexRow(rec: LibrarySampleRecord): SanitisedSampleIndexRow {
  const key = keyFromLibrarySampleName(rec.name);
  const [sourcetype, format] = key.split('::');
  return {
    key,
    sourcetype,
    ...(format ? { format } : {}),
    events: typeof rec.numEvents === 'number' ? rec.numEvents : 0,
    fingerprint: '',
    sanitisedAt: '',
    verdict: 'unverified',
    method: 'none',
  };
}

export interface SanitisedLibraryListing {
  available: boolean;
  gid: string;
  rows: SanitisedSampleIndexRow[];
  /** Keys shown only as degraded rows (metadata unavailable; events still shared). */
  degraded: string[];
  error?: string;
}

/** List the shared library for a worker group, richest metadata first. */
export async function listSanitisedLibrary(gid: string): Promise<SanitisedLibraryListing> {
  if (!gid) return { available: false, gid, rows: [], degraded: [], error: 'Choose a worker group.' };
  try {
    const records = await listLibraryRecords(gid);
    // One read of this app's own store fills metadata the shared record can't carry
    // (the org dropped `description`, or the entry was saved by an older build).
    const own = await fetchSanitisedSamples().catch(() => null);
    const ownDocs = own?.documents || {};
    const rows: SanitisedSampleIndexRow[] = [];
    const degraded: string[] = [];
    for (const rec of records) {
      const fromDesc = libraryIndexRow(rec);
      if (fromDesc) { rows.push(fromDesc); continue; }
      const key = keyFromLibrarySampleName(rec.name);
      const local = ownDocs[key];
      if (local) { rows.push(sanitisedSampleIndexRow(local)); continue; }
      rows.push(degradedIndexRow(rec));
      degraded.push(key);
    }
    rows.sort((a, b) => a.key.localeCompare(b.key));
    return { available: true, gid, rows, degraded };
  } catch (error) {
    return { available: false, gid, rows: [], degraded: [], error: error instanceof Error ? error.message : 'unknown error' };
  }
}

export interface SanitisedLibraryFetch {
  key: string;
  events: string[];
  doc: SanitisedSampleDoc | null;
  /** Where the returned metadata came from — `degraded` means events only. */
  source: 'description' | 'app-store' | 'degraded' | 'missing';
}

/** Fetch one library entry's events + reconstructed document. */
export async function fetchSanitisedLibrarySample(gid: string, key: string): Promise<SanitisedLibraryFetch> {
  const wantName = sanitisedLibrarySampleName(key);
  const records = await listLibraryRecords(gid);
  const rec = records.find(r => r.name === wantName);
  if (!rec) {
    // Not in the shared library; this app's own store may still have it.
    const local = await fetchSanitisedSample(key).catch(() => null);
    if (local) return { key, events: local.events, doc: local, source: 'app-store' };
    return { key, events: [], doc: null, source: 'missing' };
  }
  const { events } = await downloadSample(gid, rec.id);
  if (rec.description) {
    const doc = parseSanitisedLibraryMeta(rec.description, events);
    if (doc) return { key: doc.key, events: doc.events, doc, source: 'description' };
  }
  const local = await fetchSanitisedSample(key).catch(() => null);
  if (local) return { key, events: local.events, doc: local, source: 'app-store' };
  return { key, events, doc: null, source: 'degraded' };
}

export interface SanitisedLibrarySaveResult {
  ok: boolean;
  sampleId?: string;
  error?: string;
  /** Fate of the write-through mirror into THIS app's own store. */
  mirror?: 'config' | 'app-kv' | 'browser' | 'failed' | 'skipped';
}

/**
 * Save a sanitised document to the shared library: the events + `description`
 * metadata go to the worker-group sample (the cross-app carrier), and the full
 * document is mirrored into this app's own store (fast, complete same-app reads +
 * the read fallback if the org drops `description`). A mirror failure never fails
 * the save — the shared record already carries everything a peer app needs.
 */
export async function saveSanitisedLibrarySample(gid: string, doc: SanitisedSampleDoc): Promise<SanitisedLibrarySaveResult> {
  const safe = parseSanitisedSampleDoc(doc);
  if (!safe) return { ok: false, error: 'Invalid sanitised sample document.' };
  if (!gid) return { ok: false, error: 'Choose a destination worker group.' };
  let sampleId: string;
  try {
    sampleId = await upsertLibrarySample(gid, sanitisedLibrarySampleName(safe.key), safe.events, sanitisedLibraryMeta(safe));
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'Failed to save to the shared library.' };
  }
  let mirror: SanitisedLibrarySaveResult['mirror'] = 'skipped';
  try {
    const m = await saveSanitisedSample(safe);
    mirror = m.ok ? m.storedIn : 'failed';
  } catch { mirror = 'failed'; }
  return { ok: true, sampleId, mirror };
}

/** Remove a library entry from the worker group (and best-effort from the local mirror). */
export async function deleteSanitisedLibrarySample(gid: string, key: string): Promise<{ ok: boolean; error?: string }> {
  if (!gid) return { ok: false, error: 'Choose a worker group.' };
  try {
    const records = await listLibraryRecords(gid);
    const rec = records.find(r => r.name === sanitisedLibrarySampleName(key));
    if (rec) await deleteLibraryRecord(gid, rec.id);
    await deleteSanitisedSample(key).catch(() => { /* mirror cleanup is best-effort */ });
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'Failed to delete from the shared library.' };
  }
}
