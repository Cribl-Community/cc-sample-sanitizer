/**
 * Per-install delta of sanitised samples for iframe mode.
 *
 * The committed store ships with the app. An installed app has no filesystem, so
 * local additions and removals are kept as a delta in app KV and mirrored to
 * localStorage. Rebuilding the delta against the bundle makes app upgrades converge:
 * once a published sample ships in the bundle, its identical overlay entry disappears.
 */
import { getRunMode } from './run-mode';
import { safeGetItem, safeSetItem } from './safe-storage';
import {
  parseSanitisedSampleDoc,
  type SanitisedSampleDoc,
} from './sanitised-sample-store';

export interface SanitisedSampleOverlay {
  samples: Record<string, SanitisedSampleDoc>;
  removed: string[];
  updatedAt: string;
}

export const SANITISED_OVERLAY_KV_KEY = 'sanitised-samples/overlay';
export const SANITISED_OVERLAY_LS_KEY = 'sanitised-samples-overlay';
export const SANITISED_OVERLAY_MAX_BYTES = 1_000_000;

const apiBase = (): string => {
  const fromWindow = typeof window !== 'undefined' ? window.CRIBL_API_URL : undefined;
  return fromWindow && fromWindow.length > 0 ? fromWindow.replace(/\/+$/, '') : '/api/v1';
};

const overlayUrl = (): string => `${apiBase()}/kvstore/${SANITISED_OVERLAY_KV_KEY}`;
let overlayPromise: Promise<SanitisedSampleOverlay | null> | null = null;
let overlayStoredIn: 'app-kv' | 'browser' = 'browser';

export function sanitisedOverlayStoredIn(): 'app-kv' | 'browser' {
  return overlayStoredIn;
}

export function invalidateSanitisedOverlayCache(): void {
  overlayPromise = null;
}

function unwrap(value: unknown): unknown {
  let candidate: any = value;
  for (let i = 0; i < 3 && typeof candidate === 'string'; i++) {
    if (!candidate.trim()) return null;
    try { candidate = JSON.parse(candidate); } catch { return null; }
  }
  candidate = candidate?.items?.[0]?.value ?? candidate?.value ?? candidate;
  if (typeof candidate === 'string') {
    try { candidate = JSON.parse(candidate); } catch { return null; }
  }
  return candidate;
}

export function parseSanitisedOverlay(value: unknown): SanitisedSampleOverlay | null {
  const candidate = unwrap(value) as Partial<SanitisedSampleOverlay> | null;
  if (!candidate || typeof candidate !== 'object') return null;
  const rawSamples = candidate.samples;
  const removed = Array.isArray(candidate.removed)
    ? [...new Set(candidate.removed.filter((v): v is string => typeof v === 'string' && !!v))]
    : [];
  if (!rawSamples || typeof rawSamples !== 'object' || Array.isArray(rawSamples)) {
    if (!removed.length) return null;
  }
  const samples: Record<string, SanitisedSampleDoc> = {};
  for (const [key, value] of Object.entries(rawSamples || {})) {
    const doc = parseSanitisedSampleDoc(value);
    if (!doc || doc.key !== key) return null;
    samples[key] = doc;
  }
  if (!Object.keys(samples).length && !removed.length) return null;
  return {
    samples,
    removed,
    updatedAt: typeof candidate.updatedAt === 'string' ? candidate.updatedAt : '',
  };
}

export function mergeSanitisedOverlay(
  bundled: Record<string, SanitisedSampleDoc>,
  overlay: SanitisedSampleOverlay | null | undefined,
): Record<string, SanitisedSampleDoc> {
  const merged = { ...bundled };
  for (const key of overlay?.removed || []) delete merged[key];
  for (const [key, doc] of Object.entries(overlay?.samples || {})) merged[key] = doc;
  return merged;
}

export function diffSanitisedOverlay(
  bundled: Record<string, SanitisedSampleDoc>,
  next: Record<string, SanitisedSampleDoc>,
  meta: { now?: string } = {},
): SanitisedSampleOverlay {
  const samples: Record<string, SanitisedSampleDoc> = {};
  for (const [key, doc] of Object.entries(next)) {
    if (!bundled[key] || JSON.stringify(bundled[key]) !== JSON.stringify(doc)) samples[key] = doc;
  }
  return {
    samples,
    removed: Object.keys(bundled).filter(key => !(key in next)),
    updatedAt: meta.now || new Date().toISOString(),
  };
}

export function loadSanitisedOverlay(): Promise<SanitisedSampleOverlay | null> {
  if (!overlayPromise) {
    overlayPromise = (async () => {
      if (getRunMode() === 'iframe') {
        try {
          const response = await fetch(overlayUrl());
          if (response.ok) {
            const parsed = parseSanitisedOverlay(await response.text());
            if (parsed) {
              overlayStoredIn = 'app-kv';
              return parsed;
            }
          }
        } catch { /* browser mirror below */ }
      }
      overlayStoredIn = 'browser';
      return parseSanitisedOverlay(safeGetItem(SANITISED_OVERLAY_LS_KEY));
    })();
  }
  return overlayPromise;
}

export async function saveSanitisedOverlay(
  overlay: SanitisedSampleOverlay,
): Promise<{ storedIn: 'app-kv' | 'browser' }> {
  const body = JSON.stringify(overlay);
  if (body.length > SANITISED_OVERLAY_MAX_BYTES) {
    throw new Error(
      `Sanitised-sample overlay is ${Math.round(body.length / 1024)} KB, over the `
      + `${Math.round(SANITISED_OVERLAY_MAX_BYTES / 1024)} KB app storage limit. `
      + 'Download the sample or save it from standalone mode instead.',
    );
  }
  // Always keep the browser mirror. It is the graceful fallback when app KV is
  // unavailable and the UI can tell the user exactly where the sample landed.
  safeSetItem(SANITISED_OVERLAY_LS_KEY, body);
  if (getRunMode() === 'iframe') {
    try {
      const response = await fetch(overlayUrl(), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (response.ok) {
        overlayStoredIn = 'app-kv';
        overlayPromise = Promise.resolve(overlay);
        return { storedIn: 'app-kv' };
      }
    } catch { /* browser result below */ }
  }
  overlayStoredIn = 'browser';
  overlayPromise = Promise.resolve(overlay);
  return { storedIn: 'browser' };
}
