/**
 * localStorage that cannot throw, with an in-memory fallback.
 *
 * A sandboxed iframe without `allow-same-origin` throws on any `localStorage` access — not
 * returns null, throws — so every read and write in the app goes through here.
 *
 * This lives in its own module purely so it can be imported EAGERLY. The bundled knowledge
 * in `bundled-data.ts` is several megabytes of JSON and is now loaded on demand; these three
 * one-line functions used to sit in that file, which meant a caller wanting to read a cache
 * key had to pull the whole golden-pipeline catalogue in with it.
 */

const memoryStore = new Map<string, string>();
let localStorageAvailable: boolean | null = null;

export function hasLocalStorage(): boolean {
  if (localStorageAvailable !== null) return localStorageAvailable;
  try { localStorage.setItem('__ls_test', '1'); localStorage.removeItem('__ls_test'); localStorageAvailable = true; } catch { localStorageAvailable = false; }
  return localStorageAvailable;
}

export function safeGetItem(key: string): string | null {
  if (hasLocalStorage()) { try { return localStorage.getItem(key); } catch { /* fall through */ } }
  return memoryStore.get(key) ?? null;
}

export function safeSetItem(key: string, value: string): void {
  if (hasLocalStorage()) { try { localStorage.setItem(key, value); return; } catch { /* fall through */ } }
  memoryStore.set(key, value);
}

/**
 * safeSetItem for writes that must survive a reload: false when only the memory
 * fallback took it (quota full, or no localStorage), so the caller can say so
 * instead of reporting a write that a refresh throws away.
 */
export function safeSetItemDurable(key: string, value: string): boolean {
  if (hasLocalStorage()) { try { localStorage.setItem(key, value); return true; } catch { /* fall through */ } }
  memoryStore.set(key, value);
  return false;
}

export function safeRemoveItem(key: string): void {
  if (hasLocalStorage()) { try { localStorage.removeItem(key); return; } catch { /* fall through */ } }
  memoryStore.delete(key);
}

/**
 * localStorage use in characters, grouped by key prefix (up to the first `:`),
 * largest first — what a "storage is full" message names.
 */
export function localStorageUsage(): { total: number; byPrefix: [string, number][] } {
  const by = new Map<string, number>();
  let total = 0;
  if (hasLocalStorage()) {
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (!k) continue;
        const n = k.length + (localStorage.getItem(k)?.length || 0);
        const prefix = k.includes(':') ? k.slice(0, k.indexOf(':')) : k;
        by.set(prefix, (by.get(prefix) || 0) + n);
        total += n;
      }
    } catch { /* sandboxed */ }
  }
  return { total, byPrefix: [...by].sort((a, b) => b[1] - a[1]) };
}

/** Remove every localStorage key that matches; returns how many went. */
export function evictLocalStorage(match: (key: string) => boolean): number {
  if (!hasLocalStorage()) return 0;
  const doomed: string[] = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && match(k)) doomed.push(k);
    }
    for (const k of doomed) localStorage.removeItem(k);
  } catch { /* sandboxed */ }
  return doomed.length;
}

/** The fallback store itself, for the prune pass that has to enumerate keys. */
export function memoryStoreKeys(): string[] {
  return [...memoryStore.keys()];
}

export function memoryStoreDelete(key: string): void {
  memoryStore.delete(key);
}
