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

export function safeRemoveItem(key: string): void {
  if (hasLocalStorage()) { try { localStorage.removeItem(key); return; } catch { /* fall through */ } }
  memoryStore.delete(key);
}

/** The fallback store itself, for the prune pass that has to enumerate keys. */
export function memoryStoreKeys(): string[] {
  return [...memoryStore.keys()];
}

export function memoryStoreDelete(key: string): void {
  memoryStore.delete(key);
}
