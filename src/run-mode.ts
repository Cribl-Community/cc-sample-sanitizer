declare global {
  interface Window {
    CRIBL_API_URL?: string;
  }
}

// 'backend' (build 712) = a Cribl Backend Function's Node runtime — no `window`
// at all. Distinct from 'standalone' (the local Vite dev server, a real browser
// page with no CRIBL_API_URL) because `shouldUseBackendProxy()` (sample-io.ts)
// treats 'standalone' as "route everything through this repo's own .mjs dev-proxy
// handlers" — which do not exist once code is running inside an actual deployed
// Backend Function. Falling back to 'standalone' here for a `window`-less
// context would silently misroute every Cribl API call.
export type RunMode = 'iframe' | 'standalone' | 'backend';

export const getRunMode = (): RunMode => {
  if (typeof window === 'undefined') return 'backend';
  const fromWindow = window.CRIBL_API_URL;
  if (fromWindow && fromWindow.length > 0) return 'iframe';
  return 'standalone';
};
