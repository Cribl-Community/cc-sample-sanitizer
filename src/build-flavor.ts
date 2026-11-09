/**
 * Whether this build offers the development AI gateway as a provider. True in the development repository; the Cribl-Community copy is built
 * with false (PUBLIC_REWRITES in scripts/publish-community.mjs), because nobody
 * outside Cribl can reach it.
 */
export const INTERNAL_AI = false;

/**
 * Whether this build ships the development server's `/api/pack-generator/*` handlers (the
 * scripts/*.mjs routes Vite serves in standalone mode). True in the development repository and
 * in the Pack Generator's community copy, which ships them. The Sample Sanitizer's community
 * copy does not, so scripts/publish-sanitizer-dist.mjs builds it with false and no code path
 * can reach a route that is not there.
 */
export const DEV_BACKEND = false;

/**
 * fetch() for a development-server route. Without that server it answers the 404 the missing
 * route would have given, so callers fail exactly as before — but nothing touches the network.
 */
export function devServerFetch(path: string, init?: RequestInit): Promise<Response> {
  if (!DEV_BACKEND) {
    return Promise.resolve(new Response(JSON.stringify({ error: 'The development server is not part of this build.' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    }));
  }
  return fetch(path, init);
}
