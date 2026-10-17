/**
 * Whether this build offers Cribl's internal AI (Aperture over Tailscale) as a
 * provider. True in the development repository; the Cribl-Community copy is built
 * with false (PUBLIC_REWRITES in scripts/publish-community.mjs), because nobody
 * outside Cribl can reach it.
 */
export const INTERNAL_AI = false;
