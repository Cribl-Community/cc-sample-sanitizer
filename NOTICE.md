# Do not edit this repository directly

Distribution + review channel for the **Cribl Sample Sanitizer** app. Everything
here is GENERATED from the `cribl-pack-generator` monorepo by
`npm run publish:sanitizer` — hand edits are overwritten on the next publish.

- **`source/`** — the sanitizer's reachable source graph, published so it can be
  VERIFIED before Marketplace acceptance (AI-free, no external calls). It is the
  sanitizer only, not the whole Pack Generator, and is not the build's source of
  truth — edit in the monorepo.
- **`package.json` / `static/` / `default/`** — the built, installable app package.
- Each release attaches the packaged `.tgz`.

Install in Cribl via **Apps → View All → Add App → Import from Git**, supplying
this repo URL and a release tag (e.g. `v1.0.258`).
