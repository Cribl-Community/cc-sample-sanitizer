# Contributing

Issues and pull requests are welcome here.

## This repository is generated

The Sample Sanitizer is a build target of the Cribl Pack Generator's development repository. Every file here is generated from it, and each release replaces the whole tree. So a pull request is not merged here directly. A maintainer ports the change to the source, and it ships in the next release, with you credited as co-author. The pull request gets a comment that links to that release.

## Before you open a pull request

```bash
npm ci
npm run lint
npm test
npm run build
```

`npm test` runs the tests in `tests/`, which also run on every pull request. Two rules are not negotiable:

- **No AI.** The sanitise engine is rule-based and deterministic. `tests/sanitizer-ai-free-test.mjs` fails if any AI dependency is introduced.
- **No network.** Sanitising runs entirely in the browser, so the sample never leaves it. Do not add a call that sends it anywhere.

## Reporting a missed or wrong mask

Open an issue with the log type and a few lines that show the problem. **Replace the real values first** with made-up ones of the same shape, for example a different IP address or user name. Never paste the original data.
