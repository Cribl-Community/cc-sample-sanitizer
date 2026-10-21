# Sample Sanitizer

Turn a real log sample into a shareable, de-identified sample — **entirely on-box, with no AI and no external network calls.**

Sharing production log samples is how teams reproduce parsing problems, build pipelines, and file support cases. But raw samples carry hostnames, IPs, usernames, emails, tokens, and other identifiers you can't paste into a ticket, a Slack channel, or a vendor thread. Sample Sanitizer removes that friction: point it at a real sample, review what it found, sanitise, and share the result with confidence.

## When to use this app

Use it before you share a production log sample outside its source: in a support case, a vendor thread, a Slack channel, or as test data for a pipeline or pack. It keeps the sample's structure, so a parser built against the sanitised sample still works on the real data.

## How to use

1. **Bring a sample** — upload a file, paste text, pull live events from a Cribl worker group, or search existing worker-group samples (including samples inside installed packs) by name.
2. **Review detected identifiers** — the app highlights the values it will replace (IPs, hostnames, emails, usernames, tokens, and similar), so you see exactly what changes before anything is rewritten.
3. **Sanitise** — identifiers are consistently pseudonymised (the same input value maps to the same replacement throughout the sample, so structure and correlations survive while the real values do not).
4. **Share** — download the sanitised sample, or save it to a shared, per-worker-group sanitised-sample library for your team to reuse.

## Why it's safe to run

- **No AI.** The sanitise engine is fully rule-based and deterministic. There is no model, no prompt, no inference — verifiable in the source and enforced by an automated test that fails the build if any AI dependency is introduced.
- **No external hosts.** The app ships **no proxies** and makes no outbound calls. The only network it touches is your own Cribl leader's API, over the platform's authenticated session.
- **Least-privilege RBAC.** The bundled policy grants only what the app needs: read worker groups/workers, capture events, read/write the sanitised-sample library, and **read-only** discovery of samples inside installed packs (so you can pick one to sanitise). It never writes to packs.

## Before you install

- A Cribl Cloud org with the App Platform (Preview) enabled.
- Access to at least one worker group if you want to pull live events or save to the shared library (uploading/pasting a sample works without one).
- **No minimum platform version for credential/secret detection.** The credential/secret patterns ship with the app as a public-source rule library (gitleaks + Microsoft Presidio, both MIT, plus vendor-published token shapes), so pattern-based secret detection works on any supported version with no network call.

## Privacy note

Sanitisation is best-effort de-identification driven by pattern detection. Always review the highlighted identifiers — and the sanitised output — before sharing externally. The app is built from the same sanitise engine as the Cribl Pack Generator.

## Installation

Install from the **Cribl Apps Marketplace** (**Apps → View All → Add App**). You can also upload the packaged `.tgz` from a release directly in **Cribl → Apps**.

After install, an admin must grant open access (**Apps → Sample Sanitizer → Settings → Members & Teams**); App Platform gates who may *open* an installed app separately from `policies.yml`. No configuration is required — open the app and select a sample.

## Configuration

None. The app has no settings, keys or external services to set up. Which worker groups you can capture from or save to follows your Cribl role.

## Permissions and external access

The app asks Cribl for these API permissions (`default/policies.yml`):

- **Worker groups and workers**: read, for the group picker and to hide groups with no connected worker.
- **Capture** (`/m/*/system/capture`): to pull live events from a worker group.
- **Samples** (`/m/*/system/samples`): read and write the shared sanitised-sample library. Delete (`/m/*/system/samples/*`) removes a library entry when you delete it in the app.
- **Packs and pack samples**: read only, to find samples inside installed packs.

External hosts: none. The app declares no proxies.

## Data and storage

- Your sample is processed in the browser. The raw sample is not stored by the app.
- Sanitised samples you save go to the worker group's sample library, where anyone with access to that group can read them, and are also recorded in the app's own KV store. Downloads go to your machine. Only sanitised output is saved.
- Nothing is sent outside your Cribl org.

## Contributing

Issues and pull requests are welcome in this repository. It is generated from the Cribl Pack Generator's development repository, so a maintainer ports an accepted change there and it ships in the next release. See [CONTRIBUTING.md](CONTRIBUTING.md). `npm test` runs the bundled tests, including the ones that keep the sanitise engine AI-free.

## Support

Open an issue in [this repository](https://github.com/Cribl-Community/cc-sample-sanitizer/issues). It is maintained by Wilfred van der Linde (Cribl Solutions Engineering), who aims to fix critical security issues within 10 days and high ones within 4 weeks.

## Known limitations and troubleshooting

- Detection is pattern based. An identifier in a format the rules don't know can survive, so always review the output before you share it.
- Live capture needs a worker group with at least one connected worker; groups without one are hidden.
- Saving to the library needs write access to the worker group's samples in your Cribl role.

## License

Licensed under Apache-2.0 — see `LICENSE`.

## Release notes

- **1.0.x (current)** — the sanitiser's stable feature set, published from the Cribl Pack Generator monorepo.
  - **Structure errors say where and why.** When sanitising would change the sample's
    structure, the message now names the first line it happens on, what changes there
    (`the field "user.email" would become "user.x"`, or the text before and after), and the
    replacement that causes it, so you know which one to untick or edit.
  - **JSON field names are never rewritten.** A value that also spells a key — GCP audit's
    `compute.googleapis.com` service name inside the `compute.googleapis.com/root_trigger_id`
    label key, or a user called `admin` next to an `"admin": true` flag — is replaced in values
    only, so the sample no longer stops at "JSON line(s) changed their field names".
  - **The wire format can never change.** Every replacement is guaranteed to preserve the
    line's structure — the count of tabs, pipes, commas, `=` and spaces is held constant, so a
    positional or delimited parser still splits the sample into the same fields it did before.
    A stand-in that would have shifted a boundary (a display name like `John Smith` collapsing to
    one token, for instance) is re-minted by shape instead. This is enforced at the point the
    alias is created, not merely checked afterwards, so no identifier class can break the layout.
  - **A mis-recognised source no longer blocks a clean sample.** When a key-value/CEF log is
    matched to a positional parser, whole `key=value` chunks can land in address-named columns
    (`src_ip = "quotePriority=NORMAL"`). The identity-coverage proof recognises that an
    address field holding a non-address value is a parse artefact, not a leaked identity, so it
    stops demanding the impossible while still holding real, unmasked IPs to account.
  - **Clearer sanitise step.** The masking choice is a single chip row — *Whole value* is
    selected by default, with one chip per detectable piece of the value — and the before/after
    panes are always visible side by side. When an identity does survive, the alert names the
    exact line and field so it can be fixed in one look.
  - **Credential/secret pattern detection** ships with the app as a public-source rule
    library (gitleaks + Microsoft Presidio, both MIT, plus vendor-published token shapes). There is
    no network call and no minimum platform version — a JWT, an AWS key pair, a connection URI's
    password, a card number and an SSN are removed before a sample can be shared, on any supported
    version. The rules are filtered before use (patterns that are only a character class and a length
    are dropped so they can't rewrite field names) and scrambled character-for-character so length,
    delimiters and structure survive.
  - **Core intake and sharing** — file/paste/worker-group sample intake, identifier review,
    deterministic pseudonymisation, download, and a per-worker-group shared sanitised-sample library.
