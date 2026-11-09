# Sample Sanitizer

Turn a real log sample into a shareable, de-identified sample — **entirely on-box, with no AI and no external network calls.**

Sharing production log samples is how teams reproduce parsing problems, build pipelines, and file support cases. But raw samples carry hostnames, IPs, usernames, emails, tokens, and other identifiers you can't paste into a ticket, a Slack channel, or a vendor thread. Sample Sanitizer removes that friction: point it at a real sample, review what it found, sanitise, and share the result with confidence.

## What this app does

It finds the identifiers in a sample (IP and MAC addresses, host and user names, emails, certificate names, tokens and other secrets), shows you each one, and replaces them with consistent stand-ins. The sample keeps its structure, so it still parses the same way.

**For** pipeline builders, Stream administrators and support engineers who need to share real events. **Runs on** Cribl.Cloud, or a self-managed Leader with App Platform enabled. It reads and saves samples on Stream worker groups and Edge fleets.

## When to use this app

Use it before you share a production log sample outside its source: in a support case, a vendor thread, a Slack channel, or as test data for a pipeline or pack. It keeps the sample's structure, so a parser built against the sanitised sample still works on the real data.

## How to use

1. **Bring a sample** — upload a file, paste text, pull live events from a Cribl worker group, or search existing worker-group samples (including samples inside installed packs) by name.
2. **Review detected identifiers** — the app highlights the values it will replace (IPs, hostnames, emails, usernames, tokens, and similar), so you see exactly what changes before anything is rewritten.
3. **Sanitise** — identifiers are consistently pseudonymised (the same input value maps to the same replacement throughout the sample, so structure and correlations survive while the real values do not).
4. **Share** — download the sanitised sample, or save it to a shared, per-worker-group sanitised-sample library for your team to reuse.

First run: open the app, choose **Paste events**, paste a few log lines, and press **Identify source**. The Source step names the sourcetype it recognised and how many lines its parser reads. **Review sanitisation** then shows each value before and after. **Apply and verify** checks the result and offers the download or upload.

## Why it's safe to run

- **No AI.** The sanitise engine is fully rule-based and deterministic. There is no model, no prompt, no inference — verifiable in the source and enforced by an automated test that fails the build if any AI dependency is introduced.
- **No external hosts.** The app ships **no proxies** and makes no outbound calls. The only network it touches is your own Cribl leader's API, over the platform's authenticated session.
- **Least-privilege RBAC.** The bundled policy grants only what the app needs: read worker groups/workers, capture events, read and create worker-group samples (replacing one only after you confirm), and **read-only** discovery of samples inside installed packs (so you can pick one to sanitise). It never deletes anything and never writes to packs.
- **A final check on the output.** Before a sanitised sample can be uploaded or downloaded, the whole text is searched again for every value you chose to replace. If any is still there, the app refuses and lists it by line.

## Before you install

- A Cribl Cloud org with the App Platform (Preview) enabled.
- Access to at least one worker group if you want to pull live events or save to the shared library (uploading/pasting a sample works without one). Saving needs a Cribl role that can write that group's samples; capture needs one that can capture.
- **No minimum platform version for credential/secret detection.** The credential/secret patterns ship with the app as a public-source rule library (gitleaks + Microsoft Presidio, both MIT, plus vendor-published token shapes), so pattern-based secret detection works on any supported version with no network call.

## Privacy note

Sanitisation is best-effort de-identification driven by pattern detection. Always review the highlighted identifiers — and the sanitised output — before sharing externally. The app is built from the same sanitise engine as the Cribl Pack Generator.

## Installation

Install from the **Cribl Apps Marketplace** (**Apps → View All → Add App**). You can also upload the packaged `.tgz` from a release directly in **Cribl → Apps**.

After install, an admin must grant open access (**Apps → Sample Sanitizer → Settings → Members & Teams**); App Platform gates who may *open* an installed app separately from `policies.yml`. No configuration is required — open the app and select a sample.

## Configuration

None. The app has no settings, keys or external services to set up. Which worker groups you can capture from or save to follows your Cribl role.

## Permissions and external access

The app asks Cribl for exactly these API permissions (`config/policies.yml`). It has no delete permission.

| Route | Methods | Why |
|---|---|---|
| `/master/groups`, `/master/workers` | GET | The group picker; groups with no connected worker are hidden |
| `/m/*/system/capture` | POST | Pull live events from a worker group |
| `/m/*/system/samples` | GET, POST | List a group's samples, and save a new one |
| `/m/*/system/samples/*` | PATCH | Replace a sample of the same name, only after you confirm |
| `/m/*/system/samples/*/content` | GET | Read a sample to sanitise it |
| `/m/*/packs`, `/m/*/p/*/system/samples`, `/m/*/p/*/system/samples/*/content` | GET | Find and read samples inside installed packs |

External hosts: none. The app declares no proxies.

## Data and storage

- **Processed in the browser.** Detection, replacement and the checks run locally. The original events and the original-to-replacement map exist only in browser memory and are discarded when you save, reset or close the app. Neither is ever written to storage, a download or an upload.
- **Only sanitised output leaves the screen.** An upload goes to the chosen worker group's samples, where anyone with access to that group can read it. A download goes to your machine. The app keeps no copy of either: it writes nothing to the app's KV store or to browser storage.
- **No customer names in the evidence.** The evidence JSON and report describe where the sample came from by type (`uploaded file`, `pasted events`, `worker-group sample`, `live capture`), not by its file or sample name.
- **Nothing is sent outside your Cribl org.** No AI, no external hosts, no telemetry.
- **Size.** Files up to 10 MB can be sanitised. Up to 1 MB can be uploaded to a worker group; larger results can still be downloaded.

## Security

- **Access:** the app acts with the signed-in user's Cribl session and role, so it can do no more than that user. Who can open it is set in **Members & Teams**.
- **Secrets:** the app holds none and asks for none. Secrets found in a sample are scrambled character by character, and the original is never stored.
- **Known vulnerabilities:** none open. `npm audit` reports 0 for the shipped dependencies.
- **Report a vulnerability** privately, as described under [Support](#support).

## Contributing

Issues and pull requests are welcome in this repository. It is generated from the Cribl Pack Generator's development repository, so a maintainer ports an accepted change there and it ships in the next release. See [CONTRIBUTING.md](CONTRIBUTING.md). `npm test` runs the bundled tests, including the ones that keep the sanitise engine AI-free.

## Support

Open an issue in [this repository](https://github.com/Cribl-Community/cc-sample-sanitizer/issues). It is maintained by Wilfred van der Linde (Cribl Solutions Engineering). Critical issues get an answer within 24 hours, Monday to Friday, during business hours (CET). Critical and high-severity bugs are fixed first.

**Security issues.** Report them privately through [**Security → Report a vulnerability**](https://github.com/Cribl-Community/cc-sample-sanitizer/security/advisories/new) — only the maintainers see the report. Do not put exploit details or sample data in a public issue. Fix targets from the report:

| Severity | Fixed within |
|---|---|
| Critical | 10 days |
| High | 4 weeks |
| Medium | 12 weeks |
| Low | 25 weeks |

## Known limitations and troubleshooting

- Detection is pattern based. An identifier in a format the rules don't know is not detected, so always review the output before you share it. A value that *was* detected but sits where the replacement can't reach (glued to another word, as in `backup-jsmith`) blocks the save until you mask it with a pattern.
- A user or host name used as a JSON key (`{"quota":{"jsmith":5}}`) is kept, because names like `admin` are just as often field names. An email, IP or MAC address as a key is replaced.
- Live capture needs a worker group with at least one connected worker; groups without one are hidden.
- Saving to the library needs write access to the worker group's samples in your Cribl role.

## License

Licensed under Apache-2.0 — see `LICENSE`.

## Release notes

- **1.0.276**
  - **Certificate names are sanitised part by part.** `CN\=gw01,O\=acme` (Check Point `originsicname`, TLS subjects) is offered as its gateway and organisation names, also where a name starts another token (`layer_name=gw01-simplified`), and the labels and escaping stay.
  - **The Source step shows the detected sourcetype** with its confidence and why, and **CEF events exported as JSON** (`{"_raw":"CEF:0|…"}`) are recognised offline.
  - **The parser check is honest.** A JSON export is judged by its `_raw`, and the save step shows a tick only when the check passes. A failure the original sample shares says so.
  - **No Pack Generator settings code ships any more**, so the bundle has no AI provider tables.
  - **A final check on the output**: any value you chose to replace that is still in the text blocks the upload or download and is listed by line.
  - **Values next to punctuation are replaced**: an IP or email ending a sentence, both ends of an IP range, case variants of host and user names, URL-encoded emails (`jsmith%40acme.com`) and 59 more top-level domains (`.au`, `.ch`, …).
  - **Email, IP and MAC addresses as JSON keys are replaced**; other keys are still kept.
  - **Upload asks before replacing** a worker-group sample with the same name. The policy no longer includes delete.
  - **Large files**: over 10 MB is refused up front; over 1 MB can be downloaded but not uploaded.
  - **The evidence no longer contains the file name.**
- **1.0.x** — the sanitiser's stable feature set, published from the Cribl Pack Generator monorepo.
  - **Structure errors say where and why.** When sanitising would change the sample's
    structure, the message now names the first line it happens on, what changes there
    (`the field "user.email" would become "user.x"`, or the text before and after), and the
    replacement that causes it, so you know which one to untick or edit.
  - **JSON field names are not rewritten.** A value that also spells a key — GCP audit's
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
