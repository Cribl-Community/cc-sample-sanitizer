/**
 * AI-generated sample library — shared conventions + the verification gate.
 *
 * WHY THIS EXISTS
 * The app can always fall back to asking a model for sample events, but nothing
 * used to check that the generated events were something the pipeline's own
 * parser could actually read. A sample the parser can't read produces a pipeline
 * that extracts nothing, which then shows up much later as "extraction 0" on a
 * deployed pack. This module is the gate: generate → VERIFY against the real
 * parser → only then keep it.
 *
 * Verified samples are stored in `config/ai-samples/` (committed, one file per
 * sample) so every user and every fresh clone gets them without paying the AI
 * cost again. That directory holds ONLY AI-generated content — deliberately
 * separated from the mined pack samples (`config/sample-library/`) and the real
 * vendor logs (`config/source-samples.json`) so a bad one can be spotted in a
 * diff and removed with a single `git rm`.
 *
 * BOTH RUN MODES (Hard Rule 18): this is plain TS with no Node imports, so the
 * iframe bundle imports it directly and the standalone backend `.mjs` handlers
 * import it through tsx. There is no mirrored copy to drift.
 */

import {
  canonicalizeSourcetype,
  getParserFieldNames,
  getParserForSourcetype,
  sampleFingerprint,
  sampleMatchesSourceExpectation,
  type PipelineFunction,
} from './source-recognition';
import sourcetypeAliasData from '../config/sourcetype-aliases.json';

// --- Keys and file names ------------------------------------------------------
// Mirrors golden-github.mjs's `keyToFile`: `::` is the key separator and `__` is
// its on-disk spelling, so the two stores read the same way.

/** `<sourcetype>` or `<sourcetype>::<wireFormat>` for multi-format sources. */
export function aiSampleKey(sourcetype: string, format?: string | null): string {
  const st = canonicalizeSourcetype(sourcetype);
  const fmt = (format || '').trim().toLowerCase();
  return fmt ? `${st}::${fmt}` : st;
}

export function aiSampleKeyToFile(key: string): string {
  return `${key.replace(/::/g, '__')}.json`;
}

/**
 * Exact store-key aliases: `config/sourcetype-aliases.json` → `storeKeys`. Distinct
 * from the substring `aliases` map in the same file, which is for the reference
 * CATALOG — a store lookup is file equality, and a substring pattern there could serve
 * a neighbouring product's real log as if it were ours.
 */
const SAMPLE_STORE_ALIASES: Record<string, string> = sourcetypeAliasData.storeKeys || {};

/**
 * The keys a sample store should be asked for, in order: the format-specific key, the
 * bare sourcetype, then the same two under an aliased name.
 *
 * The alias tier exists because a customer's sourcetype name usually carries the
 * COLLECTING TEAM's prefix, not the vendor's (`ncsc_cloudflare_device_posture`,
 * `mscs_azure_eventhub`), while the harvested stores are keyed by the vendor's own
 * dataset name. Without it the real Cloudflare Logpush events sat unread on disk while
 * a fabricated sample for the same source went to the review queue on a structure-only
 * pass — the real log loses to a generated one purely because of the prefix.
 *
 * Used by BOTH `getVendorLibrarySample` implementations (Hard Rule 18) so there is one
 * resolution order, not a mirror of one.
 */
export function sampleStoreKeys(sourcetype: string, format?: string | null): string[] {
  const keys: string[] = [];
  const add = (st: string) => {
    if (format) keys.push(aiSampleKey(st, format));
    keys.push(aiSampleKey(st));
  };
  add(sourcetype);
  const alias = SAMPLE_STORE_ALIASES[canonicalizeSourcetype(sourcetype)];
  if (alias) add(alias);
  return [...new Set(keys)];
}

export function aiSampleFileToKey(file: string): string {
  return file.replace(/\.json$/, '').replace(/__/g, '::');
}

/**
 * Content fingerprint used by the rejection list. Deleting a bad sample only
 * helps if it cannot come straight back on the next run, so `rejected.json`
 * records this and the promote step refuses anything matching.
 *
 * Deliberately a plain string hash (djb2) rather than node:crypto — this module
 * runs in the browser too, and collision resistance is not a security property
 * here: a false match would only mean re-verifying a sample we already trusted.
 */
export function sampleRejectionFingerprint(events: string[]): string {
  const joined = (events || []).join('\n');
  let h = 5381;
  for (let i = 0; i < joined.length; i++) h = ((h << 5) + h + joined.charCodeAt(i)) | 0;
  return `${(h >>> 0).toString(16)}-${joined.length}`;
}

// --- Document shape -----------------------------------------------------------

export interface SampleVerification {
  /**
   * `fail` means a check ran and the sample lost it. `unverified` means no check
   * could run at all — NOT the same thing, and not rendered as a failure. (Same
   * rule the scoring lenses follow: an unmeasurable stage is not a zero.)
   */
  verdict: 'pass' | 'fail' | 'unverified';
  /** Which check produced the verdict. */
  method: 'parser-emulation' | 'source-expectation' | 'structure' | 'none';
  /** Events from which the emulated parser extracted at least one field. */
  eventsParsed: number;
  /** Events actually checked (the sample is capped for speed). */
  eventsChecked: number;
  /** Distinct field names the emulated parser produced. */
  fields: string[];
  /** Human-readable reasons — the retry prompt quotes these back to the model. */
  reasons: string[];
  /** Up to 3 events that yielded nothing, for the retry prompt. */
  offendingEvents: string[];
  /**
   * The sourcetype key found echoed into the events themselves (see `detectKeyEcho`).
   * Always measured; only *fails* a sample when the events are synthetic, because a
   * real vendor log is ground truth whatever it happens to contain.
   */
  keyEcho?: KeyEchoFinding | null;
}

export interface AiSampleProvenance {
  model?: string;
  buildNumber?: number;
  generatedAt?: string;
  /** How the generation was grounded: recognition facts, a real anchor line, … */
  grounding?: string;
}

export interface AiSampleDoc {
  version: 1;
  key: string;
  sourcetype: string;
  format?: string;
  events: string[];
  fingerprint: string;
  verification: SampleVerification;
  provenance: AiSampleProvenance;
}

export function buildAiSampleDoc(args: {
  sourcetype: string;
  format?: string | null;
  events: string[];
  verification: SampleVerification;
  provenance?: AiSampleProvenance;
}): AiSampleDoc {
  const key = aiSampleKey(args.sourcetype, args.format);
  return {
    version: 1,
    key,
    sourcetype: canonicalizeSourcetype(args.sourcetype),
    format: (args.format || '').trim().toLowerCase() || undefined,
    events: args.events,
    fingerprint: sampleRejectionFingerprint(args.events),
    verification: args.verification,
    provenance: args.provenance || {},
  };
}

// --- Parser emulation ---------------------------------------------------------
// `getParserForSourcetype` returns Cribl pipeline function specs, not runnable
// code, so to answer "will the parser read this?" without deploying anything we
// emulate the function types that do the actual extracting:
//
//   regex_extract — conf.regex is a JS regex literal in a string; its named
//                   groups ARE the extracted field names.
//   serde extract — json / kvp / csv, all straightforwardly reproducible.
//   eval          — ONLY `a || b || c` chains of bare field names, resolved by
//                   lookup (resolveAliasChain). Arbitrary Cribl expressions are
//                   NOT evaluated.
//
// That narrow slice of `eval` is not optional. Several parsers route the raw line
// into a scratch field before parsing it: FortiGate does
// `__kvp_src = __cef_ext || _raw` and then runs its kvp serde on `__kvp_src`, so
// that single CEF-or-native fork carries every field the parser extracts. While
// evals were skipped outright the serde had an undefined source, real FortiGate
// logs looked unparseable, and the vendor-sample gate rejected them as
// wrong-format — a false negative in the checker, read as a bad sample.
//
// `lookup` / `code` still make the chain unemulatable — cisco_asa, for instance,
// gets its fields from a CSV-lookup regex applied inside an eval. Those cases
// fall through to the source-expectation check rather than being failed.

const MAX_EVENTS_CHECKED = 40;

/** Parse a Cribl `conf.regex` string (`/body/flags`) into a RegExp. */
function parseRegexLiteral(raw: unknown): RegExp | null {
  const s = String(raw || '');
  if (!s) return null;
  const m = s.match(/^\/(.*)\/([gimsuy]*)$/s);
  try {
    return m ? new RegExp(m[1], m[2].replace(/g/g, '')) : new RegExp(s);
  } catch {
    return null;
  }
}

/** Collect leaf paths of a parsed JSON value (dotted, like Cribl accessors). */
function jsonLeafPaths(value: unknown, prefix = '', out: Set<string> = new Set()): Set<string> {
  if (value === null || typeof value !== 'object') {
    if (prefix) out.add(prefix);
    return out;
  }
  if (Array.isArray(value)) {
    if (prefix) out.add(prefix);
    return out;
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    jsonLeafPaths(v, prefix ? `${prefix}.${k}` : k, out);
  }
  return out;
}

/** The value at a dotted leaf path produced by `jsonLeafPaths`. */
function jsonLeafValue(root: unknown, path: string): unknown {
  let cur: unknown = root;
  for (const key of path.split('.')) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}

/** Split a CSV line on the delimiter, honouring double-quoted values. */
function splitCsv(line: string, delim: string): string[] {
  const out: string[] = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQ) {
      if (ch === '"') inQ = false; else cur += ch;
    } else if (ch === '"') inQ = true;
    else if (ch === delim) { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

/**
 * A Cribl eval value that is nothing but field names joined by `||` (optionally
 * ending in `undefined`) — `'__cef_ext || _raw'`, `'src_ip || srcaddr || srcip'`.
 * Resolving these by lookup is safe and needs no expression evaluation; anything
 * with an operator, call, literal or ternary in it is left alone.
 */
const ALIAS_CHAIN = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\s*\|\|\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)*$/;

/** First operand of an alias chain that has a non-empty value on the event. */
function resolveAliasChain(expr: string, event: Record<string, unknown>): unknown {
  for (const name of expr.split('||').map(s => s.trim())) {
    if (name === 'undefined') continue;
    const v = event[name];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

interface EmulationResult {
  fields: Set<string>;
  /** True when at least one regex_extract/serde function was available to run. */
  emulatable: boolean;
  /** True when a lookup/code function means the real parser extracts more. */
  partial: boolean;
  /** The event the functions built — field name → value, for `extractFieldValues`. */
  values: Record<string, unknown>;
}

/**
 * Run the emulatable parser functions over ONE raw line and report the field
 * names they produce. Functions are applied in order and share an event object,
 * so a later `regex_extract` reading `source: 'message'` sees what an earlier one
 * captured — the f5_bigip parser depends on exactly that chaining.
 */
function emulateParse(fns: PipelineFunction[], rawLine: string): EmulationResult {
  const event: Record<string, unknown> = { _raw: rawLine };
  const fields = new Set<string>();
  let emulatable = false, partial = false;

  for (const fn of fns) {
    const conf = (fn.conf || {}) as Record<string, unknown>;
    if (fn.id === 'regex_extract') {
      const re = parseRegexLiteral(conf.regex);
      if (!re) { partial = true; continue; }
      emulatable = true;
      const src = event[String(conf.source || '_raw')];
      if (typeof src !== 'string') continue;
      const m = re.exec(src);
      if (!m?.groups) continue;
      for (const [k, v] of Object.entries(m.groups)) {
        if (v === undefined) continue;
        event[k] = v;
        // `__`-prefixed fields are internal plumbing (CEF header capture etc.),
        // not source content — don't let them inflate the field count.
        if (!k.startsWith('__')) fields.add(k);
      }
    } else if (fn.id === 'serde' && String(conf.mode || 'extract') === 'extract') {
      const type = String(conf.type || '');
      const src = event[String(conf.srcField || '_raw')];
      if (typeof src !== 'string') { if (type) partial = true; continue; }
      if (type === 'json') {
        emulatable = true;
        try {
          const parsed = JSON.parse(src);
          for (const p of jsonLeafPaths(parsed)) {
            // The leaf VALUE, not a `true` placeholder: the sanitiser reads these to
            // learn which values are identities, and a placeholder tells it nothing.
            // `fields` is unaffected, so field counting is unchanged.
            const v = jsonLeafValue(parsed, p);
            event[p] = v === undefined ? true : v;
            fields.add(p);
          }
        } catch { /* unparseable line — counts as extracting nothing */ }
      } else if (type === 'kvp') {
        emulatable = true;
        const delim = String(conf.delimChar || ' ');
        const quote = String(conf.quoteChar || '"');
        const q = quote.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const d = delim.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = new RegExp(`([\\w.\\-]+)=(${q}[^${q}]*${q}|[^${d}]*)`, 'g');
        let m: RegExpExecArray | null;
        while ((m = re.exec(src)) !== null) {
          if (!m[1]) continue;
          event[m[1]] = m[2];
          if (!m[1].startsWith('__')) fields.add(m[1]);
        }
      } else if (type === 'csv') {
        emulatable = true;
        const names = Array.isArray(conf.fields) ? (conf.fields as string[]) : [];
        const cols = splitCsv(src, String(conf.delimChar || ','));
        // A CSV parser only really read the line if the column count is in the
        // right ballpark — a 3-column line fed to a 47-column PAN parser has not
        // been parsed, it has been misread.
        if (names.length && cols.length >= Math.ceil(names.length * 0.5)) {
          names.forEach((n, i) => {
            if (!n || cols[i] === undefined || cols[i] === '') return;
            event[n] = cols[i];
            if (!n.startsWith('__')) fields.add(n);
          });
        }
      } else {
        partial = true;
      }
    } else if (fn.id === 'eval') {
      // Only alias chains (see ALIAS_CHAIN). Anything else is left unevaluated;
      // it derives values from fields already counted, so skipping it can only
      // undercount — never invent a field the parser doesn't produce.
      const add = Array.isArray(conf.add) ? (conf.add as { name?: unknown; value?: unknown }[]) : [];
      for (const entry of add) {
        const name = String(entry?.name || '');
        const expr = String(entry?.value ?? '').trim();
        if (!name || !ALIAS_CHAIN.test(expr)) continue;
        const v = resolveAliasChain(expr, event);
        if (v === undefined) continue;
        event[name] = v;
        if (!name.startsWith('__')) fields.add(name);
      }
    } else if (fn.id === 'lookup' || fn.id === 'code') {
      // The real parser extracts through these; we can't. Whatever we measure is
      // a floor, so a zero here must never be reported as a failure.
      partial = true;
    }
  }
  return { fields, emulatable, partial, values: event };
}

/**
 * Run the emulatable parser functions over one raw line and return the field VALUES.
 *
 * The sanitiser needs this to find identities the way a parser sees them rather than the
 * way a regex guesses. A bare username or short hostname is invisible to any pattern — in
 * an Apache access line `jsmith` is just a word between an IP and a bracket — but the
 * parser that reads the line names it `user`, and a named field with a known meaning is
 * exactly what tells the sanitiser to replace its value.
 *
 * Only string values come back: the callers care about text that appears in the raw line,
 * and a number or boolean is neither an identity nor safely replaceable. `_raw` is
 * excluded for the same reason — it is the whole line, not a field within it.
 */
export function extractFieldValues(fns: PipelineFunction[], rawLine: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!fns?.length || !rawLine) return out;
  const { values } = emulateParse(fns, rawLine);
  for (const [k, v] of Object.entries(values)) {
    if (k === '_raw' || k.startsWith('__')) continue;
    if (typeof v === 'string' && v) out[k] = v;
  }
  return out;
}

// --- The verification gate ----------------------------------------------------

/** Fraction of events that must yield fields for a sample to pass. */
const MIN_PARSE_RATIO = 0.8;
/** A sample yielding fewer distinct fields than this hasn't really been parsed. */
const MIN_FIELDS = 3;

/**
 * Can the pipeline's own parser read these events?
 *
 * Strongest available check wins:
 *   1. parser emulation — the real regexes/serdes, run locally.
 *   2. source expectation — shares `sampleMatchesSourceExpectation` with the
 *      golden guard, for parsers we can't emulate (lookup/code driven).
 *   3. neither → `unverified`. Not a pass and not a failure; the review step
 *      shows it as unverified so a human decides.
 *
 * `opts.synthetic` says these events came from a MODEL, not from a vendor. It adds
 * one check that only makes sense for generated data: the sourcetype key echoed
 * into the events (`detectKeyEcho`). The echo is measured either way and reported
 * on the result, but it only fails a synthetic sample — a real vendor log is ground
 * truth whatever it contains, and rejecting one for its own contents would be the
 * checker overruling the evidence.
 */
export function verifyGeneratedSample(
  sourcetype: string,
  events: string[],
  opts: { synthetic?: boolean } = {},
): SampleVerification {
  const list = (events || []).filter(e => typeof e === 'string' && e.trim().length > 0);
  const base: SampleVerification = {
    verdict: 'unverified', method: 'none', eventsParsed: 0,
    eventsChecked: 0, fields: [], reasons: [], offendingEvents: [], keyEcho: null,
  };
  if (list.length === 0) {
    return { ...base, verdict: 'fail', reasons: ['no events'] };
  }

  const checked = list.slice(0, MAX_EVENTS_CHECKED);
  const keyEcho = detectKeyEcho(sourcetype, checked);
  // A fabricated sample can still satisfy every structural check — the events are
  // well-formed, they just describe a log nobody ships. So this verdict is applied
  // LAST, over whatever the format checks concluded.
  const withEcho = (v: SampleVerification): SampleVerification => {
    if (!keyEcho) return { ...v, keyEcho: null };
    if (!opts.synthetic) return { ...v, keyEcho };
    return {
      ...v, keyEcho, verdict: 'fail',
      reasons: [keyEchoReason(keyEcho), ...v.reasons],
      offendingEvents: v.offendingEvents.length ? v.offendingEvents : checked.slice(0, 3).map(e => e.slice(0, 300)),
    };
  };
  let parserFns: PipelineFunction[] = [];
  try {
    parserFns = getParserForSourcetype(sourcetype, false) || [];
  } catch {
    parserFns = [];
  }

  // An UNRECOGNIZED sourcetype gets a generic `serde json` from
  // getParserForSourcetype — a default guess, not knowledge about this source.
  // Emulating it would hard-fail every non-JSON unknown source, which is exactly
  // the population the library most needs to cover, so route those to the
  // structural check instead. `getParserFieldNames` is empty precisely when no
  // source-specific parser exists.
  const hasSourceSpecificParser = getParserFieldNames(sourcetype).length > 0;
  if (!hasSourceSpecificParser) {
    return withEcho(verifyByStructure(sourcetype, checked));
  }

  const allFields = new Set<string>();
  const offending: string[] = [];
  let parsed = 0, emulatable = false, partial = false;

  for (const line of checked) {
    const r = emulateParse(parserFns, line);
    emulatable = emulatable || r.emulatable;
    partial = partial || r.partial;
    if (r.fields.size > 0) {
      parsed++;
      for (const f of r.fields) allFields.add(f);
    } else if (offending.length < 3) {
      offending.push(line.slice(0, 300));
    }
  }

  if (emulatable) {
    const ratio = parsed / checked.length;
    const fields = [...allFields].sort();
    const reasons: string[] = [];
    if (ratio < MIN_PARSE_RATIO) {
      reasons.push(`the ${sourcetype} parser extracted no fields from ${checked.length - parsed} of ${checked.length} events`);
    }
    if (fields.length < MIN_FIELDS) {
      reasons.push(`only ${fields.length} distinct field(s) extracted (need ${MIN_FIELDS}) — the events do not carry this source's structure`);
    }
    // A wrong-format sample can still satisfy a permissive parser (a kvp serde
    // happily reads `k=v` out of the wrong vendor's log), so the expectation
    // check is applied as well when one is declared.
    if (sampleMatchesSourceExpectation(sourcetype, checked.join('\n')) === 'mismatch') {
      reasons.push(`the events do not match the wire format declared for ${sourcetype} (wrong log family or missing critical keys)`);
    }
    return withEcho({
      verdict: reasons.length === 0 ? 'pass' : 'fail',
      method: 'parser-emulation',
      eventsParsed: parsed, eventsChecked: checked.length,
      fields, reasons,
      offendingEvents: reasons.length === 0 ? [] : offending,
    });
  }

  // No emulatable extractor (lookup/code-driven parser, or no parser at all).
  const expectation = sampleMatchesSourceExpectation(sourcetype, checked.join('\n'));
  if (expectation === 'match') {
    return withEcho({
      ...base, verdict: 'pass', method: 'source-expectation', eventsChecked: checked.length,
      reasons: [`${sourcetype}'s parser cannot be checked locally${partial ? ' (lookup/code driven)' : ''}; the events match its declared wire format`],
    });
  }
  if (expectation === 'mismatch') {
    return withEcho({
      ...base, verdict: 'fail', method: 'source-expectation', eventsChecked: checked.length,
      reasons: [`the events do not match the wire format declared for ${sourcetype} (wrong log family or missing critical keys)`],
      offendingEvents: checked.slice(0, 3).map(e => e.slice(0, 300)),
    });
  }
  return withEcho({
    ...base, method: 'none', eventsChecked: checked.length,
    reasons: [`no parser and no declared wire format for ${sourcetype} — nothing to verify against`],
  });
}

// --- Fabrication detector: the sourcetype key echoed into the event -----------
//
// The strongest signal that a model wrote from the KEY rather than from the
// format. Found on 6 of 34 staged samples, on 100% of their lines:
//
//   estreamer-sensor01 cisco_estreamer_data_dns: timestamp=1705…
//   ivanti-ps01 ivanti_ps: AUT24229: …
//   ics-gw01 ivantitop[14522]: INFO AUTH_SUCCESS realm="Employees" …
//   … event_type=http_fpc_metadata severity=INFO …
//
// No real daemon is named after a Splunk sourcetype, and no vendor emits its own
// Splunk sourcetype as a field value. A pack built on such a sample matches
// nothing in production.
//
// SCOPE IS DELIBERATELY NARROW, and the boundaries were MEASURED against the 638
// harvested vendor docs plus source-samples.json — a rule that flags real logs is not
// a rule, it is a second bug.
//
//  * The key must appear in a POSITION THE WIRE FORMAT OWNS — syslog program/tag, a
//    field name, or a field value — never merely somewhere in the line. Hypori's real
//    Java logger is `[com.hypori.session.SessionManager]`; a vendor name inside a
//    dotted class path is what a real log looks like, and the tag/field boundaries
//    already exclude it.
//  * MULTI-TOKEN KEYS ONLY. This is the guard the sweep actually justified: with
//    single-token keys allowed, the real `haproxy` vendor sample is flagged on 13 of
//    15 lines, because a one-word sourcetype usually IS the daemon name (haproxy,
//    sshd, postfix, nginx). There is no way to tell that from a fabrication, so
//    single-token keys are out of reach on purpose. Cost: `ivantitop`, `aemcdn` and
//    `hypori` are not caught here — they need a human, or the squashed-duplicate flag.
//  * FIELD-VALUE echo is the WEAKEST of the three positions, and knowing that is the
//    reason `synthetic` exists. Four real vendor docs carry their own key as a field
//    value (`"event.dataset":"elasticsearch.server"`, `"type":"akamai_siem"`) — because
//    our key was DERIVED from Elastic's dataset name in the first place. On a real log
//    that is ground truth; only on generated events is it evidence of the prompt
//    leaking into the answer.
//
// Net on the real 34-sample queue: 3 flagged (cisco_estreamer_data_dns, ivanti_ps,
// http_fpc_metadata), 0 of 638 real vendor docs affected, since none is synthetic.

/** `syslog program[pid]:` / `program:` tag position at the head of a line. */
const SYSLOG_TAG_RE = /(?:^|\s)([A-Za-z][\w.-]{2,})(?:\[\d+\])?:\s/;

export interface KeyEchoFinding {
  /** The key form found echoed in the events. */
  form: string;
  /** Where it appeared — the reason this is evidence and not coincidence. */
  position: 'syslog-program' | 'field-name' | 'field-value';
  /** How many of the checked lines carry it. */
  lines: number;
  /** Lines checked. */
  checked: number;
  /** One redacted excerpt, for the reason text and the retry prompt. */
  excerpt: string;
}

/**
 * Does the sourcetype key appear in a position the WIRE FORMAT owns?
 *
 * Returns null for anything that isn't evidence. Requires the echo on a majority
 * of lines: one line mentioning the key could be a coincidence in free text, but a
 * model that used the key as the program name uses it on every line.
 */
export function detectKeyEcho(sourcetype: string, events: string[]): KeyEchoFinding | null {
  const raw = String(sourcetype || '').split('::')[0].trim();
  if (!raw) return null;
  const tokens = raw.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  // A one-word sourcetype usually IS the daemon name — measured: allowing them flags
  // the real `haproxy` vendor sample on 13 of 15 lines. Nothing distinguishes that
  // from a fabrication, so they are out of scope.
  if (tokens.length < 2) return null;
  const forms = [...new Set([
    raw.toLowerCase(),
    tokens.join(''),      // squashed: ivantitop
    tokens.join('_'),
    tokens.join('-'),
    tokens.join('.'),
  ])].filter(f => f.length >= 6);
  const lines = (events || []).map(e => String(e ?? '')).filter(l => l.trim());
  if (!lines.length) return null;

  let best: KeyEchoFinding | null = null;
  for (const form of forms) {
    const fieldName = new RegExp(`(?:^|[\\s,{"'])"?${escapeRe(form)}"?\\s*[=:]`, 'i');
    const fieldValue = new RegExp(`[=:]\\s*"?${escapeRe(form)}"?(?:[\\s,"'}]|$)`, 'i');
    const counts: Record<KeyEchoFinding['position'], number> = { 'syslog-program': 0, 'field-name': 0, 'field-value': 0 };
    const excerpts: Partial<Record<KeyEchoFinding['position'], string>> = {};
    for (const line of lines) {
      const tag = SYSLOG_TAG_RE.exec(line);
      let pos: KeyEchoFinding['position'] | null = null;
      if (tag && tag[1].toLowerCase() === form) pos = 'syslog-program';
      else if (fieldName.test(line)) pos = 'field-name';
      else if (fieldValue.test(line)) pos = 'field-value';
      if (!pos) continue;
      counts[pos]++;
      if (!excerpts[pos]) {
        const i = line.toLowerCase().indexOf(form);
        excerpts[pos] = line.slice(Math.max(0, i - 30), i + form.length + 20);
      }
    }
    for (const pos of Object.keys(counts) as KeyEchoFinding['position'][]) {
      const hit = counts[pos];
      if (hit * 2 <= lines.length) continue; // needs a majority, not an anecdote
      if (best && best.lines >= hit) continue;
      best = { form, position: pos, lines: hit, checked: lines.length, excerpt: excerpts[pos] || '' };
    }
  }
  return best;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** The reason line a key echo contributes to a verification verdict. */
export function keyEchoReason(f: KeyEchoFinding): string {
  const where = f.position === 'syslog-program'
    ? 'as the syslog program name'
    : f.position === 'field-name' ? 'as a field name' : 'as a field value';
  return `the sourcetype key "${f.form}" appears ${where} on ${f.lines} of ${f.checked} events (…${f.excerpt}…) — real logs are not named after a Splunk sourcetype, so these events were written from the key rather than from the vendor's format`;
}

// --- Evidence tier: what a verdict is actually worth --------------------------

export type SampleEvidence = 'parser-verified' | 'format-declared' | 'structure-only' | 'none';

/**
 * Collapse a verification into what it PROVES, for display and ordering.
 *
 * `verdict: 'pass'` alone is not an answer to "is this sample correct?" — it is
 * produced by three checks of very different strength, and a review screen that
 * renders them identically invites approving fabricated data. Measured on a real
 * 34-sample queue: 3 parser-verified, 17 structure-only, 14 unverifiable — and one
 * of the structure-only "passes" (`ncsc_cloudflare_device_posture`) had 0 of 15
 * field names in common with the real captured Cloudflare event.
 *
 *  * `parser-verified` — the source's own parser read the events. Real evidence.
 *  * `format-declared` — no emulatable parser, but the events match the wire
 *    format declared in GOLDEN_SOURCE_EXPECTATIONS. Good evidence.
 *  * `structure-only` — we know nothing about this vendor; the events are merely
 *    well-formed data with ≥3 keys. NOT evidence about the format.
 *  * `none` — nothing could be checked.
 */
export function sampleEvidence(v: Pick<SampleVerification, 'verdict' | 'method'> | null | undefined): SampleEvidence {
  if (!v || v.verdict !== 'pass') return 'none';
  if (v.method === 'parser-emulation') return 'parser-verified';
  if (v.method === 'source-expectation') return 'format-declared';
  if (v.method === 'structure') return 'structure-only';
  return 'none';
}

/** Short, honest label for the review UI. Never says "verified" unless it was. */
export function sampleEvidenceLabel(e: SampleEvidence): string {
  switch (e) {
    case 'parser-verified': return 'parser-verified';
    case 'format-declared': return 'matches declared format';
    case 'structure-only': return 'structure only — format unproven';
    default: return 'not checked';
  }
}

// --- Real customer volume, for RANKING only ----------------------------------
//
// The census is REAL CUSTOMER DATA and is deliberately NOT in this repo. It used to be
// a static `import` of `config/sourcetype-volumes.json`, which put 542 customer
// sourcetype volumes into this module's import graph — and this module is reachable
// from the Sample Sanitizer, whose reachable SOURCE is published for review (Hard Rules
// 25 & 29). That is how a customer census reached a public-bound repo.
//
// So the data is PUSHED IN, never imported: `setSourcetypeVolumes()` is called by the
// standalone backend from a gitignored local file if the maintainer has one. Loading it
// at runtime (rather than as a module import) is the load-bearing part — an import can
// be bundled and published, a runtime read cannot. Same reasoning as the secret rules
// (Hard Rule 31). With nothing pushed in, ranking degrades to "unranked" and every
// caller still works.

const VOLUME_INDEX = new Map<string, number>();

/** Census key → squashed lookup key, so colon/underscore/case spellings agree. */
const squashVolumeKey = (name: string) => String(name || '').toLowerCase().replace(/[^a-z0-9]/g, '');

/**
 * Install the volume census (standalone only; see the note above).
 *
 * Accepts the census shape `{ "<name>": { total } }` or a flat `{ "<name>": number }`.
 * Replaces whatever was installed before, so a reload cannot accumulate.
 */
export function setSourcetypeVolumes(volumes: Record<string, { total?: number } | number> | null | undefined): void {
  VOLUME_INDEX.clear();
  for (const [name, rec] of Object.entries(volumes || {})) {
    const total = Number(typeof rec === 'number' ? rec : rec?.total) || 0;
    const squashed = squashVolumeKey(name);
    if (!squashed) continue;
    // Keep the largest when two census names squash together.
    if ((VOLUME_INDEX.get(squashed) ?? 0) < total) VOLUME_INDEX.set(squashed, total);
  }
}

/** How many census rows are installed — 0 means ranking is off, not that volumes are 0. */
export function sourcetypeVolumesLoaded(): number {
  return VOLUME_INDEX.size;
}

/**
 * Event count this sourcetype carries in the real customer census, or null.
 *
 * ONLY for ordering work — never for deciding whether a source is buildable
 * (recognition is separate from buildability, and a 1-event source is still a
 * legitimate source). Census names are colon-separated (`cisco:estreamer:data:firewall`)
 * where app keys are underscore-separated, so the lookup is squash-insensitive.
 *
 * Returns null when no census is installed — `null` and `0` must stay distinguishable:
 * unranked is not "the lowest-volume source we know".
 */
export function sourcetypeVolume(sourcetype: string): number | null {
  const raw = squashVolumeKey(String(sourcetype || '').split('::')[0]);
  if (!raw) return null;
  return VOLUME_INDEX.get(raw) ?? null;
}

/**
 * Keys in a staged batch that are the separator-less spelling of a sourcetype already
 * present in its separated form (`ivantitop` next to `ivanti_top`) — returned as the
 * subset to drop.
 *
 * The recognizer resolves both spellings (that squashed tier is what makes
 * `XmlWinEventLog…Operational_CIM` fast), so a batch can ask for a sample twice under
 * two names and pay two generations for one source. Measured on the 34-sample review
 * queue: 3 pairs, ~9% of the review effort for nothing. The separated spelling wins
 * because it is the canonical one; a group where NO member carries a separator is not a
 * duplicate of anything and is left alone.
 *
 * Redundant is not the same as wrong, so callers should DELETE these rather than
 * blacklist the content — the same events under the canonical key may be perfectly good.
 */
export function squashedDuplicateKeys(docs: Array<{ key: string; sourcetype: string }>): Set<string> {
  const bySquash = new Map<string, Array<{ key: string; sourcetype: string }>>();
  for (const d of docs) {
    const squash = String(d.sourcetype || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!squash) continue;
    bySquash.set(squash, [...(bySquash.get(squash) || []), d]);
  }
  const dupes = new Set<string>();
  for (const [squash, group] of bySquash) {
    if (group.length < 2) continue;
    if (!group.some(d => d.sourcetype.toLowerCase() !== squash)) continue;
    for (const d of group) if (d.sourcetype.toLowerCase() === squash) dupes.add(d.key);
  }
  return dupes;
}

/** Distinct self-describing keys a structurally-checked sample must carry. */
const MIN_STRUCTURE_KEYS = 3;

/**
 * Fallback for sourcetypes we have no parser knowledge about. We can't say the
 * events are *right* — nobody here knows what this vendor emits — but we can say
 * whether they're self-describing log data at all rather than prose or a single
 * repeated line. Passing here means "usable and structurally sound"; the doc
 * records `method: 'structure'` so the review step shows the weaker evidence.
 */
function verifyByStructure(sourcetype: string, checked: string[]): SampleVerification {
  const fp = sampleFingerprint(checked.join('\n'));
  const distinct = new Set(checked.map(l => l.trim())).size;
  const reasons: string[] = [];
  if (distinct < Math.ceil(checked.length * 0.9)) {
    reasons.push(`${checked.length - distinct} of ${checked.length} events are exact duplicates`);
  }
  if (fp.format === 'unstructured') {
    // Unstructured text for an unknown vendor is genuinely unverifiable: we have
    // neither a parser nor a declared format to hold it to. Not a failure.
    return {
      verdict: reasons.length ? 'fail' : 'unverified', method: reasons.length ? 'structure' : 'none',
      eventsParsed: 0, eventsChecked: checked.length, fields: [],
      reasons: reasons.length ? reasons
        : [`${sourcetype} has no parser and the events are unstructured text — nothing to verify against`],
      offendingEvents: [],
    };
  }
  if (fp.keys.length < MIN_STRUCTURE_KEYS) {
    reasons.push(`only ${fp.keys.length} distinct ${fp.format} key(s) across the sample (need ${MIN_STRUCTURE_KEYS})`);
  }
  return {
    verdict: reasons.length === 0 ? 'pass' : 'fail',
    method: 'structure',
    eventsParsed: reasons.length === 0 ? checked.length : 0,
    eventsChecked: checked.length,
    fields: fp.keys,
    reasons: reasons.length ? reasons
      : [`no parser for ${sourcetype}; the events are well-formed ${fp.format} with ${fp.keys.length} distinct keys`],
    offendingEvents: reasons.length ? checked.slice(0, 3).map(e => e.slice(0, 300)) : [],
  };
}

// --- Harvested vendor samples -------------------------------------------------
// Real vendor log lines taken from a third-party corpus (today: elastic/integrations
// package test fixtures) and held in the shared samples pool (src/samples-pool.ts —
// the bodies live outside this repo, the manifest ships). Same doc shape and
// key convention as the AI store, but `synthetic` is false and provenance records
// where the lines came from, so a wrong one can be traced and deleted.
//
// These sit ABOVE the AI library and BELOW `config/source-samples.json` in the
// resolution chain: real data beats generated data, and our own curated corpus
// beats an import we didn't hand-check.

export interface VendorSampleUpstream {
  /** Corpus identity, e.g. `elastic/integrations`. */
  repo: string;
  /** Pinned commit the lines were taken from — makes the harvest reproducible. */
  commit: string;
  /** Path within the corpus of the fixture that contributed the first stored line. */
  path: string;
  /**
   * Every fixture that contributed a stored line, when the sample was assembled
   * from more than one. Present only for merged samples, so `path` keeps its
   * original meaning and single-fixture docs keep their original shape.
   */
  paths?: string[];
  /** Licence of the upstream corpus; kept per file so the NOTICE can't drift. */
  license: string;
}

export interface VendorSampleDoc {
  version: 1;
  key: string;
  sourcetype: string;
  format?: string;
  events: string[];
  fingerprint: string;
  verification: SampleVerification;
  /**
   * How much we actually know about this sample:
   *   `verified`   — the sourcetype's own parser (or its declared wire format) read it.
   *   `structure`  — no parser for this source, but the lines are well-formed
   *                  self-describing log data.
   *   `provenance` — nothing could be checked; we trust it only because it is a
   *                  real fixture from the upstream corpus. Weakest tier.
   */
  confidence: 'verified' | 'structure' | 'provenance';
  upstream: VendorSampleUpstream;
}

/** Longest single line we will store — one runaway line can dwarf the bundle. */
export const VENDOR_SAMPLE_MAX_LINE = 8000;
/**
 * Lines kept per sample. Raised 12 → 20 once the harvest started MERGING every
 * fixture of a key instead of keeping only the best one: a pipeline builder needs
 * 10-20 events to generalize a regex past the single example it was written from,
 * and 133 keys have ≥20 distinct real lines available across their fixtures.
 * Keys that cannot reach it stay short here and are topped up at request time
 * (see `guardExtendedEvents`) rather than padded with synthetic lines in the store.
 */
export const VENDOR_SAMPLE_MAX_EVENTS = 20;
/**
 * Total bytes of event text kept per sample. The line cap alone is not enough:
 * 12 lines of a verbose finding JSON ran to 60 KB, and a few hundred of those
 * would dominate the repo and the iframe build for no extra information. Raised
 * with the event cap so a 20-line text sample is not trimmed back to 3 by bytes.
 */
export const VENDOR_SAMPLE_MAX_BYTES = 24000;
/** Lines kept even when the byte budget is already spent, so a sample is never 1 line. */
export const VENDOR_SAMPLE_MIN_EVENTS = 3;

/**
 * Keys in `config/source-samples.json` whose lines their OWN parser cannot read.
 *
 * That store outranks every later tier, so a broken entry there is worse than a
 * missing one: it shadows any good sample we import or generate, and the app
 * silently builds a pipeline that extracts nothing. Listing a key here makes both
 * run modes fall through to the next tier instead.
 *
 * `auditd`: 4 of its 10 lines use the ausearch-interpreted timestamp
 * `msg=audit(11/20/2025 16:57:48.909:110027)` while both parsers require the epoch
 * form — see the KNOWN_VERIFIER_GAPS note in tests/ai-sample-library-test.mjs. The
 * file is regenerated by `npm run sync:source-samples`, so hand-patching it would
 * be undone on the next sync; skipping it at resolution time survives that.
 * `linux_audit` reaches the same entry through its alias list, so both keys fall
 * through to the harvested epoch-form sample.
 *
 * A key belongs here ONLY while `verifyGeneratedSample` genuinely fails it —
 * tests/vendor-sample-library-test.mjs asserts that, so a stale entry cannot
 * quietly suppress a sample that has since been fixed.
 */
export const UNREADABLE_SOURCE_SAMPLES = new Set(['auditd']);

/** One store-backed sourcetype for the bulk availability map. */
export interface StoreBackedSample {
  /** Canonical sourcetype the wizard looks up in `referenceAvailability[st]`. */
  sourcetype: string;
  /** Best-effort event count (shown as "N real events available"). */
  sampleEvents: number;
  /** Which store the sample came from — used for the "pack" attribution label. */
  pack: string;
}

/** Index shape shared by the vendor / ai / sanitised sample stores. */
interface SampleStoreIndex {
  samples?: Array<{ key?: string; sourcetype?: string; events?: number }>;
}

/**
 * Derive the wizard-lookup sourcetype from a store key (`zscaler_web::cef` →
 * `zscaler_web`). The store KEY — not the doc's `.sourcetype` field — is what the
 * resolver matches and what the user selects, so it wins: source-samples keys the
 * github sample `github_cloud_audit` but tags it `.sourcetype: "github:cloud:audit"`,
 * and the UI looks up `github_cloud_audit`.
 */
function storeKeyToSourcetype(key: string | undefined, sourcetype: string | undefined): string {
  const base = (key || sourcetype || '').trim();
  return base.split('::')[0];
}

/**
 * Sourcetypes whose ONLY sample lives in one of the fallback stores
 * (vendor-samples / source-samples / ai-samples / sanitised-samples) rather than
 * the reference catalogue.
 *
 * The bulk availability map that gates the wizard's "reference sample" source
 * option was built only from the catalogue, so the 638 harvested vendor samples
 * (github_*, and hundreds more) reported `hasSamples:false` and the UI offered
 * AI-only — even though the per-sourcetype `resolveFallbackSample` endpoint DID
 * resolve them. This mirrors the resolver's tier set into the availability map so
 * both agree. Pure: it reads only the index manifests (no sample-file content
 * loaded — an iframe must not eagerly hydrate 638 lazy chunks just to badge them).
 * Both run modes call it with their own imported/parsed index data (Hard Rule 18).
 */
export function storeBackedAvailability(opts: {
  vendorIndex?: SampleStoreIndex | null;
  aiIndex?: SampleStoreIndex | null;
  sanitisedIndex?: SampleStoreIndex | null;
  sourceSamples?: Record<string, { sourcetype?: string; example_logs?: string[] }> | null;
}): Map<string, StoreBackedSample> {
  const out = new Map<string, StoreBackedSample>();
  const add = (st: string, events: number, pack: string) => {
    if (!st) return;
    const existing = out.get(st);
    // Keep the entry with the most events; first store wins the pack label on ties.
    if (existing && existing.sampleEvents >= events) return;
    out.set(st, { sourcetype: st, sampleEvents: events, pack });
  };
  for (const s of opts.vendorIndex?.samples || []) {
    add(storeKeyToSourcetype(s.key, s.sourcetype), s.events || 0, 'vendor-samples');
  }
  for (const [key, entry] of Object.entries(opts.sourceSamples || {})) {
    if (UNREADABLE_SOURCE_SAMPLES.has(key)) continue;
    const logs = entry?.example_logs;
    if (!logs?.length) continue;
    add(key.split('::')[0], logs.length, 'source-samples');
  }
  for (const s of opts.aiIndex?.samples || []) {
    add(storeKeyToSourcetype(s.key, s.sourcetype), s.events || 0, 'ai-samples');
  }
  for (const s of opts.sanitisedIndex?.samples || []) {
    add(storeKeyToSourcetype(s.key, s.sourcetype), s.events || 0, 'sanitised-samples');
  }
  return out;
}

/** Distinct keys a structure-only import must show (the gate itself passes at 3). */
const STRUCTURE_MIN_KEYS = 5;
/** Minimum distinct lines for a sample nothing could verify. */
const PROVENANCE_MIN_EVENTS = 5;
/** Minimum average line length for a provenance-only sample. */
const PROVENANCE_MIN_AVG_LEN = 30;

export interface VendorSampleGate {
  accept: boolean;
  confidence: VendorSampleDoc['confidence'];
  /** Why it was accepted or rejected — printed by the harvest report. */
  reason: string;
}

/**
 * Decide whether a harvested sample is good enough to keep. Quality over quantity:
 * the corpus is large enough that being strict costs us nothing, while one
 * wrong-format sample silently produces a pack that extracts nothing.
 *
 * The rule that matters: **if we HAVE a parser for this sourcetype, the sample must
 * actually pass it.** For those sources "unverifiable" is not neutral — we know what
 * the format looks like, so a sample we can't read is evidence against the sample,
 * not a gap in the checker. Only sources we know nothing about may fall back to
 * structural or provenance-only evidence.
 */
export function gateVendorSample(
  sourcetype: string,
  events: string[],
  verification: SampleVerification,
): VendorSampleGate {
  const known = getParserFieldNames(sourcetype).length > 0;

  // Before any question of quality: a sample carrying a provider credential is not
  // publishable at all (see CREDENTIAL_PATTERNS). The harvest already drops such
  // lines when it assembles events, so reaching here means a doc predates the rule or
  // a caller built its events another way — which is exactly why this is a gate and
  // not only a filter. `auditPoolDoc` re-runs this gate, so the publisher refuses to
  // push such a doc without needing its own copy of the rule.
  const creds = credentialLikeMatches(events);
  if (creds.length) {
    return {
      accept: false,
      confidence: 'provenance',
      reason: `contains credential-shaped content (${creds.join(', ')}) — drop the offending line(s); a public pool must not republish a secret`,
    };
  }

  if (verification.verdict === 'fail') {
    return { accept: false, confidence: 'provenance', reason: `verification failed: ${verification.reasons[0] || 'unknown'}` };
  }

  if (verification.verdict === 'pass' && (verification.method === 'parser-emulation' || verification.method === 'source-expectation')) {
    return { accept: true, confidence: 'verified', reason: `${verification.method}: ${verification.fields.length} field(s)` };
  }

  // Everything below is weaker evidence, and a source we have a parser for is not
  // allowed to use it.
  if (known) {
    return {
      accept: false,
      confidence: 'provenance',
      reason: `${sourcetype} has its own parser, so only parser-verified samples are kept (got ${verification.verdict}/${verification.method})`,
    };
  }

  if (verification.verdict === 'pass' && verification.method === 'structure') {
    // The structural check passes at 3 keys, which is the right bar for "is this
    // log data at all". For an import we hold it higher: a 4-key fixture teaches
    // a pipeline builder almost nothing about the source.
    if (verification.fields.length < STRUCTURE_MIN_KEYS) {
      return { accept: false, confidence: 'structure', reason: `only ${verification.fields.length} distinct key(s); an imported sample needs ${STRUCTURE_MIN_KEYS} to be worth keeping` };
    }
    return { accept: true, confidence: 'structure', reason: `well-formed, ${verification.fields.length} distinct key(s), no parser to check against` };
  }

  // Provenance-only: unverifiable text from a source we know nothing about. Kept
  // only if it is substantial enough to be worth showing a user at all.
  const distinct = new Set(events.map(e => e.trim())).size;
  const avgLen = events.reduce((n, e) => n + e.length, 0) / Math.max(1, events.length);
  if (distinct < PROVENANCE_MIN_EVENTS) {
    return { accept: false, confidence: 'provenance', reason: `unverifiable and only ${distinct} distinct line(s) (need ${PROVENANCE_MIN_EVENTS})` };
  }
  if (avgLen < PROVENANCE_MIN_AVG_LEN) {
    return { accept: false, confidence: 'provenance', reason: `unverifiable and lines average ${Math.round(avgLen)} chars (need ${PROVENANCE_MIN_AVG_LEN})` };
  }
  return { accept: true, confidence: 'provenance', reason: `unverifiable (${verification.method}); kept on upstream provenance, ${distinct} distinct lines` };
}

// --- credential-shaped content -----------------------------------------------
// A harvested corpus is somebody's PRODUCTION log, contributed as a test fixture,
// and production logs contain secrets. Elastic's `traefik` fixture holds two real
// access-log lines with `?oauth_token=ya29.…` in the URL — genuine Google OAuth
// tokens that leaked upstream. GitHub's push protection blocked the first publish of
// the pool on exactly those two lines, which is the right outcome and also the whole
// reason this rule exists at the level of the LIBRARY rather than the publisher:
//   • the pool is PUBLIC (Rule 30), so admitting one means republishing someone
//     else's credential under our own account, and a `git push --force` later cannot
//     unpublish it;
//   • a credential is worthless as sample data — it teaches a pipeline builder
//     nothing about the wire format that a redacted value would not;
//   • bypassing push protection to ship it would be trading a real secret for a
//     sample we can drop at no cost (resolution falls through to the next tier).
// Only PROVIDER-ISSUED credential formats are listed — shapes that are unambiguous
// and are what secret scanners actually block. A bearer JWT is deliberately NOT here:
// `eyJ…` appears in a large share of legitimate auth/proxy logs, scanners do not
// treat it as a secret on its own, and matching it would gut the corpus for no gain.
const CREDENTIAL_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'Google OAuth access token', re: /ya29\.[A-Za-z0-9_-]{20,}/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'AWS access key id', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/ },
  { name: 'Slack token', re: /\bxox[abprse]-[A-Za-z0-9-]{10,}/ },
  { name: 'Stripe live key', re: /\bsk_live_[0-9a-zA-Z]{16,}\b/ },
  { name: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: 'OpenAI key', re: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/ },
  { name: 'private key block', re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----/ },
];

/**
 * The name of the credential format this line carries, or null. Exported so the
 * harvest can report what it dropped and the pool gates can name what they refused.
 */
export function credentialLikeMatch(line: string): string | null {
  const text = String(line || '');
  for (const { name, re } of CREDENTIAL_PATTERNS) if (re.test(text)) return name;
  return null;
}

/** Every credential format present across these events, deduplicated. */
export function credentialLikeMatches(events: string[]): string[] {
  const found = new Set<string>();
  for (const e of events || []) {
    const hit = credentialLikeMatch(e);
    if (hit) found.add(hit);
  }
  return [...found];
}

/** Split one fixture's raw text into the candidate lines it contributes. */
export function vendorSampleLines(rawText: string): string[] {
  return String(rawText || '')
    .split('\n')
    .map(l => l.replace(/\r$/, '').trim())
    .filter(l => l.length > 0 && l.length <= VENDOR_SAMPLE_MAX_LINE)
    // Fixture comment markers are not log lines.
    .filter(l => !l.startsWith('#'))
    // Drop the LINE, not the document: a fixture is usually one credential-bearing
    // request among a dozen clean ones, and the rest are still the real format.
    // Removing a whole event is not editing one — the lines that remain are verbatim
    // and still traceable to the pinned upstream commit, which is what the licence
    // requires (Rule 30).
    .filter(l => !credentialLikeMatch(l));
}

/**
 * Pick the lines to store from one or more fixtures of the SAME sourcetype.
 *
 * Round-robin across the groups rather than draining the first one, because each
 * fixture upstream is usually a different message type: `system_security` has 371
 * lines spread over 53 fixtures, and taking the first 20 in file order would store
 * 20 variants of one event where round-robin stores 20 different events. Variety is
 * the entire reason a builder wants more than one line.
 */
export function selectVendorSampleEventsFromGroups(groups: string[][]): string[] | null {
  // The per-line rules are re-applied here, not just in `vendorSampleLines`, so a
  // caller that assembles groups itself cannot bypass the line cap — or leak a
  // credential-bearing line in past the filter.
  const lists = (groups || []).map(g => (g || []).filter(l =>
    typeof l === 'string' && l.length > 0 && l.length <= VENDOR_SAMPLE_MAX_LINE
    && !l.startsWith('#') && !credentialLikeMatch(l)));
  const distinct: string[] = [];
  const seen = new Set<string>();
  let bytes = 0;
  const cursors = new Array(lists.length).fill(0);
  let exhausted = false;
  while (!exhausted && distinct.length < VENDOR_SAMPLE_MAX_EVENTS) {
    exhausted = true;
    for (let g = 0; g < lists.length && distinct.length < VENDOR_SAMPLE_MAX_EVENTS; g++) {
      const list = lists[g];
      // Advance past lines already taken (a line can appear in several fixtures).
      while (cursors[g] < list.length && seen.has(list[cursors[g]])) cursors[g]++;
      if (cursors[g] >= list.length) continue;
      exhausted = false;
      const line = list[cursors[g]++];
      // Stop on the byte budget, but never below the minimum: a single line is not
      // a sample of a format, it's one example of one event type.
      if (bytes + line.length > VENDOR_SAMPLE_MAX_BYTES && distinct.length >= VENDOR_SAMPLE_MIN_EVENTS) {
        return distinct;
      }
      seen.add(line);
      distinct.push(line);
      bytes += line.length;
    }
  }
  return distinct.length ? distinct : null;
}

/** Normalize ONE fixture's raw text into the lines we would store, or null. */
export function selectVendorSampleEvents(rawText: string): string[] | null {
  return selectVendorSampleEventsFromGroups([vendorSampleLines(rawText)]);
}

export function buildVendorSampleDoc(args: {
  sourcetype: string;
  format?: string | null;
  events: string[];
  verification: SampleVerification;
  confidence: VendorSampleDoc['confidence'];
  upstream: VendorSampleUpstream;
}): VendorSampleDoc {
  return {
    version: 1,
    key: aiSampleKey(args.sourcetype, args.format),
    sourcetype: canonicalizeSourcetype(args.sourcetype),
    format: (args.format || '').trim().toLowerCase() || undefined,
    events: args.events,
    fingerprint: sampleRejectionFingerprint(args.events),
    verification: args.verification,
    confidence: args.confidence,
    upstream: args.upstream,
  };
}

/**
 * Render a failed verification into prompt text for the retry. Today's retry
 * re-sends the identical prompt, so a model that got the format wrong gets it
 * wrong again; telling it what failed is the cheapest possible improvement.
 */
export function renderVerificationFeedback(v: SampleVerification): string {
  if (!v || v.verdict === 'pass') return '';
  const lines = [
    'YOUR PREVIOUS ATTEMPT WAS REJECTED. This is why — fix it, do not repeat it:',
    ...v.reasons.map(r => `- ${r}`),
  ];
  if (v.offendingEvents.length) {
    lines.push('Events that could not be parsed at all:');
    lines.push(...v.offendingEvents.map(e => `  ${e}`));
  }
  if (v.fields.length) {
    lines.push(`Fields that DID parse (keep these, they are correct): ${v.fields.slice(0, 20).join(', ')}`);
  }
  lines.push('Emit the exact wire format this source really uses, with its real field names.');
  return `\n${lines.join('\n')}\n`;
}

// --- Request-time sample extension --------------------------------------------
// A builder needs 10-20 events to generalize: a regex written from ONE example
// usually only matches that example, and value coverage over 1-2 lines measures
// almost nothing. But 486 of the harvested keys have fewer than 20 real lines in
// existence, so the missing events can only come from a model.
//
// They are therefore generated AT REQUEST TIME and never committed: the stores stay
// 100% real and traceable (the upstream licence requires the notice to stay
// attached, and an invented line is neither the real format nor traceable), while a
// bad extension dies with the build that asked for it.
//
// The model's job is deliberately narrow: VARY THE VALUES, NEVER INVENT THE FORMAT.
// That is what `guardExtendedEvents` enforces, deterministically, with no second AI
// call. It matters for scoring as much as for correctness: value coverage divides by
// the sample's own distinct values, so a line carrying an invented FIELD would be
// counted as a value the pipeline failed to extract and would trigger repair rounds
// chasing a field the vendor never emits. Once every synthetic value lives in a
// shape the real lines already showed, a value that goes missing in the output is a
// genuine defect — usually a regex that only matched the single real example.

// A sample event arrives either as a raw log LINE or as a Cribl event OBJECT
// (`{_raw, _time, cribl_breaker, …}` — the shape `config/sample-library/` stores and
// the shape the Cribl samples API returns). Turning one into a line has exactly one
// correct rule: an event that carries a `_raw` string IS that string; only an event
// with no `_raw` (a source whose events really are parsed objects) serialises.
//
// Getting this wrong is silent and expensive. `extendThinSample` used a bare
// `JSON.stringify(e)`, so every infoblox_dns line became a serialised ENVELOPE
// (`{"_raw":"<30>Mar 11 …","_time":…}`) — the deployed pack's sample really did hold
// double-wrapped events. The syslog parser then extracted the envelope's own keys,
// value coverage divided by `_raw`/`_time`/`cribl_breaker`, and the row scored a
// near-zero mapping for a pipeline that was fine. One rule, one place.
export function eventToLine(e: unknown): string {
  if (typeof e === 'string') return e.trim();
  if (e === null || e === undefined) return '';
  const raw = (e as Record<string, unknown>)._raw;
  if (typeof raw === 'string' && raw.trim()) return raw.trim();
  try { return JSON.stringify(e); } catch { return String(e); }
}

/** `eventToLine` over a list, dropping blanks. */
export function eventsToLines(events: unknown[] | null | undefined): string[] {
  return (Array.isArray(events) ? events : []).map(eventToLine).filter(Boolean);
}

/** Events a build asks the model for when it has no stored sample at all.
 *
 * Was 50. Generation cost scales with the ask and 50 events put a plain request
 * at 45-87s uncontended (measured), which crossed the old 90s wall under batch
 * concurrency and cost the row its sample entirely. 20 is what
 * `SAMPLE_EXTEND_TARGET` already treats as a full sample, so nothing downstream
 * wants more. */
export const GENERATED_SAMPLE_COUNT = 20;

/** Below this many events a sample is too thin to build a pipeline from. */
export const SAMPLE_EXTEND_FLOOR = 10;
/** Events we aim for after extension. */
export const SAMPLE_EXTEND_TARGET = 20;
/** Fraction of a candidate's words that must already appear in the real lines. */
const EXTEND_MIN_VOCAB_RATIO = 0.7;
/** A candidate may not be much shorter or longer than the real lines. */
const EXTEND_LEN_MIN_RATIO = 0.4;
const EXTEND_LEN_MAX_RATIO = 2.5;
/** Minimum delimited columns before a line's column count is treated as its shape. */
const EXTEND_MIN_COLUMNS = 5;

export interface SampleShapeUniverse {
  /** Envelope the real lines share (`json` / `kvp` / `cef` / `unstructured`). */
  format: string;
  /** Every key the real lines carry, lowercased — the ONLY keys allowed. */
  keys: string[];
  /** Words the real lines use, for sources with no keys to compare. */
  vocab: string[];
  /** Dominant delimiter and column count, when the real lines are delimited. */
  delimiter: string | null;
  columns: number | null;
  minLen: number;
  maxLen: number;
}

/** Words that carry format meaning: alphabetic, ≥3 chars, digits masked out. */
function lineVocab(line: string): string[] {
  return line
    .replace(/\d+/g, ' ')
    .split(/[^A-Za-z_]+/)
    .filter(t => t.length >= 3)
    .map(t => t.toLowerCase());
}

/** Column count if `line` is consistently delimited, else null. */
function delimitedColumns(lines: string[]): { delimiter: string; columns: number } | null {
  for (const delimiter of [',', '\t', '|']) {
    const counts = lines.map(l => l.split(delimiter).length);
    const columns = counts[0];
    if (columns < EXTEND_MIN_COLUMNS) continue;
    if (counts.every(c => c === columns)) return { delimiter, columns };
  }
  return null;
}

/** Everything the real lines permit a synthetic line to look like. */
export function sampleShapeUniverse(realEvents: string[]): SampleShapeUniverse {
  const real = (realEvents || []).filter(e => typeof e === 'string' && e.trim().length > 0).map(e => e.trim());
  const fp = sampleFingerprint(real.join('\n'));
  const keys = new Set(fp.keys);
  // Per-line fingerprints too: a whole-sample scan can miss a key that only one
  // line carries, and that key must still be legal for a synthetic line.
  const vocab = new Set<string>();
  for (const line of real) {
    for (const k of sampleFingerprint(line).keys) keys.add(k);
    for (const w of lineVocab(line)) vocab.add(w);
  }
  const delim = fp.format === 'unstructured' && real.length ? delimitedColumns(real) : null;
  const lens = real.map(l => l.length);
  return {
    format: fp.format,
    keys: [...keys].sort(),
    vocab: [...vocab].sort(),
    delimiter: delim?.delimiter ?? null,
    columns: delim?.columns ?? null,
    minLen: lens.length ? Math.min(...lens) : 0,
    maxLen: lens.length ? Math.max(...lens) : 0,
  };
}

// --- Wire-format description (what the USER needs to see before choosing) -----
//
// Several sources emit their events in more than one wire format depending on how
// the feed was configured (Zscaler NSS: key=value / JSON / CEF; FortiGate: kvp or
// CEF; Corelight: JSON or TSV — `MULTI_FORMAT_SOURCES` in pack-builder.ts). The
// pack is built around the format of the sample it was given, so picking a sample
// blind means silently picking a format: a CEF sample for a feed that really emits
// key=value produces a pipeline that extracts nothing from production data. Every
// place the app OFFERS a sample therefore labels its format, using this one
// describer so the label cannot disagree between run modes or between screens.
//
// `sampleFingerprint`'s envelope is deliberately coarse (json / kvp / cef /
// unstructured) because that is all the replay guard needs. A human choosing
// between two samples needs the finer distinctions — LEEF is not CEF, TSV is not
// CSV, and XML is not "unstructured text" — so this adds them.

export type SampleFormatId =
  | 'empty' | 'json' | 'xml' | 'cef' | 'leef' | 'kvp' | 'csv' | 'tsv' | 'psv' | 'syslog' | 'text';

export interface SampleFormatDescription {
  id: SampleFormatId;
  /** Short badge text, e.g. `CEF`, `Key=value`, `TSV (14 cols)`. */
  label: string;
  /** One sentence for a tooltip / advice line. */
  detail: string;
  /** Lines that were inspected. */
  lines: number;
  /** Share of inspected lines matching `id` (1 = every line agrees). */
  agreement: number;
  /** True when the sample carries more than one shape — worth telling the user. */
  mixed: boolean;
  delimiter?: string;
  columns?: number;
}

const FORMAT_DETAIL: Record<SampleFormatId, string> = {
  empty: 'No events to inspect.',
  json: 'One JSON object per line — fields are named, so extraction is a json serde.',
  xml: 'XML events — extraction needs XML parsing and event breaking on the element boundary, not newlines.',
  cef: 'ArcSight CEF — a pipe-delimited header plus key=value extension fields.',
  leef: 'IBM LEEF — a pipe-delimited header plus tab-delimited attributes.',
  kvp: 'Space-separated key=value pairs — extraction is a kvp serde.',
  csv: 'Comma-separated columns with no field names — the column order IS the schema.',
  tsv: 'Tab-separated columns with no field names — the column order IS the schema.',
  psv: 'Pipe-separated columns with no field names — the column order IS the schema.',
  syslog: 'Syslog-style free text — extraction needs regex patterns per message type.',
  text: 'Free text with no delimiters or field names — extraction needs regex patterns.',
};

/**
 * Syslog framing at the head of a line: optional octet count, optional `<pri>`
 * with optional RFC5424 version digit, then a BSD (`Apr 17 [2020 ]14:08:08` —
 * Cisco ASA emits the 4-token form) or ISO-8601 timestamp.
 */
const SYSLOG_HEAD =
  /^(?:\d{2,6}\s+)?(?:<\d{1,3}>\s*\d?\s*)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d\d:\d\d:\d\d|\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)/;

/** A JSON object carried inside another envelope (syslog-framed Corelight/Zeek, …). */
function embeddedJson(line: string): boolean {
  const start = line.indexOf('{');
  const end = line.lastIndexOf('}');
  if (start < 1 || end < start) return false;
  const body = line.slice(start, end + 1);
  // Only call it JSON when the object IS the event, not a brace in a message.
  if (body.length < line.length * 0.6) return false;
  try {
    const parsed: unknown = JSON.parse(body);
    return !!parsed && typeof parsed === 'object' && Object.keys(parsed as object).length >= 3;
  } catch { return false; }
}

/** Classify ONE line. Order matters: the specific envelopes must win over kvp. */
function classifyLine(line: string): { id: SampleFormatId; wrapped?: boolean } {
  const l = line.trim();
  if (!l) return { id: 'empty' };
  if (/(?:^|\s)LEEF:\s*\d(?:\.\d)?\|/.test(l)) return { id: 'leef' };
  if (/(?:^|\s)CEF:\s*\d+\|/.test(l)) return { id: 'cef' };
  if (/^[[{]/.test(l)) {
    try { JSON.parse(l); return { id: 'json' }; } catch { /* not valid JSON — keep looking */ }
  }
  // `<166>Jan 12 …` is syslog priority, NOT xml — check for a real element name.
  if (/^<\?xml/i.test(l) || (/^<[A-Za-z_]/.test(l) && /(?:<\/[A-Za-z_][\w:.-]*>|\/>)/.test(l))) return { id: 'xml' };
  if (embeddedJson(l)) return { id: 'json', wrapped: true };
  // `|` and `;` count as pair separators: Check Point log-exporter writes
  // `time=…|hostname=…|product=…`, which is key=value, not pipe-separated columns.
  // The value stops at a pair separator too: `time=…|hostname=…` is two pairs, and a
  // value matched as `\S+` would swallow the whole (space-free) line as one pair.
  const kvHits = (l.match(/(?:^|[\s,;|{[])[A-Za-z_][\w.-]*\s*=\s*(?:"[^"]*"|[^\s|;]*)/g) || []).length;
  if (kvHits >= 3) return { id: 'kvp' };
  if (SYSLOG_HEAD.test(l)) return { id: 'syslog' };
  if (kvHits >= 1) return { id: 'kvp' };
  return { id: 'text' };
}

/**
 * Describe the wire format of a sample so it can be shown BEFORE it is used.
 *
 * Deterministic and offline — no AI, no network — because it labels a list of
 * samples in the UI and has to be instant. Inspects at most `limit` lines and
 * reports the dominant shape plus whether the lines disagree.
 */
export function describeSampleFormat(events: string[] | string, limit = 50): SampleFormatDescription {
  const lines = (Array.isArray(events) ? events : String(events || '').split('\n'))
    .map(l => (l || '').trim()).filter(Boolean).slice(0, limit);
  if (lines.length === 0) {
    return { id: 'empty', label: 'No events', detail: FORMAT_DETAIL.empty, lines: 0, agreement: 0, mixed: false };
  }
  const seen = lines.map(classifyLine);
  const tally = new Map<SampleFormatId, number>();
  for (const s of seen) tally.set(s.id, (tally.get(s.id) || 0) + 1);
  let [id, hits] = [...tally.entries()].sort((a, b) => b[1] - a[1])[0];
  const agreement = hits / lines.length;

  // Columns are a property of the WHOLE sample, never of one line: any long free-text
  // line splits into "5 columns" on a comma. Only lines that carry no field names can
  // be columnar, and the column count has to repeat.
  let delimited: { delimiter: string; columns: number } | null = null;
  let framed = false;
  if (id === 'text' || id === 'syslog') {
    const plain = lines.filter((_, i) => seen[i].id === id && !lines[i].startsWith('#'));
    delimited = dominantDelimited(plain);
    if (delimited) {
      // Columns carried inside a syslog frame (Aruba CX): the frame has to come off
      // before the columns line up, so say both rather than hiding one. The frame is
      // there when the first column is not one token — a CSV whose first column is an
      // ISO timestamp (`2024-01-24T15:31:51.231Z,…`) is NOT framed.
      const d = delimited.delimiter;
      framed = id === 'syslog'
        && plain.filter(l => /\s/.test(l.slice(0, l.indexOf(d)))).length / plain.length >= 0.7;
      id = delimited.delimiter === '\t' ? 'tsv' : delimited.delimiter === ',' ? 'csv' : 'psv';
      hits = plain.length;
    }
  }

  const wrapped = id === 'json' && seen.some(s => s.id === 'json' && s.wrapped);
  const label = delimited
    ? `${id.toUpperCase()} (${delimited.columns} cols${framed ? ', syslog-framed' : ''})`
    : id === 'kvp' ? 'Key=value'
    : id === 'syslog' ? 'Syslog text'
    : id === 'text' ? 'Free text'
    : wrapped ? 'JSON (syslog-framed)'
    : id.toUpperCase();
  return {
    id, label, lines: lines.length, agreement, mixed: tally.size > 1,
    detail: FORMAT_DETAIL[id]
      + (wrapped ? ' Each event is a JSON object inside a syslog frame — the frame has to be stripped first.' : '')
      + (framed ? ' The columns sit inside a syslog frame, which has to be stripped before they line up.' : '')
      + (tally.size > 1
        ? ` ${hits} of ${lines.length} inspected lines look like this; the sample mixes ${tally.size} shapes.`
        : ''),
    ...(delimited ? { delimiter: delimited.delimiter, columns: delimited.columns } : {}),
  };
}

/** The column count if ≥70% of `lines` split into the same number of fields. */
function dominantDelimited(lines: string[]): { delimiter: string; columns: number } | null {
  if (lines.length === 0) return null;
  for (const delimiter of ['\t', ',', '|']) {
    const tally = new Map<number, number>();
    for (const l of lines) {
      const c = l.split(delimiter).length;
      if (c >= EXTEND_MIN_COLUMNS) tally.set(c, (tally.get(c) || 0) + 1);
    }
    const best = [...tally.entries()].sort((a, b) => b[1] - a[1])[0];
    if (best && best[1] / lines.length >= 0.7) return { delimiter, columns: best[0] };
  }
  return null;
}

/**
 * Does a described sample match one option of a `MultiFormatSpec`? Used to tell the
 * user "this sample is the CEF variant" and to warn when it is not the variant they
 * picked. Option ids come from `MULTI_FORMAT_SOURCES` in pack-builder.ts.
 */
export function sampleFormatMatchesVariant(desc: SampleFormatDescription, optionId: string): boolean {
  switch ((optionId || '').toLowerCase()) {
    case 'json': return desc.id === 'json';
    case 'cef': return desc.id === 'cef';
    case 'leef': return desc.id === 'leef';
    case 'kv': case 'kvp': return desc.id === 'kvp';
    case 'tsv': return desc.id === 'tsv';
    case 'csv': return desc.id === 'csv';
    // W3C ELF and SQUID are both space-separated free text to the classifier.
    case 'elf': case 'squid': return desc.id === 'text' || desc.id === 'syslog';
    default: return false;
  }
}

/**
 * Which of a source's variants are actually PRESENT in a sample, line by line.
 *
 * A dominant-shape label is not enough for a source that ships in several formats:
 * the Corelight reference sample really does carry syslog-framed JSON records AND
 * Zeek TSV rows, so building "the JSON variant" from it silently drops 40% of the
 * events. Returns the option ids that at least `minShare` of the lines match.
 */
export function sampleVariantsPresent(
  events: string[] | string,
  optionIds: string[],
  { limit = 50, minShare = 0.1 } = {},
): string[] {
  const lines = (Array.isArray(events) ? events : String(events || '').split('\n'))
    .map(l => (l || '').trim()).filter(Boolean).slice(0, limit);
  if (lines.length === 0) return [];
  const hits = new Map<string, number>();
  for (const line of lines) {
    const desc = describeSampleFormat([line]);
    for (const id of optionIds) {
      if (sampleFormatMatchesVariant(desc, id)) hits.set(id, (hits.get(id) || 0) + 1);
    }
  }
  return optionIds.filter(id => (hits.get(id) || 0) / lines.length >= minShare);
}

export interface ExtensionGuardResult {
  /** Synthetic lines that may be used, in the order given. */
  accepted: string[];
  rejected: { line: string; reason: string }[];
  universe: SampleShapeUniverse;
  /** Verification of real + accepted, the last line of defence. */
  verification: SampleVerification;
  /** True when the safety net threw the whole extension away. */
  discarded: boolean;
}

/**
 * Decide which AI-generated lines may join a real sample.
 *
 * Rejecting a candidate is cheap — the sample is simply shorter — so every rule here
 * errs toward rejection. There is no AI in this function: the guards are the reason
 * request-time extension is safe enough to put in the build path at all.
 */
export function guardExtendedEvents(
  sourcetype: string,
  realEvents: string[],
  candidates: string[],
): ExtensionGuardResult {
  const real = (realEvents || []).filter(e => typeof e === 'string' && e.trim().length > 0).map(e => e.trim());
  const universe = sampleShapeUniverse(real);
  const accepted: string[] = [];
  const rejected: { line: string; reason: string }[] = [];
  const seen = new Set(real);
  const keySet = new Set(universe.keys);
  const vocabSet = new Set(universe.vocab);

  // Strongest available guard, and self-calibrating: if we own a parser for this
  // source AND it reads every real line on its own, hold each candidate to the same
  // bar. Only applied when the real lines clear it — a per-line check is stricter
  // than the whole-sample one (9 of 22 parser-owned harvested docs contain a real
  // line that fails alone), so demanding it unconditionally would reject genuine
  // vendor formats. Stated as "no worse than the real lines", it catches what the
  // free-text vocabulary guard cannot: a line built from the right WORDS in the
  // wrong shape (`… fw-01 built inbound tcp connection …` with no `%ASA-6-302013:`
  // passes the vocabulary test and extracts nothing).
  const lineVerifies = (line: string) => verifyGeneratedSample(sourcetype, [line]).verdict !== 'fail';
  const holdToParser = getParserFieldNames(sourcetype).length > 0 && real.length > 0 && real.every(lineVerifies);

  for (const raw of candidates || []) {
    const line = typeof raw === 'string' ? raw.trim() : '';
    const reject = (reason: string) => rejected.push({ line: line.slice(0, 300), reason });
    if (!line) continue;
    if (line.length > VENDOR_SAMPLE_MAX_LINE) { reject(`longer than the ${VENDOR_SAMPLE_MAX_LINE}-char line cap`); continue; }
    if (seen.has(line)) { reject('duplicate of a line we already have'); continue; }
    // A wildly shorter or longer line is a truncation, a merge of two events, or a
    // model apology — none of which is a sample of this format.
    if (universe.maxLen > 0 && (line.length < universe.minLen * EXTEND_LEN_MIN_RATIO || line.length > universe.maxLen * EXTEND_LEN_MAX_RATIO)) {
      reject(`length ${line.length} is outside the real lines' range (${universe.minLen}-${universe.maxLen})`);
      continue;
    }

    const fp = sampleFingerprint(line);
    if (universe.format !== 'unstructured') {
      // Structured source: the envelope must match and the keys must be a SUBSET.
      // This is the guard that matters — it makes a hallucinated field impossible
      // rather than merely unlikely.
      if (fp.format !== universe.format) { reject(`${fp.format} line in a ${universe.format} sample`); continue; }
      const extra = fp.keys.filter(k => !keySet.has(k));
      if (extra.length) { reject(`introduces ${extra.length} field(s) the real lines never carry: ${extra.slice(0, 5).join(', ')}`); continue; }
      if (fp.keys.length === 0) { reject('carries no recognizable fields'); continue; }
    } else if (universe.columns) {
      // Delimited text (PAN CSV, TSV): the column count IS the schema.
      const columns = line.split(universe.delimiter as string).length;
      if (columns !== universe.columns) { reject(`${columns} columns, the real lines have ${universe.columns}`); continue; }
    } else {
      // Free text: nothing to compare structurally, so hold the line to the
      // vocabulary the real lines use. A different message template, another
      // vendor's format, or an English sentence all fail this; a real template
      // with different values passes.
      const words = lineVocab(line);
      if (words.length === 0) { reject('no recognizable words to compare against the real lines'); continue; }
      const known = words.filter(w => vocabSet.has(w)).length;
      const ratio = known / words.length;
      if (ratio < EXTEND_MIN_VOCAB_RATIO) {
        reject(`only ${Math.round(ratio * 100)}% of its words appear in the real lines (need ${Math.round(EXTEND_MIN_VOCAB_RATIO * 100)}%)`);
        continue;
      }
    }

    if (holdToParser && !lineVerifies(line)) {
      reject(`the ${sourcetype} parser reads every real line but cannot read this one`);
      continue;
    }

    seen.add(line);
    accepted.push(line);
  }

  // Safety net: whatever survived, the source's own parser must still read the
  // combined sample. If the extension broke that, the extension goes, not the
  // sample — the real lines were fine before we asked for more.
  const verification = verifyGeneratedSample(sourcetype, [...real, ...accepted]);
  if (verification.verdict === 'fail' && accepted.length) {
    const realOnly = verifyGeneratedSample(sourcetype, real);
    if (realOnly.verdict !== 'fail') {
      for (const line of accepted) rejected.push({ line: line.slice(0, 300), reason: `discarded: with it, the ${sourcetype} parser no longer reads the sample` });
      return { accepted: [], rejected, universe, verification: realOnly, discarded: true };
    }
  }
  return { accepted, rejected, universe, verification, discarded: false };
}

/**
 * Strip model reasoning + markdown fences from raw AI output.
 *
 * Lives here because BOTH sample paths need it and neither may own it: the
 * standalone backend cleans through `cleanSampleText` (scripts/ai-samples.mjs,
 * which calls this) and the iframe client cleans in `src/ai-client.ts`. A model
 * that leaks `<think>` and is only cleaned on one side produces a "sample" whose
 * single event is the marker itself (the f5:bigip:syslog bug).
 *
 * `think` must stay in the marker list alongside `thinking`/`thought` — sonnet-5
 * emits the bare form.
 */
export function stripAiReasoning(text: string): string {
  const block = /<\|?(start_of_thought|thinking|thought|think)\|?>[\s\S]*?<\|?(end_of_thought|\/thinking|\/thought|\/think)\|?>/gi;
  const closer = /<\|?(end_of_thought|\/thinking|\/thought|\/think)\|?>/gi;
  let t = String(text ?? '').replace(block, '');
  // An unclosed opening marker leaves the whole reasoning dump in place, so fall
  // back to dropping everything up to and INCLUDING the last closing marker
  // still present (leaving the marker itself would glue it onto the first event).
  let end = -1;
  let endLen = 0;
  for (let m = closer.exec(t); m; m = closer.exec(t)) { end = m.index; endLen = m[0].length; }
  if (end !== -1) t = t.slice(end + endLen);
  return t.replace(/^```[a-z]*\n?/gim, '').replace(/^```\s*$/gim, '').trim();
}

/** True when a resolved sample is too thin to build a pipeline from. */
export function needsSampleExtension(events: unknown[] | null | undefined): boolean {
  const n = Array.isArray(events) ? events.filter(e => typeof e === 'string' ? e.trim().length > 0 : e != null).length : 0;
  return n > 0 && n < SAMPLE_EXTEND_FLOOR;
}

/**
 * Prompt for the extension call. Deliberately not the sample-generation prompt:
 * the format is already in front of the model, so asking it to research or invent
 * anything is pure downside. Every instruction here has a matching guard in
 * `guardExtendedEvents`, so a model that ignores one loses the line.
 */
export function buildSampleExtensionPrompt(
  sourcetype: string,
  realEvents: string[],
  want: number,
  feedback?: string,
): { systemPrompt: string; userPrompt: string } {
  const real = (realEvents || []).map(e => String(e).trim()).filter(Boolean);
  const universe = sampleShapeUniverse(real);
  const shape = universe.format !== 'unstructured'
    ? `The events are ${universe.format}. Use ONLY these field names, and no others, and put ALL of them on EVERY line you emit:\n${universe.keys.join(', ')}`
    : universe.columns
      ? `The events are delimited text with exactly ${universe.columns} columns separated by "${universe.delimiter === '\t' ? '\\t' : universe.delimiter}". Every line you emit must have exactly ${universe.columns} columns.`
      : 'The events are unstructured text. Reuse the SAME message templates as the examples — change only the values inside them (timestamps, IPs, ports, hosts, ids, users, counters).';
  // The length rule is stated in characters because it is CHECKED in characters.
  // A model given a 1972-char kvp example happily answers with 130-char lines
  // carrying a handful of the fields; every one of those is then discarded for
  // being outside the real range, and the extension silently yields nothing.
  const lenRule = universe.maxLen > 0
    ? `- Each line must be roughly ${universe.minLen === universe.maxLen ? `${universe.maxLen}` : `${universe.minLen}-${universe.maxLen}`} characters long, like the examples — dropping fields to make a shorter line gets the line discarded.`
    : '- Keep each line the same size as the examples.';
  const systemPrompt = `You extend a real log sample with more events of the SAME source. You are NOT inventing a format: real examples are given, and your output is checked against them mechanically.

${shape}

Rules — a line that breaks any of these is discarded:
- Emit ONLY raw log lines, one per line. No markdown, no numbering, no commentary.
- Never introduce a field, key, column or message template that is not in the examples.
- Never repeat an example line verbatim.
- Vary the VALUES: timestamps within a plausible window, different IPs (mix internal and public), ports, hostnames, users, ids, byte counts, outcomes (both success and failure where the examples show both).
${lenRule}
- Keep each line's syntax valid and complete.`;
  const userPrompt = `Source: ${sourcetype}
Here are ${real.length} real ${sourcetype} event(s):
${real.join('\n')}

Emit ${want} additional ${sourcetype} events in exactly this format, one per line.${feedback || ''}`;
  return { systemPrompt, userPrompt };
}

/**
 * The output allowance for EVERY extension call, and deliberately the maximum the
 * gateway accepts.
 *
 * It is a ceiling, not a reservation — an answer that needs 5 K tokens is billed as 5 K
 * whatever the ceiling says — so there is no reason to send anything smaller, and one
 * very good reason not to: on a reasoning model the thinking comes out of the SAME
 * allowance as the answer. Measured on sonnet-5 via Aperture, a 530-char CEF source
 * asked for 27 lines within 16000 tokens returned ZERO text three times out of three
 * (`stop_reason: max_tokens`, `thinking_tokens: 16000`, no text block at all); the same
 * source at 32000 returned all 16 requested lines in 90s. What bounds the cost here is
 * the ASK (see `sampleExtensionAsk`), never the ceiling.
 */
export const SAMPLE_EXTEND_MAX_TOKENS = 32000;

/**
 * How much generated text ONE call may be asked for.
 *
 * Latency is dominated by the model's thinking, not by the bytes, and it varies wildly
 * for identical input: thycotic_ss (530-char CEF) asked for 16 lines returned in 90s
 * once and ran past 240s twice. Asking for ~6 KB instead of ~9 KB costs a few events —
 * 11 generated lines still clears SAMPLE_EXTEND_FLOOR — and buys a call that lands.
 */
const SAMPLE_EXTEND_ANSWER_CHARS = 6000;

/**
 * How many lines to ask for, given how WIDE the real lines are.
 *
 * More than we need, because a guard rejection costs nothing while coming back short
 * costs another round trip — but bounded by the total TEXT we are asking the model to
 * write, because that is what sets the latency. Measured: ~8 KB of generated text takes
 * 75-90s when it lands at all, and 19 KB (10 lines of a 1972-char kvp source) blew past
 * a 180s timeout with nothing to show. Ten to fifteen events already clears
 * SAMPLE_EXTEND_FLOOR, so trading line count for width is nearly free.
 */
export function sampleExtensionAsk(want: number, realEvents?: string[]): number {
  const generous = Math.min(40, Math.max(1, Math.ceil(Number(want) * 1.5)));
  const avg = averageLineLength(realEvents);
  if (!avg) return generous;
  return Math.max(4, Math.min(generous, Math.floor(SAMPLE_EXTEND_ANSWER_CHARS / avg)));
}

function averageLineLength(realEvents?: string[]): number {
  const lens = (realEvents || []).map(e => String(e || '').length).filter(n => n > 0);
  return lens.length ? lens.reduce((a, b) => a + b, 0) / lens.length : 0;
}

export interface SampleExtensionAttempt {
  ask: number;
  maxTokens: number;
}

/**
 * The whole retry policy, in one place, for both run modes: at most TWO model calls.
 *
 * The second is not a repeat — it asks for roughly HALF as many lines, and it is told
 * which guards rejected the first batch. That shape recovers both observed failures: a
 * model that thought itself out of budget, and a model that got the wire format wrong
 * and would otherwise get it wrong again identically. Two calls is also the latency
 * ceiling we can put on a build path where each call measured 25-150s.
 */
export function sampleExtensionAttempts(
  realEvents: string[],
  want: number,
  opts: { budgetMs?: number } = {},
): SampleExtensionAttempt[] {
  // Inside the Cribl iframe every request dies at the platform proxy's 30s
  // ceiling, so the plan above — which is built around calls measured at 25-150s —
  // could only ever spend 60s to arrive at nothing. Ask for a little, once: a
  // short extension that lands beats a generous one that cannot.
  if (opts.budgetMs && opts.budgetMs <= 30_000) {
    return [{ ask: Math.max(2, Math.min(6, want)), maxTokens: 3000 }];
  }
  const first = sampleExtensionAsk(want, realEvents);
  return [
    { ask: first, maxTokens: SAMPLE_EXTEND_MAX_TOKENS },
    { ask: Math.max(4, Math.ceil(first / 2)), maxTokens: SAMPLE_EXTEND_MAX_TOKENS },
  ];
}

/**
 * Turn guard rejections into prompt text for ONE retry. Re-sending the identical
 * prompt is what the AI-sample library already learned not to do: a model that got
 * the shape wrong gets it wrong again, at full latency.
 */
export function renderExtensionFeedback(rejected: { line: string; reason: string }[]): string {
  const reasons = [...new Set((rejected || []).map(r => r.reason))].slice(0, 4);
  if (!reasons.length) return '';
  return `\n\nYour previous attempt was rejected — every line failed a mechanical check:\n${reasons.map(r => `- ${r}`).join('\n')}\nFix exactly those problems. Emit nothing but log lines.`;
}
