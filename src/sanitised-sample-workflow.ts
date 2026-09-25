/**
 * Browser-safe orchestration for the sanitised-sample wizard.
 *
 * There are no fetches here. In particular, recognising an unsanitised sample must
 * never fall through to the AI detector: the user has not reviewed the data yet.
 */
import {
  canonicalizeSourcetype,
  getParserForSourcetype,
  getSupportedSourcetypeCatalog,
  matchDatatypeParserBySample,
  matchGoldenSourceBySample,
  matchJsonSignature,
  recognizeSourcetype,
} from './source-recognition';
import {
  describeSampleFormat,
  eventsToLines,
  extractFieldValues,
  verifyGeneratedSample,
  type SampleFormatDescription,
  type SampleVerification,
} from './sample-library';
import {
  applySanitisation,
  checkStructurePreserved,
  planSanitisation,
  proveIdentityCoverage,
  summariseSanitisation,
  type CoverageProof,
  type ParsedLine,
  type SanitiseEntry,
  type SanitiseOptions,
  type SanitisePlan,
  type StructuralCheck,
} from './sample-sanitise';

const DEFAULT_PARSE_CAP = 3_000;

export function normaliseSampleInput(input: string): string {
  const text = String(input || '').replace(/\r\n/g, '\n').trim();
  if (!text) return '';
  if (text.startsWith('[') || text.startsWith('{')) {
    try {
      const value = JSON.parse(text);
      if (Array.isArray(value)) return eventsToLines(value).filter(line => line.trim()).join('\n');
      if (Array.isArray(value?.events)) return eventsToLines(value.events).filter(line => line.trim()).join('\n');
    } catch { /* not a JSON array; preserve the user's text */ }
  }
  const eventStarts = text.match(/<Event(?:\s|>)/g)?.length || 0;
  if (eventStarts >= 2) {
    const events = text.replace(/\n/g, '').split(/(?=<Event(?:\s|>))/).filter(event => event.trim());
    if (events.length >= eventStarts) return events.join('\n');
  }
  return text;
}

export interface LocalSampleRecognition {
  sourcetype: string;
  display: string;
  method: 'datatype-parser' | 'static-parser' | 'signature' | 'format-only';
  confidence: 'high' | 'low';
  reason: string;
  format: SampleFormatDescription;
  offline: true;
  // Next-best candidates the recogniser also considered, canonicalised. Surfaced
  // as one-click quick-picks so a confidently-wrong top guess is cheap to correct.
  alternatives?: string[];
}

export function recogniseSampleLocally(events: string): LocalSampleRecognition {
  const format = describeSampleFormat(events.split('\n').filter(Boolean).slice(0, 50));
  const match = matchDatatypeParserBySample(events);
  if (match) {
    const recognised = recognizeSourcetype(match.parserKey);
    const sourcetype = recognised.canonical || match.parserKey;
    // runnersUp are "key:conf" diagnostics strings — surface their canonical
    // sourcetypes as alternatives so the reviewer can switch in one click.
    const alternatives = (match.runnersUp || [])
      .map(s => canonicalizeSourcetype(String(s).split(':')[0]))
      .filter((a, i, all) => a && a !== sourcetype && all.indexOf(a) === i);
    return {
      sourcetype,
      display: sourcetype,
      method: 'datatype-parser',
      confidence: 'high',
      reason: `Matched the ${match.parserKey} datatype parser locally.`,
      format,
      offline: true,
      alternatives,
    };
  }
  // A distinctive raw signature (e.g. the SAP SAL binary TLV record marker) names
  // a golden source that fingerprints as keyless `unstructured`, so neither the
  // datatype-parser matcher above nor the JSON-signature matcher below can label
  // it. Unambiguous single match only.
  const golden = matchGoldenSourceBySample(events);
  if (golden) {
    const recognised = recognizeSourcetype(golden.sourcetype);
    const sourcetype = recognised.canonical || golden.sourcetype;
    return {
      sourcetype,
      display: sourcetype,
      method: 'signature',
      confidence: 'high',
      reason: `Recognised ${golden.description} by its distinctive raw signature.`,
      format,
      offline: true,
    };
  }
  // A JSON or XML sample is self-describing: its field names come from the data, not
  // from a positional / delimited / regex parser. Running the text-oriented static
  // parsers over it produces false matches — a comma-heavy JSON line comma-splits into
  // dozens of bogus "columns" and a CSV parser (palo_alto_threat) then claims it with
  // high confidence and 53 "fields". The genuine JSON/XML datatype parsers (crowdstrike,
  // cloudtrail, …) already had their chance via matchDatatypeParserBySample above; for
  // everything else the sanitiser reads identifiers straight from the JSON/XML values
  // (fieldPairs + the pattern passes), so fall through to a format-only result rather
  // than mislabel the source.
  const selfDescribing = format.id === 'json' || format.id === 'xml';
  // A self-describing JSON sample carries no positional/delimited parser, but some
  // well-known JSON feeds (O365 Unified Audit Log, …) are unmistakable by their
  // top-level key signature. Name those instead of leaving them "self-describing",
  // so the sourcetype is correct in both apps (Hard Rule 25). Sanitisation still
  // reads field names straight from the data, so this only improves the label.
  if (selfDescribing) {
    const sig = matchJsonSignature(events);
    if (sig) {
      const recognised = recognizeSourcetype(sig.sourcetype);
      const sourcetype = recognised.canonical || sig.sourcetype;
      return {
        sourcetype,
        display: sourcetype,
        method: 'signature',
        confidence: 'high',
        reason: `Recognised ${sig.description} by its JSON key signature (${sig.matched.join(', ')}).`,
        format,
        offline: true,
      };
    }
  }
  // Static parsers are not all present in the Search datatype store. Try the same
  // parser functions the builder would use and require both breadth (half the lines)
  // and richness (three named fields) so a generic timestamp regex cannot claim a
  // source merely because it found one token.
  const lines = events.split('\n').filter(line => line.trim()).slice(0, 12);
  const scored: { sourcetype: string; parsed: number; fields: number }[] = [];
  const seen = new Set<string>();
  for (const item of selfDescribing ? [] : getSupportedSourcetypeCatalog()) {
    const canonical = canonicalizeSourcetype(item.name);
    if (!canonical || seen.has(canonical)) continue;
    seen.add(canonical);
    let functions: ReturnType<typeof getParserForSourcetype> = [];
    try { functions = getParserForSourcetype(canonical, false) || []; } catch { continue; }
    if (!functions.length) continue;
    let parsed = 0;
    const fields = new Set<string>();
    for (const line of lines) {
      try {
        const values = extractFieldValues(functions, line);
        const names = Object.keys(values || {}).filter(name => !name.startsWith('__'));
        if (names.length) parsed++;
        names.forEach(name => fields.add(name));
      } catch { /* candidate miss */ }
    }
    if (parsed < Math.max(1, Math.ceil(lines.length / 2)) || fields.size < 3) continue;
    scored.push({ sourcetype: canonical, parsed, fields: fields.size });
  }
  scored.sort((a, b) => b.parsed - a.parsed || b.fields - a.fields);
  const best = scored[0] || null;
  if (best) {
    const alternatives = scored.slice(1, 4).map(s => s.sourcetype).filter(s => s !== best.sourcetype);
    return {
      sourcetype: best.sourcetype,
      display: best.sourcetype,
      method: 'static-parser',
      confidence: 'high',
      reason: `Matched the ${best.sourcetype} static parser locally (${best.parsed}/${lines.length} lines, ${best.fields} fields).`,
      format,
      offline: true,
      alternatives,
    };
  }
  return {
    sourcetype: '',
    display: selfDescribing ? `${format.label} (self-describing)` : 'Source not recognised',
    method: 'format-only',
    confidence: 'low',
    // A self-describing sample needs no sourcetype to sanitise: field names come from the
    // data, so the value + field passes run directly. Only positional/delimited formats
    // genuinely need a sourcetype to know what each column is.
    reason: selfDescribing
      ? `${format.label} is self-describing — its field names come from the data, so sanitisation runs directly. Set a sourcetype only if you want parser-verified coverage.`
      : `The wire format looks like ${format.label}, but no local parser matched it. Enter the sourcetype to continue.`,
    format,
    offline: true,
  };
}

/**
 * Decide which parser to sanitise a sample WITH — the single resolution both the
 * pack-generation wizard and the sample-library wizard share, so they always agree.
 *
 * Order, strongest-first:
 *   1. A confirmed/entered sourcetype whose static parser exists (the wizard's
 *      strength — the pack-gen flow almost always has this).
 *   2. A direct datatype-parser content match (`matchDatatypeParserBySample`),
 *      which returns the parser functions even when no static parser is registered.
 *   3. The full-catalogue local recogniser (`recogniseSampleLocally`, breadth +
 *      richness thresholds) — this is what lets the LIBRARY flow, which starts
 *      from a cold paste with no sourcetype, still find a parser.
 * Every tier is local: nothing here reaches AI or the network (Hard Rule 23).
 */
export function resolveSanitiseSourcetype(
  events: string,
  hint?: string,
): { sourcetype: string; functions: ReturnType<typeof getParserForSourcetype> } {
  const tryParser = (name: string): { canonical: string; fns: ReturnType<typeof getParserForSourcetype> } => {
    const canonical = canonicalizeSourcetype(name);
    try { return { canonical, fns: getParserForSourcetype(canonical, false) || [] }; }
    catch { return { canonical, fns: [] }; }
  };
  const name = String(hint || '').trim();
  if (name) {
    const { canonical, fns } = tryParser(name);
    if (fns.length) return { sourcetype: canonical, functions: fns };
  }
  const match = matchDatatypeParserBySample(events);
  if (match) return { sourcetype: match.parserKey, functions: match.functions };
  const rec = recogniseSampleLocally(events);
  if (rec.sourcetype) {
    const { canonical, fns } = tryParser(rec.sourcetype);
    if (fns.length) return { sourcetype: canonical, functions: fns };
    // A recognised source with no static parser (e.g. a signature-named JSON feed
    // like o365_management_activity) still has a real name worth carrying through —
    // JSON sanitisation reads field names from the data, so the empty function list
    // is expected. Prefer it over discarding the recognition.
    return { sourcetype: canonical, functions: [] };
  }
  return { sourcetype: name ? canonicalizeSourcetype(name) : '', functions: [] };
}

/**
 * Flatten one JSON line into a flat `field → value` record (nested objects become dotted
 * paths, array elements collapse onto the same path). Returns null for a non-JSON line.
 *
 * A self-describing JSON sample has no static/datatype parser (its fields ARE the data),
 * so without this the coverage proof (`proveIdentityCoverage`) sees zero readable lines and
 * reports `blind` — which the strict library save-flow rejects. Flattening gives the proof
 * real fields to check, so a JSON sample can be verified and saved like any other.
 */
export function flattenJsonLine(line: string): ParsedLine | null {
  const t = line.trimStart();
  if (t[0] !== '{' && t[0] !== '[') return null;
  let obj: unknown;
  try { obj = JSON.parse(line); } catch { return null; }
  if (!obj || typeof obj !== 'object') return null;
  const out: Record<string, string> = {};
  const walk = (value: unknown, prefix: string): void => {
    if (value === null || value === undefined) return;
    if (Array.isArray(value)) { for (const el of value) walk(el, prefix); return; }
    if (typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) walk(v, prefix ? `${prefix}.${k}` : k);
      return;
    }
    if (!prefix) return;
    // First writer wins for a repeated path (array element) — the proof only needs each
    // distinct identity value to appear once, and String() keeps the raw value verbatim.
    if (out[prefix] === undefined) out[prefix] = String(value);
  };
  walk(obj, '');
  return Object.keys(out).length ? out : null;
}

export function parseSampleLocally(
  events: string,
  sourcetype: string,
  cap = DEFAULT_PARSE_CAP,
): { parsed: ParsedLine[]; parserName?: string } {
  if (!events.trim()) return { parsed: [] };
  const { sourcetype: parserName, functions } = resolveSanitiseSourcetype(events, sourcetype);
  const lines = events.split('\n');
  if (!functions.length) {
    // No parser matched. If the sample is JSON, its fields are self-describing — flatten
    // each line so the coverage proof has real fields to verify (otherwise it is `blind`).
    const flattened = lines.map((line, index) =>
      index >= cap || !line.trim() ? null : flattenJsonLine(line));
    return flattened.some(Boolean) ? { parsed: flattened, parserName: 'json' } : { parsed: [] };
  }
  const parsed = lines.map((line, index) => {
    if (index >= cap || !line.trim()) return null;
    try { return extractFieldValues(functions, line); } catch { return null; }
  });
  return { parsed, parserName: parserName || undefined };
}

export function planSampleSanitisation(
  events: string,
  sourcetype: string,
  options: Omit<SanitiseOptions, 'parsed' | 'parserName' | 'sourcetype'> = {},
): SanitisePlan {
  const local = parseSampleLocally(events, sourcetype);
  return planSanitisation(events, {
    ...options,
    parsed: local.parsed,
    parserName: local.parserName,
    sourcetype: canonicalizeSourcetype(sourcetype),
  });
}

export interface AppliedSanitisation {
  text: string;
  events: string[];
  replacementsApplied: number;
  structure: StructuralCheck;
  coverage: { total: number; replaced: number; blind: boolean; ok: boolean };
  verification: SampleVerification;
  parserName?: string;
}

/**
 * The single sanitise COMPUTE, shared by both flows. It runs the whole sequence —
 * replace values, check the wire format survived, re-parse before/after and prove
 * the identities changed, and (opt-in) re-verify against the source parser — and
 * RETURNS the result. It never throws and has no side effects, so each caller can
 * apply its own policy over the same numbers:
 *   - pack-gen wizard  → advisory: write the result back, WARN in a notice, allow undo.
 *   - sample library    → strict: `applyAndVerifySanitisation` throws on any failing
 *                         gate and discards the original (the trust-tier boundary).
 * Keeping this in one place is what guarantees the two flows can never diverge.
 */
export interface SanitisationRun {
  before: string;
  text: string;
  events: string[];
  changed: boolean;
  liveEntries: number;
  structure: StructuralCheck;
  coverage: CoverageProof;
  verification: SampleVerification | null;
  // Verification of the ORIGINAL, untouched events (only when opts.verify). It exists so a
  // caller can tell whether sanitisation DEGRADED parseability or the raw sample simply never
  // parsed cleanly to begin with. Real access logs carry scanner probes, TLS handshakes on the
  // HTTP port and `408` timeout lines the combined/common regex cannot read — blaming the
  // sanitiser for those (as a bare AFTER check does) is a false alarm.
  verificationBefore: SampleVerification | null;
  parserName?: string;
  summary: string;
}

export function runSanitisation(
  before: string,
  sourcetype: string,
  entries: SanitiseEntry[],
  opts: { verify?: boolean } = {},
): SanitisationRun {
  const live = entries.filter(entry => entry.enabled && !!entry.alias && entry.alias !== entry.original);
  const text = applySanitisation(before, entries);
  const structure = checkStructurePreserved(before, text);
  const beforeParsed = parseSampleLocally(before, sourcetype);
  const afterParsed = parseSampleLocally(text, sourcetype);
  const coverage = proveIdentityCoverage(beforeParsed.parsed, afterParsed.parsed, {
    sourcetype: canonicalizeSourcetype(sourcetype),
  });
  const events = text.split('\n').filter(line => line.trim());
  const beforeEvents = before.split('\n').filter(line => line.trim());
  const canonical = canonicalizeSourcetype(sourcetype);
  const verification = opts.verify ? verifyGeneratedSample(canonical, events) : null;
  // Baseline the ORIGINAL against the same parser so the caller can separate a sanitisation
  // regression from a source that never parsed cleanly (see the field doc above).
  const verificationBefore = opts.verify ? verifyGeneratedSample(canonical, beforeEvents) : null;
  return {
    before,
    text,
    events,
    changed: text !== before,
    liveEntries: live.length,
    structure,
    coverage,
    verification,
    verificationBefore,
    parserName: afterParsed.parserName || beforeParsed.parserName,
    summary: summariseSanitisation(entries),
  };
}

/**
 * Thrown when the sanitisation cannot be applied. `survivors` is populated only for the
 * coverage-survivor case, so the UI can point the reviewer at the exact line + field that
 * still carries an identity instead of just refusing with a sentence.
 */
export class SanitisationBlocked extends Error {
  survivors: { field: string; value: string; line: number }[];
  constructor(message: string, survivors: { field: string; value: string; line: number }[] = []) {
    super(message);
    this.name = 'SanitisationBlocked';
    this.survivors = survivors;
  }
}

export function applyAndVerifySanitisation(
  before: string,
  sourcetype: string,
  entries: SanitiseEntry[],
): AppliedSanitisation {
  const run = runSanitisation(before, sourcetype, entries, { verify: true });
  if (!run.liveEntries) throw new SanitisationBlocked('No enabled replacement changes this sample.');
  if (!run.changed) throw new SanitisationBlocked('The enabled replacements did not change this sample.');
  if (!run.structure.ok) throw new SanitisationBlocked(`Sanitisation changed the wire format: ${run.structure.problems.join(' ')}`);
  if (!run.coverage.ok || run.coverage.blind) {
    if (run.coverage.blind) {
      throw new SanitisationBlocked('The parser could not prove that identifying field values changed; this sample cannot be stored safely.');
    }
    const survivors = run.coverage.remaining;
    const where = survivors.length === 1
      ? `line ${survivors[0].line}`
      : `${survivors.length} places (lines ${[...new Set(survivors.map(s => s.line))].join(', ')})`;
    throw new SanitisationBlocked(
      `${survivors.length} parsed ${survivors.length === 1 ? 'identity' : 'identities'} still ${survivors.length === 1 ? 'shows' : 'show'} through unchanged at ${where} — mask ${survivors.length === 1 ? 'it' : 'them'} below, then apply again.`,
      survivors);
  }
  // verify:true above guarantees a verification result. Block ONLY on a sanitisation-caused
  // regression: the original parsed and the sanitised sample no longer does. A raw sample that
  // already failed the parser (real access logs carry scanner probes / TLS handshakes / `408`
  // timeout lines the combined/common regex cannot read) is the source's own nature, not
  // something the sanitiser broke — rejecting the save for it would be a false alarm.
  if (run.verification?.verdict === 'fail' && run.verificationBefore?.verdict !== 'fail') {
    throw new Error(`Sanitising changed the events enough that the ${sourcetype} parser no longer reads them: ${run.verification.reasons.join(' ')}`);
  }
  return {
    text: run.text,
    events: run.events,
    replacementsApplied: run.liveEntries,
    structure: run.structure,
    coverage: {
      total: run.coverage.total,
      replaced: run.coverage.replaced,
      blind: run.coverage.blind,
      ok: run.coverage.ok,
    },
    verification: run.verification as SampleVerification,
    parserName: run.parserName,
  };
}
