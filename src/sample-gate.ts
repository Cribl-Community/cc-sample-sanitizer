// Sample usability gate (packtester audit 2026-10-02). Eight of 74 batch packs
// were built from a sample that was the generator's REFUSAL text ("Unable to
// generate aemcdn events: no exact field names…"), and one from a column of bare
// timestamps. The build happily parsed, mapped and scored that text — a pack for
// a log nobody ships, with a number on it. A sample like that is not measurable:
// the build must stop and say so instead of minting a score.

export interface SampleUsability {
  usable: boolean;
  kind: 'ok' | 'refusal' | 'degenerate' | 'empty';
  reason: string;
  /** Share of lines that triggered the verdict (0..1). */
  ratio: number;
}

/** A refusal or abstention line from a sample generator (LLM), not a log line. */
const REFUSAL_LINE = new RegExp([
  String.raw`^\s*(?:unable to|cannot|can(?:'|’)t|could not|i (?:can(?:'|’)?t|cannot|am unable|am not able|don(?:'|’)t have)|i(?:'|’)m (?:sorry|unable)|sorry\b|as an ai\b)`,
  String.raw`^\s*(?:no|there is no) (?:canonical|exact|authentic|documented|vendor-defined|universal|standard(?:ized)?|public) (?:raw )?(?:event |log )?(?:format|schema|fields?|samples?|examples?)`,
  String.raw`^\s*exact .{0,80}\bcannot be determined\b`,
  String.raw`\b(?:is a|are) (?:versioned )?binary protocol\b.{0,80}\bno (?:universal )?text`,
].join('|'), 'i');

// A refusal often continues as plain explanatory prose ("Cisco eStreamer DNS
// records are versioned binary protocol data."). Log lines carry structure —
// key=value, JSON, an IP, a clock time — prose does not. Prose AND abstention
// vocabulary together mark a refusal line.
const ABSTAIN_VOCAB = /\b(?:unable|cannot|can(?:'|’)t|unavailable|unknown|undocumented|not (?:defined|documented|determinable|available)|requires?|required|without|guess(?:ing)?|provide|(?:deployment|client)-specific|no (?:[\w-]+ ){0,3}(?:format|schema|fields?|samples?|names?))\b/i;
function isProse(line: string): boolean {
  if (/[={}[\]<>|]/.test(line)) return false;
  if (/\b\d{1,3}(?:\.\d{1,3}){3}\b|\d{1,2}:\d{2}(?::\d{2})?/.test(line)) return false;
  return line.split(/\s+/).filter(w => /^[A-Za-z][A-Za-z'’,.-]*$/.test(w)).length >= 6;
}
// Short abstention stubs a generator pads a refusal with ("Hypori event format
// unavailable", "Hypori log schema unspecified"): a few bare words ending in an
// abstention word, no structure at all.
const ABSTAIN_TAIL = /\b(?:unavailable|unspecified|unknown|undocumented|undefined|not (?:provided|available|documented|specified|known))\.?$/i;
function isAbstainStub(line: string): boolean {
  if (/[={}[\]<>|:"]/.test(line) || /\d/.test(line)) return false;
  const words = line.split(/\s+/);
  return words.length >= 3 && words.length <= 10 && words.every(w => /^[A-Za-z][A-Za-z'’.,-]*$/.test(w)) && ABSTAIN_TAIL.test(line);
}
export const isRefusalLine = (l: string) => REFUSAL_LINE.test(l) || (isProse(l) && ABSTAIN_VOCAB.test(l)) || isAbstainStub(l);

/** An event with nothing in it: `{}`, `[]`, `null`, `""` (ivanti_auditlog 2026-10-09: 5 of 8). */
export const isEmptyEvent = (e: string) => /^\s*(?:\{\s*\}|\[\s*\]|null|""|'')\s*,?\s*$/.test(String(e ?? ''));

/**
 * Line-level cleanup for a GENERATED sample (packtester audit 2026-10-09). The
 * whole-sample gate below only fails a sample that is mostly refusal; 13 batch
 * samples carried a refusal paragraph or `{}` padding under that bar and were
 * built and scored as if the lines were events. Empty events are dropped
 * (they hold no value, so nothing is lost); refusal lines are dropped AND
 * returned, because a model that said it does not know the format wrote the
 * rest of the sample by guessing — the caller decides what that costs.
 */
export function splitNonEvents(events: string[]): { events: string[]; refusals: string[]; empties: number } {
  const kept: string[] = [];
  const refusals: string[] = [];
  let empties = 0;
  for (const e of events || []) {
    const t = String(e ?? '').trim();
    if (!t) continue;
    if (isEmptyEvent(t)) { empties++; continue; }
    // A single-line event is a refusal as a whole; a multi-line one (XML) only
    // when every line is.
    const lines = t.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    if (lines.length && lines.every(isRefusalLine)) { refusals.push(t); continue; }
    kept.push(e);
  }
  return { events: kept, refusals, empties };
}

const REFUSAL_RATIO = 0.5;
const DEGENERATE_RATIO = 0.8;

/**
 * Value tokens in an event: a bare timestamp or a lone word is one token. JSON
 * counts a key and a value per leaf (`{"category":"Administrative"}` is thin but
 * names a field — not degenerate), XML its elements/attributes (minified
 * `<a><b>x</b></a>` has no whitespace to split on).
 */
function valueTokens(event: string): number {
  const t = event.trim();
  if (/^[{[]/.test(t)) {
    try {
      let n = 0;
      const walk = (v: unknown): void => {
        if (v && typeof v === 'object') for (const x of Object.values(v as object)) walk(x);
        else n += 2;
      };
      const parsed = JSON.parse(t);
      // A bare JSON scalar (`"2026-10-02"`) is still one value.
      if (!parsed || typeof parsed !== 'object') return 1;
      walk(parsed);
      return n;
    } catch { /* not JSON — fall through */ }
  }
  if (/^<[A-Za-z?!]/.test(t)) return (t.match(/<[A-Za-z_][^>]*>|\s[\w:-]+=["']/g) || []).length;
  return t.split(/[\s,;|=]+/).filter(Boolean).length;
}

export function assessSampleUsable(events: string[]): SampleUsability {
  const lines = (events || [])
    .flatMap(e => String(e ?? '').split(/\r?\n/))
    .map(l => l.trim())
    .filter(Boolean);
  if (!lines.length) return { usable: false, kind: 'empty', reason: 'The sample has no events.', ratio: 1 };

  const refusals = lines.filter(isRefusalLine).length;
  if (refusals / lines.length >= REFUSAL_RATIO) {
    return {
      usable: false, kind: 'refusal', ratio: refusals / lines.length,
      reason: `The sample is generator refusal text, not log events (${refusals}/${lines.length} lines, e.g. "${lines.find(isRefusalLine)!.slice(0, 100)}"). Provide real events for this source.`,
    };
  }
  // Degenerate is judged per EVENT, not per line: a multi-line XML event has one
  // token per line but many per event (Trellix ePO).
  const evs = (events || []).map(e => String(e ?? '').trim()).filter(Boolean);
  const degenerate = evs.filter(e => valueTokens(e) <= 1).length;
  if (evs.length && degenerate / evs.length >= DEGENERATE_RATIO) {
    return {
      usable: false, kind: 'degenerate', ratio: degenerate / evs.length,
      reason: `The sample carries no fields to extract: ${degenerate}/${evs.length} events hold a single value (e.g. "${evs[0].slice(0, 60)}"). Provide complete events for this source.`,
    };
  }
  return { usable: true, kind: 'ok', reason: '', ratio: 0 };
}

// --- Shared-sample subtype check ---------------------------------------------
// Five FortiGate packs (utm, event, adc, traffic, fgt_firewall) were all built
// from ONE sample whose every line was `type=traffic` — the utm/event packs
// parse and map a log type their source never sends. When the sample has a
// type discriminator with a single value and the sourcetype names a different
// subtype, say so (a warning: the sample may still be right for a generic name).
const DISCRIMINATOR = /(?:^|[\s,{;|])"?(type|subtype|log_?type|logtype|event_?type)"?\s*[=:]\s*"?([A-Za-z][\w-]*)/gi;
// The primary discriminator wins (FortiGate: `type=traffic subtype=forward`).
const DISCRIMINATOR_ORDER = ['type', 'log_type', 'logtype', 'event_type', 'eventtype', 'subtype'];
// Trailing sourcetype tokens that name a wire format / family, not a subtype.
const GENERIC_SUFFIX = new Set(['log', 'logs', 'syslog', 'json', 'cef', 'leef', 'xml', 'csv', 'kv', 'kvp', 'firewall',
  'fw', 'events', 'event_log', 'audit', 'access', 'security', 'all', 'raw', 'data', 'structured', 'text', 'results',
  // transports, not subtypes
  'eventhub', 'kafka', 's3', 'hec', 'api', 'stream', 'logpush']);

export interface SubtypeMismatch { subtype: string; sampleTypes: string[]; reason: string }

// Vendor abbreviations that survive in a squashed pack name but are not subtypes.
const VENDOR_ABBREV = new Set(['fgt', 'pan', 'asa', 'ftd', 'wsa', 'esa', 'sma', 'fmc', 'nss']);

function stripGenericSuffix(t: string): string {
  for (let changed = true; changed;) {
    changed = false;
    for (const g of GENERIC_SUFFIX) if (t.length > g.length && t.endsWith(g)) { t = t.slice(0, -g.length); changed = true; }
  }
  return t;
}

/**
 * The subtype a build was asked for: the sourcetype's own last token
 * (`pan_traffic` → traffic), else what the pack name adds on top of a
 * canonicalized sourcetype (`fortigateutm-ocsf` over `fortinet_fortigate` → utm).
 */
export function declaredSubtype(sourcetype: string, packName?: string): string | null {
  const tokens = String(sourcetype || '').toLowerCase().split(/[_:\-/\s]+/).filter(Boolean);
  const ok = (t: string) => t.length >= 3 && !/^\d+$/.test(t) && !GENERIC_SUFFIX.has(t) && !VENDOR_ABBREV.has(t);
  // The pack name is what the user asked for; the sourcetype may already be
  // canonicalized to the product (`fortinet_fortigate`), whose last token is a
  // product name, not a subtype.
  if (packName) {
    let rest = String(packName).toLowerCase().replace(/[-_][a-z0-9#]+$/, '').replace(/[^a-z0-9]/g, '');
    for (const t of [...tokens].sort((a, b) => b.length - a.length)) rest = rest.split(t).join('');
    rest = stripGenericSuffix(rest);
    if (ok(rest)) return rest;
    // Nothing beyond the sourcetype: the sourcetype's own subtype, when it has one
    // that the pack name repeats (`pan_traffic` / `pantraffic-ocsf`).
  }
  if (tokens.length >= 2 && ok(tokens[tokens.length - 1])) {
    const last = tokens[tokens.length - 1];
    // `fortinet_fortigate`: the second token repeats the vendor stem → product, not subtype.
    if (tokens.length === 2 && last.slice(0, 4) === tokens[0].slice(0, 4)) return null;
    return last;
  }
  return null;
}

export function sampleSubtypeMismatch(sourcetype: string, events: string[], packName?: string): SubtypeMismatch | null {
  const subtype = declaredSubtype(sourcetype, packName);
  if (!subtype) return null;
  const byKey = new Map<string, Set<string>>();
  for (const e of (events || []).slice(0, 50)) {
    for (const m of String(e).matchAll(DISCRIMINATOR)) {
      const k = m[1].toLowerCase();
      if (!byKey.has(k)) byKey.set(k, new Set());
      byKey.get(k)!.add(m[2].toLowerCase());
    }
  }
  const primary = DISCRIMINATOR_ORDER.find(k => byKey.has(k));
  if (!primary) return null;
  const values = byKey.get(primary)!;
  if (values.size !== 1) return null;   // a mixed sample — nothing to say
  const only = [...values][0];
  const matches = (v: string) => v.includes(subtype) || subtype.includes(v);
  if ([...byKey.values()].some(set => [...set].some(matches))) return null;
  const who = packName && !String(sourcetype).toLowerCase().endsWith(subtype) ? `${packName} (${sourcetype})` : sourcetype;
  return {
    subtype, sampleTypes: [only],
    reason: `The ${who} sample only contains type=${only} events, but the build names the "${subtype}" subtype — it may be a sample shared with a sibling source. Mapping and scores describe ${only} events.`,
  };
}
