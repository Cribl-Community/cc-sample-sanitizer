// Wire-format classification of a sample — the ONE place that answers "what shape
// is this data on the wire?" (JSON / XML / CEF / LEEF / key=value / columns / text).
//
// Dependency-free on purpose: detection (App.tsx, ai-client.ts), the backend
// detector (scripts/ai-validate.mjs), parser routing and the golden store
// (golden-variant.ts) all ask the same question, and the sanitizer graph imports
// sample-library, so this must never reach an AI client or a bundled corpus.
// sample-library.ts re-exports everything here, so its existing importers are
// unchanged.

/** Minimum delimited columns before a line's column count is treated as its shape. */
const MIN_DELIMITED_COLUMNS = 5;

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
      if (c >= MIN_DELIMITED_COLUMNS) tally.set(c, (tally.get(c) || 0) + 1);
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

// --- Source wire format (the format dimension of a build) ---------------------
//
// `describeSampleFormat` answers for a HUMAN (it separates `syslog` from `text`
// because the advice differs). A build needs the coarser question "which parser
// family reads this", where syslog-framed free text and bare free text are the
// same thing: regex over `_raw`. That is the vocabulary sourcetypes declare as
// their native formats (source-recognition.ts) and the golden store keys on
// (golden-variant.ts), so a FortiGate CEF golden can never replay on FortiGate
// key=value data.

export type SourceWireFormat = 'cef' | 'leef' | 'json' | 'xml' | 'kvp' | 'csv' | 'tsv' | 'psv' | 'text';

export const SOURCE_WIRE_FORMATS: readonly SourceWireFormat[] =
  ['cef', 'leef', 'json', 'xml', 'kvp', 'csv', 'tsv', 'psv', 'text'];

/**
 * A sample has a single wire format only when MORE than this share of its lines
 * agree. Exactly half is a mixed feed (a Zscaler NSS sample that is half CEF,
 * half key=value), and a mixed feed must not be filed under either variant.
 */
const WIRE_MAX_MIXED_SHARE = 0.5;

export function isSourceWireFormat(value: unknown): value is SourceWireFormat {
  return typeof value === 'string' && (SOURCE_WIRE_FORMATS as readonly string[]).includes(value);
}

/**
 * The build-relevant wire format of a described sample, or null when it cannot be
 * told (no events, or no shape carries more than half the lines). Null is "unknown",
 * never a format: every consumer treats it as "do what you did before formats
 * existed", so a mixed sample can never be filed under the wrong variant.
 */
export function wireFormatOf(desc: SampleFormatDescription): SourceWireFormat | null {
  if (desc.id === 'empty' || desc.lines === 0) return null;
  if (desc.agreement <= WIRE_MAX_MIXED_SHARE && desc.columns == null) return null;
  return desc.id === 'syslog' ? 'text' : desc.id;
}

/**
 * `wireFormatOf(describeSampleFormat(events))`. Also accepts preview events
 * (`{_raw}` objects, as a validator report carries them); any other object is
 * read as the JSON it would serialise to.
 */
export function sampleWireFormat(events: unknown[] | string | null | undefined, limit = 50): SourceWireFormat | null {
  if (events == null) return null;
  const lines = Array.isArray(events)
    ? events.map(e => typeof e === 'string' ? e
      : e && typeof e === 'object' && typeof (e as { _raw?: unknown })._raw === 'string' ? (e as { _raw: string })._raw
      : e == null ? '' : JSON.stringify(e))
    : String(events);
  return wireFormatOf(describeSampleFormat(lines, limit));
}

// --- CEF / LEEF header (the vendor names itself) --------------------------------
//
// A CEF or LEEF event carries its own Device Vendor and Device Product in the
// header, so for these two formats the source is READ, not guessed. Syslog-framed
// headers (`<189>Jan 12 host CEF:0|Fortinet|Fortigate|…`) are found anywhere after
// whitespace, matching `classifyLine`.

export interface SecurityHeader {
  format: 'cef' | 'leef';
  /** Header version token (`0`, `1.0`, `2.0`). */
  version: string;
  vendor: string;
  product: string;
  productVersion: string;
}

export interface SampleSecurityHeader extends SecurityHeader {
  /** Share of inspected lines carrying this exact vendor + product. */
  share: number;
  lines: number;
}

// Header fields may escape a pipe as `\|` (and a backslash as `\\`).
const HEADER_FIELD = String.raw`((?:\\.|[^|\\])*)`;
const SECURITY_HEADER_RE = new RegExp(
  String.raw`(?:^|\s)(CEF|LEEF):\s*(\d+(?:\.\d+)?)\|` + HEADER_FIELD + String.raw`\|` + HEADER_FIELD + String.raw`\|` + HEADER_FIELD + String.raw`\|`,
);

const unescapeHeaderField = (s: string): string => s.replace(/\\(.)/g, '$1').trim();

/** The CEF/LEEF header of ONE line, or null when the line carries none. */
export function parseSecurityHeader(line: string): SecurityHeader | null {
  const m = SECURITY_HEADER_RE.exec(String(line || ''));
  if (!m) return null;
  return {
    format: m[1] === 'LEEF' ? 'leef' : 'cef',
    version: m[2],
    vendor: unescapeHeaderField(m[3]),
    product: unescapeHeaderField(m[4]),
    productVersion: unescapeHeaderField(m[5]),
  };
}

/**
 * The dominant CEF/LEEF header of a sample: the vendor + product most lines name,
 * with the share of inspected lines that name it. Null when no line has a header.
 * Callers decide what share is enough — detection wants a clear majority.
 */
export function sampleSecurityHeader(events: string[] | string, limit = 50): SampleSecurityHeader | null {
  const lines = (Array.isArray(events) ? events : String(events || '').split('\n'))
    .map(l => (l || '').trim()).filter(Boolean).slice(0, limit);
  if (lines.length === 0) return null;
  const tally = new Map<string, { header: SecurityHeader; hits: number }>();
  for (const line of lines) {
    const h = parseSecurityHeader(line);
    if (!h || !h.vendor) continue;
    const key = `${h.format}|${h.vendor.toLowerCase()}|${h.product.toLowerCase()}`;
    const slot = tally.get(key);
    if (slot) slot.hits++;
    else tally.set(key, { header: h, hits: 1 });
  }
  const best = [...tally.values()].sort((a, b) => b.hits - a.hits)[0];
  if (!best) return null;
  return { ...best.header, share: best.hits / lines.length, lines: lines.length };
}
