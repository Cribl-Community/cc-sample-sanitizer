/**
 * Local, AI-free pseudonymisation of a sample's identities.
 *
 * Uploaded, worker-group, pasted and live-captured events are customer data, and this
 * app puts sample lines into AI prompts at a dozen call sites. Sending them to a model
 * vendor is not allowed, so the identities have to be replaced BEFORE the sample is
 * used — and the replacing has to happen here, in the browser, with no network call of
 * any kind. Nothing in this module fetches, imports a service, or talks to a model.
 *
 * The three rules that shape the whole design:
 *
 * 1. CONSISTENT, not per-occurrence random. One alias per distinct real value, applied
 *    everywhere. A fresh random value at each occurrence would turn forty events about
 *    one host into forty hosts, and this sample is what the generated pipeline is
 *    scored against — repeated hosts, src/dest pairs and per-user sessions are exactly
 *    the structure that makes the score mean anything.
 *
 * 2. SHAPE-PRESERVING. The sample also has to stay parseable, because parsers are
 *    generated and regex-scored against it. An FQDN stays an FQDN with the same label
 *    count, `CORP\jsmith` stays `DOMAIN\user`, an 8-character account stays 8
 *    characters, and every alias uses `[a-z0-9-]` so JSON/CSV/KVP quoting survives.
 *
 * 3. SALTED PER RUN, never hashed bare. An alias derived from an unsalted hash of the
 *    original is reversible: there are only ~4e9 IPv4 addresses, so a hash is a lookup
 *    table, not anonymisation. The mapping is seeded randomly per run and lives only in
 *    memory, so it cannot be reversed outside the session that made it.
 *
 * `planSanitisation` decides WHAT to replace and `applySanitisation` performs it. The
 * split is deliberate: the reviewer sees and edits the mapping before anything changes,
 * because a false positive that silently rewrites a sample produces a wrong pack that
 * nobody can see afterwards.
 */

import datatypeFieldAliasesData from '../config/datatype-field-aliases.json';
// The sanitiser used to statically import cim-data-models, sentinel-destinations,
// golden-formats and source-samples (~1.08 MB) purely to derive two flat lists. That
// dragged all four into the standalone Sample Sanitizer bundle. They are now pre-derived
// at build time into the small `sanitise-vocabulary.json` (see scripts/gen-sanitise-vocabulary.mjs) —
// behaviour is identical (the field names are still run through consider() below).
import sanitiseVocabulary from '../config/sanitise-vocabulary.json';
import sanitiseHintsData from '../config/sanitise-hints.json';
// Pure classification/compilation of the secret rules. The rules themselves are NOT imported
// here — they are installed from the bundled library and handed to `setSecretRules` (below).
import { compileSecretRules, type SecretRule } from './secret-rule-filter';

const SCHEMA_FIELD_NAMES: string[] = (sanitiseVocabulary as { schemaFieldNames?: string[] }).schemaFieldNames || [];
const PUBLIC_CORPUS_TOKENS: string[] = (sanitiseVocabulary as { publicTokens?: string[] }).publicTokens || [];

// ---------------------------------------------------------------------------
// What we recognise
// ---------------------------------------------------------------------------

export type IdentityKind = 'ipv4' | 'ipv6' | 'fqdn' | 'host' | 'user' | 'email' | 'mac' | 'custom' | 'secret' | 'pii';

/** How an IPv4/IPv6 literal is scoped — an alias must land in the SAME class. */
export type IpClass =
  | 'private'      // RFC1918 / RFC4193 unique-local: stays private, same block
  | 'loopback'
  | 'link-local'
  | 'cgnat'        // RFC6598 100.64/10
  | 'multicast'
  | 'public'       // → RFC5737 / RFC3849 documentation ranges
  | 'reserved';    // 0.0.0.0, broadcast, documentation ranges we already emit

export interface SanitiseEntry {
  /** The literal as it appears in the sample. */
  original: string;
  /** What it will be replaced with. Editable by the reviewer. */
  alias: string;
  kind: IdentityKind;
  /** Occurrences across the whole sample — the reviewer's cue for what matters. */
  count: number;
  /** For IPs: the class the alias had to preserve. */
  ipClass?: IpClass;
  /** Why this was picked up: the field name for field-aware hits, else the pattern. */
  via: string;
  /** Off = leave this value alone. False positives are unchecked here, not deleted. */
  enabled: boolean;
  /**
   * `certain` — a pattern matched, or a named field said what the value is.
   * `suspect` — a shape-and-variance guess with no field to back it up. Ships unticked:
   * a guess that silently rewrites a sample is worse than a guess the reviewer declines.
   */
  confidence: 'certain' | 'suspect';
  /**
   * For a shape/pattern pick: the slices of `original` that actually change.
   *
   * Apply still replaces the whole `original` with `alias` (so `8196` inside
   * `name[8196]:` does not also rewrite a bare port). The highlight and the review row
   * show only these slices — otherwise "replace the number" looks like the whole token
   * is selected.
   */
  patchSpans?: { start: number; end: number; alias: string }[];
}

export interface SanitisePlan {
  entries: SanitiseEntry[];
  /** Things the reviewer should look at before applying. */
  warnings: string[];
  /** How the identities were found, for the panel's "how much of this was automatic". */
  sources: {
    /** Hits that came from a real parser's named fields. */
    parser: number;
    /** Hits from the generic key=value / JSON scan. */
    field: number;
    /** Hits from a text-wide pattern (IP, email, FQDN, MAC, DOMAIN\user). */
    pattern: number;
    /** Unticked shape-and-variance suspects. */
    suspect: number;
    /** Credentials matched by a secret rule or a credential field name. */
    secret: number;
    /** Personal and device identifiers claimed by a named field. */
    pii: number;
    /** The parser used, when one was resolved locally. */
    parserName?: string;
  };
}

/** Field name → value for one line, as a real parser reads it. */
export type ParsedLine = Record<string, string> | null | undefined;

/**
 * How an entry says it exists because the reviewer picked its field, not because anything
 * recognised the value. Shared so the review list can group these and the warnings can tell
 * them apart from the fields our own lists named.
 */
export const PICKED_FIELD_VIA = 'you picked field';

export interface SanitiseOptions {
  /** Extra literals to replace — customer name, internal domain, project codes. */
  extraLiterals?: string[];
  /**
   * Field names whose every value the reviewer asked to replace.
   *
   * The counterpart to `extraLiterals`, for the case a literal cannot express. A quote
   * number is a different eight digits on every event, so there is no literal to add — and
   * the values that most need this are exactly the ones too shapeless to name individually.
   * Picking the field says "whatever is in here, replace it", which is both the safe
   * instruction and the one the reviewer actually has in mind.
   */
  extraFields?: string[];
  /**
   * Shape patterns the reviewer asked to apply: replace only the named capture groups
   * wherever the pattern matches. Encoded in the extras box as `re:<source>|g1,g2`.
   */
  extraPatterns?: { source: string; groupNames: string[] }[];
  /** Deterministic seed. Omit for a random one (the normal, unreversible case). */
  seed?: number;
  /**
   * Per-line field maps from the parser the app resolved for this sample, aligned with
   * `text.split('\n')`.
   *
   * This is what turns guessing into reading. A bare username matches no pattern and sits
   * in no `key=value` pair — in an Apache line `jsmith` is just a word, and in a CSV it is
   * just column three — but the parser that reads the format NAMES it, and a named field
   * with a known meaning is proof rather than a hunch. Injected rather than imported so
   * this module keeps its no-dependency, no-network shape.
   */
  parsed?: ParsedLine[];
  /** Which parser produced `parsed`, for the reviewer's benefit. */
  parserName?: string;
  /** The detected sourcetype, used to look up precision hints. */
  sourcetype?: string;
  /** Include the unticked shape-and-variance tier. Default true. */
  suggestSuspects?: boolean;
}

// ---------------------------------------------------------------------------
// Seeded RNG — small, dependency-free, good enough to pick aliases
// ---------------------------------------------------------------------------

/** mulberry32. Not cryptographic: it chooses aliases, it does not protect them. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomSeed(): number {
  const g = globalThis as { crypto?: { getRandomValues?: (a: Uint32Array) => void } };
  if (g.crypto?.getRandomValues) {
    const buf = new Uint32Array(1);
    g.crypto.getRandomValues(buf);
    return buf[0];
  }
  return Math.floor(Math.random() * 0xffffffff);
}

// ---------------------------------------------------------------------------
// Alias vocabulary
// ---------------------------------------------------------------------------

/* Deliberately bland and obviously synthetic. Realistic-LOOKING aliases read better
   but invite a reader to mistake a sanitised sample for real data, and a real person
   somewhere is called whatever we generate. */
const GIVEN = ['ada', 'ben', 'cara', 'dan', 'eve', 'finn', 'gia', 'hugo', 'iris', 'jon',
  'kate', 'liam', 'mia', 'noah', 'olga', 'pete', 'quin', 'rosa', 'sam', 'tess',
  'uma', 'vera', 'will', 'xena', 'yuri', 'zoe'];
const SURNAME = ['adler', 'brook', 'chase', 'dover', 'ellis', 'foley', 'grant', 'hayes',
  'irwin', 'joyce', 'keane', 'lowry', 'mercer', 'novak', 'oakes', 'poole',
  'quill', 'reyes', 'stone', 'tyler', 'usher', 'vance', 'wolfe', 'yates'];
const HOST_WORD = ['node', 'host', 'srv', 'app', 'web', 'db', 'edge', 'core', 'gw', 'proxy',
  'relay', 'store', 'mail', 'auth', 'log', 'ctrl'];
/* RFC 2606 reserves these for exactly this use, so a sanitised FQDN can never resolve
   to somebody's real estate. */
const SAFE_TLD = ['example.com', 'example.net', 'example.org', 'internal.example', 'test'];

// ---------------------------------------------------------------------------
// IP classification
// ---------------------------------------------------------------------------

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
/* A separate, non-global twin: `.test()` on a /g regex advances lastIndex and so
   returns a different answer on the same input next call. */
const IPV4_ONE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
/* Loose candidate match; `classifyIpv6` decides what is really an address. A run of
   colon-separated hex is also what a syslog timestamp (`09:14:02`) and a MAC address
   (`00:1b:44:11:3a:b7`) look like, and rewriting either would wreck the sample — the
   timestamp is what nearly every parser anchors on. The structural rule in
   `classifyIpv6` is what tells the three apart. */
const IPV6_RE = /(?:[0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4}(?:%[0-9a-z]+)?/gi;
/* Anchored twin, for asking whether a WHOLE value is an IPv6 address rather than scanning a
   line for one. Each quad is capped at four hex (`{0,4}`), so a 16-hex correlation id
   (`10A1DC85FE999AEC:CA305DEA:…`) does not read as an address, and any value carrying a
   non-hex character (`=`, `~`, `NORMAL`) fails outright. */
const IPV6_ONE = new RegExp(`^(?:${IPV6_RE.source})$`, 'i');

function ipv4Octets(ip: string): number[] | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map(p => Number(p));
  if (nums.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  // `01.2.3.4` and `1.2.3.4.5` are not addresses; a leading zero means somebody's
  // version string or an ID, not an octet.
  if (parts.some(p => p.length > 1 && p.startsWith('0'))) return null;
  return nums;
}

export function classifyIpv4(ip: string): IpClass | null {
  const o = ipv4Octets(ip);
  if (!o) return null;
  const [a, b] = o;
  if (a === 127) return 'loopback';
  if (a === 10) return 'private';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 169 && b === 254) return 'link-local';
  if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
  if (a >= 224 && a <= 239) return 'multicast';
  if (a === 0 || a >= 240) return 'reserved';
  // Already-documentation addresses (RFC5737) are left alone: re-mapping our own
  // output on a second pass would churn the sample for nothing.
  if (a === 192 && b === 0 && o[2] === 2) return 'reserved';
  if (a === 198 && b === 51 && o[2] === 100) return 'reserved';
  if (a === 203 && b === 0 && o[2] === 113) return 'reserved';
  return 'public';
}

export function classifyIpv6(ip: string): IpClass | null {
  const bare = ip.split('%')[0].toLowerCase();
  if (!bare.includes(':')) return null;

  /* The discriminator: a real IPv6 literal either compresses with `::` or spells out all
     eight groups. A timestamp (`09:14:02`, three groups, no `::`) and a MAC (six groups,
     no `::`) satisfy neither, which is exactly why they are safe from us. */
  const groups = bare.split(':');
  const compressed = bare.includes('::');
  if (groups.length < 3 || groups.length > 8) return null;
  if (!compressed && groups.length !== 8) return null;
  if (groups.some(g => g && !/^[0-9a-f]{1,4}$/.test(g))) return null;

  if (bare === '::1') return 'loopback';
  if (bare === '::') return 'reserved';
  if (/^fe[89ab]/.test(bare)) return 'link-local';
  if (/^f[cd]/.test(bare)) return 'private';
  if (/^ff/.test(bare)) return 'multicast';
  if (bare.startsWith('2001:db8')) return 'reserved';   // RFC3849, already documentation
  return 'public';
}

/** Which /24-equivalent the address sits in, so co-subnet hosts stay co-subnet. */
function ipv4Prefix(ip: string): string {
  const o = ipv4Octets(ip)!;
  return `${o[0]}.${o[1]}.${o[2]}`;
}

// ---------------------------------------------------------------------------
// Field-name knowledge: which keys hold identities
// ---------------------------------------------------------------------------

const FIELD_ALIASES = (datatypeFieldAliasesData as { aliases: Record<string, string> }).aliases;

/* Canonical names (post-alias) that carry each identity kind. The alias table already
   folds `hostname`/`dvchost`/`syslog_hostname` onto `host` and `suser`/`username` onto
   `user`, so this stays short and the vendor spellings come for free. */
const HOST_CANON = new Set(['host', 'fqdn', 'dest_host', 'src_host', 'dvc', 'device', 'computer']);
const USER_CANON = new Set(['user', 'src_user', 'dest_user', 'account', 'src_nt_domain', 'nt_domain']);
const IP_CANON = new Set(['src_ip', 'dest_ip', 'src_translated_ip', 'dest_translated_ip', 'ip', 'client_ip']);

/**
 * Field names that LOOK identity-bearing and are not.
 *
 * Harvesting the shipped schemas is what gives this broad vendor coverage, but a blind
 * harvest is worse than a short hand-written list: these are categories, counts and
 * classifications whose values are shared vocabulary, not identities. Replacing
 * `user_type=admin` with a random name does not protect anybody — it destroys the field
 * that tells the pipeline what kind of logon this was.
 */
const NOT_IDENTITY = [
  /_bunit$/,           // CIM business-unit tags: a grouping, not a person
  /_priority$/, /_category$/, /_count$/, /_type$/, /_class$/, /_role$/,
  /^user_agent/, /agent$/,   // a browser string, and replacing it breaks UA parsing
  /^host_?(type|os|group|role)/,
  /(is|has)_/, /_id$/, /_key$/, /_guid$/, /_uuid$/,
  /^(src|dest|source|destination)_(port|interface|zone|translated_port)$/,
  /domain_?(type|kind)$/,
  /_status$/, /_action$/, /_result$/, /_reason$/, /_severity$/, /_level$/,
];

/* Substrings that mark a schema column as holding a host, a user or an address. Applied
   to the shipped CIM / Sentinel / golden-format vocabularies below. */
const HOST_HINT = /(^|_)(host|hostname|fqdn|computer|machine|device_?name|dvchost|dvc_?host|nt_?domain|domainname)($|_)/;
const USER_HINT = /(^|_)(user|username|account|accountname|logon_?name|upn|principal|actor|owner|requester|initiator)($|_)/;
const IP_HINT = /(^|_)(ip|ipaddr|ipaddress|ip_?addr|addr|address)($|_)/;

/* Vendor field names run the role and the thing together with no separator at all —
   `clientip`, `srcaddr`, `desthost`, `remoteuser`. The boundary-anchored hints above cannot
   see inside those, and they are common enough in real schemas that missing them costs more
   than the small risk of reading a role prefix that was not one. */
const CONCAT_ROLE = '(?:c|s|d|client|clnt|src|source|dst|dest|destination|remote|local|peer|host|device|dvc|nat|xlate|orig|target|subject|actor|caller)';
const CONCAT_IP = new RegExp(`^${CONCAT_ROLE}(?:ip|ipaddr|ipaddress|addr|address)$`);
const CONCAT_HOST = new RegExp(`^${CONCAT_ROLE}(?:host|hostname|computer|machine|fqdn|devname)$`);
const CONCAT_USER = new RegExp(`^${CONCAT_ROLE}(?:user|username|account|logon|principal|upn)$`);

/**
 * One spelling for a field name.
 *
 * CamelCase, hyphens and spaces all mean the same word break — `ActorUsername`, `cs-username`
 * and `Caller Computer Name` are the same idea in three schemas' house styles, and the hint
 * patterns below are anchored on `_`, so everything has to arrive in that shape.
 */
function snakeFieldName(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[-\s.]+/g, '_')
    .toLowerCase();
}

function hintedKind(snake: string): IdentityKind | null {
  if (USER_HINT.test(snake) || CONCAT_USER.test(snake)) return 'user';
  if (HOST_HINT.test(snake) || CONCAT_HOST.test(snake)) return 'host';
  if (IP_HINT.test(snake) || CONCAT_IP.test(snake)) return 'ipv4';
  return null;
}

/** Everything the shipped schemas contribute, resolved once at module load. */
const SCHEMA_IDENTITY: Map<string, IdentityKind> = buildSchemaIdentityMap();

/**
 * Harvest identity-bearing column names out of the vocabularies already in the repo.
 *
 * The CIM data models, the Sentinel table columns and the golden-format canonical maps
 * between them name the same concepts in hundreds of vendor spellings — `ActorUsername`,
 * `DvcHostname`, `SourceUserName`, `Computer`, `suser`. Deriving from those means a field
 * spelling only has to be known in ONE place in this repo, instead of being re-listed here
 * and drifting.
 */
function buildSchemaIdentityMap(): Map<string, IdentityKind> {
  const out = new Map<string, IdentityKind>();
  const consider = (rawName: string) => {
    const name = rawName.trim();
    if (!name || name.length < 2) return;
    const snake = snakeFieldName(name);
    if (NOT_IDENTITY.some(re => re.test(snake))) return;
    const kind = hintedKind(snake);
    if (!kind) return;
    out.set(name.toLowerCase(), kind);
    out.set(snake, kind);
  };

  // SCHEMA_FIELD_NAMES is the pre-derived union of CIM object fields, Sentinel table
  // columns and golden canonicalMap dests (see gen-sanitise-vocabulary.mjs). Running each
  // through consider() is identical to the old per-file loops.
  for (const name of SCHEMA_FIELD_NAMES) consider(name);
  for (const [alias, canon] of Object.entries(FIELD_ALIASES)) {
    // The alias table is authoritative about its own canonical targets, so trust the
    // canonical side and let the alias inherit it.
    const kind: IdentityKind | null = USER_CANON.has(canon) ? 'user'
      : HOST_CANON.has(canon) ? 'host'
      : IP_CANON.has(canon) ? 'ipv4'
      : null;
    if (kind) { out.set(alias, kind); out.set(canon, kind); }
  }
  return out;
}

/** How many field spellings the shipped schemas contributed — pinned by a test. */
export const SCHEMA_IDENTITY_FIELD_COUNT = SCHEMA_IDENTITY.size;

/** Field name → the identity kind its VALUE holds, or null if it holds none. */
export function fieldIdentityKind(rawName: string): IdentityKind | null {
  const name = rawName.trim().replace(/^["']|["']$/g, '');
  // A dotted JSON path is named by its LEAF: `userIdentity.userName` is a user.
  const leaf = (name.includes('.') ? name.slice(name.lastIndexOf('.') + 1) : name).toLowerCase();
  const snake = snakeFieldName(leaf);
  if (NOT_IDENTITY.some(re => re.test(snake))) return null;

  const canon = FIELD_ALIASES[leaf] || FIELD_ALIASES[snake] || leaf;
  if (HOST_CANON.has(canon)) return 'host';
  if (USER_CANON.has(canon)) return 'user';
  if (IP_CANON.has(canon)) return 'ipv4';

  const fromSchema = SCHEMA_IDENTITY.get(leaf) || SCHEMA_IDENTITY.get(snake);
  if (fromSchema) return fromSchema;

  // Windows event XML spellings, which no schema file lists.
  if (/^(subject|target)user(_?name)?$/.test(snake)) return 'user';
  if (/^(subject|target)domain_?name$/.test(snake)) return 'host';
  return hintedKind(snake);
}

// ---------------------------------------------------------------------------
// Value patterns
// ---------------------------------------------------------------------------

const EMAIL_RE = /\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g;
const MAC_RE = /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi;
const WINUSER_RE = /\b([A-Za-z][\w-]{1,30})\\([\w.$-]{1,64})\b/g;
/* In JSON a real `DOMAIN\user` is written with a DOUBLED backslash (`DOMAIN\\user`); a
   single backslash is always a string escape. Matching the single-backslash form on a
   JSON line reads escape sequences as domain\user — `"AW:  Müller\t04.08.2026"`
   yields the bogus pair `u00fcller` \ `t04.08.2026` and, worse, rewriting a token next to
   a `\` produces an invalid escape (`\c`) that breaks the JSON. So JSON lines require the
   doubled backslash. */
const WINUSER_JSON_RE = /\b([A-Za-z][\w-]{1,30})\\\\([\w.$-]{1,64})\b/g;

/* A line is JSON only if it opens like one AND actually parses — a syslog line that merely
   contains a `{...}` blob is not, so it keeps the single-backslash (native) domain\user form. */
function lineLooksLikeJson(line: string): boolean {
  const t = line.trimStart();
  if (t[0] !== '{' && t[0] !== '[') return false;
  try { JSON.parse(line); return true; } catch { return false; }
}
/* An FQDN needs a plausible TLD, otherwise every `foo.bar` in a stack trace, file name
   or version string matches. */
const FQDN_RE = /\b(?![\d.]+\b)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.(?:com|net|org|local|internal|lan|corp|io|co|gov|edu|mil|de|nl|uk|fr|be|example|test)\b/gi;
/** The same shape, anchored, for testing one value rather than scanning a line. */
const FQDN_ONE = new RegExp(`^${FQDN_RE.source.replace(/\\b/g, '')}$`, 'i');

/* Tokens that LOOK like identities but are structure, not content. Rewriting any of
   these breaks the parse or the sourcetype detection outright. */
const NEVER = new Set([
  'localhost', 'localhost.localdomain', 'example.com', 'example.net', 'example.org',
  'unknown', 'none', 'null', 'n/a', 'na', '-', 'system', 'root', 'admin',
  'administrator', 'guest', 'nobody', 'anonymous', 'local', 'default',
]);

// ---------------------------------------------------------------------------
// Per-source precision hints, and what the shipped corpus already publishes
// ---------------------------------------------------------------------------

interface HintSource {
  match?: string[];
  identityFields?: string[];
  neverReplace?: string[];
  note?: string;
}
interface HintsFile {
  global?: {
    neverReplace?: string[];
    vocabulary?: string[];
    secretFields?: string[];
    piiFields?: string[];
    suspectFields?: string[];
    neverReplaceFields?: string[];
  };
  sources?: Record<string, HintSource>;
}
const HINTS = sanitiseHintsData as HintsFile;

/** Technical vocabulary that ends in digits and is therefore suspect-shaped but not a name. */
const TECH_VOCAB = new Set((HINTS.global?.vocabulary || []).map(s => s.toLowerCase()));
const GLOBAL_NEVER = new Set((HINTS.global?.neverReplace || []).map(s => s.toLowerCase()));

const asFieldSet = (names?: string[]) => new Set((names || []).map(s => canonField(s)));

/**
 * Field names whose VALUE is a credential whatever it looks like.
 *
 * This is the half of the problem a pattern library cannot solve. An AWS secret key is forty
 * base64 characters and a card number is fifteen digits; as patterns those are
 * `[A-Za-z0-9/+=]{40}` and a brand-prefix test, the first of which also matches every MD5 in
 * the log and the second of which misses any card whose prefix was never allocated. What
 * identifies them is the name of the field holding them. Reading named fields is already the
 * strongest thing this module does, so the rule library supplies the patterns for secrets
 * that have a shape and this supplies the names for the ones that do not.
 */
const SECRET_FIELDS = asFieldSet(HINTS.global?.secretFields);

/**
 * Field names that identify a person or the device in their pocket.
 *
 * Separate from secrets on purpose. A subscriber's handset serial is an identity, not a
 * credential: it wants the same consistent alias treatment every hostname gets, and telling
 * the reviewer to "rotate" it would be nonsense.
 */
const PII_FIELDS = asFieldSet(HINTS.global?.piiFields);

/**
 * Fields holding a customer-linkable business identifier — an order, a quote, a policy.
 *
 * These reach the review list UNTICKED. An order number is not a person, but it correlates
 * to one in whatever system issued it, and that trade-off is the reviewer's to make: they
 * may be exactly what a pipeline is meant to key on. Offering rather than deciding is the
 * same rule the shape-and-variance tier follows.
 */
const SUSPECT_FIELDS = asFieldSet(HINTS.global?.suspectFields);

/**
 * Fields holding product or device vocabulary, which must never be read as an identity.
 *
 * `SGS5`, `IP6P-64` and `ULPRE50` are phone model codes, and they are indistinguishable from
 * short hostnames to any heuristic — the suspects tier offered every one of them. Replacing
 * them protects nobody and corrupts the fields a generated pipeline extracts and is scored
 * against.
 */
const NEVER_REPLACE_FIELDS = asFieldSet(HINTS.global?.neverReplaceFields);

export interface SourceHints {
  key: string | null;
  identityFields: Set<string>;
  neverReplace: Set<string>;
  note?: string;
}

function canonKey(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

/**
 * A field name reduced to what it is called, so one spelling covers the family.
 *
 * `userIdentity.userName`, `"card_number"` and `cardNumber` all have to reach the same
 * lookup: quotes stripped, JSON path reduced to its leaf, hyphens and underscores folded
 * away. Without the last step every list below would need three spellings of every entry.
 */
function canonField(raw: string): string {
  const name = raw.trim().replace(/^["']|["']$/g, '').toLowerCase();
  const leaf = name.includes('.') ? name.slice(name.lastIndexOf('.') + 1) : name;
  return leaf.replace(/[^a-z0-9]/g, '');
}

/**
 * Hints for a sourcetype: extra identity fields, and values that must be left alone.
 *
 * The second half is the one that earns its keep. `inside` and `outside` on a Cisco ASA,
 * `root` as a Fortinet VDOM, `port1` as an interface — all read exactly like short
 * hostnames to any heuristic, and replacing them corrupts the parse and the detection
 * while protecting nobody.
 */
export function sourceHints(sourcetypeRaw?: string): SourceHints {
  const identityFields = new Set<string>();
  const neverReplace = new Set(GLOBAL_NEVER);
  if (!sourcetypeRaw?.trim()) return { key: null, identityFields, neverReplace };
  const key = canonKey(sourcetypeRaw);
  let hit: string | null = null;
  let note: string | undefined;
  for (const [name, src] of Object.entries(HINTS.sources || {})) {
    const patterns = src.match?.length ? src.match : [name];
    if (!patterns.some(p => key.includes(canonKey(p)))) continue;
    hit = name;
    note = src.note;
    for (const f of src.identityFields || []) identityFields.add(f.toLowerCase());
    for (const v of src.neverReplace || []) neverReplace.add(v.toLowerCase());
    break;
  }
  return { key: hit, identityFields, neverReplace, note };
}

/**
 * Tokens that the repo already ships in public vendor samples.
 *
 * Deliberately narrow in effect: this ONLY suppresses the unticked suspect tier, never a
 * pattern or field hit. The reasoning is asymmetric — a customer host could legitimately
 * be called `web01` or `WIN-DC01` too, so treating corpus membership as proof of
 * publicness would be a way to skip real identities. Used to quieten guesses, it cannot
 * cause a leak; used to skip certainties, it could.
 */
let publicTokenCache: Set<string> | null = null;
export function publicCorpusTokens(): Set<string> {
  if (publicTokenCache) return publicTokenCache;
  // PUBLIC_CORPUS_TOKENS is the pre-derived token set from source-samples' example logs
  // (see gen-sanitise-vocabulary.mjs) — same contents, no 635 KB static import.
  publicTokenCache = new Set(PUBLIC_CORPUS_TOKENS);
  return publicTokenCache;
}

/** Version strings are the classic IPv4 false positive: `10.1.2.3` is both. */
const VERSION_CONTEXT = /\b(?:version|ver|v|release|build|rev|sdk|agent|schema)\b\W{0,3}$/i;

/* RFC2606/RFC6761 reserved names — where our own FQDN aliases land. Skipping them makes
   a second pass over an already-sanitised sample leave the hostnames alone instead of
   re-rolling them. (Bare usernames cannot be recognised this way, so the caller still
   tracks whether a sample has been sanitised rather than relying on detection.) */
const RESERVED_DOMAIN = /(?:^|\.)(?:example\.(?:com|net|org)|example|test|invalid|localdomain)$/i;

// ---------------------------------------------------------------------------
// Alias generation
// ---------------------------------------------------------------------------

/**
 * Mint aliases that keep the shape of the original and collide with nothing.
 *
 * "Do not use the names which are in the files" is a hard requirement, so every
 * candidate is checked against the set of every token in the sample — not just the
 * values being replaced — and re-rolled on a hit. Without that check a generated
 * `web01` could land on a real `web01` elsewhere in the sample and quietly merge two
 * different machines into one.
 */
class AliasMinter {
  private used = new Set<string>();
  private prefixMap = new Map<string, string>();
  private domainMap = new Map<string, string[]>();
  private rand: () => number;
  private taken: Set<string>;

  constructor(taken: Set<string>, seed: number) {
    this.taken = taken;
    this.rand = rng(seed);
  }

  private pick<T>(list: T[]): T { return list[Math.floor(this.rand() * list.length)]; }
  private int(n: number): number { return Math.floor(this.rand() * n); }

  private fresh(make: () => string, max = 200): string {
    for (let i = 0; i < max; i++) {
      const c = make();
      const key = c.toLowerCase();
      if (!this.used.has(key) && !this.taken.has(key)) { this.used.add(key); return c; }
    }
    // Exhausted the vocabulary for this shape — fall back to a counter, still unique.
    let n = 1;
    for (;;) {
      const c = `${make()}-${n++}`;
      const key = c.toLowerCase();
      if (!this.used.has(key) && !this.taken.has(key)) { this.used.add(key); return c; }
    }
  }

  /** Same class in, same class out; co-subnet addresses stay co-subnet. */
  ipv4(original: string, cls: IpClass): string {
    const o = ipv4Octets(original)!;
    const host = () => 1 + this.int(253);
    if (cls === 'public') {
      // RFC5737 documentation space. Three /24s is 762 addresses; a sample with more
      // distinct public IPs than that gets the counter fallback via `fresh`.
      const nets = ['192.0.2', '198.51.100', '203.0.113'];
      const srcPrefix = ipv4Prefix(original);
      let net = this.prefixMap.get(srcPrefix);
      if (!net) { net = this.pick(nets); this.prefixMap.set(srcPrefix, net); }
      return this.fresh(() => `${net}.${host()}`);
    }
    if (cls === 'private') {
      // Keep the block that identifies it as private, randomise inside it. The original
      // /24 maps to one new /24 so subnet-based pipeline logic still sees neighbours.
      const srcPrefix = ipv4Prefix(original);
      let prefix = this.prefixMap.get(srcPrefix);
      if (!prefix) {
        if (o[0] === 10) prefix = `10.${this.int(256)}.${this.int(256)}`;
        else if (o[0] === 172) prefix = `172.${16 + this.int(16)}.${this.int(256)}`;
        else prefix = `192.168.${this.int(256)}`;
        this.prefixMap.set(srcPrefix, prefix);
      }
      return this.fresh(() => `${prefix}.${host()}`);
    }
    if (cls === 'cgnat') return this.fresh(() => `100.${64 + this.int(64)}.${this.int(256)}.${host()}`);
    if (cls === 'link-local') return this.fresh(() => `169.254.${this.int(256)}.${host()}`);
    // Loopback, multicast and reserved carry protocol meaning, not identity.
    return original;
  }

  ipv6(original: string, cls: IpClass): string {
    const quad = () => this.int(0x10000).toString(16);
    if (cls === 'public') return this.fresh(() => `2001:db8:${quad()}:${quad()}::${quad()}`);
    if (cls === 'private') return this.fresh(() => `fd00:${quad()}:${quad()}::${quad()}`);
    if (cls === 'link-local') return this.fresh(() => `fe80::${quad()}:${quad()}`);
    return original;
  }

  /**
   * `web01.corp.local` → `node14.internal.example`, same label count.
   *
   * The domain SUFFIX is mapped consistently, so every host that shared `acme.local`
   * still shares one domain afterwards. Rolling it per host would scatter one estate
   * across several fake domains — visibly wrong to a reviewer, and wrong to any pipeline
   * that extracts a domain and groups by it.
   */
  fqdn(original: string): string {
    const labels = original.split('.');
    const depth = labels.length;
    const host = this.hostLabel(labels[0]);
    if (depth <= 1) return host;

    const srcDomain = labels.slice(1).join('.').toLowerCase();
    let domainLabels = this.domainMap.get(srcDomain);
    if (!domainLabels) {
      const base = this.pick(SAFE_TLD).split('.');
      // Pad the middle so the label count matches: parsers split on dots.
      const filler: string[] = [];
      for (let i = 0; i < depth - 1 - base.length; i++) filler.push(this.pick(HOST_WORD));
      domainLabels = [...filler, ...base].slice(0, Math.max(depth - 1, 1));
      this.domainMap.set(srcDomain, domainLabels);
    }
    return [host, ...domainLabels].join('.');
  }

  private hostLabel(sample: string): string {
    const digits = (sample.match(/\d+$/) || [''])[0].length;
    const upper = sample === sample.toUpperCase() && /[A-Z]/.test(sample);
    const make = () => {
      const word = this.pick(HOST_WORD);
      const n = digits ? String(1 + this.int(digits >= 2 ? 98 : 9)).padStart(digits, '0') : '';
      return upper ? (word + n).toUpperCase() : word + n;
    };
    return this.fresh(make);
  }

  host(original: string): string {
    return original.includes('.') ? this.fqdn(original) : this.hostLabel(original);
  }

  /** Mirror the original's construction: dotted, first-initial, or opaque account. */
  user(original: string): string {
    const g = () => this.pick(GIVEN);
    const s = () => this.pick(SURNAME);
    const upper = original === original.toUpperCase() && /[A-Z]/.test(original);
    const cap = /^[A-Z][a-z]/.test(original);
    const wrap = (v: string) => upper ? v.toUpperCase() : cap ? v[0].toUpperCase() + v.slice(1) : v;

    // A display name carrying internal whitespace — "John Smith", "SMITH, John". The default
    // path below collapses it to a single spaceless token, which drops a space and changes the
    // line's whitespace count; the wire-format check then reads that as a shifted parser and
    // blocks the save. Mint each alphabetic word from the name pools and keep every separator —
    // space, comma — exactly where it was, so the wire format is preserved verbatim.
    if (/\s/.test(original)) {
      let n = 0;
      return this.fresh(() => original.replace(/[A-Za-z]+/g, w => {
        const repl = n++ % 2 === 0 ? this.pick(GIVEN) : this.pick(SURNAME);
        return w === w.toUpperCase() && /[A-Z]/.test(w) ? repl.toUpperCase()
          : /^[A-Z]/.test(w) ? repl[0].toUpperCase() + repl.slice(1).toLowerCase()
          : repl.toLowerCase();
      }));
    }
    if (/^[a-z]+\.[a-z]+$/i.test(original)) return this.fresh(() => wrap(`${g()}.${s()}`));
    if (/^[a-z]+_[a-z]+$/i.test(original)) return this.fresh(() => wrap(`${g()}_${s()}`));
    if (original.endsWith('$')) return this.fresh(() => `${this.hostLabel(original)}$`);  // machine account
    if (/^svc[-_]/i.test(original)) return this.fresh(() => `svc-${this.pick(HOST_WORD)}${this.int(90) + 10}`);
    if (/^\d+$/.test(original)) return this.fresh(() => String(this.int(9e6) + 1e6));      // numeric uid
    // Default: first initial + surname, trimmed to the original's length so a parser
    // with a fixed-width or bounded expectation still matches.
    return this.fresh(() => {
      const v = wrap(`${g()[0]}${s()}`);
      return original.length >= 4 && v.length > original.length ? v.slice(0, original.length) : v;
    });
  }

  email(original: string): string {
    const [local, domain] = original.split('@');
    const user = this.user(local);
    const dom = domain && NEVER.has(domain.toLowerCase()) ? domain : this.pick(SAFE_TLD);
    return `${user}@${dom}`;
  }

  mac(): string {
    const oct = () => this.int(256).toString(16).padStart(2, '0');
    // 02: locally administered, so it can never be a real vendor's OUI.
    return this.fresh(() => `02:${oct()}:${oct()}:${oct()}:${oct()}:${oct()}`);
  }

  /**
   * A literal the reviewer picked out by hand, aliased by its SHAPE.
   *
   * Someone selecting `acme-corp.com` in the sample means the hostname, so it has to come
   * back as a hostname — an opaque `edge450` there would break any parser that splits it
   * on dots. Falling through to a plain token is only for things with no shape to keep.
   */
  custom(original: string): string {
    if (original.includes('@') && /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(original)) return this.email(original);
    const cls = classifyIpv4(original);
    if (cls && cls !== 'reserved') return this.ipv4(original, cls);
    if (/^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+$/i.test(original)) return this.fqdn(original);
    /* Nothing with a shape to keep (a hostname, an email, an address) — so preserve it
       positionally instead: each letter comes back a letter, each digit a digit, and every
       separator stays put. A `${word}${digits}` stand-in used to append digits to a value
       that had none (and letters where there were digits), which broke both the character
       classes a parser matches and the reviewer's ability to trust the before/after. */
    return this.pii(original);
  }

  /**
   * A secret, scrambled character by character rather than blanked.
   *
   * A blunt redactor replaces what it finds with `REDACTED`, which is right for a
   * destination but wrong here: this sample is about to be *scored* against a pipeline, and collapsing
   * a 180-character JWT to a single word changes the line's length band, its delimiter
   * count and often whether the parser still matches at all. Replacing each character with
   * a random one of the same class destroys the secret just as completely — nothing of the
   * original survives, and the substitution is not reversible — while leaving every
   * structural property the parser reads: length, separators, and where the digits were.
   *
   * Deliberately NOT `fresh()`-checked for collisions. A secret is not an identity; there
   * is no cross-line consistency to maintain, and two secrets scrambling to the same value
   * would mean nothing to anyone.
   */
  secret(original: string): string {
    /* Substituting inside the value's own alphabet, not just its character classes. A
       handset serial is fourteen hex digits and a pipeline extracting it will be matched
       against `[0-9A-F]{14}`, so turning `3852D7E1E168F3` into `5295S2G4J577Q9` preserves
       the length and the case and still fails the extraction — which is the exact breakage
       this whole approach exists to avoid. Hex is the case worth special-casing: serials,
       MEIDs, hashes and object ids are all hex, and they are common in the fields that reach
       this minter. */
    const hex = /^[0-9A-Fa-f]+$/.test(original) && /[A-Fa-f]/.test(original);
    const LOWER = hex ? 'abcdef' : 'abcdefghijkmnopqrstuvwxyz';
    const UPPER = hex ? 'ABCDEF' : 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    let out = '';
    for (const ch of original) {
      if (ch >= '0' && ch <= '9') out += String(this.int(10));
      else if (ch >= 'a' && ch <= 'z') out += LOWER[this.int(LOWER.length)];
      else if (ch >= 'A' && ch <= 'Z') out += UPPER[this.int(UPPER.length)];
      else out += ch;   // separators, padding, the `://` in a URI: all structure, all kept
    }
    // A value made only of separators would come back identical and read as "unchanged".
    return out === original ? `${out}x` : out;
  }

  /**
   * A personal or device identifier — a handset serial, a subscriber number, a postcode.
   *
   * Same character-class substitution as a secret, and for the same reason: an ESN is
   * fourteen hex digits, an MDN is ten decimal ones, and a pipeline extracting either will
   * be regex-matched against whatever we put back. What differs is meaning rather than
   * mechanism, so this is minted through `fresh()` — unlike a secret, this IS an identity,
   * and two different handsets colliding on one alias would merge two subscribers.
   */
  pii(original: string): string {
    return this.fresh(() => this.secret(original), 50);
  }
}

// ---------------------------------------------------------------------------
// Secrets — the public-source secret / sensitive-data rules library
// ---------------------------------------------------------------------------

/*
 * The identity tiers above answer "whose estate is this": hosts, users, IPs, domains. They
 * have never answered "is there a live credential in here", and a real uploaded log often
 * carries one — a bearer token in an API gateway line, an AWS key pair in a CI audit event,
 * a database URI with the password still in it. Shipping a hostname to a model vendor is a
 * privacy problem; shipping a working key is a security incident.
 *
 * The vocabulary comes from a public-source rule library (`config/bundled-secret-rules.json`
 * — gitleaks + Presidio + vendor-published token shapes), installed by `secret-rules.ts` and
 * handed to `setSecretRules` below. The two-part design (a pattern plus context keywords) is
 * followed here, because a pattern alone is not enough: `\b4\d{15}\b` is a Visa number beside
 * the word "card" and an order id everywhere else. The library is filtered before it gets
 * here — rules whose regex is nothing but a character class and a length are dropped; see
 * `secret-rule-filter.ts` for why those cannot be made safe for a sanitiser that has to keep
 * the sample parseable.
 *
 * THIS MODULE HAS NO WAY TO REACH THE NETWORK, and that is deliberate: the rules are PUSHED
 * IN, never pulled. A sanitiser that could fetch could also post, and this module holds
 * unsanitised customer data. The installer lives in a separate module for exactly that
 * reason — `tests/secret-detection-test.mjs` asserts nothing here can make a request.
 *
 * When no rules have been supplied, the named-field pass below still runs, so `password=`
 * and `api_key=` are still caught. Only PATTERN-based detection is lost, and the UI says so
 * rather than implying a clean sample.
 */

/** Anchor terms are looked for in the text immediately before a match, not merely somewhere
 *  on the line. A line containing `authorization=` would otherwise vouch for every value on
 *  it, which is how `method=POST` and `status=200` get reported as credentials. */
const ANCHOR_WINDOW = 40;

/**
 * Auth schemes that stay put when the credential after them is scrambled.
 *
 * `Authorization: Basic YWRtaW4…` — the word `Basic` is not the secret, it is what tells a
 * parser (and a reader) which scheme is in use, and several pipelines branch on it. Only
 * what follows it is redacted.
 */
const AUTH_SCHEME = /^(Basic|Bearer|Digest|Negotiate|NTLM|AWS4-HMAC-SHA256|Token|ApiKey)\s+/i;

/** Below this a "secret" is a coincidence. The shortest thing the kept rules describe
 *  is a 9-digit routing number. */
const MIN_SECRET_LEN = 8;

let secretRuleSource: SecretRule[] = [];
let compiledSecretRules: { rule: SecretRule; re: RegExp }[] | null = null;

/**
 * Supply the rules detection should use. Called once per session, after the library has
 * been filtered (`ensureSecretRules` in `secret-rules.ts`).
 *
 * Replaces rather than merges, and drops the compiled cache: a second call with a different
 * library must not leave the previous set of patterns live.
 */
export function setSecretRules(rules: SecretRule[]): void {
  secretRuleSource = (rules || []).slice();
  compiledSecretRules = null;
}

/** How many rules detection currently has. 0 means pattern detection is not available. */
export function secretRuleCount(): number {
  return secretRuleSource.length;
}

/**
 * Compiled on first use, not when the rules arrive.
 *
 * This module is on the app's startup path, and building ~130 regexes to sit unused until
 * somebody uploads a sample is exactly the kind of eager work that made the app slow to
 * start. Compilation itself is in `secret-rule-filter.ts`, shared with the audit.
 */
function secretRules(): { rule: SecretRule; re: RegExp }[] {
  if (compiledSecretRules) return compiledSecretRules;
  compiledSecretRules = compileSecretRules(secretRuleSource);
  return compiledSecretRules;
}

export interface SecretHit {
  value: string;
  /** Where it came from — a secret rule id, or the field name that gave it away. */
  via: string;
}

/**
 * Never let a match swallow the field name in front of the value.
 *
 * A rule broad enough to match `key=value` whole would otherwise have its key scrambled
 * along with its secret, turning `authorization=…` into `tdspyv=…` — and a field name is
 * structure, the very thing every parser keys on. The sync script drops the rules known to
 * do this, but the guarantee belongs here too: this module cannot know what a future
 * upstream rule will look like, and one bad import must not be able to corrupt a sample.
 *
 * Only a leading `name=` or `name:` is trimmed. A `:` inside a connection URI is left
 * alone, because `postgres://user:pass@host` has to be redacted whole.
 */
function trimToValue(match: string): string {
  if (match.includes('://')) return match;
  const m = match.match(/^([A-Za-z][\w.-]*)\s*[=:]\s*(.+)$/s);
  return m ? m[2] : match;
}

/**
 * From a connection URI, the password and nothing else.
 *
 * A URI rule matches `postgresql://svc_billing:Pa55w0rd!@db-prod-01.internal:5432/billing`
 * whole, and redacting it whole is what a Destination wants. Here it is the wrong unit of
 * work three times over: it scrambles the scheme a pipeline may branch on, it scrambles the
 * account name and the hostname that the identity tiers replace far better, and — worst —
 * it gives that host a one-off alias unrelated to the one it gets on every other line,
 * so a pipeline grouping by host would see two different machines.
 *
 * Narrowing to the password leaves everything else to the tier that owns it, which is the
 * whole principle this module runs on: replace each thing with the right kind of thing.
 */
function credentialInUri(match: string): string | null {
  const m = match.match(/^[A-Za-z][\w+.-]*:\/\/[^:/\s"']+:([^@/\s"']+)@/);
  return m ? m[1] : null;
}

/**
 * Find secrets line by line, gating on each rule's own context keywords.
 *
 * `literal`-precision rules carry their own evidence — data either contains `AKIA` or
 * `-----BEGIN PRIVATE KEY-----` or it does not — so they fire unaided. `structural` and
 * `numeric` rules describe a shape that innocent data shares, so they need a keyword
 * nearby. A hit with no keyword is dropped rather than offered as a suspect: an unticked
 * row reading "this 16-digit order id may be a credit card" teaches the reviewer to ignore
 * the list, and the identity tiers already rely on that list being worth reading.
 */
export function findSecrets(text: string): SecretHit[] {
  const hits = new Map<string, string>();   // value -> what first claimed it
  const rules = secretRules();
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    const lower = line.toLowerCase();
    for (const { rule, re } of rules) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }   // guard against a zero-width loop
        const matched = trimToValue(m[0]);
        if (!matched) continue;
        if (rule.precision !== 'literal') {
          const from = Math.max(0, m.index - ANCHOR_WINDOW);
          const before = lower.slice(from, m.index);
          if (!rule.anchors.some(a => before.includes(a.toLowerCase()))) continue;
        }
        /* A URI's password is the secret; its scheme, account and host are not. A password
           is also the one secret allowed to be short — people choose short ones. */
        const embedded = credentialInUri(matched);
        const value = embedded ?? matched;
        if (!embedded && value.trim().length < MIN_SECRET_LEN) continue;
        if (!hits.has(value)) hits.set(value, `secret rule “${rule.id}”`);
      }
    }

    /* Named-field pass: a value in `password=` or `aws_secret_access_key=` is a credential
       regardless of shape, and no pattern safe enough to import could have found it. */
    for (const { name, value } of fieldPairs(line)) {
      if (!SECRET_FIELDS.has(canonField(name))) continue;
      const raw = value.trim().replace(/^["']|["']$/g, '');
      const scheme = raw.match(AUTH_SCHEME);
      const secret = scheme ? raw.slice(scheme[0].length) : raw;
      if (secret.length < MIN_SECRET_LEN) continue;
      if (!hits.has(secret)) hits.set(secret, `field “${name.trim().replace(/^["']|["']$/g, '')}”`);
    }
  }
  /* Longest first so a whole connection URI is offered rather than the password inside it:
     redacting the part would leave the host and the account name in place. */
  return [...hits.entries()]
    .sort((a, b) => b[0].length - a[0].length)
    .map(([value, via]) => ({ value, via }));
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/**
 * Every `key=value` and `"key": value` pair on a line.
 *
 * `:` is only honoured after a QUOTED key, i.e. JSON. Accepting a bare `key: value` looks
 * like it would catch more, but in free-text syslog it catches the wrong things and then
 * cascades: in `…Successful : server = 10.0.0.9 : user = jsmith` it pairs
 * `Successful:server`, consumes the text through `server`, and by the time the scan
 * reaches `user = jsmith` the key is already behind it — so the actual username is never
 * seen. Colon-delimited values that matter (`outside:10.20.30.40`) are addresses, and
 * those are found by pattern anyway.
 */
function* fieldPairs(line: string): Generator<{ name: string; value: string; index: number }> {
  const kv = /(?:"([\w.$-]+)"\s*:|\b([\w.$-]+)\s*=)\s*(?:"([^"]*)"|'([^']*)'|([^\s,;"'}\]]+))/g;
  let m: RegExpExecArray | null;
  while ((m = kv.exec(line))) {
    const name = m[1] ?? m[2] ?? '';
    const value = m[3] ?? m[4] ?? m[5] ?? '';
    if (!name || !value) continue;
    yield { name, value, index: m.index + m[0].lastIndexOf(value) };
  }
}

/** Every word-ish token, for the "alias must not collide with the sample" check. */
function allTokens(text: string): Set<string> {
  const out = new Set<string>();
  for (const t of text.toLowerCase().match(/[a-z0-9][\w.$-]*/g) || []) out.add(t);
  return out;
}

function looksLikeVersion(line: string, index: number): boolean {
  return VERSION_CONTEXT.test(line.slice(Math.max(0, index - 24), index));
}

/* A name with a digit suffix — `web01`, `fw-edge-02`, `acme-core-01`, `SRV12`. Two leading
   letters minimum, which is what keeps hex fragments and `T09` out of a timestamp. */
const SUSPECT_HOSTISH = /^[a-z]{2,}[a-z0-9]*(?:[-_][a-z0-9]+)*[-_]?\d{1,4}$/i;
/* A dotted personal name — `j.smith`, `maria.lopez`. Very common as an account name and
   invisible to the FQDN pattern, which insists on a real TLD. */
const SUSPECT_DOTTED = /^[a-z]{1,20}\.[a-z]{2,20}$/i;
const ALL_HEX = /^[0-9a-f]+$/i;

/**
 * Tell a hostname from a vendor message code.
 *
 * `%ASA-6-302013` and `fw-edge-01` are the same shape to any simple pattern, and getting
 * this wrong is expensive in both directions: rewriting a message id breaks the parser that
 * keys off it, and skipping a hostname leaks the device. The segments settle it — a name
 * reads `word-word-NN`, whereas a message code carries a bare numeric segment in the middle
 * and a long serial at the end.
 */
function hostishSegments(token: string): boolean {
  const segs = token.split(/[-_]/);
  if (segs.length === 1) return true;
  for (let i = 0; i < segs.length - 1; i++) if (/^\d+$/.test(segs[i])) return false;
  const last = segs[segs.length - 1];
  return !(/^\d+$/.test(last) && last.length > 4);
}
/* Second labels that make a dotted token a filename, not a person. */
const FILE_EXT = new Set([
  'log', 'txt', 'py', 'js', 'ts', 'jsx', 'tsx', 'json', 'xml', 'yml', 'yaml', 'html', 'htm',
  'css', 'exe', 'dll', 'so', 'sh', 'bat', 'ps1', 'conf', 'cfg', 'ini', 'csv', 'tsv', 'gz',
  'zip', 'tar', 'jar', 'war', 'md', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'bin', 'dat',
  'tmp', 'bak', 'old', 'sys', 'db', 'sql', 'class', 'jsp', 'php', 'rb', 'go', 'rs', 'cpp',
  'java', 'sock', 'pid', 'key', 'pem', 'crt', 'cer', 'msi', 'iso', 'img', 'lock', 'swp',
]);

// ---------------------------------------------------------------------------
// Structure the format gives away for free
// ---------------------------------------------------------------------------

/* RFC3164 and RFC5424 both put the host in a fixed place: after the timestamp, before the
   program name. That makes the single most common identity in real samples — the device
   that emitted the line — a matter of position rather than guesswork. */
const SYSLOG_HEADER = new RegExp(
  '^(?:<\\d{1,3}>)?(?:\\d\\s+)?'                                    // optional PRI, optional version
  + '(?:[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{1,2}:\\d{2}:\\d{2}'        // Nov 12 09:14:02
  + '|\\d{4}-\\d{2}-\\d{2}[T ][\\d:.]+(?:Z|[+-]\\d{2}:?\\d{2})?)'   // 2024-11-12T09:14:02Z
  + '\\s+([A-Za-z][\\w.-]{1,62})\\s+\\S',
);

/** The `#Fields:` directive of a W3C extended log, which names every column. */
const W3C_FIELDS = /^#Fields:\s*(.+)$/i;

/**
 * Field maps the FORMAT hands over, for samples no parser matched.
 *
 * Three structures carry their own column names and cost nothing to read: the syslog
 * header, a CSV/TSV header row, and a W3C `#Fields:` directive. Between them they cover a
 * large share of what people actually upload, and unlike the shape heuristics these are
 * positional facts — a value in the syslog host slot IS the host, so it is offered ticked
 * rather than as a maybe.
 */
export function structuralFields(lines: string[]): ParsedLine[] {
  const out: ParsedLine[] = lines.map(() => null);
  const put = (i: number, name: string, value: string) => {
    if (!value) return;
    out[i] = { ...(out[i] || {}), [name]: value };
  };

  lines.forEach((line, i) => {
    const m = SYSLOG_HEADER.exec(line);
    if (m?.[1]) put(i, 'host', m[1]);
  });

  // Column names, from a W3C directive or a plain header row.
  let columns: string[] | null = null;
  let delim = ',';
  let startAt = 0;
  for (let i = 0; i < lines.length && i < 20; i++) {
    const w3c = W3C_FIELDS.exec(lines[i].trim());
    if (w3c) {
      columns = w3c[1].trim().split(/\s+/);
      delim = ' ';
      startAt = i + 1;
      break;
    }
  }
  if (!columns) {
    const firstIdx = lines.findIndex(l => l.trim());
    const first = firstIdx >= 0 ? lines[firstIdx].trim() : '';
    for (const d of [',', '\t', ';', '|']) {
      const cells = first.split(d);
      if (cells.length < 3) continue;
      /* A header row is all names: no empty cells, nothing numeric, nothing that looks
         like a timestamp. Requiring at least one recognisable identity column keeps this
         from firing on data that merely happens to be comma-separated — and it also means
         the pass only runs when it would actually find something. */
      const namey = cells.every(c => /^"?[A-Za-z][\w. -]{0,40}"?$/.test(c.trim()));
      if (!namey) continue;
      const names = cells.map(c => c.trim().replace(/^"|"$/g, ''));
      if (!names.some(n => fieldIdentityKind(n))) continue;
      columns = names;
      delim = d;
      startAt = firstIdx + 1;
      break;
    }
  }

  if (columns) {
    for (let i = startAt; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim() || line.trimStart().startsWith('#')) continue;
      const cells = splitDelimited(line, delim);
      // A row with the wrong column count was not read by this header; guessing would
      // shift every value one column to the left, which is worse than reading nothing.
      if (cells.length !== columns.length) continue;
      columns.forEach((name, c) => {
        const v = cells[c]?.trim().replace(/^"|"$/g, '');
        if (v && v !== '-') put(i, name, v);
      });
    }
  }

  return out;
}

/** Split on a delimiter, honouring double quotes. */
function splitDelimited(line: string, delim: string): string[] {
  if (delim === ' ') return line.trim().split(/\s+/);
  const out: string[] = [];
  let cur = '', inQ = false;
  for (const ch of line) {
    if (inQ) { if (ch === '"') inQ = false; else cur += ch; continue; }
    if (ch === '"') { inQ = true; continue; }
    if (ch === delim) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur);
  return out;
}

interface Suspect { value: string; kind: IdentityKind; via: string; count: number }

/**
 * The last resort: tokens that look like names and behave like names.
 *
 * For a custom source with no parser and no `key=value`, a bare hostname is genuinely
 * undecidable — so instead of deciding, this offers. Two signals combine: SHAPE (a
 * digit-suffixed name or a dotted personal name) and VARIANCE (a token in most lines is
 * product or protocol vocabulary, whereas an identity appears in some lines and not
 * others). Everything found here ships unticked, because the cost of a wrong guess is a
 * silently corrupted sample and a pack built against fiction.
 */
function findSuspects(
  lines: string[],
  found: Map<string, SanitiseEntry>,
  isNever: (v: string) => boolean,
): Suspect[] {
  const bodyLines = lines.filter(l => l.trim());
  if (bodyLines.length < 2) return [];
  const publicTokens = publicCorpusTokens();

  const docFreq = new Map<string, number>();
  const total = new Map<string, number>();
  const casing = new Map<string, string>();
  for (const line of bodyLines) {
    const seen = new Set<string>();
    for (const t of line.match(/[A-Za-z][\w.-]{1,39}/g) || []) {
      const lower = t.toLowerCase();
      if (!casing.has(lower)) casing.set(lower, t);
      total.set(lower, (total.get(lower) || 0) + 1);
      if (!seen.has(lower)) { seen.add(lower); docFreq.set(lower, (docFreq.get(lower) || 0) + 1); }
    }
  }

  const out: Suspect[] = [];
  /* Variance only means something once there are enough events to vary across. In a
     four-line sample nearly every token is "constant", so applying the filter there would
     reject the whole sample rather than narrow it. */
  const varianceTells = bodyLines.length >= 6;
  for (const [lower, df] of docFreq) {
    // In three quarters of the lines or more: that is the format talking, not a name.
    if (varianceTells && df / bodyLines.length >= 0.75) continue;
    if (isNever(lower) || TECH_VOCAB.has(lower) || publicTokens.has(lower)) continue;
    const value = casing.get(lower)!;
    if (found.has(value) || found.has(lower)) continue;

    let kind: IdentityKind | null = null;
    let via = '';
    if (!lower.includes('.') && SUSPECT_HOSTISH.test(lower) && hostishSegments(lower)
        && !(ALL_HEX.test(lower) && lower.length >= 8)) {
      kind = 'host';
      via = 'looks like a name (digit suffix, varies between events)';
    } else if (SUSPECT_DOTTED.test(lower) && !FILE_EXT.has(lower.slice(lower.indexOf('.') + 1))) {
      kind = 'user';
      via = 'looks like a personal name (varies between events)';
    }
    if (!kind) continue;
    out.push({ value, kind, via, count: total.get(lower)! });
  }

  /* Frequent first, and capped: a list of a hundred maybes is not a review, it is a wall
     the reviewer will click past. */
  return out.sort((a, b) => b.count - a.count || a.value.localeCompare(b.value)).slice(0, 25);
}

/**
 * Decide what to replace. Nothing is changed here — the caller shows this to the
 * reviewer first.
 *
 * Pattern detection runs text-wide for the kinds that are unambiguous on their own
 * (IPs, emails, `DOMAIN\user`, MACs, FQDNs). Bare hostnames and bare usernames are NOT
 * recognisable as tokens — `jsmith` is indistinguishable from any other word — so those
 * are only picked up from a field whose NAME says what it holds. Anything outside both
 * nets (a customer name, a project code) needs `extraLiterals`; that gap is real and
 * the UI has to say so.
 */
export function planSanitisation(text: string, opts: SanitiseOptions = {}): SanitisePlan {
  const seed = opts.seed ?? randomSeed();
  const lines = text.split('\n');
  const taken = allTokens(text);
  const minter = new AliasMinter(taken, seed);
  const warnings: string[] = [];

  const hints = sourceHints(opts.sourcetype);
  const tally = { parser: 0, field: 0, pattern: 0, suspect: 0, secret: 0 };

  /**
   * Everything sitting in a product- or device-vocabulary field, gathered up front.
   *
   * The field-aware pass can skip these by name, but the suspects tier works on bare tokens
   * and cannot see which field a word came from — which is how `SGS5`, `IP6P-64` and
   * `ULPRE50` were all offered as probable hostnames. Collecting the values once and
   * treating them as never-replace closes that off wherever they appear in the line.
   */
  /** Business-identifier field name → the distinct values seen, for the closing warning. */
  const businessIdFields: Record<string, Set<string>> = {};

  const vocabularyValues = new Set<string>();
  for (const line of lines) {
    if (!line.trim()) continue;
    for (const { name, value } of fieldPairs(line)) {
      if (!NEVER_REPLACE_FIELDS.has(canonField(name))) continue;
      const v = value.trim().replace(/^["']|["']$/g, '');
      if (v && v !== 'NA') vocabularyValues.add(v.toLowerCase());
    }
  }

  /** Structural or vocabulary values that must survive untouched. */
  const isNever = (v: string) => {
    const lower = v.toLowerCase();
    return NEVER.has(lower) || hints.neverReplace.has(lower) || vocabularyValues.has(lower);
  };

  /**
   * The same, minus the vocabulary — what still holds when the reviewer picked the field.
   *
   * `NA` and `null` survive a field pick, because replacing a placeholder changes how the
   * sample parses and nobody means that by "sanitise this field". Vocabulary values are
   * deliberately not consulted: that list is a default about field NAMES, and an explicit
   * pick is the reviewer overruling exactly such a default. Letting it win here would make
   * the pick quietly do nothing, which is the worst of the available outcomes.
   */
  const isStructural = (v: string) => {
    const lower = v.toLowerCase();
    return NEVER.has(lower) || hints.neverReplace.has(lower);
  };

  const pickedFields = new Set((opts.extraFields || []).map(f => canonField(f)).filter(Boolean));
  const pickedSeen = new Set<string>();

  // original → entry, so a value seen twenty times gets one alias and a count of 20.
  const found = new Map<string, SanitiseEntry>();
  // Dotted-quad literals seen in version context, and seen as a genuine address.
  const versionSeen = new Set<string>();
  const addressSeen = new Set<string>();
  const add = (
    original: string,
    kind: IdentityKind,
    via: string,
    ipClass?: IpClass,
    confidence: 'certain' | 'suspect' = 'certain',
  ) => {
    const existing = found.get(original);
    if (existing) {
      existing.count++;
      // A value first guessed and then confirmed by a named field is no longer a guess.
      if (confidence === 'certain' && existing.confidence === 'suspect') {
        existing.confidence = 'certain';
        existing.enabled = true;
        existing.via = via;
        existing.kind = kind;
      }
      return;
    }
    found.set(original, {
      original, alias: '', kind, count: 1, ipClass, via,
      enabled: confidence === 'certain',
      confidence,
    });
  };

  /**
   * Read identities off the named fields of a real parser.
   *
   * This is the pass that reaches what nothing else can. `10.1.2.3 - jsmith [12/Nov/2024]`
   * gives up its address to a pattern, but `jsmith` is a word between an IP and a bracket
   * and no regex can know better; the Apache parser calls it `user` and settles it. Same
   * for column three of a CSV, a CEF header position, and a Windows `<Data Name=…>`.
   */
  const readParsedLine = (fields: Record<string, string>, line: string) => {
    for (const [name, rawValue] of Object.entries(fields)) {
      const value = rawValue.trim().replace(/^"(.*)"$/, '$1').trim();
      if (!value || value.length > 120 || isNever(value)) continue;
      const hinted = hints.identityFields.has(name.toLowerCase());
      const kind = fieldIdentityKind(name) || (hinted ? 'custom' : null);
      if (!kind) continue;
      /* Already settled by a text-wide pattern, and better handled there: an address in
         `src_ip`, a UPN in `user`, a `DOMAIN\account`, an FQDN in `host`. Handing an FQDN
         to the host minter would collapse `web01.corp.local` to a single label and break
         every parser that splits it on dots. */
      if (IPV4_ONE.test(value) || value.includes('@') || value.includes('\\')) continue;
      if (value.includes('.') && FQDN_ONE.test(value)) continue;
      if (kind === 'ipv4' || kind === 'ipv6') continue;   // an address field without an address
      /* Purely numeric values are ports, counters and record ids — except where a hint
         says this exact field is an identity, which is how an AWS account id or a numeric
         UID gets replaced instead of dismissed. */
      if (/^[\d.]+$/.test(value) && !hinted) continue;
      if (looksLikeVersion(line, Math.max(0, line.indexOf(value)))) continue;
      const before = found.size;
      add(value, kind, `parsed field “${name}”`);
      if (found.size > before) tally.parser++;
    }
  };

  const patternAdd = (original: string, kind: IdentityKind, via: string, ipClass?: IpClass) => {
    const before = found.size;
    add(original, kind, via, ipClass);
    if (found.size > before) tally.pattern++;
  };

  /* The parser's own fields win where it read a line; the structural pass fills in what it
     did not, and covers samples no parser matched at all. */
  const structural = structuralFields(lines);
  lines.forEach((line, i) => {
    if (!line.trim()) return;
    const fromParser = opts.parsed?.[i];
    const merged = fromParser || structural[i]
      ? { ...(structural[i] || {}), ...(fromParser || {}) }
      : null;
    if (merged) readParsedLine(merged, line);
  });

  for (const line of lines) {
    if (!line.trim()) continue;

    for (const m of line.matchAll(IPV4_RE)) {
      const cls = classifyIpv4(m[0]);
      if (!cls) continue;
      if (cls === 'loopback' || cls === 'multicast' || cls === 'reserved') continue;
      /* `10.1.2.3` is a valid address and a plausible version string. The decision has
         to be made per VALUE, not per occurrence, because one alias is applied
         everywhere — so a literal is only spared when EVERY occurrence sits in version
         context. Mixed means it is a real address somewhere, and leaking an address is
         worse than rewriting a version number. */
      if (looksLikeVersion(line, m.index!)) { versionSeen.add(m[0]); continue; }
      patternAdd(m[0], 'ipv4', 'IPv4 pattern', cls);
      addressSeen.add(m[0]);
    }

    for (const m of line.matchAll(IPV6_RE)) {
      const cls = classifyIpv6(m[0]);
      if (!cls || cls === 'loopback' || cls === 'multicast' || cls === 'reserved') continue;
      patternAdd(m[0], 'ipv6', 'IPv6 pattern', cls);
    }

    for (const m of line.matchAll(EMAIL_RE)) patternAdd(m[0], 'email', 'email pattern');
    for (const m of line.matchAll(MAC_RE)) patternAdd(m[0], 'mac', 'MAC pattern');

    // `CORP\jsmith`: the domain and the account are separate identities, and the
    // backslash has to survive so the DOMAIN\user shape is intact. On a JSON line the
    // separator is a doubled backslash (a single one is an escape) — see WINUSER_JSON_RE.
    for (const m of line.matchAll(lineLooksLikeJson(line) ? WINUSER_JSON_RE : WINUSER_RE)) {
      if (!isNever(m[1])) patternAdd(m[1], 'host', 'DOMAIN\\user pattern');
      if (!isNever(m[2])) patternAdd(m[2], 'user', 'DOMAIN\\user pattern');
    }

    for (const m of line.matchAll(FQDN_RE)) {
      if (isNever(m[0]) || RESERVED_DOMAIN.test(m[0])) continue;
      patternAdd(m[0], 'fqdn', 'FQDN pattern');
    }

    /* Generic field-aware pass. Still worth running with a parser present: it reads
       `key=value` and JSON that the parser's own functions may not extract, and the two
       agree on anything they both see. */
    for (const { name, value, index } of fieldPairs(line)) {
      const canon = canonField(name);
      /**
       * The reviewer pointed at this field and said replace it.
       *
       * First, so it outranks every default below — the vocabulary skip, the business-ID
       * skip, and the schema's opinion about what the name means. Those defaults are
       * precisely what an explicit pick is overruling, and a pick that lost to one of them
       * would leave the reviewer looking at a sample they had asked to be cleaned and had
       * been told, in a warning, to clean this way.
       *
       * Aliased as `pii` for its mechanism rather than its meaning: a quote number is not
       * personal data, but it needs what the pii minter does — character-class scrambling
       * that keeps eight digits eight digits, minted fresh so two different quotes never
       * collide into one. Its own `via` keeps it in its own group in the review list.
       */
      if (pickedFields.has(canon)) {
        const v = value.trim().replace(/^["']|["']$/g, '');
        if (v && v.length <= 120 && !isStructural(v)) {
          pickedSeen.add(canon);
          const before = found.size;
          add(v, 'pii', `${PICKED_FIELD_VIA} “${name.trim().replace(/^["']|["']$/g, '')}”`);
          if (found.size > before) tally.field++;
        }
        continue;
      }
      /* Product and device vocabulary. Checked before anything else claims the value: a
         phone model code is not a machine, and the generated pipeline extracts this field. */
      if (NEVER_REPLACE_FIELDS.has(canon)) continue;
      const hinted = hints.identityFields.has(name.toLowerCase());
      /* A field that names a person or their handset is an identity even when the generic
         schema vocabulary has never heard of it — `esn`, `mdn`, `marketZip`. */
      const isPii = PII_FIELDS.has(canon);
      /* Counted and named in a warning rather than turned into rows. There are 22 distinct
         order numbers in a 22-event sample, so one row each would bury the eight rows that
         actually matter — and a reviewer wants to decide about the FIELD, not tick a hundred
         individual numbers. */
      if (!isPii && SUSPECT_FIELDS.has(canon)) {
        const v0 = value.trim().replace(/^["']|["']$/g, '');
        if (v0 && v0 !== 'NA') (businessIdFields[name.trim()] ||= new Set()).add(v0);
        continue;
      }
      const kind = fieldIdentityKind(name) || (isPii ? 'pii' : hinted ? 'custom' : null);
      if (!kind) continue;
      const v = value.trim();
      if (!v || isNever(v) || found.has(v)) {
        if (found.has(v)) found.get(v)!.count++;
        continue;
      }
      // Already covered by a pattern above (an IP in `src_ip=`, a UPN in `user=`).
      if (IPV4_ONE.test(v) || v.includes('@') || v.includes('\\')) continue;
      /* All-digit values are normally ports, counters and row ids. A field that says it
         holds a subscriber number or a postcode is the exception — that is the whole reason
         the name is listed. */
      if ((/^[\d.]+$/.test(v) || /^\d+$/.test(v)) && !hinted && !isPii) continue;
      /* An ip-named field holding something that is not an address. Real ones were taken by
         the pattern tier above, so normally there is nothing here worth having — except that
         `address` means a street as readily as it means a host, and the schema vocabulary
         only knows the network sense. Deciding by the value settles it: `address=10.1.2.3`
         was already handled as an address, `address=MACON` is where somebody lives. */
      if (kind === 'ipv4' || kind === 'ipv6') {
        if (!isPii) continue;
        add(v, 'pii', `field “${name}”`);
        tally.field++;
        continue;
      }
      if (looksLikeVersion(line, index)) continue;
      const before = found.size;
      add(v, kind, `field “${name}”`);
      if (found.size > before) tally.field++;
    }
  }

  /* Secrets, from the secret rules library. Runs after the identity tiers and before the
     suspects: a credential is the one thing here that is dangerous rather than merely
     private, so it is never offered as an optional suggestion. Where a secret encloses an
     identity — a connection URI holding both the account and the host — both rows stand,
     and the longest-first ordering below redacts the URI whole. */
  for (const hit of findSecrets(text)) {
    if (isNever(hit.value)) continue;
    const before = found.size;
    add(hit.value, 'secret', hit.via);
    if (found.size > before) tally.secret++;
  }

  if (opts.suggestSuspects !== false) {
    for (const s of findSuspects(lines, found, isNever)) {
      const before = found.size;
      add(s.value, s.kind, s.via, undefined, 'suspect');
      if (found.size > before) { tally.suspect++; found.get(s.value)!.count = s.count; }
    }
  }

  for (const v of versionSeen) {
    if (addressSeen.has(v)) {
      warnings.push(`“${v}” appears both as an address and after a version keyword. It is being replaced everywhere, because leaving a real address in is worse than rewriting a version number — untick it if it is only ever a version.`);
    } else {
      warnings.push(`Skipped “${v}” — every occurrence follows a version keyword, so it is a version string, not an address.`);
    }
  }

  for (const literal of opts.extraLiterals || []) {
    const trimmed = literal.trim();
    if (!trimmed) continue;
    const count = text.split(trimmed).length - 1;
    if (!count) { warnings.push(`“${trimmed}” does not appear in this sample.`); continue; }
    found.set(trimmed, { original: trimmed, alias: '', kind: 'custom', count, via: 'your list', enabled: true, confidence: 'certain' });
  }

  /* Pattern picks: one entry per distinct FULL match, alias rebuilt with only the chosen
     groups replaced. Applying the full match (not the bare group values) is what keeps
     `4212` inside `name[4212]:` from also rewriting ports and counters on the same line. */
  for (const pat of opts.extraPatterns || []) {
    let re: RegExp;
    try { re = new RegExp(pat.source, 'g'); }
    catch {
      warnings.push(`Pattern “${pat.source}” is not a valid regular expression.`);
      continue;
    }
    const selected = new Set(pat.groupNames);
    if (!selected.size) continue;
    // Per-group value → stand-in, so the same name across two matches stays one alias.
    const groupAlias = new Map<string, Map<string, string>>();
    const mintGroup = (groupName: string, value: string) => {
      let m = groupAlias.get(groupName);
      if (!m) { m = new Map(); groupAlias.set(groupName, m); }
      const hit = m.get(value);
      if (hit) return hit;
      /* Positional class-preserving for every group, letters and digits alike: a `host`
         stand-in for a letter run could return a different length or shape, whereas `pii`
         swaps each character within its own class (letter→letter, digit→digit) and keeps
         the run's length, which is what the pattern pick was meant to preserve. */
      const alias = minter.pii(value);
      m.set(value, alias);
      return alias;
    };
    const matchCounts = new Map<string, number>();
    const matchAlias = new Map<string, string>();
    const matchPatches = new Map<string, { start: number; end: number; alias: string }[]>();
    for (const hit of text.matchAll(re)) {
      const full = hit[0];
      const groups = hit.groups || {};
      // Rebuild from the match by walking selected named groups in left-to-right index order.
      const named = Object.keys(groups)
        .filter(n => selected.has(n) && groups[n] != null)
        .map(n => {
          const val = groups[n]!;
          const idx = full.indexOf(val);
          return { name: n, val, idx: idx < 0 ? 0 : idx };
        })
        .sort((a, b) => a.idx - b.idx || a.name.localeCompare(b.name));
      // Prefer positions from the regex indices when available (named groups don't expose index in JS).
      // Fall back to sequential replace of known samples in order of appearance in `full`.
      let cursor = 0;
      const parts: string[] = [];
      const patches: { start: number; end: number; alias: string }[] = [];
      const used = new Set<number>();
      for (const g of named) {
        let at = full.indexOf(g.val, cursor);
        // If the same digits appear twice, take the next occurrence not yet used.
        while (at >= 0 && used.has(at)) at = full.indexOf(g.val, at + 1);
        if (at < 0) continue;
        parts.push(full.slice(cursor, at));
        const alias = mintGroup(g.name, g.val);
        parts.push(alias);
        patches.push({ start: at, end: at + g.val.length, alias });
        used.add(at);
        cursor = at + g.val.length;
      }
      parts.push(full.slice(cursor));
      const rebuilt = parts.join('');
      if (rebuilt === full) continue;
      matchCounts.set(full, (matchCounts.get(full) ?? 0) + 1);
      if (!matchAlias.has(full)) {
        matchAlias.set(full, rebuilt);
        matchPatches.set(full, patches);
      }
    }
    if (!matchAlias.size) {
      warnings.push(`Pattern did not match anything (or selected groups did not change a match).`);
      continue;
    }
    for (const [full, alias] of matchAlias) {
      found.set(full, {
        original: full,
        alias,
        kind: 'custom',
        count: matchCounts.get(full) ?? 1,
        via: PICKED_PATTERN_VIA,
        enabled: true,
        confidence: 'certain',
        patchSpans: matchPatches.get(full),
      });
    }
  }

  /* Composite identifiers whose parts are already covered are dropped in favour of the
     parts. An ARN like `arn:aws:iam::123456789012:user/jsmith` is a real identity, but
     replacing the whole string with one opaque alias destroys a structure that pipelines
     extract from — whereas replacing the account id and the username inside it leaves
     `arn:aws:iam::<alias>:user/<alias>`, which is both anonymous and still an ARN. */
  for (const [value, entry] of [...found]) {
    if (!/[:/]/.test(value) || entry.kind === 'ipv6' || entry.kind === 'mac') continue;
    /* A secret is exempt. `postgresql://svc_billing:Pa55w0rd!@db-prod-01.internal/billing`
       has a hostname inside it that the FQDN tier already found, so this rule would keep
       the parts and drop the whole — leaving the password sitting in the middle of it. The
       credential is the reason the row exists, and only replacing the whole string removes
       it. */
    if (entry.kind === 'secret') continue;
    if (entry.via === PICKED_PATTERN_VIA) continue;
    const parts = value.split(/[^\w.$-]+/).filter(p => p.length > 2);
    const covered = parts.filter(p => found.has(p) && found.get(p) !== entry);
    if (covered.length) found.delete(value);
  }

  /* Longest first, so replacing `web01.corp.local` happens before the bare `web01` it
     contains. Applying the short one first would corrupt the long one. */
  const entries = [...found.values()].sort((a, b) =>
    b.original.length - a.original.length || a.original.localeCompare(b.original));

  for (const e of entries) {
    // Pattern picks already carry the rebuilt full-match alias (groups substituted).
    // Re-minting by kind would replace `hosta[1001]:` with a single custom token and
    // destroy the punctuation the pattern was meant to keep.
    if (e.via === PICKED_PATTERN_VIA && e.alias) continue;
    e.alias = e.kind === 'ipv4' ? minter.ipv4(e.original, e.ipClass!)
      : e.kind === 'ipv6' ? minter.ipv6(e.original, e.ipClass!)
      : e.kind === 'email' ? minter.email(e.original)
      : e.kind === 'mac' ? minter.mac()
      : e.kind === 'fqdn' ? minter.fqdn(e.original)
      : e.kind === 'user' ? minter.user(e.original)
      : e.kind === 'custom' ? minter.custom(e.original)
      : e.kind === 'secret' ? minter.secret(e.original)
      : e.kind === 'pii' ? minter.pii(e.original)
      : minter.host(e.original);
    // A class we deliberately leave alone (loopback, multicast) mints to itself.
    if (e.alias === e.original) e.enabled = false;
  }

  /* Hard guarantee that a mask can never change the wire format. A replacement swaps
     `original`→`alias` in place, so it shifts a delimited/positional field boundary the moment
     the alias holds a different count of a structural char (tab, pipe, comma, '=', space) than
     the value it replaces. The value minters keep separators in place by design, but a
     kind-specific stand-in — a collapsed display name, a token of a different shape, a future
     minter — could still slip one in. Rather than trust each minter to get it right (and let the
     save gate reject the sample after the fact), re-mint any offending alias by SHAPE:
     character-class substitution (`pii`) keeps every structural char exactly where the original
     had it, so it is structurally impossible to emit a replacement that breaks the format.
     Pattern picks are exempt — their rebuilt alias is punctuation-faithful by construction, and
     re-minting would destroy the shape it was built to keep. */
  for (const e of entries) {
    if (e.via === PICKED_PATTERN_VIA || !e.alias || e.alias === e.original) continue;
    if (STRUCTURAL_CHARS.some(d => countOf(e.original, d) !== countOf(e.alias, d))) {
      e.alias = minter.pii(e.original);
    }
  }

  /* Count what each entry would ACTUALLY replace, in order, and drop the ones that turn
     out to replace nothing. `acme-corp.com` is picked up as an FQDN in its own right, but
     if it only ever occurs inside `mbrennan@acme-corp.com` then the longer email entry
     consumes it first — leaving a row in the review list that claims two occurrences and
     changes nothing. The reviewer has to be able to trust these counts. */
  const candidates = entries.filter(e => e.alias !== e.original);  // a class we leave alone
  const hits = new Map<string, number>();
  const all = buildReplacer(candidates);
  const enabledOnly = buildReplacer(candidates.filter(e => e.enabled));
  if (all) {
    text.replace(all.re, hit => {
      hits.set(hit, (hits.get(hit) ?? 0) + 1);
      const e = all.byValue.get(hit)!;
      if (e.enabled) return e.alias;
      /* Only a row that will actually be applied gets to consume the text. An unticked
         suspect that swallowed its matches here would hide them from the rows below it and
         understate their counts, which is the opposite of what a review list is for — so
         the inside of an unticked match is re-scanned for the ticked rows nested in it.
         `mbrennan@acme-corp.com` left unticked must not shelter `acme-corp.com`. */
      if (enabledOnly) {
        hit.replace(enabledOnly.re, inner => {
          hits.set(inner, (hits.get(inner) ?? 0) + 1);
          return '';
        });
      }
      return hit;
    });
  }
  const live: SanitiseEntry[] = [];
  for (const e of candidates) {
    const n = hits.get(e.original) ?? 0;
    if (!n) continue;
    e.count = n;
    live.push(e);
  }

  const certainNames = live.some(e =>
    e.confidence === 'certain' && (e.kind === 'host' || e.kind === 'user' || e.kind === 'fqdn'));

  if (hints.key) {
    const bits = [`Applied the ${hints.key} profile`];
    if (hints.note) bits.push(hints.note);
    warnings.push(`${bits.join(' — ')}.`);
  }

  /* Stated first and in its own terms. Every other row here is a privacy matter; this one
     means a working credential was sitting in a file someone was about to hand to a model
     vendor, and it is still live in whatever system it came from. */
  const secrets = live.filter(e => e.kind === 'secret');
  if (secrets.length) {
    const why = [...new Set(secrets.map(e => e.via))];
    warnings.push(`Found ${secrets.length} probable credential${secrets.length === 1 ? '' : 's'} in this sample — ${why.join(', ')}. ${secrets.length === 1 ? 'It is' : 'They are'} scrambled character-for-character rather than blanked, so the sample still parses. Treat the original as exposed and rotate it: sanitising this copy does not revoke anything.`);
  }

  /* Reported separately from credentials, because the action is different. Nobody rotates a
     postcode or a handset serial — these are identities, and what matters is that they were
     found by the field holding them rather than by any pattern. */
  const piiRows = live.filter(e => e.kind === 'pii' && e.enabled && !e.via.startsWith(PICKED_FIELD_VIA));
  if (piiRows.length) {
    const fields = [...new Set(piiRows.map(e => e.via.replace(/^field “|”$/g, '')))];
    warnings.push(`Replaced ${piiRows.length} personal or device identifier${piiRows.length === 1 ? '' : 's'} named by ${fields.length === 1 ? 'the field' : 'the fields'} ${fields.map(f => `“${f}”`).join(', ')}. These carry no pattern a scanner could match — a handset serial or a postcode is just digits — so the field name is the only thing that identifies them.`);
  }

  /* Reported in the reviewer's own terms: they asked for a field, so the confirmation is
     about the field and not about the hundred values it turned into. */
  const pickedRows = live.filter(e => e.via.startsWith(PICKED_FIELD_VIA) && e.enabled);
  if (pickedRows.length) {
    const fields = [...new Set(pickedRows.map(e => e.via.slice(PICKED_FIELD_VIA.length).trim().replace(/^“|”$/g, '')))];
    warnings.push(`Replaced every value of ${fields.map(f => `“${f}”`).join(' and ')} because you picked ${fields.length === 1 ? 'that field' : 'those fields'} — ${pickedRows.length} distinct value${pickedRows.length === 1 ? '' : 's'}. Each keeps its shape, so a digits-only reference stays the same length in digits and the sample still parses.`);
  }

  /* A pick that found nothing has to say so. The reviewer highlighted a value and chose its
     field, so silence would read as "done" while the sample still carries every one. */
  const missed = [...pickedFields].filter(f => !pickedSeen.has(f));
  if (missed.length) {
    warnings.push(`Could not find ${missed.map(f => `“${f}”`).join(' or ')} as a ${missed.length === 1 ? 'field' : 'fields'} holding replaceable values in this sample. Field picks read ${'`key=value`'} and JSON pairs — if this sample is positional or the values are all placeholders, pick the values themselves instead.`);
  }

  /* Named but not touched, with the counts, because the reviewer can only weigh what they
     know is there. Deliberately a sentence rather than a hundred rows: these fields hold one
     distinct value per event, so listing them individually would bury everything above. */
  const businessIds = Object.entries(businessIdFields).filter(([, v]) => v.size);
  if (businessIds.length) {
    const parts = businessIds.map(([f, v]) => `“${f}” (${v.size} distinct)`);
    warnings.push(`Left ${parts.join(' and ')} in place. ${businessIds.length === 1 ? 'It is' : 'They are'} not personal data, but ${businessIds.length === 1 ? 'it correlates' : 'they correlate'} to a customer in whatever system issued ${businessIds.length === 1 ? 'it' : 'them'} — and a pipeline may well be meant to key on ${businessIds.length === 1 ? 'it' : 'them'}, so the choice is yours. Add ${businessIds.length === 1 ? 'the value' : 'the values'} below if this sample is leaving your estate.`);
  }

  if (opts.parserName && tally.parser) {
    warnings.push(`Read ${tally.parser} identit${tally.parser === 1 ? 'y' : 'ies'} out of named fields using the ${opts.parserName} parser. Those are field-typed rather than guessed, which is how bare usernames and short hostnames get found at all.`);
  } else if (!opts.parsed?.length) {
    warnings.push('No parser matched this sample, so bare names could only be guessed by shape. Check the unticked suggestions carefully, and add anything missed below.');
  }

  /* Said even when NOTHING was found — especially then. A reviewer who sees an empty
     mapping must not conclude the sample is clean; bare names are only reachable through a
     parser or a named field, and that gap has to be stated rather than implied. */
  if (!certainNames) {
    warnings.push('No hostnames or usernames were positively identified. Bare names are only findable through a parser field, a field that says what it holds (user=, host=, SubjectUserName…), or a DOMAIN\\user / FQDN / email form — anything else has to be highlighted in the sample or listed below.');
  }

  return {
    entries: live,
    warnings,
    sources: {
      parser: live.filter(e => e.via.startsWith('parsed field')).length,
      field: live.filter(e => e.via.startsWith('field ')).length,
      pattern: live.filter(e => e.via.endsWith('pattern')).length,
      suspect: live.filter(e => e.confidence === 'suspect').length,
      secret: live.filter(e => e.kind === 'secret').length,
      pii: live.filter(e => e.kind === 'pii').length,
      parserName: opts.parserName,
    },
  };
}

// ---------------------------------------------------------------------------
// Applying
// ---------------------------------------------------------------------------

function escapeRe(s: string): string { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/**
 * Replace every enabled entry throughout the text.
 *
 * Whole-token only: a bare `web01` must not rewrite the `web01` inside
 * `web01.corp.local` (which is its own entry with its own alias), and a user called
 * `sam` must not turn `samba` into `<alias>ba`. Entries arrive longest-first from
 * `planSanitisation`, and each replacement is applied over the result of the last so a
 * value nested in a longer one is already gone by the time its own turn comes.
 */
/**
 * One regex that matches any of these values, plus the value → entry lookup to go with it.
 *
 * The alternative is a scan of the whole sample per entry, and entry count grows with the
 * sample: a 5,000-event log has a distinct account number, handset serial and mobile number
 * on every line, which came to 26,000 entries and made both replacement and counting
 * quadratic — 77 seconds of blocked main thread. One combined pass is ~0.2s for the same
 * work.
 *
 * Order is load-bearing. Alternation in JavaScript is leftmost-FIRST, not leftmost-longest,
 * so `web01` listed before `web01.corp.local` would match the short one and strand the
 * domain. Callers pass entries already sorted longest-first and this preserves that order,
 * which is also what makes a single pass equivalent to the old sequential one.
 */
function buildReplacer(entries: SanitiseEntry[]) {
  const byValue = new Map(entries.map(e => [e.original, e]));
  if (!byValue.size) return null;
  /* `(?![\w.$-])` rather than `\b`: `\b` would fire in the middle of an FQDN or a dotted
     account name, which is exactly the boundary that matters here. The guard is hoisted OUT of
     the alternation and written once, not per value — a businessevent.log yields tens of
     thousands of entries and a per-branch guard makes the regex (and the scan) grow with them.
     A user-picked pattern is the exception. Its own regex already fixed where the match begins
     and ends, and that span can legitimately start or end mid-word — `product_id=Goats&…` picked
     as `_id=Goats&…` begins right after `product`. A boundary guard would then refuse to re-find
     the exact literal here (the char before it is `d`, a word char), the counting pass would see
     zero hits, and the row would silently vanish from the preview even though the pattern matched.
     So the (few, explicit) pattern picks are matched as their exact literal, unguarded and FIRST
     so a pick wins over an auto-detected sub-match nested inside it; everything else stays in the
     one hoisted-guard group. When there are no picks this is byte-for-byte the old fast regex. */
  const all = [...byValue.values()];
  const guarded = all.filter(e => e.via !== PICKED_PATTERN_VIA);
  const branches = all.filter(e => e.via === PICKED_PATTERN_VIA).map(e => escapeRe(e.original));
  if (guarded.length) {
    branches.push(`(?<![\\w.$-])(?:${guarded.map(e => escapeRe(e.original)).join('|')})(?![\\w.$-])`);
  }
  const re = new RegExp(branches.length > 1 ? `(?:${branches.join('|')})` : branches[0], 'g');
  return { re, byValue };
}

/** Where one entry sits in the text, for showing the reviewer what is covered. */
export interface SanitiseSpan {
  start: number;
  end: number;
  entry: SanitiseEntry;
}

/**
 * Every place in the text that the plan covers, in order and non-overlapping.
 *
 * Built from the same matcher as `applySanitisation`, deliberately. A highlight drawn by a
 * separate "find the sensitive bits" routine would eventually disagree with what the apply
 * step actually does, and a highlight that disagrees is worse than none — it is the screen
 * telling the reviewer a card number is handled when it is not, or the reverse, which is
 * what sent them looking in the first place.
 *
 * Unticked rows are included and flagged through `entry.enabled`, because "found this, and
 * it is NOT going to be changed" is exactly the state the reviewer needs to see.
 *
 * Pattern picks carry `patchSpans`: apply still swaps the whole token (so a bare port that
 * happens to equal the bracketed id is left alone), but the highlight only paints the
 * groups the reviewer chose — otherwise "replace 8196" looks like the whole
 * `name[8196]:` is selected.
 */
export function markSanitisation(text: string, entries: SanitiseEntry[]): SanitiseSpan[] {
  const m = buildReplacer(entries.filter(e => e.alias !== e.original));
  if (!m) return [];
  const spans: SanitiseSpan[] = [];
  m.re.lastIndex = 0;
  for (let hit = m.re.exec(text); hit; hit = m.re.exec(text)) {
    const entry = m.byValue.get(hit[0])!;
    const patches = entry.patchSpans;
    if (patches?.length) {
      for (const p of patches) {
        spans.push({ start: hit.index + p.start, end: hit.index + p.end, entry });
      }
    } else {
      spans.push({ start: hit.index, end: hit.index + hit[0].length, entry });
    }
  }
  return spans.sort((a, b) => a.start - b.start || a.end - b.end);
}

/**
 * What the review row should show for a pattern pick: only the parts that change.
 *
 * Apply still keys on the full token; this is display-only so "Sanitize numbers like 8196"
 * does not read as replacing `consequuntur[8196]:` wholesale.
 */
export function patternPatchDisplay(entry: SanitiseEntry): { from: string; to: string } | null {
  if (!entry.patchSpans?.length) return null;
  return {
    from: entry.patchSpans.map(p => entry.original.slice(p.start, p.end)).join('+'),
    to: entry.patchSpans.map(p => p.alias).join('+'),
  };
}

/**
 * Rebuild a pattern-pick alias after the reviewer edits the displayed patch value(s).
 *
 * `displayTo` is what the review input holds — either a single stand-in, or several joined
 * with `+` in left-to-right patch order. Splices into `original` so punctuation stays put.
 */
export function rebuildPatternAlias(entry: SanitiseEntry, displayTo: string): string {
  const patches = entry.patchSpans;
  if (!patches?.length) return displayTo;
  const parts = displayTo.split('+');
  let out = '';
  let cursor = 0;
  for (let i = 0; i < patches.length; i++) {
    const p = patches[i];
    out += entry.original.slice(cursor, p.start);
    out += (parts[i] ?? p.alias);
    cursor = p.end;
  }
  out += entry.original.slice(cursor);
  return out;
}

export function applySanitisation(text: string, entries: SanitiseEntry[]): string {
  const live = entries.filter(e => e.enabled && e.alias && e.alias !== e.original);
  const m = buildReplacer(live);
  if (!m) return text;
  /* A function replacer, so an alias is inserted literally. A machine-account alias ends in
     `$`, and `$&` in a string replacement would splice the match back in. */
  return text.replace(m.re, hit => m.byValue.get(hit)!.alias);
}

export interface PreviewLine {
  /** 1-based line number in the sample. */
  lineNo: number;
  before: string;
  after: string;
  /**
   * Changed spans, tightened to the differing characters, within `before`/`after`. Carry the
   * same `try`/`bad` flags as `afterSpans` so a before-pane overlay can colour the original
   * values it is about to replace identically to their result (committed / provisional / blocking).
   */
  beforeSpans: { start: number; end: number; try?: boolean; bad?: boolean }[];
  /**
   * `try` marks a span produced by an entry the caller flagged as not-yet-committed
   * (`tryKeys`), so the UI can render a live preview of a pick the reviewer is hovering
   * over in a distinct colour from the masks already applied. Absent = committed.
   *
   * `bad` marks a span produced by an entry the caller flagged as wire-format-breaking
   * (`badKeys`) — its alias shifts a delimiter/whitespace count and would trip the save
   * gate (`checkStructurePreserved`). The UI paints these red so the reviewer can see
   * exactly which mask is blocking the save. Takes visual precedence over `try`.
   */
  afterSpans: { start: number; end: number; try?: boolean; bad?: boolean }[];
}

/**
 * A before/after preview of the lines the plan actually changes, one entry per changed line
 * up to `maxLines`, with the changed spans on each side.
 *
 * Built from the SAME `buildReplacer` as `applySanitisation`, so the preview cannot promise a
 * result Apply then does not produce — the whole reason the marks and the apply share a
 * matcher. Each span is tightened to the characters that actually differ (common prefix and
 * suffix trimmed): a pattern pick that only touches `[8196]`'s digits highlights `8196`, not
 * the whole `consequuntur[8196]:`, while a host swap with nothing in common highlights all of
 * it. `totalChanged` counts every changed line so the panel can say how many more it did not
 * show.
 *
 * `tryKeys` (optional) is a set of `${kind}:${original}` entry keys the caller wants marked
 * as not-yet-committed: any after-span produced by one of those entries is flagged `try`, so
 * a reviewer previewing a masking choice sees exactly where it would land in a distinct
 * colour, before pressing Apply. Committed entries are unaffected.
 *
 * `badKeys` (optional) is a set of the same `${kind}:${original}` keys the caller wants marked
 * as wire-format-breaking (see `structuralOffenders`): any after-span they produce is flagged
 * `bad`, so the UI can paint red exactly the mask that shifts a delimiter/whitespace boundary
 * and blocks the save.
 */
export function previewSanitisation(
  text: string,
  entries: SanitiseEntry[],
  maxLines = 5,
  includeUnchanged = false,
  tryKeys?: Set<string>,
  badKeys?: Set<string>,
): { lines: PreviewLine[]; totalChanged: number } {
  const live = entries.filter(e => e.enabled && e.alias && e.alias !== e.original);
  const m = buildReplacer(live);
  const lines = text.split('\n');
  const unchanged = (before: string, i: number): PreviewLine =>
    ({ lineNo: i + 1, before, after: before, beforeSpans: [], afterSpans: [] });
  /* With nothing to replace there is still a "before/after" to show when the caller wants an
     always-on view (`includeUnchanged`): every line, its after identical to its before. The
     changed-only preview keeps returning an empty list so it can hide itself. */
  if (!m) {
    return includeUnchanged
      ? { lines: lines.slice(0, maxLines).map(unchanged), totalChanged: 0 }
      : { lines: [], totalChanged: 0 };
  }
  const out: PreviewLine[] = [];
  let totalChanged = 0;
  for (let i = 0; i < lines.length; i++) {
    const before = lines[i];
    m.re.lastIndex = 0;
    let after = '';
    let at = 0;
    const beforeSpans: { start: number; end: number; try?: boolean; bad?: boolean }[] = [];
    const afterSpans: { start: number; end: number; try?: boolean; bad?: boolean }[] = [];
    let changed = false;
    for (let hit = m.re.exec(before); hit; hit = m.re.exec(before)) {
      const matched = hit[0];
      const entry = m.byValue.get(matched)!;
      const alias = entry.alias;
      const entryKey = `${entry.kind}:${entry.original}`;
      const isTry = tryKeys ? tryKeys.has(entryKey) : false;
      const isBad = badKeys ? badKeys.has(entryKey) : false;
      after += before.slice(at, hit.index);
      const aStart = after.length;
      if (entry.patchSpans?.length) {
        /* A pattern pick keeps its punctuation and only swaps the captured sub-runs, so mark
           exactly those — never a character diff of matched vs alias, which over-trims the
           moment a stand-in digit/letter coincides with the original (`8196` → `…6` marked
           only `819`). The before-spans index into the token; the after-spans track the
           running length delta as each run is replaced left-to-right. */
        let delta = 0;
        for (const p of entry.patchSpans) {
          beforeSpans.push({ start: hit.index + p.start, end: hit.index + p.end, try: isTry, bad: isBad });
          const aRunStart = aStart + p.start + delta;
          afterSpans.push({ start: aRunStart, end: aRunStart + p.alias.length, try: isTry, bad: isBad });
          delta += p.alias.length - (p.end - p.start);
        }
      } else {
        // A literal identity swap: the whole matched value IS the identity — mark it whole.
        beforeSpans.push({ start: hit.index, end: hit.index + matched.length, try: isTry, bad: isBad });
        afterSpans.push({ start: aStart, end: aStart + alias.length, try: isTry, bad: isBad });
      }
      after += alias;
      at = hit.index + matched.length;
      changed = true;
      if (matched.length === 0) m.re.lastIndex++; // zero-width guard, should not happen
    }
    if (!changed) {
      if (includeUnchanged && out.length < maxLines) out.push(unchanged(before, i));
      continue;
    }
    after += before.slice(at);
    totalChanged++;
    if (out.length < maxLines) out.push({ lineNo: i + 1, before, after, beforeSpans, afterSpans });
  }
  return { lines: out, totalChanged };
}

// ---------------------------------------------------------------------------
// Proving it worked
// ---------------------------------------------------------------------------

export interface CoverageProof {
  /** Distinct field/value identity pairs the parser could see before sanitising. */
  total: number;
  /** How many of those now hold a different value. */
  replaced: number;
  /** The ones that did not change, with the field that exposed them and the 1-based line
      number they sit on — so the UI can point the reviewer straight at the problem. */
  remaining: { field: string; value: string; line: number }[];
  /** True when no parser could read the sample, so this proves nothing either way. */
  blind: boolean;
  ok: boolean;
}

/**
 * Re-read the sanitised sample with the same parser and prove the identities are gone.
 *
 * The structural check answers "is it still parseable"; this answers the question that
 * actually matters before the text is allowed near a model vendor: "is every identity the
 * parser can see now a different value than it was". That turns a claim into a count — "12
 * of 12 identity fields replaced" — and it catches the two failures a mapping list cannot
 * show by itself: a field the plan never offered, and a row the reviewer unticked without
 * realising what it held.
 *
 * `blind` matters as much as `ok`. When no parser could read the sample there is nothing to
 * verify, and reporting that as success would be the most misleading thing this function
 * could do.
 */
export function proveIdentityCoverage(
  before: ParsedLine[],
  after: ParsedLine[],
  opts: { sourcetype?: string } = {},
): CoverageProof {
  const hints = sourceHints(opts.sourcetype);
  const isNever = (v: string) => NEVER.has(v.toLowerCase()) || hints.neverReplace.has(v.toLowerCase());
  const seen = new Set<string>();
  const remaining: { field: string; value: string; line: number }[] = [];
  let total = 0, replaced = 0, readable = 0;

  before.forEach((fields, i) => {
    if (!fields) return;
    readable++;
    for (const [name, rawValue] of Object.entries(fields)) {
      const value = rawValue.trim();
      if (!value || value.length > 120 || isNever(value)) continue;
      const kind = fieldIdentityKind(name);
      const hinted = hints.identityFields.has(name.toLowerCase());
      if (!kind && !hinted) continue;
      /* A field the schema TYPES as an IP (`src_ip`, `dest_ip`, `nat_src_ip`, …) whose value is
         not an IP address is a parser mis-assignment, not a leaked identity — a KVP/CEF sample
         mislabelled as a positional firewall log lands `quotePriority=NORMAL` in `src_ip` and
         `conversationId=ESB~…` in `dest_ip`. Demanding the reviewer "mask" those is impossible
         (there is no address there to replace) and would block a sample that is in fact clean, so
         hold an IP field to account only for values that genuinely look like an IP. */
      if (kind === 'ipv4' && !IPV4_ONE.test(value) && !IPV6_ONE.test(value)) continue;
      /* Addresses are checked FIRST, because an address is also a string of digits and
         dots: dismissing it as a counter would drop the most common identity of all from
         the count and make a thin verification look thorough. Only the classes that carry
         protocol meaning rather than identity are left out, since those are deliberately
         not replaced and counting them would make a correct run look broken. */
      if (IPV4_ONE.test(value)) {
        const cls = classifyIpv4(value);
        if (!cls || cls === 'loopback' || cls === 'multicast' || cls === 'reserved') continue;
      } else if (/^[\d.]+$/.test(value) && !hinted) {
        continue;                                       // ports, counters, record ids
      }

      const key = `${name}\u0000${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      total++;
      if (after[i]?.[name]?.trim() === value) remaining.push({ field: name, value, line: i + 1 });
      else replaced++;
    }
  });

  return { total, replaced, remaining, blind: readable === 0, ok: readable > 0 && remaining.length === 0 };
}

// ---------------------------------------------------------------------------
// Did we break the sample?
// ---------------------------------------------------------------------------

export interface StructuralCheck {
  ok: boolean;
  problems: string[];
}

/**
 * Compare the STRUCTURE of the sample before and after, and report anything that moved.
 *
 * The sample's whole job downstream is to be parsed: a pipeline is generated against
 * it, regex-scored against it, and previewed with it. So a replacement that changes the
 * line count, breaks JSON, or alters the field keys has quietly destroyed the thing the
 * pack is built from — and the resulting pack would be wrong in a way no one would spot
 * later. Cheap to check here, expensive to discover afterwards.
 *
 * This is format-agnostic on purpose. The parser-faithful check (`verifyGeneratedSample`)
 * needs a confirmed sourcetype, which the reviewer may not have picked yet.
 */
export function checkStructurePreserved(before: string, after: string): StructuralCheck {
  const problems: string[] = [];
  const a = before.split('\n'), b = after.split('\n');
  if (a.length !== b.length) problems.push(`Line count changed (${a.length} → ${b.length}).`);

  const n = Math.min(a.length, b.length);
  let jsonBroken = 0, keysChanged = 0, delimChanged = 0, wsChanged = 0;
  for (let i = 0; i < n; i++) {
    const x = a[i], y = b[i];
    if (!x.trim()) continue;

    const looksJson = x.trimStart().startsWith('{') || x.trimStart().startsWith('[');
    if (looksJson) {
      try {
        JSON.parse(x);
        try { JSON.parse(y); } catch { jsonBroken++; continue; }
        if (jsonKeys(x) !== jsonKeys(y)) keysChanged++;
      } catch { /* not valid JSON before either — not ours to judge */ }
    }

    for (const d of ['\t', '|', ',', '=']) {
      if (countOf(x, d) !== countOf(y, d)) { delimChanged++; break; }
    }
    if (countOf(x, ' ') !== countOf(y, ' ')) wsChanged++;
  }

  if (jsonBroken) problems.push(`${jsonBroken} line(s) were valid JSON before and are not now.`);
  if (keysChanged) problems.push(`${keysChanged} JSON line(s) changed their field names — only values should change.`);
  if (delimChanged) problems.push(`${delimChanged} line(s) changed delimiter count, which can shift a CSV/KVP/CEF field boundary.`);
  if (wsChanged) problems.push(`${wsChanged} line(s) changed whitespace, which can shift a positional parser.`);

  return { ok: !problems.length, problems };
}

/** The delimiter + whitespace characters whose per-line count `checkStructurePreserved` guards. */
const STRUCTURAL_CHARS = ['\t', '|', ',', '=', ' '];

/**
 * Which enabled entries would shift a structural character count — i.e. exactly the masks the
 * save gate (`checkStructurePreserved`) would flag as changing the wire format.
 *
 * A replacement swaps `original`→`alias` in place, so it changes a line's count of a
 * delimiter/whitespace char if and only if the alias holds a different number of that char than
 * the original it replaces (independent of the surrounding line — the rest is untouched). This
 * lets the UI attribute a whole-sample structural break back to the individual pick that caused
 * it and paint just those spans red, instead of only reporting a line count. Returns the
 * `${kind}:${original}` keys, the same convention `previewSanitisation`'s `badKeys` expects.
 */
export function structuralOffenders(entries: SanitiseEntry[]): Set<string> {
  const bad = new Set<string>();
  for (const e of entries) {
    if (!e.enabled || !e.alias || e.alias === e.original) continue;
    for (const d of STRUCTURAL_CHARS) {
      if (countOf(e.original, d) !== countOf(e.alias, d)) { bad.add(`${e.kind}:${e.original}`); break; }
    }
  }
  return bad;
}

function countOf(s: string, ch: string): number {
  let n = 0;
  for (const c of s) if (c === ch) n++;
  return n;
}

function jsonKeys(line: string): string {
  const keys: string[] = [];
  const walk = (v: unknown, path: string) => {
    if (!v || typeof v !== 'object') return;
    if (Array.isArray(v)) { v.forEach(item => walk(item, `${path}[]`)); return; }
    for (const [k, val] of Object.entries(v)) { keys.push(`${path}.${k}`); walk(val, `${path}.${k}`); }
  };
  try { walk(JSON.parse(line), ''); } catch { return ''; }
  return keys.sort().join(',');
}

// ---------------------------------------------------------------------------
// Picking a value out of the sample by selecting it
// ---------------------------------------------------------------------------

export interface SelectionCandidate {
  /** What would actually be added — the selection grown to whole-token edges. */
  literal: string;
  /** The raw selection, when it differs from `literal`, so the UI can show the growth. */
  selected: string;
  ok: boolean;
  /** Why it cannot be added, or which existing row already covers it. */
  reason?: string;
  /**
   * The `key=value` pair the selection sits in, when it sits in one.
   *
   * Present whether or not the value alone can be added, because it is usually the better
   * offer either way: someone highlighting `51015341` in `quoteNumber=51015341` means quote
   * numbers, not that one number. Picking the field also reaches the values they did not
   * highlight, including the ones further down the sample they never scrolled to.
   */
  field?: FieldPick;
  /**
   * A composite-token shape derived from the selection (e.g. `bufbwjesfe[4212]:`).
   *
   * When present the pick bar can offer to replace individual capture groups — the name,
   * the number, or both — across every match of that shape in the sample.
   */
  pattern?: PatternPick;
  /**
   * A label-anchored value mask derived from a `label<delim>value` selection
   * (`inode=5330950`, `inode: 5330950`, `inode 5330950`).
   *
   * Unlike `pattern`, the label and its delimiter are kept LITERAL and only the value is a
   * capture group — so masking it keeps the field name (`inode=<masked>`) and touches only
   * this field's value, never every `word=number` on the line. Offered mainly for the `:`
   * and space delimiters that `key=value` field parsing misses (the `=` case is already the
   * whole-field pick).
   */
  valueMask?: PatternPick;
  /**
   * True when `valueMask` was derived from the reviewer's OWN selection spanning a whole
   * `label<delim>value` (they highlighted `a=b`, not just the value `b`).
   *
   * The value mask alone would narrow an explicit whole-pair pick down to the value — the
   * refine strip would then show only `b`, and the per-part composite offers would be
   * suppressed, so the reviewer who highlighted `a=b` sees choices "only about b". This flag
   * lets the UI keep operating on the whole `a=b`: the strip shows the pair and its pieces
   * (`a`, `b`) stay pickable, while the value mask is still offered as the recommended default.
   * False for the value-only cases (a bare value, a JSON value the caret merely lands in).
   */
  valueMaskFromSelection?: boolean;
  /**
   * A mask for ONE run marked inside a wider, previously-selected scope.
   *
   * Present only when the caller passed a `scope` and this selection is a strict sub-range of
   * it: everything outside the marked run stays literal, so picking this masks just that run
   * in that exact context. It is the "select the whole thing, then highlight the part" gesture
   * — the arbitrary-boundary companion to the auto-split shape chips.
   */
  markMask?: PatternPick;
}

/** A field the reviewer can choose to sanitise wholesale, with what that would cost. */
export interface FieldPick {
  /** As written in the sample, for the button text. */
  name: string;
  /** Normalised, which is what the plan matches on. */
  canon: string;
  /** How many different values the field holds across the sample. */
  distinct: number;
  /** How many times the field appears — one per event, usually. */
  occurrences: number;
  /**
   * Every value is already going, so there is nothing to offer.
   *
   * True both for a field picked earlier and for one the tiers already cover on their own:
   * `esn` is found by name and replaced everywhere, and offering to sanitise it again would
   * invite the reviewer to fix something that is not broken.
   */
  covered: boolean;
}

/**
 * The `key=value` pair a character offset falls inside the value of.
 *
 * Uses `fieldPairs`, the same reader the planner uses, rather than a second regex written
 * for this. A selection UI that disagreed with the planner about where a field ends would
 * offer the reviewer a field the plan then does not act on.
 */
export function fieldAt(text: string, offset: number): { name: string; value: string } | null {
  const lineStart = text.lastIndexOf('\n', Math.max(0, offset - 1)) + 1;
  let lineEnd = text.indexOf('\n', offset);
  if (lineEnd < 0) lineEnd = text.length;
  const line = text.slice(lineStart, lineEnd);
  const rel = offset - lineStart;

  for (const { name, value, index } of fieldPairs(line)) {
    if (rel >= index && rel < index + value.length) return { name: name.trim().replace(/^["']|["']$/g, ''), value };
  }
  return null;
}

/** The prefix marking a whole-field pick in the reviewer's list of extras. */
export const FIELD_TOKEN = 'field:';

/** The prefix marking a shape/pattern pick: `re:<pattern>|g1,g2`. */
export const PATTERN_TOKEN = 're:';

/** Via tag for entries produced by a reviewer pattern pick (review-list grouping). */
export const PICKED_PATTERN_VIA = 'pattern you picked';

export interface PatternGroup {
  /** `g1`, `g2`, … left to right. */
  name: string;
  /** The concrete text from the selection that this group captured. */
  sample: string;
  /** How the chunk was classified when the shape was built. */
  kind: 'letters' | 'digits' | 'alnum';
  /**
   * The exact regex fragment this group matches, when it is richer than the plain
   * `[A-Za-z]+` / `\d+` that `kind` implies. `labelValueShape` sets this for hex, id and
   * dotted value classes so the pick-bar chip shows the regex that will actually run, not a
   * `\d+` that lies about a `pub.esb.genericasync.response`-shaped value. `decomposeShape`
   * sets it to `[A-Za-z0-9]+` for a merged letters+digits run (`win8cvha`).
   */
  classRe?: string;
  /**
   * A likely identifier the pick bar should star. A separator-free run that mixes letters
   * and digits (`win8cvha`, `dc01srv`) reads as a hostname/asset id far more often than the
   * dictionary words around it — so it is the part a reviewer almost always means to mask.
   * Pure-letter and pure-digit groups are left unstarred: a bare number could be a port or a
   * counter, and a bare word is usually format, not identity.
   */
  recommend?: boolean;
}

export interface ShapePattern {
  /** Regex source with named groups, no flags — callers add `g`. */
  source: string;
  groups: PatternGroup[];
  /** The full token the shape was derived from. */
  token: string;
}

export interface PatternPick {
  shape: ShapePattern;
  /** Match count of this shape across the census text. */
  matches: number;
}

/**
 * Split a token into variable runs (letters and/or digits) and fixed punctuation.
 *
 * The split is on the alnum ↔ punctuation boundary ONLY: a run of letters and digits with
 * no separator between them (`win8cvha`, `dc01srv`) is ONE part, because that whole word is
 * the identity — offering `win` / `8` / `cvha` as three separate parts asks the reviewer to
 * reason about a boundary the data never drew. A run is then classified as letters, digits,
 * or `alnum` (it carries both), which drives the regex fragment and the recommend star.
 *
 * Only variable runs become capture groups; everything else is escaped as a literal. A bare
 * word (one variable run, no punctuation) is not a useful shape — the literal path owns that.
 */
export function decomposeShape(token: string): ShapePattern | null {
  const t = token.trim();
  if (!t || t.length > 120) return null;
  const chunks: { variable: boolean; text: string }[] = [];
  for (const ch of t) {
    // `_` is a separator between variable runs, so `BI_DEV_USER` splits into BI / DEV / USER
    // and `svc_01` into svc / 01. The reviewer is NOT offered those runs individually for a
    // snake_case name (that boundary is not theirs to reason about) — buildSanitiseChoices
    // collapses a pure-underscore composite into ONE whole-token shape choice. Keeping `_` a
    // separator here means each run is classified on its own (letters vs digits), so the
    // whole-token mask is `(?<g1>[A-Za-z]+)_(?<g2>\d+)` for `svc_01`, not a lossy single class.
    const variable = /[A-Za-z0-9]/.test(ch);
    const last = chunks[chunks.length - 1];
    if (last && last.variable === variable) last.text += ch;
    else chunks.push({ variable, text: ch });
  }
  const variables = chunks.filter(c => c.variable);
  if (!variables.length) return null;
  const fixed = chunks.filter(c => !c.variable);
  // No fixed punctuation → not a composite shape (web01 stays on the literal path).
  if (!fixed.length) return null;

  const groups: PatternGroup[] = [];
  let source = '';
  let gi = 1;
  for (const c of chunks) {
    if (!c.variable) {
      source += escapeRe(c.text);
      continue;
    }
    const name = `g${gi++}`;
    const allLetters = /^[A-Za-z]+$/.test(c.text);
    const allDigits = /^\d+$/.test(c.text);
    if (allLetters) {
      source += `(?<${name}>[A-Za-z]+)`;
      groups.push({ name, sample: c.text, kind: 'letters' });
    } else if (allDigits) {
      source += `(?<${name}>\\d+)`;
      groups.push({ name, sample: c.text, kind: 'digits' });
    } else {
      // Mixed letters+digits run with no separator (`win8cvha`, `dc01srv`) — one identity, so
      // one class and the recommend star (see PatternGroup.recommend).
      source += `(?<${name}>[A-Za-z0-9]+)`;
      groups.push({ name, sample: c.text, kind: 'alnum', classRe: '[A-Za-z0-9]+', recommend: true });
    }
  }
  if (groups.length < 1) return null;
  return { source, groups, token: t };
}

/**
 * A label-anchored value mask: keep the field NAME and its delimiter literal, replace only
 * the VALUE after it. Built for the reviewer who highlights `inode=5330950`, `inode: 5330950`
 * or `inode 5330950` and means "mask that number, but keep telling me it is the inode".
 *
 * Deliberately narrower than `decomposeShape`, which turns BOTH sides into capture groups
 * (`(?<g1>[A-Za-z]+)=(?<g2>\\d+)`): pick the value group there and you mask the value after
 * EVERY word, not just this one. Here the label is a literal, so only `inode`'s value moves.
 *
 * Guards — the delimiter scope the design settled on (`=`, `:`, or a single space), each
 * with the two conditions that keep prose out:
 *  - the label must look like a field name (a letter-led identifier), not a number or symbol;
 *  - the value must be numeric, hex, id-shaped, or a STRUCTURED token (one carrying an inner
 *    `.` or `-`, like `pub.esb.genericasync.response` or a hostname), so a run of English
 *    words never qualifies. A bare dictionary word (`status=active`) is still refused: it is
 *    almost never an identity and masking it everywhere would corrupt an enum.
 * The value class ends the match at the first character it does not accept — `[\\w.-]` stops
 * at the `,` that starts the next field, which is exactly the "the comma marks the end" the
 * reviewer meant when they highlighted a whole `field=value` pair out of a comma-joined line.
 * Delimiter whitespace is `[ \\t]` only, never `\\s`: a mask that reached across a newline
 * would swallow the line break and merge two events into one value. The `=` case is also
 * covered by the whole-field pick (`fieldPairs` reads `name=value`), but only when the
 * selection lands INSIDE the value; a reviewer who highlights the label first (the natural
 * way to grab a whole `key=value`) gets no field offer, so this is their route to
 * "keep the field, replace the whole value".
 */
export function labelValueShape(token: string, opts: { explicit?: boolean } = {}): ShapePattern | null {
  const t = token.trim();
  if (!t || t.length > 160) return null;
  /* `explicit` = the reviewer HIGHLIGHTED this whole pair, so the value is identity by their
     choice. The value-class guards below ("a bare word is usually format, not identity") exist
     to protect SPECULATIVE offers — a mask surfaced without being asked for. When the pair was
     deliberately selected, that reasoning no longer applies, so a plain-word value (`env=prod`,
     `"Operation": "MailItemsAccessed"`) is masked too. Speculative callers leave it false. */
  const explicit = !!opts.explicit;

  /* JSON pair — `"key": "value"`, `"key":"value"` or `"key": value` — the quoted form the
     reviewer sees in an O365 / CloudTrail / any-JSON record. Same "keep the label, replace the
     value" intent as the key=value branch below, but the key AND the surrounding quotes stay
     LITERAL and only the value CONTENT is captured, so the sanitised sample is still valid JSON
     (masking the quotes too would produce `"key": RANDOM`, which no longer parses). A quoted
     value may contain spaces (`"John Smith"`); the closing quote bounds the match so it can never
     run past this one field. A trailing comma from a mid-object selection is tolerated. */
  const jm = /^"([\w.$-]+)"[ \t]*:[ \t]*(?:"([^"]*)"|([^\s,;"'}\]]+))[ \t]*,?$/.exec(t);
  if (jm) {
    const label = jm[1];
    if (!/[A-Za-z]/.test(label) || NEVER.has(label.toLowerCase())) return null;
    const quoted = jm[2] !== undefined;
    const value = quoted ? jm[2] : jm[3];
    if (!value) return null; // empty value: nothing to mask
    let classRe: string;
    let source: string;
    if (quoted) {
      classRe = '[^"]*';
      source = `"${escapeRe(label)}"[ \\t]*:[ \\t]*"(?<g1>[^"]*)"`;
    } else {
      // Bare JSON scalar. Anchored to the key, so a bare number is safe here even though it is
      // refused on its own. Same numeric / id classes as the key=value branch below; an explicit
      // pick also accepts a plain word (`"env": prod`).
      const bare = /^\d+$/.test(value) ? '\\d+'
        : (/^[A-Za-z0-9][\w.-]*$/.test(value) && /[\d.-]/.test(value)) ? '[A-Za-z0-9][\\w.-]*'
        : explicit && /^[A-Za-z]+$/.test(value) ? '[A-Za-z]+'
        : explicit && /^[^\s,;"'}\]]+$/.test(value) ? '[^\\s,;"\'}\\]]+'
        : null;
      if (!bare) return null;
      classRe = bare;
      source = `(?<![\\w.$-])"${escapeRe(label)}"[ \\t]*:[ \\t]*(?<g1>${bare})`;
    }
    const kind: 'letters' | 'digits' = /^[A-Za-z]+$/.test(value) ? 'letters' : 'digits';
    return {
      source,
      groups: [{ name: 'g1', sample: value, kind, classRe }],
      token: quoted ? `"${label}": "${value}"` : `"${label}": ${value}`,
    };
  }

  const m = /^([A-Za-z_][\w.$-]*?)[ \t]*([=:]|[ \t])[ \t]*(\S+)$/.exec(t);
  if (!m) return null;
  const label = m[1];
  const rawDelim = m[2];
  const value = m[3].replace(/[,;.]+$/, '');
  // Label must read as a field name (carries a letter) and not be a structural placeholder.
  if (!/[A-Za-z]/.test(label) || NEVER.has(label.toLowerCase())) return null;
  // Value shape: numeric, hex (0x… or a long a-f run), an id (alnum carrying a digit), or a
  // structured token (alnum carrying an inner `.` or `-`: dotted queue/host names, uuids).
  let valueClass: string | null = null;
  if (/^\d+$/.test(value)) valueClass = '\\d+';
  else if (/^0x[0-9a-fA-F]+$/.test(value)) valueClass = '0x[0-9a-fA-F]+';
  else if (/^[0-9a-fA-F]{6,}$/.test(value) && /[a-fA-F]/.test(value)) valueClass = '[0-9a-fA-F]+';
  else if (/^[A-Za-z0-9][\w.-]*$/.test(value) && /[\d.-]/.test(value)) valueClass = '[A-Za-z0-9][\\w.-]*';
  // Explicit pick: the reviewer highlighted the whole pair, so mask a plain-word value too
  // (`status=active`) — by a class, so "every status= value" still generalises.
  else if (explicit && /^[A-Za-z]+$/.test(value)) valueClass = '[A-Za-z]+';
  else if (explicit && /^[^\s,;"']+$/.test(value)) valueClass = '[^\\s,;"\']+';
  if (!valueClass) return null;
  const delim = rawDelim === '=' ? '[ \\t]*=[ \\t]*'
    : rawDelim === ':' ? '[ \\t]*:[ \\t]*'
    : '[ \\t]+';
  // (?<![\w.$-]) so `inode` does not match inside `myinode`; the value class ends the token.
  const source = `(?<![\\w.$-])${escapeRe(label)}${delim}(?<g1>${valueClass})`;
  const kind: 'letters' | 'digits' = /^[A-Za-z]+$/.test(value) ? 'letters' : 'digits';
  // Display token normalised to one delimiter char, so the button can show `inode: ` + value.
  const shownDelim = rawDelim === '=' ? '=' : rawDelim === ':' ? ': ' : ' ';
  // classRe carries the true value class so the chip shows `[A-Za-z0-9][\w.-]*`, not a `\d+`
  // that misdescribes a dotted or hex value (only `\d+` values would read correctly from kind).
  return { source, groups: [{ name: 'g1', sample: value, kind, classRe: valueClass }], token: `${label}${shownDelim}${value}` };
}

/**
 * The key-anchored whole-value mask for a JSON pair the selection LANDS ON — with or without its
 * surrounding quotes, and whether the reviewer grabbed the whole value or a run inside it.
 *
 * This is what makes "select the value and mask it" work for JSON. Selecting `"BEUP…"` (the value
 * WITH its quotes) matched no `key<delim>value` shape — the selection starts on a `"`, so both
 * labelValueShape and fieldAt missed it — and the composite splitter then shredded
 * `BEUP281MB3649 (15.20.4200.000)` into eight per-run fragments, none of them the field. And
 * selecting the inner value alone (`BEUP281MB3649 (15.20…`) tricked labelValueShape into reading
 * the value's own first word as a LABEL, masking the version and keeping the server literal —
 * backwards. Anchoring on the real JSON key from the surrounding line fixes both: the key + the
 * quotes stay literal and the whole value is the single captured group, so the sample stays valid
 * JSON and every value of that key is covered.
 */
export function enclosingJsonValueMask(text: string, start: number, end: number): ShapePattern | null {
  if (start > end) return null;
  const lineStart = text.lastIndexOf('\n', Math.max(0, start - 1)) + 1;
  let lineEnd = text.indexOf('\n', start);
  if (lineEnd < 0) lineEnd = text.length;
  const line = text.slice(lineStart, lineEnd);
  const relS = start - lineStart;
  const relE = end - lineStart;
  const re = /"([\w.$-]+)"[ \t]*:[ \t]*(?:"([^"]*)"|([^\s,;"'}\]]+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) {
    const quoted = m[2] !== undefined;
    const valueLen = quoted ? m[2].length + 2 : m[3].length; // +2 for the two quotes
    const valStart = m.index + m[0].length - valueLen;
    const valEnd = m.index + m[0].length;
    // The selection must sit within this pair's value region — allowed to include the quotes —
    // and overlap the value itself (relE past the opening quote, relS before the closing one).
    if (relS >= m.index && relS < valEnd && relE > valStart && relE <= valEnd) {
      return labelValueShape(quoted ? `"${m[1]}": "${m[2]}"` : `"${m[1]}": ${m[3]}`, { explicit: true });
    }
  }
  return null;
}

/**
 * Mark ONE run inside a wider selection as the only part to replace.
 *
 * The reviewer highlights the whole `"command_start_%s" "win8cvha"`, then highlights just
 * `win8cvha` inside it: everything outside the mark stays literal and only the marked run
 * becomes a capture group, so the shape matches this exact context and replaces only that
 * run. It is the "keep the rest, mask this part" gesture — for a boundary the auto-split
 * chips do not offer (a sub-word, or a span that crosses a separator).
 *
 * `scope` is the outer selection text; `relStart`/`relEnd` index into it. The mark is grown
 * to its own alnum edges so a half-word highlight still lands on a whole `[A-Za-z0-9]`
 * boundary — a mask ending mid-run would match nothing. Refused when the mark is empty, has
 * no alnum, or is the whole scope (that is just the plain literal / whole-shape pick).
 */
export function markedValueShape(scope: string, relStart: number, relEnd: number): ShapePattern | null {
  if (!scope || relStart >= relEnd || relStart < 0 || relEnd > scope.length) return null;
  const alnum = /[A-Za-z0-9]/;
  let s = relStart, e = relEnd;
  // Grow only while still in the MIDDLE of an alnum run (both sides alnum), so a mark that
  // already ends at a separator is left where the reviewer put it.
  while (s > 0 && alnum.test(scope[s - 1]) && alnum.test(scope[s])) s--;
  while (e < scope.length && alnum.test(scope[e]) && alnum.test(scope[e - 1])) e++;
  const marked = scope.slice(s, e);
  if (!marked || !alnum.test(marked)) return null;
  if (s === 0 && e === scope.length) return null; // whole scope → not a mark
  const prefix = scope.slice(0, s);
  const suffix = scope.slice(e);
  let cls: string; let kind: PatternGroup['kind'];
  if (/^[A-Za-z]+$/.test(marked)) { cls = '[A-Za-z]+'; kind = 'letters'; }
  else if (/^\d+$/.test(marked)) { cls = '\\d+'; kind = 'digits'; }
  else { cls = '[A-Za-z0-9]+'; kind = 'alnum'; }
  const source = `${escapeRe(prefix)}(?<g1>${cls})${escapeRe(suffix)}`;
  return { source, groups: [{ name: 'g1', sample: marked, kind, classRe: cls }], token: scope };
}

/**
 * Grow a `[relStart, relEnd)` range to its whole alnum-run edges within `scope`, the same way
 * `markedValueShape` does — a half-word mark snaps to a full `[A-Za-z0-9]` boundary, since a
 * mask ending mid-run would match nothing. Returns null if the grown run has no alnum.
 */
function growAlnumRange(scope: string, relStart: number, relEnd: number): { start: number; end: number } | null {
  if (relStart >= relEnd || relStart < 0 || relEnd > scope.length) return null;
  const alnum = /[A-Za-z0-9]/;
  let s = relStart, e = relEnd;
  while (s > 0 && alnum.test(scope[s - 1]) && alnum.test(scope[s])) s--;
  while (e < scope.length && alnum.test(scope[e]) && alnum.test(scope[e - 1])) e++;
  if (s >= e || !alnum.test(scope.slice(s, e))) return null;
  return { start: s, end: e };
}

/**
 * Mark SEVERAL runs inside one selection as the parts to replace — the multi-select form of
 * `markedValueShape`. The reviewer taps `AssociatedAdminUnits` and `fbd713153f3e` (or drags one
 * and taps the other) inside `"AssociatedAdminUnits": ["…fbd713153f3e"]` and both become capture
 * groups (`g1`, `g2`, … left to right) while everything between them stays literal, so the shape
 * matches this exact context and replaces only the chosen runs.
 *
 * Each range is grown to its whole alnum run, then overlapping/duplicate ranges are merged, so a
 * chip and a drag that land on the same run collapse into one group. Refused (null) when nothing
 * survives, or when the single surviving run is the whole scope (that is the plain whole-value
 * pick, not a part). `ranges` index into `scope`.
 */
export function markedValueShapeMulti(
  scope: string,
  ranges: { start: number; end: number }[],
  mode: 'shape' | 'exact' = 'shape',
): ShapePattern | null {
  if (!scope || !ranges.length) return null;
  const grown = ranges
    .map(r => growAlnumRange(scope, r.start, r.end))
    .filter((r): r is { start: number; end: number } => !!r)
    .sort((a, b) => a.start - b.start);
  if (!grown.length) return null;
  // Merge overlapping/touching runs so two gestures on the same run become one group.
  const merged: { start: number; end: number }[] = [];
  for (const r of grown) {
    const last = merged[merged.length - 1];
    if (last && r.start <= last.end) last.end = Math.max(last.end, r.end);
    else merged.push({ ...r });
  }
  if (merged.length === 1 && merged[0].start === 0 && merged[0].end === scope.length) return null;
  const groups: PatternGroup[] = [];
  let source = '';
  let cursor = 0;
  let gi = 1;
  for (const run of merged) {
    source += escapeRe(scope.slice(cursor, run.start));
    const marked = scope.slice(run.start, run.end);
    let kind: PatternGroup['kind'];
    if (/^[A-Za-z]+$/.test(marked)) kind = 'letters';
    else if (/^\d+$/.test(marked)) kind = 'digits';
    else kind = 'alnum';
    // 'shape' → a character class (`\d+`, `[A-Za-z]+`, `[A-Za-z0-9]+`) so ANY value of this
    // shape in this context is masked (the reviewer's "wildcards"); 'exact' → the run's own
    // literal so ONLY this value is masked here (their "exact match like 12345"). Both keep
    // the surrounding punctuation literal, which is what pins the match to this one place.
    const cls = mode === 'exact'
      ? escapeRe(marked)
      : kind === 'letters' ? '[A-Za-z]+' : kind === 'digits' ? '\\d+' : '[A-Za-z0-9]+';
    const name = `g${gi++}`;
    source += `(?<${name}>${cls})`;
    groups.push({ name, sample: marked, kind, classRe: cls });
    cursor = run.end;
  }
  source += escapeRe(scope.slice(cursor));
  return { source, groups, token: scope };
}

/**
 * The regex fragment a single shape group matches — `[A-Za-z]+` or `\d+`.
 *
 * The pick bar shows this on each option so the reviewer sees the actual regex before
 * choosing it, not just a friendly "numbers like 8196" label. Kept in lock-step with the
 * fragments `decomposeShape` writes into `source`, so the chip and the applied regex agree.
 */
export function groupRegexFragment(group: PatternGroup): string {
  if (group.classRe) return group.classRe;
  return group.kind === 'digits' ? '\\d+' : group.kind === 'alnum' ? '[A-Za-z0-9]+' : '[A-Za-z]+';
}

/**
 * Grow a selection across joining punctuation so `4212` inside `bufbwjesfe[4212]:` becomes
 * the whole composite token the pattern is derived from.
 */
export function expandToShapeToken(text: string, start: number, end: number): string {
  if (start >= end) return '';
  const SHAPE = /[A-Za-z0-9[\](){}:./\-_@]/;
  let s = start, e = end;
  while (s > 0 && SHAPE.test(text[s - 1])) s--;
  while (e < text.length && SHAPE.test(text[e])) e++;
  // Stop at whitespace / quotes already (SHAPE excludes them). Trim trailing commas etc.
  return text.slice(s, e).replace(/^[,;]+|[,;]+$/g, '');
}

/**
 * One alphanumeric COMPONENT of a structured value, with its offsets into that value.
 * `15.20.4200.000` → four components; `BEUP281MB3649` → `BEUP`,`281`,`MB`,`3649`.
 */
export interface ValueComponent { text: string; start: number; end: number; kind: PatternGroup['kind']; }

/**
 * Break a composite value into the alphanumeric runs a reviewer could mask individually — the
 * pieces behind the "pick a piece" chips in the in-panel part picker.
 *
 * Splitting on every non-alnum separator (`. : - _ / space ( ) [ ]`) is deliberate: it is exactly
 * the granularity `markedValueShape` snaps a free drag to (it grows a mark to the whole alnum run),
 * so each component maps 1:1 to a clean, safe in-context mask. A version's `4200` becomes its own
 * chip instead of being reachable only as the whole `15.20.4200.000`.
 *
 * Returns `[]` for an atomic value (a single run) — there is nothing finer to offer. The offsets
 * are relative to `value`, so the caller can feed them straight to `markedValueShape(value, s, e)`.
 */
export function splitStructuredToken(value: string): ValueComponent[] {
  if (!value) return [];
  const out: ValueComponent[] = [];
  for (const m of value.matchAll(/[A-Za-z0-9]+/g)) {
    const text = m[0];
    const start = m.index ?? 0;
    // A lone digit / single char is not worth its own chip — it matches all over and is unsafe
    // as a standalone identity; the surrounding components carry the signal.
    if (text.length < 2 && !/[A-Za-z]/.test(text)) continue;
    const kind: PatternGroup['kind'] = /^[A-Za-z]+$/.test(text) ? 'letters' : /^\d+$/.test(text) ? 'digits' : 'alnum';
    out.push({ text, start, end: start + text.length, kind });
  }
  // Only a genuinely composite value (two or more runs) has pieces worth choosing between.
  return out.length >= 2 ? out : [];
}

/** Count non-overlapping matches of a shape across the sample. */
export function countShapeMatches(text: string, source: string): number {
  try {
    const re = new RegExp(source, 'g');
    let n = 0;
    for (const _ of text.matchAll(re)) n++;
    return n;
  } catch {
    return 0;
  }
}

  /**
   * Encode / decode a pattern pick for the extras box.
   *
   * Form: `re:<source>|g1+g2` — source is built by us (no raw `|` inside). Groups use `+`
   * rather than `,` because the extras box is itself comma-separated.
   */
export function encodePatternExtra(source: string, groupNames: string[]): string {
  const groups = groupNames.filter(Boolean).join('+');
  return `${PATTERN_TOKEN}${source}|${groups}`;
}

export function parsePatternExtra(token: string): { source: string; groupNames: string[] } | null {
  const raw = token.trim();
  if (!raw.toLowerCase().startsWith(PATTERN_TOKEN)) return null;
  const body = raw.slice(PATTERN_TOKEN.length);
  const bar = body.lastIndexOf('|');
  if (bar < 0) return null;
  const source = body.slice(0, bar);
  // `+` not `,` — the extras box is itself comma-separated, so a group list with commas
  // would be torn apart before parsePatternExtra ever saw it.
  const groupNames = body.slice(bar + 1).split(/[+]/).map(s => s.trim()).filter(Boolean);
  if (!source || !groupNames.length) return null;
  // Accept any valid capture-group identifier. Our own auto-shape picks name them g1, g2, …,
  // but a hand-written regex ("write your own regex") may name them anything —
  // `(?<test>\d+)` → group `test`. Reject only genuinely malformed names so a mistyped token
  // still fails loud rather than silently becoming a literal replace.
  if (!groupNames.every(g => /^[A-Za-z_$][\w$]*$/.test(g))) return null;
  return { source, groupNames };
}

/**
 * The named capture groups declared in a regex source, left-to-right and de-duplicated.
 *
 * These are the fields the "write your own regex" editor offers to mask: writing
 * `id=(?<test>\d+)` names one field, `test`. Lookbehind (`(?<=`, `(?<!`) is deliberately
 * NOT a capture group and is skipped. Pure and offline.
 */
export function listNamedGroups(source: string): string[] {
  const names: string[] = [];
  const seen = new Set<string>();
  for (const m of source.matchAll(/\(\?<(?![=!])([A-Za-z_$][\w$]*)>/g)) {
    if (!seen.has(m[1])) { seen.add(m[1]); names.push(m[1]); }
  }
  return names;
}

/**
 * Seed a "write your own regex" draft from a highlighted selection, so opening the editor
 * from a pick starts with a pattern that already extracts EXACTLY what the reviewer selected —
 * they only refine it. EXTRACTION only: every whitespace-separated run becomes its own named
 * capture group (`g1`, `g2`, …) so each is separately maskable; the whitespace between runs
 * becomes `\s+`.
 *
 * The capture-group body is the run's LITERAL text (regex-escaped), not a shape class. This is
 * the whole point: a shape seed like `(?<g1>\S+)` is unanchored — run against a real event it
 * matches the FIRST `\S+` anywhere (the leading IP), never the highlighted span, so the live
 * preview masks the wrong thing. Seeding the literal text anchors the pattern on the actual
 * selection, so what the reviewer highlighted is what lights up. They then generalise by hand
 * (turn `(?<g1>product_id=Goats)` into `product_id=(?<g1>\S+)`, drop a group to leave it as
 * context, etc.) — the same shape as a hand-written `GET\s/(?<ff>product)`.
 *
 * `this is test 1234` with `test 1234` selected → `(?<g1>test)\s+(?<g2>1234)`.
 * `product_id=Goats` selected → `(?<g1>product_id=Goats)` (one whitespace-free run, one group).
 *
 * Pure and offline. Returns '' for an empty/blank selection.
 */
export function regexFromSelection(selected: string): string {
  // Trim the edges so a stray leading/trailing space in the highlight doesn't anchor the
  // pattern on whitespace — the reviewer selected the tokens, not the gaps around them.
  const text = (selected ?? '').trim();
  if (!text) return '';
  let out = '';
  let group = 0;
  // Split into maximal whitespace / non-whitespace runs, in order.
  for (const part of text.match(/\s+|\S+/g) ?? []) {
    if (/^\s+$/.test(part)) { out += '\\s+'; continue; }
    group += 1;
    // Escape the literal so regex metacharacters in the selection (`.`, `?`, `&`, `(`, …)
    // match themselves — the seed must find the highlighted text verbatim, not treat it as a
    // pattern.
    out += `(?<g${group}>${escapeRe(part)})`;
  }
  return out;
}

export interface RegexGroupSample {
  /** The capture-group name — a field the reviewer can choose to mask. */
  name: string;
  /** A real value this group captured from the sample, for the pick UI (empty if none). */
  sample: string;
  /** How many matches captured a non-empty value for this group. */
  hits: number;
}

export interface RegexDraftInfo {
  /** Whether the source compiles as a regular expression. */
  valid: boolean;
  /** The compile error message when it does not. */
  error?: string;
  /** Named capture groups, in source order, each with an example capture and a hit count. */
  groups: RegexGroupSample[];
  /** How many times the whole pattern matched across the scanned sample. */
  matches: number;
}

/**
 * Describe a hand-written regex against the current sample, for the "write your own regex"
 * editor: does it compile, what named capture groups (fields) does it declare, a real
 * captured example per group, and how many times the whole pattern hits. It powers the
 * field checklist and the validity feedback; the before/after highlight is driven separately
 * by folding the pick into the plan.
 *
 * Pure, offline and bounded — scans at most `cap` matches so a broad pattern (e.g. `.`)
 * cannot lock the UI while the reviewer is still typing.
 */
export function describeRegexDraft(source: string, text: string, cap = 2000): RegexDraftInfo {
  const trimmed = source.trim();
  if (!trimmed) return { valid: false, groups: [], matches: 0 };
  let re: RegExp;
  try { re = new RegExp(trimmed, 'g'); }
  catch (err) { return { valid: false, error: err instanceof Error ? err.message : String(err), groups: [], matches: 0 }; }
  const names = listNamedGroups(trimmed);
  const samples = new Map<string, string>();
  const hits = new Map<string, number>();
  let matches = 0;
  // matchAll advances lastIndex on zero-width matches, so a group like `(?<x>\d*)` cannot
  // spin forever; the cap bounds a broad-but-non-empty pattern.
  for (const hit of text.matchAll(re)) {
    matches++;
    const groups = hit.groups || {};
    for (const name of names) {
      const value = groups[name];
      if (value == null || value === '') continue;
      hits.set(name, (hits.get(name) ?? 0) + 1);
      if (!samples.has(name)) samples.set(name, value);
    }
    if (matches >= cap) break;
  }
  return {
    valid: true,
    groups: names.map(name => ({ name, sample: samples.get(name) ?? '', hits: hits.get(name) ?? 0 })),
    matches,
  };
}

/**
 * Split the extras box into plain literals, whole-field picks, and shape patterns.
 *
 * One box rather than a second list, because that box is already where the UI promises a
 * picked value can be edited or removed again, and a field pick has to be undoable the same
 * way. `field:quoteNumber` is written by the button rather than typed, but it reads plainly
 * enough that deleting it is obvious — which is all that is being asked of the format.
 */
export function splitExtras(text: string): {
  literals: string[];
  fields: string[];
  patterns: { source: string; groupNames: string[] }[];
} {
  const literals: string[] = [];
  const fields: string[] = [];
  const patterns: { source: string; groupNames: string[] }[] = [];
  const classify = (token: string) => {
    if (!token) return;
    if (token.toLowerCase().startsWith(FIELD_TOKEN)) {
      const name = token.slice(FIELD_TOKEN.length).trim();
      if (name) fields.push(name);
      return;
    }
    const pat = parsePatternExtra(token);
    if (pat) { patterns.push(pat); return; }
    // A mistyped `re:…` without a valid group list must not become a literal replace —
    // that would try to replace the whole regex source string and do nothing useful.
    if (token.toLowerCase().startsWith(PATTERN_TOKEN)) return;
    literals.push(token);
  };
  // A pattern pick lives on its OWN line so its source may safely contain commas
  // (`\d{1,3}`, `{2,}`) — a hand-written regex from the "write your own regex" editor often
  // does, and a blind comma split would tear it apart. Everything else keeps the
  // comma-separated convention (pasted name lists, literals, field picks).
  for (const line of text.split('\n')) {
    const whole = line.trim();
    if (!whole) continue;
    if (whole.toLowerCase().startsWith(PATTERN_TOKEN)) { classify(whole); continue; }
    for (const raw of whole.split(',')) classify(raw.trim());
  }
  return { literals, fields, patterns };
}

/** What sanitising a whole field would touch: which values, and how often they occur. */
export function fieldCensus(text: string, canon: string): { values: Set<string>; occurrences: number } {
  const values = new Set<string>();
  let occurrences = 0;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    for (const { name, value } of fieldPairs(line)) {
      if (canonField(name) !== canon) continue;
      const v = value.trim().replace(/^["']|["']$/g, '');
      if (!v) continue;
      occurrences++;
      values.add(v);
    }
  }
  return { values, occurrences };
}

/* Characters that belong to one value. `\` is excluded deliberately: selecting inside
   `CORP\jsmith` should reach the account, not glue the domain and the account into a
   single literal — they are two identities and the DOMAIN\user shape has to survive. */
const TOKEN_CHAR = /[\w.$@-]/;

/**
 * Grow a selection to whole-token edges.
 *
 * Replacement is whole-token (`applySanitisation` brackets each literal with
 * `(?<![\w.$-])` / `(?![\w.$-])`), so a half-selected `acme` inside `acme-corp.com` would
 * match nothing, get dropped as a zero-hit entry, and vanish with no explanation. Growing
 * to the edges is also what the reviewer meant: they pointed at a value, not at a
 * substring of one.
 */
export function expandToToken(text: string, start: number, end: number): string {
  if (start >= end) return '';
  let s = start, e = end;
  while (s > 0 && TOKEN_CHAR.test(text[s - 1])) s--;
  while (e < text.length && TOKEN_CHAR.test(text[e])) e++;
  const grown = text.slice(s, e).replace(/^[.-]+|[.-]+$/g, '');
  // A run with no separators at all (a long JSON blob) would swallow the line; in that
  // case trust the reviewer's own edges instead.
  return grown.length > 120 ? text.slice(start, end).trim() : grown;
}

/**
 * Decide what a selection in the sample would add, and whether it can be added at all.
 *
 * Kept here rather than in the component so the refusals are testable: each one is a way
 * to corrupt a sample, not a style preference.
 */
export function describeSelection(opts: {
  text: string;
  start: number;
  end: number;
  entries: SanitiseEntry[];
  /** Fields already picked, so the offer is not repeated for one that is being replaced. */
  pickedFields?: string[];
  /**
   * The whole sample, when `text` is only the slice on screen.
   *
   * The offer names a number — "all 22 values of quoteNumber" — and a pick acts on the
   * whole sample, so counting the visible two hundred lines would promise a fraction of
   * what it does. Defaults to `text` for callers where they are the same.
   */
  censusText?: string;
  /**
   * A wider selection made just before this one, so a narrower highlight inside it can be
   * read as "mark this part of that". Indexes into `text`. When this selection is a strict
   * sub-range of `[scopeStart, scopeEnd)`, the candidate carries a `markMask` that keeps the
   * rest of the scope literal. Omit for the ordinary single-selection case.
   */
  scopeStart?: number;
  scopeEnd?: number;
}): SelectionCandidate | null {
  const { text, start, end, entries } = opts;
  const selected = text.slice(start, end);
  if (!selected.trim()) return null;

  /**
   * The field the selection sits in, if any, and what picking it would do.
   *
   * Worked out before any refusal, because it is what most of the refusals should be
   * offering instead. The old flow dead-ended a reviewer who highlighted `51015341` in
   * `quoteNumber=51015341` with "that is just a number" — true of the eight characters, and
   * useless, since the sample says right next to them exactly which eight characters they
   * are. The number is unsafe to replace on its own and the field is perfectly safe to
   * replace, and only one of those two facts was being reported.
   */
  const picked = new Set((opts.pickedFields || []).map(f => canonField(f)));
  const pair = fieldAt(text, start);
  let field: FieldPick | undefined;
  if (pair) {
    const canon = canonField(pair.name);
    const { values, occurrences } = fieldCensus(opts.censusText ?? text, canon);
    if (values.size) {
      /* Already handled counts as covered however it got that way. `esn` is found by its
         own name and replaced everywhere, and offering to sanitise it again would have the
         reviewer fixing something that is not broken — and then wondering why the count in
         the button never showed up in the list. */
      const going = new Set(entries.filter(e => e.enabled).map(e => e.original));
      field = {
        name: pair.name, canon,
        distinct: values.size,
        occurrences,
        covered: picked.has(canon) || [...values].every(v => going.has(v)),
      };
    }
  }

  /* Shape from the composite token around the selection — independent of whether the
     literal alone is safe. `4212` inside `bufbwjesfe[4212]:` is a bad literal and a good
     pattern group; both facts have to be available to the pick bar. */
  const shapeToken = expandToShapeToken(text, start, end);
  const shape = shapeToken ? decomposeShape(shapeToken) : null;
  const census = opts.censusText ?? text;
  const pattern: PatternPick | undefined = shape && shape.groups.length >= 1
    ? { shape, matches: countShapeMatches(census, shape.source) }
    : undefined;

  /* Label-anchored value mask: keep `inode<delim>`, mask only the value. Built from the
     reviewer's own selection when the label is in it (`inode=5330950`, `inode: 5330950`,
     `"MailboxOwnerSid": "S-1-…"`), and — when they grabbed ONLY the value, which is what a
     double-click on `ppid=27477` (or on a JSON value) gives — rebuilt from the pair around the
     caret so the value alone still offers "keep the label, replace the value". Attached to
     every outcome so the pick bar can offer it even when the bare value is refused as "just a
     number".

     The rebuild tries the JSON-quoted, JSON-bare and `key=value` forms in turn: fieldPairs
     strips the quotes off a JSON key, so the caret's own line does not say which shape it was.
     A 0-match reconstruction is dropped, so the wrong shape simply falls through to the right
     one and a wrong-delimiter guess never surfaces a mask that would replace nothing. */
  let valueMask: PatternPick | undefined;
  // A JSON value the selection lands on wins first: it anchors on the real key from the line, so
  // grabbing the value — with its quotes, or just the text inside — masks the WHOLE value and
  // keeps the key literal, instead of the value's own first word being read as a label (or the
  // value being shredded into per-run fragments). See enclosingJsonValueMask.
  // `explicit: true` — the reviewer highlighted this span deliberately, so a plain-word value
  // in it is theirs to mask; the class guards only protect the speculative rebuild path below.
  const lvJson = enclosingJsonValueMask(text, start, end);
  // Only tried when there is no JSON-value anchor: this is the "the reviewer selected the whole
  // `a=b`" case, which drives `valueMaskFromSelection` so the UI keeps offering the whole pair.
  const lvFromSelection = lvJson ? null : labelValueShape(selected, { explicit: true });
  const lvDirect = lvJson ?? lvFromSelection;
  let valueMaskFromSelection = false;
  if (lvDirect) {
    valueMask = { shape: lvDirect, matches: countShapeMatches(census, lvDirect.source) };
    valueMaskFromSelection = lvDirect === lvFromSelection;
  } else if (pair) {
    for (const recon of [`"${pair.name}": "${pair.value}"`, `"${pair.name}": ${pair.value}`, `${pair.name}=${pair.value}`]) {
      const lvField = labelValueShape(recon);
      const matches = lvField ? countShapeMatches(census, lvField.source) : 0;
      if (lvField && matches > 0) { valueMask = { shape: lvField, matches }; break; }
    }
  }

  /* Mark inside a scope: a narrower highlight fully within the previous selection means
     "replace only this run, in that context". Built from the scope text so the rest stays
     literal; dropped if it matches nothing (a scope no longer on screen). Offered on every
     outcome — a marked run that is itself "just a number" is exactly what the mask makes
     safe, because the surrounding literal pins it to this one place. */
  let markMask: PatternPick | undefined;
  const { scopeStart, scopeEnd } = opts;
  if (scopeStart !== undefined && scopeEnd !== undefined
    && start >= scopeStart && end <= scopeEnd && (start > scopeStart || end < scopeEnd)) {
    const scopeText = text.slice(scopeStart, scopeEnd);
    const mm = markedValueShape(scopeText, start - scopeStart, end - scopeStart);
    const matches = mm ? countShapeMatches(census, mm.source) : 0;
    if (mm && matches > 0) markMask = { shape: mm, matches };
  }

  const fail = (reason: string): SelectionCandidate =>
    ({ literal: selected.trim(), selected, ok: false, reason, field, pattern, valueMask, valueMaskFromSelection, markMask });

  // One alias replaces one value. A selection across lines is not a value, and replacing
  // it would take the newline with it and merge two events into one.
  if (/[\n\r]/.test(selected)) return fail('Select a single value — a selection spanning lines is not one.');

  const literal = expandToToken(text, start, end);
  if (!literal) return fail('Nothing selectable there.');
  if (literal.length < 2) return fail('Too short to replace safely — it would match all over the sample.');
  /* A bare number is unsafe as a literal wherever it came from: `443` is a port, a counter
     and an ID on the same line, and replacing every one of them corrupts all three. What
     makes it safe is the field name in front of it, so that is what gets offered — the
     refusal only stands when there is no field to anchor to. A pattern offer can still
     stand: `name[443]:` only replaces 443 inside that shape. */
  if (/^\d+$/.test(literal)) {
    return fail(field
      ? `“${literal}” on its own is just a number — replacing every one of them would corrupt ports, counters and IDs. Sanitise it by its field instead.`
      : pattern
        ? `“${literal}” on its own is just a number — use the shape buttons to replace it only inside “${shapeToken}”-like tokens.`
        : `“${literal}” is just a number — replacing it would corrupt ports, counters and IDs. There is no field name around it to pin it down.`);
  }
  if (NEVER.has(literal.toLowerCase())) return fail(`“${literal}” is a structural placeholder, not an identity.`);

  const already = entries.find(e => e.original === literal);
  if (already) return { literal, selected, ok: false, reason: `Already covered — it becomes “${already.alias}”.`, field, pattern, valueMask, valueMaskFromSelection, markMask };

  const inside = entries.find(e => e.original.includes(literal) && e.original !== literal);
  if (inside) return { literal, selected, ok: false, reason: `Already covered as part of “${inside.original}”.`, field, pattern, valueMask, valueMaskFromSelection, markMask };

  return { literal, selected, ok: true, field, pattern, valueMask, valueMaskFromSelection, markMask };
}

/**
 * One plain-language masking choice, ready to render as a radio option.
 *
 * `describeSelection` returns up to four different ways to mask what the reviewer highlighted
 * (a whole field, a label-anchored value, one part of a composite token, the exact literal),
 * and the old pick bar showed all of them at once as a wall of regex-fragment buttons that no
 * one could tell apart. `buildSanitiseChoices` turns that same candidate into an ORDERED,
 * de-duplicated list of intents — "Every pid= value", "Only pid=27480", "Just the number
 * inside sshd[…]" — each with a one-line consequence and the exact extras-box token it writes,
 * with exactly one marked `recommended`. Both panels render this identically, so the guided
 * question stays in parity by construction.
 */
export interface SanitiseChoice {
  /** Stable id for the radio group and for tests. */
  id: string;
  /** The action in the reviewer's words, e.g. `Every “pid=” value`. */
  label: string;
  /** What it does / what it leaves alone, shown under the label. */
  detail: string;
  /**
   * How this choice MATCHES — the second question the reviewer is really asking, surfaced as
   * a badge so it is visible without reading the detail:
   *   - `format` → any value in this position, whatever it is (a field / label-anchored mask).
   *   - `exact`  → only this one literal text, wherever it appears.
   *   - `part`   → only a sub-run of a composite token (a marked run or one shape group).
   */
  match: 'format' | 'exact' | 'part';
  /** The token this appends to the extras box when applied. */
  token: string;
  /** Which review group to open so the new row is visible. */
  openGroup: 'picked' | 'custom';
  /** The safe default — pre-selected, and starred in the UI. Exactly one per list. */
  recommended?: boolean;
}

/** `n places` / `1 place` for a match count, or '' when the count is unknown. */
function placeNote(n: number): string {
  return n > 1 ? `${n} places` : n === 1 ? '1 place' : '';
}

/** The label part of a `label<delim>value` shape token, keeping its delimiter (`pid=`, `inode:`). */
function valueMaskLabel(shape: ShapePattern): string {
  const value = shape.groups[0]?.sample ?? '';
  const at = value ? shape.token.lastIndexOf(value) : -1;
  const head = at > 0 ? shape.token.slice(0, at) : shape.token;
  // Drop trailing space and the value's opening quote so a JSON head `"MailboxOwnerSid": "`
  // reads `"MailboxOwnerSid":`; a kvp head `pid=` is left untouched (no trailing quote/space).
  return head.replace(/\s*["']?\s*$/, '') || shape.token;
}

/**
 * Derive the ordered, guided masking choices for a selection.
 *
 * Priority (most specific first): a marked run inside a wider scope → a label-anchored value
 * mask (or, when there is no value mask, the whole field) → each variable part of a composite
 * token → every part at once → the exact literal. The composite-part offers are SUPPRESSED
 * when a value mask exists: `pid=27480` should read "every pid= value / only pid=27480", not
 * also offer to mask `pid` and `27480` as two unrelated runs. The recommended default is the
 * most specific safe intent: a marked run, else the value/field mask, else the starred
 * identifier part (or the number, in a bracketed token), else the first offer.
 */
export function buildSanitiseChoices(sel: SelectionCandidate | null): SanitiseChoice[] {
  if (!sel) return [];
  const choices: SanitiseChoice[] = [];

  if (sel.markMask) {
    const g = sel.markMask.shape.groups[0];
    const where = placeNote(sel.markMask.matches);
    choices.push({
      id: 'mark',
      label: `Only the marked “${g.sample}”`,
      detail: `just where it sits inside “${sel.markMask.shape.token}”, nothing else${where ? ` · ${where}` : ''}`,
      match: 'part',
      token: encodePatternExtra(sel.markMask.shape.source, ['g1']),
      openGroup: 'picked',
    });
  }

  if (sel.valueMask) {
    const label = valueMaskLabel(sel.valueMask.shape);
    const where = placeNote(sel.valueMask.matches);
    choices.push({
      id: 'valueMask',
      label: `Every “${label}” value`,
      detail: `mask any value of “${label}”, whatever it is — the label stays${where ? ` · ${where}` : ''}`,
      match: 'format',
      token: encodePatternExtra(sel.valueMask.shape.source, ['g1']),
      openGroup: 'picked',
    });
  } else if (sel.field && !sel.field.covered) {
    const f = sel.field;
    choices.push({
      id: 'field',
      label: f.distinct === 1 ? `The one value of “${f.name}”` : `All ${f.distinct} values of “${f.name}”`,
      detail: `mask any value of “${f.name}”, whatever it is — each replaced consistently`,
      match: 'format',
      token: `${FIELD_TOKEN}${f.name}`,
      openGroup: 'picked',
    });
  }

  let preferredPartId: string | undefined;
  if (sel.pattern) {
    const { shape, matches } = sel.pattern;
    const where = placeNote(matches);
    /* A pure snake_case name (`BI_DEV_USER`, `svc_account`) is ONE identity: the reviewer never
       means "just BI" or "just DEV", and its underscores are not a boundary they should have to
       reason about. Collapse it into a SINGLE whole-token shape mask — "any value shaped like
       this" — instead of one confusing per-segment run each. Offered EVEN when a value mask
       exists, because the two catch different things: the value mask is position-anchored
       (`every value after "user"`) while this one is position-free (it also masks `BI_DEV_USER`
       where it appears with no label in front). */
    const snake = shape.groups.length > 1 && /^[A-Za-z0-9]+(?:_[A-Za-z0-9]+)+$/.test(shape.token);
    if (snake) {
      choices.push({
        id: 'shape-all',
        label: `Any value shaped like “${shape.token}”`,
        detail: `mask anything of this shape wherever it appears — “${shape.token}” → random, keep the underscores${where ? ` · ${where}` : ''}`,
        match: 'part',
        token: encodePatternExtra(shape.source, shape.groups.map(g => g.name)),
        openGroup: 'picked',
      });
      preferredPartId = 'shape-all';
    } else if (!sel.valueMask || sel.valueMaskFromSelection) {
      /* Per-part offers when there is no cleaner label-anchored mask — otherwise a value the
         caret merely lands in (`pid=27480`) would surface "just the pid word" and "just the
         27480 number" alongside the value mask, the noise the redesign removes. BUT when the
         reviewer highlighted the WHOLE `a=b` themselves (`valueMaskFromSelection`), the parts
         they selected are theirs to refine, so keep offering them next to the value mask. */
      for (const g of shape.groups) {
        const noun = g.kind === 'alnum' ? 'identifier' : g.kind === 'digits' ? 'number' : 'word';
        choices.push({
          id: `part:${g.name}`,
          label: `Just the ${noun} in “${shape.token}”-like tokens`,
          detail: `e.g. “${g.sample}” → random, keep the punctuation around it${where ? ` · ${where}` : ''}`,
          match: 'part',
          token: encodePatternExtra(shape.source, [g.name]),
          openGroup: 'picked',
        });
      }
      const star = shape.groups.find(g => g.recommend) ?? shape.groups.find(g => g.kind === 'digits') ?? shape.groups[0];
      if (star) preferredPartId = `part:${star.name}`;
      if (shape.groups.length > 1) {
        choices.push({
          id: 'shape-all',
          label: `Every part of “${shape.token}”`,
          detail: `all ${shape.groups.length} variable parts at once, keep the punctuation`,
          match: 'part',
          token: encodePatternExtra(shape.source, shape.groups.map(g => g.name)),
          openGroup: 'picked',
        });
      }
    }
  }

  if (sel.ok) {
    const others = choices.length > 0;
    choices.push({
      id: 'literal',
      label: others ? `Only “${sel.literal}”` : `Replace “${sel.literal}”`,
      detail: others
        ? 'match only this exact text, wherever it appears — leaves similar values alone'
        : 'match this exact text everywhere it appears in the sample',
      match: 'exact',
      token: sel.literal,
      openGroup: 'custom',
    });
  }

  if (choices.length) {
    const prefer =
      choices.find(c => c.id === 'mark')
      ?? choices.find(c => c.id === 'valueMask' || c.id === 'field')
      ?? (preferredPartId ? choices.find(c => c.id === preferredPartId) : undefined)
      ?? choices[0];
    prefer.recommended = true;
  }
  return choices;
}

/**
 * Whether this selection can be NARROWED by highlighting a part of it — the signal the wizard
 * uses to offer the "mask only part of it" second step (the scope→mark gesture).
 *
 * True when the selected value is a COMPOSITE: its shape breaks into more than one variable run
 * (`BEUP281MB3649 (15.20.4200.000)` → a word + a version), so masking the whole value is more
 * than the reviewer may want and highlighting one run inside it produces a `markMask`. A single
 * atomic value (`bob`, one number) has nothing finer to pick, so the step is not offered.
 *
 * Once a mark is already active (`sel.markMask`) the refinement has happened — the mark choice
 * is in the list — so there is nothing more to prompt.
 */
export function canRefineSelection(sel: SelectionCandidate | null): boolean {
  if (!sel || sel.markMask) return false;
  return !!sel.pattern && sel.pattern.shape.groups.length > 1;
}

// ---------------------------------------------------------------------------
// The guard: one place where sample text is allowed to become prompt text
// ---------------------------------------------------------------------------

export class UnsanitisedSampleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsanitisedSampleError';
  }
}

/**
 * The ONLY way the wizard should turn its sample into a snippet for an AI prompt.
 *
 * Every call site used to write `sampleEvents.split('\n').slice(0, 15).join('\n')` for
 * itself, which meant there was no single place where the decision "may this leave the
 * building?" could be made or found. A button that the reviewer has to remember to press
 * is not a policy; this is.
 *
 * Throws rather than returning empty. A silent empty snippet would make the AI answer
 * confidently about nothing, and the resulting pack would be quietly worthless — a loud
 * failure that names the fix is the kinder outcome.
 */
/**
 * Which sample sources are customer data.
 *
 * Only these four carry events from the user's estate. A reference/vendor sample is
 * public, and an AI-generated one came out of the model in the first place — gating those
 * would block flows that never had a privacy question, and a guard that blocks safe work
 * is a guard people switch off.
 */
export function sampleNeedsSanitising(sourceMode: string): boolean {
  return sourceMode === 'upload' || sourceMode === 'existing'
    || sourceMode === 'paste' || sourceMode === 'live-capture';
}

export function aiSampleSnippet(opts: {
  sampleEvents: string;
  /** `WizardState.sourceMode` — decides whether this is customer data at all. */
  sourceMode: string;
  /** `WizardState.sampleSanitised` — granted for this exact text and cleared on change. */
  sanitised: boolean | undefined;
  /** `QualitySettings.requireSanitisedSamples`. */
  required: boolean;
  lines?: number;
}): string {
  const { sampleEvents, sourceMode, sanitised, required, lines = 15 } = opts;
  if (required && sampleNeedsSanitising(sourceMode) && sampleEvents.trim() && !sanitised) {
    throw new UnsanitisedSampleError(
      'These events have not been sanitised, and sending un-sanitised sample data to the AI provider is turned off. '
      + 'Use “Sanitize sample” on the source step to replace hostnames, usernames and IP addresses locally, '
      + 'then run this again. (Settings → “Require sanitised samples” controls this.)');
  }
  return sampleEvents.split('\n').slice(0, lines).join('\n');
}

// ---------------------------------------------------------------------------
// Summary for the UI and the audit line
// ---------------------------------------------------------------------------

export function summariseSanitisation(entries: SanitiseEntry[]): string {
  const on = entries.filter(e => e.enabled);
  if (!on.length) return 'nothing replaced';
  const byKind = new Map<string, number>();
  for (const e of on) {
    const label = e.kind === 'ipv4' || e.kind === 'ipv6' ? 'IP address'
      : e.kind === 'fqdn' ? 'hostname' : e.kind === 'mac' ? 'MAC address'
      : e.kind === 'custom' ? 'custom literal' : e.kind;
    byKind.set(label, (byKind.get(label) || 0) + 1);
  }
  return [...byKind.entries()]
    .map(([k, n]) => `${n} ${k}${n === 1 ? '' : k.endsWith('s') ? '' : 's'}`)
    .join(', ');
}
