// ============================================================================
// secret-rule-filter.ts — classify + filter a secret / sensitive-data rule library
// ============================================================================
//
// The sanitiser detects live credentials and other sensitive data by matching each line
// against a library of rules — a regex plus up to six "context keywords". The library is a
// public-source set (`config/bundled-secret-rules.json`): patterns adapted from gitleaks and
// Microsoft Presidio (both MIT) plus vendor-published token shapes, so nothing proprietary is
// carried and the Sample Sanitizer can publish its source for review.
//
// A raw library is not usable as-is, and the judgement about which rules are SAFE has to be
// shared between the loader that installs them and the audit that validates the file. Both
// call `filterSecretRules`, so they can never disagree about what "usable" means.
//
// WHY THE LIBRARY IS FILTERED, NOT USED WHOLESALE
//
// A blunt secret rule would replace whatever it matches and not care what the event looks
// like afterwards. We cannot: the sample is *scored* against the pipeline we generate, so a
// false positive that eats a delimiter or a field name yields a wrong pack with no visible
// cause. Two kinds of rule are therefore dropped:
//
//   1. Classes our own tiers already own — IP, MAC, URL, email. Ours are class- and
//      shape-preserving (a private IP stays private, in its own /24); a bare regex would be a
//      regression, not an improvement.
//   2. Rules whose regex is nothing but a character class and a length, e.g.
//      `/[a-zA-Z0-9@\.]{8,}/` or `/[a-zA-Z0-9_]{1,50}=[a-zA-Z0-9]{1,200}/` (which matches
//      every key=value pair in a syslog line). Context keywords can make these usable when
//      the answer is "redact the event"; they are not enough here, where a single stray
//      match corrupts the thing we measure against.
//
// What survives is judged by the DISCRIMINATOR in the pattern itself:
//   literal    — carries a distinctive literal run: `AKIA`, `-----BEGIN`, `postgres://`,
//                `sk-`. Trustworthy on the pattern alone.
//   structural — several quantified runs joined by literal separators, like a JWT's three
//                dot-separated segments or `user:pass@host`. Trustworthy WITH a keyword.
//   numeric    — digits only, with word boundaries: a card number, an SSN, a national ID.
//                Trustworthy WITH a keyword, and safe in a way the alphanumeric blobs are
//                not — a digit run cannot be mistaken for a hostname, a base64 token or a
//                hex hash, which is exactly how the dropped rules do damage.
//   structured — SEVERAL character classes in a fixed sequence, at least one of them
//                restricted to digits or a single letter case: an IBAN (`[A-Z]{2}[0-9]{2}
//                [A-Z0-9]{11,30}`), a Spanish DNI (`[0-9]{8}[A-Z]`), an Italian codice
//                fiscale, a UK NINo, an EU VAT number. These carry real structure — a fixed
//                country prefix and fixed-length segments — so they are far more than "a
//                class and a length", yet they are alphanumeric so `numeric` cannot hold
//                them. Trustworthy WITH a keyword, exactly like `numeric`. The restricted-
//                class requirement is the line against the loose blobs: a hex hash is ONE
//                class, and `key=value` is two BROAD classes (both admit upper+lower+digit),
//                so neither qualifies.
//   loose      — one alphanumeric character class and a length, or several broad ones.
//                Dropped. This is where `[a-f0-9]{40}` lives, which matches every git SHA in
//                a log, `[a-f0-9]{32}` (every MD5), and `[a-zA-Z0-9_]{1,50}=[a-zA-Z0-9]{1,200}`
//                (every key=value pair).
//
// No imports: this is pure string/regex analysis, so it is reachable from the AI-free
// sanitizer build and from a plain Node script alike.

/** A rule as the bundled library stores it (same wire shape a rules endpoint would return). */
export interface SecretRuleInput {
  id?: string;
  lib?: string;
  regex?: string;
  rulesets?: string[];
  contextKeywords?: { keyword?: string }[];
}

export type SecretPrecision = 'literal' | 'structural' | 'numeric' | 'structured';

/** A rule in the shape detection consumes. */
export interface SecretRule {
  id: string;
  regex: string;
  anchors: string[];
  precision: SecretPrecision;
  rulesets?: string[];
  discriminator?: string;
}

export interface SecretFilterResult {
  rules: SecretRule[];
  liveTotal: number;
  droppedOurs: string[];
  droppedLoose: string[];
  droppedUnparseable: string[];
}

/**
 * Classes the sanitiser's own tiers detect and replace better than a bare regex can,
 * because they are rebuilt rather than blanked: an IP keeps its scope, an FQDN keeps its
 * label count, a user keeps its `DOMAIN\` prefix. A second, blunter opinion about values we
 * already handle correctly would only regress them.
 */
const OURS_ALREADY = /^(ipv4_address|ipv6_address|standard_mac_address|http_url|www_url|email)$/;

/**
 * Rule ids, normalised to the snake_case key form.
 *
 * A library may key a rule `aba_routing_number` and also carry a display name
 * (`ABA Routing Number`); normalising first makes the filter independent of which form an
 * id arrives in, and keeps stored ids stable so an audit's NEW/CHANGED diff stays meaningful.
 */
export function canonSecretRuleId(id: string): string {
  return String(id || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

/** Strip the `/…/flags` wrapper a pattern is stored in. */
export function splitRuleRegex(literal: string): { body: string; flags: string } | null {
  const m = String(literal || '').match(/^\/(.*)\/([gimsuy]*)$/s);
  return m ? { body: m[1], flags: m[2] } : null;
}

/**
 * The longest run of plain literal characters in a pattern — ignoring anything inside a
 * character class, and stopping at metacharacters. `AKIA-?[0-9A-Z]{16}` yields `AKIA`;
 * `[a-zA-Z0-9_\/]{16,}` yields nothing.
 */
export function longestLiteralRun(body: string): string {
  let best = '', run = '';
  const flush = () => { if (run.length > best.length) best = run; run = ''; };
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '\\') {
      const next = body[i + 1];
      // An escaped punctuation character is still a literal the data must contain; an
      // escaped letter is a class shorthand (\d, \w, \b) and is not.
      if (next && /[.\-/:@_+]/.test(next)) run += next; else flush();
      i++;
      continue;
    }
    // Character classes and quantifier braces contribute nothing. Skipping the BRACE
    // CONTENTS is the point: reading `{1,200}` character by character used to leave `200`
    // sitting in the run, so every rule with a long upper bound looked like it carried a
    // literal discriminator.
    if (c === '[' || c === '{') {
      flush();
      const close = c === '[' ? ']' : '}';
      let j = i + 1;
      while (j < body.length && body[j] !== close) { if (body[j] === '\\') j++; j++; }
      i = j;
      continue;
    }
    // Group openers, alternation, anchors: structure, not content.
    if (c === '(') {
      flush();
      const ahead = body.slice(i + 1);
      const prefix = ahead.match(/^\?(?:<[A-Za-z_][A-Za-z0-9_]*>|:|=|!|<=|<!)/);
      if (prefix) i += prefix[0].length;
      continue;
    }
    if (/[)|^$]/.test(c)) { flush(); continue; }
    if (/[A-Za-z0-9_:@/.\-+]/.test(c)) {
      // A quantifier applies to the character before it, so that character is optional and
      // cannot be relied on as a discriminator.
      const q = body[i + 1];
      if (q === '?' || q === '*' || q === '{') { flush(); i += q === '{' ? 0 : 1; continue; }
      run += c;
      continue;
    }
    flush();
  }
  flush();
  return best;
}

/** How many quantified runs the pattern has, i.e. how much shape it insists on. */
export function quantifiedSegments(body: string): number {
  return (body.match(/\{\d+(?:,\d*)?\}|[+*]/g) || []).length;
}

/**
 * The pattern with every character class emptied.
 *
 * Structure has to be judged on the separators the DATA must contain, not on characters
 * that merely happen to appear inside a class. `[a-zA-Z0-9_]{1,50}=[a-zA-Z0-9]{1,200}`
 * looked structural only because the `-` in the range `a-z` was read as a separator — and
 * that rule matches every `key=value` pair in a syslog line.
 */
export function stripClasses(body: string): string {
  return body.replace(/\[(?:[^\]\\]|\\.)*\]/g, '');
}

/**
 * True when the pattern can only ever match digits and separators — `\b4\d{15}\b`,
 * `\b3[47][0-9]{13}\b`, `\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b`. Checked by removing every
 * construct that admits a digit or a separator and seeing whether any letter class is left.
 */
export function digitsOnly(body: string): boolean {
  // Any class that can admit a letter disqualifies the pattern outright.
  const classes = body.match(/\[(?:[^\]\\]|\\.)*\]/g) || [];
  if (classes.some(c => /[a-zA-Z]/.test(c.replace(/\\[dsw]/gi, '')))) return false;
  const stripped = body
    .replace(/\[(?:[^\]\\]|\\.)*\]/g, '')  // the classes, now known to be digit-only
    .replace(/\\[dbs]/g, '')               // \d \b \s
    .replace(/\{\d+(?:,\d*)?\}/g, '')      // quantifiers
    .replace(/[()|?*+^$\-.\s\\/]/g, '')    // grouping, alternation, literal separators
    .replace(/\d/g, '');                   // literal digits
  return stripped.length === 0;
}

/**
 * Count the character-class runs in a pattern and how many are RESTRICTED.
 *
 * A class is "broad" when it admits lowercase AND uppercase AND a digit — `[a-zA-Z0-9_]`,
 * `\w` — the shape a token or a hash takes. A class is "restricted" when it is missing at
 * least one of those — digits only (`[0-9]`, `\d`), one letter case (`[A-Z]`), or letters
 * with no digits. `structured` needs SEVERAL classes AND at least one restricted one:
 * that is what an IBAN or a national id has and a hex blob or a `key=value` pair does not
 * (a hash is one class; a cookie is two broad ones).
 */
export function characterClassRuns(body: string): { total: number; restricted: number } {
  const classes = body.match(/\[(?:[^\]\\]|\\.)*\]/g) || [];
  let restricted = 0;
  for (const c of classes) {
    const inner = c.slice(1, -1);
    // Treat \w as admitting every case + digit; \d as a digit only.
    const admitsWord = /\\w/i.test(inner);
    const lower = admitsWord || /(?:^|[^\\])[a-z]/.test(inner);
    const upper = admitsWord || /(?:^|[^\\])[A-Z]/.test(inner);
    const digit = admitsWord || /(?:^|[^\\])[0-9]/.test(inner) || /\\d/.test(inner);
    if (!(lower && upper && digit)) restricted++;
  }
  // `\d` outside a class is a restricted run too (a bare digit sequence between letters).
  const digitShorthands = (body.replace(/\[(?:[^\]\\]|\\.)*\]/g, '').match(/\\d/g) || []).length;
  return { total: classes.length + digitShorthands, restricted: restricted + digitShorthands };
}

export function classifySecretRule(rule: SecretRuleInput): { precision: SecretPrecision | 'loose' | 'unparseable'; literal: string } {
  const parsed = splitRuleRegex(rule.regex || '');
  if (!parsed) return { precision: 'unparseable', literal: '' };
  const { body } = parsed;
  const literal = longestLiteralRun(body);
  const anchors = (rule.contextKeywords || []).length;
  // Three or more literal characters is a real discriminator: data either contains `AKIA`
  // or it does not. Two would let `0x` or `::` through, which is not evidence of anything.
  if (literal.length >= 3) return { precision: 'literal', literal };
  // Several quantified runs held together by separators is a shape, not just a length —
  // a JWT's `xxx.yyy.zzz`, a `user:pass@host` URI. Usable, but only with a keyword.
  const skeleton = stripClasses(body);
  if (quantifiedSegments(body) >= 2 && /[.\-/:@]/.test(skeleton)) return { precision: 'structural', literal };
  // A digit run beside the word "card" or "ssn" is evidence. Without a keyword it is just
  // a number, so these are worthless unless there is something to anchor on.
  if (anchors > 0 && digitsOnly(body) && /\\b|\(\?<!/.test(body)) return { precision: 'numeric', literal };
  // Several fixed-length classes, at least one restricted — an IBAN, a DNI, a codice
  // fiscale. As trustworthy as `numeric` WITH a keyword, and dropped without one. The
  // restricted-class gate is what keeps the hex/blob rules out (see characterClassRuns).
  const runs = characterClassRuns(body);
  if (anchors > 0 && runs.total >= 2 && runs.restricted >= 1) return { precision: 'structured', literal };
  return { precision: 'loose', literal };
}

/** The shape detection consumes. Keyword list flattened — the library nests each in an object. */
export function storedSecretRule(rule: SecretRuleInput, cls: { precision: SecretPrecision; literal: string }): SecretRule {
  return {
    id: canonSecretRuleId(rule.id || ''),
    regex: String(rule.regex || ''),
    anchors: (rule.contextKeywords || []).map(k => k.keyword || '').filter(Boolean),
    rulesets: (rule.rulesets || []).slice().sort(),
    precision: cls.precision,
    discriminator: cls.literal || undefined,
  };
}

/**
 * The whole library in, the usable rules out — the ONE definition of "usable".
 *
 * Sorted by id so two runs against the same library are byte-identical, which is what lets
 * an audit diff a fetch against its stored baseline without cosmetic churn.
 */
export function filterSecretRules(live: SecretRuleInput[]): SecretFilterResult {
  const rules: SecretRule[] = [];
  const droppedOurs: string[] = [];
  const droppedLoose: string[] = [];
  const droppedUnparseable: string[] = [];
  for (const rule of live || []) {
    const id = canonSecretRuleId(rule.id || '');
    const cls = classifySecretRule(rule);
    if (OURS_ALREADY.test(id)) { droppedOurs.push(id); continue; }
    if (cls.precision === 'unparseable') { droppedUnparseable.push(id); continue; }
    if (cls.precision === 'loose') { droppedLoose.push(id); continue; }
    rules.push(storedSecretRule(rule, { precision: cls.precision, literal: cls.literal }));
  }
  rules.sort((a, b) => a.id.localeCompare(b.id));
  return { rules, liveTotal: (live || []).length, droppedOurs, droppedLoose, droppedUnparseable };
}

/**
 * Compile the stored patterns for matching.
 *
 * A malformed pattern is skipped rather than thrown: one construct this JS engine rejects
 * must not take the whole sanitiser down. `g` is forced on because detection scans each line
 * with `exec` in a loop.
 */
export function compileSecretRules(rules: SecretRule[]): { rule: SecretRule; re: RegExp }[] {
  const out: { rule: SecretRule; re: RegExp }[] = [];
  for (const rule of rules || []) {
    const m = splitRuleRegex(rule.regex || '');
    if (!m) continue;
    try {
      const flags = m.flags.includes('g') ? m.flags : `${m.flags}g`;
      out.push({ rule, re: new RegExp(m.body, flags) });
    } catch { /* pattern this JS engine will not take — skip it, keep the rest */ }
  }
  return out;
}
