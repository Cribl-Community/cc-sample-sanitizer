/**
 * Source recognition + static parser layer — the LEAN, AI-free core shared by the
 * Pack Generator and the standalone Sample Sanitizer.
 *
 * This module was carved out of pack-builder.ts (Hard Rule 25): the sanitiser only
 * needs to RECOGNISE a source and build its PARSER, never the golden/XSIAM/Sentinel
 * destination machinery. Keeping that here means the sanitizer bundle imports only
 * the small parser data (datatype-parsers.json + the tiny source-sample-keys.json
 * name list), NOT golden-formats.json / xsiam-sources.json / source-samples.json.
 *
 * pack-builder.ts re-exports every public symbol below, so its importers are
 * unaffected. Never import pack-builder from here (would re-drag the heavy graph).
 * No AI provider imports may ever appear in this module or its reachable set.
 */
import datatypeParsersData from '../config/datatype-parsers.json';
import sourceSampleKeysData from '../config/source-sample-keys.json';

// Golden-path predicate is injected by pack-builder (which owns golden-formats.json)
// so getSupportedSourcetypeCatalog can flag golden-buildable sourcetypes WITHOUT this
// lean module importing the heavy golden spec. When unset (e.g. the sanitizer, which
// never reads the golden flag), the flag is simply false.
let _goldenPathPredicate: ((name: string, fmt: string) => boolean) | null = null;
export function setGoldenPathPredicate(fn: ((name: string, fmt: string) => boolean) | null): void {
  _goldenPathPredicate = fn;
  _supportedCatalog = null;
}

export interface ContractLintFinding {
  severity: 'error' | 'warning';
  stage: string;      // function description or id
  field: string;      // the unresolved field name being read
  expr: string;       // the offending expression (truncated)
  hint: string;
}

// --- Parser declaration contract ---------------------------------------------
// `getParserFieldNames` is the DECLARED contract: it is handed to the mapping AI
// as "the fields you may read" and every lint above trusts it. Nothing checked it
// against `getParserForSourcetype`, the parser that actually runs — so the two
// drifted, silently and badly:
//   • apache_access / nginx_access had NO case at all and fell through to
//     `default:`, which returns the *Cribl Search datatype* parser's field list
//     (clientip/request/remote_addr/time_local) while the hand-built parser that
//     really runs emitted client_ip/uri/timestamp. Neither set is canonical, so
//     nginx_access fed the golden CIM spec ZERO fields and apache_access three.
//   • palo_alto_* hand-listed `src_translated_ip`/`app`/`ip_protocol`/`rule` while
//     the CSV serde emits `nat_src_ip`/`application`/`protocol`/`rule_name`.
//   • cisco_esa declared `protocol`, which the golden CIM spec reads and no stage
//     produces — so the AI mapped an always-empty field.
// An OVERCLAIM is the harmful direction: it makes the mapping AI write reads that
// can never resolve. Under-declaring is merely a missed opportunity, so it is a
// warning. Fields the self-healing alias layer adds at build time (log_time, Rule 8)
// are never overclaims.
export const SELF_HEALED_FIELDS = new Set(['log_time', '_time']);

export interface ExtractionCoverage {
  format: 'kvp' | 'json' | 'cef' | 'clf' | 'csv' | 'unstructured';
  sampleKeys: string[];       // distinct keys seen across the sampled events
  capturedKeys: string[];     // keys the parse stage should populate
  missedKeys: string[];       // present in raw, NOT captured — the coverage gap
  findings: ContractLintFinding[];
  coverage: number;           // captured / sampleKeys, 0..1 (1 when nothing to extract)
}

// Strip outer quotes that some sources wrap around the entire _raw line
// (Zscaler NSS KV format, some syslog forwarders).
export function stripOuterQuotes(line: string): string {
  if (line.length > 2 && line[0] === '"' && line[line.length - 1] === '"' && !line.startsWith('{"')) {
    return line.slice(1, -1);
  }
  return line;
}

// Detect the structural envelope of a raw line and enumerate its field keys.
export function extractSampleKeys(rawLines: string[]): { format: ExtractionCoverage['format']; keys: Set<string> } {
  const keys = new Set<string>();
  const sample = rawLines.slice(0, 40).map(stripOuterQuotes);
  // JSON object per line?
  const jsonHits = sample.filter(l => { const t = l.trim(); return t.startsWith('{') && t.endsWith('}'); });
  if (jsonHits.length >= Math.max(1, sample.length * 0.6)) {
    for (const l of jsonHits) {
      try { for (const k of Object.keys(JSON.parse(l))) keys.add(k); } catch { /* skip */ }
    }
    if (keys.size > 0) return { format: 'json', keys };
  }
  // CEF-wrapped? (header + key=value extension) — treat the extension as KVP.
  const cefHits = sample.filter(l => /CEF:\d+\|/.test(l));
  const isCef = cefHits.length >= Math.max(1, sample.length * 0.6);
  // key=value pairs (SAP/FortiGate/ASA-KVP). Keys are word chars; values are
  // quoted or run to the next space. Require several pairs per line to qualify.
  const kvRe = /(?:^|\s)([A-Za-z_][\w.]*)=("(?:[^"\\]|\\.)*"|\S*)/g;
  let kvLines = 0;
  for (const l of sample) {
    const src = isCef ? (l.split(/CEF:\d+\|/)[1] || l).split('|').slice(6).join('|') : l;
    let n = 0; let m: RegExpExecArray | null;
    kvRe.lastIndex = 0;
    while ((m = kvRe.exec(src)) !== null) { keys.add(m[1]); n++; }
    if (n >= 2) kvLines++;
  }
  if (kvLines >= Math.max(1, sample.length * 0.5)) return { format: isCef ? 'cef' : 'kvp', keys };
  // Otherwise unstructured/positional (syslog free text, CLF, CSV) — we can't
  // reliably enumerate named keys, so return none (check becomes a no-op).
  keys.clear();
  return { format: 'unstructured', keys };
}

export interface SampleFingerprint {
  format: ExtractionCoverage['format'];
  keys: string[];  // sorted, lowercased distinct keys present in the sample
}

export function sampleFingerprint(sampleEvents: string): SampleFingerprint {
  const rawLines = (sampleEvents || '').split('\n').map(l => l.trim()).filter(Boolean);
  const { format, keys } = extractSampleKeys(rawLines);
  return { format, keys: [...keys].map(k => k.toLowerCase()).sort() };
}

interface GoldenSourceExpectation {
  format: 'unstructured' | 'kvp' | 'cef' | 'json';
  /**
   * Extra wire formats the golden parser also handles. Zscaler NSS is the
   * load-bearing case: the parser accepts JSON / KV / CEF, but a single
   * `format: 'kvp'` used to reject every JSON sample off the golden path onto
   * AI/schematizer hybrids (pack nbb: empty SourceIP/DestinationIP).
   */
  alsoFormats?: Array<'kvp' | 'cef' | 'json'>;
  /** Critical raw-source keys expected in the fingerprint (lowercased). */
  keys?: string[];
  /** For unstructured sources: regex patterns the raw sample must match. */
  patterns?: RegExp[];
  /**
   * The `patterns` above are specific enough to IDENTIFY this source from a raw
   * sample alone (not just validate an already-named one). Only sources whose
   * signature cannot plausibly collide with another feed set this — e.g. the SAP
   * SAL binary TLV record marker. `matchGoldenSourceBySample` scans only these,
   * and still bails on any ambiguity (≥2 distinctive sources matching), so a
   * loose syslog-shaped pattern can never auto-adopt the wrong golden path.
   */
  distinctive?: boolean;
}

const GOLDEN_SOURCE_EXPECTATIONS: Record<string, GoldenSourceExpectation> = {
  cisco_asa: {
    format: 'unstructured',
    // ASA message ids come in two shapes: `%ASA-6-302013:` and the subsystem
    // form `%ASA-session-7-609002:` (session/webvpn/dap messages). The pattern
    // used to require the first, so a real ASA sample made mostly of subsystem
    // messages was judged a format MISMATCH and pushed off the golden path onto
    // AI — silently, since falling back to AI is not an error. Found while
    // verifying the real cisco:asa sample in config/source-samples.json.
    patterns: [/%(?:ASA|FTD)(?:-[a-z][\w-]*)?-\d-\d+:/i],
  },
  cisco_esa: {
    format: 'unstructured',
    patterns: [/\b(?:Info|Warning|Critical|Debug|Trace):\s/],
  },
  sap_hana: {
    // SAP HANA indexserver/nameserver/statisticsserver trace + audit lines:
    // [2024-01-15 00:03:12.441][ERROR][33421][SAP HANA Database][indexserver.ini][Thread N] msg
    // The bracketed timestamp + [LEVEL] + [pid] head is unique enough that a
    // JSON/CEF HANA export (different feeds) won't wrongly take this golden path.
    format: 'unstructured',
    patterns: [/^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\]\[\w+\]\[\d+\]\[/],
  },
  // Rule 14: the hand-built parser reads the syslog-framed NIOS form. A JSON or
  // CEF/LEEF Infoblox feed (infoblox_cef/infoblox_leef are separate datatypes)
  // must NOT take this golden path — the envelope regex would extract nothing.
  infoblox_dns: {
    format: 'unstructured',
    patterns: [/^<\d+>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+.*?\b(?:named|dhcpd|httpd)\[\d+\]:/m],
  },
  // Rule 14: without an expectation the golden guard cannot check format, so a
  // JSON/CloudWatch-wrapped VPC sample would still take the golden path and the
  // space-delimited regex would extract nothing. The v2/v5 default record starts
  // `<version> <12-digit account> eni-...`.
  aws_vpc_v5: {
    format: 'unstructured',
    patterns: [/^\d+\s+\d{12}\s+eni-\S+\s+\S+\s+\S+\s+\d+\s+\d+\s+\d+\s/m],
  },
  aws_vpc_v2: {
    format: 'unstructured',
    patterns: [/^\d+\s+\d{12}\s+eni-\S+\s+\S+\s+\S+\s+\d+\s+\d+\s+\d+\s/m],
  },
  palo_alto_traffic: {
    format: 'unstructured',
    patterns: [/,TRAFFIC,/],
  },
  palo_alto_threat: {
    format: 'unstructured',
    patterns: [/,THREAT,/],
  },
  palo_alto_system: {
    format: 'unstructured',
    patterns: [/,SYSTEM,/],
  },
  // Rule 14: VMware vCenter/ESXi log lines are RFC5424 syslog
  // (`<pri>1 <ISO-ts> <host> <app> <procid> - - <body>`). The fingerprinter reads
  // the `key=value` fragments in some bodies as kvp, so pin the golden guard to
  // the RFC5424 envelope; a non-RFC5424 vSphere feed safely falls to AI.
  vsphere: {
    format: 'unstructured',
    patterns: [/^<\d+>\d+\s+\d{4}-\d\d-\d\dT[\d:.]+(?:[+-]\d\d:\d\d|Z)?\s+\S+\s+\S+\s+/m],
  },
  windows_powershell: {
    format: 'unstructured',
    patterns: [/LogName=.*(?:PowerShell|Security|System)/i, /EventCode=\d+/],
  },
  windows_security: {
    // XML attributes make the fingerprinter detect 'kvp'; the critical keys are
    // XML attribute names that only appear in Windows Event XML.
    format: 'kvp',
    keys: ['xmlns', 'name', 'systemtime', 'processid', 'guid', 'threadid'],
  },
  // Per-channel Windows XML canonicals. The guard's job here is FORMAT
  // compatibility (is this Windows Event XML at all?) — channel identity comes
  // from the sourcetype name, and `matchesExpectation` cannot discriminate
  // channels anyway because a structured expectation is checked on fingerprint
  // keys, which for XML are the same attribute names on every channel.
  // `windows_sysmon` had NO entry at all (Rule 14 gap found while extending
  // tests/windows-xml-parser-test.mjs): with no expectation the guard returns
  // 'unknown', which `goldenPathMatchesSample` treats as permission, so a classic
  // key=value or JSON "sysmon" sample took the golden path and the XML front-end
  // read nothing out of it.
  windows_sysmon: {
    format: 'kvp',
    keys: ['xmlns', 'name', 'systemtime', 'processid', 'guid', 'threadid'],
  },
  windows_dns_client: {
    format: 'kvp',
    keys: ['xmlns', 'name', 'systemtime', 'processid', 'guid', 'threadid'],
  },
  windows_defender: {
    format: 'kvp',
    keys: ['xmlns', 'name', 'systemtime', 'processid', 'guid', 'threadid'],
  },
  windows_system: {
    format: 'kvp',
    keys: ['xmlns', 'name', 'systemtime', 'processid', 'threadid'],
  },
  windows_application: {
    // The Application channel has no Execution/Correlation elements on most
    // providers, so `threadid`/`guid` are absent — requiring them would fail the
    // 50%-overlap check on a perfectly good sample.
    format: 'kvp',
    keys: ['xmlns', 'name', 'systemtime', 'qualifiers'],
  },
  fortinet_fortigate: {
    format: 'kvp',
    keys: ['date', 'time', 'devname', 'devid', 'logid', 'type', 'srcip', 'dstip'],
  },
  checkpoint_firewall: {
    format: 'kvp',
    keys: ['action', 'src', 'dst', 'loguid', 'origin', 'product', 'conn_direction'],
  },
  sap_audit: {
    format: 'kvp',
    keys: ['date', 'time', 'user', 'tcode', 'host', 'text', 'mandt', 'class'],
  },
  // Binary RSAU/SAL: one newline-less blob of length-prefixed records, each
  // `<4-digit header len><3-char msg id><14-digit YYYYMMDDHHMMSS>…`. It carries
  // no delimited key=value pairs, so it fingerprints 'unstructured'; the record
  // marker (msg id + a 19xx/20xx timestamp, anchored on the length prefix) is
  // specific enough that a mislabeled text/CSV/kvp feed — or the space-delimited
  // `sap_audit` KVP form — will NOT wrongly take this binary golden path. Rule 14:
  // without this, a mislabeled sample under `sap_audit_tlv` returns 'unknown' and
  // is silently admitted, and the TLV `code` decoder extracts nothing from it.
  sap_audit_tlv: {
    format: 'unstructured',
    patterns: [/\d{4}[A-Z]{2}[A-Z0-9](?:19|20)\d{12}/],
    // The length-prefix + msg-id + 14-digit-timestamp record marker is unique to
    // the SAP SAL binary export — no other feed carries it — so it can NAME this
    // source from a bare sample (the file often arrives named only by its numeric
    // timestamp, which canonicalises to nothing).
    distinctive: true,
  },
  salesforce_setupaudittrail: {
    // Setup Audit Trail is one JSON object per event. These keys distinguish it
    // from arbitrary JSON and guarantee the canonical parser reaches the audit
    // values (action/section/display/actor/timestamp) the golden specs read.
    format: 'json',
    keys: ['action', 'section', 'display', 'createdbyid', 'createddate'],
  },
  f5_bigip: {
    // BIG-IP LTM/TMM syslog — unstructured RFC3164 text with an optional
    // <priority> prefix and F5 message-ids (`01260013:5:`). Match on the syslog
    // header or an F5 message-id so a mislabeled JSON/kvp sample falls to AI.
    format: 'unstructured',
    patterns: [/\b\d{8}:\d:/, /^(?:<\d+>)?\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[\w.-]+\s+\w+\s+[\w-]+\[\d+\]:/m],
  },
  aws_cloudtrail: {
    format: 'json',
    keys: ['eventversion', 'eventtime', 'eventsource', 'eventname', 'awsregion', 'useridentity', 'sourceipaddress', 'requestparameters'],
  },
  corelight_conn: {
    format: 'json',
    keys: ['_path', 'uid', 'id.orig_h', 'id.resp_h', 'proto', 'conn_state', 'orig_bytes', 'resp_bytes'],
  },
  zeek_conn: {
    format: 'json',
    keys: ['_path', 'uid', 'id.orig_h', 'id.resp_h', 'proto', 'conn_state', 'orig_bytes', 'resp_bytes'],
  },
  zscaler_web: {
    // NSS feed templates emit KV, JSON, or CEF — parser handles all three.
    // Keys must be shared across templates: JSON NSS often omits reason /
    // protocol / requestmethod / useragent that KV feeds include (pack nbb).
    format: 'kvp',
    alsoFormats: ['json', 'cef'],
    keys: ['action', 'serverip', 'urlcategory', 'url', 'user'],
  },
  linux_audit: {
    // auditd lines are `type=VALUE msg=audit(epoch:serial): k=v ...` — kvp with a
    // distinctive `type=` + `msg=audit(` signature.
    format: 'kvp',
    keys: ['type', 'msg', 'arch', 'syscall', 'comm', 'exe', 'uid', 'pid', 'res'],
  },
  gcp_audit: {
    // Google Cloud Audit Logs are JSON envelopes. These keys distinguish them
    // from arbitrary JSON and guarantee the canonical parser can reach the
    // nested protoPayload/resource values used by CIM and OCSF.
    format: 'json',
    keys: ['insertid', 'logname', 'protopayload', 'resource', 'severity', 'timestamp'],
  },
  suricata_ids: {
    format: 'json',
    keys: ['event_type', 'src_ip', 'dest_ip', 'proto', 'flow_id', 'timestamp'],
  },
  corelight_dns: { format: 'json', keys: ['_path', 'uid', 'id.orig_h', 'ts'] },
  corelight_http: { format: 'json', keys: ['_path', 'uid', 'id.orig_h', 'ts'] },
  corelight_ssl: { format: 'json', keys: ['_path', 'uid', 'id.orig_h', 'ts'] },
  corelight_kerberos: { format: 'json', keys: ['_path', 'uid', 'id.orig_h', 'ts'] },
  corelight_ldap: { format: 'json', keys: ['_path', 'uid', 'id.orig_h', 'ts'] },
  corelight_ldap_search: { format: 'json', keys: ['_path', 'uid', 'id.orig_h', 'ts'] },
  corelight_ntp: { format: 'json', keys: ['_path', 'uid', 'id.orig_h', 'ts'] },
  corelight_notice: { format: 'json', keys: ['_path', 'uid', 'ts'] },
  corelight_weird: { format: 'json', keys: ['_path', 'uid', 'ts'] },
  corelight_tunnel: { format: 'json', keys: ['_path', 'uid', 'id.orig_h', 'ts'] },
  corelight_vpn: { format: 'json', keys: ['_path', 'uid', 'ts'] },
  corelight_snmp: { format: 'json', keys: ['_path', 'uid', 'id.orig_h', 'ts'] },
  corelight_smtp_links: { format: 'json', keys: ['_path', 'uid', 'ts'] },
  corelight_software: { format: 'json', keys: ['_path', 'ts'] },
  corelight_known_hosts: { format: 'json', keys: ['_path', 'ts'] },
  corelight_known_remotes: { format: 'json', keys: ['_path', 'ts'] },
  corelight_known_services: { format: 'json', keys: ['_path', 'ts'] },
  corelight_analyzer: { format: 'json', keys: ['_path', 'ts'] },
  corelight_reporter: { format: 'json', keys: ['_path', 'ts'] },
  corelight_suricata_enriched: { format: 'json', keys: ['_path', 'ts'] },
  corelight_suricata_eve: { format: 'json', keys: ['_path', 'ts'] },
};

/**
 * Does this sample structurally look like what `sourcetype`'s parser expects?
 *
 * Factored OUT of `goldenPathMatchesSample` so the golden guard and the
 * AI-sample verifier (src/sample-library.ts) share ONE implementation — a
 * generated sample is only worth keeping if the same check that admits a real
 * sample to the golden path admits it too. Two copies of this reasoning would
 * drift, and the drift would be invisible (one side accepts, the other rejects).
 *
 * `'unknown'` is NOT `'mismatch'`: a sourcetype with no declared expectation
 * hasn't failed a check, it has no check to fail. Callers decide what to do with
 * that — the golden guard stays lenient, the verifier reports "unverified".
 */
export function sampleMatchesSourceExpectation(sourcetype: string, sampleEvents: string): 'match' | 'mismatch' | 'unknown' {
  if (!sampleEvents || !sampleEvents.trim()) return 'unknown';
  const canonical = canonicalizeSourcetype(sourcetype);
  const expectation = GOLDEN_SOURCE_EXPECTATIONS[canonical];
  if (!expectation) return 'unknown';
  return matchesExpectation(expectation, sampleEvents) ? 'match' : 'mismatch';
}

/**
 * Can this golden source's parser produce a NON-STRING falsy value (numeric `0`,
 * boolean `false`) as a field value?
 *
 * Only regex-extracted (`unstructured`) sources are guaranteed string-only — a
 * capture group is ALWAYS a string, so a field's only falsy-but-defined value is
 * `''`, which the golden leaf's presence guard (`String(x) != ''`) already drops.
 * For those, a resolved alias chain's trailing `|| undefined` fall-through is
 * redundant and can be dropped for cleaner output (see resolveAliasChainToParser).
 *
 * JSON sources can carry a real `0`/`false` that the presence guard ADMITS, so
 * the tail must stay to keep the output byte-identical to the portable chain.
 * kvp/cef are treated as MAY-emit too: Cribl's KV/CEF parsers can numeric-coerce
 * a bare `key=0`, and we will not bet byte-identical output on that not happening.
 * Unknown sources are conservative (MAY-emit → keep the tail).
 */
export function sourceMayEmitNativeFalsy(sourcetype: string): boolean {
  const expectation = GOLDEN_SOURCE_EXPECTATIONS[canonicalizeSourcetype(sourcetype)];
  if (!expectation) return true;
  return expectation.format !== 'unstructured' || !!expectation.alsoFormats?.includes('json');
}

/**
 * How many of `keys` appear as REAL delimited pairs in the raw sample text
 * (`key=` for kvp/cef, `"key":` for json), case-insensitively. This is stronger
 * evidence than a fingerprint key-set match: it proves the golden parser will
 * actually extract those fields, regardless of which wire variant the
 * fingerprinter labeled the sample. Used both to admit sparse/mixed samples the
 * fingerprint under-counts and to keep out keyless (mislabeled) text.
 */
function countDelimitedKeys(keys: string[], sampleEvents: string): number {
  const snippet = sampleEvents.slice(0, 4000);
  return keys.filter(k => {
    const kk = k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(^|[\\s,{])${kk}\\s*=`, 'i').test(snippet)
      || new RegExp(`"${kk}"\\s*:`, 'i').test(snippet);
  }).length;
}

function matchesExpectation(expectation: GoldenSourceExpectation, sampleEvents: string): boolean {
  const fp = sampleFingerprint(sampleEvents);

  if (expectation.format === 'unstructured') {
    // The golden parser expects unstructured text (syslog, CSV without headers).
    // If the sample fingerprints as structured (kvp/json/cef with real keys),
    // that's a format mismatch — unless the fingerprinter found very few keys
    // (XML attributes on a mostly-text line can produce a false kvp hit).
    if (fp.format !== 'unstructured' && fp.keys.length > 3) {
      // Structured sample for an unstructured-expected sourcetype → mismatch.
      // Exception: allow if patterns still match (e.g. CEF-wrapped Fortinet
      // that gets detected as cef but user is labeling it cisco_asa by mistake
      // — patterns won't match anyway so we'd return false correctly).
      if (!expectation.patterns || expectation.patterns.length === 0) return false;
    }
    // Check raw patterns: at least one must match somewhere in the sample
    if (expectation.patterns && expectation.patterns.length > 0) {
      const sampleSnippet = sampleEvents.slice(0, 4000); // check first ~4K chars
      const anyMatch = expectation.patterns.some(re => re.test(sampleSnippet));
      return anyMatch;
    }
    return true;
  }

  // Structured expectation (kvp, json, cef)
  // Format compatibility check: the fingerprint format should match what we expect.
  // Allow cef as a kvp-compatible variant (FortiGate can be CEF-wrapped).
  // alsoFormats covers multi-wire parsers (Zscaler JSON NSS alongside KV/CEF).
  const allowed = new Set<string>([expectation.format, ...(expectation.alsoFormats || [])]);
  const formatCompatible =
    allowed.has(fp.format) ||
    (allowed.has('kvp') && fp.format === 'cef') ||
    (allowed.has('cef') && fp.format === 'kvp');

  if (!formatCompatible) {
    // Format mismatch: e.g. sample is JSON but sourcetype expects kvp.
    if (fp.format === 'unstructured') {
      // The fingerprint found no delimited keys. A kvp/cef/json golden parser
      // extracts NOTHING from keyless text, so running it here yields a pipeline
      // that maps only enrichment constants (extraction≈0) — the sap_audit-on-
      // syslog failure. Only allow the golden path if at least one critical
      // source key still appears as a real delimited pair in the raw sample
      // (covers genuinely sparse kvp samples the fingerprinter under-counts);
      // otherwise it's a mislabeled sample → fall to AI.
      if (expectation.keys && expectation.keys.length > 0) {
        // At least one critical key must appear as a real delimited pair.
        return countDelimitedKeys(expectation.keys, sampleEvents) > 0;
      }
      // No critical keys declared → can't tell, preserve prior lenient behavior.
      return true;
    }
    return false;
  }

  // Key overlap check: at least 50% of critical source keys should appear
  if (expectation.keys && expectation.keys.length > 0) {
    const fpKeySet = new Set(fp.keys); // already lowercased
    const critical = expectation.keys.slice(0, 8);
    const matched = critical.filter(k => fpKeySet.has(k)).length;
    if (matched >= Math.ceil(critical.length * 0.5)) return true;
    // The fingerprinter picked a different wire variant than the expectation
    // keys are written for — e.g. a mixed KV+CEF+JSON Zscaler NSS sample
    // fingerprints as `cef` and yields CEF-extension keys (act/cs1label/dst…),
    // so the KV-oriented expectation keys aren't in fp.keys. The raw text is
    // authoritative: if the expectation's own keys still appear as real
    // delimited pairs, the golden parser WILL extract them → admit it. Stays
    // strict (≥50%) so genuinely mislabeled/keyless samples still fall to AI.
    return countDelimitedKeys(critical, sampleEvents) >= Math.ceil(critical.length * 0.5);
  }

  return true;
}

/**
 * Offline source identification for feeds whose raw signature is distinctive
 * enough to NAME them (not just validate an already-named one). Scans only
 * `GOLDEN_SOURCE_EXPECTATIONS` entries flagged `distinctive`, and returns a key
 * only when EXACTLY ONE such source's guard matches the sample — any ambiguity
 * returns null so the caller falls through to the AI/manual path.
 *
 * The motivating case is the SAP SAL binary TLV export: it fingerprints as
 * keyless `unstructured`, so neither the datatype-parser matcher nor the JSON
 * signature matcher can name it, and its file is usually named only by a numeric
 * timestamp — leaving "not recognised". Its record marker is unique, so it is
 * safe to adopt on sight.
 */
export function matchGoldenSourceBySample(sampleEvents: string): { sourcetype: string; description: string } | null {
  if (!sampleEvents || !sampleEvents.trim()) return null;
  const matches: string[] = [];
  for (const [key, exp] of Object.entries(GOLDEN_SOURCE_EXPECTATIONS)) {
    if (!exp.distinctive || !exp.patterns || exp.patterns.length === 0) continue;
    if (matchesExpectation(exp, sampleEvents)) matches.push(key);
  }
  if (matches.length !== 1) return null; // 0 = no match; ≥2 = ambiguous → AI/manual
  const key = matches[0];
  return { sourcetype: key, description: SOURCETYPE_DESCRIPTIONS[key] || key };
}

export interface PipelineFunction {
  id: string;
  filter?: string;
  disabled?: boolean | null;
  description?: string;
  final?: boolean;
  conf: Record<string, unknown>;
}

// --- Sourcetype canonicalization ---

// Aliases map a user-entered / vendor sourcetype onto the canonical key whose
// parser + mappings we already implement. FTD's syslog is ASA-format-compatible
// (same %XXX-sev-id: header and message bodies), so it reuses the ASA parser.
const SOURCETYPE_ALIASES: Record<string, string> = {
  cisco_ftd: 'cisco_asa',
  cisco_firepower: 'cisco_asa',
  cisco_firepower_syslog: 'cisco_asa',
  paloalto_traffic: 'palo_alto_traffic',
  paloalto_threat: 'palo_alto_threat',
  // Bare family token from pipeline ids like palo_alto_to_cim — traffic is the
  // common CSV case; threat stays explicit as palo_alto_threat.
  palo_alto: 'palo_alto_traffic',
  // Common shorthands people put in a batch CSV. Without these, `Palo_Alert`
  // canonicalizes to `palo_alert` — which has NO parser and NO golden path, so
  // it falls to generic AI and produces broken output (batch scored it 4/undef).
  // Map the short/vendor forms to the canonical sourcetypes the app supports.
  palo_traffic: 'palo_alto_traffic',
  palo_alert: 'palo_alto_threat',
  palo_threat: 'palo_alto_threat',
  pan_traffic: 'palo_alto_traffic',
  pan_threat: 'palo_alto_threat',
  panw_traffic: 'palo_alto_traffic',
  panw_threat: 'palo_alto_threat',
  paloalto_system: 'palo_alto_system',
  palo_system: 'palo_alto_system',
  pan_system: 'palo_alto_system',
  panw_system: 'palo_alto_system',
  // SAP HANA trace/audit logs — canonical is sap_hana. Common vendor/short forms
  // (concatenated `saphana`, bare `hana`, `hanadb`, the audit variant) all map in
  // so a batch CSV or a hand-typed name doesn't fall to generic AI.
  saphana: 'sap_hana',
  hana: 'sap_hana',
  hanadb: 'sap_hana',
  sap_hana_audit: 'sap_hana',
  hana_audit: 'sap_hana',
  sap_hana_db: 'sap_hana',
  cisco_ftd_syslog: 'cisco_asa',
  cisco_ironport: 'cisco_esa',
  ironport: 'cisco_esa',
  esa: 'cisco_esa',
  checkpoint_cef: 'checkpoint_firewall',
  alibaba_actiontrail: 'alibaba_action_trail',
  action_trail: 'alibaba_action_trail',
  actiontrail: 'alibaba_action_trail',
  // FortiGate ships under many Splunk sourcetype names (traffic/utm/event/web/
  // fortinet:fgt:firewall/…). They all use the same key=value FortiGate syslog
  // format the built-in fortinet_fortigate parser + golden CIM path handle.
  // Without these, `fortigate_traffic` had no parser and fell to generic AI.
  fortigate_traffic: 'fortinet_fortigate',
  fortigate_utm: 'fortinet_fortigate',
  fortigate_event: 'fortinet_fortigate',
  fortigate_web: 'fortinet_fortigate',
  fortigate: 'fortinet_fortigate',
  fortinet_fgt_firewall: 'fortinet_fortigate',
  fortinet_fgt_traffic: 'fortinet_fortigate',
  fortinet_fgt_utm: 'fortinet_fortigate',
  // SAP SAL binary (length-prefixed TLV / RSAU) variant — distinct from the
  // space-delimited KVP `sap_audit`. Names seen in the field for the raw feed.
  sap_sal_tlv: 'sap_audit_tlv',
  sap_rsau: 'sap_audit_tlv',
  sap_audit_binary: 'sap_audit_tlv',
  // GENERIC "SAP Security Audit Log" names (the shared display form of BOTH the
  // KVP `sap_audit` and the binary `sap_audit_tlv`) resolve to the BINARY TLV
  // variant: the raw on-disk SAL / RSAU feed IS the length-prefixed binary
  // format, while the space-delimited KVP export is deliberately labeled
  // `sap_audit` (kept exact above). Without this, the bare name is 'unresolved'
  // and the build falls to generic AI — which emits a header-only regex_extract
  // that decodes ONE record and drops the rest (observed on pack `sss`). The
  // golden guard still protects a mislabeled KVP sample: it fails the TLV
  // pattern and falls to AI exactly as before, so this is neutral-or-better.
  sap_security_audit_log: 'sap_audit_tlv',
  sap_sal: 'sap_audit_tlv',
  sap_secaudit: 'sap_audit_tlv',
  sap_security_auditlog: 'sap_audit_tlv',
  // Zscaler NSS web proxy logs — various names in the wild
  zscalernss_web: 'zscaler_web',
  zscaler_zia: 'zscaler_web',
  zscaler_url: 'zscaler_web',
  zscaler_nss: 'zscaler_web',
  zscaler_weblog: 'zscaler_web',
  zscaler_nssweblog: 'zscaler_web', // Splunk TA sourcetype zscaler:nssweblog
  // Cribl Search datatype ids that are EXACT duplicates of a hand-built source.
  // Left un-aliased they resolved to their own stock parser (vendor-native names,
  // `clientip`/`remote_addr`/`request`) AND to data class `generic`, so a build that
  // asked for CIM/OCSF on them got the default network spec and mapped almost
  // nothing. Aliasing hands them the canonical parser + the web_proxy data class.
  // `resolveDatatypeParser` maps the reverse direction by its own table, so the
  // stock-parser candidate stays reachable for the extraction-stage comparison.
  apache_httpd_accesslog_combined: 'apache_access',
  apache_httpd_accesslog_common: 'apache_access',
  nginx_accesslog: 'nginx_access',
  // Splunk TA sourcetype names for Windows event logs. XmlWinEventLog (XML) and
  // WinEventLog (classic key=value) both land on our windows_security parser +
  // golden path (it handles the Windows XML/EventData model). Channel-suffixed
  // forms (XmlWinEventLog:Security, WinEventLog:Application) canonicalize with the
  // channel folded in — strip it to the base here via explicit entries for the
  // common channels; the recognizer's fuzzy tier catches the rest.
  xmlwineventlog: 'windows_security',
  wineventlog: 'windows_security',
  xmlwineventlog_security: 'windows_security',
  wineventlog_security: 'windows_security',
  xmlwineventlog_microsoft_windows_sysmon_operational: 'windows_sysmon',
  wineventlog_microsoft_windows_sysmon_operational: 'windows_sysmon',
  xmlwineventlog_microsoft_windows_powershell_operational: 'windows_powershell',
  wineventlog_microsoft_windows_powershell_operational: 'windows_powershell',
  // High-frequency Windows channel/naming variants seen in real deployments
  // (enriched-sourcetype census). Every channel shares the same XML ENVELOPE, but
  // the channel is NOT "just a filter": each one's EventData carries entirely
  // different Data Name attributes, so a channel folded onto windows_security got
  // the Security alias set (TargetUserName/IpAddress/LogonType) and — worse — an
  // `authentication` data class, which made `resolveGoldenFormat` deterministically
  // pick the golden AUTHENTICATION spec for DNS queries and Defender detections.
  // That is exactly the batch-446 signature (extraction healthy, mapping ~0) and it
  // failed SILENTLY because the golden path never errors. Each channel with its own
  // event model now has its own canonical, parser alias step and data class; the
  // shared XML front-end is `windowsXmlFrontEnd`. Sysmon (build 344) was the first
  // instance of this same bug.
  xmlwineventlog_system: 'windows_system',
  wineventlog_system: 'windows_system',
  system_wineventlog: 'windows_system',
  xmlwineventlog_application: 'windows_application',
  wineventlog_application: 'windows_application',
  application_wineventlog: 'windows_application',
  security_wineventlog: 'windows_security',
  xmlwineventlog_microsoft_windows_windows_defender_operational: 'windows_defender',
  wineventlog_microsoft_windows_windows_defender_operational: 'windows_defender',
  xmlwineventlog_microsoft_windows_dns_client_operational: 'windows_dns_client',
  wineventlog_microsoft_windows_dns_client_operational: 'windows_dns_client',
  // NTLM stays on windows_security: it IS an authentication channel (UserName/
  // DomainName/WorkstationName/LogonType), so both the alias set and the golden
  // Authentication spec are already right for it.
  xmlwineventlog_microsoft_windows_ntlm_operational: 'windows_security',
  // AWS VPC flow logs delivered via CloudWatch Logs (Splunk aws:cloudwatchlogs:
  // vpcflow). aws_vpc_v5 carries the Cribl Search datatype parser for the v5
  // flow-record layout; aws_vpc_flow is the data-class alias.
  aws_cloudwatchlogs_vpcflow: 'aws_vpc_v5',
  aws_vpc_flow: 'aws_vpc_v5',
  vpcflow: 'aws_vpc_v5',
  vpcflow_v5: 'aws_vpc_v5',
  // AWS CloudTrail via CloudWatch Logs / CloudTrail-lake sourcetype forms.
  aws_cloudwatchlogs_cloudtrail: 'aws_cloudtrail',
  aws_cloudtrail_cloudwatch: 'aws_cloudtrail',
  // Generic web access logs. Customers ship the combined/common log format under
  // a bare "access_log"/"access_combined" sourcetype (no vendor). That IS the
  // Apache/NGINX combined access line our apache_access parser + web_proxy golden
  // path handle — so route it there rather than letting fuzzy pick aws_s3_access.
  access_log: 'apache_access',
  access_combined: 'apache_access',
  access_combined_wcookie: 'apache_access', // combined log + cookie field
  accesslog: 'apache_access',
  web_access: 'apache_access',
  httpd_access: 'apache_access',
  tomcat_access_log: 'apache_access', // Tomcat access valve = combined log format
  ms_iis_auto: 'microsoft_iis_accesslog', // Splunk ms:iis:auto → IIS access log
  iis_access: 'microsoft_iis_accesslog',
  // FortiGate ADC and pan:firewall naming variants → the buildable golden sources
  // (enriched-sourcetype census). ADC is the same FortiGate syslog KV format;
  // pan:firewall is the umbrella PAN sourcetype → traffic is the golden default.
  fortigate_adc: 'fortinet_fortigate',
  pan_firewall: 'palo_alto_traffic',
  // *nix /var/log daemon logs. These are all RFC3164/5424 syslog the linux_syslog
  // parser + golden path handle. Customers ship them under the bare file name
  // (messages, secure, cron, maillog, kern, dmesg) and rotated variants
  // (messages-45, cron-8) — the recognizer's rotation-suffix stripper collapses
  // the rotation number to the base BEFORE this lookup, so only the base names
  // are needed here. dnf/dnf.librepo/dnf.rpm are the RHEL package-manager logs
  // (dot-folded to underscores by the stripper). (enriched-sourcetype census.)
  messages: 'linux_syslog',
  messages_log: 'linux_syslog',
  syslog: 'linux_syslog',
  syslog_ng: 'linux_syslog',
  secure: 'linux_syslog',
  secure_log: 'linux_syslog',
  maillog: 'linux_syslog',
  kern: 'linux_syslog',
  dmesg: 'linux_syslog',
  auth: 'linux_syslog',
  cron: 'linux_syslog',
  cron_log: 'linux_syslog',
  dnf: 'linux_syslog',
  dnf_log: 'linux_syslog',
  dnf_rpm: 'linux_syslog',
  dnf_rpm_log: 'linux_syslog',
  dnf_librepo: 'linux_syslog',
  dnf_librepo_log: 'linux_syslog',
  // Generic Linux audit daemon log → linux_audit golden path.
  audit: 'linux_audit',
  // F5 BIG-IP shipped as `f5:bigip:syslog` (Splunk) → f5_bigip carries the parser
  // + CIM golden path; the trailing `_syslog` transport token otherwise leaves it
  // as an unbuildable f5_bigip_syslog (validation report flagged the AI content).
  f5_bigip_syslog: 'f5_bigip',
  // Separator-less spellings. These are not vendor names — the recognizer's
  // squashed-form tier (the one that resolves CamelCase like XmlWinEventLog)
  // derives them, and a batch carrying both spellings then generates and stores
  // a sample under each. `squashedDuplicateKeys` already flags the pair in the
  // review panel; aliasing them here is what stops the derived spelling from
  // resolving to a key of its own, with no parser and no golden path behind it.
  vmwarensx: 'vmware_nsx',
  ivantitop: 'ivanti_top',
  httpfpcmetadata: 'http_fpc_metadata',
};

// Normalize a sourcetype so behavioral lookups (parser, drops, flags, mappings,
// classification) match regardless of how the user typed it. Lowercases,
// converts separators/spaces to underscores, then applies the alias table.
// The ORIGINAL sourcetype is kept by callers for display and the emitted
// `sourcetype` field — only behavior selection uses the canonical form.
export function canonicalizeSourcetype(sourcetype: string): string {
  const normalized = (sourcetype || '')
    .trim()
    .toLowerCase()
    // Splunk sourcetypes are colon-delimited (cisco:asa, pan:traffic,
    // aws:cloudtrail) and channel names use '/' (…Sysmon/Operational). Treat
    // ':' '/' '.' like space/hyphen so the canonical form (cisco_asa,
    // …sysmon_operational, dnf_librepo_log) matches the built-in parser + golden
    // path. The ORIGINAL colon/slash form is preserved for the emitted
    // `sourcetype` field. Dots appear in file-based names (dnf.librepo.log).
    .replace(/[\s:/\-.]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '');
  return SOURCETYPE_ALIASES[normalized] || normalized;
}

export function isKnownSourcetype(sourcetypeRaw: string): boolean {
  const st = canonicalizeSourcetype(sourcetypeRaw);
  return getParserFieldNames(st).length > 0
    || getDatatypeParserFunctions(st) !== null
    || st in SOURCETYPE_DATACLASS;
}

// STRICT known: a GENUINELY-registered sourcetype — a hand-built parser case, a
// data-class entry, or an EXACT/aliased datatype id. Unlike isKnownSourcetype it
// does NOT accept a lenient substring datatype match, so a near-miss on its own
// name (`cisco_asaa`, `fortinet_fortigateeee`) is NOT treated as exact. The
// recognizer uses this to gate the exact/alias tier; such a name then falls through
// to fuzzy and is corrected to the real source (cisco_asa) rather than accepted —
// which is what stops the demo generator synthesising a sample for a typo.
export function isKnownSourcetypeStrict(sourcetypeRaw: string): boolean {
  const st = canonicalizeSourcetype(sourcetypeRaw);
  if (st in SOURCETYPE_DATACLASS) return true;
  // getParserFieldNames covers hand-built switch cases (exact by canonical name);
  // strictDatatype makes its datatype fallback exact/alias-only.
  if (getParserFieldNames(st, { strictDatatype: true }).length > 0) return true;
  // A strict datatype with real parse functions but an empty declared `fields[]`
  // (getParserFieldNames would return [] for it) is still genuinely known.
  const dtp = resolveDatatypeParser(st, /* strict */ true);
  return !!dtp && dtp.functions.some(f => f.id !== 'comment');
}

// Just the separator/underscore normalization from canonicalizeSourcetype WITHOUT
// the alias remap — so callers can tell whether the alias table actually changed
// the name (an aliased hit vs an exact hit).
export function normalizeSourcetypeName(sourcetype: string): string {
  return (sourcetype || '')
    .trim()
    .toLowerCase()
    .replace(/[\s:/\-.]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '');
}

// The corpus of canonical sourcetype names the app deterministically supports —
// used for fuzzy matching an unrecognized name back to a real source. Built once
// from every place a canonical name is registered: datatype parsers, the
// data-class table, the description table, and the alias TARGETS (the canonical
// side of the alias map). Hand-built parser cases live in a switch and can't be
// enumerated, so their names are covered via the description/data-class tables.
// Splunk TA / real-world sourcetype names we ship a bundled sample for. These
// are authoritative source-native names (config/source-samples.json — normalized
// keys AND their original colon-form `sourcetype`, e.g. xmlwineventlog +
// "XmlWinEventLog", aws_cloudwatchlogs_vpcflow + "aws:cloudwatchlogs:vpcflow").
// A name that hits this set is a REAL source even if it has no built-in parser —
// it resolves to a bundled sample and builds via AI on real events, so it must
// count as recognized (not rejected).
let _sourceSampleKeys: Set<string> | null = null;
function getSourceSampleKeys(): Set<string> {
  if (_sourceSampleKeys) return _sourceSampleKeys;
  const set = new Set<string>();
  for (const name of sourceSampleKeysData as string[]) set.add(canonicalizeSourcetype(name));
  _sourceSampleKeys = set;
  return _sourceSampleKeys;
}

// The SURFACE-form fuzzy corpus: recognizable names as a user would TYPE them,
// BEFORE alias remap — the normalized alias keys (xmlwineventlog,
// aws_cloudwatchlogs_vpcflow) and the raw normalized source-sample keys. Each
// maps to the resolved canonical (via canonicalizeSourcetype). This lets a typo
// like "aws_cloudwatchlogs_vpclow" fuzzy-match the surface form
// "aws_cloudwatchlogs_vpcflow" and resolve to the real canonical "aws_vpc_v5" —
// which the post-alias corpus alone could never do (it only holds "aws_vpc_v5").
let _surfaceCorpus: Array<{ surface: string; canonical: string }> | null = null;
function getSurfaceCorpus(): Array<{ surface: string; canonical: string }> {
  if (_surfaceCorpus) return _surfaceCorpus;
  const map = new Map<string, string>();
  const add = (surface: string) => {
    if (!surface || map.has(surface)) return;
    map.set(surface, SOURCETYPE_ALIASES[surface] || surface);
  };
  for (const k of Object.keys(SOURCETYPE_ALIASES)) add(k);
  for (const name of sourceSampleKeysData as string[]) add(normalizeSourcetypeName(name));
  _surfaceCorpus = [...map.entries()].map(([surface, canonical]) => ({ surface, canonical }));
  return _surfaceCorpus;
}

// A name we can resolve deterministically to a real source WITHOUT a parser —
// currently means "we ship a bundled sample for it". Kept separate from
// isKnownSourcetype (which requires a parser/datatype/data-class) so the
// recognizer can distinguish "golden-buildable" from "AI-buildable-on-real-sample".
export function hasSourceSample(sourcetypeRaw: string): boolean {
  return getSourceSampleKeys().has(canonicalizeSourcetype(sourcetypeRaw));
}

// The STANDARD sourcetype catalog the app can actually build well — the grounding
// set for AI resolution. A customer-delivered name should be mapped TO one of
// these, never invented. Golden-path names (deterministic parser + schema) are
// flagged so the resolver/UI can prefer them. Excludes generic passthrough
// pseudo-types (json/csv/generic_*) that aren't real sources.
let _supportedCatalog: { name: string; golden: boolean }[] | null = null;
export function getSupportedSourcetypeCatalog(): { name: string; golden: boolean }[] {
  if (_supportedCatalog) return _supportedCatalog;
  const names = new Set<string>();
  for (const k of Object.keys(DATATYPE_PARSERS)) names.add(k);
  for (const k of getSourceSampleKeys()) names.add(k);
  for (const k of Object.keys(SOURCETYPE_DESCRIPTIONS)) names.add(k);
  for (const k of Object.keys(SOURCETYPE_DATACLASS)) names.add(k);
  const SKIP = /^(json|csv|generic_|v2_|pan_traffic_fixed$)/i;
  _supportedCatalog = [...names]
    .filter(n => n && !SKIP.test(n))
    .sort()
    .map(name => {
      let golden = false;
      const goldenPath = _goldenPathPredicate;
      try { golden = getParserFieldNames(name).length > 0 && !!goldenPath && ['cim', 'ocsf', 'cef', 'ecs'].some(fmt => goldenPath(name, fmt)); } catch { /* not golden */ }
      return { name, golden };
    });
  return _supportedCatalog;
}

let _knownSourcetypeCorpus: string[] | null = null;
function getKnownSourcetypeCorpus(): string[] {
  if (_knownSourcetypeCorpus) return _knownSourcetypeCorpus;
  const set = new Set<string>();
  for (const k of Object.keys(DATATYPE_PARSERS)) set.add(k);
  for (const k of Object.keys(SOURCETYPE_DATACLASS)) set.add(k);
  for (const k of Object.keys(SOURCETYPE_DESCRIPTIONS)) set.add(k);
  for (const v of Object.values(SOURCETYPE_ALIASES)) set.add(v);
  for (const k of getSourceSampleKeys()) set.add(k);
  _knownSourcetypeCorpus = [...set];
  return _knownSourcetypeCorpus;
}

// Squashed-form index: every surface form (alias keys + sample keys) mapped from
// its separator-free spelling to the canonical name. Resolves CamelCase /
// concatenated pipeline-name forms (XmlWinEventLogMicrosoftWindowsSysmonOperational)
// that carry the right TOKENS but no separators, so normalizeSourcetypeName can't
// split them. Deterministic and exact — the squashed letters must match a known
// surface form exactly; no fuzzy. Value is the resolved canonical sourcetype.
let _squashedIndex: Map<string, string> | null = null;
function getSquashedIndex(): Map<string, string> {
  if (_squashedIndex) return _squashedIndex;
  const idx = new Map<string, string>();
  const squash = (s: string) => tokenizeLabel(s).join('');
  const add = (surface: string, canonical: string) => {
    const key = squash(surface);
    if (key && !idx.has(key)) idx.set(key, canonical);
  };
  for (const { surface, canonical } of getSurfaceCorpus()) add(surface, canonical);
  for (const cand of getKnownSourcetypeCorpus()) add(cand, cand);
  _squashedIndex = idx;
  return _squashedIndex;
}

// Resolve a concatenated / CamelCase label to a canonical sourcetype by squashing
// both sides to their separator-free token spelling and looking up an exact hit.
// A terminal dest-format token (…_CIM, …Ocsf) is stripped first. Returns the
// canonical name, or null if the squashed form isn't a known surface spelling.
function resolveSquashedLabel(label: string, destFormat?: string): string | null {
  const tokens = stripTerminalDestToken(tokenizeLabel(label), destFormat);
  if (tokens.length < 2) return null; // a single squashed token is too ambiguous
  const key = tokens.join('');
  return getSquashedIndex().get(key) || null;
}

// Bounded Levenshtein — early-exits once distance exceeds `max` so it stays cheap
// on the ~1.3k corpus. Returns max+1 when the true distance is larger.
function boundedLevenshtein(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  if (a === b) return 0;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

// RecognitionStatus separates "what is this source" from "can we build it well"
// (per the sourcetype-resolution spec). A source can be RECOGNIZED without having
// a golden path — it still builds via AI. Only 'unresolved' blocks the build.
//   exact/alias        — resolves to a canonical we build deterministically (green)
//   catalogue_gap      — vendor/product/family identified (hint, fuzzy-high, or an
//                        AI real-source confirmation) but no canonical golden entry;
//                        build via AI, non-blocking (amber)
//   needs_confirmation — weak/ambiguous evidence; editable, non-blocking (red-ish)
//   unresolved         — no defensible candidate; BLOCKS the build (red)
// NOTE: the old 'metadata_confirmed' status was REMOVED — it "confirmed" a source
// purely because pack_name/pipeline_name token-matched the sourcetype, but this app
// GENERATES those names from the sourcetype, so the match was circular (always true)
// and confirmed nothing. Not-in-catalog sources are now validated by the model
// (aiValidate → isRealSource), exactly like the interactive pack generator does.
export type RecognitionStatus =
  | 'exact' | 'alias' | 'catalogue_gap' | 'needs_confirmation' | 'unresolved';

export interface SourcetypeRecognition {
  original: string;
  normalized: string;          // separator-normalized, pre-alias (comparison key)
  canonical: string;           // best resolved canonical name (may be a suggestion)
  canonicalDisplay: string;    // colon/preserved display form (never a made-up key)
  tier: 'exact' | 'alias' | 'fuzzy' | 'hint' | 'none';
  status: RecognitionStatus;
  known: boolean;              // resolves to a real parser/datatype/data-class
  hasGolden: boolean;          // a deterministic golden path exists
  suggestion?: string;         // fuzzy-suggested canonical (tier 'fuzzy' only)
  confidence: 'high' | 'medium' | 'low' | 'none';
  score: number;               // 0-100 evidence score (spec confidence model)
  vendor?: string;             // identified vendor/platform (recognition, not build)
  product?: string;            // identified product/component
  logFamily?: string;          // identified log family
  description?: string;        // human product/log-family description
  evidence?: string;           // short why-this-was-selected note
}

// Curated recognition hints for REAL, identifiable sources that we do NOT have a
// golden path for. Purpose: identify vendor/product/log-family so the UI shows a
// real description + amber "catalogue gap" instead of "Unknown source type", and
// the row builds via AI on its own name (never force-mapped to a wrong canonical).
// Keyed by an ordered set of REQUIRED tokens (all must be present in the input's
// token set). Longest/most-specific match wins. This is recognition ground-truth,
// NOT an alias table — none of these resolve to a buildable canonical.
// `glued`: this single-token vendor prefix also appears CONCATENATED with a
// subtype in real exports (Splunk TA style: aemaccess, aemhttpdaccess, aemerror)
// where the tokenizer can't split it. When set, the hint also matches a lone
// glued input token that STARTS WITH the hint token. Opt-in per hint so we never
// prefix-match a short token against an unrelated word (bro→broker).
// `gluedSuffixWords`: for a short/greedy glued prefix (e.g. `ora`), only accept
// the match when the remainder AFTER the prefix contains one of these log-domain
// words — validating that the tail is a real log type, not a coincidental word.
// oraaudit→"audit"✓, oraapxaudit→"…audit"✓, orange→"nge"✗. Omit for long,
// unambiguous prefixes (aem/corelight/trellix) which need no tail check.
interface RecognitionHint { tokens: string[]; vendor: string; product: string; logFamily: string; description: string; glued?: boolean; gluedSuffixWords?: string[]; }
const RECOGNITION_HINTS: RecognitionHint[] = [
  { tokens: ['citrix', 'netscaler'], vendor: 'Citrix', product: 'NetScaler ADC', logFamily: 'network/appfw', description: 'Citrix NetScaler ADC syslog (traffic / AppFirewall)' },
  { tokens: ['netscaler'], vendor: 'Citrix', product: 'NetScaler ADC', logFamily: 'network', description: 'Citrix NetScaler ADC logs' },
  { tokens: ['cloudflare', 'gateway', 'dns'], vendor: 'Cloudflare', product: 'Cloudflare Gateway', logFamily: 'dns', description: 'Cloudflare Gateway DNS logs' },
  { tokens: ['cloudflare', 'gateway'], vendor: 'Cloudflare', product: 'Cloudflare Gateway', logFamily: 'web_gateway', description: 'Cloudflare Gateway logs' },
  { tokens: ['cloudflare', 'http'], vendor: 'Cloudflare', product: 'Cloudflare', logFamily: 'http', description: 'Cloudflare HTTP request logs' },
  { tokens: ['cloudflare'], vendor: 'Cloudflare', product: 'Cloudflare', logFamily: 'web', description: 'Cloudflare logs' },
  { tokens: ['ironport', 'wsa'], vendor: 'Cisco', product: 'IronPort Web Security Appliance', logFamily: 'web_proxy', description: 'Cisco IronPort WSA web/proxy access logs' },
  { tokens: ['cisco', 'wsa'], vendor: 'Cisco', product: 'Web Security Appliance', logFamily: 'web_proxy', description: 'Cisco WSA web/proxy access logs' },
  { tokens: ['vcenter'], vendor: 'VMware', product: 'vCenter Server', logFamily: 'syslog', description: 'VMware vCenter Server syslog' },
  { tokens: ['esxi'], vendor: 'VMware', product: 'ESXi', logFamily: 'syslog', description: 'VMware ESXi host syslog' },
  { tokens: ['bluecoat', 'proxysg'], vendor: 'Broadcom', product: 'Blue Coat ProxySG', logFamily: 'web_proxy', description: 'Blue Coat ProxySG access logs' },
  { tokens: ['bluecoat'], vendor: 'Broadcom', product: 'Blue Coat', logFamily: 'web_proxy', description: 'Blue Coat proxy logs' },
  { tokens: ['sharepoint'], vendor: 'Microsoft', product: 'SharePoint', logFamily: 'collaboration', description: 'Microsoft SharePoint audit/usage logs' },
  { tokens: ['azure', 'eventhub'], vendor: 'Microsoft', product: 'Azure Event Hub', logFamily: 'cloud_ingest', description: 'Microsoft Azure Event Hub ingestion (parent stream — subtype not inferred)' },
  { tokens: ['aem'], vendor: 'Adobe', product: 'Experience Manager', logFamily: 'application', description: 'Adobe Experience Manager (AEM) application logs', glued: true },
  { tokens: ['aws', 'waf'], vendor: 'AWS', product: 'WAF', logFamily: 'web_firewall', description: 'AWS WAF web ACL logs' },
  { tokens: ['juniper', 'junos'], vendor: 'Juniper', product: 'Junos', logFamily: 'network', description: 'Juniper Junos device logs (firewall/routing)' },
  { tokens: ['fpc'], vendor: 'Full Packet Capture', product: 'FPC metadata', logFamily: 'http_metadata', description: 'Full-packet-capture HTTP metadata (low-confidence — confirm)' },
  { tokens: ['splunk', 'soar'], vendor: 'Splunk', product: 'SOAR', logFamily: 'application', description: 'Splunk SOAR (Phantom) service/daemon logs' },
  { tokens: ['corelight'], vendor: 'Corelight', product: 'Corelight (Zeek)', logFamily: 'network', description: 'Corelight/Zeek network monitoring logs (conn/dns/http/files/ssl…)', glued: true },
  { tokens: ['zeek'], vendor: 'Zeek', product: 'Zeek', logFamily: 'network', description: 'Zeek (Bro) network monitoring logs', glued: true },
  // VMware ESXi host daemon logs (vmware:esxlog:Hostd, :Vpxa, :vmkernel, …). One
  // hint covers the whole esxlog:* family — recognized (catalogue_gap), build via
  // AI on the real sample. 'esxlog' token is unique enough on its own.
  { tokens: ['vmware', 'esxlog'], vendor: 'VMware', product: 'ESXi host log', logFamily: 'syslog', description: 'VMware ESXi host daemon/service logs (hostd/vpxa/vmkernel/…)' },
  // Ivanti appliance logs (ivanti_*, ivanti:core:*, ivanti:sentry:*). Covers the
  // Ivanti Connect Secure / Sentry / EPMM (MobileIron) appliance log family.
  { tokens: ['ivanti'], vendor: 'Ivanti', product: 'Ivanti appliance', logFamily: 'application', description: 'Ivanti appliance logs (Connect Secure / Sentry / EPMM)' },
  // Generic web/app-server logs shipped under bare/port-prefixed names
  // (ssl_access_log, 9443_access_log, httpd_error_log, jira_error_log, mod_jk_log).
  // Recognized as web-server logs (catalogue_gap, build via AI). NOTE: the bare
  // `access_log`/`access_combined` names are aliased to apache_access above (golden
  // path) — the alias tier runs first, so only the non-apache-golden variants land
  // here. Two token pairs keep these specific enough to avoid false positives.
  { tokens: ['access', 'log'], vendor: 'Web Server', product: 'Access log', logFamily: 'web', description: 'Web/application server access log (combined-log-format family)' },
  { tokens: ['error', 'log'], vendor: 'Web Server', product: 'Error log', logFamily: 'web', description: 'Web/application server error log' },
  { tokens: ['mod', 'jk'], vendor: 'Apache', product: 'mod_jk connector', logFamily: 'web', description: 'Apache/Tomcat mod_jk connector log' },
  { tokens: ['modsec'], vendor: 'Apache', product: 'ModSecurity', logFamily: 'web_firewall', description: 'Apache ModSecurity WAF audit log', glued: true },
  // Vendor products from the enriched-sourcetype census (no golden path yet →
  // catalogue_gap, build via AI on real samples). Tokens use the tokenizeLabel
  // output form (McAfee→mc/afee, f5→f/5) so subset matching fires. One entry per
  // vendor covers all its subtypes (tenable:sc:vuln/admin/web/…, rsa:securid:*).
  { tokens: ['tenable'], vendor: 'Tenable', product: 'Tenable.sc / Tenable.ad', logFamily: 'vulnerability', description: 'Tenable Security Center / Tenable.ad vulnerability & audit logs' },
  { tokens: ['securid'], vendor: 'RSA', product: 'SecurID', logFamily: 'authentication', description: 'RSA SecurID authentication logs' },
  { tokens: ['netwitness'], vendor: 'RSA', product: 'NetWitness', logFamily: 'network', description: 'RSA NetWitness network/metadata logs' },
  { tokens: ['mcafee'], vendor: 'McAfee', product: 'ePO', logFamily: 'endpoint', description: 'McAfee ePolicy Orchestrator (ePO) threat/DLP/Solidcore events' },
  { tokens: ['nginx'], vendor: 'NGINX', product: 'NGINX', logFamily: 'web', description: 'NGINX web server / NGINX Plus logs (access/error/API)' },
  { tokens: ['bigip'], vendor: 'F5', product: 'BIG-IP', logFamily: 'network', description: 'F5 BIG-IP LTM/APM logs' },
  { tokens: ['tanium'], vendor: 'Tanium', product: 'Tanium', logFamily: 'endpoint', description: 'Tanium endpoint detect/discover logs' },
  { tokens: ['jira'], vendor: 'Atlassian', product: 'Jira', logFamily: 'application', description: 'Atlassian Jira application/security/audit logs' },
  { tokens: ['trellix'], vendor: 'Trellix', product: 'Trellix', logFamily: 'endpoint', description: 'Trellix (McAfee) endpoint/TIE logs', glued: true },
  { tokens: ['fidelis'], vendor: 'Fidelis', product: 'Fidelis', logFamily: 'network', description: 'Fidelis endpoint/network security logs' },
  { tokens: ['delinea'], vendor: 'Delinea', product: 'Delinea (Thycotic)', logFamily: 'authentication', description: 'Delinea Secret Server / PAM logs' },
  { tokens: ['mandiant'], vendor: 'Mandiant', product: 'Advantage ASM', logFamily: 'threat_intel', description: 'Mandiant Advantage Attack Surface Management' },
  { tokens: ['forcepoint'], vendor: 'Forcepoint', product: 'Forcepoint', logFamily: 'email', description: 'Forcepoint email/web security logs' },
  { tokens: ['symantec', 'email'], vendor: 'Broadcom', product: 'Symantec Email Security.cloud', logFamily: 'email', description: 'Symantec Email Security.cloud (ATP/antispam/antimalware)' },
  { tokens: ['fml'], vendor: 'Fortinet', product: 'FortiMail', logFamily: 'email', description: 'Fortinet FortiMail (fml) mail security logs' },
  { tokens: ['fortiproxy'], vendor: 'Fortinet', product: 'FortiProxy', logFamily: 'web_proxy', description: 'Fortinet FortiProxy web proxy logs', glued: true },
  { tokens: ['clearswift'], vendor: 'Fortra', product: 'Clearswift', logFamily: 'email', description: 'Clearswift Secure Email Gateway logs' },
  { tokens: ['postfix'], vendor: 'Postfix', product: 'Postfix MTA', logFamily: 'email', description: 'Postfix mail transfer agent logs', glued: true },
  { tokens: ['brocade'], vendor: 'Broadcom', product: 'Brocade', logFamily: 'network', description: 'Brocade fabric/switch syslog' },
  { tokens: ['commvault'], vendor: 'Commvault', product: 'Commvault', logFamily: 'backup', description: 'Commvault data-protection logs' },
  { tokens: ['ise'], vendor: 'Cisco', product: 'Identity Services Engine', logFamily: 'authentication', description: 'Cisco ISE authentication/authorization logs' },
  { tokens: ['prime'], vendor: 'Cisco', product: 'Prime', logFamily: 'network', description: 'Cisco Prime Infrastructure logs' },
  { tokens: ['juniper'], vendor: 'Juniper', product: 'Junos', logFamily: 'network', description: 'Juniper Junos device logs' },
  { tokens: ['trendmicro'], vendor: 'Trend Micro', product: 'Trend Micro', logFamily: 'endpoint', description: 'Trend Micro InterScan / endpoint logs', glued: true },
  { tokens: ['akamai'], vendor: 'Akamai', product: 'Akamai', logFamily: 'web', description: 'Akamai web/CDN/security logs' },
  { tokens: ['arbor'], vendor: 'NETSCOUT', product: 'Arbor', logFamily: 'network', description: 'NETSCOUT Arbor DDoS (Pravail/APS) logs' },
  { tokens: ['solarwinds'], vendor: 'SolarWinds', product: 'SolarWinds', logFamily: 'network', description: 'SolarWinds network/VPN monitoring logs' },
  { tokens: ['misp'], vendor: 'MISP', product: 'MISP', logFamily: 'threat_intel', description: 'MISP threat-intelligence platform logs', glued: true },
  { tokens: ['dmarc'], vendor: 'DMARC', product: 'DMARC aggregate', logFamily: 'email', description: 'DMARC aggregate (RUA) reports', glued: true },
  { tokens: ['zabbix'], vendor: 'Zabbix', product: 'Zabbix', logFamily: 'monitoring', description: 'Zabbix monitoring agent/server logs', glued: true },
  { tokens: ['elasticsearch'], vendor: 'Elastic', product: 'Elasticsearch', logFamily: 'application', description: 'Elasticsearch server logs', glued: true },
  { tokens: ['websphere'], vendor: 'IBM', product: 'WebSphere', logFamily: 'application', description: 'IBM WebSphere application server logs', glued: true },
  { tokens: ['mariadb'], vendor: 'MariaDB', product: 'MariaDB', logFamily: 'database', description: 'MariaDB database server logs', glued: true },
  { tokens: ['mssql'], vendor: 'Microsoft', product: 'SQL Server', logFamily: 'database', description: 'Microsoft SQL Server error/audit logs', glued: true },
  { tokens: ['vsftpd'], vendor: 'vsftpd', product: 'vsftpd', logFamily: 'ftp', description: 'vsftpd FTP server logs', glued: true },
  { tokens: ['idrac'], vendor: 'Dell', product: 'iDRAC', logFamily: 'hardware', description: 'Dell iDRAC out-of-band management logs', glued: true },
  { tokens: ['securetransport'], vendor: 'Axway', product: 'SecureTransport', logFamily: 'mft', description: 'Axway SecureTransport managed file transfer logs', glued: true },
  { tokens: ['dataminer'], vendor: 'Skyline', product: 'DataMiner', logFamily: 'monitoring', description: 'Skyline DataMiner logs', glued: true },
  { tokens: ['isva'], vendor: 'IBM', product: 'Security Verify Access', logFamily: 'authentication', description: 'IBM Security Verify Access (ISVA) logs', glued: true },
  { tokens: ['ixia'], vendor: 'Keysight', product: 'Ixia', logFamily: 'network', description: 'Keysight/Ixia network packet-broker logs', glued: true },
  { tokens: ['hypori'], vendor: 'Hypori', product: 'Hypori', logFamily: 'application', description: 'Hypori virtual mobile infrastructure logs', glued: true },
  { tokens: ['attackiq'], vendor: 'AttackIQ', product: 'AttackIQ', logFamily: 'security', description: 'AttackIQ breach & attack simulation (CEF)' },
  { tokens: ['domaintools'], vendor: 'DomainTools', product: 'DomainTools', logFamily: 'threat_intel', description: 'DomainTools Whois/enrichment logs' },
  { tokens: ['teamcymru'], vendor: 'Team Cymru', product: 'Team Cymru', logFamily: 'threat_intel', description: 'Team Cymru threat-intelligence feed', glued: true },
  { tokens: ['apache'], vendor: 'Apache', product: 'HTTP Server', logFamily: 'web', description: 'Apache HTTP Server logs (access/error)', glued: true },
  { tokens: ['pan', 'audit'], vendor: 'Palo Alto Networks', product: 'PAN-OS', logFamily: 'audit', description: 'Palo Alto Networks PAN-OS config/system audit logs' },
  { tokens: ['aws', 'config'], vendor: 'AWS', product: 'Config', logFamily: 'cloud_audit', description: 'AWS Config configuration-item / compliance change logs' },
  { tokens: ['stash'], vendor: 'Atlassian', product: 'Bitbucket (Stash)', logFamily: 'application', description: 'Atlassian Bitbucket/Stash access & audit logs', glued: true },
  // Generic web-server request/error logs shipped under bare protocol names
  // (http_request, https_error, ssl_request_log). Two-token pairs keep them
  // specific; the more-specific vendor web hints (cloudflare:http, apache_*) win
  // by longest-match so these only catch the un-vendored generics.
  { tokens: ['http', 'request'], vendor: 'Web Server', product: 'HTTP request log', logFamily: 'web', description: 'Web server HTTP request/access log' },
  { tokens: ['https', 'request'], vendor: 'Web Server', product: 'HTTPS request log', logFamily: 'web', description: 'Web server HTTPS request/access log' },
  { tokens: ['http', 'error'], vendor: 'Web Server', product: 'HTTP error log', logFamily: 'web', description: 'Web server HTTP error log' },
  { tokens: ['https', 'error'], vendor: 'Web Server', product: 'HTTPS error log', logFamily: 'web', description: 'Web server HTTPS error log' },
  { tokens: ['ssl', 'request'], vendor: 'Web Server', product: 'SSL request log', logFamily: 'web', description: 'Web server SSL request log (Apache mod_ssl ssl_request_log family)' },
  // Remaining census real-products with no golden path.
  // `ora`-prefixed sourcetypes are overwhelmingly Oracle in a log context
  // (oraaudit, oraapxaudit, oraiosaudit, oralistener, oraalert…). Per the user:
  // "when it starts with ora, mostly is oracle" — but validate the tail so we
  // don't eat coincidental words: the part after `ora` must be a real log type
  // (Oracle audit IS a real source — Unified/Standard/APEX/listener auditing).
  { tokens: ['ora'], vendor: 'Oracle', product: 'Oracle', logFamily: 'database', description: 'Oracle database audit/APEX/iOS/listener/alert logs', glued: true,
    gluedSuffixWords: ['audit', 'aud', 'listener', 'alert', 'trace', 'log', 'apx', 'apex', 'ios', 'db', 'sql', 'net', 'tns'] },
  { tokens: ['ssm', 'agent'], vendor: 'AWS', product: 'Systems Manager Agent', logFamily: 'cloud_management', description: 'AWS SSM Agent audit/operation logs' },
  { tokens: ['foreman'], vendor: 'Red Hat', product: 'Foreman/Katello', logFamily: 'management', description: 'Foreman/Katello lifecycle-management logs' },
  { tokens: ['aemcdn'], vendor: 'Adobe', product: 'Experience Manager CDN', logFamily: 'web_firewall', description: 'Adobe AEM CDN / WAF logs' },
  { tokens: ['stream', 'dns'], vendor: 'Cribl', product: 'Stream DNS', logFamily: 'dns', description: 'Cribl Stream DNS capture logs' },
  { tokens: ['sysmon', 'deploy'], vendor: 'Splunk', product: 'Sysmon deployment log', logFamily: 'management', description: 'Sysmon TA deployment/install log (NOT Sysmon events)' },
  { tokens: ['datadiode'], vendor: 'Data Diode', product: 'Data diode', logFamily: 'network', description: 'Unidirectional data-diode gateway syslog', glued: true },
  { tokens: ['netbackup'], vendor: 'Veritas', product: 'NetBackup', logFamily: 'backup', description: 'Veritas NetBackup job/connection logs', glued: true },
  { tokens: ['event', 'viewer'], vendor: 'Microsoft', product: 'Windows Event Viewer', logFamily: 'windows', description: 'Windows Event Viewer exported logs' },
];

// Match the most-specific recognition hint whose required tokens are ALL present
// in the input token set. Returns null when nothing matches.
// A `glued` single-token hint ALSO matches when the input is a lone token that
// STARTS WITH the hint token (aemaccess/aemhttpdaccess → aem; corelight_files
// tokenizes to two so it hits the normal subset path). Guarded so the glued
// token is a real prefix (≥3 chars, next char is not a letter that would make it
// a different word — we require the remainder to be a plausible subtype suffix).
function matchRecognitionHint(tokens: string[]): RecognitionHint | null {
  const tset = new Set(tokens);
  let best: RecognitionHint | null = null;
  for (const h of RECOGNITION_HINTS) {
    if (h.tokens.every(t => tset.has(t))) {
      if (!best || h.tokens.length > best.tokens.length) best = h;
    }
  }
  if (best) return best;
  // No subset hit — try glued prefix match on the lone MEANINGFUL token (a single
  // vendor token possibly followed by only format/transport tokens, e.g.
  // trellixTIE_syslog → ["trellixtie","syslog"]). Drop format tokens first so a
  // trailing `syslog`/`log` doesn't defeat the glued match.
  const meaningful = tokens.filter(t => !FORMAT_TOKENS.has(t));
  if (meaningful.length === 1) {
    const lone = meaningful[0];
    for (const h of RECOGNITION_HINTS) {
      if (!h.glued || h.tokens.length !== 1) continue;
      const pfx = h.tokens[0];
      if (pfx.length >= 3 && lone.length > pfx.length && lone.startsWith(pfx)) {
        // Short/greedy prefix: require the tail to contain a known log-domain word.
        if (h.gluedSuffixWords) {
          const tail = lone.slice(pfx.length);
          if (!h.gluedSuffixWords.some(w => tail.includes(w))) continue;
        }
        if (!best || pfx.length > best.tokens[0].length) best = h;
      }
    }
  }
  return best;
}

// Terminal destination-format suffixes appended to pack/pipeline names
// (VcenterSyslog_CIM). Stripped ONLY when standalone and dest_format matches.
const DEST_SUFFIX_TOKENS = new Set(['cim', 'ocsf', 'ecs', 'cef', 'asim', 'udm', 'json', 'leef', 'sentinel', 'xsiam']);

// Split a pack/pipeline/sourcetype label into an ordered lowercase token list:
// CamelCase boundaries (incl. letter↔digit), and all separators. Preserves
// numeric/version tokens. Used only for comparison, never for display.
function tokenizeLabel(label: string): string[] {
  return (label || '')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/([a-zA-Z])(\d)/g, '$1 $2')
    .replace(/(\d)([a-zA-Z])/g, '$1 $2')
    .replace(/[\s:/\-_.]+/g, ' ')
    .trim()
    .toLowerCase()
    .split(' ')
    .filter(Boolean);
}

// Strip a single terminal destination-suffix token if present and it matches the
// requested dest_format (or dest_format is unknown/empty — then strip any known
// dest suffix, since pack names conventionally append it).
function stripTerminalDestToken(tokens: string[], destFormat?: string): string[] {
  if (tokens.length < 2) return tokens;
  const last = tokens[tokens.length - 1];
  const df = (destFormat || '').trim().toLowerCase();
  if (DEST_SUFFIX_TOKENS.has(last) && (!df || last === df || (df === 'cim' && last === 'cim'))) {
    return tokens.slice(0, -1);
  }
  return tokens;
}

// Leading namespace / collector / tenant prefixes customers prepend to a real
// sourcetype (ncsc:cisco:asa, custom::paloalto:traffic). A namespace is NOT a
// product (per the resolver contract) — strip a KNOWN prefix and re-recognize
// the remainder. We only strip from a curated list so we never destroy a real
// leading token (e.g. "cisco" in cisco_asa is not a namespace).
const NAMESPACE_PREFIXES = new Set([
  'ncsc', 'nci', 'custom', 'tenant', 'corp', 'org', 'prod', 'dev', 'test',
  'lab', 'internal', 'ext', 'external', 'collector', 'ingest', 'src', 'source',
]);
// Format / transport / collection-style tokens that are not products on their own.
const FORMAT_TOKENS = new Set([
  'syslog', 'cef', 'leef', 'json', 'xml', 'kv', 'kvp', 'raw', 'log', 'logs',
  'estreamer', 'operational', 'rfc3164', 'rfc5424', 'nopri', 'tcp', 'udp',
]);

// Strip log-rotation / size-marker suffixes so a rotated file name collapses to
// its base for recognition. Splunk/rsyslog emit the SAME source under many
// rotated names: messages-45, cron-8, dnf.librepo-3, ssl_error_log-2, plus size
// markers like *-too_small / *_too_small. All are the same source as the base
// (messages, cron, dnf_librepo, ssl_error_log). Operates on the NORMALIZED
// (underscore) form. Returns the trimmed base, or the input unchanged.
//   messages_45 → messages ; dnf_librepo_3 → dnf_librepo ; kern_837 → kern
//   ssl_error_log_2 → ssl_error_log ; cron_too_small → cron
// A PURELY numeric leading token (8010_log) is NOT a rotation — left alone (it's
// a port-numbered log, handled elsewhere). Never strips to empty.
function stripRotationSuffix(normalized: string): string {
  let s = normalized;
  // size marker: trailing _too_small
  s = s.replace(/_too_small$/, '');
  // trailing pure-numeric rotation counter, but only when the remainder still has
  // a non-numeric base (so 8010_log stays, messages_45 → messages).
  const m = s.match(/^(.*?)_(\d+)$/);
  if (m && /[a-z]/.test(m[1])) s = m[1];
  return s || normalized;
}

// Strip one leading namespace token if present. Returns the remainder (still
// separator-form) or null if nothing was stripped.
function stripNamespacePrefix(normalized: string): string | null {
  const parts = normalized.split('_');
  if (parts.length < 2) return null;
  if (NAMESPACE_PREFIXES.has(parts[0])) {
    // Strip all consecutive leading namespace tokens (ncsc_custom_cisco_asa).
    let i = 0;
    while (i < parts.length - 1 && NAMESPACE_PREFIXES.has(parts[i])) i++;
    return parts.slice(i).join('_');
  }
  return null;
}

// Strip a leading HOSTNAME token (web1, web2, srv03, node1…) — customers often
// prefix the source with the emitting host. A host is not a product; strip it and
// resolve the remainder (web2:secure_log → secure_log → linux_syslog). Only a
// short curated set of host-role words followed by digits, so we never eat a real
// leading product token (db2 stays — 'db' is deliberately excluded). Returns the
// remainder (>=1 token) or null.
function stripHostPrefix(normalized: string): string | null {
  const parts = normalized.split('_');
  if (parts.length < 2) return null;
  if (/^(web|www|host|srv|server|node|worker|vm)\d+$/.test(parts[0])) {
    return parts.slice(1).join('_');
  }
  return null;
}

// Strip trailing format/transport tokens (syslog, cef, json, tcp…) that describe
// the REPRESENTATION, not the product. `f5_bigip_syslog` → `f5_bigip`,
// `citrix_netscaler_appfw_cef` → `citrix_netscaler_appfw`. Returns the trimmed
// remainder (>=1 token) or null if nothing was stripped. Never strips down to
// empty (a name that is ONLY format tokens stays as-is).
function stripFormatSuffix(normalized: string): string | null {
  const parts = normalized.split('_');
  let end = parts.length;
  while (end > 1 && FORMAT_TOKENS.has(parts[end - 1])) end--;
  return end < parts.length ? parts.slice(0, end).join('_') : null;
}

// Preserve a customer-delivered display form (spec: canonical-name preservation).
// Trim only; keep colons/case/separators. cisco:estreamer:data:dns stays as-is;
// the underscore form is only ever a comparison key, never the display value.
function preserveDisplayForm(raw: string): string {
  return (raw || '').trim();
}

// Core deterministic resolver over an already-normalized value.
interface CoreResolution {
  canonical: string;
  tier: 'exact' | 'alias' | 'fuzzy' | 'none';
  known: boolean;
  hasGolden: boolean;
  suggestion?: string;
  confidence: 'high' | 'medium' | 'low' | 'none';
}

// Optional configuration evidence from the batch row (Screen 1). destFormat feeds
// the squashed CamelCase tier (terminal dest-token strip). packName/pipelineName are
// carried for context only — they are GENERATED from the sourcetype, so they cannot
// independently confirm it (that circular check was removed in build 412).
export interface RecognitionEvidence { packName?: string; pipelineName?: string; destFormat?: string; }

// Deterministic (no-AI) sourcetype recognition. Separates RECOGNITION (what is
// this source) from BUILDABILITY (do we have a golden). Order, cheapest first:
//   exact/alias        — resolves to a known canonical (buildable)
//   catalogue_gap      — recognition hint identifies vendor/product (no golden)
//   fuzzy→needs_confirmation — bounded edit/token match (confirm)
//   unresolved         — nothing defensible; escalates to model validation, then blocks
// A not-in-catalog name that no hint covers returns 'unresolved' here; the batch
// pre-flight then validates it with the model (aiValidate → isRealSource) exactly
// as the interactive pack generator does. Never throws; a lookup error → 'unresolved'.
export function recognizeSourcetype(sourcetypeRaw: string, evidence?: RecognitionEvidence): SourcetypeRecognition {
  const original = sourcetypeRaw || '';
  const display = preserveDisplayForm(original);
  const normalized = normalizeSourcetypeName(original);

  // Assemble a full recognition record from a core resolution + derived status.
  const finalize = (core: CoreResolution, extra?: Partial<SourcetypeRecognition>): SourcetypeRecognition => {
    let status: RecognitionStatus;
    let score: number;
    if (core.tier === 'exact') { status = 'exact'; score = core.hasGolden ? 100 : 95; }
    else if (core.tier === 'alias') { status = 'alias'; score = core.hasGolden ? 98 : 92; }
    else if (core.tier === 'fuzzy') { status = 'needs_confirmation'; score = core.confidence === 'high' ? 80 : 60; }
    else { status = 'unresolved'; score = 20; }
    return {
      original, normalized, canonical: core.canonical, canonicalDisplay: display,
      tier: core.tier, status, known: core.known, hasGolden: core.hasGolden,
      suggestion: core.suggestion, confidence: core.confidence, score,
      description: describeSourcetype(core.canonical) || undefined,
      ...extra,
    };
  };

  // Namespace strip FIRST when a curated collector/tenant prefix is present
  // (ncsc:, custom::). A namespace is not a product; strip a KNOWN prefix and
  // resolve the remainder deterministically. Only accept a known hit here.
  const stripped = stripNamespacePrefix(normalized) ?? stripHostPrefix(normalized);
  if (stripped && stripped !== normalized) {
    const alt = resolveNormalized(stripped);
    if (alt.known) return finalize(alt);
  }

  // Resolve the name as-is (no namespace, or namespace remainder wasn't known).
  const primary = resolveNormalized(normalized);
  if (primary.known) return finalize(primary);

  // ROTATION / SIZE-MARKER strip: messages-45, cron-8, dnf.librepo-3,
  // ssl_error_log-2, *-too_small all collapse to their base (messages, cron,
  // dnf_librepo, ssl_error_log). A rotated file is the SAME source as its base —
  // resolve the base and accept only a KNOWN hit (via parser/alias, e.g.
  // messages→linux_syslog). Applied to the namespace-stripped form too.
  const forRot = (stripped && stripped !== normalized) ? stripped : normalized;
  const derot = stripRotationSuffix(forRot);
  if (derot && derot !== forRot) {
    const alt = resolveNormalized(derot);
    if (alt.known) return finalize(alt);
  }

  // Trailing format/transport token strip: f5_bigip_syslog → f5_bigip. Only
  // accept a deterministic KNOWN hit — removing a format suffix should reveal a
  // real product, not a fuzzy guess.
  const base = (stripped && stripped !== normalized) ? stripped : normalized;
  const noFmt = stripFormatSuffix(base);
  if (noFmt && noFmt !== base) {
    const alt = resolveNormalized(noFmt);
    if (alt.known) return finalize(alt);
  }

  // SQUASHED / CamelCase form. A concatenated pipeline-name spelling
  // (XmlWinEventLogMicrosoftWindowsSysmonOperational_CIM) carries the right tokens
  // but no separators, so normalizeSourcetypeName can't split it. Squash both
  // sides to their separator-free token form and take an EXACT known hit — this
  // resolves the pipeline_name form to its canonical (windows_sysmon) so it uses
  // the golden/static path instead of falling to slow AI on huge XML. Strips a
  // terminal dest token (_CIM) first. Deterministic, exact — never fuzzy.
  const squashed = resolveSquashedLabel(original, evidence?.destFormat);
  if (squashed) {
    const alt = resolveNormalized(normalizeSourcetypeName(squashed));
    if (alt.known) return finalize(alt);
  }

  // RECOGNITION HINT (spec: catalogue_gap). A curated hint identifies the
  // vendor/product/log-family for a real source we have no golden for. Recognized
  // (amber), non-blocking — builds via AI on its own name, never force-mapped.
  // Feed the hint matcher the most-reduced form: strip namespace/host prefix and
  // any rotation/size suffix so a glued lone-token hint (ora → oraapxaudit) fires
  // even on oraapxaudit_too_small.
  const hintTokens = stripRotationSuffix(stripNamespacePrefix(normalized) ?? stripHostPrefix(normalized) ?? normalized);
  const hint = matchRecognitionHint(tokenizeLabel(hintTokens));
  if (hint) {
    return {
      original, normalized, canonical: normalized, canonicalDisplay: display,
      tier: 'hint', status: 'catalogue_gap', known: false, hasGolden: false,
      confidence: 'medium', score: 75,
      vendor: hint.vendor, product: hint.product, logFamily: hint.logFamily,
      description: hint.description,
      evidence: `recognized as ${hint.vendor} ${hint.product} — no golden path (build via AI)`,
    };
  }

  // Fuzzy on the stripped form as a last deterministic lead.
  if (stripped && stripped !== normalized && primary.tier === 'none') {
    const alt = resolveNormalized(stripped);
    if (alt.tier === 'fuzzy') return finalize(alt);
  }

  return finalize(primary);
}

// Core resolver over an already-normalized value. Returns exact/alias/fuzzy/none.
function resolveNormalized(normalized: string): CoreResolution {
  const canonical = SOURCETYPE_ALIASES[normalized] || normalized;

  let known = false;
  let hasGolden = false;
  try {
    // "known" = we can build it deterministically: a parser/datatype/data-class
    // OR a bundled source sample (real events → AI build). Both mean it's a real,
    // recognized source rather than an unidentifiable string. STRICT here: a mere
    // substring datatype match (cisco_asaa → cisco_asa_syslog) must NOT count, or a
    // typo is accepted as exact on its own name; such names fall through to fuzzy
    // and are corrected to the real source instead.
    known = isKnownSourcetypeStrict(canonical) || hasSourceSample(canonical);
    const goldenPath = _goldenPathPredicate;
    hasGolden = getParserFieldNames(canonical).length > 0
      && !!goldenPath && ['cim', 'ocsf', 'cef', 'ecs'].some(fmt => goldenPath(canonical, fmt));
  } catch { /* fall through as unknown */ }

  if (known) {
    const tier: 'exact' | 'alias' = normalized === canonical ? 'exact' : 'alias';
    return { canonical, tier, known: true, hasGolden, confidence: 'high' };
  }

  // Not known → bounded fuzzy match. Surface corpus first (typed forms resolving
  // through aliases), then the post-alias canonical corpus.
  if (normalized) {
    let best: string | null = null;
    let bestDist = 2; // accept distance ≤ 2
    for (const { surface, canonical: canon } of getSurfaceCorpus()) {
      const d = boundedLevenshtein(normalized, surface, bestDist);
      if (d < bestDist) { bestDist = d; best = canon; if (d === 0) break; }
    }
    if (bestDist > 0) {
      for (const cand of getKnownSourcetypeCorpus()) {
        const d = boundedLevenshtein(normalized, cand, bestDist);
        if (d < bestDist) { bestDist = d; best = cand; if (d === 0) break; }
      }
    }
    // Token-subset fallback: every meaningful token of the input appears in a
    // candidate. Format/transport tokens are ignored so "cisco_asa_syslog" still
    // matches "cisco_asa". Only when edit distance found nothing.
    //
    // Guard against a single shared token producing a bogus match: "ivanti_ps"
    // must NOT match "ivanti_vtm_audit" just because both start with "ivanti".
    // Require the input to carry at least TWO meaningful tokens (so a lone-vendor
    // prefix can't win) AND the candidate to share more than just that first
    // token. cisco_asa_syslog (2 tokens: cisco, asa) → cisco_asa still passes.
    if (!best) {
      const inTokens = normalized.split('_').filter(t => t.length > 2 && !FORMAT_TOKENS.has(t));
      if (inTokens.length >= 2) {
        for (const cand of getKnownSourcetypeCorpus()) {
          const candTokens = new Set(cand.split('_'));
          const shared = inTokens.filter(t => candTokens.has(t)).length;
          if (inTokens.every(t => candTokens.has(t)) && shared >= 2) { best = cand; bestDist = 2; break; }
        }
      }
    }
    if (best) {
      const confidence: 'high' | 'medium' = bestDist <= 1 ? 'high' : 'medium';
      return { canonical: best, tier: 'fuzzy', known: false, hasGolden: false, suggestion: best, confidence };
    }
  }

  return { canonical, tier: 'none', known: false, hasGolden: false, confidence: 'none' };
}

const SOURCETYPE_DESCRIPTIONS: Record<string, string> = {
  cisco_asa: 'Cisco ASA/FTD firewall syslog',
  palo_alto_traffic: 'Palo Alto Networks traffic logs',
  palo_alto_threat: 'Palo Alto Networks threat logs',
  palo_alto_system: 'Palo Alto Networks system logs',
  fortinet_fortigate: 'FortiGate firewall key=value syslog',
  checkpoint_firewall: 'Check Point firewall logs',
  aws_vpc_v5: 'AWS VPC Flow Logs',
  aws_cloudtrail: 'AWS CloudTrail API audit',
  zscaler_web: 'Zscaler NSS web proxy logs',
  cisco_esa: 'Cisco Email Security Appliance',
  windows_security: 'Windows Security Event Log (XML)',
  windows_powershell: 'Windows PowerShell script block logs',
  windows_sysmon: 'Windows Sysmon endpoint telemetry',
  windows_system: 'Windows System Event Log channel (XML)',
  windows_application: 'Windows Application Event Log channel (XML)',
  windows_defender: 'Microsoft Defender Antivirus operational log (XML)',
  windows_dns_client: 'Windows DNS Client operational log (XML)',
  azure_signin: 'Azure AD sign-in logs',
  okta_system: 'Okta system authentication logs',
  sap_audit: 'SAP Security Audit Log',
  sap_audit_tlv: 'SAP Security Audit Log (binary length-prefixed TLV / RSAU)',
  sap_hana: 'SAP HANA indexserver/nameserver trace and audit logs',
  crowdstrike_falcon: 'CrowdStrike Falcon endpoint detection',
  linux_audit: 'Linux auditd logs',
  linux_syslog: 'Linux syslog (auth/daemon/kern)',
  gcp_audit: 'Google Cloud audit logs',
  alibaba_action_trail: 'Alibaba Cloud ActionTrail',
  apache_access: 'Apache HTTP access log (combined)',
  nginx_access: 'Nginx HTTP access log',
  infoblox_dns: 'Infoblox DNS query logs',
  corelight_dns: 'Corelight/Zeek DNS logs',
  corelight_conn: 'Corelight/Zeek connection logs',
  suricata_ids: 'Suricata IDS/IPS JSON alerts',
  cisco_meraki: 'Cisco Meraki MX firewall syslog',
  duo_security: 'Duo Security authentication logs',
  carbonblack_edr: 'VMware Carbon Black EDR events',
};

export function describeSourcetype(sourcetypeRaw: string): string {
  const canonical = canonicalizeSourcetype(sourcetypeRaw);
  if (SOURCETYPE_DESCRIPTIONS[canonical]) return SOURCETYPE_DESCRIPTIONS[canonical];
  // Check datatype parsers for a description
  const dtp = DATATYPE_PARSERS[canonical];
  if (dtp && dtp.description) return dtp.description;
  // Check if it has a known data class — at least classify it
  const dc = SOURCETYPE_DATACLASS[canonical];
  if (dc && dc !== 'generic') {
    const words = canonical.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    const classLabel = dc.replace(/_/g, ' ');
    return `${words} (${classLabel})`;
  }
  // Check if it has a parser (known) — title case it
  if (getParserFieldNames(canonical).length > 0) {
    return canonical.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  }
  // Substring-matched Cribl Search stock datatype parser (e.g.
  // cisco:estreamer:data:firewall → cisco_estreamer). Surface the matched
  // parser's own description so the row doesn't read "Unknown source type"
  // when it is in fact buildable via a stock parser.
  const dtpFns = getDatatypeParserFunctions(canonical);
  if (dtpFns) {
    const matched = DATATYPE_PARSERS[dtpFns.searchDatatypeId] || Object.values(DATATYPE_PARSERS).find(p => p.searchDatatypeId === dtpFns.searchDatatypeId);
    if (matched?.description) return `${matched.description} (via ${dtpFns.searchDatatypeId})`;
    return canonical.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  }
  return 'Unknown source type';
}

// --- Cribl Search datatype parsers (fallback library) ---
// Translated from Cribl Search stock datatypes (config/datatype-parsers.json).
// Used as a fallback in getParserForSourcetype for sourcetypes that don't have a
// hand-tuned built-in parser. Hand-built parsers always take priority.

interface DatatypeParser {
  dataFormat: string;
  functions: PipelineFunction[];
  fields: string[];
  timeField: string | null;
  searchDatatypeId: string;
  description: string;
}
const BUNDLED_DATATYPE_PARSERS: Record<string, DatatypeParser> =
  (datatypeParsersData as { parsers: Record<string, DatatypeParser> }).parsers;

// The live store. Standalone syncs the Search catalog into the bundled JSON on
// disk; the iframe cannot, so it layers a per-install overlay on top (see
// src/datatype-overlay.ts). Everything below resolves against THIS map, so an
// imported parser is usable by the builder the moment the overlay is installed.
const DATATYPE_PARSERS: Record<string, DatatypeParser> = { ...BUNDLED_DATATYPE_PARSERS };

export function getBundledDatatypeParsers(): Record<string, DatatypeParser> {
  return BUNDLED_DATATYPE_PARSERS;
}

export function getDatatypeParserStore(): Record<string, DatatypeParser> {
  return { ...DATATYPE_PARSERS };
}

/**
 * Replace the live store with bundled + overlay. Rebuilt from the bundled
 * baseline every time, so installing twice is the same as installing once, and
 * an overlay that shrinks actually gives parsers back.
 */
export function installDatatypeParserOverlay(
  overlay: { parsers?: Record<string, DatatypeParser>; removed?: string[] } | null | undefined,
): { count: number; added: number; removed: number } {
  for (const key of Object.keys(DATATYPE_PARSERS)) delete DATATYPE_PARSERS[key];
  Object.assign(DATATYPE_PARSERS, BUNDLED_DATATYPE_PARSERS);
  let removed = 0;
  for (const id of overlay?.removed || []) {
    if (id in DATATYPE_PARSERS) { delete DATATYPE_PARSERS[id]; removed++; }
  }
  const added = Object.keys(overlay?.parsers || {}).length;
  Object.assign(DATATYPE_PARSERS, overlay?.parsers || {});
  // These are memoized from the store, so they are wrong the instant it changes.
  _supportedCatalog = null;
  _knownSourcetypeCorpus = null;
  return { count: Object.keys(DATATYPE_PARSERS).length, added, removed };
}

// Return JUST the Cribl Search datatype parser functions for a sourcetype (or
// null if none / it has no real parse functions). Exposed so the extraction
// resolver can offer Search extraction as the HIGHEST-priority candidate,
// independent of the hand-built parser (which resolveDatatypeParser is only a
// fallback for inside getParserForSourcetype).
// Header-optional fallback shared by name- and sample-driven resolution: the PAN
// (and similar) Search parsers are 2-stage — a regex_extract pulls the CSV body
// out of the syslog header into `__payload`, then a serde parses `__payload`. But
// real events often arrive WITHOUT the `<priority>`/syslog-header prefix (the
// reference PAN samples do), so the header regex doesn't match, `__payload` is
// never set, and the serde reads nothing → 0 fields extracted. Inject
// `__payload = __payload || _raw` right before any serde that reads `__payload`,
// so the serde always has the raw line to parse when there was no header to strip.
function injectPayloadFallback(fns: PipelineFunction[]): PipelineFunction[] {
  const functions: PipelineFunction[] = [];
  let payloadFallbackAdded = false;
  for (const f of fns) {
    const srcField = (f.conf as any)?.srcField;
    if (f.id === 'serde' && srcField === '__payload' && !payloadFallbackAdded) {
      functions.push({
        id: 'eval', filter: 'true',
        description: 'Fall back to _raw when there is no syslog header to strip',
        conf: { add: [{ name: '__payload', value: "__payload || _raw" }] },
      });
      payloadFallbackAdded = true;
    }
    functions.push(f);
  }
  return functions;
}

export function getDatatypeParserFunctions(sourcetypeRaw: string): { functions: PipelineFunction[]; fields: string[]; searchDatatypeId: string } | null {
  const dtp = resolveDatatypeParser(sourcetypeRaw);
  if (!dtp) return null;
  const real = dtp.functions.filter(f => f.id !== 'comment');
  if (real.length === 0) return null;
  return { functions: injectPayloadFallback(dtp.functions), fields: dtp.fields || [], searchDatatypeId: dtp.searchDatatypeId };
}

// --- Sample-shape stock-parser matching (lever B) ---------------------------
// For an UNKNOWN sourcetype (no built-in parser, no name-matched stock parser,
// no golden replay), pick the Cribl Search stock parser whose EXTRACTION LOGIC
// actually fits THIS sample — matched by CONTENT SHAPE, not by name. Two signals,
// both run locally in JS against the real sample (no Cribl round-trip):
//   • regex anchor match — run the parser's leading regex_extract over the sample
//     lines; a parser designed for this data matches most lines and captures
//     several named groups. Strongest signal for raw/syslog sources (exactly the
//     case AI otherwise guesses at). Catch-all anchors (<2 captured groups) are
//     rejected so a `(?<msg>.*)` parser can't win by matching everything.
//   • declared-field overlap — for structured kvp/csv sources the parser is a
//     wildcard serde, so compare the parser's declared `fields[]` against the
//     sample's actual keys.
// Deliberately conservative: returns a match only above a high confidence bar,
// else null so the caller falls through to AI (today's behavior). A wrong silent
// pick is the risk, so the bar is set to "this parser clearly fits", and the
// chosen parser + the confidence of the runners-up are logged (no silent caps).

export interface DatatypeSampleMatch {
  parserKey: string;
  searchDatatypeId: string;
  functions: PipelineFunction[];
  fields: string[];
  confidence: number;         // 0..1
  method: 'regex' | 'fields';
  runnersUp: string[];        // "key:conf" for the next-best candidates (diagnostics)
}

// Convert a Cribl regex STRING form (`/pattern/flags`) to a JS RegExp. Named
// groups are standard JS; strip any flags V8 won't accept. Returns null on any
// pattern JS can't compile (so a bad parser regex just skips that candidate).
function criblRegexToJs(rx: string, extraFlags = ''): RegExp | null {
  try {
    const m = /^\/([\s\S]*)\/([a-z]*)$/.exec((rx || '').trim());
    const pattern = m ? m[1] : rx;
    const flags = ((m ? m[2] : '') + extraFlags).replace(/[^gimsuy]/g, '');
    // dedupe flags (RegExp throws on repeats)
    return new RegExp(pattern, [...new Set(flags.split(''))].join(''));
  } catch { return null; }
}

// Named groups that carry only the SYSLOG ENVELOPE, not source content. A parser
// whose leading regex captures only these matched the transport, not the data —
// it must not qualify as a content match (see matchDatatypeParserBySample).
const ENVELOPE_GROUP_NAMES = new Set([
  'priority', 'pri', 'syslog_pri', 'facility',
  'syslog_timestamp', 'timestamp', 'syslog_host', 'host', 'hostname',
  'app', 'appname', 'app_name', 'process', 'proc', 'pid', 'procid', 'tag',
  'message', 'msg', 'payload',
]);

// ---------------------------------------------------------------------------
// JSON content-signature recognition.
//
// Every JSON datatype parser we sync from Cribl Search is a bare `json` serde
// declaring only `fields: ["_raw"]`, so `matchDatatypeParserBySample`'s
// field-overlap signal can never identify a SPECIFIC JSON source — every JSON
// sample falls through to "self-describing". That is fine for sanitisation
// (field names come from the data) but leaves well-known JSON feeds unnamed.
//
// This table names a JSON source by its distinctive top-level key set. A
// signature matches when EVERY `required` key is present (case-insensitive) and,
// if given, at least `minAny` of `any` keys are present. The most specific
// signature (most required keys) wins. Keep signatures tight enough that they
// cannot collide with an unrelated JSON feed.
interface JsonSignatureSource {
  sourcetype: string;
  required: string[];
  any?: string[];
  minAny?: number;
  description: string;
}

const JSON_SIGNATURE_SOURCES: JsonSignatureSource[] = [
  {
    // Microsoft 365 / Office 365 Unified Audit Log (Management Activity API).
    // The Common schema is shared across every workload (Exchange, SharePoint,
    // AzureActiveDirectory, …), so this canonical sourcetype covers them all.
    sourcetype: 'o365_management_activity',
    required: ['RecordType', 'CreationTime', 'Operation', 'OrganizationId', 'Workload', 'UserKey', 'UserType'],
    description: 'Microsoft 365 Unified Audit Log (Management Activity API) — JSON per record',
  },
];

export interface JsonSignatureMatch {
  sourcetype: string;
  matched: string[];
  description: string;
}

/**
 * Recognise a well-known JSON source by its top-level key signature. Returns null
 * for non-JSON samples, empty input, or any JSON that matches no signature (the
 * common case — it stays self-describing). Pure and offline (Hard Rule 23).
 */
export function matchJsonSignature(sampleEvents: string): JsonSignatureMatch | null {
  const rawLines = (sampleEvents || '').split('\n').map(l => l.trim()).filter(Boolean).slice(0, 40);
  if (rawLines.length === 0) return null;
  const { format, keys } = extractSampleKeys(rawLines);
  if (format !== 'json' || keys.size === 0) return null;
  const present = new Set([...keys].map(k => k.toLowerCase()));
  let best: JsonSignatureSource | null = null;
  for (const sig of JSON_SIGNATURE_SOURCES) {
    if (!sig.required.every(k => present.has(k.toLowerCase()))) continue;
    if (sig.any && sig.any.length) {
      const hit = sig.any.filter(k => present.has(k.toLowerCase())).length;
      if (hit < (sig.minAny ?? 1)) continue;
    }
    if (!best || sig.required.length > best.required.length) best = sig;
  }
  return best ? { sourcetype: best.sourcetype, matched: best.required, description: best.description } : null;
}

export function matchDatatypeParserBySample(sampleEvents: string): DatatypeSampleMatch | null {
  const rawLines = (sampleEvents || '').split('\n').map(l => l.trim()).filter(Boolean).slice(0, 40).map(stripOuterQuotes);
  if (rawLines.length === 0) return null;
  const { keys } = extractSampleKeys(rawLines);
  const sampleKeysLc = new Set([...keys].map(k => k.toLowerCase()));

  interface Cand { key: string; conf: number; method: 'regex' | 'fields' }
  const cands: Cand[] = [];

  for (const [key, dtp] of Object.entries(DATATYPE_PARSERS)) {
    if (dtp.functions.filter(f => f.id !== 'comment').length === 0) continue;

    // Signal 1 — anchor-regex match + capture richness. A parser may carry
    // several alternative header regexes (e.g. ASA with vs without a year in the
    // timestamp); test each and keep the best-fitting anchor.
    let regexConf = 0;
    const anchorFns = dtp.functions.filter(f => f.id === 'regex_extract' && (f.conf as any)?.regex);
    for (const anchorFn of anchorFns) {
      const rxStr = String((anchorFn.conf as any).regex);
      const anchor = criblRegexToJs(rxStr);
      const groupCount = (rxStr.match(/\(\?<[A-Za-z_$][\w$]*>/g) || []).length;
      if (!anchor || groupCount === 0) continue;
      let matched = 0, contentSum = 0;
      for (const line of rawLines) {
        const mm = line.match(anchor);
        if (mm) {
          matched++;
          const g = mm.groups || {};
          // Count only CONTENT groups toward richness — exclude syslog-envelope
          // and `__scratch` names. A generic envelope parser (fortinet/pan
          // "_syslog_wrapped") captures syslog_timestamp/host/app/__payload for
          // ANY syslog line; without this it would win on the envelope alone and
          // mis-assign a wholly different source. Only real extracted content
          // (client_ip, http_status, query_name, …) should qualify a match.
          for (const [gk, gv] of Object.entries(g)) {
            if (gv == null || String(gv).trim() === '') continue;
            if (gk.startsWith('__')) continue;
            // Normalize a leading `syslog_` prefix so syslog_priority /
            // syslog_hostname / syslog_timestamp all fold onto the base envelope
            // names below (PAN/fortinet wrapped parsers use the prefixed form).
            const norm = gk.toLowerCase().replace(/^syslog_/, '');
            if (ENVELOPE_GROUP_NAMES.has(norm)) continue;
            contentSum++;
          }
        }
      }
      const matchRate = matched / rawLines.length;
      const avgContent = matched ? contentSum / matched : 0;
      // Reject catch-all / envelope-only anchors: require ≥2 real content groups.
      if (avgContent >= 2 && matchRate > regexConf) regexConf = matchRate;
    }

    // Signal 2 — declared-field overlap (structured kvp/csv wildcards).
    let fieldConf = 0;
    if (sampleKeysLc.size >= 3 && (dtp.fields || []).length) {
      const pf = new Set(dtp.fields.map(f => f.toLowerCase()));
      let hit = 0;
      for (const k of sampleKeysLc) if (pf.has(k)) hit++;
      // require at least 3 overlapping keys so {host,time,message} coincidences
      // can't score a spurious match.
      if (hit >= 3) fieldConf = hit / sampleKeysLc.size;
    }

    const method: 'regex' | 'fields' = regexConf >= fieldConf ? 'regex' : 'fields';
    const conf = Math.max(regexConf, fieldConf);
    if (conf > 0) cands.push({ key, conf, method });
  }

  if (cands.length === 0) return null;
  cands.sort((a, b) => b.conf - a.conf);
  const top = cands[0];
  // Acceptance bar: a regex anchor must fit ≥75% of lines; a field-overlap match
  // must cover ≥60% of the sample's keys. Below that, fall through to AI.
  const bar = top.method === 'regex' ? 0.75 : 0.6;
  if (top.conf < bar) return null;

  const dtp = DATATYPE_PARSERS[top.key];
  return {
    parserKey: top.key,
    searchDatatypeId: dtp.searchDatatypeId,
    functions: injectPayloadFallback(dtp.functions),
    fields: dtp.fields || [],
    confidence: top.conf,
    method: top.method,
    runnersUp: cands.slice(1, 4).map(c => `${c.key}:${c.conf.toFixed(2)}`),
  };
}

// Resolve a sourcetype to a Search-datatype parser. Matches by exact id, then by
// a normalized/aliased form (e.g. palo_alto_traffic → pan_traffic_syslog).
function resolveDatatypeParser(sourcetypeRaw: string, strict = false): DatatypeParser | null {
  const st = (sourcetypeRaw || '').toLowerCase().replace(/[\s-]+/g, '_');
  if (DATATYPE_PARSERS[st]) return DATATYPE_PARSERS[st];
  // Common name → datatype-id aliases for our wizard sourcetypes.
  const ALIAS: Record<string, string> = {
    palo_alto_traffic: 'pan_traffic_syslog', palo_alto_threat: 'pan_threat_syslog',
    cisco_asa: 'cisco_asa_syslog', fortinet_fortigate: 'fortinet_fortigate_syslog_wrapped',
    windows_security: 'microsoft_windows_eventlog_classic', linux_audit: 'linux_auditd_log',
    apache_access: 'apache_httpd_accesslog_combined',
    nginx_access: 'nginx_accesslog',
    // Graph JSON sign-ins (v2 Search datatype). Do not alias syslog-shaped
    // wizard names like okta_system onto JSON-only v2 IDs.
    azure_signin: 'azure_graph_signins',
    azure_signinlogs: 'azure_graph_signins',
  };
  if (ALIAS[st] && DATATYPE_PARSERS[ALIAS[st]]) return DATATYPE_PARSERS[ALIAS[st]];
  // STRICT callers (the recognizer's exactness check) stop here: only an EXACT or
  // aliased datatype id counts as a genuinely-known name. The lenient substring
  // match below is a BUILD-path convenience (pick the closest parser for whatever
  // name survived recognition) — but as a recognition signal it wrongly flags a
  // near-miss (`cisco_asaa` → substring `cisco_asa`) as an exact known sourcetype,
  // so the demo generator accepts the typo on its own name and synthesises a sample
  // instead of correcting to the real `cisco_asa` (which has a golden path + sample).
  if (strict) return null;
  // Substring match (e.g. "infoblox" → infoblox_syslog). Prefer a candidate that
  // actually has parse functions, and prefer _syslog over _csv/_nopri variants.
  // JSON-only v2 parsers are exact/alias matches only — substring would let
  // "audit" steal aws_eks_audit / gitlab_audit_log / etc.
  const candidates = Object.keys(DATATYPE_PARSERS).filter(k => {
    const p = DATATYPE_PARSERS[k];
    const jsonOnly = /json|ndjson/i.test(p.dataFormat || '')
      && !p.functions.some(f => f.id === 'regex_extract' || (f.id === 'serde' && (f.conf as { type?: string })?.type !== 'json'));
    if (jsonOnly) return false;
    return k.includes(st) || st.includes(k.replace(/_syslog|_log$|_csv$/, ''));
  });
  if (candidates.length === 0) return null;
  const scored = candidates
    .map(k => ({ k, p: DATATYPE_PARSERS[k] }))
    .sort((a, b) => {
      const fa = a.p.functions.filter(f => f.id !== 'comment').length;
      const fb = b.p.functions.filter(f => f.id !== 'comment').length;
      if ((fb > 0 ? 1 : 0) !== (fa > 0 ? 1 : 0)) return (fb > 0 ? 1 : 0) - (fa > 0 ? 1 : 0);
      const rank = (k: string) => k.endsWith('_syslog') ? 0 : /_nopri$|_csv$/.test(k) ? 2 : 1;
      return rank(a.k) - rank(b.k);
    });
  return scored[0].p;
}

// --- Parsers ---

/**
 * The XML front-end EVERY XmlWinEventLog channel shares: `C.Text.parseWinEvent`
 * over a de-braced `_raw`, flatten, then strip the verbose `_raw_Event_<Section>_`
 * path prefixes so `<EventID>` reads as `EventID` and `<Data Name='QueryName'>` as
 * `QueryName`. Only the ALIAS step that follows is channel-specific, because each
 * channel's EventData carries different Data Name attributes.
 *
 * `stripSpaces` adds a second rename that removes spaces from field names: the
 * Defender channel names its entries `Threat Name`/`Action Name`/`Product Name`,
 * and a field name containing a space is not a valid Cribl accessor path (same
 * class of failure as the hyphenated SAP keys — it throws at eval-init, and even
 * a bracket read cannot rescue it).
 */
function windowsXmlFrontEnd(channel: string, stripSpaces = false): PipelineFunction[] {
  const fns: PipelineFunction[] = [
    {
      id: 'eval',
      description: `Parse and compact ${channel} XML with the native Windows event parser`,
      conf: {
        add: [
          { name: '_raw', value: "_raw.replace(/[{}\\t]/gm,'').replace(/[\\n\\r]+/gm,',')" },
          { name: '_raw', value: "C.Text.parseWinEvent(_raw,['0x0','0','-'])" },
        ],
      },
    },
    {
      id: 'flatten',
      description: 'Flatten the parsed Windows event into top-level fields',
      conf: { fields: ['_raw'], prefix: '', depth: 5, delimiter: '_' },
    },
    {
      id: 'rename',
      description: 'Remove verbose Windows XML path prefixes from field names',
      conf: { baseFields: [], renameExpr: "name.replace(/_raw_Event_\\w+_/,'')", rename: [] },
    },
  ];
  if (stripSpaces) {
    fns.push({
      id: 'rename',
      description: 'Remove spaces from EventData field names (a space is not a valid accessor path)',
      conf: { baseFields: [], renameExpr: "name.replace(/ /g,'')", rename: [] },
    });
  }
  return fns;
}

/** Windows Event `Level` → syslog severity number. Shared by every channel. */
const WINDOWS_LEVEL_TO_SEVERITY =
  "Level == '0' ? 6 : Level == '1' ? 2 : Level == '2' ? 3 : Level == '3' ? 4 : Level == '4' ? 6 : Level == '5' ? 7 : undefined";

/**
 * Canonical Windows Event-Log channels + PowerShell — the families where code
 * functions are ALWAYS permitted (Hard Rule 3 + the user's standing rule,
 * 2026-08-31: "for this xmlwineventlog, we should always allow a code function,
 * as these windows events are hard to do, same as powershell").
 *
 * Windows XML EventData and PowerShell ScriptBlock logs are too irregular to
 * parse reliably with regex_extract alone, so `allowCodeFunctions` is forced ON
 * for these regardless of the wizard toggle (`isWindowsCodeFamily`, consulted at
 * the `buildStagedPipeline` choke point). The shipped static parsers already use
 * the native `C.Text.parseWinEvent` eval — which needs no code function — so the
 * guarantee is what unblocks a code-based iterator for any UNRECOGNISED channel
 * that falls through to the AI parse path, and future-proofs the policy.
 */
export const WINDOWS_CODE_FAMILY: ReadonlySet<string> = new Set<string>([
  'windows_security', 'windows_sysmon', 'windows_powershell', 'windows_dns_client',
  'windows_defender', 'windows_system', 'windows_application',
]);

/** True when a sourcetype is a Windows XML channel or PowerShell — code always allowed. */
export function isWindowsCodeFamily(sourcetypeRaw: string): boolean {
  return WINDOWS_CODE_FAMILY.has(canonicalizeSourcetype(sourcetypeRaw));
}

export function getParserForSourcetype(sourcetypeRaw: string, _allowCodeFunctions: boolean): PipelineFunction[] {
  const sourcetype = canonicalizeSourcetype(sourcetypeRaw);
  switch (sourcetype) {
    case 'cisco_asa': {
      // Lookup-DRIVEN parsing (mirrors the professional cribl-cisco-asa-cleanup /
      // cribl-cisco-ftd-cleanup packs): extract the message code, fetch its
      // code-specific regex from the bundled parsing lookup (ASA: 184 codes,
      // FTD: 168 codes — shipped to data/lookups/ at deploy time), then apply
      // that regex dynamically. Covers EVERY code in the lookup, not just the
      // handful visible in the sample events.
      //
      // FTD aliases to this case (same %XXX-sev-id: syslog structure) but keys
      // on ftd_code against cisco_ftd_parsing.csv. The raw sourcetype selects
      // the correct lookup file + key column so the bundled CSV always matches.
      const isFtd = /ftd|firepower/.test((sourcetypeRaw || '').toLowerCase());
      const lookupFile = isFtd ? 'cisco_ftd_parsing.csv' : 'cisco_asa_parsing.csv';
      const codeField = isFtd ? 'ftd_code' : 'asa_code';
      const codeCount = isFtd ? 168 : 184;
      // Header timestamp is "MMM D YYYY HH:MM:SS" — a hostname token optionally
      // follows before the ": %ASA-" marker (SNL-ASA-VPN-A01 in most events;
      // absent when the ASA has no configured `logging host` hostname).
      const TS_RE = '\\w{3}\\s+\\d{1,2}\\s+\\d{4}\\s+\\d{2}:\\d{2}:\\d{2}';
      return [
        {
          id: 'eval',
          description: 'Extract severity, message code, timestamp, and device host from the syslog header (%ASA-/%FTD-)',
          conf: {
            add: [
              { name: 'severity', value: "_raw.match(/%(?:ASA|FTD)-(\\d)-\\d+:/) ? _raw.match(/%(?:ASA|FTD)-(\\d)-\\d+:/)[1] : null" },
              { name: codeField, value: "_raw.match(/%(?:ASA|FTD)-\\S*-(\\d+):/) ? _raw.match(/%(?:ASA|FTD)-\\S*-(\\d+):/)[1] : null" },
              // event_code drives the golden CIM's signature_id <- event_code fallback.
              { name: 'event_code', value: `${codeField} || undefined` },
              { name: 'log_time', value: `_raw.match(/^(${TS_RE})/) ? Date.parse(_raw.match(/^(${TS_RE})/)[1]) / 1000 : undefined` },
              { name: 'host', value: `_raw.match(/^${TS_RE}\\s+(\\S+)\\s*:\\s*%(?:ASA|FTD)-/) ? _raw.match(/^${TS_RE}\\s+(\\S+)\\s*:\\s*%(?:ASA|FTD)-/)[1] : undefined` },
            ],
          },
        },
        {
          id: 'lookup',
          filter: 'true',
          description: `Fetch the per-code extraction regex for this code (${codeCount} codes)`,
          conf: {
            // matchType MUST be omitted — adding matchType:'first' breaks the
            // regex-column lookup (verified against cribl-cisco-asa-cleanup).
            matchMode: 'exact',
            reloadPeriodSec: 60,
            addToEvent: false,
            ignoreCase: false,
            inFields: [{ eventField: codeField, lookupField: codeField }],
            outFields: [{ lookupField: 'regex', eventField: '__regex' }],
            file: lookupFile,
          },
        },
        {
          id: 'eval',
          filter: '__regex && _raw.match(__regex)',
          description: 'Apply the code-specific regex and spread its named groups onto the event',
          conf: {
            add: [
              { name: 'groups', value: '_raw.match(__regex).groups' },
              { name: '', value: 'Object.assign(__e, groups)' },
            ],
            remove: ['groups', '__regex'],
          },
        },
        {
          id: 'eval',
          description: 'Alias per-code fields to CIM canonical names + fallback action verb',
          conf: {
            add: [
              // Normalize transport to lowercase; infer 'icmp' when icmp fields present but no explicit transport
              { name: 'transport', value: "transport ? transport.toLowerCase() : (icmp_type != null || icmp_code != null) ? 'icmp' : undefined" },
              { name: 'bytes_out', value: 'bytes != null ? Number(bytes) : undefined' },
              { name: 'action', value: "action || (_raw.match(/\\b(Deny|Denied|Permit|Permitted|Built|Teardown|Allow|Allowed|Block|Blocked|Reset|Drop|Dropped)\\b/i) ? _raw.match(/\\b(Deny|Denied|Permit|Permitted|Built|Teardown|Allow|Allowed|Block|Blocked|Reset|Drop|Dropped)\\b/i)[1] : undefined)" },
              { name: 'user', value: "src_nt_domain ? src_nt_domain + '\\\\' + (src_user || '') : src_user || src_sg_info || user || undefined" },
              { name: 'src_zone', value: 'src_interface || undefined' },
              { name: 'dest_zone', value: 'dest_interface || undefined' },
              { name: 'duration', value: 'duration_hour != null ? Number(duration_hour) * 3600 + Number(duration_minute) * 60 + Number(duration_second) : undefined' },
              // Only emit icmp_type/icmp_code when transport is ICMP (106023 TCP events capture ACL annotations as "type X, code Y")
              { name: 'icmp_type', value: "/icmp/i.test(String(transport)) ? icmp_type : undefined" },
              { name: 'icmp_code', value: "/icmp/i.test(String(transport)) ? icmp_code : undefined" },
            ],
          },
        },
      ];
    }

    case 'f5_bigip': {
      // F5 BIG-IP LTM/TMM syslog (RFC3164). Lines carry an OPTIONAL <priority>
      // prefix, then a syslog header, then an optional F5 message-id
      // (`01260013:5`), then the free-text message. The golden extraction regex
      // began with `\w` and could NOT match the leading `<134>`, so extraction
      // scored 0 and every format (asim/cim/ocsf) fell to the slow AI retry.
      // Emit the canonical field model the f5 mapping goldens read
      // (src_ip/dest_ip/dest_port/host/severity/log_time/message + F5 specifics).
      return [
        {
          id: 'regex_extract',
          description: 'Parse F5 syslog header WITH message-id (optional <priority> prefix)',
          conf: {
            source: '_raw',
            regex: '/^(?:<(?<syslog_pri>\\d+)>)?(?<timestamp>\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(?<host>[\\w.\\-]+)\\s+(?<severity>\\w+)\\s+(?<process>[\\w\\-]+)\\[(?<pid>\\d+)\\]:\\s+(?<msg_id>\\d[\\d:]*\\d):\\s+(?<message>.+)$/',
            iterations: 1,
            overwrite: false,
          },
        },
        {
          id: 'regex_extract',
          filter: 'message == undefined',
          description: 'Parse F5 syslog header WITHOUT message-id (syslog-ng, httpd, mcpd)',
          conf: {
            source: '_raw',
            regex: '/^(?:<(?<syslog_pri>\\d+)>)?(?<timestamp>\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(?<host>[\\w.\\-]+)\\s+(?<severity>\\w+)\\s+(?<process>[\\w\\-]+)\\[(?<pid>\\d+)\\]:\\s+(?<message>.+)$/',
            iterations: 1,
            overwrite: false,
          },
        },
        {
          id: 'regex_extract',
          filter: 'message != undefined',
          description: 'Pull client/server endpoints, pool, node, virtual, monitor status from the message body',
          conf: {
            source: 'message',
            // All groups optional — a given F5 message carries only some. Two
            // passes below (client-side vs pool/node member-side) keep src vs
            // dest unambiguous.
            regex: '/(?:\\bclient\\s+(?<src_ip>[\\d.]+):(?<src_port>\\d+))?(?:.*?\\b(?:member|node|server)\\s+\\S*?(?<dest_ip>[\\d.]+):(?<dest_port>\\d+))?(?:.*?\\bPool\\s+(?<pool>\\S+))?(?:.*?\\bvirtual\\s+(?<virtual>\\S+))?(?:.*?\\bstatus\\s+(?<status_code>\\d{3})\\b)?/i',
            iterations: 1,
            overwrite: false,
          },
        },
        {
          id: 'regex_extract',
          filter: "message && /\\bAUDIT\\b/.test(message)",
          description: 'Pull tmsh AUDIT fields (user, folder, module, status, cmd_data) from the message body',
          conf: {
            source: 'message',
            // tmsh audit lines: `AUDIT - pid=7354 user=root folder=/ module=(tmos)#
            // status=[Command OK] cmd_data=list cm device recursive`. A kvp serde
            // cannot read these: `status=[Command OK]` and the trailing free-text
            // `cmd_data=` both contain spaces, so it would split them mid-value.
            // `user=` is required (the filter guarantees an AUDIT line); the rest
            // are optional because not every audit line carries all of them.
            regex: '/\\buser=(?<user>\\S+)(?:\\s+folder=(?<folder>\\S+))?(?:\\s+module=(?<module>\\S+))?(?:\\s+status=\\[(?<status>[^\\]]*)\\])?(?:\\s+cmd_data=(?<cmd_data>.+))?/',
            iterations: 1,
            overwrite: false,
          },
        },
        {
          id: 'eval',
          description: 'Derive log_time from the syslog timestamp (add current year) + normalize severity/action',
          conf: {
            add: [
              // Syslog RFC3164 timestamp has no year — Date.parse needs one.
              { name: 'log_time', value: "timestamp ? Date.parse(timestamp + ' ' + new Date().getUTCFullYear()) / 1000 : undefined" },
              { name: 'ssl_event', value: "message && /SSL[\\w\\s()]*(?:failed|error|success)/i.test(message) ? message.match(/SSL[\\w\\s()]*(?:failed|error|success)/i)[0] : undefined" },
              { name: 'action', value: "message && /\\b(down|up|failed|success|blocked|denied|reload|reset|disconnect)\\b/i.test(message) ? message.match(/\\b(down|up|failed|success|blocked|denied|reload|reset|disconnect)\\b/i)[1].toLowerCase() : undefined" },
            ],
          },
        },
      ];
    }

    case 'cisco_esa':
      // Cisco ESA (IronPort) AsyncOS mail_logs are plain text, one physical
      // line per event, but a single message spans MANY lines correlated by
      // MID/ICID. A flat pipeline cannot stitch those together, so we do
      // best-effort PER-LINE extraction: parse the common header, then pull
      // the identifiers/fields that appear on whichever line this event is.
      // Downstream correlation (sender IP ↔ MID) would need a stateful step.
      return [
        {
          id: 'regex_extract',
          description: 'Extract ESA log header (timestamp, level, message body)',
          conf: {
            source: '_raw',
            // Day is space-padded, so allow 1-2 spaces between month and day.
            regex: '/^(?<log_time>\\w{3}\\s+\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+\\d{4})\\s+(?<level>Info|Warning|Critical|Debug|Trace):\\s+(?<msg_body>.*)$/',
          },
        },
        {
          id: 'regex_extract',
          description: 'Extract message/connection identifiers (MID, ICID, DCID, RID)',
          conf: {
            source: 'msg_body',
            // All optional — a given line carries only some of these.
            regex: '/(?:\\bMID\\s+(?<mid>\\d+))?(?:.*?\\bICID\\s+(?<icid>\\d+))?(?:.*?\\bDCID\\s+(?<dcid>\\d+))?(?:.*?\\bRID\\s+\\[?(?<rid>\\d+))?/',
          },
        },
        {
          id: 'regex_extract',
          filter: "msg_body && msg_body.indexOf('New SMTP ICID') >= 0",
          description: 'Parse new inbound SMTP connection (sender IP + reverse DNS)',
          conf: {
            source: 'msg_body',
            regex: '/New SMTP ICID\\s+\\d+\\s+interface\\s+(?<interface>\\S+).*?address\\s+(?<src_ip>[\\d.]+)\\s+reverse dns host\\s+(?<reverse_dns>\\S+)\\s+verified\\s+(?<dns_verified>\\w+)/',
          },
        },
        {
          id: 'regex_extract',
          filter: "msg_body && msg_body.indexOf('From:') >= 0",
          description: 'Parse envelope sender (From)',
          conf: {
            source: 'msg_body',
            regex: '/From:\\s+<?(?<sender>[^>\\s]+)>?/',
          },
        },
        {
          id: 'regex_extract',
          filter: "msg_body && msg_body.indexOf('To:') >= 0",
          description: 'Parse envelope recipient (To)',
          conf: {
            source: 'msg_body',
            regex: '/To:\\s+<?(?<recipient>[^>\\s]+)>?/',
          },
        },
        {
          id: 'regex_extract',
          filter: "msg_body && msg_body.indexOf('Subject') >= 0",
          description: 'Parse subject',
          conf: {
            source: 'msg_body',
            regex: "/Subject\\s+'(?<subject>[^']*)'/",
          },
        },
        {
          id: 'regex_extract',
          filter: "msg_body && msg_body.indexOf('interim verdict') >= 0 || msg_body && msg_body.indexOf('using engine') >= 0",
          description: 'Parse anti-spam verdict (engine + verdict)',
          conf: {
            source: 'msg_body',
            regex: '/using engine:\\s+(?<scan_engine>\\S+)\\s+spam\\s+(?<spam_verdict>\\w+)/',
          },
        },
        {
          id: 'regex_extract',
          filter: "msg_body && msg_body.indexOf('antivirus') >= 0",
          description: 'Parse antivirus verdict',
          conf: {
            source: 'msg_body',
            regex: "/antivirus\\s+(?<av_verdict>\\w+)(?:\\s+'(?<av_name>[^']+)')?/",
          },
        },
        {
          id: 'regex_extract',
          filter: "msg_body && msg_body.indexOf('rule') >= 0",
          description: 'Parse Outbreak Filters rule name',
          conf: {
            source: 'msg_body',
            regex: "/rule\\s+'(?<filter_rule>[^']+)'/",
          },
        },
        {
          id: 'regex_extract',
          filter: "msg_body && msg_body.indexOf('DKIM') >= 0",
          description: 'Parse DKIM verification result and domain',
          conf: {
            source: 'msg_body',
            regex: '/DKIM verification\\s+(?<dkim_result>\\w+)\\s+domain\\s+(?<dkim_domain>\\S+)/',
          },
        },
        {
          id: 'regex_extract',
          filter: "msg_body && msg_body.indexOf('TLS') >= 0 && msg_body.indexOf('CN=') >= 0",
          description: 'Parse TLS peer certificate CN',
          conf: {
            source: 'msg_body',
            regex: '/CN=(?<tls_peer_cn>[^\\s]+)/',
          },
        },
        {
          id: 'eval',
          description: 'Classify ESA event action and category from message body',
          conf: {
            add: [
              {
                name: 'action',
                value: "msg_body && (msg_body.indexOf('queued for delivery') >= 0 || msg_body.indexOf('Message done') >= 0) ? 'delivered' : msg_body && (msg_body.indexOf('Dropped') >= 0 || msg_body.indexOf('aborted') >= 0) ? 'dropped' : msg_body && msg_body.indexOf('quarantine') >= 0 ? 'quarantined' : msg_body && msg_body.indexOf('Bounced') >= 0 ? 'bounced' : msg_body && msg_body.indexOf('TLS') >= 0 ? 'allowed' : msg_body && msg_body.indexOf('DKIM') >= 0 ? 'allowed' : 'received'",
              },
              {
                name: 'category',
                value: "msg_body && msg_body.indexOf('quarantine') >= 0 ? 'phishing' : msg_body && msg_body.indexOf('TLS') >= 0 ? 'tls' : msg_body && msg_body.indexOf('DKIM') >= 0 ? 'dkim' : msg_body && msg_body.indexOf('spam') >= 0 ? 'spam' : msg_body && msg_body.indexOf('antivirus') >= 0 ? 'malware' : 'email'",
              },
            ],
          },
        },
        {
          id: 'eval',
          description: 'Alias ESA fields to CIM Email canonical names',
          conf: {
            add: [
              { name: 'severity', value: "level == 'Critical' ? 'critical' : level == 'Warning' ? 'medium' : level == 'Info' ? 'informational' : level == 'Debug' ? 'low' : undefined" },
              { name: 'message_id', value: 'mid || undefined' },
              { name: 'session_id', value: 'dcid || icid || undefined' },
              { name: 'src_user', value: 'sender || undefined' },
              { name: 'user', value: 'sender || undefined' },
              { name: 'dest_user', value: 'recipient || undefined' },
              { name: 'subject', value: 'subject || undefined' },
              { name: 'app', value: "'Cisco ESA'" },
              { name: 'vendor_product', value: "'Cisco Email Security Appliance'" },
              { name: 'signature', value: 'filter_rule || av_name || undefined' },
              { name: 'src', value: 'src_ip || tls_peer_cn || undefined' },
              { name: 'host', value: "'cisco-esa'" },
            ],
          },
        },
      ];

    case 'sap_hana':
      // SAP HANA server trace/audit logs are plain text, one line per event:
      //   [<ts>][<LEVEL>][<pid>][<component>][<source_file>][Thread <n>] <message>
      // The 5-bracket head is fully regular; the free-text message carries the
      // security-relevant detail (user, source IP, outcome) inconsistently, so we
      // parse the head deterministically and pull user/IP best-effort, then
      // classify outcome/category and alias to the canonical model the CIM/CEF/
      // OCSF golden specs read (log_time, severity, user, src, outcome, message).
      return [
        {
          id: 'regex_extract',
          description: 'Extract SAP HANA log head (time, level, pid, component, source file, thread)',
          conf: {
            source: '_raw',
            regex: '/^\\[(?<log_time>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d+)\\]\\[(?<level>\\w+)\\]\\[(?<pid>\\d+)\\]\\[(?<component>[^\\]]+)\\]\\[(?<source_file>[^\\]]+)\\]\\[Thread (?<os_thread>\\d+)\\]\\s*(?<msg_body>.*)$/',
          },
        },
        {
          id: 'regex_extract',
          filter: "msg_body && (msg_body.indexOf('user') >= 0 || msg_body.indexOf('User') >= 0)",
          description: 'Best-effort account name from the message (quoted or key=value form)',
          conf: {
            source: 'msg_body',
            // Handles both `user 'SYSTEM'` and `user='UNKNOWN'`.
            regex: "/\\buser\\s*=?\\s*'?(?<user>[A-Za-z0-9_.@-]+)'?/i",
          },
        },
        {
          id: 'regex_extract',
          filter: "msg_body && msg_body.indexOf('.') >= 0",
          description: 'Best-effort source IPv4 from the message',
          conf: {
            source: 'msg_body',
            regex: '/(?<src_ip>(?:\\d{1,3}\\.){3}\\d{1,3})/',
          },
        },
        {
          id: 'eval',
          description: 'Classify SAP HANA outcome/category and alias to canonical fields',
          conf: {
            add: [
              { name: 'severity', value: "level == 'ALERT' ? 'critical' : level == 'ERROR' ? 'high' : level == 'WARNING' ? 'medium' : level == 'INFO' ? 'informational' : undefined" },
              { name: 'outcome', value: "msg_body && (msg_body.indexOf('login failed') >= 0 || msg_body.indexOf('failed') >= 0 || msg_body.indexOf('refused') >= 0 || msg_body.indexOf('denied') >= 0 || msg_body.indexOf('insufficient privilege') >= 0 || msg_body.indexOf('missing authorization') >= 0 || msg_body.indexOf('violation') >= 0 || msg_body.indexOf('locked') >= 0 || msg_body.indexOf('not in allowlist') >= 0) ? 'failure' : msg_body && (msg_body.indexOf('success') >= 0 || msg_body.indexOf('completed') >= 0 || msg_body.indexOf('established') >= 0 || msg_body.indexOf('connected') >= 0 || msg_body.indexOf('passed') >= 0) ? 'success' : undefined" },
              { name: 'category', value: "source_file == 'auditing' || (msg_body && msg_body.indexOf('AUDIT:') >= 0) ? 'audit' : msg_body && (msg_body.indexOf('login') >= 0 || msg_body.indexOf('credential') >= 0 || msg_body.indexOf('connect') >= 0 || msg_body.indexOf('Connection') >= 0 || msg_body.indexOf('privilege') >= 0) ? 'authentication' : msg_body && (msg_body.indexOf('Backup') >= 0 || msg_body.indexOf('backup') >= 0 || msg_body.indexOf('Replication') >= 0 || msg_body.indexOf('replication') >= 0) ? 'system' : 'database'" },
              { name: 'message', value: 'msg_body || undefined' },
              { name: 'src', value: 'src_ip || undefined' },
              { name: 'user', value: 'user || undefined' },
              { name: 'app', value: "'SAP HANA'" },
              { name: 'vendor_product', value: "'SAP HANA Database'" },
            ],
          },
        },
      ];

    case 'palo_alto_traffic':
      return [
        {
          id: 'serde',
          description: 'Parse PAN-OS CSV traffic log with named columns',
          conf: {
            mode: 'extract',
            type: 'csv',
            srcField: '_raw',
            // Column names use the CANONICAL model every golden spec reads:
            // dest_* (NOT dst_*) and protocol/bytes as the specs expect. A
            // dst_ip here would silently never map (golden OCSF/CIM read
            // dest_ip) — the classic dst_/dest_ drift, invisible to the
            // contract lint because it can't see inside a serde's fields.
            fields: ['future_use1', 'receive_time', 'serial_number', 'type', 'threat_content_type', 'future_use2', 'generated_time', 'src_ip', 'dest_ip', 'nat_src_ip', 'nat_dest_ip', 'rule_name', 'src_user', 'dest_user', 'application', 'virtual_system', 'src_zone', 'dest_zone', 'inbound_if', 'outbound_if', 'log_action', 'future_use3', 'session_id', 'repeat_count', 'src_port', 'dest_port', 'nat_src_port', 'nat_dest_port', 'flags', 'protocol', 'action', 'bytes', 'bytes_out', 'bytes_in', 'packets', 'start_time', 'duration', 'category', 'future_use4', 'sequence_number', 'action_flags', 'src_location', 'dest_location', 'future_use5', 'packets_out', 'packets_in', 'session_end_reason'],
          },
        },
      ];

    case 'palo_alto_threat':
      return [
        {
          id: 'serde',
          description: 'Parse PAN-OS CSV threat log with named columns',
          conf: {
            mode: 'extract',
            type: 'csv',
            srcField: '_raw',
            // Canonical dest_* names (NOT dst_*) so the golden OCSF/CIM/CEF
            // specs' dest_ip/dest_port/dest_zone reads actually resolve.
            fields: ['future_use1', 'receive_time', 'serial_number', 'type', 'threat_content_type', 'future_use2', 'generated_time', 'src_ip', 'dest_ip', 'nat_src_ip', 'nat_dest_ip', 'rule_name', 'src_user', 'dest_user', 'application', 'virtual_system', 'src_zone', 'dest_zone', 'inbound_if', 'outbound_if', 'log_action', 'future_use3', 'session_id', 'repeat_count', 'src_port', 'dest_port', 'nat_src_port', 'nat_dest_port', 'flags', 'protocol', 'action', 'url_filename', 'threat_id', 'category', 'severity', 'direction', 'sequence_number', 'action_flags', 'src_location', 'dest_location', 'future_use4', 'content_type', 'pcap_id', 'filedigest', 'cloud', 'url_idx', 'user_agent', 'file_type', 'xff', 'referer', 'sender', 'subject', 'recipient'],
          },
        },
      ];

    case 'palo_alto_system':
      return [
        {
          id: 'serde',
          description: 'Parse PAN-OS CSV system log with named columns',
          conf: {
            mode: 'extract',
            type: 'csv',
            srcField: '_raw',
            // PAN-OS SYSTEM log has its OWN column layout — NOT the traffic/threat
            // one (no src/dest 5-tuple; it carries event_id/module/description).
            // System is data class 'audit', so the columns model the canonical
            // audit fields the golden specs read (log_time via generated_time,
            // severity, event_id, description). Canonical names only;
            // future_use columns are dropped from the field list.
            fields: ['future_use1', 'receive_time', 'serial_number', 'type', 'subtype', 'future_use2', 'generated_time', 'virtual_system', 'event_id', 'object', 'future_use3', 'future_use4', 'module', 'severity', 'description', 'sequence_number', 'action_flags', 'dg_hier_level_1', 'dg_hier_level_2', 'dg_hier_level_3', 'dg_hier_level_4', 'virtual_system_name', 'device_name'],
          },
        },
        {
          id: 'eval',
          description: 'Alias PAN-OS SYSTEM columns onto the canonical names the golden specs read',
          conf: {
            // Rule 10, and the reason the vendor column names alone are not enough:
            // EVERY golden spec reads `host` for the device that emitted the event and
            // `message`/`text` for its free-text description, while PAN-OS spells them
            // `device_name` and `description`. Without these two aliases an audit source
            // fed ECS/OCSF/Chronicle/CommonSecurityLog/NextGen mapped almost nothing —
            // the parser looked complete and the mapping stage had nothing to assemble.
            // The vendor names are KEPT (they are what a PAN-native reader expects);
            // these only add the canonical spelling next to them.
            add: [
              { name: 'host', value: 'device_name' },
              { name: 'message', value: 'description' },
            ],
          },
        },
      ];

    case 'fortinet_fortigate':
      return [
        {
          id: 'regex_extract',
          description: 'Extract CEF extension (if CEF-wrapped)',
          conf: {
            source: '_raw',
            regex: '/CEF:\\d+\\|(?<__cef_vendor>[^|]*)\\|(?<__cef_product>[^|]*)\\|(?<__cef_version>[^|]*)\\|(?<__cef_id>[^|]*)\\|(?<__cef_name>[^|]*)\\|(?<__cef_severity>[^|]*)\\|(?<__cef_ext>.*)$/',
          },
        },
        {
          id: 'eval',
          description: 'Set KVP source field',
          conf: { add: [{ name: '__kvp_src', value: '__cef_ext || _raw' }] },
        },
        {
          id: 'serde',
          description: 'Parse KVP fields',
          conf: { mode: 'extract', type: 'kvp', srcField: '__kvp_src', delimChar: ' ', quoteChar: '"' },
        },
        {
          id: 'code',
          description: 'Strip FTNTFGT prefix from FortiGate vendor fields',
          conf: {
            maxNumOfIterations: 5000,
            code: [
              'for (const key of Object.keys(__e)) {',
              '  if (key.startsWith("FTNTFGT")) {',
              '    const clean = key.slice(7);',
              '    if (!__e[clean]) __e[clean] = __e[key];',
              '    delete __e[key];',
              '  }',
              '}',
            ].join('\n'),
          },
        },
        {
          id: 'eval',
          description: 'Normalize CEF/FortiGate field names to standard',
          conf: {
            add: [
              // Canonical field model uses src_ip / dest_ip / dest_port /
              // transport (see canonical-fields.md). FortiGate KVP uses
              // srcip/dstip/dstport/proto — normalize to the canonical names so
              // the golden CEF/CIM/OCSF specs (which read dest_ip, transport…)
              // map correctly. Keep the dst_* aliases too for back-compat.
              { name: 'src_ip', value: 'src_ip || src || srcaddr || srcip || undefined' },
              { name: 'dest_ip', value: 'dest_ip || dst_ip || dst || dstaddr || dstip || undefined' },
              { name: 'src_port', value: 'src_port || spt || srcport || undefined' },
              { name: 'dest_port', value: 'dest_port || dst_port || dpt || dstport || undefined' },
              // transport as a NAME (tcp/udp/icmp), converting FortiGate's numeric
              // proto via a ternary chain (Cribl-safe; no IIFE). Unknowns keep
              // the original value.
              { name: '__proto_raw', value: 'String(transport || protocol || proto || "")' },
              { name: 'transport', value: "__proto_raw == '6' ? 'tcp' : __proto_raw == '17' ? 'udp' : __proto_raw == '1' ? 'icmp' : __proto_raw == '58' ? 'ipv6-icmp' : __proto_raw == '47' ? 'gre' : __proto_raw == '50' ? 'esp' : __proto_raw == '51' ? 'ah' : __proto_raw == '132' ? 'sctp' : (__proto_raw || undefined)" },
              { name: 'protocol', value: 'protocol || proto || undefined' },
              { name: 'action', value: 'action || act || undefined' },
              // Canonical identifier + human name + timestamp + severity so the
              // golden CEF/CIM/OCSF specs get a real SignatureID (logid), a
              // descriptive Name (type:subtype), correct _time (eventtime epoch
              // ms, or date+time), and numeric severity from the level word.
              { name: 'event_code', value: 'event_code || logid || undefined' },
              { name: 'message', value: "type ? (subtype ? String(type) + ':' + String(subtype) : String(type)) : (msg || undefined)" },
              { name: 'log_time', value: "eventtime ? Number(String(eventtime).substring(0,13)) : (date && time ? Date.parse(String(date) + 'T' + String(time)) : undefined)" },
              { name: 'severity', value: "level == 'emergency' || level == 'alert' ? 1 : level == 'critical' ? 2 : level == 'error' ? 3 : level == 'warning' ? 4 : level == 'notice' ? 5 : level == 'information' ? 6 : (severity || undefined)" },
              { name: 'host', value: 'host || devname || devid || undefined' },
              { name: 'bytes_in', value: "bytes_in || __e['in'] || rcvdbyte || undefined" },
              { name: 'bytes_out', value: 'out || sentbyte || undefined' },
              // 'app' canonical = the application/service name (HTTPS, DNS…),
              // NEVER the protocol number. FortiGate carries it in `service` or
              // `app`/`appcat`. Do not fall back to proto here.
              { name: 'app', value: 'app || service || appcat || undefined' },
              { name: 'application', value: 'app || service || undefined' },
              { name: 'service', value: 'service || undefined' },
              // FortiGate emits the LITERAL string srcintfrole="undefined" when
              // an interface has no role — that truthy string would beat a plain
              // `|| srcintf` fallback, so scrub it before falling back to the
              // real interface NAME (srcintf/dstintf, present on every event).
              { name: 'src_zone', value: "(srcintfrole && srcintfrole != 'undefined' ? srcintfrole : srcintf) || undefined" },
              { name: 'dest_zone', value: "(dstintfrole && dstintfrole != 'undefined' ? dstintfrole : dstintf) || undefined" },
              { name: 'src_interface', value: 'srcintf || undefined' },
              { name: 'dest_interface', value: 'dstintf || undefined' },
              { name: 'src_country', value: 'srccountry || undefined' },
              // canonical dest_* (golden specs read dest_country/dest_mac).
              { name: 'dest_country', value: 'dstcountry || undefined' },
              { name: 'policy_id', value: 'policyid || undefined' },
              { name: 'policy_name', value: 'policyname || poluuid || undefined' },
              // FortiGate session id key is `sessionid` (one word).
              { name: 'session_id', value: 'sessionid || externalId || identifier || undefined' },
              { name: 'sent_bytes', value: 'out || sentbyte || undefined' },
              { name: 'rcvd_bytes', value: "__e['in'] || rcvdbyte || undefined" },
              { name: 'sent_pkts', value: 'sentpkt || undefined' },
              { name: 'rcvd_pkts', value: 'rcvdpkt || undefined' },
              { name: 'src_mac', value: 'srcmac || mastersrcmac || undefined' },
              { name: 'dest_mac', value: 'dstmac || masterdstmac || undefined' },
              // device identity + NAT translation + vdom. NOTE: FortiGate `tranip`/
              // `tranport` are the translated SOURCE (SNAT). `trandisp` is a NAT
              // DISPOSITION string (snat/dnat/noop) — NOT an IP, so it must never
              // be used as a translated address. Only set dest-translated from a
              // real dest-NAT IP field (tranip when trandisp indicates dnat).
              // device_ip must be an actual IP; FortiGate `devid` is a serial/
              // name (e.g. FGVYesCXkTwMRj1B), so it belongs in dev_id, not here.
              { name: 'device_ip', value: 'device_ip || undefined' },
              { name: 'nat_disposition', value: 'trandisp || undefined' },
              { name: 'src_translated_ip', value: "trandisp == 'dnat' ? undefined : (transip || tranip || natip || undefined)" },
              { name: 'src_translated_port', value: "trandisp == 'dnat' ? undefined : (tranport || natport || undefined)" },
              { name: 'dest_translated_ip', value: "trandisp == 'dnat' ? (tranip || undefined) : undefined" },
              { name: 'dest_translated_port', value: "trandisp == 'dnat' ? (tranport || undefined) : undefined" },
              { name: 'vdom', value: 'vd || vdom || undefined' },
              { name: 'duration', value: 'duration || undefined' },
              { name: 'packets_in', value: 'rcvdpkt || undefined' },
              { name: 'packets_out', value: 'sentpkt || undefined' },
              { name: 'dev_id', value: 'devid || undefined' },
              // client OS + FortiOS version (present on UTM/traffic events).
              { name: 'os', value: 'osname || undefined' },
              { name: 'os_version', value: 'srcswversion || osversion || undefined' },
            ],
            remove: ['__kvp_src', '__proto_raw', '__cef_ext', '__cef_vendor', '__cef_product', '__cef_version', '__cef_id', '__cef_name', '__cef_severity'],
          },
        },
      ];

    case 'checkpoint_firewall':
      return [
        {
          id: 'regex_extract',
          description: 'Extract RFC5424 syslog header and Check Point payload',
          conf: {
            source: '_raw',
            regex: '/^<(?<priority>\\d+)>(?<syslog_version>\\d+)\\s+(?<log_time>\\S+)\\s+(?<syslog_host>\\S+)\\s+(?<app_name>\\S+)\\s+(?<procid>\\S+)\\s+(?<msgid>\\S+)\\s+\\[(?<__kvp_body>.*)\\]$/',
          },
        },
        {
          id: 'regex_extract',
          description: 'Extract legacy syslog header and KVP body',
          filter: '!__kvp_body',
          conf: {
            source: '_raw',
            regex: '/^\\d+\\s+<\\d+>\\d+\\s+(?<log_time>\\S+)\\s+(?<syslog_host>\\S+)\\s+(?<__kvp_body>.*)/',
          },
        },
        {
          id: 'serde',
          description: 'Parse semicolon-delimited Check Point KVP (key:"value")',
          filter: '__kvp_body && String(__kvp_body).indexOf(";") >= 0',
          conf: { mode: 'extract', type: 'kvp', srcField: '__kvp_body', delimChar: '; ', pairDelim: ':', cleanFields: true },
        },
        {
          id: 'serde',
          description: 'Parse pipe-delimited Check Point KVP (key=value)',
          filter: '__kvp_body && String(__kvp_body).indexOf(";") < 0',
          conf: { mode: 'extract', type: 'kvp', srcField: '__kvp_body', delimChar: '|', cleanFields: true },
        },
        {
          id: 'serde',
          description: 'Parse inline semicolon KVP when no syslog wrapper matched',
          filter: '!__kvp_body && String(_raw).indexOf(";") >= 0',
          conf: { mode: 'extract', type: 'kvp', srcField: '_raw', delimChar: '; ', pairDelim: ':', cleanFields: true },
        },
        {
          id: 'regex_extract',
          description: 'Extract BSD syslog header + KVP body (space-delimited key=value)',
          filter: '!__kvp_body && !product',
          conf: {
            source: '_raw',
            regex: '/^(?<__bsd_month>\\w{3})\\s+(?<__bsd_day>\\d+)\\s+(?<__bsd_time>[\\d:]+)\\s+(?<syslog_host>\\S+)\\s+(?<__kvp_body>.*)/',
          },
        },
        {
          id: 'serde',
          description: 'Parse BSD syslog Check Point KVP (space-delimited key="value")',
          filter: '__kvp_body && !product',
          conf: { mode: 'extract', type: 'kvp', srcField: '__kvp_body', delimChar: ' ', pairDelim: '=', quoteChar: '"', cleanFields: true },
        },
        {
          id: 'serde',
          description: 'Parse bare space-delimited key="value" (no syslog header matched)',
          filter: '!__kvp_body && !product && String(_raw).indexOf("=") >= 0',
          conf: { mode: 'extract', type: 'kvp', srcField: '_raw', delimChar: ' ', pairDelim: '=', quoteChar: '"', cleanFields: true },
        },
        {
          id: 'eval',
          description: 'Normalize Checkpoint fields to canonical model',
          conf: {
            add: [
              { name: 'src_ip', value: "src ? String(src).split(' ')[0] : srcaddr || undefined" },
              { name: 'dest_ip', value: "dst ? String(dst).split(' ')[0] : dstaddr || undefined" },
              { name: 'src_port', value: 'src_port || s_port || undefined' },
              { name: 'dest_port', value: 'dst_port || service || undefined' },
              { name: 'transport', value: 'proto || protocol || undefined' },
              { name: 'action', value: 'action || rule_action || undefined' },
              { name: 'host', value: 'hostname || syslog_host || undefined' },
              { name: 'app', value: "'Check Point Firewall'" },
              { name: 'vendor_product', value: "'Check Point Software Firewall'" },
              { name: 'rule_name', value: 'rule_name || undefined' },
              { name: 'rule_id', value: 'rule_uid || undefined' },
              { name: 'direction', value: "ifdir || conn_direction || undefined" },
              { name: 'src_zone', value: 'ifname || undefined' },
              { name: 'user', value: "user ? String(user).trim() : src_user_name || undefined" },
              { name: 'event_code', value: 'logid || undefined' },
              { name: 'severity', value: "severity || '6'" },
              { name: 'device_ip', value: 'syslog_host || undefined' },
              { name: 'session_id', value: 'loguid || undefined' },
              { name: 'dev_id', value: 'loguid || machineid || undefined' },
              { name: 'match_id', value: 'match_id || undefined' },
              { name: 'parent_rule', value: 'parent_rule || undefined' },
              { name: 'origin_ip', value: 'origin || orig || undefined' },
              { name: 'bytes', value: 'bytes || undefined' },
              { name: 'bytes_in', value: 'received || client_inbound_bytes || bytes_in || undefined' },
              { name: 'bytes_out', value: 'sent || client_outbound_bytes || bytes_out || undefined' },
              { name: 'src_translated_ip', value: 'xlatesrc || nat_addtnl_rulenum || undefined' },
              { name: 'dest_translated_ip', value: 'xlatedst || undefined' },
              { name: 'src_translated_port', value: 'xlatesport || undefined' },
              { name: 'dest_translated_port', value: 'xlatedport || undefined' },
              { name: 'rule', value: 'rule_name || rule || undefined' },
              { name: 'log_time', value: "time ? Number(time) * 1000 : log_time || undefined" },
            ],
            remove: ['__kvp_body', '__bsd_month', '__bsd_day', '__bsd_time', 'syslog_host', 'time'],
          },
        },
      ];

    case 'windows_powershell':
      return [
        {
          id: 'regex_extract',
          description: 'Extract timestamp and structured fields from PowerShell log',
          conf: { source: '_raw', regex: '/^(?<log_time>\\d{1,2}\\/\\d{1,2}\\/\\d{4}\\s+\\d{1,2}:\\d{2}:\\d{2}\\s+[AP]M)\\s+LogName=(?<LogName>\\S+)\\s+SourceName=(?<SourceName>\\S+)\\s+EventCode=(?<EventCode>\\d+)\\s+EventType=(?<EventType>\\d+)\\s+Type=(?<Type>\\w+)\\s+ComputerName=(?<ComputerName>\\S+)\\s+User=(?<User>\\S+)/' },
        },
        {
          id: 'regex_extract',
          description: 'Extract Sid, TaskCategory and Message',
          conf: { source: '_raw', regex: '/Sid=(?<Sid>\\S+).*?TaskCategory=(?<TaskCategory>[^\\s](?:[^\\n]*?))\\s+OpCode=.*?Message=(?<Message>[\\s\\S]*)/' },
        },
        {
          id: 'eval',
          description: 'Alias PowerShell fields to canonical names',
          conf: {
            add: [
              { name: 'host', value: 'ComputerName || undefined' },
              { name: 'dest_ip', value: 'ComputerName || undefined' },
              { name: 'user', value: 'User || undefined' },
              { name: 'event_code', value: 'EventCode || undefined' },
              { name: 'app', value: "'PowerShell'" },
              { name: 'vendor_product', value: "'Microsoft Windows'" },
              { name: 'severity', value: "EventType == '1' ? 2 : EventType == '2' ? 4 : EventType == '4' ? 6 : undefined" },
              { name: 'action', value: "Type == 'Information' ? 'success' : Type == 'Warning' ? 'failure' : Type == 'Error' ? 'failure' : 'unknown'" },
              { name: 'signature', value: "TaskCategory || undefined" },
            ],
          },
        },
      ];

    case 'windows_security':
      return [
        {
          id: 'eval',
          description: 'Parse and compact Windows XML with the native Windows event parser',
          conf: {
            add: [
              { name: '_raw', value: "_raw.replace(/[{}\\t]/gm,'').replace(/[\\n\\r]+/gm,',')" },
              { name: '_raw', value: "C.Text.parseWinEvent(_raw,['0x0','0','-'])" },
            ],
          },
        },
        {
          id: 'flatten',
          description: 'Flatten the parsed Windows event into top-level fields',
          conf: { fields: ['_raw'], prefix: '', depth: 5, delimiter: '_' },
        },
        {
          id: 'rename',
          description: 'Remove verbose Windows XML path prefixes from field names',
          conf: { baseFields: [], renameExpr: "name.replace(/_raw_Event_\\w+_/,'')", rename: [] },
        },
        {
          id: 'eval',
          description: 'Alias Windows Security fields to canonical names',
          conf: {
            add: [
              { name: 'user', value: 'TargetUserName || SubjectUserName || undefined' },
              { name: 'src_user', value: 'SubjectUserName || undefined' },
              { name: 'dest_user', value: 'TargetUserName || undefined' },
              { name: 'src_ip', value: "IpAddress && IpAddress != '-' ? IpAddress : undefined" },
              { name: 'src_port', value: "IpPort && IpPort != '-' ? Number(IpPort) : undefined" },
              // `Computer` is a HOSTNAME. It belongs in `dest`, not `dest_ip` — a
              // hostname in an IP field is a wrong value, not a missing one, and it
              // costs nothing to move because the same value already reaches `host`.
              { name: 'dest', value: 'Computer || undefined' },
              { name: 'dest_ip', value: "Computer && Computer.match(/^\\d{1,3}(\\.\\d{1,3}){3}$/) ? Computer : undefined" },
              { name: 'host', value: 'Computer || undefined' },
              { name: 'event_code', value: 'EventID || undefined' },
              { name: 'log_time', value: 'SystemTime || TimeCreated_SystemTime || undefined' },
              { name: 'app', value: "'Windows Security'" },
              { name: 'vendor_product', value: "'Microsoft Windows'" },
              { name: 'action', value: "EventID == '4624' || EventID == '4648' ? 'success' : EventID == '4625' || EventID == '4771' ? 'failure' : EventID == '4634' || EventID == '4647' ? 'success' : EventID == '4720' ? 'created' : EventID == '4726' ? 'deleted' : 'unknown'" },
              { name: 'session_id', value: 'TargetLogonId || LogonId || undefined' },
              { name: 'severity', value: "Level == '0' ? 6 : Level == '1' ? 2 : Level == '2' ? 3 : Level == '3' ? 4 : Level == '4' ? 6 : undefined" },
              { name: 'logon_type', value: 'LogonType || undefined' },
              { name: 'process', value: 'ProcessName || NewProcessName || undefined' },
              { name: 'process_id', value: 'ProcessID || NewProcessId || undefined' },
              { name: 'src_nt_domain', value: 'SubjectDomainName || undefined' },
              { name: 'dest_nt_domain', value: 'TargetDomainName || undefined' },
              { name: 'signature', value: "EventID == '4624' ? 'An account was successfully logged on' : EventID == '4625' ? 'An account failed to log on' : EventID == '4634' ? 'An account was logged off' : EventID == '4648' ? 'A logon was attempted using explicit credentials' : EventID == '4672' ? 'Special privileges assigned to new logon' : EventID == '4720' ? 'A user account was created' : EventID == '4726' ? 'A user account was deleted' : EventID == '4776' ? 'The computer attempted to validate the credentials for an account' : undefined" },
              { name: 'authentication_method', value: 'AuthenticationPackageName || undefined' },
              { name: 'src', value: "WorkstationName || Workstation || undefined" },
            ],
          },
        },
      ];

    case 'windows_dns_client':
      // Microsoft-Windows-DNS-Client/Operational. EventData is QueryName/QueryType/
      // QueryOptions/ServerList (3006, query sent) and QueryName/QueryStatus/
      // QueryResults (3008, query completed) — nothing the Security alias set reads,
      // which is why this channel used to extract cleanly and map to almost nothing.
      return [
        ...windowsXmlFrontEnd('Windows DNS Client'),
        {
          id: 'eval',
          description: 'Alias Windows DNS Client fields to canonical names',
          conf: {
            add: [
              { name: 'log_time', value: 'SystemTime || TimeCreated_SystemTime || undefined' },
              { name: 'host', value: 'Computer || undefined' },
              { name: 'event_code', value: 'EventID || undefined' },
              { name: 'query', value: 'QueryName || undefined' },
              { name: 'dns_query', value: 'QueryName || undefined' },
              { name: 'url', value: 'QueryName || undefined' },
              // Numeric DNS QTYPE → record type name (the golden DNS specs and every
              // analyst read 'A'/'AAAA', not 1/28). Unknown codes pass through.
              { name: 'query_type', value: "QueryType == '1' ? 'A' : QueryType == '2' ? 'NS' : QueryType == '5' ? 'CNAME' : QueryType == '6' ? 'SOA' : QueryType == '12' ? 'PTR' : QueryType == '15' ? 'MX' : QueryType == '16' ? 'TXT' : QueryType == '28' ? 'AAAA' : QueryType == '33' ? 'SRV' : QueryType == '65' ? 'HTTPS' : QueryType || undefined" },
              { name: 'answer', value: "QueryResults ? String(QueryResults).replace(/;+$/,'').replace(/;/g,',') : undefined" },
              { name: 'dns_answer', value: "QueryResults ? String(QueryResults).replace(/;+$/,'').replace(/;/g,',') : undefined" },
              // ServerList is the resolver the query went to (semicolon-terminated).
              { name: 'dest_ip', value: "ServerList ? String(ServerList).replace(/;+$/,'').split(';')[0] : undefined" },
              { name: 'reply_code_id', value: 'QueryStatus || undefined' },
              { name: 'reply_code', value: "QueryStatus == '0' ? 'NOERROR' : QueryStatus == '9003' ? 'NXDOMAIN' : QueryStatus == '9501' ? 'NODATA' : QueryStatus == '9002' ? 'SERVFAIL' : QueryStatus || undefined" },
              // 3006 has no QueryStatus at all — it is the request half of the pair,
              // so reporting it as a failure would be wrong.
              { name: 'action', value: "QueryStatus === undefined ? 'query' : QueryStatus == '0' ? 'success' : 'failure'" },
              { name: 'signature', value: "EventID == '3006' ? 'DNS query sent to resolver' : EventID == '3008' ? 'DNS query completed' : EventID == '3009' ? 'DNS query answered from cache' : EventID == '3010' ? 'DNS query sent' : EventID == '3020' ? 'DNS response received' : undefined" },
              { name: 'process_id', value: 'ProcessID || Execution_ProcessID || undefined' },
              { name: 'user_id', value: 'UserID || Security_UserID || undefined' },
              { name: 'severity', value: WINDOWS_LEVEL_TO_SEVERITY },
              { name: 'transport', value: "'udp'" },
              { name: 'dest_port', value: "ServerList ? 53 : undefined" },
              { name: 'app', value: "'Windows DNS Client'" },
              { name: 'vendor', value: "'Microsoft'" },
              { name: 'product', value: "'DNS Client'" },
              { name: 'vendor_product', value: "'Microsoft Windows DNS Client'" },
            ],
          },
        },
      ];

    case 'windows_defender':
      // Microsoft-Windows-Windows Defender/Operational. EventData names carry SPACES
      // ('Threat Name', 'Action Name'), so the front-end runs with stripSpaces.
      return [
        ...windowsXmlFrontEnd('Microsoft Defender', true),
        {
          id: 'eval',
          description: 'Alias Microsoft Defender fields to canonical names',
          conf: {
            add: [
              { name: 'log_time', value: 'SystemTime || TimeCreated_SystemTime || undefined' },
              { name: 'host', value: 'Computer || undefined' },
              { name: 'hostname', value: 'Computer || undefined' },
              { name: 'event_code', value: 'EventID || undefined' },
              { name: 'signature', value: 'ThreatName || undefined' },
              { name: 'category', value: 'CategoryName || undefined' },
              { name: 'severity_name', value: 'SeverityName || undefined' },
              // Defender prefixes the detection path with `file:_`.
              { name: 'file_path', value: "Path ? String(Path).replace(/^file:_/,'') : undefined" },
              { name: 'object', value: "Path ? String(Path).replace(/^file:_/,'') : undefined" },
              { name: 'user', value: 'DetectionUser || User || undefined' },
              { name: 'user_id', value: 'UserID || Security_UserID || undefined' },
              { name: 'action', value: "ActionName ? String(ActionName).toLowerCase() : undefined" },
              { name: 'outcome', value: "StatusCode == '0' ? 'success' : StatusCode ? 'failure' : undefined" },
              { name: 'process_id', value: 'ProcessID || Execution_ProcessID || undefined' },
              { name: 'severity', value: WINDOWS_LEVEL_TO_SEVERITY },
              { name: 'app', value: "ProductName || 'Microsoft Defender Antivirus'" },
              { name: 'vendor', value: "'Microsoft'" },
              { name: 'product', value: "'Defender Antivirus'" },
              { name: 'vendor_product', value: "'Microsoft Defender Antivirus'" },
            ],
          },
        },
      ];

    case 'windows_system':
      // The System channel is one envelope carrying MANY providers (Service Control
      // Manager 7045/7036/7040, EventLog 6005/6006/6013, User32 1074, Kernel-Power
      // 41). Only the envelope is reliably named, so the alias step reads the
      // envelope plus the handful of EventData names Service Control Manager uses
      // and keeps everything else in `message` rather than inventing a model.
      return [
        ...windowsXmlFrontEnd('Windows System'),
        {
          id: 'eval',
          description: 'Alias Windows System channel fields to canonical names',
          conf: {
            add: [
              { name: 'log_time', value: 'SystemTime || TimeCreated_SystemTime || undefined' },
              { name: 'host', value: 'Computer || undefined' },
              { name: 'hostname', value: 'Computer || undefined' },
              { name: 'event_code', value: 'EventID || undefined' },
              { name: 'app', value: 'Provider_Name || Name || undefined' },
              { name: 'process', value: 'ImagePath || ServiceName || undefined' },
              { name: 'object', value: 'ServiceName || param1 || undefined' },
              { name: 'user', value: 'AccountName || undefined' },
              { name: 'process_id', value: 'ProcessID || Execution_ProcessID || undefined' },
              { name: 'user_id', value: 'UserID || Security_UserID || undefined' },
              { name: 'message', value: "Data ? (Array.isArray(Data) ? Data.join(' | ') : String(Data)) : param1 || undefined" },
              { name: 'signature', value: "EventID == '7045' ? 'A service was installed in the system' : EventID == '7036' ? 'Service state changed' : EventID == '7040' ? 'Service start type changed' : EventID == '6005' ? 'The Event log service was started' : EventID == '6006' ? 'The Event log service was stopped' : EventID == '6013' ? 'System uptime report' : EventID == '1074' ? 'System shutdown initiated' : EventID == '41' ? 'System rebooted without a clean shutdown' : undefined" },
              { name: 'action', value: "EventID == '7045' ? 'created' : EventID == '7040' ? 'modified' : EventID == '6005' ? 'started' : EventID == '6006' || EventID == '1074' ? 'stopped' : undefined" },
              { name: 'outcome', value: "Level == '1' || Level == '2' ? 'failure' : 'success'" },
              { name: 'severity', value: WINDOWS_LEVEL_TO_SEVERITY },
              { name: 'vendor', value: "'Microsoft'" },
              { name: 'product', value: "'Windows'" },
              { name: 'vendor_product', value: "'Microsoft Windows'" },
            ],
          },
        },
      ];

    case 'windows_application':
      // The Application channel is the widest of all: most providers write UNNAMED
      // `<Data>` elements (Application Error, MsiInstaller, .NET Runtime, WER), so
      // there is no per-field model to alias — only the envelope plus the Data
      // payload as `message`. Its data class is deliberately `generic`: pretending
      // this is an endpoint or authentication feed is precisely the bug being fixed.
      return [
        ...windowsXmlFrontEnd('Windows Application'),
        {
          id: 'eval',
          description: 'Alias Windows Application channel fields to canonical names',
          conf: {
            add: [
              { name: 'log_time', value: 'SystemTime || TimeCreated_SystemTime || undefined' },
              { name: 'host', value: 'Computer || undefined' },
              { name: 'hostname', value: 'Computer || undefined' },
              { name: 'event_code', value: 'EventID || undefined' },
              { name: 'app', value: 'Provider_Name || Name || undefined' },
              { name: 'message', value: "Data ? (Array.isArray(Data) ? Data.join(' | ') : String(Data)) : undefined" },
              { name: 'process', value: "Data && Array.isArray(Data) ? Data[0] : undefined" },
              { name: 'user_id', value: 'UserID || Security_UserID || undefined' },
              { name: 'process_id', value: 'ProcessID || Execution_ProcessID || undefined' },
              { name: 'signature', value: "EventID == '1000' ? 'Application error' : EventID == '1001' ? 'Windows Error Reporting report' : EventID == '1026' ? '.NET Runtime unhandled exception' : EventID == '11707' ? 'Product installation completed' : EventID == '11708' ? 'Product installation failed' : undefined" },
              { name: 'outcome', value: "Level == '1' || Level == '2' ? 'failure' : 'success'" },
              { name: 'severity', value: WINDOWS_LEVEL_TO_SEVERITY },
              { name: 'vendor', value: "'Microsoft'" },
              { name: 'product', value: "'Windows'" },
              { name: 'vendor_product', value: "'Microsoft Windows'" },
            ],
          },
        },
      ];

    case 'windows_sysmon':
      // Sysmon (Microsoft-Windows-Sysmon) shares the SAME XML parse front-end as
      // windows_security but its EventData field names are ENTIRELY different
      // (Image/CommandLine/User/SourceIp/DestinationIp/ProcessId/ParentImage/…,
      // NOT TargetUserName/IpAddress/Computer-as-dest). Aliasing it with the
      // Security field set silently produced empty output (dest_ip=Computer=the
      // hostname, src_ip/user/process all undefined) — build-344 fix. The alias
      // step below reads the real Sysmon fields and emits the canonical model the
      // golden CIM/ECS/OCSF specs read. `action` is derived from the Sysmon
      // EventID (1=process create, 3=network connect, 11=file create, 12/13/14=
      // registry, 8=CreateRemoteThread, 10=ProcessAccess, 22=DNS) since Sysmon
      // has no Security-style success/failure codes.
      return [
        {
          id: 'eval',
          description: 'Parse and compact Windows XML with the native Windows event parser',
          conf: {
            add: [
              { name: '_raw', value: "_raw.replace(/[{}\\t]/gm,'').replace(/[\\n\\r]+/gm,',')" },
              { name: '_raw', value: "C.Text.parseWinEvent(_raw,['0x0','0','-'])" },
            ],
          },
        },
        {
          id: 'flatten',
          description: 'Flatten the parsed Windows event into top-level fields',
          conf: { fields: ['_raw'], prefix: '', depth: 5, delimiter: '_' },
        },
        {
          id: 'rename',
          description: 'Remove verbose Windows XML path prefixes from field names',
          conf: { baseFields: [], renameExpr: "name.replace(/_raw_Event_\\w+_/,'')", rename: [] },
        },
        {
          id: 'eval',
          description: 'Alias Sysmon fields to canonical names',
          conf: {
            add: [
              { name: 'user', value: "User && User != '-' ? User : undefined" },
              { name: 'src_ip', value: "SourceIp && SourceIp != '-' ? SourceIp : undefined" },
              { name: 'src_port', value: "SourcePort && SourcePort != '-' ? Number(SourcePort) : undefined" },
              { name: 'dest_ip', value: "DestinationIp && DestinationIp != '-' ? DestinationIp : undefined" },
              { name: 'dest_port', value: "DestinationPort && DestinationPort != '-' ? Number(DestinationPort) : undefined" },
              { name: 'transport', value: "Protocol ? String(Protocol).toLowerCase() : undefined" },
              { name: 'host', value: 'Computer || undefined' },
              { name: 'event_code', value: 'EventID || undefined' },
              { name: 'log_time', value: 'UtcTime || SystemTime || TimeCreated_SystemTime || undefined' },
              { name: 'app', value: "'Sysmon'" },
              { name: 'vendor_product', value: "'Microsoft Sysmon'" },
              { name: 'process', value: 'Image || undefined' },
              { name: 'process_id', value: 'ProcessId || undefined' },
              { name: 'process_guid', value: 'ProcessGuid || undefined' },
              { name: 'command', value: 'CommandLine || undefined' },
              { name: 'parent_process', value: 'ParentImage || undefined' },
              { name: 'parent_process_id', value: 'ParentProcessId || undefined' },
              { name: 'parent_command', value: 'ParentCommandLine || undefined' },
              { name: 'file_path', value: 'TargetFilename || undefined' },
              { name: 'registry_path', value: 'TargetObject || undefined' },
              { name: 'file_hash', value: 'Hashes || Hash || undefined' },
              { name: 'dns_query', value: 'QueryName || undefined' },
              { name: 'action', value: "EventID == '1' ? 'process_create' : EventID == '3' ? 'network_connect' : EventID == '5' ? 'process_terminate' : EventID == '7' ? 'image_load' : EventID == '8' ? 'create_remote_thread' : EventID == '10' ? 'process_access' : EventID == '11' ? 'file_create' : EventID == '12' || EventID == '13' || EventID == '14' ? 'registry' : EventID == '22' ? 'dns_query' : 'unknown'" },
              { name: 'signature', value: 'RuleName || undefined' },
              { name: 'severity', value: "Level == '0' ? 6 : Level == '1' ? 2 : Level == '2' ? 3 : Level == '3' ? 4 : Level == '4' ? 6 : 4" },
            ],
          },
        },
      ];

    case 'sap_audit':
      // SAP Security Audit Log (SM20/SAL) in KVP form:
      //   DATE=.. TIME=.. MANDT=.. USER=.. TCODE=.. REPORT=.. MSGID=.. MSGNO=..
      //   CLASS=.. TEXT=".." HOST=.. CLIENT=.. TERMINAL=.. SUNAME=..
      // KVP-extract then normalize to the shared canonical model so the golden
      // CEF/CIM specs map it deterministically (no AI). TEXT is quoted, so the
      // kvp serde must use quoteChar '"'.
      return [
        { id: 'serde', description: 'Extract SAP audit KVP fields', conf: { mode: 'extract', type: 'kvp', srcField: '_raw', delimChar: ' ', quoteChar: '"' } },
        {
          id: 'eval',
          description: 'Normalize SAP audit fields to the canonical model',
          conf: {
            add: [
              // identity: USER performs the action; SUNAME is the same principal.
              { name: 'user', value: 'USER || SUNAME || undefined' },
              { name: 'src_user', value: 'USER || SUNAME || undefined' },
              // origin: TERMINAL is an IP in most events, a workstation name in a few.
              { name: 'src_ip', value: "TERMINAL && String(TERMINAL).match(/^(\\d{1,3}\\.){3}\\d{1,3}$/) ? TERMINAL : undefined" },
              { name: 'src_host', value: "TERMINAL && !String(TERMINAL).match(/^(\\d{1,3}\\.){3}\\d{1,3}$/) ? TERMINAL : undefined" },
              // the SAP application server that logged the event = the device.
              { name: 'host', value: 'HOST || undefined' },
              { name: 'device_ip', value: 'HOST && String(HOST).match(/^(\\d{1,3}\\.){3}\\d{1,3}$/) ? HOST : undefined' },
              // human-readable audit message + SAP message id/number as event code.
              { name: 'message', value: 'TEXT || undefined' },
              { name: 'event_code', value: "MSGID ? String(MSGID) + (MSGNO ? ':' + String(MSGNO) : '') : undefined" },
              // TCODE (SAP transaction) is the activity/application invoked;
              // REPORT is the ABAP program that ran (kept as its own canonical).
              { name: 'app', value: 'TCODE || undefined' },
              { name: 'report', value: 'REPORT || undefined' },
              // SAP client/tenant (MANDT and CLIENT are the same value). NOTE:
              // do NOT map to `vdom` — the golden CEF spec labels cs5 as "VDOM"
              // (a Fortinet concept), which is wrong for SAP. Left unmapped
              // rather than emitting a mislabeled field.
              // action: SAP CLASS is a SEVERITY class, not a disposition (a
              // CLASS=A "User created" is a successful but alert-worthy event),
              // so derive success/failure from the message text; CLASS=E (error
              // class) with no explicit wording is treated as 'error'.
              { name: 'action', value: "/fail|denied|locked|not exist|unsuccessful|invalid|unauthori[sz]|violation|reject/i.test(String(TEXT)) ? 'failure' : (CLASS == 'E' ? 'error' : 'success')" },
              // CLASS severity: A=alert/critical, E=error, W=warning, U=uncritical.
              // Emit the FortiGate-style numeric scale (lower = more severe) that
              // the golden cefSeverityFromLevel rule expects.
              { name: 'severity', value: "CLASS == 'A' ? 1 : CLASS == 'E' ? 3 : CLASS == 'W' ? 4 : CLASS == 'U' ? 6 : 5" },
              // timestamp: DATE + TIME (no tz in the source → treat as UTC).
              { name: 'log_time', value: "DATE && TIME ? Date.parse(String(DATE) + 'T' + String(TIME) + 'Z') : undefined" },
            ],
          },
        },
      ];

    case 'sap_audit_tlv':
      // SAP Security Audit Log, MODERN length-prefixed binary format (RSAU,
      // NetWeaver 7.50+) — NOT the space-delimited KVP export handled by
      // `sap_audit`. One file arrives as ONE event holding many records with no
      // newline delimiter; each record is a 4-digit header-length prefix, then a
      // 35-ish-char header (msg-id[3] + timestamp[14] + MANDT[3] + meta), then a
      // fixed 7-slot body of 4-digit length-prefixed fields:
      //   [0]=SID/system [1]=user [2]=dialog [3]=ABAP program [4]=terminal/host
      //   [5]=source IP [6]=message variables / transaction.
      // A `code` function decodes ALL records into an array; `unroll` fans that
      // array into one event per record; a final eval hoists the decoded slots to
      // the shared canonical model so the golden OCSF/CIM/CEF specs map it (no AI).
      // The header body length is read DYNAMICALLY (4 + headerLen) — never a fixed
      // offset — because the meta section varies across message classes.
      //
      // INGESTION CONTRACT (deployment, not emitted here): this parser assumes the
      // whole binary blob reaches the pipeline as a SINGLE event — the `code` fn
      // reads all of `_raw` and finds record boundaries itself. The Source's event
      // breaker must therefore be a no-op (do-not-break / single-event), never a
      // newline/regex breaker, which would split records mid-field and defeat the
      // decoder. The pack generator emits pipelines only, so this is configured on
      // the Source at deploy time; it is documented here so the assumption is not
      // silently lost.
      return [
        {
          id: 'code',
          description: 'Decode SAP SAL length-prefixed TLV records into sap_records[]',
          conf: {
            // Cribl caps the Code function's maxNumOfIterations at 10,000 — a
            // higher value is rejected at pipeline-write (500: "The maximum
            // number of iterations must be set between 1 and 10,000!"). 10,000
            // is the ceiling; a single SAL blob with more records than that
            // would need chunking upstream, which the single-event ingestion
            // contract above already discourages.
            maxNumOfIterations: 10000,
            code: [
              "const raw = String(__e._raw || '');",
              '// record start = 4-digit len + msg-id(2 alpha + 1 alnum) + 14-digit timestamp',
              'const MARK = /\\d{4}[A-Z]{2}[A-Z0-9]\\d{14}/g;',
              'const starts = []; let mm;',
              'while ((mm = MARK.exec(raw)) !== null) starts.push(mm.index);',
              'starts.push(raw.length);',
              'const IPRE = /^\\d{1,3}(\\.\\d{1,3}){3}$/;',
              'const recs = [];',
              'for (let i = 0; i < starts.length - 1; i++) {',
              '  const rec = raw.slice(starts[i], starts[i + 1]);',
              '  const headerLen = parseInt(rec.slice(0, 4), 10);',
              '  if (!(headerLen > 0)) continue;',
              '  const msgId = rec.slice(4, 7), ts = rec.slice(7, 21), mandt = rec.slice(21, 24);',
              '  const fields = []; let p = 4 + headerLen;',
              '  while (p + 4 <= rec.length) {',
              '    const ls = rec.slice(p, p + 4);',
              '    if (!/^\\d{4}$/.test(ls)) break;',
              '    const len = parseInt(ls, 10);',
              '    if (p + 4 + len > rec.length) break;',
              '    fields.push(rec.slice(p + 4, p + 4 + len));',
              '    p += 4 + len;',
              '  }',
              '  const ip = IPRE.test(fields[5] || "") ? fields[5] : (IPRE.test(fields[4] || "") ? fields[4] : undefined);',
              '  const term = (fields[4] && !IPRE.test(fields[4])) ? fields[4] : undefined;',
              '  recs.push({',
              '    _rawrec: rec, msg_id: msgId, ts: ts, mandt: mandt || undefined,',
              '    sid: fields[0] || undefined, user: fields[1] || undefined,',
              '    dialog: fields[2] || undefined, program: fields[3] || undefined,',
              '    terminal: term, ip: ip, var_data: fields[6] || undefined,',
              '  });',
              '}',
              "__e['sap_records'] = recs;",
            ].join('\n'),
          },
        },
        {
          id: 'unroll',
          description: 'Fan sap_records[] into one event per SAL record',
          conf: { srcExpr: 'sap_records', dstField: 'rec' },
        },
        {
          id: 'eval',
          description: 'Hoist decoded SAP SAL fields to the canonical model',
          conf: {
            add: [
              // reset _raw to the single record so each event carries its own line.
              { name: '_raw', value: 'rec && rec._rawrec ? rec._rawrec : _raw' },
              // identity: SAP user is the acting principal.
              { name: 'user', value: 'rec && rec.user || undefined' },
              { name: 'src_user', value: 'rec && rec.user || undefined' },
              // origin: slot 5 is the client IP; slot 4 the terminal/workstation.
              { name: 'src_ip', value: 'rec && rec.ip || undefined' },
              { name: 'src_host', value: 'rec && rec.terminal || undefined' },
              // the SAP system/instance that logged the event = the device/host.
              { name: 'host', value: 'rec && rec.sid || undefined' },
              // TCODE/activity is the message-variable field; REPORT is the ABAP program.
              { name: 'app', value: 'rec && (rec.var_data || rec.dialog) || undefined' },
              { name: 'report', value: 'rec && rec.program || undefined' },
              // SAP message id as event code; message = id + variable substitution text.
              { name: 'event_code', value: 'rec && rec.msg_id || undefined' },
              { name: 'message', value: 'rec ? (String(rec.msg_id || "") + (rec.var_data ? " " + String(rec.var_data) : "")) : undefined' },
              // AU2 = failed logon; text of other ids may still signal failure.
              { name: 'action', value: "rec && rec.msg_id == 'AU2' ? 'failure' : (/fail|denied|locked|invalid|unauthori[sz]|reject/i.test(String(rec && rec.var_data)) ? 'failure' : 'success')" },
              // severity: failed logon = warning(3); logon/RFC ok = info(6); default notice(5).
              { name: 'severity', value: "rec && rec.msg_id == 'AU2' ? 3 : (rec && (rec.msg_id == 'AU1' || rec.msg_id == 'AU3') ? 6 : 5)" },
              // timestamp: YYYYMMDDHHMMSS, no tz in source → treat as UTC.
              { name: 'log_time', value: "rec && rec.ts ? Date.parse(rec.ts.slice(0,4)+'-'+rec.ts.slice(4,6)+'-'+rec.ts.slice(6,8)+'T'+rec.ts.slice(8,10)+':'+rec.ts.slice(10,12)+':'+rec.ts.slice(12,14)+'Z') : undefined" },
            ],
            remove: ['sap_records', 'rec'],
          },
        },
      ];

    case 'salesforce_setupaudittrail':
      // Salesforce Setup Audit Trail — one JSON object per event (ndjson), with
      // capitalized keys: Action, Section, Display, DelegateUser, CreatedById,
      // CreatedByContext, CreatedByIssuer, CreatedDate, Id,
      // ResponsibleNamespacePrefix. Parse the JSON then normalize to the shared
      // canonical AUDIT model so the golden `cef#audit` / `cim#change` /
      // `ocsf#cloud_audit` specs map it deterministically (no AI). This is a
      // config/admin audit trail, so there is NO network 5-tuple to emit.
      return [
        { id: 'serde', description: 'Parse Salesforce setup-audit JSON', conf: { mode: 'extract', type: 'json', srcField: '_raw' } },
        {
          id: 'eval',
          description: 'Normalize Salesforce setup-audit fields to the canonical model',
          conf: {
            add: [
              // the audited action (e.g. "changedProfile", "PermSetAssign").
              { name: 'action', value: 'Action || undefined' },
              { name: 'signature', value: 'Action || undefined' },
              { name: 'event_code', value: 'Action || undefined' },
              // the acting principal: DelegateUser is a username when a delegated
              // admin acted; else fall back to the CreatedById 15/18-char id.
              { name: 'user', value: 'DelegateUser || CreatedById || undefined' },
              { name: 'src_user', value: 'DelegateUser || CreatedById || undefined' },
              { name: 'user_id', value: 'CreatedById || undefined' },
              { name: 'delegate_user', value: 'DelegateUser || undefined' },
              // human-readable description of the change.
              { name: 'message', value: 'Display || undefined' },
              // Section = the Setup area the change was made in (the "what/where").
              { name: 'object', value: 'Section || undefined' },
              { name: 'category', value: 'Section || undefined' },
              // provenance context for cs2/cs3/cs4.
              { name: 'namespace', value: 'ResponsibleNamespacePrefix || undefined' },
              { name: 'context', value: 'CreatedByContext || undefined' },
              { name: 'issuer', value: 'CreatedByIssuer || undefined' },
              { name: 'event_id', value: 'Id || undefined' },
              // completed setup-audit entries record actions that succeeded.
              { name: 'outcome', value: "'success'" },
              // no severity in the source — audit entries are informational.
              { name: 'severity', value: '5' },
              // CreatedDate is ISO8601 with offset (e.g. 2022-08-16T09:26:38.000+0000).
              { name: 'log_time', value: 'CreatedDate ? Date.parse(String(CreatedDate)) : undefined' },
            ],
          },
        },
      ];

    case 'linux_syslog':
      return [
        {
          id: 'regex_extract',
          description: 'Parse syslog header (timestamp, host, process, pid, message)',
          conf: {
            source: '_raw',
            regex: '/^(?<log_time>\\w+\\s+\\d+\\s+[\\d:]+)\\s+(?<host>\\S+)\\s+(?<process>[^\\[:]+)(?:\\[(?<pid>\\d+)\\])?:\\s+(?<message>.+)$/',
          },
        },
        {
          id: 'regex_extract',
          filter: "process === 'sshd'",
          description: 'Extract SSH authentication fields (user, src_ip, port, method)',
          conf: {
            source: 'message',
            regex: '/(?<action>Accepted|Failed|Invalid)\\s+(?<auth_method>\\S+)\\s+for\\s+(?:invalid user\\s+)?(?<user>\\S+)\\s+from\\s+(?<src_ip>[\\d.]+)\\s+port\\s+(?<src_port>\\d+)/',
          },
        },
        {
          id: 'regex_extract',
          filter: "process === 'sudo'",
          description: 'Extract sudo command fields (user, runas_user, command)',
          conf: {
            source: 'message',
            regex: '/(?<user>\\S+)\\s+:\\s+.*?USER=(?<runas_user>\\S+)\\s*;\\s*COMMAND=(?<command>.+)/',
          },
        },
        {
          id: 'regex_extract',
          filter: "message && message.indexOf('UFW') >= 0",
          description: 'Extract UFW firewall block fields',
          conf: {
            source: 'message',
            regex: '/\\[UFW\\s+(?<action>\\w+)\\].*?SRC=(?<src_ip>[\\d.]+)\\s+DST=(?<dest_ip>[\\d.]+).*?SPT=(?<src_port>\\d+)\\s+DPT=(?<dest_port>\\d+)\\s+.*?PROTO=(?<transport>\\w+)/',
          },
        },
        {
          id: 'eval',
          description: 'Normalize linux syslog fields to canonical model',
          conf: {
            add: [
              { name: 'app', value: 'process || undefined' },
              { name: 'vendor_product', value: "'Linux'" },
              { name: 'severity', value: "action === 'Failed' || action === 'Invalid' || action === 'BLOCK' ? 4 : 6" },
              { name: 'action', value: "action === 'Accepted' ? 'success' : action === 'Failed' || action === 'Invalid' ? 'failure' : action ? String(action).toLowerCase() : undefined" },
              { name: 'event_code', value: 'process || undefined' },
            ],
          },
        },
      ];

    case 'linux_audit':
      // Linux auditd records (USER_CMD, USER_AUTH, SYSCALL, EXECVE, ...) are
      // process/endpoint telemetry: `type=VALUE msg=audit(epoch:serial): k=v ...`.
      // KVP serde pulls the native fields (uid/pid/ppid/comm/exe/res/ses/...),
      // the regex pulls type + the audit epoch/serial, then an eval aliases them
      // to the CANONICAL process model the golden endpoint specs read.
      return [
        { id: 'serde', description: 'Parse audit KVP', conf: { mode: 'extract', type: 'kvp', srcField: '_raw', delimChar: ' ', quoteChar: '"' } },
        {
          id: 'regex_extract',
          description: 'Extract audit type and serial',
          conf: { source: '_raw', regex: '/type=(?<audit_type>\\w+)\\s+msg=audit\\((?<audit_epoch>[\\d.]+):(?<audit_serial>\\d+)\\)/' },
        },
        {
          id: 'eval',
          description: 'Normalize auditd fields to the canonical process model',
          conf: {
            add: [
              // Event time: auditd epoch is fractional seconds (1786016338.708).
              { name: 'log_time', value: 'audit_epoch' },
              // Process identity: exe = full path, comm = short name.
              { name: 'process', value: 'exe || comm' },
              { name: 'process_name', value: 'comm || exe' },
              { name: 'command', value: 'exe || comm' },
              { name: 'process_id', value: 'pid != null && pid !== "" ? Number(pid) : undefined' },
              { name: 'parent_process_id', value: 'ppid != null && ppid !== "" ? Number(ppid) : undefined' },
              // Identity: user is the acting account; uid/auid are numeric ids.
              { name: 'user_id', value: 'uid' },
              { name: 'audit_user_id', value: 'auid' },
              // Session / terminal.
              { name: 'session_id', value: 'ses' },
              { name: 'terminal', value: 'terminal' },
              // Outcome + event type. res is success/failed; audit_type is the record kind.
              { name: 'outcome', value: 'res || (success === "yes" ? "success" : success === "no" ? "failed" : success)' },
              { name: 'action', value: 'res || (success === "yes" ? "success" : success === "no" ? "failed" : undefined)' },
              { name: 'signature', value: 'audit_type' },
              // The audit key (rule tag) is the closest thing to an object/rule name.
              { name: 'object', value: 'key' },
              { name: 'rule_name', value: 'key' },
            ],
          },
        },
      ];

    case 'crowdstrike_falcon':
      // CrowdStrike Falcon telemetry is flat JSON per event (LTR/streaming).
      // Extract the JSON envelope, then normalize the vendor field names to the
      // canonical model so the golden CIM + OCSF specs map it deterministically
      // (the AI path emitted flat dst_ip/protocol that the nested OCSF spec never
      // read → score 0; this makes it a golden-path source). CrowdStrike epochs
      // are fractional seconds (e.g. "1633127320.530").
      return [
        { id: 'serde', description: 'Extract CrowdStrike Falcon JSON fields', conf: { mode: 'extract', type: 'json', srcField: '_raw' } },
        {
          id: 'eval',
          description: 'Normalize CrowdStrike fields to the canonical model',
          conf: {
            add: [
              // Network endpoints (NetworkConnectIP4/6, DnsRequest, etc.)
              { name: 'src_ip', value: 'LocalAddressIP4 || LocalAddressIP6 || undefined' },
              { name: 'dest_ip', value: 'RemoteAddressIP4 || RemoteAddressIP6 || undefined' },
              { name: 'src_port', value: 'LocalPort != null ? Number(LocalPort) : undefined' },
              { name: 'dest_port', value: 'RemotePort != null ? Number(RemotePort) : undefined' },
              // Protocol: CrowdStrike Protocol is the IANA number (6=TCP,17=UDP,1=ICMP).
              { name: 'protocol', value: "Protocol == '6' ? 'tcp' : Protocol == '17' ? 'udp' : Protocol == '1' ? 'icmp' : Protocol ? String(Protocol) : undefined" },
              { name: 'transport', value: "Protocol == '6' ? 'tcp' : Protocol == '17' ? 'udp' : Protocol == '1' ? 'icmp' : undefined" },
              // ConnectionDirection 0=outbound, 1=inbound
              { name: 'direction', value: "ConnectionDirection == '0' ? 'outbound' : ConnectionDirection == '1' ? 'inbound' : undefined" },
              { name: 'action', value: "'allowed'" },
              // Host / device / identity
              { name: 'dvc_id', value: 'aid || undefined' },
              { name: 'sensor_id', value: 'aid || undefined' },
              { name: 'customer_id', value: 'cid || undefined' },
              { name: 'src', value: 'LocalAddressIP4 || LocalAddressIP6 || aid || undefined' },
              { name: 'external_ip', value: 'aip || undefined' },
              { name: 'process_id', value: 'ContextProcessId != null ? Number(ContextProcessId) : undefined' },
              { name: 'platform', value: 'event_platform || undefined' },
              { name: 'event_type', value: 'event_simpleName || undefined' },
              { name: 'event_id', value: 'id || undefined' },
              { name: 'signature', value: 'event_simpleName || undefined' },
              { name: 'app', value: "RemotePort == '443' ? 'https' : RemotePort == '80' ? 'http' : RemotePort == '53' ? 'dns' : undefined" },
              { name: 'vendor_product', value: "'CrowdStrike Falcon'" },
              // Time: ContextTimeStamp / timestamp are fractional-second epochs.
              { name: 'log_time', value: 'timestamp || ContextTimeStamp || undefined' },
            ],
          },
        },
      ];

    case 'aws_cloudtrail':
      // CloudTrail is single-object JSON per event (one API call). Extract the
      // envelope with serde json, promote nested fields to the canonical audit
      // model, then map deterministically to CIM Change / OCSF API Activity.
      return [
        { id: 'serde', description: 'Extract CloudTrail JSON fields', conf: { mode: 'extract', type: 'json', srcField: '_raw' } },
        {
          id: 'eval',
          description: 'Promote CloudTrail nested fields to canonical audit model',
          conf: {
            add: [
              { name: 'api_operation', value: 'eventName || undefined' },
              { name: 'event_code', value: 'eventName || undefined' },
              { name: 'cloud_service', value: 'eventSource || undefined' },
              { name: 'cloud_region', value: 'awsRegion || undefined' },
              { name: 'cloud_account', value: 'recipientAccountId || undefined' },
              { name: 'request_id', value: 'requestID || undefined' },
              { name: 'event_uid', value: 'eventID || undefined' },
              { name: 'error_code', value: 'errorCode || undefined' },
              { name: 'error_message', value: 'errorMessage || undefined' },
              { name: 'user_agent', value: 'userAgent || undefined' },
              { name: 'user_type', value: 'userIdentity && userIdentity.type || undefined' },
              { name: 'user_uid', value: 'userIdentity && userIdentity.principalId || undefined' },
              { name: 'user_account', value: 'userIdentity && userIdentity.accountId || undefined' },
              { name: 'credential_uid', value: 'userIdentity && userIdentity.accessKeyId || undefined' },
              { name: 'user_arn', value: 'userIdentity && userIdentity.arn || undefined' },
              { name: 'user', value: "userIdentity && userIdentity.type === 'AssumedRole' ? (userIdentity.sessionContext && userIdentity.sessionContext.sessionIssuer && userIdentity.sessionContext.sessionIssuer.userName || (userIdentity.arn && String(userIdentity.arn).split('/').pop())) : (userIdentity && (userIdentity.userName || userIdentity.arn || userIdentity.principalId)) || undefined" },
              { name: 'src_user', value: "userIdentity && userIdentity.type === 'AssumedRole' && userIdentity.sessionContext && userIdentity.sessionContext.sessionIssuer ? userIdentity.sessionContext.sessionIssuer.userName : undefined" },
              { name: 'mfa_used', value: "userIdentity && userIdentity.sessionContext && userIdentity.sessionContext.attributes && userIdentity.sessionContext.attributes.mfaAuthenticated === 'true' ? true : undefined" },
              { name: 'src_ip', value: "sourceIPAddress && String(sourceIPAddress).match(/^(\\d{1,3}\\.){3}\\d{1,3}$|:/) ? sourceIPAddress : undefined" },
              { name: 'src_host', value: "sourceIPAddress && !String(sourceIPAddress).match(/^(\\d{1,3}\\.){3}\\d{1,3}$|:/) ? sourceIPAddress : undefined" },
              { name: 'dest_host', value: 'eventSource || undefined' },
              { name: 'object_target', value: "requestParameters && requestParameters.roleArn ? requestParameters.roleArn : (requestParameters && requestParameters.userName ? requestParameters.userName : (responseElements && responseElements.user && responseElements.user.userName ? responseElements.user.userName : undefined))" },
              { name: 'resource_name', value: "object_target || (resources && resources[0] && resources[0]['ARN']) || undefined" },
              { name: 'resource_type', value: "resources && resources[0] && resources[0]['type'] || undefined" },
              { name: 'is_read_only', value: 'readOnly === true ? true : readOnly === false ? false : undefined' },
              { name: 'outcome', value: "errorCode || errorMessage || (responseElements && responseElements.ConsoleLogin === 'Failure') ? 'failure' : 'success'" },
              { name: 'auth_action', value: "eventName === 'ConsoleLogin' ? (responseElements && responseElements.ConsoleLogin === 'Failure' ? 'failure' : 'success') : undefined" },
              { name: 'message', value: "eventName ? String(eventName) + ' on ' + String(eventSource || '') : undefined" },
              { name: 'log_time', value: 'eventTime || undefined' },
              { name: 'severity', value: "errorCode || errorMessage ? 3 : 6" },
            ],
          },
        },
      ];

    // Infoblox NIOS: the stock `infoblox_syslog` datatype parser splits the syslog
    // ENVELOPE only and leaves the whole event in `message` — the batch-446 row
    // that extracted 6 fields (priority/log_time/host/process/pid/message) and
    // mapped nothing, because no golden spec reads any of them. The payload has
    // two shapes in one feed (named query lines and dhcpd lease lines), so parse
    // the envelope once and then each payload form into the canonical model.
    case 'infoblox_dns':
      return [
        {
          id: 'regex_extract',
          description: 'Parse the syslog envelope (priority, timestamp, host, process)',
          conf: {
            source: '_raw',
            // The device IP is an OPTIONAL extra token between hostname and
            // process (present on some relay configurations).
            regex: '/^<(?<priority>\\d+)>(?<syslog_timestamp>\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(?<host>\\S+)(?:\\s+(?<device_ip>\\d+\\.\\d+\\.\\d+\\.\\d+))?\\s+(?<process>[A-Za-z_][\\w-]*)\\[(?<pid>\\d+)\\]:\\s+(?<message>.*)$/',
          },
        },
        {
          id: 'regex_extract',
          filter: "message && message.indexOf('query:') >= 0",
          description: 'Parse a named DNS query line (client, transport, query, response code)',
          conf: {
            source: 'message',
            regex: '/^(?<dns_time>\\d{1,2}-\\w{3}-\\d{4}\\s+\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?)\\s+client\\s+(?<src_ip>\\S+?)#(?<src_port>\\d+)\\s+(?<transport_raw>\\w+):\\s+query:\\s+(?<query>\\S+)\\s+(?<query_class>\\w+)\\s+(?<query_type>\\w+)(?:\\s+response:\\s+(?<reply_code>\\w+))?/',
          },
        },
        {
          id: 'regex_extract',
          filter: "message && message.indexOf('DHCP') === 0",
          description: 'Parse a dhcpd lease line (action, leased address, client MAC)',
          conf: {
            source: 'message',
            regex: '/^(?<dhcp_action>DHCP\\w+)(?:\\s+for\\s+(?<lease_ip>\\d+\\.\\d+\\.\\d+\\.\\d+))?\\s+from\\s+(?<src_mac>[0-9a-f:]{17})(?:\\s+\\((?<client_host>[^)]+)\\))?(?:\\s+via\\s+(?<via>\\S+))?/',
          },
        },
        {
          id: 'eval',
          description: 'Normalize Infoblox fields to the canonical model',
          conf: {
            add: [
              // The named payload carries the TRUE event time (with a year); the
              // syslog header has no year, so it is only the fallback. Rule 8.
              { name: 'log_time', value: 'dns_time ? Date.parse(dns_time) / 1000 : syslog_timestamp ? Date.parse(syslog_timestamp) / 1000 : undefined' },
              { name: 'src_port', value: 'src_port != null ? Number(src_port) : undefined' },
              { name: 'dest_port', value: "transport_raw ? 53 : undefined" },
              { name: 'transport', value: 'transport_raw ? String(transport_raw).toLowerCase() : undefined' },
              { name: 'protocol', value: 'transport_raw ? String(transport_raw).toLowerCase() : undefined' },
              // NOERROR is an allowed answer; every other RCODE (REFUSED,
              // NXDOMAIN, SERVFAIL) is a denied/failed one.
              { name: 'action', value: "reply_code ? (reply_code === 'NOERROR' ? 'allowed' : 'blocked') : dhcp_action ? 'allowed' : undefined" },
              { name: 'dest_ip', value: 'lease_ip || undefined' },
              { name: 'src_mac', value: 'src_mac || undefined' },
              { name: 'src_host', value: 'client_host || undefined' },
              { name: 'url', value: 'query || undefined' },
              { name: 'signature', value: "dhcp_action || (query ? 'dns query' : undefined)" },
              { name: 'event_code', value: 'dhcp_action || reply_code || undefined' },
              // Syslog PRI → severity (PRI & 7).
              { name: 'severity', value: 'priority != null ? Number(priority) % 8 : undefined' },
              { name: 'app', value: "process === 'dhcpd' ? 'dhcp' : 'dns'" },
              { name: 'process', value: 'process || undefined' },
              { name: 'device_ip', value: 'device_ip || undefined' },
              { name: 'vendor', value: "'Infoblox'" },
              { name: 'product', value: "'NIOS'" },
              { name: 'vendor_product', value: "'Infoblox NIOS'" },
            ],
          },
        },
      ];

    // Canonical name is `aws_vpc_v5` (see SOURCETYPE_ALIASES) — the switch
    // canonicalizes BEFORE it dispatches, so this used to be keyed on the alias
    // `aws_vpc_flow` and was unreachable dead code. What actually ran was the
    // Cribl Search datatype parser, a `csv` serde with no `fields` and no
    // delimiter override: VPC flow records are SPACE-separated, so a comma CSV
    // parse yields one column and the golden mapper got nothing (0/1 fields).
    // v2 and v5 share the same 14-token default record layout.
    case 'aws_vpc_v5':
    case 'aws_vpc_v2':
      return [
        {
          id: 'regex_extract',
          description: 'Parse VPC Flow log fields (v2/v5 default record layout)',
          conf: {
            source: '_raw',
            regex: '/^(?<version>\\d+)\\s+(?<account_id>\\d+)\\s+(?<interface_id>\\S+)\\s+(?<src_ip>\\S+)\\s+(?<dest_ip>\\S+)\\s+(?<src_port>\\d+)\\s+(?<dest_port>\\d+)\\s+(?<ip_protocol>\\d+)\\s+(?<packets>\\d+)\\s+(?<bytes>\\d+)\\s+(?<start>\\d+)\\s+(?<end>\\d+)\\s+(?<action>\\w+)\\s+(?<log_status>\\w+)/',
          },
        },
        {
          id: 'eval',
          description: 'Normalize VPC Flow fields to the canonical model',
          conf: {
            add: [
              // `start` is the epoch second the capture window opened — the only
              // event time a flow record carries. Rule 8: one canonical name.
              { name: 'log_time', value: 'start != null ? Number(start) : undefined' },
              { name: 'duration', value: 'start != null && end != null ? Number(end) - Number(start) : undefined' },
              { name: 'src_port', value: 'src_port != null ? Number(src_port) : undefined' },
              { name: 'dest_port', value: 'dest_port != null ? Number(dest_port) : undefined' },
              // IANA protocol number → the lowercase name every spec expects.
              { name: 'transport', value: "ip_protocol === '6' ? 'tcp' : ip_protocol === '17' ? 'udp' : ip_protocol === '1' ? 'icmp' : ip_protocol === '58' ? 'ipv6-icmp' : ip_protocol === '47' ? 'gre' : ip_protocol === '50' ? 'esp' : ip_protocol != null ? String(ip_protocol) : undefined" },
              { name: 'protocol', value: 'transport || undefined' },
              // A flow record carries ONE byte/packet total for the capture
              // window, measured from the source: total for CIM, *_out for the
              // schema specs that only read a direction.
              { name: 'bytes', value: 'bytes != null ? Number(bytes) : undefined' },
              { name: 'bytes_out', value: 'bytes != null ? Number(bytes) : undefined' },
              { name: 'packets', value: 'packets != null ? Number(packets) : undefined' },
              { name: 'packets_out', value: 'packets != null ? Number(packets) : undefined' },
              { name: 'action', value: "action === 'ACCEPT' ? 'allowed' : action === 'REJECT' ? 'blocked' : action ? String(action).toLowerCase() : undefined" },
              // The ENI is the only device identity a flow record has.
              { name: 'dev_id', value: 'interface_id || undefined' },
              { name: 'vendor', value: "'AWS'" },
              { name: 'product', value: "'VPC Flow Logs'" },
              { name: 'vendor_product', value: "'AWS VPC Flow Logs'" },
            ],
          },
        },
      ];

    case 'apache_access':
    case 'nginx_access': {
      // Combined log format (identical for Apache `combined` and nginx's default
      // `combined`), captured DIRECTLY under canonical names plus a normalize eval.
      //
      // This parser used to emit `client_ip`/`uri`/`method`/`timestamp` — none of
      // which any golden spec reads — so `apache_access::cim` fed the mapper 3 of 9
      // fields and `nginx_access` fed it ZERO, giving the batch-446 signature:
      // extraction healthy, mapping 0. The ordering comment in App's extraction
      // stage promises that "the curated golden and static parsers emit exactly
      // those [canonical] names"; for these two sources that was simply untrue.
      // The referrer/user-agent pair is optional so the `common` log format (no
      // trailing quoted pair) still matches.
      const vendorProduct = sourcetype === 'nginx_access' ? 'nginx' : 'apache';
      return [
        {
          id: 'regex_extract',
          description: 'Parse combined/common access log format',
          conf: {
            source: '_raw',
            regex: '/^(?<src_ip>\\S+)\\s+(?<ident>\\S+)\\s+(?<user>\\S+)\\s+\\[(?<timestamp>[^\\]]+)\\]\\s+"(?<http_method>\\w+)\\s+(?<uri>\\S+)\\s+(?<http_version>[^"]+)"\\s+(?<status>\\d+)\\s+(?<bytes>\\d+)(?:\\s+"(?<http_referrer>[^"]*)"\\s+"(?<http_user_agent>[^"]*)")?/',
          },
        },
        {
          id: 'eval',
          description: 'Normalize access-log fields to the canonical model',
          conf: {
            add: [
              // `[12/Jan/2026:14:22:31 +0000]` → epoch seconds. Date.parse cannot
              // read the CLF colon after the year, so respell the date part first;
              // the numeric offset is preserved and honoured.
              { name: 'log_time', value: "timestamp ? Date.parse(timestamp.replace(/^(\\d+)\\/(\\w+)\\/(\\d+):/, '$1 $2 $3 ')) / 1000 : undefined" },
              { name: 'url', value: 'uri || undefined' },
              // CLF writes '-' for an absent value; keep it out of the output so a
              // literal dash is not scored as an extracted user.
              { name: 'user', value: "user && user !== '-' ? user : undefined" },
              { name: 'src_user', value: "user && user !== '-' ? user : undefined" },
              { name: 'bytes', value: 'bytes != null ? Number(bytes) : undefined' },
              { name: 'bytes_out', value: 'bytes != null ? Number(bytes) : undefined' },
              { name: 'status', value: 'status != null ? Number(status) : undefined' },
              // A 4xx/5xx response is the access decision this source carries.
              { name: 'action', value: "status ? (Number(status) >= 400 ? 'blocked' : 'allowed') : undefined" },
              { name: 'app', value: "'http'" },
              { name: 'vendor_product', value: `'${vendorProduct}'` },
            ],
          },
        },
      ];
    }

    case 'corelight_conn':
    case 'zeek_conn':
      // Corelight/Zeek conn logs are JSON (often syslog-wrapped via RFC5424).
      // Strip the syslog header if present, then JSON serde, then normalize
      // the dotted Zeek field names (id.orig_h → src_ip, id.resp_h → dest_ip).
      return [
        {
          id: 'eval',
          description: 'Strip RFC5424 syslog header to isolate JSON payload',
          conf: {
            add: [
              { name: '_raw', value: "_raw.indexOf('{') > 0 ? _raw.slice(_raw.indexOf('{')) : _raw" },
            ],
          },
        },
        {
          id: 'serde',
          description: 'Parse Corelight/Zeek JSON conn log',
          conf: { mode: 'extract', type: 'json', srcField: '_raw' },
        },
        {
          id: 'eval',
          description: 'Normalize Zeek dotted fields to canonical names',
          conf: {
            add: [
              { name: 'src_ip', value: "__e['id.orig_h'] || undefined" },
              { name: 'src_port', value: "__e['id.orig_p'] || undefined" },
              { name: 'dest_ip', value: "__e['id.resp_h'] || undefined" },
              { name: 'dest_port', value: "__e['id.resp_p'] || undefined" },
              { name: 'transport', value: "proto || undefined" },
              { name: 'bytes_in', value: "resp_bytes != null ? Number(resp_bytes) : undefined" },
              { name: 'bytes_out', value: "orig_bytes != null ? Number(orig_bytes) : undefined" },
              { name: 'duration', value: "duration != null ? Number(duration) : undefined" },
              { name: 'action', value: "conn_state || undefined" },
              { name: 'session_id', value: "uid || undefined" },
              { name: 'log_time', value: "ts || undefined" },
              { name: 'vendor_product', value: "'Corelight Zeek'" },
              { name: 'sourcetype', value: "'corelight_conn'" },
            ],
            remove: ['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
          },
        },
      ];

    case 'corelight_dns':
    case 'corelight_http':
    case 'corelight_ssl':
    case 'corelight_kerberos':
    case 'corelight_ldap':
    case 'corelight_ldap_search':
    case 'corelight_ntp':
    case 'corelight_notice':
    case 'corelight_weird':
    case 'corelight_tunnel':
    case 'corelight_vpn':
    case 'corelight_snmp':
    case 'corelight_smtp_links':
    case 'corelight_software':
    case 'corelight_known_hosts':
    case 'corelight_known_remotes':
    case 'corelight_known_services':
    case 'corelight_analyzer':
    case 'corelight_reporter':
    case 'corelight_suricata_enriched':
    case 'corelight_suricata_eve':
      return [
        {
          id: 'eval',
          description: 'Strip RFC5424 syslog header to isolate JSON payload',
          conf: {
            add: [
              { name: '_raw', value: "_raw.indexOf('{') > 0 ? _raw.slice(_raw.indexOf('{')) : _raw" },
            ],
          },
        },
        {
          id: 'serde',
          description: 'Parse Corelight/Zeek JSON log',
          conf: { mode: 'extract', type: 'json', srcField: '_raw' },
        },
        {
          id: 'eval',
          description: 'Normalize Zeek dotted fields to canonical names',
          conf: {
            add: [
              { name: 'src_ip', value: "__e['id.orig_h'] || undefined" },
              { name: 'src_port', value: "__e['id.orig_p'] || undefined" },
              { name: 'dest_ip', value: "__e['id.resp_h'] || undefined" },
              { name: 'dest_port', value: "__e['id.resp_p'] || undefined" },
              { name: 'session_id', value: "uid || undefined" },
              { name: 'log_time', value: "ts || undefined" },
              { name: 'vendor_product', value: "'Corelight Zeek'" },
              { name: 'sourcetype', value: `'${sourcetype}'` },
            ],
            remove: ['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
          },
        },
      ];

    case 'vsphere':
      // VMware vCenter / vSphere logs are RFC5424 syslog:
      //   <PRI>1 <ISO-ts> <host> <app-name> <procid> <msgid> <sd> <message>
      // (verified against the real elastic/integrations vsphere fixture). The
      // envelope is deterministic; the app-name IS the process (vpxd, hostd,
      // vpxa, applmgmt-audit) and the message body carries the per-event detail,
      // which stays in `message` so its values still count for coverage. Golden
      // path replaces the AI free-form that this high-volume family fell to.
      return [
        {
          id: 'regex_extract',
          description: 'Extract the RFC5424 vSphere envelope',
          conf: {
            source: '_raw',
            regex: '/^<\\d+>\\d+\\s+(?<log_time>\\S+)\\s+(?<host>\\S+)\\s+(?<process>\\S+)\\s+(?<procid>\\S+)\\s+\\S+\\s+\\S+\\s+(?<message>[\\s\\S]*)$/',
          },
        },
        {
          id: 'eval',
          description: 'Alias vSphere envelope fields to the canonical model',
          conf: {
            add: [
              { name: 'pid', value: "procid && procid != '-' ? procid : undefined" },
              { name: 'app', value: 'process || undefined' },
              { name: 'dest', value: 'host || undefined' },
              { name: 'vendor', value: "'VMware'" },
              { name: 'product', value: "'vCenter Server'" },
              { name: 'vendor_product', value: "'VMware vCenter'" },
              { name: 'sourcetype', value: "'vsphere'" },
            ],
            remove: ['procid'],
          },
        },
      ];

    case 'suricata_ids':
      return [
        {
          id: 'serde',
          description: 'Parse Suricata EVE JSON',
          conf: { mode: 'extract', type: 'json', srcField: '_raw' },
        },
        {
          id: 'eval',
          description: 'Normalize Suricata fields to canonical model',
          conf: {
            add: [
              { name: 'log_time', value: "timestamp || undefined" },
              { name: 'transport', value: "proto || undefined" },
              { name: 'action', value: "event_type || undefined" },
              { name: 'app', value: "app_proto || undefined" },
              { name: 'bytes_in', value: "flow && flow.bytes_toclient != null ? Number(flow.bytes_toclient) : undefined" },
              { name: 'bytes_out', value: "flow && flow.bytes_toserver != null ? Number(flow.bytes_toserver) : undefined" },
              { name: 'session_id', value: "flow_id != null ? String(flow_id) : undefined" },
              { name: 'vendor_product', value: "'Suricata IDS'" },
              { name: 'sourcetype', value: "'suricata_ids'" },
            ],
          },
        },
      ];

    case 'zscaler_web':
      // Zscaler NSS web logs come in multiple formats depending on output config:
      //  (a) Native KV: tab-separated key=value pairs (optionally quote-wrapped)
      //  (b) CEF: syslog header + CEF:0|Zscaler|NSSWeblog|...|key=value extension
      //  (c) JSON: {"sourcetype":"zscalernss-web","event":{...}}
      // Handle all three with conditional branches (filter expressions).
      return [
        {
          id: 'eval',
          description: 'Strip outer quotes from _raw (Zscaler NSS sometimes wraps the entire line)',
          conf: {
            add: [
              { name: '_raw', value: "_raw.length > 2 && _raw.charAt(0) == '\"' && _raw.charAt(_raw.length - 1) == '\"' ? _raw.slice(1, -1) : _raw" },
            ],
          },
        },
        {
          id: 'serde',
          filter: '_raw.charAt(0) == "{"',
          description: 'JSON variant: parse JSON-format Zscaler events',
          conf: { mode: 'extract', type: 'json', srcField: '_raw' },
        },
        {
          id: 'eval',
          filter: 'typeof event === "object" && event !== null',
          description: 'JSON variant: unwrap nested event object',
          conf: {
            add: [
              { name: '', value: 'Object.assign(__e, event)' },
            ],
            remove: ['event', 'sourcetype'],
          },
        },
        {
          id: 'regex_extract',
          filter: '/CEF:\\d+\\|/.test(_raw)',
          description: 'CEF variant: extract CEF header fields',
          conf: {
            source: '_raw',
            regex: '/CEF:\\d+\\|(?<device_vendor>[^|]*)\\|(?<device_product>[^|]*)\\|(?<device_version>[^|]*)\\|(?<action>[^|]*)\\|(?<reason>[^|]*)\\|(?<severity>[^|]*)\\|(?<cef_extension>.*)$/',
          },
        },
        {
          id: 'eval',
          filter: 'typeof cef_extension !== "undefined"',
          description: 'CEF variant: replace _raw with extension for KVP extraction',
          conf: {
            add: [
              { name: '_raw', value: 'cef_extension' },
            ],
            remove: ['cef_extension'],
          },
        },
        {
          id: 'serde',
          filter: '_raw.charAt(0) != "{"',
          description: 'KV variant: extract key=value pairs from Zscaler web log',
          conf: { mode: 'extract', type: 'kvp', srcField: '_raw', cleanFields: true, allowedKeyChars: [], allowedValueChars: [] },
        },
        {
          id: 'eval',
          description: 'Normalize common field names and derive log_time',
          conf: {
            add: [
              { name: 'log_time', value: "datetime || rt || undefined" },
              // JSON NSS uses lowercase clientip; CEF/KV often ClientIP / clientpublicIP.
              { name: 'src_ip', value: "clientip || ClientIP || clientpublicIP || src || undefined" },
              { name: 'dest_ip', value: "serverip || ServerIP || dst || undefined" },
              { name: 'host', value: "devicehostname || hostname || host || undefined" },
              { name: 'dest_port', value: "serverport || dpt || undefined" },
              { name: 'bytes_in', value: "responsesize ? Number(responsesize) : (typeof in_ !== 'undefined' ? Number(in_) : undefined)" },
              { name: 'bytes_out', value: "requestsize ? Number(requestsize) : (typeof out_ !== 'undefined' ? Number(out_) : undefined)" },
              { name: 'user', value: "login || user || undefined" },
              { name: 'url', value: "url || request || undefined" },
              { name: 'url_category', value: "urlcategory || cat || undefined" },
              { name: 'app', value: "appname || app || undefined" },
              { name: 'http_method', value: "requestmethod || undefined" },
              { name: 'http_status', value: "status || outcome || undefined" },
              { name: 'vendor_product', value: "'Zscaler ZIA'" },
            ],
          },
        },
      ];

    case 'gcp_audit':
      return [
        {
          id: 'serde',
          description: 'Parse Google Cloud Audit Log JSON envelope',
          conf: { mode: 'extract', type: 'json', srcField: '_raw' },
        },
        {
          id: 'eval',
          description: 'Normalize Google Cloud Audit Log fields to the canonical cloud-audit model',
          conf: {
            add: [
              { name: 'event_uid', value: 'insertId || undefined' },
              { name: 'request_id', value: 'insertId || undefined' },
              { name: 'log_name', value: 'logName || undefined' },
              { name: 'log_time', value: 'timestamp || undefined' },
              { name: 'user', value: 'protoPayload && protoPayload.authenticationInfo && protoPayload.authenticationInfo.principalEmail || undefined' },
              { name: 'user_uid', value: 'protoPayload && protoPayload.authenticationInfo && protoPayload.authenticationInfo.principalSubject || undefined' },
              { name: 'src_ip', value: 'protoPayload && protoPayload.requestMetadata && protoPayload.requestMetadata.callerIp || undefined' },
              { name: 'user_agent', value: 'protoPayload && protoPayload.requestMetadata && protoPayload.requestMetadata.callerSuppliedUserAgent || undefined' },
              { name: 'api_operation', value: 'protoPayload && protoPayload.methodName || undefined' },
              { name: 'action', value: 'protoPayload && protoPayload.methodName || undefined' },
              { name: 'cloud_service', value: 'protoPayload && protoPayload.serviceName || undefined' },
              { name: 'app', value: 'protoPayload && protoPayload.serviceName || undefined' },
              { name: 'resource_name', value: 'protoPayload && protoPayload.resourceName || undefined' },
              { name: 'resource_type', value: 'resource && resource.type || undefined' },
              { name: 'cloud_account', value: 'resource && resource.labels && (resource.labels.project_id || resource.labels.organization_id) || undefined' },
              { name: 'permission', value: 'protoPayload && protoPayload.authorizationInfo && protoPayload.authorizationInfo[0] && protoPayload.authorizationInfo[0].permission || undefined' },
              { name: 'granted', value: 'protoPayload && protoPayload.authorizationInfo && protoPayload.authorizationInfo[0] ? protoPayload.authorizationInfo[0].granted : undefined' },
              { name: 'outcome', value: "protoPayload && protoPayload.authorizationInfo && protoPayload.authorizationInfo[0] ? (protoPayload.authorizationInfo[0].granted === true ? 'success' : (protoPayload.authorizationInfo[0].granted === false ? 'failure' : undefined)) : undefined" },
              { name: 'cloud_provider', value: "'GCP'" },
              { name: 'vendor', value: "'Google'" },
              { name: 'vendor_name', value: "'Google'" },
              { name: 'product', value: "'Cloud Audit Logs'" },
              { name: 'vendor_product', value: "'Google Cloud Audit Logs'" },
            ],
          },
        },
      ];

    default: {
      // Fallback 1: a Cribl Search stock-datatype parser (100+ vendors/variants).
      const dtp = resolveDatatypeParser(sourcetypeRaw);
      if (dtp && dtp.functions.length > 0) {
        return dtp.functions;
      }
      // Fallback 2: custom/unknown sourcetypes — try JSON.
      return [
        { id: 'serde', description: 'Try JSON parse', conf: { mode: 'extract', type: 'json', srcField: '_raw' } },
      ];
    }
  }
}

/**
 * The field names a parser function list PRODUCES, collected statically:
 * regex named groups, `eval` add names, and a serde's explicit `fields` columns.
 *
 * `dynamic` means the list is NOT exhaustive because a stage introduces
 * source-driven keys that cannot be enumerated without running it — a wildcard
 * serde (json/kvp with no `fields`), `code`, `lookup`, `flatten`, `rename`, or an
 * eval calling `C.Text.parseWinEvent`/`parseXml` (Sysmon and windows_security
 * both parse XML and then flatten it, which is where EventID/Computer/UtcTime
 * come from). A `dynamic` parser can legitimately declare names this collector
 * cannot see, so the contract test only holds NON-dynamic parsers to equality.
 *
 * Exported because `lintParserContract` and the contract test must agree on what
 * "produced" means, and because deriving a declaration from the parser itself is
 * the only way it cannot drift.
 */
export function parserProducedFields(fns: PipelineFunction[] | null | undefined): { fields: string[]; dynamic: boolean } {
  const out = new Set<string>();
  let dynamic = false;
  for (const fn of fns || []) {
    const conf = (fn.conf || {}) as Record<string, any>;
    if (fn.id === 'regex_extract') {
      const regexes = [conf.regex, ...(Array.isArray(conf.regexList) ? conf.regexList.map((r: any) => r?.regex ?? r) : [])];
      for (const r of regexes) {
        if (!r) continue;
        for (const m of String(r).matchAll(/\(\?<([A-Za-z_$][\w$]*)>/g)) out.add(m[1]);
      }
      // A dynamically-sourced regex (ASA/FTD pull theirs from a lookup) cannot be
      // enumerated from the spec at all.
      if (!conf.regex && !conf.regexList) dynamic = true;
    } else if (fn.id === 'eval') {
      for (const a of (Array.isArray(conf.add) ? conf.add : [])) {
        if (a?.name) out.add(a.name);
        if (/C\.Text\.(parseWinEvent|parseXml)/.test(String(a?.value || ''))) dynamic = true;
      }
    } else if (fn.id === 'serde') {
      const cols = Array.isArray(conf.fields) ? conf.fields : [];
      if (cols.length) for (const c of cols) out.add(typeof c === 'string' ? c : c?.name);
      else dynamic = true;                       // wildcard json/kvp: source-driven keys
    } else if (fn.id === 'code' || fn.id === 'lookup' || fn.id === 'flatten' || fn.id === 'rename') {
      dynamic = true;
    }
  }
  out.delete(undefined as unknown as string);
  return { fields: [...out], dynamic };
}

/** Serde column names for a sourcetype's own parser — a declaration that cannot drift. */
function serdeColumnsFor(sourcetype: string): string[] {
  try {
    const fns = getParserForSourcetype(sourcetype, false);
    return (fns || []).flatMap(f => (f.id === 'serde' && Array.isArray((f.conf as any)?.fields) ? (f.conf as any).fields : []));
  } catch {
    return [];
  }
}

// The canonical output fields each built-in parser produces. This is the
// CONTRACT between the parse stage and the mapping stage: the destination
// mapping MUST reference these exact names (never invent CEF/CIM-native names
// like `src`/`dst`/`spt` that no parse stage emits). Returned to the mapping AI
// so it grounds every mapping in real extracted fields.
//
// For lookup-driven parsers (ASA/FTD) the fields vary per event code, so we
// list the common/high-value fields the parsing lookup regexes produce plus the
// always-present header fields (severity, asa_code/ftd_code).
export function getParserFieldNames(sourcetypeRaw: string, opts?: { strictDatatype?: boolean }): string[] {
  const sourcetype = canonicalizeSourcetype(sourcetypeRaw);
  const isFtd = /ftd|firepower/.test((sourcetypeRaw || '').toLowerCase());
  switch (sourcetype) {
    case 'cisco_asa':
      return [
        isFtd ? 'ftd_code' : 'asa_code', 'severity', 'event_code', 'log_time', 'host',
        // Common fields the parsing-lookup regexes emit (canonical names):
        'action', 'direction', 'transport', 'protocol', 'session_id',
        'src_ip', 'src_port', 'src_interface', 'src_user', 'src_host',
        'dest_ip', 'dest_port', 'dest_interface', 'dest_user', 'dest_host',
        'src_translated_ip', 'src_translated_port', 'dest_translated_ip', 'dest_translated_port',
        'icmp_type', 'icmp_code', 'access_group', 'rule_id', 'acl_name',
        'bytes', 'bytes_in', 'bytes_out', 'duration', 'reason', 'user',
        'message', 'threat_category', 'threat_level', 'url', 'fqdn',
        // Alias eval produces these from src_interface/dest_interface/duration_*:
        'src_zone', 'dest_zone',
      ];
    case 'linux_audit':
      // Native auditd KVP fields the serde emits, plus the canonical process/auth
      // fields the alias eval derives (see getParserForSourcetype case above).
      return [
        // Native KVP / regex fields:
        'audit_type', 'audit_epoch', 'audit_serial', 'arch', 'syscall',
        'success', 'exit', 'ppid', 'pid', 'auid', 'uid', 'gid', 'euid',
        'ses', 'comm', 'exe', 'key', 'user', 'terminal', 'res',
        // Canonical fields the alias eval produces:
        'log_time', 'process', 'process_name', 'command', 'process_id',
        'parent_process_id', 'user_id', 'audit_user_id', 'session_id',
        'outcome', 'action', 'signature', 'object', 'rule_name', 'host',
      ];
    case 'cisco_esa':
      return ['log_time', 'level', 'msg_body', 'mid', 'icid', 'dcid', 'rid',
        'src_ip', 'reverse_dns', 'dns_verified', 'interface', 'sender', 'recipient',
        'subject', 'spam_verdict', 'av_verdict', 'action',
        'filter_rule', 'dkim_domain', 'dkim_result', 'tls_peer_cn', 'category',
        // Alias eval produces these CIM Email canonical fields:
        'severity', 'message_id', 'session_id', 'src_user', 'dest_user', 'user',
        'app', 'vendor_product', 'signature', 'src', 'host',
        // `mail_size` and `protocol` were declared here but no stage produces
        // them. `protocol` is READ by the golden CIM spec, so declaring it told
        // the mapping AI to map a field that is always empty.
      ];
    case 'sap_hana':
      return ['log_time', 'level', 'pid', 'component', 'source_file', 'os_thread', 'msg_body',
        // Best-effort regex captures from the free-text message:
        'user', 'src_ip',
        // Classification + canonical aliases produced by the eval stage:
        'severity', 'outcome', 'category', 'message', 'src', 'app', 'vendor_product'];
    case 'fortinet_fortigate':
      return ['src_ip', 'dest_ip', 'src_port', 'dest_port', 'transport', 'protocol',
        'action', 'app', 'service', 'bytes_in', 'bytes_out', 'sent_bytes', 'rcvd_bytes',
        'sent_pkts', 'rcvd_pkts', 'packets_in', 'packets_out', 'duration', 'session_id',
        'severity', 'level', 'src_zone', 'dest_zone', 'src_country', 'dest_country',
        'policy_id', 'policy_name', 'src_mac', 'dest_mac', 'device_ip', 'dev_id',
        'src_translated_ip', 'src_translated_port', 'dest_translated_ip', 'dest_translated_port',
        'vdom', 'type', 'subtype', 'msg', 'user', 'log_time', 'host',
        'event_code', 'message', 'application', 'os', 'os_version', 'nat_disposition'];
    case 'f5_bigip':
      return ['syslog_pri', 'timestamp', 'host', 'severity', 'process', 'pid',
        'msg_id', 'message', 'log_time', 'src_ip', 'src_port', 'dest_ip',
        'dest_port', 'pool', 'virtual', 'status_code', 'ssl_event', 'action',
        // tmsh AUDIT lines — `user` is the one the CIM/CEF/CSL specs read
        // (user / suser / SourceUserName); the rest are command-audit context.
        'user', 'folder', 'module', 'status', 'cmd_data'];
    case 'sap_audit':
      return ['user', 'src_user', 'src_ip', 'src_host', 'host', 'device_ip',
        'message', 'event_code', 'app', 'report', 'action', 'severity', 'log_time'];
    case 'sap_audit_tlv':
      return ['user', 'src_user', 'src_ip', 'src_host', 'host', 'message',
        'event_code', 'app', 'report', 'action', 'severity', 'log_time'];
    case 'salesforce_setupaudittrail':
      return ['action', 'signature', 'event_code', 'user', 'src_user', 'user_id',
        'delegate_user', 'message', 'object', 'category', 'namespace', 'context',
        'issuer', 'event_id', 'outcome', 'severity', 'log_time'];
    case 'aws_cloudtrail':
      return ['api_operation', 'event_code', 'cloud_service', 'cloud_region', 'cloud_account',
        'request_id', 'src_ip', 'src_host', 'dest_host', 'user_agent', 'user', 'user_type', 'user_uid',
        'user_account', 'user_arn', 'src_user', 'credential_uid', 'mfa_used', 'event_uid',
        'error_code', 'error_message', 'resource_name', 'resource_type', 'object_target',
        'is_read_only', 'outcome', 'auth_action', 'message', 'log_time', 'severity'];
    case 'gcp_audit':
      return ['event_uid', 'request_id', 'log_name', 'log_time', 'severity',
        'user', 'user_uid', 'src_ip', 'user_agent', 'api_operation', 'cloud_service',
        'resource_name', 'resource_type', 'cloud_account', 'permission', 'granted',
        'outcome', 'action', 'app', 'cloud_provider', 'vendor', 'vendor_name',
        'product', 'vendor_product'];
    case 'crowdstrike_falcon':
      return ['src_ip', 'dest_ip', 'src_port', 'dest_port', 'protocol', 'transport',
        'direction', 'action', 'dvc_id', 'sensor_id', 'customer_id', 'src', 'external_ip',
        'process_id', 'platform', 'event_type', 'event_id', 'signature', 'app',
        'vendor_product', 'log_time'];
    // cisco_firepower now aliases to cisco_asa (same syslog format)
    case 'palo_alto_traffic':
    case 'palo_alto_threat':
    case 'palo_alto_system':
      // DERIVED from the parser's own CSV columns, never hand-listed. The old
      // hand-written list overclaimed 11-13 names the serde does not emit
      // (`src_translated_ip` vs the real `nat_src_ip`, `app` vs `application`,
      // `ip_protocol` vs `protocol`, `rule` vs `rule_name`, plus threat-only
      // columns declared for traffic). Those names were handed to the mapping AI
      // as available fields, so it wrote mappings that read fields which are
      // always empty. The two subtypes have DIFFERENT column sets (47 vs 53), which
      // one shared literal list cannot represent correctly anyway.
      // `log_time` is added by buildLogTimeAliasFn from generated_time/receive_time.
      // SYSTEM also declares the two canonical aliases its own eval stage adds — a
      // declared name the parser does not emit is a lie to the mapping AI, and an
      // emitted name it does not declare is invisible to it (and to the vacuity lint).
      return [...serdeColumnsFor(sourcetype).filter(f => !/^future_use\d*$/.test(f)), 'log_time',
        ...(sourcetype === 'palo_alto_system' ? ['host', 'message'] : [])];
    case 'corelight_conn':
    case 'zeek_conn':
      return ['src_ip', 'src_port', 'dest_ip', 'dest_port', 'transport', 'duration',
        'bytes_in', 'bytes_out', 'action', 'session_id', 'log_time',
        'vendor_product', 'sourcetype', 'conn_state', 'proto', 'uid',
        'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'orig_ip_bytes', 'resp_ip_bytes',
        'missed_bytes', 'history', 'local_orig', 'local_resp',
        'orig_cc', 'resp_cc', 'community_id', '_path', '_system_name'];
    case 'vsphere':
      // RFC5424 envelope only — vCenter/vpxd/hostd write free-text bodies, so
      // there are no per-message fields to declare beyond the envelope + aliases.
      return ['log_time', 'host', 'process', 'message', 'pid', 'app', 'dest',
        'vendor', 'product', 'vendor_product', 'sourcetype'];
    case 'suricata_ids':
      return ['src_ip', 'src_port', 'dest_ip', 'dest_port', 'transport', 'action',
        'app', 'bytes_in', 'bytes_out', 'session_id', 'log_time',
        'vendor_product', 'sourcetype', 'event_type', 'flow_id', 'proto',
        'app_proto', 'timestamp', 'in_iface', 'flow', 'tcp', 'alert',
        'community_id', 'metadata'];
    case 'corelight_dns':
    case 'corelight_http':
    case 'corelight_ssl':
    case 'corelight_kerberos':
    case 'corelight_ldap':
    case 'corelight_ldap_search':
    case 'corelight_ntp':
    case 'corelight_notice':
    case 'corelight_weird':
    case 'corelight_tunnel':
    case 'corelight_vpn':
    case 'corelight_snmp':
    case 'corelight_smtp_links':
    case 'corelight_software':
    case 'corelight_known_hosts':
    case 'corelight_known_remotes':
    case 'corelight_known_services':
    case 'corelight_analyzer':
    case 'corelight_reporter':
    case 'corelight_suricata_enriched':
    case 'corelight_suricata_eve':
      return ['src_ip', 'src_port', 'dest_ip', 'dest_port', 'session_id', 'log_time',
        'vendor_product', 'sourcetype', 'uid', '_path', '_system_name', 'ts',
        'proto', 'service', 'duration', 'community_id'];
    case 'zscaler_web':
      return ['log_time', 'src_ip', 'dest_ip', 'dest_port', 'action', 'reason',
        'protocol', 'url', 'url_category', 'app', 'user', 'http_method', 'http_status',
        'bytes_in', 'bytes_out', 'vendor_product', 'severity', 'hostname',
        'department', 'location', 'device_vendor', 'device_product',
        'threatname', 'threatcategory', 'threatclass', 'dlpengine', 'dlpdictionaries',
        'filetype', 'fileclass', 'useragent', 'refererURL', 'pagerisk',
        'transactionsize', 'event_id'];
    case 'windows_security':
      return ['EventID', 'Computer', 'Level', 'Channel', 'ProcessID', 'UserID',
        'SystemTime', 'TimeCreated_SystemTime', 'log_time',
        'TargetUserName', 'SubjectUserName', 'IpAddress', 'IpPort', 'LogonType',
        'TargetLogonId', 'ProcessName', 'NewProcessName', 'SubjectDomainName',
        'TargetDomainName', 'AuthenticationPackageName', 'WorkstationName', 'Workstation',
        'user', 'src_user', 'dest_user', 'src_ip', 'src_port', 'src', 'dest', 'dest_ip',
        'host', 'event_code',
        'app', 'vendor_product', 'action', 'session_id', 'severity',
        'logon_type', 'process', 'process_id', 'src_nt_domain', 'dest_nt_domain',
        'signature', 'authentication_method'];
    case 'windows_sysmon':
      return ['EventID', 'Computer', 'Level', 'Channel', 'UtcTime',
        'SystemTime', 'TimeCreated_SystemTime', 'log_time',
        'User', 'SourceIp', 'SourcePort', 'DestinationIp', 'DestinationPort', 'Protocol',
        'Image', 'ProcessId', 'ProcessGuid', 'CommandLine',
        'ParentImage', 'ParentProcessId', 'ParentCommandLine',
        'TargetFilename', 'TargetObject', 'Hashes', 'Hash', 'QueryName', 'RuleName',
        'user', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'transport', 'host', 'event_code',
        'app', 'vendor_product', 'action', 'severity',
        'process', 'process_id', 'process_guid', 'command',
        'parent_process', 'parent_process_id', 'parent_command',
        'file_path', 'registry_path', 'file_hash', 'dns_query', 'signature'];
    // Must stay in step with the windows_dns_client/_defender/_system/_application
    // cases in getParserForSourcetype — all four share `windowsXmlFrontEnd`, so the
    // envelope names are identical and only the EventData half differs.
    case 'windows_dns_client':
      return ['EventID', 'Computer', 'Level', 'Channel', 'ProcessID', 'UserID',
        'Provider_Name', 'SystemTime', 'TimeCreated_SystemTime', 'log_time',
        'QueryName', 'QueryType', 'QueryOptions', 'QueryStatus', 'QueryResults',
        'ServerList', 'IsNetworkQuery', 'NetworkQueryIndex', 'InterfaceIndex',
        'host', 'event_code', 'query', 'dns_query', 'url', 'query_type',
        'answer', 'dns_answer', 'dest_ip', 'dest_port', 'transport',
        'reply_code', 'reply_code_id', 'action', 'signature', 'process_id', 'user_id',
        'severity', 'app', 'vendor', 'product', 'vendor_product'];
    case 'windows_defender':
      return ['EventID', 'Computer', 'Level', 'Channel', 'ProcessID', 'UserID',
        'Provider_Name', 'SystemTime', 'TimeCreated_SystemTime', 'log_time',
        'ProductName', 'ThreatName', 'SeverityName', 'CategoryName', 'Path',
        'DetectionUser', 'User', 'ActionName', 'ActionID', 'StatusCode',
        'FeatureName', 'ScanID', 'ScanTypeName', 'CurrentSignatureVersion',
        'host', 'hostname', 'event_code', 'signature', 'category', 'severity_name',
        'file_path', 'object', 'user', 'user_id', 'action', 'outcome', 'process_id',
        'severity', 'app', 'vendor', 'product', 'vendor_product'];
    case 'windows_system':
      return ['EventID', 'Computer', 'Level', 'Channel', 'ProcessID', 'UserID',
        'Provider_Name', 'SystemTime', 'TimeCreated_SystemTime', 'log_time',
        'ServiceName', 'ImagePath', 'ServiceType', 'StartType', 'AccountName',
        'param1', 'Data',
        'host', 'hostname', 'event_code', 'app', 'process', 'object', 'user',
        'process_id', 'user_id', 'message', 'signature', 'action', 'outcome',
        'severity', 'vendor', 'product', 'vendor_product'];
    case 'windows_application':
      return ['EventID', 'Computer', 'Level', 'Channel', 'ProcessID', 'UserID',
        'Provider_Name', 'SystemTime', 'TimeCreated_SystemTime', 'log_time', 'Data',
        'host', 'hostname', 'event_code', 'app', 'message', 'process',
        'user_id', 'process_id', 'signature', 'outcome',
        'severity', 'vendor', 'product', 'vendor_product'];
    case 'windows_powershell':
      return ['LogName', 'SourceName', 'EventCode', 'EventType', 'Type',
        'ComputerName', 'User', 'Sid', 'Message', 'TaskCategory',
        'host', 'user', 'event_code', 'app', 'vendor_product', 'severity', 'action', 'signature'];
    case 'linux_syslog':
      return ['log_time', 'host', 'process', 'pid', 'message',
        'user', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'transport',
        'auth_method', 'runas_user', 'command', 'action',
        'app', 'vendor_product', 'severity', 'event_code'];
    case 'checkpoint_firewall':
      return ['log_time', 'host', 'src_ip', 'dest_ip', 'src_port', 'dest_port',
        'transport', 'action', 'direction', 'src_zone', 'user',
        'rule_name', 'rule_id', 'rule', 'match_id', 'parent_rule', 'event_code', 'severity',
        'device_ip', 'session_id', 'dev_id', 'origin_ip',
        'bytes', 'bytes_in', 'bytes_out', 'src_translated_ip', 'dest_translated_ip',
        'src_translated_port', 'dest_translated_port',
        'app', 'vendor_product'];
    // Must stay in step with the apache/nginx case in getParserForSourcetype.
    // Without an explicit case these fell through to `default:` and declared the
    // SEARCH datatype's fields (clientip/request/remote_addr/time_local) while the
    // hand-built parser that actually runs emits the canonical names below — so
    // every lint and the mapping AI were grounded in a parser that never ran.
    case 'apache_access':
    case 'nginx_access':
      return ['src_ip', 'ident', 'user', 'src_user', 'timestamp', 'log_time',
        'http_method', 'uri', 'url', 'http_version', 'status', 'bytes', 'bytes_out',
        'http_referrer', 'http_user_agent', 'action', 'app', 'vendor_product'];
    // Must stay in step with the infoblox_dns case in getParserForSourcetype.
    case 'infoblox_dns':
      return ['priority', 'syslog_timestamp', 'host', 'device_ip', 'process', 'pid', 'message',
        'log_time', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'transport', 'protocol',
        'query', 'query_class', 'query_type', 'reply_code', 'url', 'action', 'event_code',
        'signature', 'severity', 'src_mac', 'src_host', 'lease_ip', 'dhcp_action', 'client_host',
        'via', 'transport_raw', 'dns_time', 'app', 'vendor', 'product', 'vendor_product'];
    // Same story as apache/nginx: keyed on the alias `aws_vpc_flow`, so it fell
    // through to `default:` and declared the datatype parser's single `start`
    // column. Must stay in step with the aws_vpc_v5/v2 parser case.
    case 'aws_vpc_v5':
    case 'aws_vpc_v2':
      return ['version', 'account_id', 'interface_id', 'dev_id', 'src_ip', 'dest_ip',
        'src_port', 'dest_port', 'ip_protocol', 'protocol', 'transport', 'packets',
        'packets_out', 'bytes', 'bytes_out', 'start', 'end', 'log_time', 'duration',
        'action', 'log_status', 'vendor', 'product', 'vendor_product'];
    default: {
      // Fallback to the Search-datatype parser's field list so the mapping stage
      // stays grounded in what the (datatype) parser actually produces. The
      // recognizer passes strictDatatype so a mere substring match (cisco_asaa →
      // cisco_asa_syslog) does NOT make an unregistered name look known.
      const dtp = resolveDatatypeParser(sourcetypeRaw, opts?.strictDatatype ?? false);
      if (!dtp) return [];
      // `fields` is the datatype's own declared column list, synced from Cribl
      // Search — and for several datatypes it names fields the parser's regex
      // never captures (cisco_fwsm_v2 declares transport/dest_ip/dest_port,
      // snort_alert_syslog the same, cisco_asa_syslog severity/asa_code). Those
      // are handed to the mapping AI as available, so it maps values that are
      // always empty. When the parser is statically enumerable, what it PRODUCES
      // is the truthful contract; patching the JSON would be undone by the next
      // `npm run sync:datatypes`, so correct it here at resolution time (same
      // approach as UNREADABLE_SOURCE_SAMPLES). A wildcard serde stays dynamic —
      // there the declared list is the only information available.
      const produced = parserProducedFields(dtp.functions);
      if (produced.dynamic || !produced.fields.length) return dtp.fields;
      const real = new Set(produced.fields);
      // Keep a declared timeField even if it is serde/alias-derived: Rule 8's
      // self-healing layer adds log_time at build time from whatever it finds.
      const keptDeclared = (dtp.fields || []).filter(f => real.has(f) || SELF_HEALED_FIELDS.has(f) || f === dtp.timeField);
      return [...new Set([...keptDeclared, ...produced.fields])];
    }
  }
}

export type DataClass =
  | 'network' | 'authentication' | 'endpoint' | 'web_proxy'
  | 'email' | 'cloud_audit' | 'audit' | 'dns' | 'generic';

// Sourcetype (canonical) → data class. Unknown sourcetypes fall to 'generic'.
export const SOURCETYPE_DATACLASS: Record<string, DataClass> = {
  cisco_asa: 'network', cisco_ftd: 'network', cisco_firepower: 'network',
  palo_alto_traffic: 'network', palo_alto_threat: 'network',
  // PAN-OS SYSTEM logs are device/config/operational events (HA, auth daemon,
  // general system) — a config-change/operational trail, NOT the network
  // 5-tuple that traffic/threat carry. 'audit' picks the right golden spec.
  palo_alto_system: 'audit',
  sap_audit_tlv: 'authentication',
  fortinet_fortigate: 'network', checkpoint_firewall: 'network',
  aws_vpc_v5: 'network', zscaler_web: 'web_proxy',
  cisco_esa: 'email',
  windows_security: 'authentication', azure_signin: 'authentication',
  okta_system: 'authentication',
  // SAP Security Audit Log is logon-centric (logon success/failure, user actions);
  // Authentication (OCSF 3002 / CIM Authentication) fits it far better than the
  // generic config-change `audit` class. Salesforce Setup Audit Trail stays
  // `audit` — it is genuinely a config-change trail.
  sap_audit: 'authentication',
  sap_hana: 'authentication',
  salesforce_setupaudittrail: 'audit',
  windows_powershell: 'endpoint', windows_sysmon: 'endpoint',
  // Windows XML per channel — the whole point of splitting them off
  // windows_security. `windows_application` stays deliberately `generic`: its
  // providers write unnamed <Data> blobs, so there is no security model to claim
  // and `json` is the honest destination recommendation.
  windows_system: 'endpoint', windows_defender: 'endpoint',
  windows_dns_client: 'dns', windows_application: 'generic',
  crowdstrike_falcon: 'endpoint', linux_audit: 'endpoint', linux_syslog: 'endpoint',
  aws_cloudtrail: 'cloud_audit', gcp_audit: 'cloud_audit',
  alibaba_action_trail: 'cloud_audit',
  apache_access: 'web_proxy', nginx_access: 'web_proxy',
  infoblox_dns: 'dns', corelight_dns: 'dns',
  // Corelight subtypes that must beat the `/^corelight_/` → network pattern.
  corelight_ldap: 'authentication', corelight_ldap_search: 'authentication',
  corelight_http: 'web_proxy', corelight_smtp_links: 'email',
};

