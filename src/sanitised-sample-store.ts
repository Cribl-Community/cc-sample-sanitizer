/**
 * Shared document contract for pseudonymised, parser-validated customer samples.
 *
 * The document is deliberately a one-way artifact: it contains the sanitised events
 * and evidence that they still work, but never the originals or the replacement map.
 * Both persistence implementations (repo files and iframe KV) accept only this shape.
 */
import {
  aiSampleKey,
  sampleRejectionFingerprint,
  type SampleVerification,
} from './sample-library';

export type SanitisedSourceMode = 'upload' | 'paste' | 'group' | 'live-capture';

export interface SanitisedCoverage {
  total: number;
  replaced: number;
  ok: boolean;
  blind: boolean;
}

export interface SanitisedSampleProvenance {
  sourceMode: SanitisedSourceMode;
  /** Filename or "pasted events"; safe context only, never event content. */
  sourceLabel: string;
  replacementsApplied: number;
  structurePreserved: boolean;
  coverage: SanitisedCoverage;
  sanitisedAt: string;
  buildNumber?: number;
}

export interface SanitisedSampleDoc {
  version: 1;
  key: string;
  sourcetype: string;
  format?: string;
  events: string[];
  fingerprint: string;
  verification: SampleVerification;
  provenance: SanitisedSampleProvenance;
  sanitised: true;
}

export interface SanitisedSampleIndexRow {
  key: string;
  sourcetype: string;
  format?: string;
  events: number;
  fingerprint: string;
  sanitisedAt: string;
  verdict: SampleVerification['verdict'];
  method: SampleVerification['method'];
}

export const SANITISED_SAMPLE_MAX_BYTES = 1_000_000;

function unsafeKeyPart(value: string): boolean {
  return /[/\\]/.test(value) || value.includes('..')
    || value.includes('\u0000') || value.includes('\r') || value.includes('\n');
}

export function sanitisedSampleKey(sourcetype: string, format?: string | null): string {
  const source = String(sourcetype || '').trim();
  const fmt = String(format || '').trim();
  if (!source || unsafeKeyPart(source)) throw new Error('Invalid sourcetype for a sanitised sample.');
  if (fmt && unsafeKeyPart(fmt)) throw new Error('Invalid format for a sanitised sample.');
  const key = aiSampleKey(source, fmt || null);
  if (!key || unsafeKeyPart(key)) throw new Error('Invalid sourcetype for a sanitised sample.');
  return key;
}

function finiteCount(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null;
}

function normaliseVerification(value: Partial<SampleVerification>): SampleVerification {
  const verdict = value.verdict;
  const method = value.method;
  if (!['pass', 'fail', 'unverified'].includes(String(verdict))) throw new Error('Invalid sample verification verdict.');
  if (!['parser-emulation', 'source-expectation', 'structure', 'none'].includes(String(method))) {
    throw new Error('Invalid sample verification method.');
  }
  return {
    verdict: verdict!,
    method: method!,
    eventsParsed: finiteCount(value.eventsParsed) ?? 0,
    eventsChecked: finiteCount(value.eventsChecked) ?? 0,
    fields: Array.isArray(value.fields) ? value.fields.filter((v): v is string => typeof v === 'string') : [],
    reasons: Array.isArray(value.reasons) ? value.reasons.filter((v): v is string => typeof v === 'string') : [],
    offendingEvents: Array.isArray(value.offendingEvents)
      ? value.offendingEvents.filter((v): v is string => typeof v === 'string').slice(0, 3)
      : [],
    ...(value.keyEcho ? { keyEcho: value.keyEcho } : {}),
  };
}

function normaliseProvenance(value: SanitisedSampleProvenance): SanitisedSampleProvenance {
  if (!['upload', 'paste', 'group', 'live-capture'].includes(value?.sourceMode)) throw new Error('Invalid sanitised sample source mode.');
  const total = finiteCount(value.coverage?.total);
  const replaced = finiteCount(value.coverage?.replaced);
  const replacementsApplied = finiteCount(value.replacementsApplied);
  if (total == null || replaced == null || replacementsApplied == null) throw new Error('Invalid sanitisation counts.');
  if (typeof value.sanitisedAt !== 'string' || !value.sanitisedAt) throw new Error('Missing sanitisation timestamp.');
  return {
    sourceMode: value.sourceMode,
    sourceLabel: typeof value.sourceLabel === 'string' ? value.sourceLabel.slice(0, 200) : '',
    replacementsApplied,
    structurePreserved: value.structurePreserved === true,
    coverage: {
      total,
      replaced,
      ok: value.coverage.ok === true,
      blind: value.coverage.blind === true,
    },
    sanitisedAt: value.sanitisedAt,
    ...(finiteCount(value.buildNumber) != null ? { buildNumber: finiteCount(value.buildNumber)! } : {}),
  };
}

export function buildSanitisedSampleDoc(args: {
  sourcetype: string;
  format?: string | null;
  events: string[];
  verification: Partial<SampleVerification>;
  provenance: SanitisedSampleProvenance;
}): SanitisedSampleDoc {
  const events = args.events.map(String).filter(line => line.trim());
  if (!events.length) throw new Error('A sanitised sample needs at least one event.');
  const key = sanitisedSampleKey(args.sourcetype, args.format);
  const [sourcetype, format] = key.split('::');
  const doc: SanitisedSampleDoc = {
    version: 1,
    key,
    sourcetype,
    ...(format ? { format } : {}),
    events,
    fingerprint: sampleRejectionFingerprint(events),
    verification: normaliseVerification(args.verification),
    provenance: normaliseProvenance(args.provenance),
    sanitised: true,
  };
  if (JSON.stringify(doc).length > SANITISED_SAMPLE_MAX_BYTES) {
    throw new Error(`Sanitised sample is over the ${Math.round(SANITISED_SAMPLE_MAX_BYTES / 1024)} KB storage limit.`);
  }
  return doc;
}

function unwrapJson(value: unknown): unknown {
  let candidate = value;
  for (let i = 0; i < 3 && typeof candidate === 'string'; i++) {
    try { candidate = JSON.parse(candidate); } catch { return null; }
  }
  return candidate;
}

export function parseSanitisedSampleDoc(value: unknown): SanitisedSampleDoc | null {
  const candidate = unwrapJson(value) as Partial<SanitisedSampleDoc> | null;
  if (!candidate || typeof candidate !== 'object' || candidate.version !== 1 || candidate.sanitised !== true) return null;
  if (typeof candidate.key !== 'string' || typeof candidate.sourcetype !== 'string') return null;
  if (!Array.isArray(candidate.events) || !candidate.events.length || candidate.events.some(e => typeof e !== 'string')) return null;
  if (unsafeKeyPart(candidate.key) || candidate.key !== sanitisedSampleKey(candidate.sourcetype, candidate.format)) return null;
  if (!candidate.provenance || typeof candidate.provenance !== 'object') return null;
  try {
    const rebuilt = buildSanitisedSampleDoc({
      sourcetype: candidate.sourcetype,
      format: candidate.format,
      events: candidate.events,
      verification: candidate.verification || {},
      provenance: candidate.provenance,
    });
    // The fingerprint is content-derived. Reject stale/tampered metadata rather than
    // quietly correcting a document that crossed a trust boundary.
    if (candidate.fingerprint !== rebuilt.fingerprint) return null;
    return rebuilt;
  } catch {
    return null;
  }
}

export function sanitisedSampleIndexRow(doc: SanitisedSampleDoc): SanitisedSampleIndexRow {
  return {
    key: doc.key,
    sourcetype: doc.sourcetype,
    ...(doc.format ? { format: doc.format } : {}),
    events: doc.events.length,
    fingerprint: doc.fingerprint,
    sanitisedAt: doc.provenance.sanitisedAt,
    verdict: doc.verification.verdict,
    method: doc.verification.method,
  };
}

export function downloadSanitisedSamplePayload(
  doc: SanitisedSampleDoc,
  format: 'log' | 'json' | 'report',
): { body: string; mime: string; filename: string } {
  const stem = doc.key.replace(/::/g, '__').replace(/[^a-z0-9_.-]/gi, '_');
  if (format === 'log') {
    return { body: `${doc.events.join('\n')}\n`, mime: 'text/plain', filename: `${stem}.log` };
  }
  if (format === 'report') {
    return { body: buildSanitisedSampleReportHtml(doc), mime: 'text/html', filename: `${stem}-report.html` };
  }
  // Serialise an explicit allowlist. A future in-memory field added to the session
  // cannot accidentally put the replacement map in a download.
  const safe = {
    version: doc.version,
    key: doc.key,
    sourcetype: doc.sourcetype,
    ...(doc.format ? { format: doc.format } : {}),
    events: doc.events,
    fingerprint: doc.fingerprint,
    verification: doc.verification,
    provenance: doc.provenance,
    sanitised: true,
  };
  return { body: `${JSON.stringify(safe, null, 2)}\n`, mime: 'application/json', filename: `${stem}.json` };
}

function esc(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * A self-contained, printable evidence report for a sanitised sample — the human-facing
 * counterpart to the JSON payload. It carries the same allowlisted facts (never the
 * original events or the replacement map), plus a "Print / Save as PDF" button so the
 * reviewer gets a PDF without us shipping a PDF library. Pure string builder, no Node/DOM,
 * so both run modes and the tests can call it directly.
 */
export function buildSanitisedSampleReportHtml(doc: SanitisedSampleDoc): string {
  const p = doc.provenance;
  const cov = p.coverage;
  const rows: Array<[string, string]> = [
    ['Sourcetype', doc.sourcetype],
    ['Format', doc.format || '—'],
    ['Events', String(doc.events.length)],
    ['Identities replaced', String(p.replacementsApplied)],
    ['Structure preserved', p.structurePreserved ? 'yes' : 'no'],
    ['Parser verification', `${doc.verification.verdict} (${doc.verification.method})`],
    ['Coverage', `${cov.replaced}/${cov.total} located values replaced${cov.blind ? ' — blind spots present' : ''}`],
    ['Source', `${p.sourceMode} · ${p.sourceLabel}`],
    ['Sanitised at', p.sanitisedAt],
    ['Fingerprint', doc.fingerprint],
    ...(p.buildNumber ? [['Generated by build', String(p.buildNumber)] as [string, string]] : []),
  ];
  const verdictClass = doc.verification.verdict === 'pass' ? 'ok'
    : doc.verification.verdict === 'fail' ? 'bad' : 'warn';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sanitised sample report — ${esc(doc.sourcetype)}</title>
<style>
  :root { color-scheme: light; }
  body { font: 14px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; color: #1f2933; margin: 0; padding: 32px; background: #f5f7fa; }
  .sheet { max-width: 900px; margin: 0 auto; background: #fff; border: 1px solid #e4e9ef; border-radius: 12px; padding: 28px 32px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .eyebrow { text-transform: uppercase; letter-spacing: .06em; font-size: 11px; font-weight: 700; color: #007c83; margin: 0; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; }
  .badge.ok { background: #e6fffb; color: #006d75; } .badge.warn { background: #fffbe6; color: #ad6800; } .badge.bad { background: #fff1f0; color: #a8071a; }
  table { border-collapse: collapse; width: 100%; margin: 20px 0; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #eef1f5; font-size: 13px; vertical-align: top; }
  th { width: 210px; color: #52606d; font-weight: 600; }
  td { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-word; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .05em; color: #52606d; margin: 24px 0 8px; }
  pre { background: #0f172a; color: #e2e8f0; border-radius: 8px; padding: 14px 16px; overflow: auto; font-size: 12px; line-height: 1.55; max-height: 420px; }
  .toolbar { max-width: 900px; margin: 0 auto 16px; text-align: right; }
  button { font: inherit; padding: 8px 14px; border: 1px solid #007c83; background: #007c83; color: #fff; border-radius: 7px; cursor: pointer; }
  .note { color: #7b8794; font-size: 12px; margin-top: 6px; }
  @media print { body { background: #fff; padding: 0; } .toolbar { display: none; } .sheet { border: 0; } }
</style></head>
<body>
  <div class="toolbar"><button onclick="window.print()">Print / Save as PDF</button></div>
  <div class="sheet">
    <p class="eyebrow">Cribl Pack Generator — Sanitised sample evidence</p>
    <h1>${esc(doc.sourcetype)} <span class="badge ${verdictClass}">${esc(doc.verification.verdict)}</span></h1>
    <p class="note">This report contains only sanitised events and the sanitisation evidence. The original values and the original→alias map are never recorded.</p>
    <table><tbody>
      ${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('\n      ')}
    </tbody></table>
    <h2>Sanitised events (${doc.events.length})</h2>
    <pre>${esc(doc.events.join('\n'))}</pre>
  </div>
</body></html>
`;
}
