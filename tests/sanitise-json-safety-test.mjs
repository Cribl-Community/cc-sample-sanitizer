import assert from 'node:assert/strict';
import test from 'node:test';

import {
  recogniseSampleLocally,
  parseSampleLocally,
  planSampleSanitisation,
  applyAndVerifySanitisation,
  flattenJsonLine,
} from '../src/sanitised-sample-workflow.ts';
import { planSanitisation, applySanitisation, checkStructurePreserved } from '../src/sample-sanitise.ts';

// A real Exchange Online / O365 Unified Audit Log record (one JSON object per line). Its
// Subject carries a unicode + tab escape (`Müller\t…`) that the DOMAIN\user pattern
// used to read as `u00fcller \ t04.08.2026` — a bogus identity that also corrupted the JSON.
const O365_LINE = '{"CreationTime": "2026-08-17T11:56:38", "Operation": "MailItemsAccessed", "RecordType": 50, "OrganizationId": "5c904887-9347-4183-bc19-a2068b519da9", "Workload": "Exchange", "UserKey": "1003200491C7DEAE", "UserType": 0, "UserId": "uia12226@oeslwan.com", "ClientIPAddress": "94.31.117.36", "Subject": "AW:  M\\u00fcller\\t04.08.2026\\tTrotz ganzt. Abwes. anwesend"}';

test('a self-describing JSON sample is NOT claimed by a delimited/CSV static parser', () => {
  const rec = recogniseSampleLocally(O365_LINE);
  assert.equal(rec.format.id, 'json');
  // The old bug: a comma-heavy JSON line comma-split into "53 columns" and palo_alto_threat
  // (a CSV serde) claimed it with high confidence. Whatever we recognise it as now, it must
  // never be a delimited text parser guessing.
  assert.notEqual(rec.sourcetype, 'palo_alto_threat');
  assert.ok(rec.method !== 'static-parser', `must not use a static text parser, got ${rec.method}`);
});

test('DOMAIN\\user pattern ignores JSON string escapes but keeps a real (double-backslash) pair', () => {
  const line = '{"Subject": "AW:  M\\u00fcller\\t04.08.2026\\tTrotz", "Account": "CORP\\\\jsmith"}';
  const plan = planSanitisation(line, { sourcetype: '' });
  const winuser = plan.entries.filter(e => e.via && e.via.includes('DOMAIN'));
  const originals = winuser.map(e => e.original).sort();
  // Real DOMAIN\\user (doubled backslash in JSON) is still split into its two identities…
  assert.deepEqual(originals, ['CORP', 'jsmith']);
  // …and the ü / \t escapes produce NO identity.
  assert.ok(!plan.entries.some(e => /u00fc|04\.08\.2026/.test(e.original)), 'escape sequences must not become identities');
});

test('sanitising a JSON sample keeps every line valid JSON (no invalid \\c escape)', () => {
  const plan = planSampleSanitisation(O365_LINE, '');
  const after = applySanitisation(O365_LINE, plan.entries);
  assert.doesNotThrow(() => JSON.parse(after), 'sanitised JSON must still parse');
  assert.ok(checkStructurePreserved(O365_LINE, after).ok, 'wire format must be preserved');
});

test('flattenJsonLine turns a JSON record into dotted field→value pairs', () => {
  const flat = flattenJsonLine('{"a": {"b": "x"}, "c": [1, 2], "d": null}');
  assert.equal(flat['a.b'], 'x');
  assert.equal(flat.c, '1');          // first array element wins the path
  assert.ok(!('d' in flat));          // null is dropped
  assert.equal(flattenJsonLine('not json'), null);
});

test('coverage is NOT blind for a JSON sample with no static parser (flatten fallback)', () => {
  // A generic JSON feed with no signature/parser must still be provable via flattening,
  // else the strict library save-flow rejects it as `blind`.
  const generic = '{"user_email": "alice@corp.example", "src": "203.0.113.9", "note": "hello"}';
  const parsed = parseSampleLocally(generic, '');
  assert.ok(parsed.parsed.some(Boolean), 'JSON lines must flatten to readable records');
  const plan = planSampleSanitisation(generic, '');
  // No throw = coverage proven (not blind) and structure preserved.
  assert.doesNotThrow(() => applyAndVerifySanitisation(generic, '', plan.entries));
});
