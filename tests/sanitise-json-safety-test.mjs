import assert from 'node:assert/strict';
import test from 'node:test';

import {
  recogniseSampleLocally,
  parseSampleLocally,
  planSampleSanitisation,
  applyAndVerifySanitisation,
  flattenJsonLine,
} from '../src/sanitised-sample-workflow.ts';
import {
  planSanitisation, applySanitisation, checkStructurePreserved, markSanitisation, previewSanitisation, structuralOffenders,
  PICKED_PATTERN_VIA,
} from '../src/sample-sanitise.ts';

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

// GCP audit: label keys carry the service domain (`compute.googleapis.com/root_trigger_id`)
// that `serviceName` holds as a value, and a username can equal a key (`"admin": true`). A plain
// text swap renamed those keys, and the save gate refused the sample: "N JSON line(s) changed
// their field names".
const GCP_LINE = '{"protoPayload":{"serviceName":"compute.googleapis.com","authenticationInfo":{"principalEmail":"admin@acme.com"}},"labels":{"compute.googleapis.com/root_trigger_id":"42","k\\"admin":"admin"},"admin":true}';
const entry = (kind, original, alias, extra = {}) => ({ kind, original, alias, enabled: true, count: 1, via: 'test', confidence: 'certain', ...extra });
const GCP_ENTRIES = [entry('host', 'compute.googleapis.com', 'svc01.example.net'), entry('user', 'admin', 'user01')];

test('a value that also spells a JSON key is replaced in values only (GCP audit labels)', () => {
  const after = applySanitisation(GCP_LINE, GCP_ENTRIES);
  assert.deepEqual(checkStructurePreserved(GCP_LINE, after), { ok: true, problems: [] });
  const o = JSON.parse(after);
  assert.equal(o.protoPayload.serviceName, 'svc01.example.net');
  assert.equal(o.protoPayload.authenticationInfo.principalEmail, 'user01@acme.com');
  assert.deepEqual(Object.keys(o.labels), ['compute.googleapis.com/root_trigger_id', 'k"admin']);
  assert.equal(o.labels['k"admin'], 'user01', 'a value after an escaped quote in a key is still a value');
  assert.equal(o.admin, true);
  assert.equal(structuralOffenders(GCP_ENTRIES, GCP_LINE).size, 0);
});

test('marks and preview skip JSON keys exactly as apply does', () => {
  const marked = markSanitisation(GCP_LINE, GCP_ENTRIES).map(s => GCP_LINE.slice(s.start, s.end + 2));
  assert.deepEqual(marked, ['compute.googleapis.com",', 'admin@a', 'admin"}'], 'only the three values are marked');
  const { lines } = previewSanitisation(GCP_LINE, GCP_ENTRIES);
  assert.equal(lines[0].after, applySanitisation(GCP_LINE, GCP_ENTRIES));
});

test('a picked pattern does not rewrite inside a JSON key either', () => {
  const pick = entry('user', 'googleapis', 'exampleapi', { via: PICKED_PATTERN_VIA });
  const after = applySanitisation(GCP_LINE, [pick]);
  assert.ok(checkStructurePreserved(GCP_LINE, after).ok);
  assert.match(after, /"serviceName":"compute\.exampleapi\.com"/);
});

test('a value that only ever appears as a key drops out of the plan instead of blocking it', () => {
  const lines = ['{"jdoe":1,"user":"x"}', '{"jdoe":2,"user":"y"}'].join('\n');
  assert.equal(applySanitisation(lines, [entry('user', 'jdoe', 'user01')]), lines);
});

test('non-JSON lines are untouched by the key rule', () => {
  const kv = 'admin=1 user=admin src=compute.googleapis.com';
  assert.equal(applySanitisation(kv, GCP_ENTRIES), 'user01=1 user=user01 src=svc01.example.net');
});
