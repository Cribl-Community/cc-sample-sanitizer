import assert from 'node:assert/strict';
import test from 'node:test';

import {
  planSampleSanitisation,
  runSanitisation,
  applyAndVerifySanitisation,
  resolveSanitiseSourcetype,
} from '../src/sanitised-sample-workflow.ts';
import { dnComponentValues } from '../src/sample-sanitise.ts';

// Check Point's `originsicname` is a certificate DN with backslash-escaped `=`. The parsed-field
// pass used to skip every value containing a backslash (assuming the DOMAIN\user pattern would
// catch it), so the identity was never offered — and then the coverage proof blocked Apply on
// exactly that field. Detection and proof must agree: what the proof demands, detection offers.

const cef = (sic, src, origin) =>
  String.raw`{"_raw":"CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Drop|Log|Unknown|act=Drop cs4Label=TCP Flags cs4=RST deviceDirection=0 rt=1793903105000 spt=64071 dpt=8403 ifname=bond1.62 logid=1 loguid={0x6aecca05,0x348,0xfa260940,0x3fff9c9a} origin=${origin} originsicname=${sic} sequencenum=41 version=5 dst=172.23.16.132 member_id=1_2 product=VPN-1 & FireWall-1 proto=6 src=${src}","_time":1793903109.322,"host":"64.9.38.250"}`;

const sample = [
  cef(String.raw`CN\\=SG_INFRA,O\\=cvoceanport..an3ujc`, '172.16.76.76', '64.9.38.247'),
  cef(String.raw`CN\\=SG_PROD,O\\=cvoceanport..an3ujc`, '172.16.182.71', '64.9.38.247'),
  cef(String.raw`CN\\=SG-ENG,O\\=cvoceanport..an3ujc`, '172.202.64.10', '64.9.38.247'),
  // The gateway name reused as the prefix of its policy layer name.
  cef(String.raw`CN\\=SG-ENG,O\\=cvoceanport..an3ujc`, '172.202.64.11', '64.9.38.251')
    .replace('act=Drop', 'act=Drop cs2Label=Rule Name cs2=CPNotEnoughDataForRuleMatch layer_name=SG-ENG-simplified Network layer_name=Application'),
  cef(String.raw`CN\\=CVDR4,O\\=cvoceanport..an3ujc`, '172.16.1.9', '64.9.38.248'),
].join('\n');

const originals = ['SG_INFRA', 'SG_PROD', 'SG-ENG', 'CVDR4', 'cvoceanport..an3ujc'];

test('dnComponentValues reads escaped and plain distinguished names, and nothing else', () => {
  assert.deepEqual(dnComponentValues(String.raw`CN\\=SG_INFRA,O\\=cvoceanport..an3ujc`), ['SG_INFRA', 'cvoceanport..an3ujc']);
  assert.deepEqual(dnComponentValues(String.raw`CN\=gw01,O\=corp`), ['gw01', 'corp']);
  assert.deepEqual(dnComponentValues('CN=gw01, OU=net, O=corp'), ['gw01', 'net', 'corp']);
  assert.equal(dnComponentValues(String.raw`CORP\jsmith`), null);
  assert.equal(dnComponentValues('key=value'), null, 'a single pair is not a DN');
});

for (const st of ['checkpoint', 'cef']) {
  test(`every originsicname component is offered and replaced (${st})`, () => {
    const plan = planSampleSanitisation(sample, st);
    const offered = new Set(plan.entries.filter(e => e.enabled).map(e => e.original));
    for (const o of originals) assert.ok(offered.has(o), `${o} offered`);
    assert.ok(!offered.has('CN') && !offered.has('O'), 'DN labels stay');

    const run = runSanitisation(sample, st, plan.entries, { verify: true });
    assert.equal(run.coverage.ok, true, JSON.stringify(run.coverage.remaining));
    assert.deepEqual(run.residual, []);
    assert.equal(run.structure.ok, true, JSON.stringify(run.structure));
    for (const o of originals) assert.ok(!run.text.includes(o), `${o} gone`);
    assert.match(run.text, /layer_name=[^ ]+-simplified Network/, 'layer name suffix kept');
    assert.match(run.text, /originsicname=CN\\\\=[^,]+,O\\\\=\S+ /, 'DN shape and escaping survive');
    assert.doesNotThrow(() => applyAndVerifySanitisation(sample, st, plan.entries));
  });
}

test('the sourcetype the Source step resolves also passes', () => {
  const { sourcetype: st } = resolveSanitiseSourcetype(sample);
  const plan = planSampleSanitisation(sample, st);
  assert.doesNotThrow(() => applyAndVerifySanitisation(sample, st, plan.entries), `sourcetype ${st}`);
});

test('DOMAIN\\user values are still left to the DOMAIN\\user pattern', () => {
  const s = String.raw`{"_raw":"user=CORP\\jsmith src=10.1.2.3 msg=ok"}`;
  const plan = planSampleSanitisation(s, 'kvp');
  const kinds = Object.fromEntries(plan.entries.map(e => [e.original, e.kind]));
  assert.equal(kinds.CORP, 'host');
  assert.equal(kinds.jsmith, 'user');
  assert.ok(!(String.raw`CORP\\jsmith` in kinds), 'the whole value is not added');
});

test('a plain word entry is still not rewritten inside a hyphenated token', () => {
  const s = 'host=web01 msg=failover to web01-backup';
  const plan = planSampleSanitisation(s, 'kvp');
  const run = runSanitisation(s, 'kvp', plan.entries.map(e => e.original === 'web01' ? e : { ...e, enabled: false }));
  assert.match(run.text, /web01-backup/);
});
