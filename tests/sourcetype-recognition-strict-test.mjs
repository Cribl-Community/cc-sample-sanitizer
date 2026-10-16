import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  recognizeSourcetype,
  isKnownSourcetype,
  isKnownSourcetypeStrict,
  getParserFieldNames,
} from '../src/source-recognition.ts';

// Regression: a misspelled / suffix-extended sourcetype (cisco_asaa) used to be
// classified 'exact' on its OWN name because getParserFieldNames fell through to
// a LENIENT substring datatype match (`cisco_asaa`.includes(`cisco_asa`) →
// cisco_asa_syslog parser → non-empty fields → isKnownSourcetype true). The demo
// generator then accepted the typo and synthesised a sample instead of using the
// real cisco_asa (which has a golden path + a real sample).

test('a near-miss sourcetype is NOT recognized as exact on its own name', () => {
  const r = recognizeSourcetype('cisco_asaa');
  assert.notEqual(r.status, 'exact', 'cisco_asaa must not be exact');
  assert.notEqual(r.canonical, 'cisco_asaa', 'canonical must not be the typo itself');
});

test('a distance-1 typo is corrected to the real registered source', () => {
  const r = recognizeSourcetype('cisco_asaa');
  assert.equal(r.tier, 'fuzzy');
  assert.equal(r.confidence, 'high');
  assert.equal(r.canonical, 'cisco_asa');
  assert.equal(r.suggestion, 'cisco_asa');
});

test('the same failure mode is fixed for other substring-matched vendors', () => {
  // fortinet_fortigateeee substring-matched fortinet_fortigate_syslog_wrapped and
  // was wrongly 'exact'. It is now not-exact (too far a miss to auto-correct → it
  // falls to unresolved, which BLOCKS and asks the user rather than synthesising).
  const r = recognizeSourcetype('fortinet_fortigateeee');
  assert.notEqual(r.status, 'exact');
  assert.notEqual(r.status, 'alias');
});

test('genuinely-registered names stay exact — no regression', () => {
  for (const name of ['cisco_asa', 'cisco:asa', 'cisco_asa_syslog', 'windows_sysmon',
    'fortinet_fortigate', 'aws_cloudtrail', 'sap_audit', 'salesforce_setupaudittrail']) {
    assert.equal(recognizeSourcetype(name).status, 'exact', `${name} must remain exact`);
  }
});

test('isKnownSourcetypeStrict rejects a substring-only match but keeps real ones', () => {
  assert.equal(isKnownSourcetypeStrict('cisco_asaa'), false);
  assert.equal(isKnownSourcetypeStrict('fortinet_fortigateeee'), false);
  assert.equal(isKnownSourcetypeStrict('cisco_asa'), true);
  assert.equal(isKnownSourcetypeStrict('cisco:asa'), true);
  assert.equal(isKnownSourcetypeStrict('cisco_asa_syslog'), true);
  assert.equal(isKnownSourcetypeStrict('windows_sysmon'), true);
});

test('the BUILD path stays lenient — strictness is recognition-only', () => {
  // getParserFieldNames (loose default) still resolves a substring match so a
  // pipeline can build if a name somehow reaches it; only the recognizer is strict.
  assert.ok(getParserFieldNames('cisco_asaa').length > 0, 'loose build lookup unchanged');
  assert.equal(getParserFieldNames('cisco_asaa', { strictDatatype: true }).length, 0,
    'strict lookup refuses the substring match');
  // And isKnownSourcetype (loose, used by build-path callers) is unchanged.
  assert.equal(isKnownSourcetype('cisco_asaa'), true);
});
