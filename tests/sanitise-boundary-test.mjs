import assert from 'node:assert/strict';
import test from 'node:test';

import { planSampleSanitisation, applyAndVerifySanitisation } from '../src/sanitised-sample-workflow.ts';
import { applySanitisation, checkStructurePreserved, PICKED_PATTERN_VIA } from '../src/sample-sanitise.ts';

// Values the replacer used to leave in place while the parsed field was masked. Each sample must
// now pass the strict save gate with none of its originals left.
const saves = (sample, sourcetype = 'kvp') => applyAndVerifySanitisation(sample, sourcetype, planSampleSanitisation(sample, sourcetype).entries).text;

test('an IP and an email at the end of a sentence are replaced', () => {
  const out = saves('src=81.2.69.160 email=jsmith@acme.com msg="Failed login from 81.2.69.160. Notified jsmith@acme.com."');
  assert.doesNotMatch(out, /81\.2\.69\.160|jsmith|acme\.com/);
  assert.match(out, /from [\d.]+\. Notified \S+@\S+\."/, 'the full stops stay');
});

test('both ends of an IP range are detected and replaced', () => {
  const out = saves('src=81.2.69.160 msg="range 81.2.69.160-81.2.69.170"');
  assert.doesNotMatch(out, /81\.2\.69\.1[67]0/);
  assert.match(out, /range [\d.]+-[\d.]+"/);
});

test('a name followed by a dash and more text is still not rewritten inside it', () => {
  // `web01` must not turn `web01-backup` into `<alias>-backup`: that is a different device.
  const plan = planSampleSanitisation('host=web01 job=web01-backup', 'kvp');
  const web01 = plan.entries.find(e => e.original === 'web01');
  assert.ok(web01);
  assert.match(applySanitisation('host=web01 job=web01-backup', [web01]), /job=web01-backup/);
});

test('a case variant of a host name is replaced with the same alias', () => {
  const out = saves('host=FW-ACME01 user=jsmith msg="restarted fw-acme01"');
  assert.doesNotMatch(out, /acme01/i);
  const [, alias] = out.match(/host=(\S+)/);
  assert.match(out, new RegExp(`restarted ${alias}"`));
});

test('a URL-encoded email is replaced, account name included, and keeps its %40', () => {
  const out = saves('src=81.2.69.160 url="/login?u=jsmith%40acme.com&x=1"');
  assert.doesNotMatch(out, /jsmith|acme/);
  assert.match(out, /u=\S+%40\S+&x=1/);
});

test('country-code domains are recognised', () => {
  const out = saves('src=81.2.69.160 dst=mail.contoso.com.au peer=vpn01.acme.ch');
  assert.doesNotMatch(out, /contoso|acme|\.au\b|\.ch\b/);
});

test('a JSON key that is exactly an email or IP is replaced; a key that may be schema is kept', () => {
  const line = '{"user":"jsmith@acme.com","quota":{"jsmith@acme.com":5,"81.2.69.160":1},"flags":{"admin":true}}';
  const out = saves(line, 'json');
  assert.doesNotMatch(out, /jsmith|acme|81\.2\.69\.160/);
  const parsed = JSON.parse(out);
  assert.equal(parsed.flags.admin, true, '"admin" is a field name here and must survive');
  assert.deepEqual(Object.values(parsed.quota), [5, 1]);
  assert.equal(Object.keys(parsed.quota)[0], parsed.user, 'the key gets the same alias as the value');
});

test('the structure gate still refuses any other renamed JSON key', () => {
  const check = checkStructurePreserved('{"admin":true,"n":1}', '{"yfoley":true,"n":1}');
  assert.equal(check.ok, false);
  assert.match(check.problems.join(' '), /changed their field names/);
});

test('only caseless kinds match a case variant; a secret or a pick stays case-exact', () => {
  const e = (original, alias, kind, via = 'test') => ({ original, alias, kind, count: 1, via, enabled: true, confidence: 'certain' });
  const out = applySanitisation('a=Tok3nAbC b=tok3nabc c=Goats& d=goats& u=JSMITH', [
    e('Tok3nAbC', 'Xyz9qWeR', 'secret'),
    e('Goats&', 'Sheep&', 'custom', PICKED_PATTERN_VIA),
    e('jsmith', 'yfoley', 'user'),
  ]);
  assert.equal(out, 'a=Xyz9qWeR b=tok3nabc c=Sheep& d=goats& u=yfoley');
});
