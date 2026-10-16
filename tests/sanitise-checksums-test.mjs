/**
 * Checksum-proven values and login-message usernames (build 815).
 *
 * Found in a side-by-side with the LogTotal Stream sanitizer: our sample sanitiser left a
 * card number with no "card" keyword beside it, a bare IBAN, international phone numbers,
 * the user in sshd's "Accepted publickey for jdoe from", and a Windows XML TargetUserName
 * when no parser had matched. These tests fail if:
 *   1. a Luhn-valid card with a real issuer prefix, or a mod-97-valid IBAN, is left in place;
 *   2. a number that fails either check (an id, an epoch timestamp) is rewritten;
 *   3. a timezone offset or an unformatted counter is taken for a phone number;
 *   4. a username in fixed login wording is missed, or ordinary prose is taken for one;
 *   5. the XML leaf pass breaks the XML it reads.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  luhnValid, cardIssuerMatches, findCardNumbers, ibanValid, findIbans, findPhoneNumbers,
} from '../src/sanitise-checksums.ts';
import {
  planSanitisation, applySanitisation, structuralFields, checkStructurePreserved,
} from '../src/sample-sanitise.ts';

const sanitise = text => {
  const plan = planSanitisation(text, { seed: 7 });
  return { plan, out: applySanitisation(text, plan.entries) };
};
const users = plan => plan.entries.filter(e => e.kind === 'user').map(e => e.original);

test('a card number is an issuer prefix at its length with a valid Luhn digit', () => {
  assert.ok(luhnValid('4111111111111111') && cardIssuerMatches('4111111111111111'));
  assert.ok(!luhnValid('4111111111111112'), 'one digit off fails the checksum');
  assert.ok(luhnValid('1234567812345670') && !cardIssuerMatches('1234567812345670'),
    'passing Luhn is not enough: nothing is issued under 1');
  assert.deepEqual(findCardNumbers('pan 4111 1111 1111 1111 amex 3782-822463-10005 ok'),
    ['4111 1111 1111 1111', '3782-822463-10005'], 'printed forms are found as written');
  assert.deepEqual(findCardNumbers('ts=1727600000000 seq=41111111111111110 v=4111111111111111.5'), [],
    'not an epoch ms, not a longer run, not inside a decimal');
  assert.deepEqual(findCardNumbers('4111-1111 1111-1111'), [], 'separators must be consistent');
  // Real CrowdStrike ids from the shipped corpus, each Luhn-valid under a card prefix.
  assert.deepEqual(findCardNumbers('ParentProcessId=4493251989128 x 4232575157917097360 y 380464698635444223'), [],
    'EDR process ids at the lengths cards are rarely issued at');
  assert.deepEqual(findCardNumbers('"TargetProcessId":"4111111111111111"'), [], 'an id field holds an id');
});

test('an IBAN is the country length plus a mod-97 checksum', () => {
  assert.ok(ibanValid('NL91ABNA0417164300'));
  assert.ok(ibanValid('GB82 WEST 1234 5698 7654 32'));
  assert.ok(!ibanValid('NL91ABNA0417164301'), 'a changed digit fails mod-97');
  assert.ok(!ibanValid('NL91ABNA04171643000'), 'the wrong length for NL fails before the checksum');
  assert.deepEqual(findIbans('to GB82 WEST 1234 5698 7654 32 OK'), ['GB82 WEST 1234 5698 7654 32'],
    'an uppercase word after a grouped IBAN is not swallowed');
  assert.deepEqual(findIbans('build AB12CDEFGHIJKLMNOP id XY00123456789012'), [], 'IBAN-shaped is not an IBAN');
});

test('a phone number is international, and a timezone or a bare counter is not one', () => {
  assert.deepEqual(findPhoneNumbers('sms to +31 6 12345678 ok; call +1 (415) 555-0132.'),
    ['+31 6 12345678', '+1 (415) 555-0132'], 'the full stop after it is not part of it');
  assert.deepEqual(findPhoneNumbers('callback +1-415-555-0132 22'), ['+1-415-555-0132'],
    'a space-separated number after a dashed phone is the next field');
  assert.deepEqual(findPhoneNumbers('10:00:00 +1000 1727600000 rtt=+0200'), [], 'timezone offsets');
  assert.deepEqual(findPhoneNumbers('delta=+12345678 bytes'), [], 'no separators and no keyword');
  assert.deepEqual(findPhoneNumbers('msisdn=+31612345678'), ['+31612345678'], 'no separators but a keyword');
});

test('the planner replaces them, keeping each one\'s shape', () => {
  const line = 'txn ok ref=5500005555555559 payout NL91ABNA0417164300 notify +44 20 7946 0958 id=1234567890123456';
  const { plan, out } = sanitise(line);
  for (const v of ['5500005555555559', 'NL91ABNA0417164300', '+44 20 7946 0958']) {
    assert.ok(!out.includes(v), `${v} is replaced`);
  }
  assert.ok(out.includes('id=1234567890123456'), 'an id that is no card stays');
  assert.equal(plan.entries.find(e => e.original === '5500005555555559').kind, 'secret');
  assert.equal(plan.entries.find(e => e.original === 'NL91ABNA0417164300').kind, 'pii');
  assert.match(out, /notify \+\d\d \d\d \d{4} \d{4} /, 'the phone keeps its grouping');
  assert.ok(checkStructurePreserved(line, out).ok);
});

test('usernames in fixed login wording are found, prose is not', () => {
  const sample = [
    'Sep 29 10:01:02 auth66 sshd[4212]: Accepted publickey for jdoe from 10.4.4.4 port 51122 ssh2',
    'Sep 29 10:01:03 auth66 sshd[4213]: Failed password for invalid user mkowalski from 10.4.4.5 port 22 ssh2',
    'Sep 29 10:01:04 auth66 sshd[4214]: Invalid user a.smith from 10.4.4.6 port 22',
    'Sep 29 10:01:05 auth66 sshd[4215]: pam_unix(sshd:session): session opened for user bwayne(uid=1001) by (uid=0)',
    'Sep 29 10:01:06 auth66 sudo:   ckent : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/ls',
    'Sep 29 10:01:07 auth66 sshd[4216]: Failed password for root from 10.4.4.7 port 22 ssh2',
    'Sep 29 10:01:08 auth66 app[1]: waiting for connection from 10.4.4.8',
    'Sep 29 10:01:09 auth66 sshd[4217]: Disconnected from user pparker 10.4.4.9 port 22',
    'Sep 29 10:01:10 auth66 app[2]: this detection extracts words from user agents to build a baseline',
  ].join('\n');
  const { plan, out } = sanitise(sample);
  const found = users(plan);
  for (const u of ['jdoe', 'mkowalski', 'a.smith', 'bwayne', 'ckent', 'pparker']) {
    assert.ok(found.includes(u), `${u} is a user`);
    assert.ok(!new RegExp(`\\b${u.replace('.', '\\.')}\\b`).test(out), `${u} is gone from the output`);
  }
  assert.ok(!found.includes('root'), 'a well-known account is structure, not an identity');
  assert.ok(!found.includes('connection'), '"for connection from" is prose');
  assert.ok(!found.includes('agents'), '"from user agents" is prose');
  assert.ok(out.includes('Accepted publickey for '), 'the wording around the name survives');
});

test('Windows text rendering: Account Name', () => {
  const { plan } = sanitise('An account was successfully logged on.\tAccount Name:\t\tmkowalski\tAccount Domain:\t\tACME');
  assert.ok(users(plan).includes('mkowalski'));
});

test('XML leaf elements are fields even when no parser matched, and the XML survives', () => {
  const xml = '<Event><System><Computer>WS-0042.corp.acme.com</Computer></System><EventData>'
    + '<Data Name="TargetUserName">mkowalski</Data><Data Name="SubjectUserName">-</Data>'
    + '<Data Name="LogonType">3</Data></EventData></Event>';
  assert.deepEqual(structuralFields([xml])[0],
    { Computer: 'WS-0042.corp.acme.com', TargetUserName: 'mkowalski', SubjectUserName: '-', LogonType: '3' });
  const { out } = sanitise(xml);
  assert.ok(!out.includes('mkowalski'), 'TargetUserName is replaced');
  assert.ok(out.includes('<Data Name="SubjectUserName">-</Data>'), 'a placeholder stays');
  assert.ok(out.includes('<Data Name="LogonType">3</Data>'), 'a number that is no identity stays');
  const tags = s => s.match(/<\/?[A-Za-z][^>]*>/g).map(t => t.replace(/"[^"]*"/g, '""')).join('');
  assert.equal(tags(out), tags(xml), 'every tag and attribute name is unchanged');
});
