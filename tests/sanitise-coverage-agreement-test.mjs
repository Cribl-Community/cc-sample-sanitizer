import assert from 'node:assert/strict';
import test from 'node:test';

import {
  planSampleSanitisation,
  applyAndVerifySanitisation,
  SanitisationBlocked,
} from '../src/sanitised-sample-workflow.ts';
import {
  planSanitisation,
  proveIdentityCoverage,
  normaliseFieldValue,
} from '../src/sample-sanitise.ts';

// Detection owns the offer and the Apply-time coverage proof only confirms it. A plan the
// reviewer never touched must therefore always apply: if the proof finds an identity, detection
// should have offered it already. Before this, auditd blocked Apply on `acct "root"` (the proof
// compared the QUOTED value against the never-replace list) and detection offered `0`, `?` and
// `(none)` as identities, which would have rewritten every `exit=0` in the sample.

const auditd = [
  'type=EXECVE msg=audit(1756700000.000:100000000): argc=3 a0="awk" a1="-v" a2="name=lxc0123456789ab"',
  'type=SYSCALL msg=audit(1756700000.000:100000001): arch=c000003e syscall=59 success=yes exit=0 ppid=812 pid=900 auid=1001 uid=0 gid=0 euid=0 tty=(none) ses=4 comm="awk" exe="/usr/bin/gawk" key="exec"',
  'type=USER_ACCT msg=audit(1756700001.000:100000002): pid=1 uid=0 auid=4294967295 ses=4294967295 msg=\'op=PAM:accounting grantors=pam_unix acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success\'',
  'type=USER_LOGIN msg=audit(1756700002.000:100000003): pid=2 uid=0 auid=1001 ses=5 msg=\'op=login acct="jsmith" exe="/usr/sbin/sshd" hostname=web01.corp.local addr=10.20.30.40 terminal=ssh res=success\'',
  'type=USER_AUTH msg=audit(1756700003.000:100000004): pid=3 uid=0 auid=4294967295 ses=4294967295 msg=\'op=PAM:authentication grantors=? acct="(unknown)" exe="/usr/sbin/sshd" hostname=203.0.113.9 addr=203.0.113.9 terminal=ssh res=failed\'',
].join('\n');

test('normaliseFieldValue strips one matching pair of quotes and nothing else', () => {
  assert.equal(normaliseFieldValue(' "root" '), 'root');
  assert.equal(normaliseFieldValue("'jsmith'"), 'jsmith');
  assert.equal(normaliseFieldValue('"half'), '"half');
  assert.equal(normaliseFieldValue('"a" and "b"'), 'a" and "b', 'only the outer pair');
  assert.equal(normaliseFieldValue('plain'), 'plain');
});

test('the proof ignores a quoted never-replace value, as detection does', () => {
  const parsed = [{ acct: '"root"', user: '"nobody"' }];
  const proof = proveIdentityCoverage(parsed, parsed, { sourcetype: 'linux_audit' });
  assert.deepEqual(proof.remaining, []);
});

test('the proof still catches a quoted real identity that did not change', () => {
  const parsed = [{ acct: '"jsmith"' }];
  const proof = proveIdentityCoverage(parsed, parsed, { sourcetype: 'linux_audit' });
  assert.deepEqual(proof.remaining.map(r => r.value), ['jsmith']);
});

for (const st of ['linux_audit', 'linux:audit']) {
  test(`${st}: placeholders and sentinel ids are never offered`, () => {
    const plan = planSampleSanitisation(auditd, st, { seed: 7 });
    const offered = plan.entries.map(e => e.original);
    for (const junk of ['0', '?', '(none)', '(unknown)', '4294967295', 'root']) {
      assert.ok(!offered.includes(junk), `${junk} must not be offered (got ${offered.join(', ')})`);
    }
    for (const real of ['jsmith', 'web01.corp.local', '10.20.30.40']) {
      assert.ok(plan.entries.some(e => e.original === real && e.enabled), `${real} should be offered and ticked`);
    }
  });

  test(`${st}: the untouched plan applies without the reviewer masking anything`, () => {
    const plan = planSampleSanitisation(auditd, st, { seed: 7 });
    const applied = applyAndVerifySanitisation(auditd, st, plan.entries);
    assert.ok(!applied.text.includes('jsmith'));
    assert.ok(applied.text.includes('acct="root"'), 'root is structure and stays');
    assert.ok(applied.text.includes('exit=0'), 'counters are untouched');
  });

  test(`${st}: unticking a real identity still blocks Apply and names it`, () => {
    const plan = planSampleSanitisation(auditd, st, { seed: 7 });
    const entries = plan.entries.map(e => (e.original === 'jsmith' ? { ...e, enabled: false } : e));
    assert.throws(
      () => applyAndVerifySanitisation(auditd, st, entries),
      err => err instanceof SanitisationBlocked
        && err.survivors.some(s => s.field === 'acct' && s.value === 'jsmith'),
    );
  });
}

test('a coverage gap is offered ticked, with the field that exposed it', () => {
  const text = 'login ok acct=jdoe42 from x';
  const plan = planSanitisation(text, { seed: 3, coverageGaps: [{ field: 'acct', value: 'jdoe42' }] });
  const entry = plan.entries.find(e => e.original === 'jdoe42');
  assert.ok(entry, 'gap value must be offered');
  assert.equal(entry.enabled, true);
  assert.match(entry.via, /parsed field “acct”/);
  assert.notEqual(entry.alias, 'jdoe42');
});

test('a coverage gap never resurrects a structural value', () => {
  const plan = planSanitisation('acct=root uid=0', { seed: 3, coverageGaps: [{ field: 'acct', value: 'root' }, { field: 'uid', value: '0' }] });
  assert.deepEqual(plan.entries.map(e => e.original), []);
});

test('the proof leaves alone the IPv6 classes the IPv6 pattern leaves alone', () => {
  const parsed = [{ dest_ip: 'ff02::1:ff77:20d4', src_ip: '2001:db8:e7d:390:64f4:d1b:52aa:5479' }];
  assert.deepEqual(proveIdentityCoverage(parsed, parsed, {}).remaining, []);
  const pub = [{ src_ip: '2a00:1450:4001:82a::200e' }];
  assert.equal(proveIdentityCoverage(pub, pub, {}).remaining.length, 1, 'a public IPv6 still counts');
});

test('the proof skips a local built-in account but not a domain one', () => {
  const local = [{ user: '.\\admin' }];
  assert.deepEqual(proveIdentityCoverage(local, local, {}).remaining, []);
  const domain = [{ user: 'CORP\\admin' }];
  assert.equal(proveIdentityCoverage(domain, domain, {}).remaining.length, 1, 'CORP still names the customer');
});

test('a ticked composite value handed to its parts ticks those parts', () => {
  // `suser` holds a gateway path whose pieces are only unticked shape suspects on their own.
  const lines = [
    'CEF:0|Zscaler|NSSWeblog|5.0|Allowed|None|0| suser=GW01SITE7/ZS_INET3->GW01SITE7 act=Allowed',
    'CEF:0|Zscaler|NSSWeblog|5.0|Allowed|None|0| suser=GW02SITE8/ZS_INET4->GW02SITE8 act=Allowed',
  ].join('\n');
  const plan = planSanitisation(lines, { seed: 5, coverageGaps: [
    { field: 'suser', value: 'GW01SITE7/ZS_INET3->GW01SITE7' },
    { field: 'suser', value: 'GW02SITE8/ZS_INET4->GW02SITE8' },
  ] });
  for (const part of ['GW01SITE7', 'GW02SITE8']) {
    const e = plan.entries.find(x => x.original === part);
    if (e) assert.equal(e.enabled, true, `${part} must be ticked once its whole was`);
  }
  assert.ok(plan.entries.some(e => e.enabled && /GW01SITE7/.test(e.original)), 'the gateway is covered one way or the other');
});
