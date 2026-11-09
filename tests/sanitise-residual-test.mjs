import assert from 'node:assert/strict';
import test from 'node:test';

import {
  planSampleSanitisation,
  runSanitisation,
  applyAndVerifySanitisation,
  SanitisationBlocked,
} from '../src/sanitised-sample-workflow.ts';
import { findResidualOriginals } from '../src/sample-sanitise.ts';

// The final residual scan: every enabled original that is still anywhere in the sanitised text
// blocks the save. The parse-based coverage proof only sees parsed fields, so a value elsewhere
// in the text that the replacer leaves alone (here: glued to another word) used to pass it.

const entry = (original, alias, kind = 'user', enabled = true) =>
  ({ original, alias, kind, count: 1, via: 'test', enabled, confidence: 'certain' });

test('a value the replacer cannot reach blocks the save even though the parsed field was replaced', () => {
  // `backup-jsmith`: the account name glued to another word is out of the replacer's reach on
  // purpose (it would also rewrite `web01` inside `web01-backup`), so the residual scan catches it.
  const sample = 'src=81.2.69.160 user=jsmith folder=backup-jsmith';
  const plan = planSampleSanitisation(sample, 'kvp');
  const run = runSanitisation(sample, 'kvp', plan.entries, { verify: true });
  assert.equal(run.coverage.ok, true, 'the parse-based proof alone does not see it');
  assert.deepEqual(run.residual.map(r => [r.kind, r.value, r.line]), [['user', 'jsmith', 1]]);
  assert.throws(() => applyAndVerifySanitisation(sample, 'kvp', plan.entries), err => {
    assert.ok(err instanceof SanitisationBlocked);
    assert.match(err.message, /still in the sanitised text at line 1/);
    assert.deepEqual(err.survivors, [{ field: 'user', value: 'jsmith', line: 1 }]);
    return true;
  });
});

test('a fully replaced sample still saves', () => {
  const sample = 'src=81.2.69.160 user=jsmith action=allow\nsrc=81.2.69.161 user=jsmith action=deny';
  const applied = applyAndVerifySanitisation(sample, 'kvp', planSampleSanitisation(sample, 'kvp').entries);
  assert.doesNotMatch(applied.text, /81\.2\.69\.16[01]|jsmith/);
});

test('matching is case-insensitive', () => {
  const hits = findResidualOriginals('host=HOST-A01 note="restarted fw-acme01"', [entry('FW-ACME01', 'HOST-A01', 'host')]);
  assert.deepEqual(hits, [{ kind: 'host', value: 'fw-acme01', line: 1 }]);
});

test('a value inside a longer token is not a hit', () => {
  assert.deepEqual(findResidualOriginals('ip=192.0.2.1 other=10.0.0.15 user=jsmithers', [
    entry('10.0.0.1', '192.0.2.1', 'ipv4'),
    entry('jsmith', 'yfoley'),
  ]), []);
});

test('JSON object keys are not hits — the replacer never rewrites a key', () => {
  const text = '{"user":"yfoley","flags":{"admin":true}}';
  assert.deepEqual(findResidualOriginals(text, [entry('admin', 'yfoley')]), []);
});

test('an alias that contains its own original is not a hit', () => {
  assert.deepEqual(findResidualOriginals('user=jsmith-masked', [entry('jsmith', 'jsmith-masked')]), []);
});

test('an unticked entry is the reviewer\'s choice, not a residual', () => {
  assert.deepEqual(findResidualOriginals('user=jsmith', [entry('jsmith', 'yfoley', 'user', false)]), []);
});

test('line numbers are exact far past the parse cap', () => {
  const lines = Array.from({ length: 5000 }, (_, i) => `n=${i} user=yfoley`);
  lines[4321] = 'n=4321 msg="seen jsmith."';
  const hits = findResidualOriginals(lines.join('\n'), [entry('jsmith', 'yfoley')]);
  assert.deepEqual(hits, [{ kind: 'user', value: 'jsmith', line: 4322 }]);
});
