/**
 * Sanitising has to stay usable on a real sample, not just a demo one.
 *
 * The review list was built when a sample meant a dozen events with a handful of repeated
 * hostnames. A real log is not that: businessevent.log carries a distinct account number,
 * handset serial, mobile number and card number on EVERY line, so entry count grows with
 * the sample rather than settling. At 5,000 events that was 26,000 entries, and both the
 * counting pass and the replacement did one full scan of the text per entry — quadratic,
 * 77 seconds of blocked main thread, and 26,000 rows of checkboxes nobody can read.
 *
 * These tests pin the two properties that fixes: the work is linear in the sample, and every
 * entry is reachable in the review list through exactly one collapsed group.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { planSanitisation, applySanitisation, markSanitisation, PICKED_FIELD_VIA, setSecretRules } from '../src/sample-sanitise.ts';
import { filterSecretRules } from '../src/secret-rule-filter.ts';
import { SANITISE_GROUPS, SANITISE_ROW_CAP, groupOf, groupEntries } from '../src/sanitise-groups.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = p => readFileSync(join(root, p), 'utf-8');

/* The secret rules are pushed into the sanitiser, so the module starts with none. Install the
   bundled public-source baseline — the same library the app installs at startup — because these
   tests measure the cost and the coverage of a FULL detection pass; running them against an empty
   rule set would understate both. */
setSecretRules(filterSecretRules(JSON.parse(read('config/bundled-secret-rules.json')).items).rules);

/** businessevent.log in miniature: every field distinct per event, which is the hard case. */
const corpus = n => Array.from({ length: n }, (_, i) =>
  `2020-02-11 13:04:17,753},Event [Event=UpdateBillingProvQuote, timestamp=158142${i}, `
  + `properties={orderType=ChangeESN, esn=3852D7E1E1${String(i % 10000).padStart(4, '0')}, `
  + `accountNumber=9000${String(i % 100000).padStart(5, '0')}, social=51714${String(i % 10000).padStart(4, '0')}, `
  + `userName=user${i}, mdn=65460${String(i % 100000).padStart(5, '0')}, marketCity="MACON", `
  + `marketZip=${31294 + (i % 500)}, cardNumber=60113579814${String(i % 10000).padStart(4, '0')}, `
  + `host=web${i % 50}.corp.local, src=10.2.${i % 255}.${(i * 7) % 255}]`).join('\n');

// ---------------------------------------------------------------------------
// Linear, not quadratic
// ---------------------------------------------------------------------------

test('planning and applying scale with the sample rather than with its square', () => {
  const time = (n) => {
    const text = corpus(n);
    const t0 = performance.now();
    const plan = planSanitisation(text, { seed: 1 });
    const t1 = performance.now();
    const out = applySanitisation(text, plan.entries);
    const t2 = performance.now();
    return { plan: t1 - t0, apply: t2 - t1, entries: plan.entries.length, out, text };
  };

  const small = time(250);
  const large = time(2000);   // 8× the events

  // Entry count really does grow with the sample: that is what made the old shape quadratic.
  assert.ok(large.entries > small.entries * 5,
    `entries must scale with the sample for this test to mean anything (${small.entries} → ${large.entries})`);

  /* Generous, because a CI box is noisy and this is a complexity assertion rather than a
     benchmark. Quadratic would be ~64× for 8× the input; anything under 25× cannot be. */
  const ratio = (large.plan + large.apply) / Math.max(small.plan + small.apply, 1);
  assert.ok(ratio < 25,
    `8× the events took ${ratio.toFixed(1)}× the time — that is not linear `
    + `(${(small.plan + small.apply).toFixed(0)}ms → ${(large.plan + large.apply).toFixed(0)}ms)`);

  // And an absolute ceiling, since "linear" is no comfort if the constant is a minute.
  assert.ok(large.plan + large.apply < 8000,
    `2,000 events took ${(large.plan + large.apply).toFixed(0)}ms, which blocks the UI`);
});

test('one combined pass replaces exactly what one pass per entry did', () => {
  /* Compared against the implementation it replaced, rather than against a property.
     Checking `!out.includes(original)` looks equivalent and is not: these aliases are random
     digits, so a scrambled account number quite happily contains some other row's postcode
     by chance, and the test fails on arithmetic rather than on a bug. */
  const sequential = (text, entries) => {
    const escape = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    let out = text;
    for (const e of entries) {
      if (!e.enabled || !e.alias || e.alias === e.original) continue;
      out = out.replace(new RegExp(`(?<![\\w.$-])${escape(e.original)}(?![\\w.$-])`, 'g'), () => e.alias);
    }
    return out;
  };

  for (const n of [1, 12, 60]) {
    const text = corpus(n);
    const plan = planSanitisation(text, { seed: 5 });
    assert.equal(applySanitisation(text, plan.entries), sequential(text, plan.entries),
      `combined and sequential replacement disagree at ${n} events`);
  }

  const text = corpus(60);
  const plan = planSanitisation(text, { seed: 5 });
  const out = applySanitisation(text, plan.entries);
  assert.equal(out.split('\n').length, text.split('\n').length, 'line count intact');
  assert.equal((out.match(/=/g) || []).length, (text.match(/=/g) || []).length, 'delimiters intact');
});

test('an unticked row still does not shelter the ticked rows inside it', () => {
  /* The subtlety a single pass could have lost. Unticked rows do not consume text, so a
     ticked value nested inside one has to keep firing — otherwise leaving a suggestion
     unticked would quietly protect an identity underneath it. */
  const text = [
    'from=mbrennan@acme-corp.com host=acme-corp.com',
    'from=mbrennan@acme-corp.com host=acme-corp.com',
  ].join('\n');
  const plan = planSanitisation(text, { seed: 2 });
  const email = plan.entries.find(e => e.original.includes('@'));
  const inner = plan.entries.find(e => e.original === 'acme-corp.com');
  if (!email || !inner) return;   // tiers changed; the nesting case is covered elsewhere

  email.enabled = false;
  const out = applySanitisation(text, plan.entries);
  assert.ok(!out.includes('host=acme-corp.com'), 'the ticked domain is still replaced');
  assert.ok(out.includes('mbrennan@'), 'and the unticked email is still left alone');
});

// ---------------------------------------------------------------------------
// The review list has to stay readable, and lose nothing
// ---------------------------------------------------------------------------

test('every kind of finding lands in exactly one group, including kinds not invented yet', () => {
  /* The failure this prevents is silent. Adding a kind — `pii` was added in build 482 —
     with no group to hold it would drop those rows out of the review list while they carried
     on being replaced, which is the worst of both. `a_kind_we_have_not_written_yet` stands in
     for the next one. */
  const kinds = ['ipv4', 'ipv6', 'fqdn', 'host', 'user', 'email', 'mac', 'custom', 'secret',
    'pii', 'a_kind_we_have_not_written_yet'];
  for (const kind of kinds) {
    for (const confidence of ['certain', 'suspect']) {
      const entry = { kind, confidence, original: 'x', alias: 'y', count: 1, via: 't', enabled: true };
      assert.ok(groupOf(entry), `${kind}/${confidence} reaches a group`);
      assert.equal(groupEntries([entry]).length, 1, `${kind}/${confidence} is rendered once, not twice`);
    }
  }

  /* A credential stays a credential even if some future tier marks it a guess. It must never
     be filed under "suggestions", where unticked is the default. Spelled out in full because
     grouping reads `via` as well as `kind` now, and a half-built entry is not an entry. */
  const partial = { original: 'x', alias: 'y', count: 1, via: 't', enabled: true };
  assert.equal(groupOf({ ...partial, kind: 'secret', confidence: 'suspect' }).id, 'secret');
  assert.equal(groupOf({ ...partial, kind: 'pii', confidence: 'suspect' }).id, 'pii');

  /* Picked-by-field rows are grouped by WHY they exist rather than by kind, so they need
     their own line here: they are minted as `pii` for the alias shape, and would otherwise
     be indistinguishable from a handset serial the tool found on its own. */
  const picked = { ...partial, kind: 'pii', confidence: 'certain', via: `${PICKED_FIELD_VIA} “quoteNumber”` };
  assert.equal(groupOf(picked).id, 'picked');
});

test('a real plan is fully covered by the groups, with the credentials first', () => {
  const plan = planSanitisation(corpus(40), { seed: 4 });
  const grouped = groupEntries(plan.entries);
  const counted = grouped.reduce((n, g) => n + g.rows.length, 0);
  assert.equal(counted, plan.entries.length, 'no entry is dropped or double-counted');
  assert.ok(grouped.length >= 3, 'and a real sample really does spread across several groups');

  assert.equal(SANITISE_GROUPS[0].id, 'secret', 'credentials lead');
  assert.equal(SANITISE_GROUPS[SANITISE_GROUPS.length - 1].id, 'suspect', 'and guesses come last');
  for (const g of SANITISE_GROUPS) {
    assert.equal(typeof g.label(1), 'string');
    assert.notEqual(g.label(1), g.label(2), `“${g.id}” reads correctly for one and for many`);
    assert.ok(g.note(2, plan).length > 20, `“${g.id}” says what was done and why`);
  }
});

test('the panel folds the groups shut and caps what it draws', () => {
  /* `includes` rather than `assert.match`: the wizard file is large, and a regex assertion
     that fails prints the whole file into the test output. The panel lives in the
     SanitizeWizard now (the new-pack step opens it as a modal). */
  const src = read('src/sanitize-wizard.tsx');
  const has = (needle, why) => assert.ok(src.includes(needle), `${why} (looked for: ${needle})`);

  has('groupEntries(plan.entries)', 'the panel renders from the shared group list');
  has('openGroups[group.id] ?? false', 'every group is shut until asked for, credentials included');
  has('slice(0, SANITISE_ROW_CAP)', 'and never draws an unbounded list');
  has('{isOpen && (', 'rows are mounted only when the group is open, not merely hidden');
  has('setGroup(originals, true)', 'a whole group can be ticked at once');
  assert.ok(SANITISE_ROW_CAP >= 50 && SANITISE_ROW_CAP <= 500, 'the cap is a sane size');
});

// ---------------------------------------------------------------------------
// Showing the reviewer what is covered
//
// The panel used to list findings below a box of raw sample text, so the only way to answer
// "is that card number handled?" was to read the value out of the sample and hunt for it in
// the list. Looking at `cardNumber=6011357981409475` sitting there unmarked and concluding
// nothing had been done to it was the reasonable inference, and it was wrong.
// ---------------------------------------------------------------------------

test('every marked span is exactly what the apply step will change', () => {
  /* The property that makes highlighting worth having. A mark drawn by a second opinion
     about what looks sensitive would eventually disagree with the apply step, and a
     highlight that disagrees is worse than none — it tells the reviewer a card number is
     handled when it is not. */
  const text = corpus(20);
  const plan = planSanitisation(text, { seed: 8 });
  const spans = markSanitisation(text, plan.entries);
  assert.ok(spans.length > 50, 'a real sample marks a lot of the line');

  for (const s of spans) {
    const slice = text.slice(s.start, s.end);
    if (s.entry.patchSpans?.length) {
      assert.ok(s.entry.original.includes(slice),
        'a pattern span covers a changed part of the token its row applies');
    } else {
      assert.equal(slice, s.entry.original,
        'a span covers precisely the value its row is about');
    }
  }
  // Non-overlapping and in order, or the rendered layer would double-print the text.
  for (let i = 1; i < spans.length; i++) {
    assert.ok(spans[i].start >= spans[i - 1].end, 'spans do not overlap');
  }

  // Rebuilding the text from the spans returns the original, byte for byte.
  let rebuilt = '', at = 0;
  for (const s of spans) { rebuilt += text.slice(at, s.start) + text.slice(s.start, s.end); at = s.end; }
  rebuilt += text.slice(at);
  assert.equal(rebuilt, text, 'the marked layer renders the sample unchanged');

  /* And the coverage is the same set the apply step acts on: everything ticked is marked,
     so nothing is quietly replaced without having been shown. */
  const marked = new Set(spans.filter(s => s.entry.enabled).map(s => s.entry.original));
  for (const e of plan.entries) {
    if (e.enabled && e.count > 0) assert.ok(marked.has(e.original), `${e.original} is replaced, so it must be marked`);
  }
});

test('a found-but-unticked value is marked as staying, not as going', () => {
  const text = ['host=fw-edge-01 user=jsmith src=10.2.14.77', 'host=fw-edge-02 user=jsmith src=10.2.14.78'].join('\n');
  const plan = planSanitisation(text, { seed: 9 });
  const victim = plan.entries.find(e => e.enabled);
  assert.ok(victim, 'something was found');
  victim.enabled = false;

  const spans = markSanitisation(text, plan.entries);
  const off = spans.filter(s => s.entry.original === victim.original);
  assert.ok(off.length, 'it is still shown — the reviewer needs to see it was found');
  assert.ok(off.every(s => !s.entry.enabled), 'and shown as unticked, so it reads as staying put');
  assert.ok(applySanitisation(text, plan.entries).includes(victim.original), 'and it does stay put');
});

test('the KV spellings a business event actually uses are all covered', () => {
  /* Written from the real miss. businessevent.log names things `cardNumber`, `social`,
     `esn` and `mdn`; the next log will name them something adjacent, and the field name is
     now the primary evidence, so the spellings are the coverage. */
  const cases = [
    ['cardNumber', '4111111111111111'], ['card_number', '4111111111111111'], ['ccNum', '4111111111111111'],
    ['pan', '4111111111111111'], ['primaryAccountNumber', '4111111111111111'],
    ['social', '517140087'], ['SSN', '517140087'], ['social_security_number', '517140087'],
    ['taxId', '517140087'], ['tin', '517140087'],
    ['esn', '3852D7E1E168F3'], ['imei', '3852D7E1E168F3'], ['serialNumber', '3852D7E1E168F3'],
    ['marketZip', '31294'], ['postalCode', '31294'], ['city', 'MACON'], ['address', 'MACON'],
    ['dob', '1984-03-11'], ['birthDate', '1984-03-11'],
  ];
  for (const [key, value] of cases) {
    const line = `orderType=ChangeESN, ${key}=${value}, planCode=900POST60`;
    const plan = planSanitisation(line, { seed: 1 });
    const out = applySanitisation(line, plan.entries.filter(e => e.enabled));
    assert.ok(!out.includes(value), `${key}=${value} was left in the sample`);
    assert.ok(out.includes('planCode=900POST60'), `${key}: the vocabulary either side is untouched`);
  }
});

test('an address field is read by its value, not by one fixed meaning', () => {
  /* `address` is a street as readily as it is a host, and the schema vocabulary only knows
     the network sense — which is right for most of this corpus and wrong for a billing log. */
  const net = planSanitisation('address=192.168.1.5 port=443', { seed: 1 });
  assert.equal(net.entries.find(e => e.original === '192.168.1.5')?.kind, 'ipv4',
    'an address that is an address stays an address');

  const postal = planSanitisation('address=MACON, planCode=900POST60', { seed: 1 });
  assert.equal(postal.entries.find(e => e.original === 'MACON')?.kind, 'pii',
    'and one that is a place is personal data');
});

test('the panel shows events before and after, both built from the same replacer', () => {
  const src = read('src/sanitize-wizard.tsx');
  const has = (needle, why) => assert.ok(src.includes(needle), `${why} (looked for: ${needle})`);
  // The after is the sanitised result of the SAME lines, built from the same replacer as Apply,
  // and always rendered (all lines, unchanged included) so it can never quietly disappear.
  has('previewSanitisation(raw, active.entries, PREVIEW_LINE_CAP, true, activeProvisional?.tryKeys, badKeys)',
    'the after view is the always-on, line-capped build from the shared replacer');
  has('className="sanitise-beforeafter"', 'events are laid out before and after, side by side');
  has('className="sanitise-sample sanitise-after"', 'the after column renders the sanitised result');
  has('renderPreviewSpans(line.after, line.afterSpans', 'and the changed spans are highlighted in the after');
  // The removed dual-layer overlay and its scroll-sync machinery must be gone.
  assert.ok(!src.includes('sanitise-sample-marks'), 'no stacked marks layer remains');
  assert.ok(!src.includes('sanitise-sample-over'), 'no transparent-glyph overlay remains');
  assert.ok(!src.includes('new ResizeObserver(fit)'), 'no content-grow observer is needed for a single native-scroll pane');
});

test('both before/after columns wrap in the frame instead of scrolling sideways', () => {
  const css = read('src/App.css');
  const base = css.slice(css.indexOf('.sanitise-sample {'), css.indexOf('.sanitise-sample::selection'));

  /* An event here is one 1,100-character line. Read through a horizontal scrollbar it shows
     about twenty characters at a time, which is why a masked card number was never found on
     screen. Both columns share the .sanitise-sample base, which must wrap. */
  assert.ok(base.includes('white-space: pre-wrap'), 'the sample base wraps');
  assert.ok(!base.includes('overflow-x: auto'), 'rather than scrolling sideways');
  assert.ok(base.includes('overflow-wrap: break-word'), 'including the very long unbroken runs');
  for (const metric of ['font-family', 'font-size', 'line-height', 'white-space', 'overflow-wrap']) {
    assert.ok(base.includes(`${metric}:`), `${metric} is on the shared .sanitise-sample base, so both columns wrap identically`);
  }
  // The after column preserves internal whitespace per line so positional parsers read alike.
  const after = css.slice(css.indexOf('.sanitise-after-line'), css.indexOf('.sanitise-after-line') + 160);
  assert.ok(after.includes('white-space: pre-wrap'), 'each after line preserves its own whitespace');
});

test('typing in the literals box does not replan on every keystroke', () => {
  const src = read('src/sanitize-wizard.tsx');
  const textarea = src.slice(src.indexOf('className="sanitise-extra"'), src.indexOf('className="sanitise-extra"') + 400);
  assert.ok(textarea.includes('onChange={event => replanFromText'),
    'planning a large sample per character is a second of frozen UI between letters');
  assert.ok(src.includes('window.clearTimeout(replanTimer.current)'), 'and the timer is cleaned up');
});
