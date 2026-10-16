/**
 * The sanitiser shows events before and after, side by side: the left column is the real
 * textarea the reviewer selects in, the right column is the sanitised result of the same
 * lines, always rendered. There is no longer a stacked marks overlay to keep aligned — the
 * after is its own independent render — so the one layout property still worth proving in a
 * real browser is that neither column scrolls SIDEWAYS. A 1,100-character business event left
 * to scroll horizontally shows about twenty characters at a time, which is exactly how a
 * masked value stays invisible off the right edge and the reviewer concludes nothing was done
 * to it. Both columns must wrap long lines into their frame instead.
 *
 * The sibling suite greps the stylesheet; this renders the real markup with the real
 * stylesheet in a real browser and asks the browser what it measured, because wrapping
 * depends on things CSS text cannot show: how the browser breaks a very long line and whether
 * a scrollbar appeared.
 *
 * Chrome is not a dependency of this project, so this skips when it is absent rather than
 * failing. Set CHROME to point at a binary elsewhere.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { planSanitisation, previewSanitisation } from '../src/sample-sanitise.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const CHROME = [
  process.env.CHROME,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
].find(p => p && existsSync(p));

/* businessevent.log in miniature. The long unbroken line is the point: it is what forces the
   wrapping that this test exists to check. */
const corpus = n => Array.from({ length: n }, (_, i) =>
  `2020-02-11 13:04:17,753},Event [Event=UpdateBillingProvQuote, timestamp=158142${i}, `
  + `properties={JMSCorrelationID=NA, orderType=ChangeESN, quotePriority=NORMAL, `
  + `esn=3852D7E1E1${String(i % 10000).padStart(4, '0')}, `
  + `accountNumber=9000${String(i % 100000).padStart(5, '0')}, social=51714${String(i % 10000).padStart(4, '0')}, `
  + `userName=user${i}, mdn=65460${String(i % 100000).padStart(5, '0')}, marketCity="MACON", `
  + `marketState=GA, marketZip=${31294 + (i % 500)}, planName="900 Minute", `
  + `cardNumber=60113579814${String(i % 10000).padStart(4, '0')}, `
  + `host=web${i % 50}.corp.local, src=10.2.${i % 255}.${(i * 7) % 255}]`).join('\n');

const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** The same before/after markup App.tsx renders, with the project's own stylesheet. */
function page(text, entries) {
  const preview = previewSanitisation(text, entries, 200, true);
  const afterLines = preview.lines
    .map(l => `<div class="sanitise-after-line">${esc(l.after) || '&nbsp;'}</div>`)
    .join('');

  const css = readFileSync(join(root, 'src/App.css'), 'utf-8');
  const block = css.slice(css.indexOf('.sanitise-rows {'), css.indexOf('.btn-small {'));

  return { preview, html: `<!doctype html><meta charset="utf-8">
<style>body { font-family: -apple-system, system-ui, sans-serif; margin: 20px; }
${block}
/* Force a scrollbar that takes up space. Headless defaults to the overlay kind, which is
   zero-width and hides the failure this test most wants to see. */
::-webkit-scrollbar { width: 15px; height: 15px; }
::-webkit-scrollbar-thumb { background: #bbb; }</style>
<div class="sanitise-beforeafter">
  <div class="sanitise-ba-col">
    <div class="sanitise-ba-tag sanitise-ba-tag-before">before</div>
    <textarea class="sanitise-sample" readonly rows="1">${esc(text)}</textarea>
  </div>
  <div class="sanitise-ba-col">
    <div class="sanitise-ba-tag sanitise-ba-tag-after">after</div>
    <div class="sanitise-sample sanitise-after">${afterLines}</div>
  </div>
</div>
<script>
  const before = document.querySelector('.sanitise-ba-tag-before ~ textarea, .sanitise-ba-col textarea');
  const after = document.querySelector('.sanitise-after');
  document.title = JSON.stringify({
    afterLines: after.querySelectorAll('.sanitise-after-line').length,
    sidewaysBefore: before.scrollWidth > before.clientWidth + 1,
    sidewaysAfter: after.scrollWidth > after.clientWidth + 1,
  });
</script>` };
}

/** Render at a window width and read back what the browser measured. */
function render(html, width) {
  const dir = mkdtempSync(join(tmpdir(), 'sanitise-render-'));
  const file = join(dir, 'panel.html');
  writeFileSync(file, html);
  const dom = execFileSync(CHROME, [
    '--headless', '--disable-gpu', '--no-sandbox',
    `--window-size=${width},2400`, '--virtual-time-budget=5000',
    '--dump-dom', file,
  ], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 });

  const m = dom.match(/<title>(.*?)<\/title>/s);
  assert.ok(m, 'the page reported a measurement');
  return JSON.parse(m[1].replace(/&quot;/g, '"').replace(/&amp;/g, '&'));
}

const sample = () => {
  const text = corpus(5);
  return { text, entries: planSanitisation(text, { seed: 99, sourcetype: 'cribl' }).entries };
};

/* Three widths, because wrapping is the whole risk: a column can wrap at one width and scroll
   sideways at another if anything sizes it differently. */
const WIDTHS = [620, 900, 1400];

test('every event shows in the after pane and neither column scrolls sideways', { skip: CHROME ? false : 'no Chrome installed' }, () => {
  const s = sample();
  const built = page(s.text, s.entries);
  assert.equal(built.preview.lines.length, s.text.split('\n').length,
    'the after pane renders one line per event, changed or not');

  for (const width of WIDTHS) {
    const r = render(built.html, width);
    assert.equal(r.afterLines, s.text.split('\n').length,
      `${width}px: the after pane draws every event`);
    /* One event is a single 1,100-character line. Left to scroll horizontally it shows about
       twenty characters at a time, which is how a masked card number stays invisible. */
    assert.equal(r.sidewaysBefore, false, `${width}px: the before column wraps, it does not scroll sideways`);
    assert.equal(r.sidewaysAfter, false, `${width}px: the after column wraps, it does not scroll sideways`);
  }
});
