import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

// The evidence JSON and HTML report used to carry the uploaded file's name
// (`acmebank-fw01-oct.log`), which names the customer the sample came from.

const wizard = readFileSync(new URL('../src/sanitize-wizard.tsx', import.meta.url), 'utf8');

test('every stored provenance labels the source by mode, never by its name', () => {
  const labels = [...wizard.matchAll(/sourceLabel: ([^,\n]+),/g)].map(m => m[1].trim());
  assert.ok(labels.length >= 2, 'both the library save and buildDoc set a label');
  for (const label of labels) assert.equal(label, 'SOURCE_MODE_LABEL[sourceMode]');
});

test('the mode labels are generic', () => {
  const table = wizard.match(/const SOURCE_MODE_LABEL[^{]*\{([^}]*)\}/);
  assert.ok(table);
  assert.doesNotMatch(table[1], /sourceLabel|file\.name|sampleId/);
});
