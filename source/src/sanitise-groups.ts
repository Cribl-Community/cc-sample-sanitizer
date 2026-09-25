import { PICKED_FIELD_VIA, PICKED_PATTERN_VIA, type SanitisePlan } from './sample-sanitise';

export type SanitiseEntryView = SanitisePlan['entries'][number];

export interface SanitiseGroup {
  id: string;
  className?: string;
  match: (e: SanitiseEntryView) => boolean;
  label: (n: number) => string;
  note: (n: number, plan: SanitisePlan) => string;
}

/**
 * How many rows of one group are drawn once it is unfolded.
 *
 * Not a limit on what gets replaced — every row in the group is applied. It is a limit on
 * what the DOM is asked to hold: a large sample yields tens of thousands of entries, and
 * mounting a checkbox and two inputs for each would cost more than the sanitising did.
 * Nobody reads the four-thousandth account number; the count and the group toggle are what
 * the decision actually rests on.
 */
export const SANITISE_ROW_CAP = 200;

/**
 * The review list, grouped by what kind of thing was found and in what order it matters.
 *
 * Split by weight rather than by tier. A credential is not a privacy judgement anybody
 * weighs, so it leads. A value a parser named is a fact and is ticked; a value matched on
 * shape alone is a guess and is not — mixing those two would either make the facts look
 * optional or make the guesses look settled.
 *
 * **First match wins**, and the last two groups are catch-alls — one for anything certain,
 * one for everything left. That is deliberate rather than tidy: predicates written to be
 * mutually exclusive drift the moment a kind is added, and a row matching no group would
 * vanish from the review list while still being replaced. Ordering the list and ending it
 * open makes a new kind land somewhere visible by construction. Use `groupOf`.
 */
export const SANITISE_GROUPS: SanitiseGroup[] = [
  {
    id: 'secret',
    className: 'sanitise-group-alert',
    match: e => e.kind === 'secret',
    label: n => (n === 1 ? 'probable credential' : 'probable credentials'),
    note: n => `Scrambled character-for-character so the sample still parses. Rotate the ${n === 1 ? 'original' : 'originals'}: this does not revoke anything.`,
  },
  {
    /* Above the tiers that found things on their own, because this one was asked for. A
       reviewer who picks a field is answering a question the tool could not, and burying
       the result among rows they never chose makes it hard to confirm the pick landed. */
    id: 'picked',
    match: e => e.via.startsWith(PICKED_FIELD_VIA) || e.via === PICKED_PATTERN_VIA,
    label: n => (n === 1 ? 'value you asked to replace' : 'values you asked to replace'),
    note: (_n, plan) => {
      const fields = [...new Set(plan.entries
        .filter(e => e.via.startsWith(PICKED_FIELD_VIA))
        .map(e => e.via.slice(PICKED_FIELD_VIA.length).trim()))];
      const patterns = plan.entries.some(e => e.via === PICKED_PATTERN_VIA);
      const bits: string[] = [];
      if (fields.length) bits.push(`every value of ${fields.join(' and ')}`);
      if (patterns) bits.push('only the parts of a shape you chose (name, number, …) — punctuation stays');
      return `${bits.join('; ')}. Remove the matching line from the list below to put them back.`;
    },
  },
  {
    id: 'pii',
    match: e => e.kind === 'pii',
    label: n => (n === 1 ? 'personal or device identifier' : 'personal and device identifiers'),
    note: () => 'Named by the field holding them — a handset serial or a postcode carries no pattern to match on. Replaced consistently, so one subscriber stays one subscriber.',
  },
  {
    id: 'network',
    match: e => e.confidence === 'certain' && (e.kind === 'ipv4' || e.kind === 'ipv6' || e.kind === 'mac'),
    label: n => (n === 1 ? 'address' : 'addresses'),
    note: () => 'Internal stays internal in its own range and public moves to documentation space, so the traffic still reads the way it did.',
  },
  {
    id: 'machine',
    match: e => e.confidence === 'certain' && (e.kind === 'host' || e.kind === 'fqdn'),
    label: n => (n === 1 ? 'machine name' : 'machine names'),
    note: () => 'Label counts and domain depth are preserved, because parsers are matched against these lines.',
  },
  {
    id: 'people',
    match: e => e.confidence === 'certain' && (e.kind === 'user' || e.kind === 'email'),
    label: n => (n === 1 ? 'account' : 'accounts'),
    note: () => 'Domain prefixes, machine-account $ and local@domain form all survive.',
  },
  {
    id: 'custom',
    match: e => e.confidence === 'certain',
    label: n => (n === 1 ? 'other value' : 'other values'),
    note: (_n, plan) => plan.sources.parser > 0 && plan.sources.parserName
      ? `Read from named fields by the ${plan.sources.parserName} parser, plus anything you added.`
      : 'Named by a field, or added by you.',
  },
  {
    id: 'suspect',
    className: 'sanitise-group-maybe',
    match: () => true,
    label: n => (n === 1 ? 'suggestion' : 'suggestions'),
    note: () => 'Matched on shape alone, so these are unticked. Tick the ones that are real — a wrong guess applied quietly builds a pack against fiction.',
  },
];

/** The one group a row belongs to. Never undefined: the last group matches anything. */
export function groupOf(entry: SanitiseEntryView): SanitiseGroup {
  return SANITISE_GROUPS.find(g => g.match(entry)) ?? SANITISE_GROUPS[SANITISE_GROUPS.length - 1];
}

/** Rows bucketed into their groups, in display order, with empty groups dropped. */
export function groupEntries(entries: SanitiseEntryView[]): (SanitiseGroup & { rows: SanitiseEntryView[] })[] {
  const buckets = new Map<string, SanitiseEntryView[]>();
  for (const e of entries) {
    const id = groupOf(e).id;
    const bucket = buckets.get(id);
    if (bucket) bucket.push(e); else buckets.set(id, [e]);
  }
  return SANITISE_GROUPS
    .filter(g => buckets.has(g.id))
    .map(g => ({ ...g, rows: buckets.get(g.id)! }));
}
