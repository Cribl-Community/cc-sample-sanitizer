import { useEffect, useMemo, useRef, useState } from 'react';

import {
  downloadSample,
  downloadPackSample,
  listGroups,
  listGroupAndPackSamples,
  liveCapture,
  publishSanitisedSample,
  saveSanitisedSample,
  uploadWorkerGroupSample,
} from './sample-io';
import {
  buildSanitisedSampleDoc,
  downloadSanitisedSamplePayload,
  sanitisedSampleKey,
  type SanitisedSampleDoc,
} from './sanitised-sample-store';
import {
  applyAndVerifySanitisation,
  runSanitisation,
  normaliseSampleInput,
  parseSampleLocally,
  planSampleSanitisation,
  recogniseSampleLocally,
  SanitisationBlocked,
  type AppliedSanitisation,
  type LocalSampleRecognition,
} from './sanitised-sample-workflow';
import { canonicalizeSourcetype, getSupportedSourcetypeCatalog } from './source-recognition';
import { buildSanitiseChoices, canRefineSelection, countShapeMatches, describeRegexDraft, describeSelection, encodePatternExtra, markedValueShapeMulti, patternPatchDisplay, PICKED_PATTERN_VIA, previewSanitisation, regexFromSelection, splitExtras, splitStructuredToken, structuralOffenders, type SanitiseEntry, type SanitisePlan, type SelectionCandidate } from './sample-sanitise';
import { ensureSecretRules, secretRulesNotice, secretRulesStatus, type SecretRulesStatus } from './secret-rules';
import { groupEntries, SANITISE_ROW_CAP } from './sanitise-groups';

// Slice a line into literal text + highlighted spans, so the before/after preview marks
// exactly what changed. Spans are non-overlapping and sorted (previewSanitisation guarantees
// it). A span flagged `try` is a not-yet-committed pick the reviewer is previewing — painted
// in `tryCls` so it stands apart from the committed masks in `cls`. A span flagged `bad` is a
// mask that shifts a delimiter/whitespace boundary and blocks the save — painted in `badCls`
// (red), which takes precedence over `try` so a blocking pick always reads as blocking.
function renderPreviewSpans(
  text: string,
  spans: { start: number; end: number; try?: boolean; bad?: boolean }[],
  cls: string,
  tryCls = cls,
  badCls = cls,
) {
  if (!spans.length) return text;
  const out: (string | React.ReactElement)[] = [];
  let at = 0;
  spans.forEach((s, i) => {
    if (s.start > at) out.push(text.slice(at, s.start));
    out.push(<mark key={i} className={s.bad ? badCls : s.try ? tryCls : cls}>{text.slice(s.start, s.end)}</mark>);
    at = s.end;
  });
  if (at < text.length) out.push(text.slice(at));
  return out;
}

export interface SanitizeWizardProps {
  open: boolean;
  onClose: () => void;
  runMode: 'iframe' | 'standalone' | 'backend';
  canPublish?: boolean;
  repo?: string;
  onOpenSettings?: () => void;
  onLibraryChanged?: () => void;
  // Embedded mode: the standalone "Sample Sanitizer" app renders the wizard inline as the
  // whole page rather than as a modal over another screen — no dimmed backdrop, no close
  // button (there is nothing behind it to return to). Defaults to false so the pack
  // generator keeps its modal behaviour unchanged.
  embedded?: boolean;
  // Apply mode: opened from the new-pack Source Data step with a sample already in hand.
  // The wizard seeds from initialRaw/initialSourcetype, opens straight on the review step
  // (no events/source/save steps), and on Apply hands the sanitised events back to the
  // caller via onApply and closes — it never persists to the library. Providing onApply
  // is what turns this mode on; applyMode makes the intent explicit at the call site.
  applyMode?: boolean;
  initialRaw?: string;
  initialSourcetype?: string;
  // `warning` carries a non-blocking advisory (e.g. the sanitised events no longer parse
  // cleanly against the source's declared wire format) so the pack generator can surface it
  // in a notice without stranding the user — apply mode is advisory, not the strict library gate.
  onApply?: (events: string[], sourcetype: string, warning?: string | null) => void;
}

type SourceMode = 'upload' | 'paste' | 'group' | 'live-capture';
type Step = 'events' | 'source' | 'sanitize' | 'save';
type Group = { id: string; name?: string; workerCount?: number };
type GroupSample = { id: string; name: string; size?: number; numEvents?: number; packId?: string; packName?: string };

const STEPS: { id: Step; label: string }[] = [
  { id: 'events', label: 'Events' },
  { id: 'source', label: 'Source' },
  { id: 'sanitize', label: 'Sanitize' },
  { id: 'save', label: 'Save' },
];

// Apply mode has a single step: the sample and sourcetype arrive from the caller, so the
// events/source pickers and the library save destinations are all skipped — the reviewer
// just reviews the replacements and applies them back into the pack.
const APPLY_STEPS: { id: Step; label: string }[] = [
  { id: 'sanitize', label: 'Sanitize' },
];

// The before and after panes must show the SAME line budget, or one pane silently ends while
// the other keeps going and the reviewer can't confirm masking past the cut. Every line is
// still sanitised on Apply — this only bounds what the preview renders.
const PREVIEW_LINE_CAP = 200;

// Append one pick to the extras box on its OWN line. A regex pick (`re:…|group`) may carry
// commas inside its source (`\d{1,3}`), and the extras box still comma-splits everything that
// is not a whole `re:` line — so newline-joining is what keeps a hand-written regex intact
// while pasted comma lists keep working. splitExtras reads both separators.
function appendExtra(current: string, token: string): string {
  const base = current.trim();
  return base ? `${base}\n${token}` : token;
}

function triggerDownload(doc: SanitisedSampleDoc, format: 'log' | 'json' | 'report') {
  const payload = downloadSanitisedSamplePayload(doc, format);
  const url = URL.createObjectURL(new Blob([payload.body], { type: payload.mime }));
  const link = document.createElement('a');
  link.href = url;
  link.download = payload.filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function SanitizeWizard({
  open, onClose, runMode, canPublish = false, repo = '',
  onLibraryChanged, embedded = false,
  applyMode = false, initialRaw = '', initialSourcetype = '', onApply,
}: SanitizeWizardProps) {
  const steps = applyMode ? APPLY_STEPS : STEPS;
  const [step, setStep] = useState<Step>('events');
  const [sourceMode, setSourceMode] = useState<SourceMode>('upload');
  const [raw, setRaw] = useState('');
  const [sourceLabel, setSourceLabel] = useState('');
  const [groups, setGroups] = useState<Group[]>([]);
  const [samples, setSamples] = useState<GroupSample[]>([]);
  const [groupId, setGroupId] = useState('');
  const [sampleId, setSampleId] = useState('');
  // Origin pack of the selected sample ('' = worker-group system sample). Tracked
  // alongside sampleId so a pack sample that shares an id with a system sample is
  // still resolved to the right endpoint.
  const [samplePackId, setSamplePackId] = useState('');
  const [sampleSearch, setSampleSearch] = useState('');
  const [recognition, setRecognition] = useState<LocalSampleRecognition | null>(null);
  const [sourcetype, setSourcetype] = useState('');
  const [plan, setPlan] = useState<SanitisePlan | null>(null);
  const [applied, setApplied] = useState<AppliedSanitisation | null>(null);
  // The "add to this generator's sample library" destination only makes sense in the Pack
  // Generator (that library is what its wizard resolves samples from). The standalone Sample
  // Sanitizer app (embedded) has no such consumer — its KV is app-scoped and nothing reads it —
  // so the option is hidden AND defaulted off there; the reviewer uses "Upload to worker group".
  // Worker-group sample filename. Defaults to the key-derived name when the save step is
  // reached (see the effect below), but the reviewer can rename it to anything valid before
  // uploading — an empty box means "use the default".
  const [groupSampleName, setGroupSampleName] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  // Identities the parser still saw unchanged after the last Apply attempt — the blocker that
  // stops the save. Kept as structured rows (not just a sentence) so the panel can point the
  // reviewer at the exact line + field and highlight it in the before pane.
  const [survivors, setSurvivors] = useState<{ field: string; value: string; line: number }[]>([]);
  const [result, setResult] = useState('');
  // Each save destination is now a self-contained action with its own button — no ticking
  // then a single "Save selected". actionBusy is the id currently running (one at a time);
  // actionDone/actionErr hold the inline confirmation or failure for each card by id.
  const [actionBusy, setActionBusy] = useState('');
  const [actionDone, setActionDone] = useState<Record<string, string>>({});
  const [actionErr, setActionErr] = useState<Record<string, string>>({});
  const fileRef = useRef<HTMLInputElement>(null);
  const alertRef = useRef<HTMLDivElement>(null);

  // Known-sourcetype catalog for the override autocomplete — memoised (the catalog
  // build is cached in source-recognition, and we only need the names here).
  const sourcetypeCatalog = useMemo(() => getSupportedSourcetypeCatalog().map(s => s.name), []);
  // Live parser check for whatever sourcetype is currently typed/picked: can its
  // parser actually read THIS sample? This closes the loop so a manual correction
  // is verifiable instead of a blind guess. Local + offline (Hard Rule 23).
  const sourceCheck = useMemo(() => {
    const st = sourcetype.trim();
    if (!st || !raw.trim()) return null;
    let parsed: ReturnType<typeof parseSampleLocally>['parsed'] = [];
    let parserName: string | undefined;
    try { ({ parsed, parserName } = parseSampleLocally(raw, st)); } catch { return null; }
    const total = raw.split('\n').filter(line => line.trim()).length;
    const readable = parsed.filter(p => p && Object.keys(p).some(k => !k.startsWith('__'))).length;
    return { parserName, readable, total, canonical: canonicalizeSourcetype(st) };
  }, [sourcetype, raw]);
  // Manual sanitisation: what the reviewer highlighted, and the extra rules they've picked.
  // These are fed back into planSampleSanitisation so a hand-picked value/field/shape becomes
  // a real plan entry — the same path the main sample panel uses (describeSelection).
  const [sel, setSel] = useState<SelectionCandidate | null>(null);
  // The two-question guided panel (Q1 "what" / Q2 "match by"):
  //  - `maskTarget` — is the reviewer masking the WHOLE value or a PART of it (the in-panel strip).
  //  - `matchBy` — for the whole value, match its FORMAT (any value of the field) or the EXACT text.
  //  - `partRanges` — the runs of the value the reviewer has picked (by drag or piece-chip), each
  //    an offset range into `wholeValueText`. MULTIPLE parts can be chosen; they are combined into
  //    ONE `markedValueShapeMulti` pattern that keeps the surrounding text literal, so a bare number
  //    is safe — the context pins it to this one place.
  const [maskTarget, setMaskTarget] = useState<'whole' | 'part'>('whole');
  const [matchBy, setMatchBy] = useState<'format' | 'exact'>('format');
  //  - `partMatchBy` — once a PART is picked, mask it by its SHAPE (a class like `\d+`, catching
  //    any value of that shape in this spot — "based on wildcards") or EXACTLY (only this literal
  //    value, e.g. `12345`, in this spot). Drives the `markedValueShapeMulti` mode below.
  const [partMatchBy, setPartMatchBy] = useState<'shape' | 'exact'>('shape');
  const [partRanges, setPartRanges] = useState<{ start: number; end: number }[]>([]);
  // The interactive value strip (the part picker). Selection offsets are read off it directly.
  const stripRef = useRef<HTMLDivElement>(null);
  // One comma/line-separated box holds every manual rule — plain literals, `field:name`
  // whole-field picks, and `re:…|g1` shape/regex picks — exactly like the new-pack sanitiser.
  // Single source of truth so a typed regex and a button-added one are the same thing, and
  // any pick can be edited or removed by editing the box.
  const [extraText, setExtraText] = useState('');
  // Which review groups are unfolded. Every group starts shut (default collapsed): what
  // each is and how many is on the header, and the sample above marks the values in place.
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  // "Write your own regex" editor: the reviewer types a regex with named capture groups
  // (`id=(?<test>\d+)`), the panes above highlight what it hits live, and they tick which
  // named groups (fields) to mask. `regexDraft` is the immediate input; `regexQuery` lags it
  // by a short debounce so the live match/plan work isn't run on every keystroke.
  const [regexOpen, setRegexOpen] = useState(false);
  const [regexDraft, setRegexDraft] = useState('');
  const [regexQuery, setRegexQuery] = useState('');
  const [regexPick, setRegexPick] = useState<Set<string>>(new Set());
  const regexNamesRef = useRef<string[]>([]);
  // One seed for the whole session so re-planning after a pick keeps existing aliases stable.
  const [seed] = useState(() => Date.now() & 0x7fffffff);
  const sampleRef = useRef<HTMLTextAreaElement>(null);
  // The before pane is a textarea (so it stays drag-selectable) with a transparent-text
  // backdrop behind it that paints the changed values in place — the standard
  // highlight-behind-textarea trick. `backdropRef` is scrolled in lockstep with the textarea
  // so its marks sit under the right glyphs.
  const backdropRef = useRef<HTMLDivElement>(null);
  // Scroll-sync for the before/after panes: mirror one pane's scrollTop onto the other so a
  // reviewer reads the same lines across. `syncing` is a re-entrancy lock — setting scrollTop
  // fires another scroll event, and without the lock the two handlers ping-pong.
  const afterRef = useRef<HTMLDivElement>(null);
  const syncing = useRef(false);
  // A wide multi-part selection is remembered as the "scope" for a follow-up mark: highlight
  // one run inside it and only that run is masked, the rest of the scope stays literal.
  const scopeRef = useRef<{ start: number; end: number } | null>(null);
  // Live-capture settings — same options as the new-pack source screen so a reviewer can
  // pull real traffic off a worker group here too (exactly the data this wizard exists to
  // sanitise). Capture is capped: at most 500 events over at most 30 seconds.
  const [captureFilter, setCaptureFilter] = useState('true');
  const [captureMaxEvents, setCaptureMaxEvents] = useState(100);
  const [captureDuration, setCaptureDuration] = useState(10);
  const [captureLoading, setCaptureLoading] = useState(false);
  // Incremental live capture: the platform fetch proxy buffers a whole response and cancels
  // anything past ~30s, so we can't stream one long capture. Instead we run a series of short
  // capture windows and append each batch to the preview as it lands — the reviewer watches
  // events accumulate. `captureProgress` drives the live counter; `stopCaptureRef` lets Stop
  // break the loop after the in-flight window returns (a single window is un-abortable, but
  // it is short by design).
  const [captureProgress, setCaptureProgress] = useState(0);
  // The captured event lines, shown live in the capture step so the reviewer can confirm
  // they grabbed the right data before identifying the source.
  const [capturedEvents, setCapturedEvents] = useState<string[]>([]);
  const stopCaptureRef = useRef(false);
  // Pre-apply snapshot, held only in memory so "Back" from the save step can return to the
  // review with the original restored. Cleared on close and after a successful save, so the
  // one-way privacy boundary still holds the moment the user leaves the wizard.
  const preApply = useRef<{ raw: string; plan: SanitisePlan | null; extraText: string; sourcetype: string } | null>(null);

  useEffect(() => {
    if (!open) return;
    void listGroups()
      .then(items => setGroups(items as Group[]))
      .catch(err => setError(err instanceof Error ? err.message : String(err)));
  }, [open]);

  // The public-source secret / sensitive-data rules — installed from a bundled library, so
  // secret detection can only run once they have landed (there is no I/O, so that is
  // essentially immediate). Started as early as the wizard opens (the install is memoized) and
  // never surfaced as an error: an unusable library must not stop somebody de-identifying a
  // sample, it just costs the pattern tier. `secretNotice` is what the review step shows then.
  const [secretStatus, setSecretStatus] = useState<SecretRulesStatus>(() => secretRulesStatus());
  useEffect(() => {
    if (!open) return;
    let live = true;
    void ensureSecretRules(groupId || undefined).then(s => { if (live) setSecretStatus(s); });
    return () => { live = false; };
  }, [open, groupId]);
  const secretNotice = secretRulesNotice(secretStatus);

  // If the rules land AFTER a plan was already built, that plan was made without the pattern
  // tier and would understate what the sample contains — the reviewer would be looking at a
  // list that is missing exactly the tokens they cannot spot by eye. Re-plan once, preserving
  // their enabled/alias edits (`keepEdits`). Keyed on the rule count so it fires on the
  // transition only, never in a loop.
  const secretPlannedWith = useRef<number>(-1);
  useEffect(() => {
    if (secretStatus.state !== 'ready') return;
    if (secretPlannedWith.current === secretStatus.rules) return;
    const first = secretPlannedWith.current === -1;
    secretPlannedWith.current = secretStatus.rules;
    // Nothing to redo if no plan exists yet — the next plan build picks the rules up itself.
    if (first && !plan) return;
    if (plan) buildPlan(extraText, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps — fires on the rules-landed transition
  }, [secretStatus.state, secretStatus.rules]);

  useEffect(() => {
    if (!open || !groupId) { setSamples([]); return; }
    setBusy('Loading samples…');
    // Worker-group system samples AND samples inside installed packs in this group.
    void listGroupAndPackSamples(groupId)
      .then(items => { setSamples(items as GroupSample[]); setError(''); })
      .catch(err => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setBusy(''));
  }, [groupId, open]);

  // Type-to-find over the combined group + pack sample list. Matches the sample name
  // or its pack's name (case-insensitive substring), so a user can type either.
  const filteredSamples = useMemo(() => {
    const q = sampleSearch.trim().toLowerCase();
    if (!q) return samples;
    return samples.filter(s =>
      s.name.toLowerCase().includes(q) || (s.packName || '').toLowerCase().includes(q));
  }, [samples, sampleSearch]);

  useEffect(() => {
    if (open) return;
    setStep('events');
    setRaw('');
    setSourceLabel('');
    setSampleSearch('');
    setRecognition(null);
    setSourcetype('');
    setPlan(null);
    setApplied(null);
    setError('');
    setResult('');
    setSel(null);
    setExtraText('');
    setOpenGroups({});
    setRegexOpen(false);
    setRegexDraft('');
    setRegexQuery('');
    setRegexPick(new Set());
    regexNamesRef.current = [];
    setCaptureFilter('true');
    setCaptureMaxEvents(100);
    setCaptureDuration(10);
    setCaptureLoading(false);
    preApply.current = null;
  }, [open]);

  const activeIndex = steps.findIndex(item => item.id === step);
  const enabled = plan?.entries.filter(item => item.enabled).length || 0;

  // Apply mode: the sample and sourcetype arrive from the caller. Seed once when the modal
  // opens (initialRaw is fixed for the lifetime of one open), recognise the format locally
  // for the plan, build the initial plan, and land straight on the review step. Runs after
  // the close-reset effect below because that only fires when `open` is false.
  useEffect(() => {
    if (!open || !applyMode) return;
    const text = normaliseSampleInput(initialRaw);
    setRaw(text);
    const found = recogniseSampleLocally(text);
    setRecognition(found);
    const st = (initialSourcetype || found.sourcetype || '').trim();
    setSourcetype(st);
    setSourceLabel('loaded sample');
    setExtraText('');
    setPlan(planSampleSanitisation(text, st, { seed }));
    setStep('sanitize');
    // eslint-disable-next-line react-hooks/exhaustive-deps — seed once per open; other deps are fixed for that open
  }, [open]);

  // The "before" textarea must show the SAME lines as the "after" pane (which is capped at
  // PREVIEW_LINE_CAP) — otherwise the panes end at different points. Selection offsets are read
  // off this displayed text; occurrence counting still uses the full `raw` (censusText), so
  // truncating the display never changes what a pick matches across the whole sample.
  // Live capture only makes sense for groups that have a connected worker — an empty group
  // yields an empty capture. Hide the rest from the picker.
  const capturableGroups = useMemo(() => groups.filter(g => (g.workerCount ?? 0) > 0), [groups]);
  const beforeLines = useMemo(() => raw ? raw.split('\n') : [], [raw]);
  const beforeDisplay = useMemo(
    () => beforeLines.length > PREVIEW_LINE_CAP ? beforeLines.slice(0, PREVIEW_LINE_CAP).join('\n') : raw,
    [beforeLines, raw],
  );
  const previewTruncated = beforeLines.length > PREVIEW_LINE_CAP;

  // The guided "what should be masked?" options for the current selection. Rebuilt from `sel`;
  // the two-question panel below derives its whole-value format/exact tokens from this list, so
  // the panel and the applied rule stay in parity by construction. The defaults for the two
  // questions are set by the reset effect further down (keyed on `sel`).
  const sanitiseChoices = useMemo(() => buildSanitiseChoices(sel), [sel]);

  // ---- Two-question guided panel derivation (all from the shared `sanitiseChoices`) ----
  // The whole-value answers: FORMAT (any value of the field — value mask / field / mask-all-parts)
  // and EXACT (only this literal text). One token each, taken straight from the guided choices so
  // the panel and the applied rule can never diverge.
  // "Match by the FORMAT" = mask by shape/position, any value: a label-anchored value mask or a
  // whole field first; else "every part" of a composite; else a lone shape run that IS the whole
  // selection (a bare identifier). Only a pure literal has no format answer at all.
  const formatChoice = useMemo(
    () => sanitiseChoices.find(c => c.match === 'format')
      ?? sanitiseChoices.find(c => c.id === 'shape-all')
      ?? sanitiseChoices.find(c => c.match === 'part'),
    [sanitiseChoices]);
  const exactChoice = useMemo(() => sanitiseChoices.find(c => c.match === 'exact'), [sanitiseChoices]);
  // The value the part-picker operates on: the whole value a format mask would replace (the value
  // behind `"OriginatingServer": …`, or the composite token like `sshd[27480]`). It appears verbatim
  // in the sample, so a `markedValueShapeMulti` built from it matches in place.
  const wholeValueText = useMemo(
    () => (sel?.valueMaskFromSelection
      // The reviewer highlighted the whole `a=b` — refine over the pair, not just the value,
      // so its pieces (`a`, `b`) stay pickable rather than showing choices "only about b".
      ? (sel.pattern?.shape.token ?? sel.selected.trim())
      : sel?.valueMask?.shape.groups[0]?.sample ?? sel?.pattern?.shape.token ?? (sel ? sel.selected.trim() : '')),
    [sel]);
  const refinable = useMemo(() => canRefineSelection(sel), [sel]);
  const valuePieces = useMemo(() => refinable ? splitStructuredToken(wholeValueText) : [], [refinable, wholeValueText]);

  // The combined part mask: ALL the runs the reviewer has picked (drag and/or chips) marked at
  // once, everything else literal. One pattern, N groups — so two, three parts of the value can be
  // masked together while their context stays. Null (nothing valid picked) means "no part yet".
  const partMask = useMemo(() => {
    if (!partRanges.length) return null;
    const shape = markedValueShapeMulti(wholeValueText, partRanges, partMatchBy);
    if (!shape) return null;
    const matches = countShapeMatches(raw, shape.source);
    if (!matches) return null;
    return { token: encodePatternExtra(shape.source, shape.groups.map(g => g.name)), shape, matches };
  }, [partRanges, wholeValueText, raw, partMatchBy]);

  // A new selection resets the two questions to their safe defaults: mask the WHOLE value, by its
  // FORMAT if that is offered (else the exact text), and no parts chosen yet.
  useEffect(() => {
    setMaskTarget('whole');
    setMatchBy(formatChoice ? 'format' : 'exact');
    setPartMatchBy('shape');
    setPartRanges([]);
    // formatChoice is derived from sel; keying on sel keeps this to one run per selection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sel]);

  // The token the panel will actually apply, given the current answers. The combined part mask
  // wins when the reviewer is on "a part"; otherwise it is the format or exact whole-value token.
  const activeChoiceToken = useMemo(() => {
    if (maskTarget === 'part') return partMask?.token;
    const chosen = matchBy === 'format' ? formatChoice : exactChoice;
    return (chosen ?? formatChoice ?? exactChoice)?.token;
  }, [maskTarget, matchBy, partMask, formatChoice, exactChoice]);

  // Whether a piece of the value (its [start,end) run) is currently among the picked parts. Two
  // gestures on the same run overlap, so an overlap test both drives the chip's "on" state and
  // lets a second tap TOGGLE the piece back off.
  function pieceIsPicked(start: number, end: number): boolean {
    return partRanges.some(r => start < r.end && end > r.start);
  }

  // Toggle a whole piece (a chip) in or out of the picked set. Adding turns the panel to "a part";
  // removing the last piece drops back to a clean part selection (the panel still shows the strip).
  function togglePartPiece(start: number, end: number) {
    setPartRanges(prev => {
      const overlaps = prev.some(r => start < r.end && end > r.start);
      const next = overlaps
        ? prev.filter(r => !(start < r.end && end > r.start))
        : [...prev, { start, end }];
      return next;
    });
    setMaskTarget('part');
    window.getSelection()?.removeAllRanges();
  }

  // Read the reviewer's drag inside the value strip as offsets into `wholeValueText` and ADD it to
  // the picked parts (multi-select — a drag augments the chips rather than replacing them). The
  // browser selection is cleared afterwards so a stale highlight can't swallow the next gesture.
  function onStripSelect() {
    const container = stripRef.current;
    if (!container) return;
    const s = window.getSelection();
    if (!s || s.isCollapsed || !s.rangeCount) return;
    const r = s.getRangeAt(0);
    if (!container.contains(r.commonAncestorContainer)) return;
    const pre = document.createRange();
    pre.selectNodeContents(container);
    pre.setEnd(r.startContainer, r.startOffset);
    const start = pre.toString().length;
    const len = s.toString().length;
    s.removeAllRanges();
    if (len <= 0) return;
    setPartRanges(prev => [...prev, { start, end: start + len }]);
    setMaskTarget('part');
  }

  // Live preview of the masking choice the reviewer is currently pointing at, BEFORE they
  // commit it with "Mask it". We build a throwaway plan that layers the selected choice's
  // token on top of the committed picks, then flag exactly the entries that choice adds
  // (`tryKeys`) so the after pane can paint them in the distinct "trying this" colour — the
  // reviewer sees where the pick lands, confirms it is the right place, then applies. Cleared
  // the instant the selection is (addExtra resets `sel`), so an applied pick just becomes a
  // normal committed mask. Rebuilt only while a choice is selected — no cost otherwise.
  const provisional = useMemo(() => {
    if (!plan || !sel) return null;
    const token = activeChoiceToken;
    if (!token) return null;
    const nextText = appendExtra(extraText, token);
    const candidate = planFromExtras(nextText, plan);
    const committed = new Set(plan.entries.map(entry => `${entry.kind}:${entry.original}`));
    const tryKeys = new Set(
      candidate.entries
        .filter(entry => entry.enabled && !committed.has(`${entry.kind}:${entry.original}`))
        .map(entry => `${entry.kind}:${entry.original}`),
    );
    return { plan: candidate, tryKeys };
    // planFromExtras is a stable closure over raw/sourcetype/seed; those are the real inputs.
    // `activeChoiceToken` folds in the two-question answers (whole/part, format/exact, partRanges).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [plan, sel, activeChoiceToken, extraText, raw, sourcetype, seed]);

  // Debounce the typed regex so the live match scan and the throwaway re-plan don't run on
  // every keystroke; the input stays immediate, the analysis lags it by a beat.
  useEffect(() => {
    if (!regexOpen) return;
    const timer = window.setTimeout(() => setRegexQuery(regexDraft), 250);
    return () => window.clearTimeout(timer);
  }, [regexDraft, regexOpen]);

  // Compile + describe the (debounced) draft against the sample: valid?, its named capture
  // groups (the fields to offer), an example capture per group, and how many times it hits.
  const regexInfo = useMemo(
    () => regexOpen ? describeRegexDraft(regexQuery, raw) : null,
    [regexOpen, regexQuery, raw],
  );

  // Keep the ticked fields in sync with the groups the draft actually declares: a group that
  // survives an edit keeps the reviewer's decision, a newly-appeared group defaults to ON (you
  // named it to mask it), and a group that disappears drops out.
  const regexGroupNames = regexInfo?.valid ? regexInfo.groups.map(group => group.name) : [];
  const regexNamesKey = regexGroupNames.join(' ');
  useEffect(() => {
    const names = regexNamesKey ? regexNamesKey.split(' ') : [];
    const prev = regexNamesRef.current;
    if (names.length === prev.length && names.every((name, i) => name === prev[i])) return;
    regexNamesRef.current = names;
    setRegexPick(old => {
      const next = new Set<string>();
      for (const name of names) if (prev.includes(name) ? old.has(name) : true) next.add(name);
      return next;
    });
  }, [regexNamesKey]);

  // The same live-preview machinery as `provisional`, but driven by the regex editor: fold the
  // encoded pattern pick onto the committed plan and flag the entries it adds, so the panes
  // highlight what the hand-written regex will mask before the reviewer commits it.
  const regexProvisional = useMemo(() => {
    if (!plan || !regexOpen || !regexInfo?.valid || !regexInfo.matches) return null;
    const picked = regexGroupNames.filter(name => regexPick.has(name));
    if (!picked.length) return null;
    // Isolate the editor: the panes must show ONLY what THIS regex matches. Fold the pattern
    // onto a fresh plan and keep just the pattern-pick entries, dropping the ambient
    // auto-detected identities and suspects — those coincide with the field shapes (a bare
    // number looks like `\d{1,4}`, a token like `\S+`), so folding them in made it look as if
    // the regex was masking values it never fully matched. Only the complete-pattern matches
    // are shown. On "Mask" the pattern commits onto the real plan (which still carries the
    // auto-detected masks), so nothing that was covered stops being covered.
    const built = planFromExtras(encodePatternExtra(regexQuery.trim(), picked), null);
    const entries = built.entries.filter(entry => entry.via === PICKED_PATTERN_VIA);
    const candidate = { ...built, entries };
    const tryKeys = new Set(entries.filter(entry => entry.enabled).map(entry => `${entry.kind}:${entry.original}`));
    return { plan: candidate, tryKeys };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [plan, regexOpen, regexInfo, regexNamesKey, regexPick, regexQuery, raw, sourcetype, seed]);

  // One provisional feeds the live preview. When the regex editor is open it owns the panes —
  // even if a stray text selection is still around, the editor's match is what the reviewer is
  // shaping. Otherwise a guided selection choice drives it.
  const activeProvisional = regexOpen ? regexProvisional : provisional;

  // A before/after look at what Apply will do, built from the SAME replacer, so it can never
  // drift from the real result. Every visible line (unchanged ones show through identically),
  // so the after can never quietly disappear; refreshes as picks are added/removed. When a
  // choice is being previewed, the candidate plan drives it and `tryKeys` paints the pick.
  // `badKeys` are the masks that shift a delimiter/whitespace boundary (structuralOffenders)
  // and would block the save — surfaced now so the reviewer sees them in red before Apply,
  // instead of hitting the wire-format error only when they press Save.
  const preview = useMemo(() => {
    if (!plan) return { lines: [], totalChanged: 0, badKeys: new Set<string>() };
    // While the regex editor is open, the panes belong to the regex: its own matches when it
    // has any (regexProvisional), otherwise a clean before=after — never the ambient base
    // plan, whose auto-detected masks would read as the regex over-matching.
    const active = activeProvisional?.plan ?? (regexOpen ? { ...plan, entries: [] } : plan);
    const badKeys = structuralOffenders(active.entries);
    const built = previewSanitisation(raw, active.entries, PREVIEW_LINE_CAP, true, activeProvisional?.tryKeys, badKeys);
    return { ...built, badKeys };
  }, [plan, raw, activeProvisional, regexOpen]);


  async function loadGroupSample() {
    if (!groupId || !sampleId) throw new Error('Choose a worker group and sample.');
    const sample = samples.find(item => item.id === sampleId && (item.packId || '') === samplePackId);
    // A pack-scoped sample is read from the pack; otherwise it's a worker-group system sample.
    const downloaded = samplePackId
      ? await downloadPackSample(groupId, samplePackId, sampleId)
      : await downloadSample(groupId, sampleId);
    const text = normaliseSampleInput(downloaded.events.join('\n'));
    setRaw(text);
    setSourceLabel(sample?.packName ? `${sample.name} · ${sample.packName}` : (sample?.name || sampleId));
    return text;
  }

  async function identify() {
    setError('');
    setBusy('Inspecting locally…');
    try {
      const text = sourceMode === 'group' ? await loadGroupSample() : normaliseSampleInput(raw);
      if (!text.trim()) throw new Error(sourceMode === 'upload' ? 'Choose a file first.' : 'Add at least one event.');
      setRaw(text);
      const found = recogniseSampleLocally(text);
      setRecognition(found);
      setSourcetype(found.sourcetype);
      setStep('source');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy('');
    }
  }

  // A pure plan build from an extras-box string, preserving the reviewer's enabled/alias
  // edits from `prev` for any entry that survives the re-plan. Pure so the provisional
  // preview (below) can build a candidate plan without touching state — `buildPlan` wraps
  // it with setPlan for the real, committing path.
  function planFromExtras(text: string, prev: SanitisePlan | null): SanitisePlan {
    const { literals, fields, patterns } = splitExtras(text);
    const fresh = planSampleSanitisation(raw, sourcetype, {
      seed, extraLiterals: literals, extraFields: fields, extraPatterns: patterns,
    });
    if (!prev) return fresh;
    const prior = new Map(prev.entries.map(entry => [`${entry.kind}:${entry.original}`, entry]));
    return {
      ...fresh,
      entries: fresh.entries.map(entry => {
        const kept = prior.get(`${entry.kind}:${entry.original}`);
        return kept ? { ...entry, enabled: kept.enabled, alias: kept.alias } : entry;
      }),
    };
  }

  // One plan build from the extras box, preserving the reviewer's enabled/alias edits for
  // any entry that survives the re-plan. `keepEdits` is off for the first plan (there is
  // nothing to keep) and on for every re-plan after a pick or an edit to the box.
  function buildPlan(text: string, keepEdits: boolean): void {
    setPlan(prev => planFromExtras(text, keepEdits ? prev : null));
  }

  // Wipe every manual masking decision back to a clean slate. Called when entering the
  // review step from the source step so re-picking a different sample (Back → choose another
  // → forward) starts a fresh session: the old sample's picks, typed rules and open regex
  // editor never leak onto the new one.
  function resetManualSanitisation() {
    setExtraText('');
    setSel(null);
    setMaskTarget('whole');
    setMatchBy('format');
    setPartRanges([]);
    setOpenGroups({});
    setRegexOpen(false);
    setRegexDraft('');
    setRegexQuery('');
    setRegexPick(new Set());
    regexNamesRef.current = [];
    scopeRef.current = null;
  }

  function confirmSource() {
    setError('');
    try {
      if (!sourcetype.trim()) throw new Error('Enter or confirm a sourcetype.');
      // Fresh session: drop any picks from a previously-reviewed sample and build the plan
      // from an empty extras box (not the stale `extraText`, whose setState hasn't landed yet).
      resetManualSanitisation();
      buildPlan('', false);
      setStep('sanitize');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  /**
   * Re-plan after the extras box changes. Planning is a full pass over the sample, and the
   * textarea would call it per keystroke; the typed text stays immediate while the re-plan
   * waits for a pause — same as the new-pack sanitiser.
   */
  const replanTimer = useRef<number | null>(null);
  function replanFromText(text: string) {
    setExtraText(text);
    if (!plan) return;
    if (replanTimer.current) window.clearTimeout(replanTimer.current);
    replanTimer.current = window.setTimeout(() => {
      replanTimer.current = null;
      buildPlan(text, true);
    }, 350);
  }
  useEffect(() => () => { if (replanTimer.current) window.clearTimeout(replanTimer.current); }, []);
  // Once the reviewer edits their picks or moves step, the last "survived unchanged" blocker is
  // stale — drop its list and the before-pane highlight so it can't linger under a later message.
  useEffect(() => { setSurvivors([]); }, [plan, step]);

  // A pick appends its token to the extras box and re-plans at once (no debounce — a click
  // is not a keystroke storm), then clears the selection so the pick bar closes cleanly.
  // `openGroup` unfolds the review group the pick lands in, so the reviewer can see the new
  // row and the value it is replaced with — otherwise it appears inside a collapsed fold.
  function addExtra(token: string, openGroup?: string) {
    const next = appendExtra(extraText, token);
    setExtraText(next);
    buildPlan(next, true);
    if (openGroup) setOpenGroups(state => ({ ...state, [openGroup]: true }));
    setSel(null);
    scopeRef.current = null;
    sampleRef.current?.setSelectionRange(0, 0);
  }

  // Offsets come from the textarea itself so growing a selection to whole-token edges is
  // reliable. A collapsed selection is ignored (not cleared) so clicking a pick button —
  // which blurs the box — doesn't unmount the bar before the click lands.
  function onSampleSelect() {
    const el = sampleRef.current;
    if (!el || !plan) return;
    if (el.selectionStart === el.selectionEnd) return;
    const { start, end } = { start: el.selectionStart, end: el.selectionEnd };
    const scope = scopeRef.current;
    const next = describeSelection({
      text: el.value, start, end,
      entries: plan.entries, pickedFields: splitExtras(extraText).fields, censusText: raw,
      scopeStart: scope?.start, scopeEnd: scope?.end,
    });
    setSel(next);
    /* Remember a wide multi-part shape as the scope for a follow-up mark; a selection that is
       itself a sub-range of the current scope IS the mark, so it must not overwrite it. */
    const isSubRange = !!scope && start >= scope.start && end <= scope.end && (start > scope.start || end < scope.end);
    if (!isSubRange) {
      scopeRef.current = next?.pattern && next.pattern.shape.groups.length >= 1 ? { start, end } : null;
    }
  }

  // Apply the two-question answer. `activeChoiceToken` already resolved to the exact extras-box
  // token for the current state — a whole-value format/exact mask (from the shared guided choices)
  // or a part mask (a `markedValueShape` built from the value strip). The review group it lands in
  // depends only on which token it is, so derive `openGroup` from the matching choice when there is
  // one; a part pick lands in the "pattern you picked" fold.
  function applySanitiseChoice() {
    const token = activeChoiceToken;
    if (!token) return;
    if (maskTarget === 'part') { addExtra(token, 'picked'); return; }
    const choice = (matchBy === 'format' ? formatChoice : exactChoice) ?? formatChoice ?? exactChoice;
    addExtra(token, choice?.openGroup);
  }

  // Open the "write your own regex" editor. `prefill` seeds the draft — from a live selection
  // it is a pattern that already extracts what was highlighted (regexFromSelection), so the
  // reviewer only refines it; from the no-selection entry point it is empty. The selection's
  // guided choices give way to the editor (setSel(null)), and the draft is pushed to both
  // `regexDraft` and `regexQuery` so the live match/preview runs this render, not after the
  // debounce. regexNamesRef is cleared so every seeded group defaults to ticked (you extracted
  // it to mask it) — the reconciliation effect treats them all as new.
  function openRegex(prefill: string) {
    setRegexDraft(prefill);
    setRegexQuery(prefill);
    setRegexPick(new Set());
    regexNamesRef.current = [];
    setRegexOpen(true);
    setSel(null);
    scopeRef.current = null;
  }

  // Leave the editor without committing — back to the guided picks.
  function closeRegex() {
    setRegexOpen(false);
    setRegexDraft('');
    setRegexQuery('');
    setRegexPick(new Set());
    regexNamesRef.current = [];
  }

  // Commit the hand-written regex as a pattern pick: encode the source with only the ticked
  // named groups, drop it into the extras box (its own line, so commas in the source survive),
  // and re-plan. Then close the editor — the new rows appear in the "pattern you picked" group
  // and the box, where it can be edited or removed like any other pick.
  function applyRegexRule() {
    if (!regexInfo?.valid) return;
    const picked = regexGroupNames.filter(name => regexPick.has(name));
    if (!picked.length || !regexInfo.matches) return;
    addExtra(encodePatternExtra(regexQuery.trim(), picked), 'picked');
    setRegexDraft('');
    setRegexQuery('');
    setRegexPick(new Set());
    regexNamesRef.current = [];
    setRegexOpen(false);
  }

  function stopLiveCapture() {
    stopCaptureRef.current = true;
  }

  async function fetchLiveCapture() {
    if (!groupId) return;
    // Batch tuning: short windows keep each request well inside the iframe proxy's ~30s cap and
    // let events show up a handful at a time. We keep looping windows until we reach the user's
    // target event count, exhaust their total duration budget, or they hit Stop.
    const BATCH_EVENTS = 25;
    const BATCH_WINDOW_MS = 4000;
    const totalBudgetMs = Math.max(1, captureDuration) * 1000;
    const filter = captureFilter || 'true';
    const label = groups.find(g => g.id === groupId)?.name || groupId;

    stopCaptureRef.current = false;
    setCaptureLoading(true);
    setCaptureProgress(0);
    setCapturedEvents([]);
    setRaw('');
    setError('');

    const seen = new Set<string>();
    const collected: string[] = [];
    const startedAt = Date.now();
    let lastError = '';
    try {
      while (
        !stopCaptureRef.current &&
        collected.length < captureMaxEvents &&
        Date.now() - startedAt < totalBudgetMs
      ) {
        const remainingEvents = captureMaxEvents - collected.length;
        const remainingMs = totalBudgetMs - (Date.now() - startedAt);
        const batchEvents = Math.min(BATCH_EVENTS, remainingEvents);
        const windowMs = Math.max(500, Math.min(BATCH_WINDOW_MS, remainingMs));
        let data: { events: string[]; count: number };
        try {
          data = await liveCapture(groupId, filter, batchEvents, windowMs);
        } catch (err) {
          lastError = err instanceof Error ? err.message : 'Live capture failed';
          break;
        }
        let added = false;
        for (const evt of data.events || []) {
          if (seen.has(evt)) continue;
          seen.add(evt);
          collected.push(evt);
          added = true;
          if (collected.length >= captureMaxEvents) break;
        }
        if (added) {
          setRaw(normaliseSampleInput(collected.join('\n')));
          setCaptureProgress(collected.length);
          setCapturedEvents([...collected]);
          setSourceLabel(`live capture · ${label}`);
        }
      }
    } finally {
      setCaptureLoading(false);
      stopCaptureRef.current = false;
    }

    if (collected.length === 0) {
      setError(
        lastError ||
          `No events matched "${filter}" during the ${captureDuration}s window. Ensure traffic is flowing and the filter matches your data.`,
      );
    } else if (lastError) {
      // Partial capture: keep what we got, but surface why it stopped early.
      setError(`Capture stopped early after ${collected.length} event(s): ${lastError}`);
    }
  }

  function toggleEntry(original: string, kind: string) {
    setPlan(current => current
      ? { ...current, entries: current.entries.map(item =>
        item.original === original && item.kind === kind ? { ...item, enabled: !item.enabled } : item) }
      : current);
  }

  // Tick or untick a whole group at once — with tens of thousands of entries the decision is
  // about the kind, not the value.
  function setGroup(originals: Set<string>, on: boolean) {
    setPlan(current => current
      ? { ...current, entries: current.entries.map(item =>
        originals.has(item.original) ? { ...item, enabled: on } : item) }
      : current);
  }

  function updateAlias(original: string, kind: string, alias: string) {
    setPlan(current => current
      ? { ...current, entries: current.entries.map(item =>
        item.original === original && item.kind === kind ? { ...item, alias } : item) }
      : current);
  }

  function applyPlan() {
    setError('');
    setSurvivors([]);
    // Apply mode is ADVISORY (the pack generator, not the strict library gate). Run the
    // shared compute without throwing, then block ONLY on a genuinely unusable result —
    // nothing changed, or the wire format is structurally broken (a delimiter/whitespace
    // shift the pipeline could not parse). A verification "fail" (e.g. the sanitised events
    // no longer match the source's declared wire format) is passed back as a WARNING, not a
    // block: the reviewer keeps the sanitised sample and can undo it in the pack wizard. This
    // is the documented split in runSanitisation — pack-gen warns, the library throws.
    if (applyMode && onApply) {
      const run = runSanitisation(raw, sourcetype, plan?.entries || [], { verify: true });
      if (!run.changed || !run.liveEntries) {
        setError('The enabled replacements did not change this sample.');
        return;
      }
      if (!run.structure.ok) {
        setError('Sanitising shifted a delimiter or whitespace boundary — narrow the picks marked in red, then apply again.');
        return;
      }
      // Warn ONLY when sanitisation DEGRADED parseability — the raw sample parsed and the
      // sanitised one no longer does. If the original already failed the parser (real access
      // logs carry scanner probes / TLS handshakes / `408` timeout lines the regex can't read),
      // the sanitiser is not the cause, so blaming it ("no longer pass the source parser") is a
      // false alarm that leaves the user with nothing to do but undo a sample that was fine.
      const degraded = run.verification?.verdict === 'fail'
        && run.verificationBefore?.verdict !== 'fail';
      const warning = degraded
        ? `Sanitising changed the events enough that the ${sourcetype} parser no longer reads them cleanly: ${run.verification!.reasons.join(' ')}`
        : null;
      onApply(run.events, sourcetype, warning);
      onClose();
      return;
    }
    try {
      const verified = applyAndVerifySanitisation(raw, sourcetype, plan?.entries || []);
      // Held only in memory so "Back" from the save step can restore the review. Cleared on
      // close and after a successful save (see the reset effect and `save`), so the one-way
      // privacy boundary still holds the moment the user actually leaves the wizard.
      preApply.current = { raw, plan, extraText, sourcetype };
      // The privacy boundary: displayed state keeps only sanitised text after apply. The
      // original and replacement map leave `plan`/`raw`; the sole copy is the in-memory
      // snapshot above, which Back consumes and reset/save discard.
      setRaw(verified.text);
      setApplied(verified);
      setPlan(null);
      // Seed the worker-group filename from the sourcetype (the reviewer can rename it on the
      // save step) so the field is never empty when they tick "Upload to worker group".
      setGroupSampleName(`${sanitisedSampleKey(sourcetype, recognition?.format.id).replace(/::/g, '__')}.log`);
      setStep('save');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      if (err instanceof SanitisationBlocked && err.survivors.length) setSurvivors(err.survivors);
      // Bring the blocker into view — it renders at the top of the body, above the fold.
      requestAnimationFrame(() => alertRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }));
    }
  }

  // Back from the save step: restore the pre-apply review so the reviewer can adjust picks
  // and re-apply, rather than being stranded on save with no way back.
  function backFromSave() {
    const snap = preApply.current;
    if (snap) {
      setRaw(snap.raw);
      setPlan(snap.plan);
      setExtraText(snap.extraText);
      setSourcetype(snap.sourcetype);
    }
    setApplied(null);
    setError('');
    setStep('sanitize');
  }

  function buildDoc(): SanitisedSampleDoc {
    if (!applied || !recognition) throw new Error('Apply and verify the sanitisation first.');
    return buildSanitisedSampleDoc({
      sourcetype,
      format: recognition.format.id,
      events: applied.events,
      verification: applied.verification,
      provenance: {
        sourceMode,
        sourceLabel: sourceLabel || `${sourceMode} sample`,
        replacementsApplied: applied.replacementsApplied,
        structurePreserved: applied.structure.ok,
        coverage: {
          total: applied.coverage.total,
          replaced: applied.coverage.replaced,
          ok: applied.coverage.ok,
          blind: applied.coverage.blind,
        },
        sanitisedAt: new Date().toISOString(),
      },
    });
  }

  // One card, one action. Runs the destination's own function, records its inline
  // confirmation or failure against the card id, and lets the operator do the next
  // one (or none) — there is no single "Save selected" gate any more.
  async function runAction(id: string, fn: () => Promise<string> | string) {
    setActionBusy(id);
    setActionErr(e => ({ ...e, [id]: '' }));
    try {
      const msg = await fn();
      setActionDone(d => ({ ...d, [id]: msg }));
      // A durable write means the sanitised sample is out; drop the last in-memory copy of
      // the original. A download is not durable in that sense, so it leaves Back available.
      if (id !== 'download') preApply.current = null;
    } catch (err) {
      setActionErr(e => ({ ...e, [id]: err instanceof Error ? err.message : String(err) }));
    } finally {
      setActionBusy('');
    }
  }

  // Add the sanitised sample to this generator's local library (Pack Generator only).
  async function saveLocalAction(): Promise<string> {
    const saved = await saveSanitisedSample(buildDoc());
    if (!saved.ok) throw new Error(saved.error || 'Could not save in the app library.');
    onLibraryChanged?.();
    return saved.storedIn === 'config' ? 'Saved in config/sanitised-samples/'
      : saved.storedIn === 'app-kv' ? 'Saved in this app installation' : 'Saved in this browser';
  }

  // Create or replace a group-level sample on the chosen worker group.
  async function uploadAction(): Promise<string> {
    if (!groupId) throw new Error('Choose the destination worker group.');
    const doc = buildDoc();
    // Reviewer-chosen filename, sanitised to a safe sample name; an empty box falls back
    // to the key-derived default. Cribl expects a plain filename, so strip path separators.
    const fallback = `${doc.key.replace(/::/g, '__')}.log`;
    let name = (groupSampleName.trim() || fallback).replace(/[/\\]/g, '_');
    if (!/\.[a-z0-9]+$/i.test(name)) name += '.log';
    await uploadWorkerGroupSample(groupId, name, doc.events);
    return `Uploaded to ${groupId} as ${name}`;
  }

  // Publish to the shared team pool (standalone dev-server GitHub write only).
  async function publishAction(): Promise<string> {
    if (!canPublish) throw new Error('Configure the dedicated sanitised-sample repository in Settings first.');
    const published = await publishSanitisedSample(buildDoc());
    if (!published.published) throw new Error(published.error || published.reason || 'Publish failed.');
    return 'Published to the shared sample pool';
  }

  if (!open) return null;
  return (
    // The click guard is load-bearing, not decoration: this wizard is opened from a
    // screen whose backdrop closes on click, and a leaked click dismissed both dialogs.
    // Embedded: no modal semantics (it IS the page) — a region, not a dialog.
    <div className={embedded ? 'sz-overlay sz-embedded' : 'sz-overlay'}
      role={embedded ? 'region' : 'dialog'} aria-modal={embedded ? undefined : true} aria-label="Sanitize a sample"
      onClick={event => event.stopPropagation()}>
      <div className="sz-modal">
        <header className="sz-header">
          <div>
            <div className="sz-eyebrow">{applyMode ? 'Pack generator' : 'Sample library'}</div>
            <h2>{applyMode ? 'Sanitize this sample' : 'Sanitize a sample'}</h2>
          </div>
          {!embedded && <button className="sz-close" onClick={onClose} aria-label="Close">×</button>}
        </header>

        {/* One step in apply mode — a rail would just show a lone "Sanitize" chip. */}
        {!applyMode && (
          <div className="sz-rail">
            {steps.map((item, index) => (
              <div className={`sz-step ${index === activeIndex ? 'active' : ''} ${index < activeIndex ? 'done' : ''}`} key={item.id}>
                <span>{index < activeIndex ? '✓' : index + 1}</span><b>{item.label}</b>
              </div>
            ))}
          </div>
        )}

        <main className="sz-body">
          <div className="sz-privacy">🔒 Detection, parsing and replacement happen locally. The original events are discarded after Apply.</div>
          {error && (
            <div ref={alertRef} className="sz-alert sz-alert-block" role="alert">
              <div className="sz-alert-head"><span className="sz-alert-icon" aria-hidden="true">⚠</span><span>{error}</span></div>
              {survivors.length > 0 && (
                <ul className="sz-alert-list">
                  {survivors.map((s, i) => (
                    <li key={`${s.line}-${s.field}-${i}`}>
                      <span className="sz-alert-line">Line {s.line}</span>
                      <span className="sz-alert-field">{s.field}</span>
                      <span className="sz-alert-still">still shows</span>
                      <code className="sz-alert-val">{s.value}</code>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
          {result && <div className="sz-note sz-success">{result}</div>}

          {step === 'events' && <>
            <h3>Choose customer events</h3>
            {/* Same source options and tile layout as the new-pack "provide sample events"
                screen — minus AI-generate, which produces synthetic data that needs no
                sanitising. */}
            <div className="field">
              <label>How do you want to provide sample events?</label>
              <div className="tile-grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))' }}>
                <div className={sourceMode === 'upload' ? 'tile active' : 'tile'}
                  onClick={() => setSourceMode('upload')}>
                  <span className="tile-icon">{'\u{1F4C1}'}</span>
                  <strong className="tile-name">Upload file</strong>
                  <span className="tile-meta">JSON, log, txt, csv</span>
                </div>
                <div className={sourceMode === 'group' ? 'tile active' : 'tile'}
                  onClick={() => setSourceMode('group')}>
                  <span className="tile-icon">{'\u{1F4BE}'}</span>
                  <strong className="tile-name">Group sample</strong>
                  <span className="tile-meta">Pick from worker group</span>
                </div>
                <div className={sourceMode === 'paste' ? 'tile active' : 'tile'}
                  onClick={() => setSourceMode('paste')}>
                  <span className="tile-icon">{'\u{1F4CB}'}</span>
                  <strong className="tile-name">Paste events</strong>
                  <span className="tile-meta">One per line or JSON</span>
                </div>
                <div className={sourceMode === 'live-capture' ? 'tile active' : 'tile'}
                  onClick={() => { setSourceMode('live-capture'); setCaptureFilter('true'); }}>
                  <span className="tile-icon">{'\u{1F4E1}'}</span>
                  <strong className="tile-name">Live capture</strong>
                  <span className="tile-meta">Capture from worker group</span>
                </div>
              </div>
            </div>
            {sourceMode === 'upload' && <div className="sz-drop" onClick={() => fileRef.current?.click()}>
              <strong>{sourceLabel || 'Choose a .log, .txt or .json file'}</strong>
              <small>{raw ? `${raw.split('\n').filter(Boolean).length} events loaded` : 'The file stays in this browser.'}</small>
              {/* The input is a CHILD of the drop zone whose onClick calls fileRef.click(); a
                  programmatic click bubbles back here and would re-enter that onClick — an
                  infinite recursion that crashes the view. Stop the bubbled click at the input. */}
              <input ref={fileRef} hidden type="file" accept=".log,.txt,.json,.ndjson,.csv,.xml"
                onClick={event => event.stopPropagation()}
                onChange={event => {
                  const file = event.target.files?.[0];
                  if (!file) return;
                  const input = event.currentTarget;
                  void file.text()
                    .then(text => { setRaw(normaliseSampleInput(text)); setSourceLabel(file.name); setError(''); })
                    .finally(() => { input.value = ''; });
                }} />
            </div>}
            {sourceMode === 'paste' && <textarea className="sz-textarea" rows={12} value={raw}
              onChange={event => { setRaw(event.target.value); setSourceLabel('pasted events'); }}
              placeholder="Paste one event per line…" />}
            {sourceMode === 'group' && <div className="sz-group-pick">
              <label className="sz-field">Worker group
                <select value={groupId} onChange={event => { setGroupId(event.target.value); setSampleId(''); setSamplePackId(''); setSampleSearch(''); }}>
                  <option value="">Choose a group…</option>{groups.map(group => <option key={group.id} value={group.id}>{group.name || group.id}</option>)}
                </select></label>
              {groupId && <div className="sz-sample-search">
                <input value={sampleSearch} onChange={event => setSampleSearch(event.target.value)}
                  placeholder="Search samples by name or pack…" aria-label="Search samples" />
                <div className="sz-sample-list" role="listbox">
                  {filteredSamples.length === 0 && <div className="sz-sample-empty">
                    {samples.length === 0 ? 'No samples in this group.' : 'No samples match your search.'}
                  </div>}
                  {filteredSamples.map(sample => {
                    const key = sample.packId ? `${sample.packId}:${sample.id}` : sample.id;
                    const selected = sampleId === sample.id && samplePackId === (sample.packId || '');
                    return <button type="button" key={key} role="option" aria-selected={selected}
                      className={`sz-sample-row${selected ? ' sz-sample-row-sel' : ''}`}
                      onClick={() => { setSampleId(sample.id); setSamplePackId(sample.packId || ''); }}>
                      <span className="sz-sample-name">{sample.name}</span>
                      {sample.packName && <span className="sz-sample-pack" title={`From pack: ${sample.packName}`}>📦 {sample.packName}</span>}
                      <span className="sz-sample-count">{sample.numEvents || '?'} events</span>
                    </button>;
                  })}
                </div>
              </div>}
            </div>}
            {sourceMode === 'live-capture' && <div className="sz-capture">
              <p className="sz-note">Captures real events flowing through the selected worker group. Only groups with a connected worker are listed. Ensure traffic is actively being processed.</p>
              <label className="sz-field">Worker group
                <select value={groupId} onChange={event => setGroupId(event.target.value)}>
                  <option value="">Choose a group…</option>{capturableGroups.map(group => <option key={group.id} value={group.id}>{group.name || group.id} · {group.workerCount} worker{group.workerCount === 1 ? '' : 's'}</option>)}
                </select></label>
              {capturableGroups.length === 0 && <small className="sz-note sz-warn">No worker group currently has a connected worker, so there is nothing to capture from. Start a worker or use Upload / Paste instead.</small>}
              <label className="sz-field">Filter expression
                <input value={captureFilter} onChange={event => setCaptureFilter(event.target.value)}
                  placeholder="true for all events, or sourcetype=='cisco_asa'" /></label>
              <div className="sz-fields">
                <label>Max events<input value={captureMaxEvents}
                  onChange={event => setCaptureMaxEvents(Math.min(500, Math.max(1, Number(event.target.value) || 100)))} /></label>
                <label>Duration (seconds)<input value={captureDuration}
                  onChange={event => setCaptureDuration(Math.min(30, Math.max(1, Number(event.target.value) || 10)))} /></label>
              </div>
              <div className="sz-capture-actions">
                <button className="sz-primary sz-capture-start" disabled={!groupId || captureLoading} onClick={() => void fetchLiveCapture()}>
                  {captureLoading
                    ? `Capturing… (${captureProgress}/${captureMaxEvents})`
                    : `▶ Start capture (${captureMaxEvents} events, ${captureDuration}s)`}
                </button>
                {captureLoading && <button className="sz-secondary" onClick={stopLiveCapture}>Stop</button>}
              </div>
              {/* Live preview — the reviewer watches events land here and confirms they're the
                  right ones BEFORE moving on to identify the source. */}
              {capturedEvents.length > 0 && <div className="sz-capture-live">
                <div className="sz-capture-live-head">
                  <strong>{capturedEvents.length} event{capturedEvents.length === 1 ? '' : 's'} captured</strong>
                  {captureLoading ? <span className="sz-note">streaming…</span> : <span className="sz-note">stopped — review below, then identify the source</span>}
                </div>
                <div className="sz-capture-live-body">
                  {capturedEvents.slice(-50).map((evt, i) => <div key={i} className="sz-capture-line">{evt}</div>)}
                </div>
                {capturedEvents.length > 50 && <small className="sz-note">Showing the latest 50 of {capturedEvents.length}.</small>}
              </div>}
              {captureLoading && capturedEvents.length === 0 && <small className="sz-note">Waiting for the first events to arrive…</small>}
            </div>}
          </>}

          {step === 'source' && <>
            <h3>Confirm the source</h3>
            <div className="sz-detected"><b>{recognition?.display || 'Source not recognised'}</b><span>auto-detected · {recognition?.confidence} confidence · {recognition?.method} · offline</span></div>
            <p>{recognition?.reason}</p>
            {!!recognition?.alternatives?.length && <div className="sz-note" style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
              <span>Not right? Other close matches:</span>
              {recognition.alternatives.map(alt => (
                <button key={alt} type="button" className="sz-secondary"
                  aria-pressed={canonicalizeSourcetype(sourcetype) === alt}
                  onClick={() => setSourcetype(alt)}>{alt}</button>
              ))}
            </div>}
            <label className="sz-field">Sourcetype
              <input value={sourcetype} onChange={event => setSourcetype(event.target.value)}
                placeholder="start typing — e.g. cisco_asa, pan_traffic_syslog"
                list="sz-sourcetype-catalog" autoComplete="off" spellCheck={false} />
            </label>
            <datalist id="sz-sourcetype-catalog">
              {sourcetypeCatalog.map(name => <option key={name} value={name} />)}
            </datalist>
            {sourceCheck && (sourceCheck.readable > 0
              ? <div className="sz-note" style={{ color: '#2e7d32' }}>
                  ✓ The {sourceCheck.parserName || sourceCheck.canonical} parser reads {sourceCheck.readable} of {sourceCheck.total} line{sourceCheck.total === 1 ? '' : 's'}
                  {sourceCheck.parserName && sourceCheck.parserName !== sourceCheck.canonical ? ` (sanitising with the ${sourceCheck.parserName} parser)` : ''}.
                </div>
              : <div className="sz-note" style={{ color: '#b26a00' }}>
                  ⚠ No parser recognises “{sourceCheck.canonical}” — values will be masked by pattern only, and the save may be blocked if identifying values can’t be proven changed.
                </div>)}
            <div className="sz-note">{recognition?.format.label}: {recognition?.format.detail}</div>
          </>}

          {step === 'sanitize' && <>
            <h3>Review replacements</h3>
            <p>{enabled} of {plan?.entries.length || 0} detected values will be replaced consistently.</p>
            {/* Shown only when the secret rules could not be loaded. It has to name what is
                STILL running: "secret detection unavailable" on its own reads as "checked,
                nothing found", which is the one impression that could get a live token shared. */}
            {secretNotice && <div className="sz-note sz-warn">⚠ {secretNotice}</div>}
            <div className="sanitise-pick">
              <label>Events — highlight anything else that has to go</label>
              {/* Events before and after, side by side. Left is the real textarea (the
                  drag-select surface — offsets come straight off it), with a transparent-text
                  backdrop behind it that marks the values about to change IN PLACE, so the
                  reviewer sees directly which parts of the original are going. The RIGHT pane
                  shows the sanitised result marked the same way, built from the same replacer as
                  Apply and always rendered so the after can never quietly disappear. Both panes
                  scroll-sync and share a line budget so they read across. */}
              <div className="sanitise-beforeafter">
                <div className="sanitise-ba-col">
                  <div className="sanitise-ba-tag sanitise-ba-tag-before">
                    <span aria-hidden="true">✎ </span>before
                    <span className="sz-pick-hint"> — select text to mask</span>
                  </div>
                  <div className="sanitise-ba-input">
                    {/* The backdrop mirrors the textarea's metrics exactly (same font, padding,
                        wrapping) and renders each line's beforeSpans; its text is transparent, so
                        only the mark backgrounds show through under the textarea's real glyphs. */}
                    <div ref={backdropRef} className="sanitise-before-backdrop" aria-hidden="true">
                      {preview.lines.map(line => (
                        <div key={line.lineNo}
                          className={survivors.some(s => s.line === line.lineNo) ? 'sanitise-before-line survivor' : 'sanitise-before-line'}>
                          {renderPreviewSpans(line.before, line.beforeSpans, 'sanitise-before-mark', 'sanitise-before-try', 'sanitise-before-bad')}
                        </div>
                      ))}
                    </div>
                    <textarea ref={sampleRef} readOnly className="sanitise-sample"
                      value={beforeDisplay} rows={1}
                      onSelect={onSampleSelect} onMouseUp={onSampleSelect} onKeyUp={onSampleSelect}
                      onScroll={() => {
                        if (syncing.current || !sampleRef.current) return;
                        syncing.current = true;
                        if (afterRef.current) afterRef.current.scrollTop = sampleRef.current.scrollTop;
                        if (backdropRef.current) backdropRef.current.scrollTop = sampleRef.current.scrollTop;
                        syncing.current = false;
                      }} />
                  </div>
                </div>
                <div className="sanitise-ba-col">
                  <div className="sanitise-ba-tag sanitise-ba-tag-after">
                    after
                    {preview.badKeys.size
                      ? (
                        <span className="sz-pick-hint sz-pick-hint-bad">
                          {` — ${preview.badKeys.size} mask${preview.badKeys.size === 1 ? '' : 's'} shift a delimiter/whitespace boundary (red) and will block the save — narrow the pick or mask the value only`}
                        </span>
                      )
                      : (
                        <span className="sz-pick-hint">
                          {activeProvisional?.tryKeys.size
                            ? ' — previewing your pick (highlighted); “Mask it” to keep'
                            : preview.totalChanged
                              ? ` — ${preview.totalChanged}${preview.totalChanged === 1 ? ' line changes' : ' lines change'}`
                              : ' — nothing changes yet'}
                        </span>
                      )}
                    <span className="sanitise-ba-ro" aria-label="read-only result">🔒 read-only</span>
                  </div>
                  <div ref={afterRef} className="sanitise-sample sanitise-after"
                    onScroll={() => {
                      if (syncing.current || !afterRef.current) return;
                      syncing.current = true;
                      if (sampleRef.current) sampleRef.current.scrollTop = afterRef.current.scrollTop;
                      if (backdropRef.current) backdropRef.current.scrollTop = afterRef.current.scrollTop;
                      syncing.current = false;
                    }}>
                    {preview.lines.map(line => (
                      <div key={line.lineNo} className="sanitise-after-line">
                        {renderPreviewSpans(line.after, line.afterSpans, 'sanitise-preview-ins', 'sanitise-preview-try', 'sanitise-preview-bad')}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              {previewTruncated && (
                <div className="field-hint sanitise-fold-more">
                  Previewing the first {PREVIEW_LINE_CAP} of {beforeLines.length} lines. All {beforeLines.length} are
                  sanitised on Apply — the rest just aren't rendered here.
                </div>
              )}
              {/* Directly under the before/after panes: EITHER the "write your own regex"
                  editor (when open) OR the guided picks. Opening the editor replaces the
                  guided options entirely (the reviewer chose to hand-write instead), and its
                  live match/preview lands in the same panes above. */}
              {regexOpen ? (
                <div className="sanitise-regex sanitise-regex-open">
                  <div className="sanitise-regex-head">
                    <span className="sanitise-regex-title">Write your own regex</span>
                    <button type="button" className="btn-link"
                      onMouseDown={event => event.preventDefault()} onClick={closeRegex}>← back to guided masks</button>
                  </div>
                  <input className="sanitise-regex-input" spellCheck={false}
                    autoCapitalize="off" autoCorrect="off" autoComplete="off"
                    value={regexDraft} placeholder={'(?<g1>\\S+)\\s(?<g2>\\d+)'}
                    aria-label="Regular expression" autoFocus
                    onChange={event => setRegexDraft(event.target.value)} />
                  <span className="sz-pick-hint">
                    The regex only <b>extracts</b> — name a capture group with <code>{'(?<name>…)'}</code>
                    {' '}and it becomes a field. Then pick the fields to mask below; anything you don't
                    pick stays as context. The panes above highlight what it hits as you type.
                  </span>
                  {regexQuery.trim() && regexInfo && !regexInfo.valid && (
                    <div className="sz-note sz-danger">
                      Not a valid regular expression{regexInfo.error ? `: ${regexInfo.error}` : ''}.
                    </div>
                  )}
                  {regexInfo?.valid && regexQuery.trim() && (
                    regexInfo.groups.length === 0 ? (
                      <div className="sz-pick-hint sanitise-regex-empty">
                        No named capture groups yet — add one like <code>{'(?<id>\\d+)'}</code> so
                        there is a field to mask.{regexInfo.matches ? ` The pattern matches ${regexInfo.matches} place${regexInfo.matches === 1 ? '' : 's'}.` : ' It matches nothing here yet.'}
                      </div>
                    ) : (
                      <>
                        <div className="sanitise-regex-groups-head">
                          Fields to mask{regexInfo.matches ? ` · ${regexInfo.matches} match${regexInfo.matches === 1 ? '' : 'es'}` : ' · no matches yet'}
                        </div>
                        {/* Each named group is a small toggle pill, side by side — tap to
                            include/exclude it from the mask. The example capture rides along as
                            a tooltip so the row stays compact. */}
                        <div className="sanitise-regex-groups">
                          {regexInfo.groups.map(group => (
                            <button type="button" key={group.name}
                              className={regexPick.has(group.name) ? 'sanitise-regex-field on' : 'sanitise-regex-field'}
                              aria-pressed={regexPick.has(group.name)}
                              title={group.hits ? `e.g. ${group.sample} · ${group.hits}×` : 'no match yet'}
                              onMouseDown={event => event.preventDefault()}
                              onClick={() => setRegexPick(prev => {
                                const next = new Set(prev);
                                if (next.has(group.name)) next.delete(group.name); else next.add(group.name);
                                return next;
                              })}>
                              <code className="sanitise-regex-field-name">{group.name}</code>
                              {group.hits ? <span className="sanitise-regex-field-eg">{group.sample}</span> : null}
                            </button>
                          ))}
                        </div>
                        <button type="button" className="sz-primary sz-pick-btn sanitise-choices-apply"
                          disabled={!regexPick.size || !regexInfo.matches}
                          onMouseDown={event => event.preventDefault()}
                          onClick={applyRegexRule}>
                          {`Mask ${regexPick.size || 'the'} field${regexPick.size === 1 ? '' : 's'}`}
                        </button>
                      </>
                    )
                  )}
                </div>
              ) : (
                <div className={sanitiseChoices.length ? 'sz-pick' : 'sz-pick sz-pick-idle'}>
                  {!sel ? (
                    <div className="sanitise-pick-idle">
                      <span className="sz-pick-hint">Drag over a hostname, username or ID — double-click picks a whole word.
                        Land inside a <code>field=value</code> pair to take the whole field, or highlight a composite like
                        <code> host[123]:</code> — then pick, in plain words, what to mask. Select a whole span and
                        highlight one part inside it to mask only that.</span>
                      <button type="button" className="sanitise-regex-toggle"
                        onMouseDown={event => event.preventDefault()} onClick={() => openRegex('')}>Write your own regex</button>
                    </div>
                  ) : sanitiseChoices.length === 0 ? (
                    <div className="sanitise-pick-idle">
                      <span className="sz-pick-no">{sel.reason || 'Nothing there can be masked on its own.'}</span>
                      <button type="button" className="sanitise-regex-toggle"
                        onMouseDown={event => event.preventDefault()} onClick={() => openRegex(regexFromSelection(sel.selected))}>Write your own regex</button>
                    </div>
                  ) : (
                    <div className="sanitise-choices sanitise-steps">
                      {/* Three numbered steps on a connecting rail (design: value-strip part
                          picker). 1 = WHAT (the whole value, or a part of it — dragged or tapped
                          on the value itself); 2 = MATCH BY (its FORMAT/any value here, or the
                          EXACT text) with the produced regex and its single "Edit regex" entry
                          sitting right where the regex is; 3 = MASK IT. The tokens come from the
                          shared `buildSanitiseChoices`, so the panel can never diverge from the
                          rule that is actually applied. */}
                      <div className="sanitise-step">
                        <div className="sanitise-step-rail"><span className="sanitise-step-num">1</span><span className="sanitise-step-spine" /></div>
                        <div className="sanitise-step-body">
                        <div className="sanitise-q-head">What should be masked?</div>
                        {/* No mode gate: the value IS the picker. "Whole value" is the pre-selected
                            default (so step 2 is populated from the start); tapping a piece — or
                            dragging across the strip — IS choosing "a part". The two are one control,
                            so it is always unambiguous what will be masked. */}
                        {refinable ? (
                          <div className="sanitise-strip-wrap">
                            <div className="sanitise-strip-hint">The whole value is masked by default — or drag across it, or tap a piece, to mask only that part (more than one is fine):</div>
                            <div ref={stripRef} className="sanitise-strip" onMouseUp={onStripSelect}>{wholeValueText}</div>
                            <div className="sanitise-strip-pieces">
                              <span className="sanitise-strip-pieces-label">Mask:</span>
                              <button type="button"
                                className={maskTarget === 'whole' ? 'sanitise-piece-chip whole on' : 'sanitise-piece-chip whole'}
                                aria-pressed={maskTarget === 'whole'}
                                onMouseDown={event => event.preventDefault()}
                                onClick={() => { setMaskTarget('whole'); setPartRanges([]); window.getSelection()?.removeAllRanges(); }}>
                                Whole value
                              </button>
                              {valuePieces.length > 0 && <span className="sanitise-piece-sep" aria-hidden="true" />}
                              {valuePieces.map(piece => (
                                <button type="button" key={`${piece.start}-${piece.end}`}
                                  className={maskTarget === 'part' && pieceIsPicked(piece.start, piece.end)
                                    ? 'sanitise-piece-chip on' : 'sanitise-piece-chip'}
                                  onMouseDown={event => event.preventDefault()}
                                  onClick={() => togglePartPiece(piece.start, piece.end)}>
                                  {piece.text}
                                </button>
                              ))}
                            </div>
                            {maskTarget === 'part' && partMask && (
                              <div className="sanitise-strip-out">
                                Masking <b>{partMask.shape.groups.map(g => g.sample).join(', ')}</b> in place — the rest of the value stays
                                {partMask.matches ? ` · ${partMask.matches} place${partMask.matches === 1 ? '' : 's'}` : ''}.
                              </div>
                            )}
                            {maskTarget === 'part' && partRanges.length > 0 && !partMask && (
                              <div className="sanitise-strip-out">Pick a part of the value to mask.</div>
                            )}
                          </div>
                        ) : (
                          <div className="sanitise-q-whole-note">The whole value will be masked.</div>
                        )}
                        </div>
                      </div>
                      <div className="sanitise-step">
                        <div className="sanitise-step-rail"><span className="sanitise-step-num">2</span><span className="sanitise-step-spine" /></div>
                        <div className="sanitise-step-body">
                        <div className="sanitise-q-head">Match by…</div>
                        {maskTarget === 'part' ? (
                          <>
                            {/* A picked part is pinned to this one place by its surrounding
                                punctuation; the choice left is whether the run ITSELF matches by
                                shape (a class like \d+ — any value like it, "wildcards") or exactly
                                (only this literal value, e.g. 12345). Both keep the context literal.
                                The produced regex is shown, and "Write your own regex" opens it to edit. */}
                            <div className="sanitise-seg-toggle">
                              <button type="button" className={partMatchBy === 'shape' ? 'on' : ''}
                                onMouseDown={event => event.preventDefault()}
                                onClick={() => setPartMatchBy('shape')}>Based on wildcards — any value like it</button>
                              <button type="button" className={partMatchBy === 'exact' ? 'on' : ''}
                                onMouseDown={event => event.preventDefault()}
                                onClick={() => setPartMatchBy('exact')}>Exact — only this value</button>
                            </div>
                            {partMask ? (
                              <div className="sanitise-q-note">
                                {partMatchBy === 'shape' ? (
                                  <><b>Any</b> value shaped like <code>{partMask.shape.groups.map(g => g.classRe).join(' · ')}</code> in this spot — the punctuation around it stays.</>
                                ) : (
                                  <><b>Only</b> <code>{partMask.shape.groups.map(g => g.sample).join(', ')}</code> where it sits here — other values in the same spot are left alone.</>
                                )}
                              </div>
                            ) : (
                              <div className="sanitise-q-note">Pick a part of the value above to mask.</div>
                            )}
                          </>
                        ) : (formatChoice || exactChoice) ? (
                          <>
                            <div className="sanitise-seg-toggle">
                              {formatChoice && (
                                <button type="button" className={matchBy === 'format' ? 'on' : ''}
                                  onMouseDown={event => event.preventDefault()}
                                  onClick={() => setMatchBy('format')}>Format — any value here</button>
                              )}
                              {exactChoice && (
                                <button type="button" className={matchBy === 'exact' ? 'on' : ''}
                                  onMouseDown={event => event.preventDefault()}
                                  onClick={() => setMatchBy('exact')}>Exact — only this text</button>
                              )}
                            </div>
                            {(() => {
                              const active = matchBy === 'format' ? (formatChoice ?? exactChoice) : (exactChoice ?? formatChoice);
                              return active ? (
                                <div className="sanitise-q-note">
                                  <b>{active.label}</b> — {active.detail}
                                </div>
                              ) : null;
                            })()}
                          </>
                        ) : null}
                        {/* The produced regex and its single hand-write entry, right where the
                            regex is. In the part flow the box shows the pattern that will be
                            applied; in the whole-value flow the editor opens prefilled from the
                            selection. "Edit regex" is styled like the other buttons on the panel,
                            and is the ONLY way into the hand-written editor from here. */}
                        {maskTarget === 'part' && partMask ? (
                          <div className="sanitise-regex-strip">
                            <div className="sanitise-regex-strip-label">Regex</div>
                            <div className="sanitise-regex-strip-row">
                              <code className="sanitise-regex-strip-code">{partMask.shape.source}</code>
                              <button type="button" className="sanitise-regex-edit"
                                onMouseDown={event => event.preventDefault()}
                                onClick={() => openRegex(partMask.shape.source)}>✎ Edit regex</button>
                            </div>
                          </div>
                        ) : maskTarget !== 'part' && (formatChoice || exactChoice) ? (
                          <div className="sanitise-regex-strip">
                            <div className="sanitise-regex-strip-row">
                              <button type="button" className="sanitise-regex-edit"
                                onMouseDown={event => event.preventDefault()}
                                onClick={() => openRegex(regexFromSelection(sel.selected))}>✎ Edit regex</button>
                            </div>
                          </div>
                        ) : null}
                        </div>
                      </div>
                      <div className="sanitise-step">
                        <div className="sanitise-step-rail"><span className="sanitise-step-num">3</span></div>
                        <div className="sanitise-step-body">
                        <div className="sanitise-q-head">Mask it</div>
                        <button type="button" className="sz-primary sz-pick-btn sanitise-choices-apply"
                          disabled={!activeChoiceToken}
                          onMouseDown={event => event.preventDefault()} onClick={applySanitiseChoice}>Mask it</button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
            {/* Grouped by kind and folded shut by default: a credential is a fact and leads,
                a shape-only match is a guess and stays unticked; opening one with forty rows
                pushed the rest off the screen. What each group is and how many is on the
                header, and the sample above marks the values in place. Row rendering (incl.
                patternPatchDisplay for shape picks) matches the new-pack sanitiser. */}
            {(() => {
              if (!plan?.entries.length) return null;
              const row = (entry: SanitiseEntry) => {
                const patch = patternPatchDisplay(entry);
                return (
                  <label key={`${entry.kind}:${entry.original}`}
                    className={entry.enabled ? 'sanitise-row' : 'sanitise-row sanitise-row-off'}>
                    <input type="checkbox" checked={entry.enabled}
                      onChange={() => toggleEntry(entry.original, entry.kind)} />
                    <span className={entry.kind === 'secret' ? 'sanitise-kind sanitise-kind-secret' : 'sanitise-kind'}>
                      {entry.kind === 'ipv4' || entry.kind === 'ipv6' ? 'IP' : entry.kind === 'pii' ? 'PII' : entry.kind}
                    </span>
                    <code className="sanitise-from" title={patch ? `inside ${entry.original}` : undefined}>
                      {patch ? patch.from : entry.original}
                    </code>
                    <span className="sanitise-arrow">{'→'}</span>
                    <input className="sanitise-to" value={patch ? patch.to : entry.alias} spellCheck={false}
                      onChange={event => updateAlias(entry.original, entry.kind, event.target.value)} />
                    <span className="sanitise-count">{entry.count}{'×'}</span>
                    <span className="sanitise-via" title={patch ? entry.original : undefined}>
                      {patch ? `${entry.via} · in ${entry.original}` : entry.via}
                    </span>
                  </label>
                );
              };
              return groupEntries(plan.entries).map(group => {
                const originals = new Set(group.rows.map(entry => entry.original));
                const on = group.rows.filter(entry => entry.enabled).length;
                const occurrences = group.rows.reduce((total, entry) => total + entry.count, 0);
                const isOpen = openGroups[group.id] ?? false;
                const shown = isOpen ? group.rows.slice(0, SANITISE_ROW_CAP) : [];
                return (
                  <div key={group.id} className="sanitise-fold">
                    <div className={`sanitise-group ${group.className || ''}`}>
                      <button type="button" className="sanitise-fold-toggle" aria-expanded={isOpen}
                        onClick={() => setOpenGroups(state => ({ ...state, [group.id]: !isOpen }))}>
                        <span className="sanitise-fold-caret">{isOpen ? '▾' : '▸'}</span>
                        {group.rows.length} {group.label(group.rows.length)}
                        <span className="sanitise-fold-meta">
                          {occurrences}{'×'} in the sample
                          {on === group.rows.length ? '' : ` · ${on} of ${group.rows.length} ticked`}
                        </span>
                      </button>
                      <span className="sanitise-fold-actions">
                        <button type="button" className="btn-link" disabled={on === group.rows.length}
                          onClick={() => setGroup(originals, true)}>tick all</button>
                        <button type="button" className="btn-link" disabled={on === 0}
                          onClick={() => setGroup(originals, false)}>none</button>
                      </span>
                    </div>
                    <div className="sanitise-fold-note">{group.note(group.rows.length, plan)}</div>
                    {isOpen && (
                      <>
                        <div className="sanitise-rows">{shown.map(row)}</div>
                        {group.rows.length > shown.length && (
                          <div className="field-hint sanitise-fold-more">
                            Showing the first {shown.length} of {group.rows.length}. The rest are included —
                            ticking the group covers every one.
                          </div>
                        )}
                      </>
                    )}
                  </div>
                );
              });
            })()}
            {/* The typed form of the same list. Pasting a known set of names beats hunting
                for each in the events, and it is where a picked value, field or regex can be
                edited or removed. Values highlighted above land here too. */}
            <details className="sanitise-typed" open={!!extraText}>
              <summary>Or type them ({(() => { const s = splitExtras(extraText); return s.literals.length + s.fields.length + s.patterns.length; })()} added)</summary>
              <textarea className="sanitise-extra" rows={2} value={extraText}
                placeholder={'ACME, acme-core-01, field:quoteNumber\nre:id=(?<test>\\d+)|test'}
                onChange={event => replanFromText(event.target.value)} />
              <span className="sz-pick-hint" style={{ display: 'block', marginTop: 4 }}>
                Comma or line separated. A whole field reads as <code>field:quoteNumber</code>; a
                regex pick as <code>re:…|group</code> or <code>re:…|g1+g2</code> — each on its own
                line so a regex may contain commas. Delete one to put its values back.
              </span>
            </details>
            {!plan?.entries.length && <div className="sz-note sz-danger">No identifying values were found. Add a replacement rule before this sample can be saved.</div>}
            {!!plan?.entries.length && enabled === 0 && <div className="sz-note">Everything is unticked — tick at least one value (or a group header) to enable Apply.</div>}
          </>}

          {step === 'save' && applied && <>
            <h3>Save or share the sanitised sample</h3>
            <div className="sz-proof">
              <b>✓ Structure preserved</b><span>✓ Parser: {applied.verification.verdict}</span>
              <span>{applied.replacementsApplied} identities replaced</span>
            </div>

            {/* Pack Generator only — the standalone Sample Sanitizer (embedded) has no local
                sample library that anything consumes, so this destination is omitted there. */}
            {!embedded && <div className="sz-action">
              <b>Add to this generator's sample library</b>
              <small>Makes it a reusable, real-format sample the pack generator will pick for <code>{sourcetype || 'this sourcetype'}</code> — {runMode === 'standalone' ? 'stored in config/sanitised-samples/' : 'stored in this app installation (App KV, browser backup)'}</small>
              <div className="sz-action-bar">
                {actionErr.local ? <span className="sz-action-msg err">⚠ {actionErr.local}</span>
                  : actionDone.local ? <span className="sz-action-msg ok">✓ {actionDone.local}</span>
                  : <span className="sz-action-hint" />}
                <button className="sz-btn" disabled={!!actionBusy} onClick={() => void runAction('local', saveLocalAction)}>
                  {actionBusy === 'local' ? 'Adding…' : actionDone.local ? 'Add again' : 'Add to library'}</button>
              </div>
            </div>}

            <div className="sz-action">
              <b>Upload to worker group</b>
              <small>Creates or replaces a group-level sample both the pack generator and the standalone Sample Sanitizer can reuse — and a Stream pipeline can use directly. Select it in Routes / QuickConnect. No AI, no original data leaves the browser.</small>
              <div className="sz-dest-sub">
                <label className="sz-field">Worker group
                  <select value={groupId} onChange={e => setGroupId(e.target.value)}>
                    <option value="">Choose a group…</option>{groups.map(group => <option key={group.id} value={group.id}>{group.name || group.id}</option>)}
                  </select></label>
                <label className="sz-field">Sample name
                  <input value={groupSampleName} onChange={e => setGroupSampleName(e.target.value)} placeholder="my_sample.log" spellCheck={false} /></label>
              </div>
              <div className="sz-action-bar">
                {actionErr.upload ? <span className="sz-action-msg err">⚠ {actionErr.upload}</span>
                  : actionDone.upload ? <span className="sz-action-msg ok">✓ {actionDone.upload}</span>
                  : <span className="sz-action-hint" />}
                <button className="sz-btn" disabled={!!actionBusy} onClick={() => void runAction('upload', uploadAction)}>
                  {actionBusy === 'upload' ? 'Uploading…' : actionDone.upload ? 'Upload again' : 'Upload to worker group'}</button>
              </div>
            </div>

            <div className="sz-action">
              <b>Download sanitised log</b>
              <small>Saves the de-identified <code>.log</code> to your machine — the sanitised events, ready to share or attach.</small>
              <div className="sz-action-bar">
                {actionDone.download ? <span className="sz-action-msg ok">✓ {actionDone.download}</span> : <span className="sz-action-hint" />}
                <button className="sz-btn" onClick={() => void runAction('download', () => { triggerDownload(buildDoc(), 'log'); return 'Downloaded sanitised .log'; })}>⤓ Download .log</button>
              </div>
            </div>

            {/* Publishing to the team pool is standalone-only (GitHub write from the dev
                server). In the iframe app it can never run, so the option is omitted
                entirely rather than shown disabled. */}
            {runMode !== 'iframe' && <div className={`sz-action ${!canPublish ? 'disabled' : ''}`}>
              <b>Publish to shared sanitised-sample pool</b>
              {canPublish
                ? <small>Shares this sanitised sample with the team via <code>{repo}</code></small>
                : <small className="sz-dest-blocked">One-time setup: turn on “Share sanitised samples” and set a separate sample repository + write token in Settings, then reopen this wizard. (Your work here isn’t saved yet — download it above first if you leave.)</small>}
              <div className="sz-action-bar">
                {actionErr.publish ? <span className="sz-action-msg err">⚠ {actionErr.publish}</span>
                  : actionDone.publish ? <span className="sz-action-msg ok">✓ {actionDone.publish}</span>
                  : <span className="sz-action-hint" />}
                <button className="sz-btn" disabled={!canPublish || !!actionBusy} onClick={() => void runAction('publish', publishAction)}>
                  {actionBusy === 'publish' ? 'Publishing…' : actionDone.publish ? 'Publish again' : 'Publish to pool'}</button>
              </div>
            </div>}

            {/* The report and evidence JSON are their own downloads — not the sanitised log —
                so they sit on their own row at the bottom, styled like the other actions. */}
            <div className="sz-downloads">
              <button className="sz-btn" onClick={() => triggerDownload(buildDoc(), 'report')}>⤓ Download report (HTML / PDF)</button>
              <button className="sz-btn" onClick={() => triggerDownload(buildDoc(), 'json')}>⤓ Download evidence JSON</button>
            </div>
          </>}
        </main>

        <footer className="sz-footer">
          {applyMode && <button className="sz-secondary" onClick={onClose}>Cancel</button>}
          {/* Back stays available on the save step until a durable destination has committed —
              once the sample is out there is nothing to go back and re-edit. */}
          {!applyMode && activeIndex > 0 && !(step === 'save' && (actionDone.local || actionDone.upload || actionDone.publish)) && <button className="sz-secondary"
            onClick={step === 'save' ? backFromSave : () => setStep(steps[activeIndex - 1].id)}>Back</button>}
          <span />
          {step === 'events' && <button className="sz-primary" disabled={!!busy} onClick={() => void identify()}>{busy || 'Identify source'}</button>}
          {step === 'source' && <button className="sz-primary" onClick={confirmSource}>Review sanitisation</button>}
          {step === 'sanitize' && <button className="sz-primary" disabled={!enabled} onClick={applyPlan}>{applyMode ? 'Apply & use this sample' : 'Apply and verify'}</button>}
          {/* No "Save selected" and no "Done" — each card commits itself and nothing is forced,
              so the save step needs no primary button; closing is the modal ✕ / Back. */}
        </footer>
      </div>
    </div>
  );
}

export default SanitizeWizard;
