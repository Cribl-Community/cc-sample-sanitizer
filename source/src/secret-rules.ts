// ============================================================================
// secret-rules.ts — install the public-source secret / sensitive-data rules
// ============================================================================
//
// The sanitiser's secret detection runs off a public-source rule library
// (`config/bundled-secret-rules.json`): patterns adapted from gitleaks and Microsoft
// Presidio (both MIT) plus vendor-published token shapes — see the NOTICE beside the file.
// Nothing proprietary is carried, so the Sample Sanitizer can publish its source for review,
// and the library needs no network call and no minimum platform version: it is always
// present, in both run modes.
//
// This module is the ONLY thing that installs the rules. `sample-sanitise.ts` cannot reach
// out at all — the rules are pushed INTO it via `setSecretRules` — which is what keeps "the
// module holding unsanitised customer data has no way to send it anywhere" true.

import bundled from '../config/bundled-secret-rules.json';
import { filterSecretRules, type SecretRuleInput } from './secret-rule-filter';
import { setSecretRules } from './sample-sanitise';

export interface SecretRulesStatus {
  /** `unloaded` = not installed yet; `ready` = rules in place; `unavailable` = running without. */
  state: 'unloaded' | 'ready' | 'unavailable';
  /** Usable rules after filtering. */
  rules: number;
  /** How many the bundled library carried before filtering — makes the filtering visible. */
  liveTotal: number;
  /** Why it is unavailable, on the rare chance the bundled file is unusable. */
  reason?: string;
}

let status: SecretRulesStatus = { state: 'unloaded', rules: 0, liveTotal: 0 };

export function secretRulesStatus(): SecretRulesStatus {
  return { ...status };
}

/** Test seam: forget what was installed so a later ensure re-installs. */
export function resetSecretRules(): void {
  status = { state: 'unloaded', rules: 0, liveTotal: 0 };
  setSecretRules([]);
}

/**
 * The message the UI shows when pattern detection is off.
 *
 * With a bundled library this is essentially unreachable — it exists so that if the file is
 * ever emptied or replaced with something the filter rejects wholesale, the UI still says
 * what is happening rather than silently reading as "checked, clean" (the one impression
 * that could get a live credential shared). It names the detection that is still running.
 */
export function secretRulesNotice(s: SecretRulesStatus = status): string | null {
  if (s.state !== 'unavailable') return null;
  return `Pattern-based secret detection is off${s.reason ? ` — ${s.reason}` : ''}. `
    + `Secrets named by their field (password, api_key, secret_access_key, …) are still detected, `
    + `and identity replacement (hosts, users, IPs, domains) is unaffected. `
    + `Review the sample yourself for tokens and keys before sharing it.`;
}

/**
 * Filter and install the bundled rules. Memoized per session.
 *
 * Kept async so callers that `await` it continue to work; there is no I/O, so it resolves
 * immediately. NEVER THROWS — secret detection is one tier of a sanitiser that has three
 * others, so a malformed library must not be able to stop somebody de-identifying a sample.
 *
 * The `group` argument is accepted and ignored: earlier the library was read per worker
 * group, and keeping the parameter means no call site had to change when the fetch went away.
 */
export function ensureSecretRules(_group?: string): Promise<SecretRulesStatus> {
  if (status.state !== 'unloaded') return Promise.resolve({ ...status });
  try {
    const items = ((bundled as { items?: SecretRuleInput[] }).items) || [];
    const filtered = filterSecretRules(items);
    if (!filtered.rules.length) {
      setSecretRules([]);
      status = {
        state: 'unavailable', rules: 0, liveTotal: filtered.liveTotal,
        reason: 'the bundled rule library produced no usable rules',
      };
    } else {
      setSecretRules(filtered.rules);
      status = { state: 'ready', rules: filtered.rules.length, liveTotal: filtered.liveTotal };
    }
  } catch (err) {
    setSecretRules([]);
    status = { state: 'unavailable', rules: 0, liveTotal: 0, reason: err instanceof Error ? err.message : String(err) };
  }
  return Promise.resolve({ ...status });
}
