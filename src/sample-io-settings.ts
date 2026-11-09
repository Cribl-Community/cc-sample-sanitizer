/**
 * The two settings `sample-io.ts` reads, injected rather than imported.
 *
 * `sample-io` is in the Sample Sanitizer's bundle; `settings-store` is the Pack Generator's
 * AI settings store (provider tables, model maps, credential handling). Importing it made the
 * AI-free Sanitizer ship all of that as dead code. `settings-store` registers itself here when it
 * loads, so the Pack Generator and the backend get the real values and the Sanitizer, which never
 * loads it, gets these defaults: no provider and no sanitised-sample sharing (standalone-only).
 */
export interface SanitisedSharingSettings {
  shareSanitisedSamples: boolean;
  sanitisedSampleTokenSet: boolean;
  sanitisedSampleRepo: string;
  sanitisedSampleBranch: string;
  goldenRepo: string;
}

export interface SampleIoSettings {
  provider: () => string;
  sanitisedSharing: () => SanitisedSharingSettings;
}

const DEFAULTS: SampleIoSettings = {
  provider: () => '',
  sanitisedSharing: () => ({
    shareSanitisedSamples: false, sanitisedSampleTokenSet: false,
    sanitisedSampleRepo: '', sanitisedSampleBranch: '', goldenRepo: '',
  }),
};

let current: SampleIoSettings = DEFAULTS;

export function provideSampleIoSettings(settings: SampleIoSettings): void { current = settings; }
export function sampleIoSettings(): SampleIoSettings { return current; }
