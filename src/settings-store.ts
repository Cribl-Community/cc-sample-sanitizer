// Settings + credential persistence — extracted from ai-client.ts.
//
// AI-FREE BY CONSTRUCTION: this module imports only ./run-mode and touches
// localStorage / cookies / Cribl KV + /lib/vars. It must NEVER import ai-client,
// ai-budget, schematizer or any provider SDK. The "sample-sanitizer" build
// target reaches loadSettings()/loadQualitySettings() through here and stays
// provably AI-free only while this file does (see CLAUDE.md Hard Rule 25,
// enforced by tests/sanitizer-ai-free-test.mjs).
import { getRunMode } from './run-mode';
import { INTERNAL_AI } from './build-flavor';

// 'cribl' = the org's own Cribl AI Settings (BYOM or Cribl-managed), reached through
// the platform's open_investigator agent. App (iframe) mode only; no key of our own.
export type AiProvider = 'anthropic' | 'bedrock' | 'openai' | 'mistral' | 'azureai' | 'gemini' | 'devproxy' | 'cribl';

export interface AiSettings {
  provider: AiProvider;
  model: string;
  normalModel?: string;
  repairModel?: string;
  anthropicApiKey?: string;
  anthropicApiKeySet?: boolean;
  bedrockRegion?: string;
  bedrockAccessKeyId?: string;
  bedrockSecretAccessKey?: string;
  bedrockCredsSet?: boolean;
  openaiApiKey?: string;
  openaiApiKeySet?: boolean;
  mistralApiKey?: string;
  mistralApiKeySet?: boolean;
  azureaiApiKey?: string;
  azureaiApiKeySet?: boolean;
  geminiApiKey?: string;
  geminiApiKeySet?: boolean;
  devProxyUrl?: string;
}

export interface BackgroundAiSnapshot {
  provider: Exclude<AiProvider, 'bedrock'>;
  model: string;
  normalModel: string;
  repairModel: string;
}

const STORAGE_KEY = 'pack-generator-ai-settings';

export function isDevIframe(): boolean {
  if (getRunMode() !== 'iframe') return false;
  try {
    return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  } catch {
    return false;
  }
}

/**
 * Inside Cribl the app uses the org's own AI Settings (Settings → AI Settings, BYOM
 * or Cribl-managed) and its AI settings are read-only. Only a localhost session —
 * the standalone dev server, or the app running in a localhost Cribl — may choose
 * another provider or model.
 */
export function aiSettingsLocked(): boolean {
  return getRunMode() === 'iframe' && !isDevIframe();
}

/** The org's AI Settings choose the model; this id only labels the choice. */
export const CRIBL_AI_SETTINGS_MODEL = 'cribl-ai-settings';

/** A locked install always reports the org's AI Settings, whatever was saved before. */
function applyAiLock(s: AiSettings): AiSettings {
  if (!aiSettingsLocked()) return s;
  const m = CRIBL_AI_SETTINGS_MODEL;
  if (s.provider === 'cribl' && s.model === m && s.normalModel === m && s.repairModel === m) return s;
  return { ...s, provider: 'cribl', model: m, normalModel: m, repairModel: m };
}

function getDefaultSettings(): AiSettings {
  // iframe defaults to Anthropic (platform proxy injects its key); standalone
  // and Backend Functions default to Aperture.
  const provider = getRunMode() === 'iframe' || !INTERNAL_AI ? 'anthropic' : 'devproxy';
  const model = provider === 'anthropic' ? 'claude-sonnet-5' : 'us.anthropic.claude-sonnet-5';
  return {
    provider,
    model,
    normalModel: model,
    repairModel: model,
    bedrockRegion: 'us-east-1',
    devProxyUrl: 'http://ai-gateway.example/bedrock',
  };
}

export let memorySettings: AiSettings | null = null;

export function canBackgroundUseProvider(provider: AiProvider): { ok: boolean; reason?: string } {
  if (provider === 'bedrock') {
    return {
      ok: false,
      reason: 'Direct Bedrock credentials cannot be used by background workers. Choose Aperture or an app-proxied provider.',
    };
  }
  if (!['anthropic', 'openai', 'mistral', 'azureai', 'gemini', 'devproxy', 'cribl'].includes(provider)) {
    return { ok: false, reason: `Unknown AI provider "${String(provider)}" in background snapshot.` };
  }
  return { ok: true };
}

/**
 * The non-secret AI settings a background run is allowed to carry, or why it
 * cannot be started at all.
 *
 * Two independent gates, and both must be checked BEFORE anything durable is
 * written (a run that can never do AI work would otherwise fail one row per
 * scheduled tick, blaming rows for a setting):
 *
 * - Direct AWS Bedrock is refused outright. Its credentials are SigV4 signing
 *   keys held in this browser; a Backend Function has no browser storage and
 *   the platform's proxy injection cannot sign a request for us.
 * - Every other external provider must already have its encrypted credential
 *   configured in this install. The snapshot deliberately carries no secret —
 *   the backend relies on `proxies.yml` header injection — so a provider whose
 *   key was never stored would produce a run that authenticates as nobody.
 *   Aperture/devproxy is exempt: it needs no per-install credential.
 */
export function backgroundAiSnapshot(
  ai: Pick<AiSettings, 'provider' | 'model'> & Partial<AiSettings>,
  quality: { normalModel?: string; repairModel?: string },
): { ok: true; snapshot: BackgroundAiSnapshot } | { ok: false; reason: string } {
  const eligibility = canBackgroundUseProvider(ai.provider);
  if (!eligibility.ok) {
    return { ok: false, reason: eligibility.reason || `AI provider "${ai.provider}" cannot run in the background.` };
  }
  const flag = AI_PROVIDER_CONFIG_FLAGS[ai.provider];
  if (flag && ai[flag] !== true) {
    return {
      ok: false,
      reason: `The ${ai.provider} API key is not configured in this install. `
        + 'A background run has no access to browser-held credentials — save the key in Settings first.',
    };
  }
  const model = ai.model;
  return {
    ok: true,
    // Exactly four non-secret fields. Anything else here would be persisted in
    // App KV for the life of the run and echoed into the platform log.
    snapshot: {
      provider: ai.provider as Exclude<AiProvider, 'bedrock'>,
      model,
      normalModel: quality.normalModel || model,
      repairModel: quality.repairModel || model,
    },
  };
}

export async function installBackendAiSnapshot(snapshot: BackgroundAiSnapshot): Promise<void> {
  const eligibility = canBackgroundUseProvider(snapshot.provider as AiProvider);
  if (!eligibility.ok) throw new Error(eligibility.reason || 'AI provider is not eligible for background execution.');
  const base = persistableAiSettings(memorySettings || getDefaultSettings());
  memorySettings = {
    ...base,
    provider: snapshot.provider,
    model: snapshot.model,
    normalModel: snapshot.normalModel,
    repairModel: snapshot.repairModel,
  };
  const flag = AI_PROVIDER_CONFIG_FLAGS[snapshot.provider];
  // The browser only snapshots a selected external provider after its encrypted
  // proxy credential has been configured. Preserve that non-secret capability
  // in the fresh Backend Function process so isAiConfigured()/aiAvailable()
  // do not reject the proxy-injected call before it is attempted.
  if (flag) memorySettings[flag] = true;
}

const AI_SECRET_FIELDS = [
  'anthropicApiKey',
  'openaiApiKey',
  'mistralApiKey',
  'azureaiApiKey',
  'geminiApiKey',
  'bedrockAccessKeyId',
  'bedrockSecretAccessKey',
] as const;

type AiSecretField = typeof AI_SECRET_FIELDS[number];

type AiProviderConfigFlag =
  | 'anthropicApiKeySet'
  | 'openaiApiKeySet'
  | 'mistralApiKeySet'
  | 'azureaiApiKeySet'
  | 'geminiApiKeySet';

const AI_PROVIDER_CONFIG_FLAGS: Partial<Record<AiProvider, AiProviderConfigFlag>> = {
  anthropic: 'anthropicApiKeySet',
  openai: 'openaiApiKeySet',
  mistral: 'mistralApiKeySet',
  azureai: 'azureaiApiKeySet',
  gemini: 'geminiApiKeySet',
};

const AI_SECRET_FLAGS: Partial<Record<AiSecretField, keyof AiSettings>> = {
  anthropicApiKey: 'anthropicApiKeySet',
  openaiApiKey: 'openaiApiKeySet',
  mistralApiKey: 'mistralApiKeySet',
  azureaiApiKey: 'azureaiApiKeySet',
  geminiApiKey: 'geminiApiKeySet',
};

export function persistableAiSettings(s: AiSettings): AiSettings {
  const out: AiSettings = { ...s };
  for (const key of AI_SECRET_FIELDS) {
    out[key] = '';
  }
  return out;
}

export function scrubStoredAiSettings(stored: Partial<AiSettings>): AiSettings {
  const parsed = { ...getDefaultSettings(), ...stored };
  for (const key of AI_SECRET_FIELDS) {
    const flag = AI_SECRET_FLAGS[key];
    if (stored[key] && flag) (parsed as any)[flag] = false;
    parsed[key] = '';
  }
  if (stored.bedrockAccessKeyId || stored.bedrockSecretAccessKey) parsed.bedrockCredsSet = false;
  parsed.model = migrateModel(parsed.model);
  return parsed;
}

const DEPRECATED_MODELS: Record<string, string> = {
  'gemini-2.0-flash': 'gemini-3.5-flash',
  'gemini-2.0-flash-001': 'gemini-3.5-flash',
  'gemini-2.0-flash-lite': 'gemini-3.1-flash-lite',
  'gemini-2.5-flash': 'gemini-3.5-flash',
  'gemini-2.5-flash-lite': 'gemini-3.5-flash',
  'gemini-2.5-flash-preview-05-20': 'gemini-3.5-flash',
  'gemini-2.5-pro': 'gemini-pro-latest',
  'gemini-2.5-pro-preview-06-05': 'gemini-pro-latest',
  'gemini-3.5-pro': 'gemini-pro-latest',
  'gemini-3.6-pro': 'gemini-pro-latest',
  'claude-sonnet-4-6-20250514': 'claude-sonnet-5',
  'claude-haiku-3-5-20241022': 'claude-haiku-4-5',
  'us.anthropic.claude-sonnet-4-6': 'us.anthropic.claude-sonnet-5',
  'us.anthropic.claude-opus-4-6-v1': 'us.anthropic.claude-opus-5',
  'us.anthropic.claude-sonnet-4-5-20250929-v1:0': 'us.anthropic.claude-sonnet-5',
  'us.anthropic.claude-haiku-4-5-20251001-v1:0': 'us.anthropic.claude-haiku-4-5',
  'us.anthropic.claude-haiku-3-5-20241022-v1:0': 'us.anthropic.claude-haiku-4-5',
  'gpt-4o-mini': 'gpt-4.1-mini',
  'o3-mini': 'o4-mini',
  'mistral-medium-latest': 'mistral-small-latest',
};

export function migrateModel(model: string): string {
  return DEPRECATED_MODELS[model] || model;
}

// A model id "belongs" to a provider if its shape matches that provider's
// naming. Used to guard against a stale normalModel/repairModel left over from
// a previous provider (e.g. an Anthropic model id persisted, then the user
// switches to Gemini — the actual call always follows settings.model, but the
// stale id would otherwise surface in the log label and mislead).
function modelBelongsToProvider(model: string | undefined, provider: AiProvider): boolean {
  if (!model) return false;
  const m = model.toLowerCase();
  switch (provider) {
    case 'anthropic': return m.startsWith('claude-');
    case 'bedrock': return m.includes('anthropic.') || m.startsWith('claude-');
    case 'devproxy': return true;
    case 'openai':
    case 'azureai': return m.startsWith('gpt-') || m.startsWith('o3') || m.startsWith('o4');
    case 'mistral': return m.startsWith('mistral-') || m.startsWith('codestral');
    case 'gemini': return m.startsWith('gemini-');
    default: return true;
  }
}

// Return `model` only if it belongs to `provider`; otherwise fall back to the
// provider's active model. Keeps normal/repair model ids from lying about the
// provider after a provider switch.
function coerceModelToProvider(model: string | undefined, provider: AiProvider, fallback: string): string {
  return modelBelongsToProvider(model, provider) ? (model as string) : fallback;
}

function canUseLocalStorage(): boolean {
  try {
    const key = '__storage_test__';
    localStorage.setItem(key, '1');
    localStorage.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

function getCookie(name: string): string | null {
  try {
    const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
    return match ? decodeURIComponent(match[1]) : null;
  } catch {
    return null;
  }
}

function setCookie(name: string, value: string) {
  try {
    document.cookie = `${name}=${encodeURIComponent(value)}; path=/; max-age=31536000; SameSite=None; Secure`;
  } catch { /* ignore */ }
}

// --- Platform persistence (the copy that survives a browser that drops iframe storage) ---
// Inside Cribl's iframe, localStorage and cookies are third-party storage: Safari,
// Brave, strict Firefox, Chrome with third-party cookies blocked and incognito drop
// them, so for those users the settings lived in memory only (2026-10-08 report).
// The durable copy is the app's own KV store, the store the sample library and
// goldens already use: no worker group, no commit, readable by anyone who can open
// the app. Secrets never go here (persistable*Settings blanks them; they stay in
// encrypted KV). The old /m/default/lib/vars variable is read once to migrate: its
// save never created the variable (a 404 is not a network error), and it needed a
// `default` group the user could edit.
export const SETTINGS_KV_KEY = 'settings/app';
const SETTINGS_VAR_ID = 'pack_generator_settings';
let platformSettingsCache: Record<string, any> | null = null;
let platformSettingsLoaded = false;

type SettingsFetch = (url: string, init?: RequestInit) => Promise<Response>;
let settingsFetch: SettingsFetch = (url, init) => fetch(url, init);
let settingsBaseOverride: string | null = null;

function getCriblApiBase(): string {
  if (settingsBaseOverride != null) return settingsBaseOverride;
  const fromWindow = typeof window !== 'undefined' ? (window as any).CRIBL_API_URL : undefined;
  if (fromWindow && fromWindow.length > 0) return fromWindow.replace(/\/+$/, '');
  return '/api/v1';
}
const platformEnabled = () => settingsBaseOverride != null || getRunMode() === 'iframe';

// A KV GET can come back as the document, as a JSON string of it, or wrapped in items[0].value.
function parseStoredBlob(text: string): Record<string, any> | null {
  let v: any = text;
  for (let i = 0; i < 3 && typeof v === 'string'; i++) {
    if (!v.trim()) return null;
    try { v = JSON.parse(v); } catch { return null; }
  }
  if (v && typeof v === 'object' && Array.isArray(v.items)) v = v.items[0]?.value ?? null;
  if (typeof v === 'string') { try { v = JSON.parse(v); } catch { return null; } }
  return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
}

async function putSettingsKv(blob: Record<string, any>): Promise<void> {
  // text/plain: a JSON content-type PUT is stored as "[object Object]".
  const resp = await settingsFetch(`${getCriblApiBase()}/kvstore/${SETTINGS_KV_KEY}`, {
    method: 'PUT', headers: { 'Content-Type': 'text/plain' }, body: JSON.stringify(blob),
  });
  if (!resp.ok) throw new Error(`Settings save failed (${resp.status})`);
}

async function loadPlatformSettings(): Promise<Record<string, any> | null> {
  if (platformSettingsLoaded) return platformSettingsCache;
  if (!platformEnabled()) { platformSettingsLoaded = true; return null; }
  try {
    const resp = await settingsFetch(`${getCriblApiBase()}/kvstore/${SETTINGS_KV_KEY}`);
    if (resp.ok) platformSettingsCache = parseStoredBlob(await resp.text());
  } catch { /* unreachable — try the legacy variable */ }
  if (!platformSettingsCache) {
    try {
      const resp = await settingsFetch(`${getCriblApiBase()}/m/default/lib/vars/${SETTINGS_VAR_ID}`);
      if (resp.ok) {
        const data = await resp.json();
        const item = data.items?.[0] || data;
        const legacy = item?.value ? parseStoredBlob(typeof item.value === 'string' ? item.value : JSON.stringify(item.value)) : null;
        if (legacy) { platformSettingsCache = legacy; await putSettingsKv(legacy).catch(() => {}); }
      }
    } catch { /* no legacy copy */ }
  }
  platformSettingsLoaded = true;
  return platformSettingsCache;
}

// Eagerly load platform settings on module init (non-blocking)
let platformReady = loadPlatformSettings();
let platformWrites: Promise<void> = Promise.resolve();

/**
 * Merge `patch` into the stored blob and write it. Waits for the initial load, so a
 * save made before it finished cannot overwrite the other half (AI vs quality) with
 * nothing; writes are chained so the last save wins.
 */
function savePlatformSettings(patch: Record<string, any>): Promise<void> {
  if (!platformEnabled()) return Promise.resolve();
  platformSettingsCache = { ...platformSettingsCache, ...patch };
  platformWrites = platformWrites
    .then(() => platformReady)
    .then(() => { platformSettingsCache = { ...platformSettingsCache, ...patch }; return putSettingsKv(platformSettingsCache); })
    .catch(() => { /* best-effort: localStorage/cookie still hold it where the browser allows */ });
  return platformWrites;
}

/** Tests: point the platform copy at a fake KV and reload it, as a fresh app start would. */
export function setSettingsKvTransportForTests(f: SettingsFetch, base: string): Promise<void> {
  settingsFetch = f; settingsBaseOverride = base;
  platformSettingsCache = null; platformSettingsLoaded = false;
  memorySettings = null; memoryQuality = null;
  platformReady = loadPlatformSettings();
  platformWrites = Promise.resolve();
  return platformReady.then(() => {});
}

/** Tests: resolves once every queued platform write has landed. */
export const platformSettingsFlushed = (): Promise<void> => platformWrites;

export function loadSettings(): AiSettings {
  return applyAiLock(loadStoredSettings());
}

function loadStoredSettings(): AiSettings {
  if (memorySettings) return memorySettings;
  // Try localStorage first
  if (canUseLocalStorage()) {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const stored = JSON.parse(raw);
        const parsed = scrubStoredAiSettings(stored);
        if (AI_SECRET_FIELDS.some(key => !!stored[key])) persistDurableAiSettings(parsed);
        memorySettings = parsed;
        return parsed;
      }
    } catch { /* ignore */ }
  }
  // Fallback: try cookie
  const cookieRaw = getCookie(STORAGE_KEY);
  if (cookieRaw) {
    try {
      const stored = JSON.parse(cookieRaw);
      const parsed = scrubStoredAiSettings(stored);
      if (AI_SECRET_FIELDS.some(key => !!stored[key])) persistDurableAiSettings(parsed);
      memorySettings = parsed;
      return parsed;
    } catch { /* ignore */ }
  }
  // Fallback: platform settings (loaded async on init, may not be ready yet)
  if (platformSettingsCache?.aiSettings) {
    const stored = platformSettingsCache.aiSettings;
    const parsed = scrubStoredAiSettings(stored);
    if (AI_SECRET_FIELDS.some(key => !!stored[key])) persistDurableAiSettings(parsed);
    memorySettings = parsed;
    return parsed;
  }
  return getDefaultSettings();
}

// Async version that waits for platform settings to load (use at app startup)
export async function loadSettingsAsync(): Promise<AiSettings> {
  return applyAiLock(await loadStoredSettingsAsync());
}

async function loadStoredSettingsAsync(): Promise<AiSettings> {
  if (memorySettings) return memorySettings;
  if (canUseLocalStorage()) {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const stored = JSON.parse(raw);
        const parsed = scrubStoredAiSettings(stored);
        if (AI_SECRET_FIELDS.some(key => !!stored[key])) persistDurableAiSettings(parsed);
        memorySettings = parsed;
        return parsed;
      }
    } catch { /* ignore */ }
  }
  const cookieRaw = getCookie(STORAGE_KEY);
  if (cookieRaw) {
    try {
      const stored = JSON.parse(cookieRaw);
      const parsed = scrubStoredAiSettings(stored);
      if (AI_SECRET_FIELDS.some(key => !!stored[key])) persistDurableAiSettings(parsed);
      memorySettings = parsed;
      return parsed;
    }
    catch { /* ignore */ }
  }
  await platformReady;
  if (platformSettingsCache?.aiSettings) {
    const stored = platformSettingsCache.aiSettings;
    const parsed = scrubStoredAiSettings(stored);
    if (AI_SECRET_FIELDS.some(key => !!stored[key])) persistDurableAiSettings(parsed);
    memorySettings = parsed;
    return parsed;
  }
  return getDefaultSettings();
}

// --- KV store helpers (encrypted credential storage for iframe proxy) ---

export function getKvBase(): string {
  if (getRunMode() === 'iframe') {
    const criblUrl = (window as any).CRIBL_API_URL || '';
    const base = criblUrl.replace(/\/api\/v1\/?$/, '');
    return `${base}/api/v1/kvstore`;
  }
  return '/api/v1/kvstore';
}


export async function kvWrite(key: string, value: string, encrypted = false): Promise<void> {
  const url = `${getKvBase()}/${key}${encrypted ? '?encrypted=true' : ''}`;
  const response = await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'text/plain' }, body: value });
  if (!response.ok) throw new Error(`Encrypted credential save failed for ${key} (${response.status})`);
}

export async function kvRead(key: string): Promise<string> {
  const response = await fetch(`${getKvBase()}/${key}`);
  if (!response.ok) throw new Error(`Encrypted credential read failed for ${key} (${response.status})`);
  return (await response.text()).trim();
}

async function kvDelete(key: string): Promise<void> {
  await fetch(`${getKvBase()}/${key}`, { method: 'DELETE' }).catch(() => {});
}

export interface DurableSettingsSinks {
  localStorage: (serialized: string) => void;
  cookie: (serialized: string) => void;
  platform: (serialized: string) => void;
}

export function persistAiSettingsToDurableSinks(s: AiSettings, sinks: DurableSettingsSinks): AiSettings {
  const persistent = persistableAiSettings(s);
  const serialized = JSON.stringify(persistent);
  sinks.localStorage(serialized);
  sinks.cookie(serialized);
  sinks.platform(serialized);
  return persistent;
}

export function persistDurableAiSettings(s: AiSettings): void {
  persistAiSettingsToDurableSinks(s, {
    localStorage: serialized => {
      if (canUseLocalStorage()) {
        try { localStorage.setItem(STORAGE_KEY, serialized); } catch { /* ignore */ }
      }
    },
    cookie: serialized => setCookie(STORAGE_KEY, serialized),
    platform: serialized => { savePlatformSettings({ aiSettings: JSON.parse(serialized) }); },
  });
}

async function persistAiCredentials(s: AiSettings): Promise<void> {
  const secrets = Object.fromEntries(
    AI_SECRET_FIELDS.filter(key => !!s[key]).map(key => [key, s[key]]),
  ) as Partial<Record<AiSecretField, string>>;
  if (Object.keys(secrets).length === 0) return;

  if (getRunMode() === 'iframe') {
    await Promise.all(Object.entries(secrets).map(([key, value]) => kvWrite(key, value, true)));
    return;
  }

  const response = await fetch('/api/pack-generator/creds-save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(secrets),
  });
  if (!response.ok) throw new Error(`Server AI credential save failed (${response.status})`);
  const result = await response.json().catch(() => null);
  if (!result?.saved) throw new Error(result?.message || 'Server did not confirm the AI credential save');
}

export async function saveSettings(s: AiSettings): Promise<void> {
  const previous = loadSettings();
  const live = applyAiLock({ ...previous, ...s });
  await persistAiCredentials(live);

  const confirmed = { ...live };
  for (const key of AI_SECRET_FIELDS) {
    const flag = AI_SECRET_FLAGS[key];
    if (flag && live[key]) (confirmed as any)[flag] = true;
  }
  if (live.bedrockAccessKeyId && live.bedrockSecretAccessKey) confirmed.bedrockCredsSet = true;
  memorySettings = confirmed;
  memoryQuality = null;
  persistDurableAiSettings(confirmed);
}

export async function clearBedrockCredentials(): Promise<void> {
  if (getRunMode() === 'iframe') {
    await Promise.all([kvDelete('bedrockAccessKeyId'), kvDelete('bedrockSecretAccessKey'), kvDelete('bedrockAuth')]);
  }
  const current = memorySettings || loadSettings();
  memorySettings = {
    ...current,
    bedrockAccessKeyId: '',
    bedrockSecretAccessKey: '',
    bedrockCredsSet: false,
  };
  memoryQuality = null;
  persistDurableAiSettings(memorySettings);
}

// --- Quality / Lake settings (separate store, persisted for next round) ---

export interface QualitySettings {
  qualityThreshold: number;   // score < this → repair flow; >= this → store golden
  // Experimental 3-stage build: each stage stores its own golden sub-part when
  // it reaches its own threshold (independent — a run can golden extraction +
  // mapping but not optimization). Default all to 80; changeable in Settings.
  expExtractionThreshold: number;
  expMappingThreshold: number;
  expOptimizationThreshold: number;
  lakeUrl: string;            // full NDJSON ingest link to the target dataset
  lakeToken: string;          // transient form value only; always blank in durable settings
  lakeTokenSet: boolean;      // nonsecret capability flag for the server-side credential
  normalModel: string;        // AI model for the normal generation flow
  repairModel: string;        // AI model for the post-deploy repair flow
  // Shared golden knowledge (PUBLIC goldens-only GitHub repo — read by anyone,
  // written only by an install that has a token, and only outside the iframe):
  shareGoldens: boolean;      // publish locally-stored goldens (score>80) to the shared pool
  goldenRepo: string;         // owner/repo of the public golden pool
  goldenBranch: string;       // branch that holds the shared-goldens/ folder
  goldenToken: string;        // transient form value only; always blank in durable settings
  goldenTokenSet: boolean;    // nonsecret capability flag: a PUBLISH credential exists
  shareSanitisedSamples: boolean;
  sanitisedSampleRepo: string;
  sanitisedSampleBranch: string;
  sanitisedSampleToken: string;     // transient; never persisted
  sanitisedSampleTokenSet: boolean; // dedicated samples-repo credential capability
  /**
   * Refuse to put un-sanitised sample events into an AI prompt.
   *
   * A Sanitize button alone is opt-in, and the requirement it serves is a prohibition:
   * uploaded, worker-group, pasted and live-captured events are customer data that may
   * not reach a model vendor. With this on, the wizard's AI steps stop and say why until
   * the sample has been pseudonymised locally (see sample-sanitise.ts) — it stops being
   * something a reviewer has to remember. Defaults OFF; a deployment opts in with
   * VITE_REQUIRE_SANITISED_SAMPLES=true, or the user turns it on in Settings.
   *
   * It governs THIRD-PARTY providers only. The Cribl Copilot schematizer talks to the
   * user's own Cribl org, which is a different question from handing data to OpenAI.
   */
  requireSanitisedSamples: boolean;
  /**
   * Drop null and blank ('') fields when a Parser (serde) parses JSON: the build
   * sets the Parser's `fieldFilterExpr` to `value!=null && value!==''`, which
   * keeps 0 and false. Cribl applies the filter to top-level fields only.
   * Defaults OFF; scoring is unaffected (null/blank already count as unfilled).
   */
  dropEmptyJsonFields: boolean;
}

const QUALITY_STORAGE_KEY = 'pack-generator-quality-settings';

// Path prefix (folder) inside the repo/branch that holds the shared goldens.
export const GOLDEN_PATH_PREFIX = 'shared-goldens';

// `import.meta.env` is a Vite build-time construct, and this module is also loaded
// by the Node test runner, the standalone handlers and a Backend Function — where
// it does not exist at all, so a BARE read is a TypeError rather than a missing
// default. Every default below goes through this guard for that reason; under Vite
// the behaviour is unchanged (an unset var still reads as '', exactly as `|| ''`).
function viteEnv(name: string): string {
  return String((import.meta.env as Record<string, string> | undefined)?.[name] ?? '');
}

// The shared golden pool's home.
export function defaultGoldenRepo(): string {
  return viteEnv('VITE_GOLDEN_REPO') || 'wvdlinde-cribl/cribl-pack-goldens';
}

function getDefaultQualitySettings(): QualitySettings {
  const ai = loadSettings();
  return {
    qualityThreshold: 80,
    expExtractionThreshold: 80,
    expMappingThreshold: 80,
    expOptimizationThreshold: 80,
    lakeUrl: viteEnv('VITE_LAKE_URL'),
    lakeToken: '',
    lakeTokenSet: false,
    normalModel: coerceModelToProvider(ai.normalModel, ai.provider, ai.model),
    repairModel: coerceModelToProvider(ai.repairModel, ai.provider, ai.model),
    shareGoldens: viteEnv('VITE_SHARE_GOLDENS') === 'true',
    goldenRepo: defaultGoldenRepo(),
    goldenBranch: viteEnv('VITE_GOLDEN_BRANCH') || 'shared-goldens',
    goldenToken: '',
    goldenTokenSet: false,
    shareSanitisedSamples: false,
    sanitisedSampleRepo: viteEnv('VITE_SANITISED_SAMPLE_REPO'),
    sanitisedSampleBranch: viteEnv('VITE_SANITISED_SAMPLE_BRANCH') || 'shared-sanitised-samples',
    sanitisedSampleToken: '',
    sanitisedSampleTokenSet: false,
    // Defaults OFF (opt-in). Sanitising only ever applied to customer-origin
    // samples (upload/paste/worker-group) — library and AI-generated samples
    // are exempt by source (see sampleNeedsSanitising) — but the mandatory
    // gate is off by default; turn it on in Settings to force it. Set
    // VITE_REQUIRE_SANITISED_SAMPLES=true to default it on for a build.
    requireSanitisedSamples: viteEnv('VITE_REQUIRE_SANITISED_SAMPLES') === 'true',
    dropEmptyJsonFields: false,
  };
}

let memoryQuality: QualitySettings | null = null;

// NOTE: there used to be a migrateQuality() here that REWROTE any Lake
// Direct-Access setting (…/direct-access…, :10080) to a hardcoded
// http://selab…:443 default and wiped the token. That was a backwards
// migration — it silently downgraded a WORKING Direct-Access config to the
// deprecated HTTP-source URL on every settings load, which is why scoring
// "stopped working after a week with no changes". Removed: whatever URL/token
// the user configured (or blank → auto-discover Direct-Access) is kept as-is.

// Where the shared pool used to live. It moved out of the app's own PRIVATE repo
// into a public goldens-only repo (build 558), then that repo moved from the
// personal wvdlinde account into the wvdlinde-cribl organization — and a stored
// setting outranks the new default each time, so any install that had ever saved
// settings would keep pointing at a repository it can no longer read, and
// silently see an empty pool.
const LEGACY_GOLDEN_REPOS = new Set(['wvdlinde/cribl-pack-generator', 'wvdlinde/cribl-pack-goldens']);

export function isLegacyGoldenRepo(repo: string | undefined): boolean {
  return LEGACY_GOLDEN_REPOS.has(String(repo || '').trim().toLowerCase());
}

function migrateQuality(q: QualitySettings): QualitySettings {
  const ai = loadSettings();
  q.lakeTokenSet = !!q.lakeTokenSet;
  q.goldenTokenSet = !!q.goldenTokenSet;
  q.sanitisedSampleTokenSet = !!q.sanitisedSampleTokenSet;
  q.goldenToken = '';
  q.sanitisedSampleToken = '';
  q.lakeToken = '';
  if (isLegacyGoldenRepo(q.goldenRepo)) q.goldenRepo = defaultGoldenRepo();
  q.normalModel = coerceModelToProvider(ai.normalModel, ai.provider, ai.model);
  q.repairModel = coerceModelToProvider(ai.repairModel, ai.provider, ai.model);
  return q;
}

export function scrubStoredQualitySettings(stored: Partial<QualitySettings>): QualitySettings {
  const parsed = { ...stored } as QualitySettings;
  if (stored.lakeToken) parsed.lakeTokenSet = false;
  if (stored.goldenToken) parsed.goldenTokenSet = false;
  if (stored.sanitisedSampleToken) parsed.sanitisedSampleTokenSet = false;
  return migrateQuality(parsed);
}

function hydrateQualitySettings(stored: Partial<QualitySettings>): QualitySettings {
  const containedLegacyToken = !!stored.goldenToken || !!stored.lakeToken;
  const pointedAtOldPool = isLegacyGoldenRepo(stored.goldenRepo);
  const parsed = scrubStoredQualitySettings({ ...getDefaultQualitySettings(), ...stored });
  // One-time migrations, written back so they happen once rather than on every
  // load: the pre-538 raw GitHub credential, and the pre-558 pool location.
  if (containedLegacyToken || pointedAtOldPool) saveQualitySettings(parsed);
  return parsed;
}

export function loadQualitySettings(): QualitySettings {
  if (memoryQuality) return memoryQuality;
  if (canUseLocalStorage()) {
    try {
      const raw = localStorage.getItem(QUALITY_STORAGE_KEY);
      if (raw) { const parsed = hydrateQualitySettings(JSON.parse(raw)); memoryQuality = parsed; return parsed; }
    } catch { /* ignore */ }
  }
  const cookieRaw = getCookie(QUALITY_STORAGE_KEY);
  if (cookieRaw) {
    try { const parsed = hydrateQualitySettings(JSON.parse(cookieRaw)); memoryQuality = parsed; return parsed; }
    catch { /* ignore */ }
  }
  // Platform persistence fallback
  if (platformSettingsCache?.qualitySettings) {
    const parsed = hydrateQualitySettings(platformSettingsCache.qualitySettings);
    memoryQuality = parsed;
    return parsed;
  }
  return getDefaultQualitySettings();
}

// Async version that waits for platform settings to load (use at app startup)
export async function loadQualitySettingsAsync(): Promise<QualitySettings> {
  if (memoryQuality) return memoryQuality;
  if (canUseLocalStorage()) {
    try {
      const raw = localStorage.getItem(QUALITY_STORAGE_KEY);
      if (raw) { const parsed = hydrateQualitySettings(JSON.parse(raw)); memoryQuality = parsed; return parsed; }
    } catch { /* ignore */ }
  }
  const cookieRaw = getCookie(QUALITY_STORAGE_KEY);
  if (cookieRaw) {
    try { const parsed = hydrateQualitySettings(JSON.parse(cookieRaw)); memoryQuality = parsed; return parsed; }
    catch { /* ignore */ }
  }
  await platformReady;
  if (platformSettingsCache?.qualitySettings) {
    const parsed = hydrateQualitySettings(platformSettingsCache.qualitySettings);
    memoryQuality = parsed;
    return parsed;
  }
  return getDefaultQualitySettings();
}

export function saveQualitySettings(s: QualitySettings) {
  const persistent = persistQualitySettingsToDurableSinks(s, {
    localStorage: serialized => {
      if (canUseLocalStorage()) {
        try { localStorage.setItem(QUALITY_STORAGE_KEY, serialized); } catch { /* ignore */ }
      }
    },
    cookie: serialized => setCookie(QUALITY_STORAGE_KEY, serialized),
    platform: serialized => { savePlatformSettings({ qualitySettings: JSON.parse(serialized) }); },
  });
  memoryQuality = {
    ...s,
    goldenToken: '',
    sanitisedSampleToken: '',
    goldenTokenSet: persistent.goldenTokenSet,
    sanitisedSampleTokenSet: persistent.sanitisedSampleTokenSet,
    lakeTokenSet: persistent.lakeTokenSet,
  };
}

export function persistableQualitySettings(s: QualitySettings): QualitySettings {
  return {
    ...s,
    lakeToken: '',
    lakeTokenSet: !!s.lakeTokenSet,
    goldenToken: '',
    goldenTokenSet: !!s.goldenTokenSet,
    sanitisedSampleToken: '',
    sanitisedSampleTokenSet: !!s.sanitisedSampleTokenSet,
  };
}

export function persistQualitySettingsToDurableSinks(
  s: QualitySettings,
  sinks: DurableSettingsSinks,
): QualitySettings {
  const persistent = persistableQualitySettings(s);
  const serialized = JSON.stringify(persistent);
  sinks.localStorage(serialized);
  sinks.cookie(serialized);
  sinks.platform(serialized);
  return persistent;
}

export async function saveLakeToken(token: string): Promise<void> {
  const value = token.trim();
  if (!value) return;
  if (getRunMode() === 'iframe') {
    await kvWrite('lakeToken', value, true);
    return;
  }
  const response = await fetch('/api/pack-generator/creds-save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ lakeToken: value }),
  });
  if (!response.ok) throw new Error(`Server Lake credential save failed (${response.status})`);
  const result = await response.json().catch(() => null);
  if (!result?.saved) throw new Error(result?.message || 'Server did not confirm the Lake credential save');
}

export async function saveGoldenReadToken(token: string): Promise<void> {
  const value = token.trim();
  if (!value) return;
  if (getRunMode() === 'iframe') {
    const response = await fetch(`${getKvBase()}/goldenReadToken?encrypted=true`, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain' },
      body: value,
    });
    if (!response.ok) throw new Error(`Encrypted GitHub credential save failed (${response.status})`);
    return;
  }
  const response = await fetch('/api/pack-generator/creds-save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ goldenReadToken: value }),
  });
  if (!response.ok) throw new Error(`Server GitHub credential save failed (${response.status})`);
  const result = await response.json().catch(() => null);
  if (!result?.saved) throw new Error(result?.message || 'Server did not confirm the GitHub credential save');
}

export async function saveSanitisedSampleToken(token: string): Promise<void> {
  const value = token.trim();
  if (!value) return;
  if (getRunMode() === 'iframe') throw new Error('Shared sample publishing is standalone-only.');
  const response = await fetch('/api/pack-generator/creds-save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sanitisedSampleToken: value }),
  });
  if (!response.ok) throw new Error(`Server sample-repository credential save failed (${response.status})`);
  const result = await response.json().catch(() => null);
  if (!result?.saved) throw new Error(result?.message || 'Server did not confirm the sample-repository credential save');
}
