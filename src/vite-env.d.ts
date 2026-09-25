/// <reference types="vite/client" />

declare const BUILD_NUMBER: number;
declare const APP_VERSION: string;

interface ImportMetaEnv {
  readonly VITE_GOLDEN_REPO?: string;
  readonly VITE_GOLDEN_BRANCH?: string;
  readonly VITE_SHARE_GOLDENS?: string;
  readonly VITE_LAKE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

declare module '*.webp' {
  const src: string;
  export default src;
}
