/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_UMAMI_ORIGIN?: string;
  readonly VITE_UMAMI_WEBSITE_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
