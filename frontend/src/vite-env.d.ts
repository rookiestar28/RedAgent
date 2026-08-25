/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_R124_CAMPAIGN_CORE_ENABLED?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
