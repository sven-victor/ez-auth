/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_BASE_URL: string
  // More environment variables...
}

interface ImportMeta {
  readonly env: ImportMetaEnv
} 