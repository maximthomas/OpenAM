/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Path-relocatable build (ADR-0004): assets use RELATIVE URLs (base './') anchored at runtime
// by the host-rewritten <base href> in index.html, so the SAME artifact serves /EUI now and
// /XUI after cutover — and deep hard-loads (e.g. /EUI/realms/edit) still load assets correctly.
// The react-router basename is derived from that same <base href> (src/config/runtime.ts),
// keeping assets and routing in sync. No mount path is baked into the bundle.
export default defineConfig({
  base: './',
  plugins: [react()],
  css: {
    preprocessorOptions: {
      // Bootstrap 5.3's Sass still uses @import and legacy color functions that Dart Sass
      // deprecates; silence those dependency-only warnings while keeping our own visible.
      scss: { quietDeps: true },
    },
  },
  build: {
    // P0-3 assembles the packaged webapp from this directory.
    outDir: 'target/app',
    emptyOutDir: true,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: true,
  },
})
