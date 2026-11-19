import { fileURLToPath, URL } from 'node:url'

import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vitest/config'

// cmd/burnlink embeds dist/ with a go:embed directive that resolves next to
// the Go source file, which is why the build writes there directly rather
// than into web/dist and leaving a copy step for the Taskfile to do.
export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: '../cmd/burnlink/dist',
    emptyOutDir: true,
  },
  // The SSR bundle of the legal pages (task web:build, build:ssr) is run by
  // plain Node, which cannot load govue's TypeScript and Vue sources from
  // node_modules, so Vite bundles the package into it.
  ssr: {
    noExternal: ['@ostendorf-cloud/govue'],
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./vitest.setup.ts'],
    css: false,
  },
})
