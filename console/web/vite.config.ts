import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// The console binary serves this build from an embedded FS, so assets must be requested from a
// root-relative path and land where //go:embed can see them.
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: { outDir: '../internal/web/dist', emptyOutDir: true },
  // In dev the SPA runs on 5173 and the console API on 8080; proxying keeps the app's fetch paths
  // identical in dev and in the embedded build, so no environment switch leaks into the code.
  server: { proxy: { '/api': 'http://127.0.0.1:8080' } },
  test: { environment: 'jsdom', globals: true, include: ['src/**/*.test.{ts,tsx}'] },
})
