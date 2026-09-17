/**
 * End-to-end and accessibility runs against the **built** console.
 *
 * `vite preview` serves `dist/`, not the dev server, so these exercise what
 * actually ships: the minified bundle, the real stylesheet, the CSP the build
 * pins. That matters because the defects this suite exists to catch are ones
 * no unit test can see — `text-transform` editing host-supplied text, focus
 * order through a real dialog, contrast as a browser computes it.
 *
 * The API is stubbed per test (see `e2e/api.ts`) rather than served by a real
 * `detent` binary. The binary's own HTTP surface is covered by the Rust suite,
 * including the assembled router; what is untested without a browser is the
 * front end, and a stub keeps these runs hermetic and off `/etc/hosts`.
 *
 * Spec files are named `*.e2e.ts` on purpose: `bun test` claims `*.test.*` and
 * `*.spec.*`, and a Playwright spec picked up by the unit runner fails in a
 * way that reads like a broken test rather than a misrouted one.
 */

import { defineConfig, devices } from '@playwright/test'

const PORT = 4173
const BASE_URL = `http://localhost:${PORT}`

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.e2e.ts',
  fullyParallel: true,
  forbidOnly: process.env.CI !== undefined,
  retries: process.env.CI !== undefined ? 2 : 0,
  workers: process.env.CI !== undefined ? 1 : undefined,
  reporter: process.env.CI !== undefined ? 'github' : 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `bun run preview --port ${PORT} --strictPort`,
    url: BASE_URL,
    reuseExistingServer: process.env.CI === undefined,
    timeout: 120_000,
  },
})
