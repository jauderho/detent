/**
 * Responsive-evidence captures, kept apart from the regression suite.
 *
 * `playwright.config.ts` owns `./e2e` and runs on every CI push. This config
 * owns `./e2e-shots` and is run on demand (`bun run shots`). The split exists
 * because the two have different jobs: the e2e suite is a pass/fail gate, the
 * shots run produces stills a human looks at. Mixing them meant an ad-hoc
 * capture spec had to live inside `testDir: './e2e'` or be smuggled in by
 * rewriting the config, which is how the M2 capture turned into a dozen shell
 * commands against `sed` and `/tmp`.
 *
 * Output lands in `SHOTS_DIR` (default `/tmp/detent-shots`), never in the
 * repository: `.gitignore` refuses images on purpose, and the evidence of
 * record is this reproducible command plus the `noOverflow` assertions, not
 * the PNGs.
 */

import { defineConfig, devices } from '@playwright/test'

const PORT = 4173
const BASE_URL = `http://localhost:${PORT}`

export default defineConfig({
  testDir: './e2e-shots',
  testMatch: '**/*.e2e.ts',
  // Stills are captured serially so a viewport change cannot race another
  // worker's page, and retries are off: a flaky screenshot is a bad screenshot.
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `bun run preview --port ${PORT} --strictPort`,
    url: BASE_URL,
    reuseExistingServer: true,
    timeout: 120_000,
  },
})
