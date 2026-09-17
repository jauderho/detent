/**
 * Responsive evidence for the M2 spike: three breakpoints, captured against
 * the built bundle with the same API stubs the regression suite uses.
 *
 * Run with `bun run shots` (from `web/`). Stills land in `SHOTS_DIR`, default
 * `/tmp/detent-shots` — outside the repo, because `.gitignore` refuses images
 * and the durable record is this file, not the PNGs.
 *
 * `noOverflow` is the assertion that makes the run a test rather than a photo
 * shoot: `documentElement.scrollWidth` must fit the viewport, so a layout
 * regression fails here instead of producing a quietly-wrong screenshot.
 */

import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { expect, type Page, test } from '@playwright/test'
import { signIn, stubApi } from '../e2e/api'

const SHOTS_DIR = process.env.SHOTS_DIR ?? '/tmp/detent-shots'

test.beforeAll(() => {
  mkdirSync(SHOTS_DIR, { recursive: true })
})

async function noOverflow(page: Page, width: number) {
  const scroll = await page.evaluate(() => document.documentElement.scrollWidth)
  expect(scroll).toBeLessThanOrEqual(width)
}

async function capture(page: Page, name: string, width: number) {
  await noOverflow(page, width)
  await page.screenshot({ path: join(SHOTS_DIR, `${name}.png`), fullPage: true })
}

test('m2: dashboard @1280', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 })
  await stubApi(page)
  await signIn(page)
  await page.goto('/')
  await page.getByRole('navigation', { name: 'sections' }).waitFor()
  await capture(page, 'm2-dashboard-1280', 1280)
})

test('m2: module @768', async ({ page }) => {
  await page.setViewportSize({ width: 768, height: 900 })
  await stubApi(page)
  await signIn(page)
  await page.goto('/modules/hosts')
  await page.getByRole('button', { name: 'plan' }).waitFor()
  await capture(page, 'm2-module-768', 768)
})

test('m2: login @390', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await stubApi(page)
  await page.goto('/login')
  await page.getByRole('button', { name: 'sign in' }).waitFor()
  await capture(page, 'm2-login-390', 390)
})
