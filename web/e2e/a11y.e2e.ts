/**
 * axe-core over every routed section, in both themes.
 *
 * Run in a real browser on the built bundle, so the rules that depend on
 * computed style — contrast above all — are evaluated against the stylesheet
 * that ships rather than against inline defaults a DOM shim invents.
 *
 * `contrast:check` already proves the *tokens* clear 4.5:1 in both themes.
 * This is the other half: that the pairings the pages actually compose from
 * those tokens clear it too, which a palette check cannot know.
 */

import AxeBuilder from '@axe-core/playwright'
import { expect, type Page, test } from '@playwright/test'
import { signIn, stubApi } from './api'

/** WCAG 2.2 AA, which is what AESTHETIC_CONTRACT.md §11 commits to. */
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

async function scan(page: Page) {
  return new AxeBuilder({ page }).withTags(TAGS).analyze()
}

/** Reports every violation by rule and node, not just the count. */
function describeViolations(results: Awaited<ReturnType<typeof scan>>): string {
  return results.violations
    .map(
      (violation) =>
        `${violation.id} (${violation.impact ?? 'unknown'}): ${violation.help}\n` +
        violation.nodes.map((node) => `    ${node.target.join(' ')}`).join('\n'),
    )
    .join('\n')
}

const SECTIONS = ['modules', 'services', 'backups', 'audit', 'certificates', 'settings'] as const

test.describe('accessibility', () => {
  test('the sign-in screen is clean', async ({ page }) => {
    await stubApi(page)
    await page.goto('/')
    await page.getByRole('button', { name: 'sign in' }).waitFor()

    const results = await scan(page)
    expect(describeViolations(results)).toBe('')
  })

  test('the dashboard is clean', async ({ page }) => {
    await stubApi(page)
    await signIn(page)

    const results = await scan(page)
    expect(describeViolations(results)).toBe('')
  })

  for (const section of SECTIONS) {
    test(`the ${section} section is clean`, async ({ page }) => {
      await stubApi(page)
      await signIn(page)
      await page.getByRole('link', { name: section }).click()
      await page.getByRole('heading', { level: 1 }).waitFor()

      const results = await scan(page)
      expect(describeViolations(results)).toBe('')
    })
  }

  test('a module page with a live form is clean', async ({ page }) => {
    await stubApi(page)
    await signIn(page)
    await page.getByRole('link', { name: 'modules' }).click()
    await page.getByRole('link', { name: 'hosts' }).click()
    await page.getByRole('button', { name: 'plan', exact: true }).waitFor()

    const results = await scan(page)
    expect(describeViolations(results)).toBe('')
  })

  test('an open dialog is clean', async ({ page }) => {
    await stubApi(page)
    await signIn(page)
    await page.getByRole('link', { name: 'modules' }).click()
    await page.getByRole('link', { name: 'hosts' }).click()
    await page.getByRole('button', { name: 'plan', exact: true }).click()
    await page.getByRole('dialog').waitFor()

    const results = await scan(page)
    expect(describeViolations(results)).toBe('')
  })

  test('the light theme is clean', async ({ page }) => {
    await stubApi(page)
    await signIn(page)
    await page.evaluate(() => {
      document.documentElement.setAttribute('data-theme', 'light')
    })

    const results = await scan(page)
    expect(describeViolations(results)).toBe('')
  })
})
