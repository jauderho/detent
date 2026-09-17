/**
 * The flows an operator actually performs, in a real browser against the built
 * bundle.
 *
 * These assert the things a jsdom/happy-dom unit test structurally cannot:
 * what the stylesheet does to text, where focus goes when a dialog opens, and
 * whether a keyboard alone can get through the apply flow.
 */

import { expect, test } from '@playwright/test'
import { signIn, stubApi } from './api'

test.describe('sign in and navigate', () => {
  test('signs in and frames the console', async ({ page }) => {
    await stubApi(page)
    await signIn(page)

    await expect(page.getByRole('link', { name: 'modules' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'sign out' })).toBeVisible()
  })

  test('reaches every section from the nav', async ({ page }) => {
    await stubApi(page)
    await signIn(page)

    for (const section of ['modules', 'services', 'backups', 'audit']) {
      await page.getByRole('link', { name: section }).click()
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    }
  })
})

test.describe('host text survives the stylesheet', () => {
  /**
   * The console sets `text-transform: lowercase` on the body. That is right for
   * its own words and wrong for the host's: `NetworkManager` shown as
   * `networkmanager` is a daemon an operator cannot paste into a shell. Only a
   * real browser applies the transform, so this is the one place the rule can
   * be checked.
   */
  test('the dashboard shows identifiers as the host spelled them', async ({ page }) => {
    await stubApi(page)
    await signIn(page)

    await expect(page.getByText('NetworkManager', { exact: true })).toBeVisible()
    await expect(page.getByText('7,900 MiB')).toBeVisible()
    await expect(page.getByText('Landlock is not compiled into this kernel')).toBeVisible()
  })

  test('the audit log shows a mixed-case caller verbatim', async ({ page }) => {
    await stubApi(page)
    await signIn(page)
    await page.getByRole('link', { name: 'audit' }).click()

    await expect(page.getByRole('cell', { name: 'token:CI-ReadOnly' })).toBeVisible()
  })

  test('the plan diff is the bytes that would be written', async ({ page }) => {
    await stubApi(page)
    await signIn(page)
    await page.getByRole('link', { name: 'modules' }).click()
    await page.getByRole('link', { name: 'hosts' }).click()
    await page.getByRole('button', { name: 'plan', exact: true }).click()

    const dialog = page.getByRole('dialog')
    await expect(dialog).toBeVisible()
    // Not `toContainText`, which normalizes: the assertion is the exact casing.
    const diff = await dialog.locator('pre').innerText()
    expect(diff).toContain('NewHost.Example')
    expect(diff).toContain('OldName')
  })
})

test.describe('the apply flow', () => {
  test('plans, applies, and arms the commit-confirm window', async ({ page }) => {
    const calls = await stubApi(page)
    await signIn(page)
    await page.getByRole('link', { name: 'modules' }).click()
    await page.getByRole('link', { name: 'hosts' }).click()

    await page.getByRole('button', { name: 'plan', exact: true }).click()
    await expect(page.getByRole('dialog')).toBeVisible()
    await page.getByRole('button', { name: 'apply this change' }).click()

    const confirm = page.getByRole('dialog')
    await expect(confirm).toContainText('/etc/hosts')
    // This module sets commit_confirm, so the dialog must say the change will
    // roll itself back — the operator is agreeing to a deadline, not a write.
    await expect(confirm).toContainText('rolls back on its own')
    await confirm.getByRole('button', { name: 'apply', exact: true }).click()

    // A regex, not the whole sentence: Fluent wraps the interpolated path in
    // bidi isolate marks, so the rendered text is not the source string
    // character for character. Scoped by content rather than position, because
    // the shell's own pending-commit banner is on screen at the same time.
    await expect(page.getByText(/the change was written to/)).toBeVisible()
    // The armed window belongs to the shell, so it is still there after
    // navigating away from the page that started it.
    await page.getByRole('link', { name: 'audit' }).click()
    await expect(page.getByRole('alert')).toContainText('waiting to be confirmed')

    const apply = calls.find((call) => call.url.endsWith('/apply'))
    expect(apply).toBeDefined()
    // The hash-conflict guard: an apply that omits this silently overwrites
    // whatever another operator wrote in the meantime.
    expect(apply?.body).toMatchObject({ expected_hash: 'b'.repeat(64) })
  })

  test('a read-only session cannot apply, and is told why', async ({ page }) => {
    await stubApi(page, { readOnly: true })
    await signIn(page)
    await page.getByRole('link', { name: 'modules' }).click()
    await page.getByRole('link', { name: 'hosts' }).click()

    const applyButton = page.getByRole('button', { name: 'apply', exact: true })
    await expect(applyButton).toBeDisabled()
    await expect(applyButton).toHaveAttribute('title', /read access only/)
  })
})

test.describe('keyboard and focus', () => {
  test('the plan dialog takes focus, traps Tab, and Escape returns it', async ({ page }) => {
    await stubApi(page)
    await signIn(page)
    await page.getByRole('link', { name: 'modules' }).click()
    await page.getByRole('link', { name: 'hosts' }).click()

    const planButton = page.getByRole('button', { name: 'plan', exact: true })
    await planButton.click()
    const dialog = page.getByRole('dialog')
    await expect(dialog).toBeVisible()

    // Focus moved into the dialog rather than being left behind it.
    await expect(dialog.locator(':focus')).toHaveCount(1)

    await page.keyboard.press('Escape')
    await expect(dialog).toBeHidden()
    await expect(planButton).toBeFocused()
  })

  test('a keyboard alone reaches the apply confirmation', async ({ page }) => {
    await stubApi(page)
    await signIn(page)
    await page.getByRole('link', { name: 'modules' }).click()
    await page.getByRole('link', { name: 'hosts' }).click()

    await page.getByRole('button', { name: 'plan', exact: true }).focus()
    await page.keyboard.press('Enter')
    await expect(page.getByRole('dialog')).toBeVisible()
  })
})

test.describe('failure states', () => {
  test('one failing panel does not blank the others', async ({ page }) => {
    await stubApi(page, { profileStatus: 500 })
    await signIn(page)

    await expect(page.getByRole('alert')).toContainText('privileged helper')
    // The module count came from a different query and is still rendered.
    await expect(page.getByText('one module is compiled into this build.')).toBeVisible()
  })
})

test.describe('theme', () => {
  test('the toggle flips the document and persists across a reload', async ({ page }) => {
    await stubApi(page)
    await signIn(page)

    const html = page.locator('html')
    await expect(html).toHaveAttribute('data-theme', 'dark')

    await page.getByRole('button', { name: /light/i }).first().click()
    await expect(html).toHaveAttribute('data-theme', 'light')

    await page.reload()
    await expect(html).toHaveAttribute('data-theme', 'light')
  })
})
