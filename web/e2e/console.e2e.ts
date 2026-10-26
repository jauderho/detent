/**
 * The flows an operator actually performs, in a real browser against the built
 * bundle.
 *
 * These assert the things a jsdom/happy-dom unit test structurally cannot:
 * what the stylesheet does to text, where focus goes when a dialog opens, and
 * whether a keyboard alone can get through the apply flow.
 */

import { expect, type Page, test } from '@playwright/test'
import { AVAILABLE_LOCALES } from '../src/i18n/locales'
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

test.describe('sign-in notices', () => {
  test('lists what changed and is dismissed from the keyboard', async ({ page }) => {
    await stubApi(page, { withNotices: true })
    await signIn(page)

    const notice = page.getByRole('status').filter({ hasText: 'since your last sign-in' })
    await expect(notice).toContainText('password changed')
    await expect(notice).toContainText('198.51.100.9')
    await expect(notice).toContainText('refused sign-in attempts since then')

    await notice.getByRole('button', { name: 'dismiss' }).focus()
    await page.keyboard.press('Enter')
    await expect(notice).toBeHidden()
  })

  test('shows nothing when nothing changed', async ({ page }) => {
    await stubApi(page)
    await signIn(page)

    await expect(page.getByText('since your last sign-in')).toBeHidden()
  })
})

test.describe('active sessions', () => {
  test('a keyboard alone ends another session after a confirmation', async ({ page }) => {
    const calls = await stubApi(page)
    await signIn(page)
    await page.getByRole('link', { name: 'settings' }).click()

    const table = page.getByRole('table', { name: 'sessions of this account' })
    await expect(table.getByText('this session')).toBeVisible()
    const end = table.getByRole('button', { name: /end the session signed in on/ })
    await end.focus()
    await page.keyboard.press('Enter')

    const dialog = page.getByRole('dialog', { name: 'end this session?' })
    await expect(dialog).toBeVisible()
    await expect(dialog.locator(':focus')).toHaveCount(1)
    await dialog.getByRole('button', { name: 'end', exact: true }).focus()
    await page.keyboard.press('Enter')

    await expect(page.getByText('the session is ended.')).toBeVisible()
    await expect(end).toBeHidden()
    expect(calls.some((call) => call.method === 'POST' && call.url.endsWith('/revoke'))).toBe(true)
  })
})

test.describe('api tokens', () => {
  test('a token is created, shown once, and revoked', async ({ page }) => {
    const calls = await stubApi(page, { stepUp: true })
    await signIn(page)
    await page.getByRole('link', { name: 'settings' }).click()

    const form = page.getByRole('form', { name: 'create an api token' })
    await form.getByLabel('label').fill('deploy bot')
    await form.getByLabel('scope').selectOption('write')
    await form.getByLabel('expires after (days)').fill('7')
    await form.getByRole('button', { name: 'create token' }).focus()
    await page.keyboard.press('Enter')

    // The host wants a step-up first; a keyboard alone gets through it.
    const stepUp = page.getByRole('dialog', { name: 'enter your password again' })
    await expect(stepUp).toBeVisible()
    await stepUp.getByLabel('current password').focus()
    await page.keyboard.type('correct horse battery staple')
    await page.keyboard.press('Enter')
    await expect(stepUp).toBeHidden()

    const value = 'e2e0'.repeat(16)
    const field = page.getByRole('textbox', { name: /^token / })
    await expect(field).toHaveValue(value)
    await expect(field).toBeFocused()
    await expect(page.getByText(/shown once/)).toBeVisible()
    const creates = calls.filter((call) => call.method === 'POST' && call.url.endsWith('/tokens'))
    expect(creates).toHaveLength(2)
    expect(creates[1]?.body).toEqual({
      label: 'deploy bot',
      scope: 'write',
      expires_in_secs: 7 * 86_400,
    })

    // Closed, the value is gone from the page; the list never had it.
    await page.getByRole('button', { name: 'done' }).click()
    await expect(field).toBeHidden()
    await expect(page.getByText(value)).toHaveCount(0)

    const table = page.getByRole('table', { name: 'api tokens on this host' })
    const revoke = table.getByRole('button', { name: /revoke the token .*deploy bot/ })
    await revoke.focus()
    await page.keyboard.press('Enter')
    const dialog = page.getByRole('dialog', { name: 'revoke this token?' })
    await expect(dialog).toBeVisible()
    await dialog.getByRole('button', { name: 'revoke', exact: true }).focus()
    await page.keyboard.press('Enter')

    await expect(page.getByText('the token is revoked.')).toBeVisible()
    await expect(revoke).toBeHidden()
    expect(
      calls.some((call) => call.method === 'POST' && call.url.endsWith('/fedcba9876543210/revoke')),
    ).toBe(true)
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
    await expect.poll(() => calls.some((call) => call.url.endsWith('/commits/pending'))).toBe(true)
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
    await expect(
      page.getByRole('alert').filter({ hasText: 'waiting to be confirmed' }),
    ).toBeVisible()
    // The armed window belongs to the shell, so it is still there after
    // navigating away from the page that started it.
    await page.getByRole('link', { name: 'audit' }).click()
    await expect(
      page.getByRole('alert').filter({ hasText: 'waiting to be confirmed' }),
    ).toBeVisible()

    const apply = calls.find((call) => call.url.endsWith('/apply'))
    expect(apply).toBeDefined()
    // The hash-conflict guard: an apply that omits this silently overwrites
    // whatever another operator wrote in the meantime.
    expect(apply?.body).toMatchObject({ expected_hash: 'b'.repeat(64) })
  })

  test('apply asks for the password, then applies', async ({ page }) => {
    const calls = await stubApi(page, { stepUp: true })
    await signIn(page)
    await page.getByRole('link', { name: 'modules' }).click()
    await page.getByRole('link', { name: 'hosts' }).click()
    await page.getByRole('button', { name: 'plan', exact: true }).click()
    await page.getByRole('button', { name: 'apply this change' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'apply', exact: true }).click()

    // The host refused the apply: the console asks for the password, with
    // focus inside the dialog, and a keyboard alone gets through it.
    const stepUp = page.getByRole('dialog', { name: 'enter your password again' })
    await expect(stepUp).toBeVisible()
    await expect(stepUp.locator(':focus')).toHaveCount(1)
    await stepUp.getByLabel('current password').focus()
    await page.keyboard.type('correct horse battery staple')
    await page.keyboard.press('Enter')

    await expect(stepUp).toBeHidden()
    await expect(page.getByText(/the change was written to/)).toBeVisible()
    const applies = calls.filter((call) => call.method === 'POST' && call.url.endsWith('/apply'))
    expect(applies).toHaveLength(2)
    const reauth = calls.find((call) => call.url.endsWith('/auth/reauth'))
    expect(reauth?.body).toEqual({ password: 'correct horse battery staple' })
  })

  /**
   * H21: the commit-confirm window lives on the host, not in the tab. A reload
   * drops every piece of React state, so the banner that comes back after one
   * can only have come from `GET /commits/pending` — and its Confirm must still
   * reach the host, or the change rolls itself back whatever the operator
   * wanted.
   */
  test('an armed window survives a reload and is confirmed', async ({ page }) => {
    const calls = await stubApi(page)
    await signIn(page)
    await page.getByRole('link', { name: 'modules' }).click()
    await page.getByRole('link', { name: 'hosts' }).click()
    await page.getByRole('button', { name: 'plan', exact: true }).click()
    await page.getByRole('button', { name: 'apply this change' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'apply', exact: true }).click()

    const banner = page.getByRole('alert').filter({ hasText: 'waiting to be confirmed' })
    await expect(banner).toBeVisible()

    const pendingReadsBefore = calls.filter((call) => call.url.endsWith('/commits/pending')).length
    await page.reload()
    await expect(banner).toBeVisible()
    expect(calls.filter((call) => call.url.endsWith('/commits/pending')).length).toBeGreaterThan(
      pendingReadsBefore,
    )

    await banner.getByRole('button', { name: 'confirm change' }).click()
    await expect(banner).toHaveCount(0)
    expect(
      calls.some((call) => call.method === 'POST' && call.url.endsWith('/commits/1/confirm')),
    ).toBe(true)
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

test.describe('a phone-width screen', () => {
  /**
   * `body` clips horizontal overflow, so a section wider than the screen does
   * not scroll — it is cut off, and a control past the edge cannot be reached.
   * The width the document asks for is the only place that shows.
   */
  const WIDTH = 390
  /** Every section, and a module page with a live form, by address. */
  const PAGES = [
    '/',
    '/modules',
    '/modules/hosts',
    '/services',
    '/backups',
    '/audit',
    '/certificates',
    '/settings',
  ]
  const pageWidth = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth)

  // Every locale: a German or French caption is wider than the English one, and
  // the pseudo-locale's brackets make every string wider.
  for (const locale of AVAILABLE_LOCALES) {
    test(`no page is wider than ${WIDTH}px in ${locale}`, async ({ page }) => {
      await page.setViewportSize({ width: WIDTH, height: 844 })
      await stubApi(page)
      await page.goto('/')
      await page.getByRole('combobox', { name: 'interface language' }).selectOption(locale)
      await expect(page.locator('html')).toHaveAttribute('lang', locale)
      expect(await pageWidth(page), `${locale} sign-in`).toBeLessThanOrEqual(WIDTH)

      // The form's labels are in the chosen language, so find its fields by name.
      await page.locator('input[name="username"]').fill('operator')
      await page.locator('input[name="password"]').fill('correct horse battery staple')
      await page.locator('button[type="submit"]').click()
      await page.getByRole('navigation').waitFor()

      for (const path of PAGES) {
        await page.goto(path)
        await page.getByRole('heading', { level: 1 }).waitFor()
        if (path === '/modules/hosts') await page.getByRole('textbox').first().waitFor()
        if (path === '/settings') await page.getByRole('table').nth(1).waitFor()
        expect(await pageWidth(page), `${locale} ${path}`).toBeLessThanOrEqual(WIDTH)
      }
    })
  }
})

test.describe('keyboard and focus', () => {
  test('the first Tab stop is a skip link that moves focus to the page', async ({ page }) => {
    await stubApi(page)
    await signIn(page)
    // A fresh load, so Tab starts from the top of the page and not from wherever
    // the sign-in click left focus.
    await page.reload()
    await page.getByRole('navigation', { name: 'sections' }).waitFor()

    await page.keyboard.press('Tab')
    const skip = page.getByRole('link', { name: 'skip to content' })
    await expect(skip).toBeFocused()
    await expect(skip).toBeInViewport()

    await page.keyboard.press('Enter')
    await expect(page.getByRole('main')).toBeFocused()
  })

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

    await expect(page.getByRole('alert').filter({ hasText: 'privileged helper' })).toContainText(
      'privileged helper',
    )
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
