/**
 * The forced password change: an account flagged `must_change_password` sees
 * this form instead of any page, and leaves it only by changing the password.
 */

import { describe, expect, it } from 'bun:test'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { SessionView } from '@/api/auth'
import { CSRF_HEADER } from '@/api/client'
import { errorResponse, jsonResponse, renderWithProviders, stubFetch } from '@/test/providers'
import { AppRoutes } from '../AppRoutes'
import { ROUTES } from '../paths'

const RESTRICTED: SessionView = {
  csrf_token: 'csrf-old',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: false,
  must_change_password: true,
}

const FRESH: SessionView = {
  ...RESTRICTED,
  csrf_token: 'csrf-new',
  must_change_password: false,
}

const NEW_PASSWORD = 'a new long passphrase'

async function renderRestricted(): Promise<ReturnType<typeof stubFetch>> {
  const stub = stubFetch([jsonResponse(RESTRICTED)])
  renderWithProviders(<AppRoutes />, { fetch: stub.fetch, route: ROUTES.settings })
  await screen.findByRole('button', { name: 'change password' })
  return stub
}

function passwordCalls(stub: ReturnType<typeof stubFetch>) {
  return stub.calls.filter((each) => each.url.endsWith('/auth/password'))
}

async function fill(
  user: ReturnType<typeof userEvent.setup>,
  current: string,
  next: string,
  confirm: string,
): Promise<void> {
  await user.type(screen.getByLabelText('current password'), current)
  await user.type(screen.getByLabelText('new password'), next)
  await user.type(screen.getByLabelText('confirm new password'), confirm)
  await user.click(screen.getByRole('button', { name: 'change password' }))
}

describe('ChangePasswordPage', () => {
  it('replaces every page for a session that must change its password', async () => {
    await renderRestricted()
    expect(screen.queryByText('this section is not built yet.')).toBeNull()
  })

  it('posts both passwords with the CSRF token, then lets the operator in', async () => {
    const user = userEvent.setup()
    const stub = await renderRestricted()

    stub.push(jsonResponse(FRESH))
    await fill(user, 'hunter2', NEW_PASSWORD, NEW_PASSWORD)

    expect(await screen.findByText('this section is not built yet.')).toBeInTheDocument()
    const [call] = passwordCalls(stub)
    expect(call?.url).toBe('/api/v1/auth/password')
    expect(call?.init.method).toBe('POST')
    expect(JSON.parse(String(call?.init.body))).toEqual({
      current_password: 'hunter2',
      new_password: NEW_PASSWORD,
    })
    expect(new Headers(call?.init.headers).get(CSRF_HEADER)).toBe('csrf-old')
  })

  it('refuses a mismatch or a short password without asking the host', async () => {
    const user = userEvent.setup()
    const stub = await renderRestricted()

    await fill(user, 'hunter2', NEW_PASSWORD, 'something else entirely')
    expect(await screen.findByText('the two new passwords are not the same.')).toBeInTheDocument()

    await user.clear(screen.getByLabelText('new password'))
    await user.clear(screen.getByLabelText('confirm new password'))
    await user.type(screen.getByLabelText('new password'), 'short')
    await user.type(screen.getByLabelText('confirm new password'), 'short')
    await user.click(screen.getByRole('button', { name: 'change password' }))
    expect(
      await screen.findByText('a password must have at least 12 characters.'),
    ).toBeInTheDocument()

    expect(passwordCalls(stub)).toHaveLength(0)
  })

  it('shows a sentence, not an id, when the host refuses the current password', async () => {
    const user = userEvent.setup()
    const stub = await renderRestricted()

    stub.push(errorResponse(401, 'web-auth-invalid-credentials', 'unauthorized'))
    await fill(user, 'wrong', NEW_PASSWORD, NEW_PASSWORD)

    await waitFor(() => {
      expect(passwordCalls(stub)).toHaveLength(1)
    })
    expect(
      await screen.findByText('the user name, password or code was not correct.'),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'change password' })).toBeInTheDocument()
  })
})
