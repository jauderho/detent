/**
 * The sign-in screen: the happy path, a refusal, the second factor, and the
 * throttle.
 *
 * Every assertion about copy is about a *sentence*. The one thing this screen
 * must never do is put a `message_id` in front of an operator.
 */

import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import type { SessionView } from '@/api/auth'
import { CSRF_HEADER } from '@/api/client'
import { errorResponse, jsonResponse, renderWithProviders, stubFetch } from '@/test/providers'
import { LoginPage } from '../LoginPage'
import { ROUTES } from '../paths'

const SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: false,
}

/** The screen, mounted after the session probe has answered "nobody". */
async function renderLogin(): Promise<ReturnType<typeof stubFetch>> {
  const stub = stubFetch([errorResponse(401, 'web-auth-unauthenticated', 'unauthorized')])
  renderWithProviders(<LoginPage />, { fetch: stub.fetch, route: ROUTES.login })
  await screen.findByRole('button', { name: 'sign in' })
  return stub
}

function loginCall(stub: ReturnType<typeof stubFetch>): { url: string; body: unknown } | null {
  // The last one: a test that submits twice cares about the second attempt.
  const call = stub.calls.findLast((each) => each.url.endsWith('/auth/login'))
  if (call === undefined) return null
  const raw = call.init.body
  return { url: call.url, body: typeof raw === 'string' ? JSON.parse(raw) : null }
}

async function fillCredentials(
  user: ReturnType<typeof userEvent.setup>,
  password = 'correct horse',
): Promise<void> {
  await user.type(screen.getByLabelText('user name'), 'operator')
  await user.type(screen.getByLabelText('password'), password)
}

describe('LoginPage — signing in', () => {
  it('posts the credentials and never puts them in the url', async () => {
    const user = userEvent.setup()
    const stub = await renderLogin()

    stub.push(jsonResponse(SESSION))
    await fillCredentials(user)
    await user.click(screen.getByRole('button', { name: 'sign in' }))

    await waitFor(() => {
      expect(loginCall(stub)).not.toBeNull()
    })
    const call = loginCall(stub)
    expect(call?.url).toBe('/api/v1/auth/login')
    expect(call?.url).not.toContain('operator')
    expect(call?.body).toEqual({ username: 'operator', password: 'correct horse' })
  })

  it('is operable from the keyboard alone', async () => {
    const user = userEvent.setup()
    const stub = await renderLogin()
    stub.push(jsonResponse(SESSION))

    await user.tab()
    await user.keyboard('operator')
    await user.tab()
    await user.keyboard('correct horse')
    // Enter in a text field submits the form, as a real form does.
    await user.keyboard('{Enter}')

    await waitFor(() => {
      expect(loginCall(stub)?.body).toEqual({
        username: 'operator',
        password: 'correct horse',
      })
    })
  })

  it('sends no CSRF header before a session has issued a token', async () => {
    const user = userEvent.setup()
    const stub = await renderLogin()
    stub.push(jsonResponse(SESSION))

    await fillCredentials(user)
    await user.click(screen.getByRole('button', { name: 'sign in' }))

    await waitFor(() => {
      expect(loginCall(stub)).not.toBeNull()
    })
    const call = stub.calls.find((each) => each.url.endsWith('/auth/login'))
    expect(new Headers(call?.init.headers).get(CSRF_HEADER)).toBeNull()
  })
})

describe('LoginPage — refusals', () => {
  it('shows the localized sentence for bad credentials, not the message id', async () => {
    const user = userEvent.setup()
    const stub = await renderLogin()

    stub.push(errorResponse(401, 'web-auth-invalid-credentials', 'unauthorized'))
    await fillCredentials(user, 'wrong')
    await user.click(screen.getByRole('button', { name: 'sign in' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('the user name, password or code was not correct.')
    expect(alert.textContent).not.toContain('web-auth-invalid-credentials')
  })

  it('falls back to a generic sentence for a message id this build does not know', async () => {
    const user = userEvent.setup()
    const stub = await renderLogin()

    stub.push(errorResponse(500, 'web-auth-something-from-the-future', 'internal'))
    await fillCredentials(user)
    await user.click(screen.getByRole('button', { name: 'sign in' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('no description for')
    expect(alert.textContent).not.toContain('web-auth-something-from-the-future')
  })

  it('reports a host it cannot reach', async () => {
    const user = userEvent.setup()
    const stub = await renderLogin()

    stub.push(new Response('<html>gateway</html>', { status: 502 }))
    await fillCredentials(user)
    await user.click(screen.getByRole('button', { name: 'sign in' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('could not read')
  })
})

describe('LoginPage — the second factor', () => {
  it('offers the code field on request', async () => {
    const user = userEvent.setup()
    await renderLogin()

    expect(screen.queryByLabelText('authenticator code')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'use an authenticator code' }))

    expect(screen.getByLabelText('authenticator code')).toBeInTheDocument()
  })

  it('reveals it once the host refuses a sign-in, since a missing code is one reason it would', async () => {
    const user = userEvent.setup()
    const stub = await renderLogin()

    stub.push(errorResponse(401, 'web-auth-invalid-credentials', 'unauthorized'))
    await fillCredentials(user)
    await user.click(screen.getByRole('button', { name: 'sign in' }))

    expect(await screen.findByLabelText('authenticator code')).toBeInTheDocument()
  })

  it('sends the code with the credentials once it has one', async () => {
    const user = userEvent.setup()
    const stub = await renderLogin()

    stub.push(errorResponse(401, 'web-auth-invalid-credentials', 'unauthorized'))
    await fillCredentials(user)
    await user.click(screen.getByRole('button', { name: 'sign in' }))
    const totp = await screen.findByLabelText('authenticator code')

    stub.push(jsonResponse(SESSION))
    await user.type(totp, '123456')
    await user.click(screen.getByRole('button', { name: 'sign in' }))

    await waitFor(() => {
      expect(loginCall(stub)?.body).toEqual({
        username: 'operator',
        password: 'correct horse',
        totp_code: '123456',
      })
    })
  })
})

describe('LoginPage — throttling', () => {
  it('reports the wait a 429 asks for, in seconds', async () => {
    const user = userEvent.setup()
    const stub = await renderLogin()

    stub.push(
      jsonResponse(
        { code: 'rate_limited', message_id: 'web-auth-rate-limited' },
        { status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': '30' } },
      ),
    )
    await fillCredentials(user)
    await user.click(screen.getByRole('button', { name: 'sign in' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('30')
    expect(alert).toHaveTextContent('too many attempts')
    expect(alert.textContent).not.toContain('web-auth-rate-limited')
  })

  it('falls back to the argument-free sentence when the host sends no Retry-After', async () => {
    const user = userEvent.setup()
    const stub = await renderLogin()

    stub.push(errorResponse(429, 'web-auth-rate-limited', 'rate_limited'))
    await fillCredentials(user)
    await user.click(screen.getByRole('button', { name: 'sign in' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('too many attempts')
    expect(alert.textContent).not.toContain('{$seconds}')
  })
})
