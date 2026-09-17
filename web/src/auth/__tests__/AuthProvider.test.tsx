/**
 * The session context, and the rule it exists for: a `401` from anywhere lands
 * the operator back at sign-in, with no crash and no loop.
 */

import { describe, expect, it } from 'bun:test'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useApiClient } from '@/api/ApiProvider'
import type { SessionView } from '@/api/auth'
import { type ApiClient, createApiClient } from '@/api/client'
import {
  errorResponse,
  type FetchStub,
  jsonResponse,
  renderWithProviders,
  stubFetch,
} from '@/test/providers'
import { useAuth } from '../AuthProvider'

const SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: false,
}

/** Shows the context's state, and can drive each of its transitions. */
function Probe() {
  const { status, session, expiresAt, login, logout } = useAuth()
  const client = useApiClient()

  return (
    <div>
      <p data-testid="status">{status}</p>
      <p data-testid="scopes">{session === null ? 'none' : session.scopes.join('+')}</p>
      <p data-testid="expires">{expiresAt === null ? 'none' : 'set'}</p>
      <button
        type="button"
        onClick={() => {
          void client.get('/api/v1/modules', {})
        }}
      >
        load modules
      </button>
      <button
        type="button"
        onClick={() => {
          void login({ username: 'operator', password: 'correct horse' })
        }}
      >
        sign in
      </button>
      <button
        type="button"
        onClick={() => {
          void logout()
        }}
      >
        sign out
      </button>
    </div>
  )
}

/** The client the provider will use, so a test can inspect the token it holds. */
function clientFor(stub: FetchStub): ApiClient {
  return createApiClient({ fetch: stub.fetch })
}

async function statusIs(value: string): Promise<void> {
  await waitFor(() => {
    expect(screen.getByTestId('status')).toHaveTextContent(value)
  })
}

describe('AuthProvider — session probe', () => {
  it('publishes the session the host reported', async () => {
    const stub = stubFetch([jsonResponse(SESSION)])
    const client = clientFor(stub)
    renderWithProviders(<Probe />, { client })

    await statusIs('authenticated')
    expect(screen.getByTestId('scopes')).toHaveTextContent('read+write')
    expect(screen.getByTestId('expires')).toHaveTextContent('set')
    await waitFor(() => {
      expect(client.hasCsrfToken()).toBe(true)
    })
  })

  it('treats a 401 from the probe as "nobody is signed in", not as a failure', async () => {
    const stub = stubFetch([errorResponse(401, 'web-auth-unauthenticated', 'unauthorized')])
    const client = clientFor(stub)
    renderWithProviders(<Probe />, { client })

    await statusIs('signed-out')
    await waitFor(() => {
      expect(client.hasCsrfToken()).toBe(false)
    })
    // One probe, and nothing that would probe again: no loop.
    expect(stub.calls).toHaveLength(1)
  })
})

describe('AuthProvider — 401 from anywhere', () => {
  it('signs the operator out, drops the token, and issues no further requests', async () => {
    const user = userEvent.setup()
    const stub = stubFetch([jsonResponse(SESSION)])
    const client = clientFor(stub)
    renderWithProviders(<Probe />, { client })
    await statusIs('authenticated')

    // The session died on the host; the next call anywhere says so.
    stub.push(errorResponse(401, 'web-auth-unauthenticated', 'unauthorized'))
    const before = stub.calls.length
    await user.click(screen.getByRole('button', { name: 'load modules' }))

    await statusIs('signed-out')
    await waitFor(() => {
      expect(client.hasCsrfToken()).toBe(false)
    })
    expect(screen.getByTestId('scopes')).toHaveTextContent('none')
    // Exactly the one call that got the 401 — the handler re-probes nothing.
    expect(stub.calls).toHaveLength(before + 1)
  })
})

describe('AuthProvider — login and logout', () => {
  it('adopts the session a successful login returned', async () => {
    const user = userEvent.setup()
    const stub = stubFetch([errorResponse(401, 'web-auth-unauthenticated', 'unauthorized')])
    const client = clientFor(stub)
    renderWithProviders(<Probe />, { client })
    await statusIs('signed-out')

    stub.push(jsonResponse(SESSION))
    await user.click(screen.getByRole('button', { name: 'sign in' }))

    await statusIs('authenticated')
    await waitFor(() => {
      expect(client.hasCsrfToken()).toBe(true)
    })
  })

  it('keeps the operator signed out when the credentials are refused', async () => {
    const user = userEvent.setup()
    const stub = stubFetch([errorResponse(401, 'web-auth-unauthenticated', 'unauthorized')])
    const client = clientFor(stub)
    renderWithProviders(<Probe />, { client })
    await statusIs('signed-out')

    stub.push(errorResponse(401, 'web-auth-invalid-credentials', 'unauthorized'))
    await user.click(screen.getByRole('button', { name: 'sign in' }))

    await statusIs('signed-out')
    await waitFor(() => {
      expect(client.hasCsrfToken()).toBe(false)
    })
  })

  it('ends the session and forgets the token on sign-out', async () => {
    const user = userEvent.setup()
    const stub = stubFetch([jsonResponse(SESSION)])
    const client = clientFor(stub)
    renderWithProviders(<Probe />, { client })
    await statusIs('authenticated')

    stub.push(new Response(null, { status: 204 }))
    await user.click(screen.getByRole('button', { name: 'sign out' }))

    await statusIs('signed-out')
    await waitFor(() => {
      expect(client.hasCsrfToken()).toBe(false)
    })
  })
})

describe('useAuth', () => {
  it('throws when used outside AuthProvider', () => {
    function Consumer() {
      const { status } = useAuth()
      return <div>{status}</div>
    }

    expect(() => render(<Consumer />)).toThrow('useAuth must be used inside <AuthProvider>')
  })
})
