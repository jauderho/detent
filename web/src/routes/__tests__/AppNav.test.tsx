/**
 * The signed-in navigation strip: links, active-state styling, and sign-out.
 */

import { describe, expect, it } from 'bun:test'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { SessionView } from '@/api/auth'
import { jsonResponse, renderWithProviders, stubFetchByUrl } from '@/test/providers'
import { AppNav } from '../AppNav'
import { ROUTES } from '../paths'

const SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: true,
}

const AUTH_ROUTE = '/api/v1/auth/session'
const LOGOUT_ROUTE = '/api/v1/auth/logout'

describe('AppNav', () => {
  it('renders nothing while the session probe is in flight', () => {
    const { promise } = Promise.withResolvers<Response>()
    const calls: Array<{ url: string; init: RequestInit }> = []
    const fetch = ((input: string | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} })
      return promise
    }) as unknown as typeof globalThis.fetch
    renderWithProviders(<AppNav />, { fetch, route: ROUTES.dashboard })

    expect(screen.queryByRole('navigation')).toBeNull()
    expect(calls.length).toBeGreaterThan(0)
  })

  it('renders nothing for a signed-out operator', async () => {
    const stub = stubFetchByUrl([
      [AUTH_ROUTE, () => jsonResponse({ message_id: 'web-auth-unauthenticated' }, { status: 401 })],
    ])
    renderWithProviders(<AppNav />, { fetch: stub.fetch, route: ROUTES.dashboard })

    await waitFor(() => {
      expect(screen.queryByRole('navigation')).toBeNull()
    })
  })

  it('marks the dashboard link as active on the dashboard route', async () => {
    const stub = stubFetchByUrl([[AUTH_ROUTE, () => jsonResponse(SESSION)]])
    renderWithProviders(<AppNav />, { fetch: stub.fetch, route: ROUTES.dashboard })

    expect(await screen.findByRole('link', { name: 'dashboard' })).toHaveClass('primary')
  })

  it('calls logout when the operator presses sign out', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl([
      [AUTH_ROUTE, () => jsonResponse(SESSION)],
      [LOGOUT_ROUTE, () => new Response(null, { status: 204 })],
    ])
    renderWithProviders(<AppNav />, { fetch: stub.fetch, route: ROUTES.dashboard })

    await user.click(await screen.findByRole('button', { name: 'sign out' }))

    await waitFor(() => {
      expect(
        stub.calls.some((call) => call.url === LOGOUT_ROUTE && call.init.method === 'POST'),
      ).toBe(true)
    })
  })
})
