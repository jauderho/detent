/**
 * The guard, end to end: what an operator sees at an address, and where a
 * `401` puts them.
 *
 * Every case drives an unknown address under the guard on purpose. The
 * subject here is the guard, not a page, and the not-found page asks the host
 * for nothing — so the only request in flight is `AuthProvider`'s session
 * probe, the call-order `stubFetch` stays sound, and the "no further calls
 * after the 401" assertion counts what it says it counts. Pointing these at a
 * real section would silently turn them into tests of that section's queries.
 */

import { describe, expect, it } from 'bun:test'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useApiClient } from '@/api/ApiProvider'
import type { SessionView } from '@/api/auth'
import { errorResponse, jsonResponse, renderWithProviders, stubFetch } from '@/test/providers'
import { AppRoutes } from '../AppRoutes'

/** An address under the guard whose page asks the host for nothing. */
const INERT_ROUTE = '/nothing-here'
const NOT_FOUND = 'that address does not name anything in this console.'

const SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: false,
  must_change_password: false,
}

/** Stands in for a page that talks to the host. */
function DataCall() {
  const client = useApiClient()
  return (
    <button
      type="button"
      onClick={() => {
        void client.get('/api/v1/modules', {})
      }}
    >
      load modules
    </button>
  )
}

describe('routing', () => {
  it('sends an unauthenticated visitor from a guarded address to sign-in', async () => {
    const stub = stubFetch([errorResponse(401, 'web-auth-unauthenticated', 'unauthorized')])
    renderWithProviders(<AppRoutes />, { fetch: stub.fetch, route: INERT_ROUTE })

    expect(await screen.findByRole('button', { name: 'sign in' })).toBeInTheDocument()
    expect(screen.queryByText(NOT_FOUND)).toBeNull()
  })

  it('renders the guarded page for a live session', async () => {
    const stub = stubFetch([jsonResponse(SESSION)])
    renderWithProviders(<AppRoutes />, { fetch: stub.fetch, route: INERT_ROUTE })

    expect(await screen.findByText(NOT_FOUND)).toBeInTheDocument()
  })

  it('answers an address it does not know with the not-found page', async () => {
    const stub = stubFetch([jsonResponse(SESSION)])
    renderWithProviders(<AppRoutes />, { fetch: stub.fetch, route: '/nothing-here' })

    expect(
      await screen.findByText('that address does not name anything in this console.'),
    ).toBeInTheDocument()
  })

  it('lands back at sign-in when a request answers 401, without looping', async () => {
    const user = userEvent.setup()
    const stub = stubFetch([jsonResponse(SESSION)])
    renderWithProviders(
      <>
        <DataCall />
        <AppRoutes />
      </>,
      { fetch: stub.fetch, route: INERT_ROUTE },
    )
    await screen.findByText(NOT_FOUND)

    stub.push(errorResponse(401, 'web-auth-unauthenticated', 'unauthorized'))
    const before = stub.calls.length
    await user.click(screen.getByRole('button', { name: 'load modules' }))

    expect(await screen.findByRole('button', { name: 'sign in' })).toBeInTheDocument()
    // The failed call, and nothing after it: the guard navigates, it does not
    // re-probe, and the login screen asks the host for nothing.
    await waitFor(() => {
      expect(stub.calls).toHaveLength(before + 1)
    })
    expect(stub.calls).toHaveLength(before + 1)
  })
})
