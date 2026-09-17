/**
 * The guard, end to end: what an operator sees at an address, and where a
 * `401` puts them.
 *
 * Every case drives `ROUTES.settings` on purpose. The subject here is the
 * guard, not a page, and settings is still a placeholder that asks the host
 * for nothing — so the only request in flight is `AuthProvider`'s session
 * probe, the call-order `stubFetch` stays sound, and the "no further calls
 * after the 401" assertion counts what it says it counts. Pointing these at a
 * real section would silently turn them into tests of that section's queries.
 * If settings ever grows a query, move these to whatever is still inert
 * rather than teaching the guard test about page data.
 */

import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { useApiClient } from '@/api/ApiProvider'
import type { SessionView } from '@/api/auth'
import { errorResponse, jsonResponse, renderWithProviders, stubFetch } from '@/test/providers'
import { AppRoutes } from '../AppRoutes'
import { ROUTES } from '../paths'

const SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: false,
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
    renderWithProviders(<AppRoutes />, { fetch: stub.fetch, route: ROUTES.settings })

    expect(await screen.findByRole('button', { name: 'sign in' })).toBeInTheDocument()
    expect(screen.queryByText('this section is not built yet.')).toBeNull()
  })

  it('renders the guarded page for a live session', async () => {
    const stub = stubFetch([jsonResponse(SESSION)])
    renderWithProviders(<AppRoutes />, { fetch: stub.fetch, route: ROUTES.settings })

    expect(await screen.findByText('this section is not built yet.')).toBeInTheDocument()
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
      { fetch: stub.fetch, route: ROUTES.settings },
    )
    await screen.findByText('this section is not built yet.')

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
