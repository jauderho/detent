/**
 * The shell: status bar on top, the section strip, the pending-commit slot,
 * and the routed page beneath them — composed with the providers `main.tsx`
 * wires, so a missing one fails here rather than in a browser.
 *
 * The signed-in case sits on `ROUTES.settings`, a section that still asks the
 * host for nothing. The subject is the frame around a page, not any page, and
 * parking this on a section with its own queries would make it fail whenever
 * that section's data shape changed — which is exactly what happened the first
 * time the real sections landed underneath it.
 */

import { describe, expect, it } from 'bun:test'
import { screen } from '@testing-library/react'
import type { SessionView } from '@/api/auth'
import { errorResponse, jsonResponse, renderWithProviders, stubFetch } from '@/test/providers'
import App from '../App'
import { ROUTES } from '../routes/paths'

const SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read'],
  subject: 'operator',
  totp_satisfied: false,
}

describe('App', () => {
  it('frames a signed-in operator with the status bar and the section strip', async () => {
    const stub = stubFetch([jsonResponse(SESSION)])
    renderWithProviders(<App />, { fetch: stub.fetch, route: ROUTES.settings })

    expect(await screen.findByText('this section is not built yet.')).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: 'sections' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'modules' })).toHaveAttribute('href', ROUTES.modules)
    expect(screen.getByRole('button', { name: 'sign out' })).toBeInTheDocument()
  })

  it('shows sign-in with no section strip when nobody is signed in', async () => {
    const stub = stubFetch([errorResponse(401, 'web-auth-unauthenticated', 'unauthorized')])
    renderWithProviders(<App />, { fetch: stub.fetch, route: ROUTES.dashboard })

    expect(await screen.findByRole('button', { name: 'sign in' })).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'sections' })).toBeNull()
  })
})
