/**
 * The session list on the settings page: every session of the account, the
 * current one marked, and ending one or all the others after a confirmation.
 */

import { describe, expect, it } from 'bun:test'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { SessionSummary, SessionView } from '@/api/auth'
import { CSRF_HEADER } from '@/api/client'
import { formatUnixSeconds } from '@/lib/format'
import {
  errorResponse,
  jsonResponse,
  renderWithProviders,
  type StubCall,
  stubFetchByUrl,
} from '@/test/providers'
import { AppRoutes } from '../AppRoutes'
import { ROUTES } from '../paths'

const SESSION: SessionView = {
  csrf_token: 'csrf-token',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: true,
  must_change_password: false,
}

const CURRENT: SessionSummary = {
  handle: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  created_unix_s: 1_789_605_296,
  last_seen_unix_s: 1_789_605_896,
  expires_in_secs: 899,
  totp_satisfied: true,
  current: true,
}

const OTHER: SessionSummary = {
  handle: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  created_unix_s: 1_789_600_000,
  last_seen_unix_s: 1_789_600_060,
  expires_in_secs: 61,
  totp_satisfied: false,
  current: false,
}

const THIRD: SessionSummary = { ...OTHER, handle: 'cccccccccccccccccccccccccccccccc' }

/** Answers `responses` in order for one endpoint; the last one repeats. */
function sequence(...responses: (() => Response)[]): () => Response {
  let index = 0
  return () => {
    const respond = responses[Math.min(index, responses.length - 1)]
    index += 1
    if (respond === undefined) throw new Error('no response')
    return respond()
  }
}

/** The settings page, with `rules` tried before the session probe. */
function render(rules: Parameters<typeof stubFetchByUrl>[0]) {
  const stub = stubFetchByUrl([
    ...rules,
    ['GET /api/v1/auth/totp', () => jsonResponse({ enrolled: false, required: false })],
    ['GET /api/v1/auth/tokens', () => jsonResponse([])],
    ['GET /api/v1/auth/session', () => jsonResponse(SESSION)],
  ])
  renderWithProviders(<AppRoutes />, { fetch: stub.fetch, route: ROUTES.settings })
  return stub
}

function posts(calls: StubCall[], path: string): StubCall[] {
  return calls.filter((each) => each.init.method === 'POST' && each.url.endsWith(path))
}

function reads(calls: StubCall[]): number {
  return calls.filter((each) => each.url.endsWith('/api/v1/auth/sessions')).length
}

function csrf(call: StubCall | undefined): string | null {
  return new Headers(call?.init.headers).get(CSRF_HEADER)
}

function time(seconds: number): string {
  return formatUnixSeconds('en-US', seconds) ?? ''
}

describe('SessionsPanel', () => {
  it('lists the sessions and marks the current one without an end control', async () => {
    render([['GET /api/v1/auth/sessions', () => jsonResponse([CURRENT, OTHER])]])

    const table = await screen.findByRole('table', { name: 'sessions of this account' })
    const rows = within(table).getAllByRole('row')
    // A header row and one row per session.
    expect(rows).toHaveLength(3)
    const [, current, other] = rows
    if (current === undefined || other === undefined) throw new Error('rows missing')
    expect(within(current).getByText('this session')).toBeInTheDocument()
    expect(within(current).queryByRole('button')).toBeNull()
    expect(within(current).getByText(time(CURRENT.created_unix_s))).toBeInTheDocument()
    expect(within(current).getByText(time(CURRENT.last_seen_unix_s))).toBeInTheDocument()
    expect(within(current).getByText(/15.*min/)).toBeInTheDocument()
    expect(within(current).getByText('yes')).toBeInTheDocument()
    expect(within(other).getByText(/2.*min/)).toBeInTheDocument()
    expect(within(other).getByText('no')).toBeInTheDocument()
    expect(
      within(other).getByRole('button', { name: /end the session signed in on/ }),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'end all other sessions' })).toBeEnabled()
    // The handle is the row key, never text on the screen.
    expect(screen.queryByText(OTHER.handle)).toBeNull()
  })

  it('ends one session after a confirmation, with the csrf token', async () => {
    const user = userEvent.setup()
    const stub = render([
      [
        `POST /api/v1/auth/sessions/${OTHER.handle}/revoke`,
        () => new Response(null, { status: 204 }),
      ],
      [
        'GET /api/v1/auth/sessions',
        sequence(
          () => jsonResponse([CURRENT, OTHER]),
          () => jsonResponse([CURRENT]),
        ),
      ],
    ])

    await user.click(await screen.findByRole('button', { name: /end the session signed in on/ }))
    const dialog = screen.getByRole('dialog', { name: 'end this session?' })
    expect(within(dialog).getByText(/is signed out at once/)).toBeInTheDocument()
    expect(posts(stub.calls, '/revoke')).toHaveLength(0)
    await user.click(within(dialog).getByRole('button', { name: 'end' }))

    expect(await screen.findByText('the session is ended.')).toBeInTheDocument()
    const [call] = posts(stub.calls, `/sessions/${OTHER.handle}/revoke`)
    expect(csrf(call)).toBe('csrf-token')
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /end the session signed in on/ })).toBeNull()
    })
    expect(screen.getByRole('button', { name: 'end all other sessions' })).toBeDisabled()
    expect(reads(stub.calls)).toBe(2)
  })

  it('cancel and escape close the dialog and end nothing', async () => {
    const user = userEvent.setup()
    const stub = render([['GET /api/v1/auth/sessions', () => jsonResponse([CURRENT, OTHER])]])

    await user.click(await screen.findByRole('button', { name: /end the session signed in on/ }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()

    await user.click(screen.getByRole('button', { name: 'end all other sessions' }))
    expect(screen.getByRole('dialog', { name: 'end all other sessions?' })).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(posts(stub.calls, '/revoke')).toHaveLength(0)
    expect(posts(stub.calls, '/revoke-others')).toHaveLength(0)
  })

  it('ends every other session and says how many', async () => {
    const user = userEvent.setup()
    const stub = render([
      ['POST /api/v1/auth/sessions/revoke-others', () => jsonResponse({ ended: 2 })],
      [
        'GET /api/v1/auth/sessions',
        sequence(
          () => jsonResponse([CURRENT, OTHER, THIRD]),
          () => jsonResponse([CURRENT]),
        ),
      ],
    ])

    await user.click(await screen.findByRole('button', { name: 'end all other sessions' }))
    const dialog = screen.getByRole('dialog', { name: 'end all other sessions?' })
    expect(within(dialog).getByText(/this session stays/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'end all other sessions' }))

    expect(await screen.findByText(/other sessions ended: .*2/)).toBeInTheDocument()
    expect(csrf(posts(stub.calls, '/sessions/revoke-others')[0])).toBe('csrf-token')
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'end all other sessions' })).toBeDisabled()
    })
  })

  it('says why when an end is refused, and reads the list again', async () => {
    const user = userEvent.setup()
    const stub = render([
      [
        `POST /api/v1/auth/sessions/${OTHER.handle}/revoke`,
        () => errorResponse(404, 'web-auth-session-unknown', 'not_found'),
      ],
      ['GET /api/v1/auth/sessions', () => jsonResponse([CURRENT, OTHER])],
    ])

    await user.click(await screen.findByRole('button', { name: /end the session signed in on/ }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'end' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'that session does not exist or has already ended.',
    )
    await waitFor(() => {
      expect(reads(stub.calls)).toBe(2)
    })
  })

  it('shows a sentence when the list cannot be read', async () => {
    render([['GET /api/v1/auth/sessions', () => errorResponse(500, 'web-auth-store-unreadable')]])

    expect(await screen.findByRole('alert')).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: 'sessions of this account' })).toBeNull()
    expect(screen.getByRole('button', { name: 'end all other sessions' })).toBeDisabled()
  })

  it('says it is reading while the list is on its way', async () => {
    const stub = stubFetchByUrl([
      ['GET /api/v1/auth/tokens', () => jsonResponse([])],
      ['GET /api/v1/auth/session', () => jsonResponse(SESSION)],
    ])
    // The list never answers, so the panel stays in its reading state.
    const fetch = (input: string | URL | Request, init?: RequestInit) =>
      String(input).endsWith('/api/v1/auth/sessions')
        ? new Promise<Response>(() => {})
        : String(input).endsWith('/api/v1/auth/totp')
          ? Promise.resolve(jsonResponse({ enrolled: false, required: false }))
          : stub.fetch(input, init)
    renderWithProviders(<AppRoutes />, {
      fetch: fetch as typeof globalThis.fetch,
      route: ROUTES.settings,
    })

    expect(await screen.findByText('reading the active sessions.')).toBeInTheDocument()
  })
})
