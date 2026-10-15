/**
 * The API token panel on the settings page: the list, minting a token that
 * is shown once, and revoking one after a confirmation. Both writes go
 * through the step-up guard.
 */

import { afterEach, describe, expect, it, mock } from 'bun:test'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { IssuedToken, SessionView, TokenView } from '@/api/auth'
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

const FAR_FUTURE = 4_000_000_000

const LAPTOP: TokenView = {
  id: '0123456789abcdef',
  label: 'laptop',
  scopes: ['read'],
  created: '2026-10-14T08:00:00Z',
  expires_at: null,
}

const CI: TokenView = {
  id: 'fedcba9876543210',
  label: 'ci',
  scopes: ['read', 'write'],
  created: '2026-10-14T09:00:00Z',
  expires_at: FAR_FUTURE,
}

const OLD: TokenView = {
  id: '00000000000000ff',
  label: 'old',
  scopes: ['read'],
  created: 'not a time',
  expires_at: 1_000_000_000,
}

const VALUE = 'a'.repeat(64)

const ISSUED: IssuedToken = { ...CI, token: VALUE }

const TOKENS = '/api/v1/auth/tokens'

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

/** The settings page, with `rules` tried before the other panels' reads. */
function render(rules: Parameters<typeof stubFetchByUrl>[0]) {
  const stub = stubFetchByUrl([
    ...rules,
    ['GET /api/v1/auth/totp', () => jsonResponse({ enrolled: false, required: false })],
    ['GET /api/v1/auth/sessions', () => jsonResponse([])],
    ['GET /api/v1/auth/session', () => jsonResponse(SESSION)],
  ])
  renderWithProviders(<AppRoutes />, { fetch: stub.fetch, route: ROUTES.settings })
  return stub
}

function posts(calls: StubCall[], path: string): StubCall[] {
  return calls.filter((each) => each.init.method === 'POST' && each.url.endsWith(path))
}

function reads(calls: StubCall[]): number {
  return calls.filter((each) => each.init.method !== 'POST' && each.url.endsWith(TOKENS)).length
}

function csrf(call: StubCall | undefined): string | null {
  return new Headers(call?.init.headers).get(CSRF_HEADER)
}

function body(call: StubCall | undefined): unknown {
  return JSON.parse(String(call?.init.body))
}

/** Puts `writeText` on `navigator.clipboard`; returns what was written. */
function clipboard(writeText: (text: string) => Promise<void>) {
  const write = mock(writeText)
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: write },
    configurable: true,
  })
  return write
}

const createForm = () => screen.getByRole('form', { name: 'create an api token' })

afterEach(() => {
  Reflect.deleteProperty(navigator, 'clipboard')
})

describe('TokensPanel', () => {
  it('lists the tokens with their scope and expiry, and no value', async () => {
    render([[`GET ${TOKENS}`, () => jsonResponse([LAPTOP, CI, OLD])]])

    const table = await screen.findByRole('table', { name: 'api tokens on this host' })
    const rows = within(table).getAllByRole('row')
    expect(rows).toHaveLength(4)
    const [, laptop, ci, old] = rows
    if (laptop === undefined || ci === undefined || old === undefined) {
      throw new Error('rows missing')
    }
    expect(within(laptop).getByText('laptop')).toBeInTheDocument()
    expect(within(laptop).getByText('read')).toBeInTheDocument()
    expect(within(laptop).getByText('never')).toBeInTheDocument()
    expect(within(ci).getByText('read and write')).toBeInTheDocument()
    expect(
      within(ci).getByText(formatUnixSeconds('en-US', FAR_FUTURE) ?? 'missing'),
    ).toBeInTheDocument()
    expect(within(old).getByText('expired')).toBeInTheDocument()
    expect(within(old).getByText('unknown')).toBeInTheDocument()
    expect(within(ci).getByRole('button', { name: /revoke the token .*ci/ })).toBeEnabled()
    // The id names the row; it is not text on the screen.
    expect(screen.queryByText(CI.id)).toBeNull()
  })

  it('says so when there are no tokens', async () => {
    render([[`GET ${TOKENS}`, () => jsonResponse([])]])
    expect(await screen.findByText('no api tokens yet.')).toBeInTheDocument()
  })

  it('creates a token and shows its value once, to copy', async () => {
    const user = userEvent.setup()
    const stub = render([
      [`POST ${TOKENS}`, () => jsonResponse(ISSUED, { status: 201 })],
      [
        `GET ${TOKENS}`,
        sequence(
          () => jsonResponse([]),
          () => jsonResponse([CI]),
        ),
      ],
    ])
    const write = clipboard(() => Promise.resolve())

    await screen.findByText('no api tokens yet.')
    await user.type(within(createForm()).getByLabelText('label'), 'ci')
    await user.selectOptions(within(createForm()).getByLabelText('scope'), 'write')
    await user.type(within(createForm()).getByLabelText('expires after (days)'), '30')
    await user.click(screen.getByRole('button', { name: 'create token' }))

    const field = await screen.findByRole('textbox', { name: /^token / })
    expect(field).toHaveValue(VALUE)
    expect(field).toHaveAttribute('readonly')
    await waitFor(() => {
      expect(field).toHaveFocus()
    })
    expect(screen.getByText(/shown once/)).toBeInTheDocument()
    const [sent] = posts(stub.calls, TOKENS)
    expect(body(sent)).toEqual({ label: 'ci', scope: 'write', expires_in_secs: 30 * 86_400 })
    expect(csrf(sent)).toBe('csrf-token')
    // The form is cleared for the next one.
    expect(within(createForm()).getByLabelText('label')).toHaveValue('')
    expect(within(createForm()).getByLabelText('expires after (days)')).toHaveValue(null)

    await user.click(screen.getByRole('button', { name: 'copy' }))
    expect(await screen.findByText('copied.')).toBeInTheDocument()
    expect(write).toHaveBeenCalledWith(VALUE)

    await waitFor(() => {
      expect(reads(stub.calls)).toBe(2)
    })
    // The list never carries the value.
    expect(screen.queryAllByText(VALUE, { exact: false })).toHaveLength(0)

    await user.click(screen.getByRole('button', { name: 'done' }))
    expect(screen.queryByRole('textbox', { name: /^token / })).toBeNull()
    expect(screen.queryByDisplayValue(VALUE)).toBeNull()
  })

  it('sends no expiry when the field is empty, and says nothing when a copy fails', async () => {
    const user = userEvent.setup()
    const stub = render([
      [`POST ${TOKENS}`, () => jsonResponse({ ...ISSUED, expires_at: null }, { status: 201 })],
      [`GET ${TOKENS}`, () => jsonResponse([])],
    ])
    const write = clipboard(() => Promise.reject(new Error('denied')))

    await screen.findByText('no api tokens yet.')
    await user.type(within(createForm()).getByLabelText('label'), 'ci')
    await user.click(screen.getByRole('button', { name: 'create token' }))
    await screen.findByDisplayValue(VALUE)
    expect(body(posts(stub.calls, TOKENS)[0])).toEqual({ label: 'ci', scope: 'read' })

    await user.click(screen.getByRole('button', { name: 'copy' }))
    await waitFor(() => {
      expect(write).toHaveBeenCalledTimes(1)
    })
    expect(screen.queryByText('copied.')).toBeNull()
  })

  it('lets the browser refuse an expiry that is not a whole number of days', async () => {
    const user = userEvent.setup()
    const stub = render([[`GET ${TOKENS}`, () => jsonResponse([])]])

    await screen.findByText('no api tokens yet.')
    await user.type(within(createForm()).getByLabelText('label'), 'ci')
    const days = within(createForm()).getByLabelText('expires after (days)')
    expect(days).toHaveAttribute('min', '1')
    expect(days).toHaveAttribute('step', '1')
    for (const typed of ['0', '1.5']) {
      await user.clear(days)
      await user.type(days, typed)
      await user.click(screen.getByRole('button', { name: 'create token' }))
      expect(days).toBeInvalid()
    }
    expect(posts(stub.calls, TOKENS)).toHaveLength(0)
  })

  it('asks for the password first when the host wants a step-up', async () => {
    const user = userEvent.setup()
    const stub = render([
      [
        `POST ${TOKENS}`,
        sequence(
          () => errorResponse(403, 'web-auth-step-up-required', 'forbidden'),
          () => jsonResponse(ISSUED, { status: 201 }),
        ),
      ],
      ['POST /api/v1/auth/reauth', () => jsonResponse({ step_up_expires_in_secs: 300 })],
      [`GET ${TOKENS}`, () => jsonResponse([])],
    ])

    await screen.findByText('no api tokens yet.')
    await user.type(within(createForm()).getByLabelText('label'), 'ci')
    await user.click(screen.getByRole('button', { name: 'create token' }))

    const dialog = await screen.findByRole('dialog', { name: 'enter your password again' })
    await user.type(within(dialog).getByLabelText('current password'), 'correct horse')
    await user.click(within(dialog).getByRole('button', { name: 'confirm' }))

    expect(await screen.findByDisplayValue(VALUE)).toBeInTheDocument()
    expect(posts(stub.calls, TOKENS)).toHaveLength(2)
    expect(posts(stub.calls, '/auth/reauth')).toHaveLength(1)
  })

  it('says why when the host refuses to mint, and shows no value', async () => {
    const user = userEvent.setup()
    render([
      [`POST ${TOKENS}`, () => errorResponse(403, 'web-auth-token-totp-required', 'forbidden')],
      [`GET ${TOKENS}`, () => jsonResponse([])],
    ])

    await screen.findByText('no api tokens yet.')
    await user.type(within(createForm()).getByLabelText('label'), 'ci')
    await user.click(screen.getByRole('button', { name: 'create token' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'this host requires a second factor. sign in with your code before you create an api token.',
    )
    expect(screen.queryByRole('region', { name: 'new api token' })).toBeNull()
  })

  it('revokes a token after a confirmation, with the csrf token', async () => {
    const user = userEvent.setup()
    const stub = render([
      [`POST ${TOKENS}/${CI.id}/revoke`, () => new Response(null, { status: 204 })],
      [
        `GET ${TOKENS}`,
        sequence(
          () => jsonResponse([LAPTOP, CI]),
          () => jsonResponse([LAPTOP]),
        ),
      ],
    ])

    await user.click(await screen.findByRole('button', { name: /revoke the token .*ci/ }))
    const dialog = screen.getByRole('dialog', { name: 'revoke this token?' })
    expect(within(dialog).getByText(/stops working at once/)).toBeInTheDocument()
    expect(posts(stub.calls, '/revoke')).toHaveLength(0)
    await user.click(within(dialog).getByRole('button', { name: 'revoke' }))

    expect(await screen.findByText('the token is revoked.')).toBeInTheDocument()
    expect(csrf(posts(stub.calls, `/tokens/${CI.id}/revoke`)[0])).toBe('csrf-token')
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /revoke the token .*ci/ })).toBeNull()
    })
  })

  it('cancel and escape close the dialog and revoke nothing', async () => {
    const user = userEvent.setup()
    const stub = render([[`GET ${TOKENS}`, () => jsonResponse([LAPTOP])]])

    await user.click(await screen.findByRole('button', { name: /revoke the token .*laptop/ }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()

    await user.click(screen.getByRole('button', { name: /revoke the token .*laptop/ }))
    expect(screen.getByRole('dialog', { name: 'revoke this token?' })).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(posts(stub.calls, '/revoke')).toHaveLength(0)
  })

  it('says why when a revoke is refused, and reads the list again', async () => {
    const user = userEvent.setup()
    const stub = render([
      [
        `POST ${TOKENS}/${LAPTOP.id}/revoke`,
        () => errorResponse(404, 'web-auth-token-unknown', 'not_found'),
      ],
      [`GET ${TOKENS}`, () => jsonResponse([LAPTOP])],
    ])

    await user.click(await screen.findByRole('button', { name: /revoke the token .*laptop/ }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'revoke' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'that api token does not exist, is revoked, or has expired.',
    )
    await waitFor(() => {
      expect(reads(stub.calls)).toBe(2)
    })
  })

  it('shows a sentence when the list cannot be read', async () => {
    render([[`GET ${TOKENS}`, () => errorResponse(500, 'web-auth-store-unreadable')]])

    expect(await screen.findByRole('alert')).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: 'api tokens on this host' })).toBeNull()
  })

  it('says it is reading while the list is on its way', async () => {
    const stub = stubFetchByUrl([
      ['GET /api/v1/auth/totp', () => jsonResponse({ enrolled: false, required: false })],
      ['GET /api/v1/auth/sessions', () => jsonResponse([])],
      ['GET /api/v1/auth/session', () => jsonResponse(SESSION)],
    ])
    // The list never answers, so the panel stays in its reading state.
    const fetch = (input: string | URL | Request, init?: RequestInit) =>
      String(input).endsWith(TOKENS) ? new Promise<Response>(() => {}) : stub.fetch(input, init)
    renderWithProviders(<AppRoutes />, {
      fetch: fetch as typeof globalThis.fetch,
      route: ROUTES.settings,
    })

    expect(await screen.findByText('reading the api tokens.')).toBeInTheDocument()
  })
})
