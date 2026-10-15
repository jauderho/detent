/**
 * The settings page: the second factor of the signed-in account, turned on
 * with a password, a QR code and a code, and turned off with a password and a
 * code.
 */

import { describe, expect, it } from 'bun:test'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { SessionView, TotpEnrolment, TotpStatus } from '@/api/auth'
import { CSRF_HEADER } from '@/api/client'
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
  csrf_token: 'csrf-old',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: false,
  must_change_password: false,
}

const RENEWED: SessionView = { ...SESSION, csrf_token: 'csrf-new', totp_satisfied: true }

const ENROLMENT: TotpEnrolment = {
  uri: 'otpauth://totp/detent:operator?secret=JBSWY3DPEHPK3PXP&issuer=detent',
  secret: 'JBSWY3DPEHPK3PXP',
  expires_in_secs: 600,
}

const OFF: TotpStatus = { enrolled: false, required: false }
const ON: TotpStatus = { enrolled: true, required: false }

const REFUSED = (): Response => errorResponse(401, 'web-auth-invalid-credentials', 'unauthorized')
const REFUSED_TEXT = 'the user name, password or code was not correct.'

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

function render(rules: Parameters<typeof stubFetchByUrl>[0]) {
  // The session list first: the probe pattern below is a prefix of its URL.
  // SessionsPanel.test.tsx covers the list itself.
  const stub = stubFetchByUrl([
    ['GET /api/v1/auth/sessions', () => jsonResponse([])],
    ['GET /api/v1/auth/session', () => jsonResponse(SESSION)],
    ...rules,
  ])
  renderWithProviders(<AppRoutes />, { fetch: stub.fetch, route: ROUTES.settings })
  return stub
}

function posts(calls: StubCall[], path: string): StubCall[] {
  return calls.filter((each) => each.init.method === 'POST' && each.url.endsWith(path))
}

function body(call: StubCall | undefined): unknown {
  return JSON.parse(String(call?.init.body))
}

function csrf(call: StubCall | undefined): string | null {
  return new Headers(call?.init.headers).get(CSRF_HEADER)
}

describe('SettingsPage', () => {
  it('turns the second factor on with the password, the key and a code', async () => {
    const user = userEvent.setup()
    const stub = render([
      ['GET /api/v1/auth/totp', () => jsonResponse(OFF)],
      ['POST /api/v1/auth/totp/enrol', () => jsonResponse(ENROLMENT)],
      ['POST /api/v1/auth/totp/confirm', () => jsonResponse(RENEWED)],
      ['POST /api/v1/auth/totp/disable', () => jsonResponse({ ...RENEWED, csrf_token: 'x' })],
    ])

    expect(await screen.findByRole('heading', { name: 'settings' })).toBeInTheDocument()
    expect(
      await screen.findByText('the second factor is off. sign-in asks for the password only.'),
    ).toBeInTheDocument()
    await user.type(screen.getByLabelText('current password'), 'hunter2')
    await user.click(screen.getByRole('button', { name: 'turn on' }))

    expect(
      await screen.findByRole('img', { name: 'qr code with the new authenticator key' }),
    ).toBeInTheDocument()
    expect(screen.getByText('JBSW Y3DP EHPK 3PXP')).toBeInTheDocument()
    expect(screen.getByText(/waits.*10.*minutes/)).toBeInTheDocument()
    const [enrol] = posts(stub.calls, '/auth/totp/enrol')
    expect(body(enrol)).toEqual({ current_password: 'hunter2' })
    expect(csrf(enrol)).toBe('csrf-old')

    const code = screen.getByLabelText('authenticator code')
    await waitFor(() => {
      expect(code).toHaveFocus()
    })
    expect(code).toHaveAttribute('autocomplete', 'one-time-code')
    expect(code).toHaveAttribute('inputmode', 'numeric')
    await user.type(code, '123456')
    await user.click(screen.getByRole('button', { name: 'confirm' }))

    expect(
      await screen.findByText('the second factor is on. sign in with a code next time.'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        'the second factor is on. each sign-in asks for a code from your authenticator.',
      ),
    ).toBeInTheDocument()
    expect(screen.queryByRole('img')).toBeNull()
    const [confirm] = posts(stub.calls, '/auth/totp/confirm')
    expect(body(confirm)).toEqual({ code: '123456' })

    // The next change carries the CSRF token of the session confirm answered.
    await user.type(screen.getByLabelText('current password'), 'hunter2')
    await user.type(screen.getByLabelText('authenticator code'), '654321')
    await user.click(screen.getByRole('button', { name: 'turn off' }))
    await waitFor(() => {
      expect(posts(stub.calls, '/auth/totp/disable')).toHaveLength(1)
    })
    expect(csrf(posts(stub.calls, '/auth/totp/disable')[0])).toBe('csrf-new')
  })

  it('shows a sentence when the password is refused, and clears it', async () => {
    const user = userEvent.setup()
    const stub = render([
      ['GET /api/v1/auth/totp', () => jsonResponse(OFF)],
      ['POST /api/v1/auth/totp/enrol', REFUSED],
    ])

    await user.type(await screen.findByLabelText('current password'), 'wrong')
    await user.click(screen.getByRole('button', { name: 'turn on' }))

    expect(await screen.findByText(REFUSED_TEXT)).toBeInTheDocument()
    expect(screen.getByLabelText('current password')).toHaveValue('')
    expect(screen.queryByRole('img')).toBeNull()
    expect(posts(stub.calls, '/auth/totp/enrol')).toHaveLength(1)
    // The refusal is about the password, not the session: still signed in.
    expect(screen.getByRole('heading', { name: 'settings' })).toBeInTheDocument()
  })

  it('keeps the key on screen after a wrong code, and cancel drops it', async () => {
    const user = userEvent.setup()
    render([
      ['GET /api/v1/auth/totp', () => jsonResponse(OFF)],
      ['POST /api/v1/auth/totp/enrol', () => jsonResponse(ENROLMENT)],
      ['POST /api/v1/auth/totp/confirm', REFUSED],
    ])

    await user.type(await screen.findByLabelText('current password'), 'hunter2')
    await user.click(screen.getByRole('button', { name: 'turn on' }))
    await user.type(await screen.findByLabelText('authenticator code'), '000000')
    await user.click(screen.getByRole('button', { name: 'confirm' }))

    expect(await screen.findByText(REFUSED_TEXT)).toBeInTheDocument()
    expect(screen.getByRole('img')).toBeInTheDocument()
    expect(screen.getByLabelText('authenticator code')).toHaveValue('')

    await user.click(screen.getByRole('button', { name: 'cancel' }))
    expect(screen.queryByRole('img')).toBeNull()
    expect(screen.queryByText(REFUSED_TEXT)).toBeNull()
    expect(screen.getByRole('button', { name: 'turn on' })).toBeInTheDocument()
  })

  it('drops an expired key and reads the status again', async () => {
    const user = userEvent.setup()
    const stub = render([
      ['GET /api/v1/auth/totp', () => jsonResponse(OFF)],
      ['POST /api/v1/auth/totp/enrol', () => jsonResponse(ENROLMENT)],
      ['POST /api/v1/auth/totp/confirm', () => errorResponse(409, 'web-auth-totp-no-pending')],
    ])

    await user.type(await screen.findByLabelText('current password'), 'hunter2')
    await user.click(screen.getByRole('button', { name: 'turn on' }))
    await user.type(await screen.findByLabelText('authenticator code'), '123456')
    const reads = stub.calls.filter((each) => each.url.endsWith('/auth/totp')).length
    await user.click(screen.getByRole('button', { name: 'confirm' }))

    expect(
      await screen.findByText('no new authenticator is waiting for a code. start again.'),
    ).toBeInTheDocument()
    expect(screen.queryByRole('img')).toBeNull()
    expect(screen.getByRole('button', { name: 'turn on' })).toBeInTheDocument()
    await waitFor(() => {
      expect(stub.calls.filter((each) => each.url.endsWith('/auth/totp')).length).toBe(reads + 1)
    })
  })

  it('turns the second factor off with the password and a code', async () => {
    const user = userEvent.setup()
    const stub = render([
      ['GET /api/v1/auth/totp', () => jsonResponse(ON)],
      ['POST /api/v1/auth/totp/disable', sequence(REFUSED, () => jsonResponse(RENEWED))],
    ])

    await user.type(await screen.findByLabelText('current password'), 'hunter2')
    await user.type(screen.getByLabelText('authenticator code'), '111111')
    await user.click(screen.getByRole('button', { name: 'turn off' }))
    expect(await screen.findByText(REFUSED_TEXT)).toBeInTheDocument()
    expect(screen.getByLabelText('current password')).toHaveValue('')

    await user.type(screen.getByLabelText('current password'), 'hunter2')
    await user.type(screen.getByLabelText('authenticator code'), '222222')
    await user.click(screen.getByRole('button', { name: 'turn off' }))

    expect(await screen.findByText('the second factor is off.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'turn on' })).toBeInTheDocument()
    const calls = posts(stub.calls, '/auth/totp/disable')
    expect(calls).toHaveLength(2)
    expect(body(calls[1])).toEqual({ current_password: 'hunter2', code: '222222' })
    expect(csrf(calls[1])).toBe('csrf-old')
  })

  it('offers no way to turn it off when the host requires it', async () => {
    render([['GET /api/v1/auth/totp', () => jsonResponse({ enrolled: true, required: true })]])

    expect(
      await screen.findByText(
        'this host requires a second factor, so it cannot be turned off here.',
      ),
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'turn off' })).toBeNull()
    expect(screen.queryByLabelText('current password')).toBeNull()
  })

  it('shows a sentence when the status cannot be read', async () => {
    render([['GET /api/v1/auth/totp', () => errorResponse(500, 'web-auth-store-unreadable')]])

    expect(await screen.findByRole('alert')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'turn on' })).toBeNull()
  })
})
