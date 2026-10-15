/**
 * The step-up dialog: a refused apply, restore, update or renewal asks for
 * the password, and is sent once more after the host accepts it.
 */

import { describe, expect, it } from 'bun:test'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { useApiClient } from '@/api/ApiProvider'
import type { SessionView } from '@/api/auth'
import { CSRF_HEADER } from '@/api/client'
import { requestCertRenew } from '@/api/system'
import {
  errorResponse,
  jsonResponse,
  renderWithProviders,
  type StubCall,
  stubFetchByUrl,
} from '@/test/providers'
import { useStepUp } from '../StepUp'

const SESSION: SessionView = {
  csrf_token: 'csrf-token',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: false,
  must_change_password: false,
  step_up_expires_in_secs: null,
}

const STEP_UP_REQUIRED = 'web-auth-step-up-required'

/** One guarded renewal per click; the result is written out. */
function Harness() {
  const client = useApiClient()
  const guard = useStepUp()
  const [result, setResult] = useState('idle')
  return (
    <div>
      <button
        type="button"
        onClick={() => {
          void guard(() => requestCertRenew(client)).then((answer) => {
            setResult(
              answer.ok
                ? 'renewed'
                : answer.error.kind === 'http'
                  ? answer.error.messageId
                  : answer.error.kind,
            )
          })
        }}
      >
        renew
      </button>
      <output>{result}</output>
    </div>
  )
}

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

function mountHarness(rules: Parameters<typeof stubFetchByUrl>[0], enrolled = false) {
  const stub = stubFetchByUrl([
    ...rules,
    ['GET /api/v1/auth/totp', () => jsonResponse({ enrolled, required: false })],
    ['GET /api/v1/auth/session', () => jsonResponse(SESSION)],
  ])
  renderWithProviders(<Harness />, { fetch: stub.fetch })
  return stub
}

function posts(calls: StubCall[], path: string): StubCall[] {
  return calls.filter((each) => each.init.method === 'POST' && each.url.endsWith(path))
}

const RENEW = '/api/v1/system/cert/renew'
const REAUTH = '/api/v1/auth/reauth'

function renewOnceRefused() {
  return [
    'POST /api/v1/system/cert/renew',
    sequence(
      () => errorResponse(403, STEP_UP_REQUIRED, 'forbidden'),
      () => jsonResponse({ requested: true }, { status: 202 }),
    ),
  ] as const
}

function reauthOk() {
  return ['POST /api/v1/auth/reauth', () => jsonResponse({ step_up_expires_in_secs: 300 })] as const
}

describe('StepUpProvider', () => {
  it('asks for the password, then sends the request once more', async () => {
    const user = userEvent.setup()
    const stub = mountHarness([renewOnceRefused(), reauthOk()])

    await user.click(await screen.findByRole('button', { name: 'renew' }))
    const dialog = await screen.findByRole('dialog', { name: 'enter your password again' })
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(screen.getByRole('form', { name: 'confirm your password' })).toBeInTheDocument()
    // The account has no second factor: no code field once that is known.
    await waitFor(() => {
      expect(screen.queryByLabelText('authenticator code')).not.toBeInTheDocument()
    })

    await user.type(screen.getByLabelText('current password'), 'correct horse')
    await user.click(screen.getByRole('button', { name: 'confirm' }))

    expect(await screen.findByText('renewed')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    const [sent] = posts(stub.calls, REAUTH)
    expect(sent?.init.body).toBe(JSON.stringify({ password: 'correct horse' }))
    expect(new Headers(sent?.init.headers).get(CSRF_HEADER)).toBe('csrf-token')
    expect(posts(stub.calls, RENEW)).toHaveLength(2)
  })

  it('asks for the code too when the account has a second factor', async () => {
    const user = userEvent.setup()
    const stub = mountHarness([renewOnceRefused(), reauthOk()], true)

    await user.click(await screen.findByRole('button', { name: 'renew' }))
    const code = await screen.findByLabelText('authenticator code')
    await waitFor(() => {
      expect(code).toBeRequired()
    })
    await user.type(screen.getByLabelText('current password'), 'correct horse')
    await user.type(code, '123456')
    await user.click(screen.getByRole('button', { name: 'confirm' }))

    expect(await screen.findByText('renewed')).toBeInTheDocument()
    const [sent] = posts(stub.calls, REAUTH)
    expect(sent?.init.body).toBe(JSON.stringify({ password: 'correct horse', totp_code: '123456' }))
  })

  it('says why and stays open when the password is refused', async () => {
    const user = userEvent.setup()
    const stub = mountHarness([
      renewOnceRefused(),
      [
        'POST /api/v1/auth/reauth',
        sequence(
          () => errorResponse(401, 'web-auth-invalid-credentials', 'unauthorized'),
          () => jsonResponse({ step_up_expires_in_secs: 300 }),
        ),
      ],
    ])

    await user.click(await screen.findByRole('button', { name: 'renew' }))
    const password = await screen.findByLabelText('current password')
    await user.type(password, 'wrong')
    await user.click(screen.getByRole('button', { name: 'confirm' }))

    expect(
      await screen.findByText('the user name, password or code was not correct.'),
    ).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(password).toHaveValue('')
    expect(posts(stub.calls, RENEW)).toHaveLength(1)
    expect(screen.getByText('idle')).toBeInTheDocument()

    await user.type(password, 'correct horse')
    await user.click(screen.getByRole('button', { name: 'confirm' }))
    expect(await screen.findByText('renewed')).toBeInTheDocument()
  })

  it('answers the first refusal when the operator cancels', async () => {
    const user = userEvent.setup()
    const stub = mountHarness([renewOnceRefused(), reauthOk()])

    await user.click(await screen.findByRole('button', { name: 'renew' }))
    await screen.findByRole('dialog')
    await user.click(screen.getByRole('button', { name: 'cancel' }))

    expect(await screen.findByText(STEP_UP_REQUIRED)).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(posts(stub.calls, REAUTH)).toHaveLength(0)
    expect(posts(stub.calls, RENEW)).toHaveLength(1)
  })

  it('closes on Escape like a cancel', async () => {
    const user = userEvent.setup()
    mountHarness([renewOnceRefused(), reauthOk()])

    await user.click(await screen.findByRole('button', { name: 'renew' }))
    await screen.findByRole('dialog')
    await user.keyboard('{Escape}')

    expect(await screen.findByText(STEP_UP_REQUIRED)).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('passes any other answer through without asking', async () => {
    const user = userEvent.setup()
    const stub = mountHarness([
      ['POST /api/v1/system/cert/renew', () => errorResponse(409, 'web-cert-renew-not-acme')],
    ])

    await user.click(await screen.findByRole('button', { name: 'renew' }))
    expect(await screen.findByText('web-cert-renew-not-acme')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(posts(stub.calls, REAUTH)).toHaveLength(0)
  })

  it('answers several waiting requests with one dialog', async () => {
    const user = userEvent.setup()
    const stub = mountHarness([
      [
        'POST /api/v1/system/cert/renew',
        sequence(
          () => errorResponse(403, STEP_UP_REQUIRED, 'forbidden'),
          () => errorResponse(403, STEP_UP_REQUIRED, 'forbidden'),
          () => jsonResponse({ requested: true }, { status: 202 }),
        ),
      ],
      reauthOk(),
    ])

    const button = await screen.findByRole('button', { name: 'renew' })
    await user.click(button)
    await screen.findByRole('dialog')
    // A second request refused while the dialog is open waits for it.
    button.click()
    await waitFor(() => {
      expect(posts(stub.calls, RENEW)).toHaveLength(2)
    })
    expect(screen.getAllByRole('dialog')).toHaveLength(1)

    await user.type(screen.getByLabelText('current password'), 'correct horse')
    await user.click(screen.getByRole('button', { name: 'confirm' }))
    expect(await screen.findByText('renewed')).toBeInTheDocument()
    expect(posts(stub.calls, REAUTH)).toHaveLength(1)
    expect(posts(stub.calls, RENEW)).toHaveLength(4)
  })

  it('throws when useStepUp is called outside the provider', () => {
    function Bare() {
      useStepUp()
      return null
    }
    expect(() => render(<Bare />)).toThrow('useStepUp must be used inside <StepUpProvider>')
  })
})
