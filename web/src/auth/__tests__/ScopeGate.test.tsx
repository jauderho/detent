/**
 * The write gate: a control the caller may not use is disabled with a reason,
 * never live until the server answers `403`.
 */

import { describe, expect, it } from 'bun:test'
import { screen, waitFor } from '@testing-library/react'
import type { SessionView } from '@/api/auth'
import { Button } from '@/components/Button'
import { errorResponse, jsonResponse, renderWithProviders, stubFetch } from '@/test/providers'
import { useWriteGate } from '../ScopeGate'

function sessionWith(scopes: string[]): SessionView {
  return {
    csrf_token: 'csrf-abc',
    expires_in_secs: 900,
    scopes,
    subject: 'operator',
    totp_satisfied: false,
  }
}

/** A write control, gated. */
function RestartControl() {
  const { canWrite, reason } = useWriteGate()
  return (
    <div>
      <Button disabled={!canWrite} title={reason}>
        restart
      </Button>
      <p data-testid="reason">{reason ?? 'none'}</p>
    </div>
  )
}

describe('useWriteGate', () => {
  it('enables the control for a session that carries write', async () => {
    const stub = stubFetch([jsonResponse(sessionWith(['read', 'write']))])
    renderWithProviders(<RestartControl />, { fetch: stub.fetch })

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'restart' })).toBeEnabled()
    })
    expect(screen.getByTestId('reason')).toHaveTextContent('none')
  })

  it('disables it for a read-only session and says why', async () => {
    const stub = stubFetch([jsonResponse(sessionWith(['read']))])
    renderWithProviders(<RestartControl />, { fetch: stub.fetch })

    // The gate is closed while the probe is in flight too, so wait for the
    // reason that belongs to a loaded read-only session.
    const reason = screen.getByTestId('reason')
    await waitFor(() => {
      expect(reason).toHaveTextContent('read access only')
    })
    expect(screen.getByRole('button', { name: 'restart' })).toBeDisabled()
    // The reason is copy, not a scope name or a message id.
    expect(reason.textContent).not.toContain('web-denied-scope')
  })

  it('disables it when nobody is signed in', async () => {
    const stub = stubFetch([errorResponse(401, 'web-auth-unauthenticated', 'unauthorized')])
    renderWithProviders(<RestartControl />, { fetch: stub.fetch })

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'restart' })).toBeDisabled()
    })
    expect(screen.getByTestId('reason')).toHaveTextContent('sign in to change anything')
  })
})

describe('useWriteGate canWrite', () => {
  function WriteFlag() {
    const { canWrite } = useWriteGate()
    return <div data-testid="canWrite">{canWrite ? 'yes' : 'no'}</div>
  }

  it('is true for a session with the write scope', async () => {
    const stub = stubFetch([jsonResponse(sessionWith(['read', 'write']))])
    renderWithProviders(<WriteFlag />, { fetch: stub.fetch })

    await waitFor(() => {
      expect(screen.getByTestId('canWrite')).toHaveTextContent('yes')
    })
  })

  it('is false for a read-only session', async () => {
    const stub = stubFetch([jsonResponse(sessionWith(['read']))])
    renderWithProviders(<WriteFlag />, { fetch: stub.fetch })

    await waitFor(() => {
      expect(screen.getByTestId('canWrite')).toHaveTextContent('no')
    })
  })
})
