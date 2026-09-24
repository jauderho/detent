/**
 * The shell-level pending-commit context and slot.
 */

import { describe, expect, it } from 'bun:test'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { PendingCommit } from '@/api/commits'
import { jsonResponse, renderWithProviders, stubFetchByUrl } from '@/test/providers'
import { PendingCommitProvider, PendingCommitSlot, usePendingCommit } from '../PendingCommit'

const COMMIT: PendingCommit = {
  commit_id: 7,
  deadline: '2999-10-21T07:28:00Z',
  rollback_targets: 1,
  timeout_s: 300,
}

function Controller() {
  const { pending, arm, clear } = usePendingCommit()
  return (
    <div>
      <button type="button" onClick={() => arm(COMMIT)}>
        arm
      </button>
      <button type="button" onClick={clear}>
        clear
      </button>
      <div data-testid="pending">{pending ? pending.commit_id : 'none'}</div>
    </div>
  )
}

describe('PendingCommitProvider', () => {
  it('arms a pending commit and clears it on request', async () => {
    const user = userEvent.setup()
    render(
      <PendingCommitProvider>
        <Controller />
      </PendingCommitProvider>,
    )

    await user.click(screen.getByRole('button', { name: 'arm' }))
    expect(screen.getByTestId('pending')).toHaveTextContent('7')

    await user.click(screen.getByRole('button', { name: 'clear' }))
    expect(screen.getByTestId('pending')).toHaveTextContent('none')
  })

  it('throws when usePendingCommit is called outside the provider', () => {
    expect(() => render(<Controller />)).toThrow(
      'usePendingCommit must be used inside <PendingCommitProvider>',
    )
  })

  it('confirms the pending commit through the API', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl([
      [
        '/api/v1/auth/session',
        () =>
          jsonResponse({
            csrf_token: 'csrf-abc',
            expires_in_secs: 900,
            scopes: ['read', 'write'],
            subject: 'operator',
            totp_satisfied: false,
          }),
      ],
      ['/api/v1/commits/7/confirm', () => jsonResponse({ commit_id: 7 })],
    ])
    renderWithProviders(
      <>
        <Controller />
        <PendingCommitSlot />
      </>,
      { fetch: stub.fetch },
    )
    await user.click(screen.getByRole('button', { name: 'arm' }))
    await user.click(screen.getByRole('button', { name: 'confirm change' }))
    expect(stub.calls.some((call) => call.url === '/api/v1/commits/7/confirm')).toBe(true)
    expect(screen.queryByText(/waiting to be confirmed/)).toBeNull()
  })
})
