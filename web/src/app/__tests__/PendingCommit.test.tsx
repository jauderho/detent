/**
 * The shell-level pending-commit context and slot.
 */

import { describe, expect, it } from 'bun:test'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { PendingCommit } from '@/api/commits'
import { PendingCommitProvider, usePendingCommit } from '../PendingCommit'

const COMMIT: PendingCommit = {
  commit_id: 7,
  deadline: '2025-10-21T07:28:00Z',
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
})
