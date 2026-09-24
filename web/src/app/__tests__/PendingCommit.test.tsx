/**
 * The shell-level pending-commit context and slot.
 */

import { afterEach, describe, expect, it, jest } from 'bun:test'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PENDING_COMMIT_POLL_MS, type PendingCommit } from '@/api/commits'
import { errorResponse, jsonResponse, renderWithProviders, stubFetchByUrl } from '@/test/providers'
import { PendingCommitSlot, usePendingCommit } from '../PendingCommit'

const COMMIT: PendingCommit = {
  commit_id: 7,
  deadline: '2999-10-21T07:28:00Z',
  rollback_targets: 1,
  timeout_s: 300,
}

afterEach(() => {
  jest.useRealTimers()
})

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
    const stub = stubFetchByUrl([['/api/v1/commits/pending', () => jsonResponse(null)]])
    renderWithProviders(<Controller />, { fetch: stub.fetch })

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
      ['/api/v1/commits/pending', () => jsonResponse(null)],
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

  it('rehydrates the pending commit and rolls it back through the API', async () => {
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
      ['/api/v1/commits/pending', () => jsonResponse(COMMIT)],
      ['/api/v1/commits/7/rollback', () => jsonResponse({ commit_id: 7, restored: 1 })],
    ])
    renderWithProviders(<PendingCommitSlot />, { fetch: stub.fetch })

    await screen.findByText(/waiting to be confirmed/)
    expect(stub.calls.some((call) => call.url === '/api/v1/commits/pending')).toBe(true)

    await user.click(screen.getByRole('button', { name: 'roll back commit' }))

    await waitFor(() => expect(screen.queryByText(/waiting to be confirmed/)).toBeNull())
    expect(
      stub.calls.some(
        (call) => call.init.method === 'POST' && call.url === '/api/v1/commits/7/rollback',
      ),
    ).toBe(true)
  })

  it('keeps the banner and reports a failed rollback', async () => {
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
      ['/api/v1/commits/pending', () => jsonResponse(COMMIT)],
      ['/api/v1/commits/7/rollback', () => errorResponse(409, 'web-request-malformed')],
    ])
    renderWithProviders(<PendingCommitSlot />, { fetch: stub.fetch })

    await screen.findByText(/waiting to be confirmed/)
    await user.click(screen.getByRole('button', { name: 'roll back commit' }))

    expect(
      await screen.findByText('the request body is not the shape this endpoint expects.'),
    ).toBeInTheDocument()
    expect(screen.getByText(/waiting to be confirmed/)).toBeInTheDocument()
  })

  it('keeps the rollback action unavailable when no commit is pending', async () => {
    const stub = stubFetchByUrl([
      [
        '/api/v1/auth/session',
        () =>
          jsonResponse({
            csrf_token: 'csrf-abc',
            expires_in_secs: 900,
            scopes: ['read'],
            subject: 'operator',
            totp_satisfied: false,
          }),
      ],
      ['/api/v1/commits/pending', () => jsonResponse(null)],
    ])
    renderWithProviders(<PendingCommitSlot />, { fetch: stub.fetch })

    await waitFor(() =>
      expect(stub.calls.some((call) => call.url === '/api/v1/commits/pending')).toBe(true),
    )
    expect(screen.queryByRole('button', { name: 'roll back commit' })).toBeNull()
  })

  it('polls while a pending commit remains armed', async () => {
    jest.useFakeTimers()
    const stub = stubFetchByUrl([
      [
        '/api/v1/auth/session',
        () =>
          jsonResponse({
            csrf_token: 'csrf-abc',
            expires_in_secs: 900,
            scopes: ['read'],
            subject: 'operator',
            totp_satisfied: false,
          }),
      ],
      ['/api/v1/commits/pending', () => jsonResponse(COMMIT)],
    ])
    renderWithProviders(<PendingCommitSlot />, { fetch: stub.fetch })

    await act(async () => {
      await Promise.resolve()
    })
    expect(stub.calls.filter((call) => call.url === '/api/v1/commits/pending')).toHaveLength(1)

    await act(async () => {
      jest.advanceTimersByTime(PENDING_COMMIT_POLL_MS)
      await Promise.resolve()
    })
    expect(stub.calls.filter((call) => call.url === '/api/v1/commits/pending')).toHaveLength(2)
  })
})
