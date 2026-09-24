import { describe, expect, it } from 'bun:test'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { jsonResponse, renderWithProviders, stubFetch, stubFetchByUrl } from '@/test/providers'
import type { SessionView } from '../auth'
import { createApiClient } from '../client'
import {
  confirmCommit,
  fetchPendingCommit,
  rollbackCommit,
  useConfirmCommit,
  useRollbackCommit,
} from '../commits'

const SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: true,
}

const AUTH_ROUTE = '/api/v1/auth/session'

describe('confirmCommit / rollbackCommit', () => {
  it('posts to the commit endpoints with the id in the path', async () => {
    const stub = stubFetch([
      jsonResponse({ commit_id: 7 }),
      jsonResponse({ commit_id: 7, restored: 1 }),
    ])
    const client = createApiClient({ fetch: stub.fetch })

    const confirmed = await confirmCommit(client, 7)
    const rolledBack = await rollbackCommit(client, 7)

    expect(stub.calls[0]?.url).toBe('/api/v1/commits/7/confirm')
    expect(confirmed.ok).toBe(true)
    expect(stub.calls[1]?.url).toBe('/api/v1/commits/7/rollback')
    expect(rolledBack.ok).toBe(true)
    if (!rolledBack.ok) return
    expect(rolledBack.data.restored).toBe(1)
  })
})

describe('fetchPendingCommit', () => {
  it('reads the monitor pending commit without a mutation body', async () => {
    const pending = {
      commit_id: 7,
      deadline: '2999-10-21T07:28:00Z',
      rollback_targets: 1,
      timeout_s: 300,
    }
    const stub = stubFetch([jsonResponse(pending)])
    const client = createApiClient({ fetch: stub.fetch })

    const result = await fetchPendingCommit(client)

    expect(stub.calls[0]?.url).toBe('/api/v1/commits/pending')
    expect(stub.calls[0]?.init.method).toBe('GET')
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.data?.commit_id).toBe(7)
  })
})

/**
 * The hooks wrap the requests above in mutations plus cache invalidation.
 * One probe each proves the wiring: the mutation calls the request, surfaces
 * its answer, and (for rollback) is reachable through the same providers
 * `main.tsx` wires. Retry/error behavior belongs to React Query, already
 * tested upstream.
 */
function ConfirmProbe() {
  const confirm = useConfirmCommit()
  return (
    <button type="button" onClick={() => confirm.mutate(7)}>
      {confirm.data ? `confirmed ${confirm.data.commit_id}` : 'confirm'}
    </button>
  )
}

function RollbackProbe() {
  const rollback = useRollbackCommit()
  return (
    <button type="button" onClick={() => rollback.mutate(7)}>
      {rollback.data ? `restored ${rollback.data.restored}` : 'roll back'}
    </button>
  )
}

describe('useConfirmCommit', () => {
  it('confirms the commit and surfaces the answer', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl([
      [AUTH_ROUTE, () => jsonResponse(SESSION)],
      ['/api/v1/commits/7/confirm', () => jsonResponse({ commit_id: 7 })],
    ])
    renderWithProviders(<ConfirmProbe />, { fetch: stub.fetch, route: '/' })

    await user.click(screen.getByRole('button', { name: 'confirm' }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /confirmed 7/ })).toBeInTheDocument()
    })
    expect(stub.calls.some((call) => call.url === '/api/v1/commits/7/confirm')).toBe(true)
  })
})

describe('useRollbackCommit', () => {
  it('rolls back and surfaces how many targets were restored', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl([
      [AUTH_ROUTE, () => jsonResponse(SESSION)],
      ['/api/v1/commits/7/rollback', () => jsonResponse({ commit_id: 7, restored: 2 })],
    ])
    renderWithProviders(<RollbackProbe />, { fetch: stub.fetch, route: '/' })

    await user.click(screen.getByRole('button', { name: 'roll back' }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /restored 2/ })).toBeInTheDocument()
    })
    expect(stub.calls.some((call) => call.url === '/api/v1/commits/7/rollback')).toBe(true)
  })
})
