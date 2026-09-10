/**
 * The `commits` resource: the two ends of the commit-confirm flow.
 *
 * docs/API.md, "the commit-confirm flow": an `apply` on a module that can lock
 * an administrator out arms a window instead of finalizing. Before the
 * deadline the operator confirms or rolls back; if neither arrives the
 * privileged monitor rolls back on its own. Both calls answer `409` for an id
 * that was already settled — that is a normal outcome, not a bug, and it is
 * what the console shows when the window closed while the operator was
 * deciding.
 */

import type { UseMutationResult } from '@tanstack/react-query'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useApiClient } from './ApiProvider'
import type { ApiClient, ApiResult } from './client'
import { MODULES_QUERY_KEY } from './modules'
import { type ApiRequestError, unwrap } from './query'
import type { components } from './schema'

export type PendingCommit = components['schemas']['PendingCommit']
export type CommitConfirmedView = components['schemas']['CommitConfirmedView']
export type RolledBackView = components['schemas']['RolledBackView']

// ── requests ────────────────────────────────────────────────────────────────

/** `POST /api/v1/commits/{id}/confirm`. Needs the `write` scope. */
export function confirmCommit(
  client: ApiClient,
  commitId: number,
): Promise<ApiResult<CommitConfirmedView>> {
  return client.post('/api/v1/commits/{id}/confirm', { path: { id: commitId } })
}

/** `POST /api/v1/commits/{id}/rollback`. Needs the `write` scope. */
export function rollbackCommit(
  client: ApiClient,
  commitId: number,
): Promise<ApiResult<RolledBackView>> {
  return client.post('/api/v1/commits/{id}/rollback', { path: { id: commitId } })
}

// ── hooks ───────────────────────────────────────────────────────────────────

export function useConfirmCommit(): UseMutationResult<
  CommitConfirmedView,
  ApiRequestError,
  number
> {
  const client = useApiClient()
  return useMutation({
    mutationFn: (commitId: number) => unwrap(confirmCommit(client, commitId)),
  })
}

/**
 * A rollback undoes every write since the window was armed, so every module's
 * cached view is suspect afterwards — the prefix, not one id, is invalidated.
 */
export function useRollbackCommit(): UseMutationResult<RolledBackView, ApiRequestError, number> {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (commitId: number) => unwrap(rollbackCommit(client, commitId)),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: MODULES_QUERY_KEY })
    },
  })
}
