/**
 * The `backups` resource: what a module retained, and putting one back.
 *
 * A backup is addressed by its index into the listing most recently produced
 * for that module, so a restore invalidates the listing it came from as well
 * as the module view whose file it just replaced.
 */

import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useApiClient } from './ApiProvider'
import type { ApiClient, ApiResult } from './client'
import { moduleQueryKey } from './modules'
import { type ApiRequestError, unwrap } from './query'
import type { components } from './schema'

export type BackupInfo = components['schemas']['BackupInfo']
export type RestoredView = components['schemas']['RestoredView']

export const BACKUPS_QUERY_KEY = ['backups'] as const

export function backupsQueryKey(moduleId: string): readonly [string, string] {
  return ['backups', moduleId]
}

// ── requests ────────────────────────────────────────────────────────────────

/** `GET /api/v1/modules/{id}/backups`, newest first. */
export async function fetchBackups(
  client: ApiClient,
  moduleId: string,
  signal?: AbortSignal,
): Promise<ApiResult<BackupInfo[]>> {
  return client.get('/api/v1/modules/{id}/backups', {
    path: { id: moduleId },
    ...(signal === undefined ? {} : { signal }),
  })
}

/** `POST /api/v1/modules/{id}/backups/{backup_id}/restore`. Needs `write`. */
export function restoreBackup(
  client: ApiClient,
  moduleId: string,
  backupId: number,
  expectedHash: string,
): Promise<ApiResult<RestoredView>> {
  return client.post('/api/v1/modules/{id}/backups/{backup_id}/restore', {
    path: { id: moduleId, backup_id: backupId },
    body: { expected_hash: expectedHash },
  })
}

// ── hooks ───────────────────────────────────────────────────────────────────

export function useBackups(moduleId: string): UseQueryResult<BackupInfo[], ApiRequestError> {
  const client = useApiClient()
  return useQuery({
    queryKey: backupsQueryKey(moduleId),
    queryFn: ({ signal }) => unwrap(fetchBackups(client, moduleId, signal)),
  })
}

export function useRestoreBackup(
  moduleId: string,
): UseMutationResult<RestoredView, ApiRequestError, { backupId: number; expectedHash: string }> {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ backupId, expectedHash }: { backupId: number; expectedHash: string }) =>
      unwrap(restoreBackup(client, moduleId, backupId, expectedHash)),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: backupsQueryKey(moduleId) })
      void queryClient.invalidateQueries({ queryKey: moduleQueryKey(moduleId) })
    },
  })
}
