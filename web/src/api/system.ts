/**
 * The `system` resource: what detection found about this host, and the audit
 * log.
 *
 * Both are read-only and both change slowly — the host profile only when the
 * host itself changes — so they share this file rather than each getting one.
 */

import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import { useApiClient } from './ApiProvider'
import type { ApiClient, ApiResult } from './client'
import { type ApiRequestError, unwrap } from './query'
import type { components } from './schema'

export type HostReport = components['schemas']['HostReport']
export type AuditRecord = components['schemas']['AuditRecord']

export const HOST_PROFILE_QUERY_KEY = ['system', 'profile'] as const

/** Filters `GET /api/v1/audit` accepts. The server caps `limit` itself. */
export type AuditQuery = {
  readonly module?: string
  readonly who?: string
  readonly limit?: number
}

export function auditQueryKey(query: AuditQuery): readonly [string, AuditQuery] {
  return ['audit', query]
}

// ── requests ────────────────────────────────────────────────────────────────

/** `GET /api/v1/system/profile`. */
export function fetchHostProfile(
  client: ApiClient,
  signal?: AbortSignal,
): Promise<ApiResult<HostReport>> {
  return client.get('/api/v1/system/profile', signal === undefined ? {} : { signal })
}

/** `GET /api/v1/audit`, newest first. */
export function fetchAudit(
  client: ApiClient,
  query: AuditQuery,
  signal?: AbortSignal,
): Promise<ApiResult<AuditRecord[]>> {
  return client.get('/api/v1/audit', {
    query,
    ...(signal === undefined ? {} : { signal }),
  })
}

// ── hooks ───────────────────────────────────────────────────────────────────

export function useHostProfile(): UseQueryResult<HostReport, ApiRequestError> {
  const client = useApiClient()
  return useQuery({
    queryKey: HOST_PROFILE_QUERY_KEY,
    queryFn: ({ signal }) => unwrap(fetchHostProfile(client, signal)),
  })
}

export function useAudit(query: AuditQuery = {}): UseQueryResult<AuditRecord[], ApiRequestError> {
  const client = useApiClient()
  return useQuery({
    queryKey: auditQueryKey(query),
    queryFn: ({ signal }) => unwrap(fetchAudit(client, query, signal)),
  })
}
