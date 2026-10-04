/**
 * The `system` resource: what detection found about this host, the serving
 * certificate, the update status, and the audit log.
 *
 * All four are read-only and change slowly — the host profile only when the
 * host itself changes — so they share this file rather than each getting one.
 */

import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useApiClient } from './ApiProvider'
import type { ApiClient, ApiResult } from './client'
import { type ApiRequestError, unwrap } from './query'
import type { components } from './schema'

export type HostReport = components['schemas']['HostReport']
export type CertReport = components['schemas']['CertReport']
export type UpdateReport = components['schemas']['UpdateReport']
export type AuditRecord = components['schemas']['AuditRecord']

export const HOST_PROFILE_QUERY_KEY = ['system', 'profile'] as const
export const CERT_QUERY_KEY = ['system', 'cert'] as const
export const UPDATE_QUERY_KEY = ['system', 'update'] as const

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
/** `GET /api/v1/system/cert`. */
export function fetchCert(client: ApiClient, signal?: AbortSignal): Promise<ApiResult<CertReport>> {
  return client.get('/api/v1/system/cert', signal === undefined ? {} : { signal })
}

/** `GET /api/v1/system/update`. */
export function fetchUpdate(
  client: ApiClient,
  signal?: AbortSignal,
): Promise<ApiResult<UpdateReport>> {
  return client.get('/api/v1/system/update', signal === undefined ? {} : { signal })
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

export type RenewRequested = components['schemas']['RenewRequested']

/** `POST /api/v1/system/cert/renew`. Needs `write`. */
export function requestCertRenew(client: ApiClient): Promise<ApiResult<RenewRequested>> {
  return client.post('/api/v1/system/cert/renew', {})
}

export type UpdateApplied = components['schemas']['UpdateAppliedView']

/** `POST /api/v1/system/update`. Needs `write`. Installs `version`, e.g. `v1.2.3`. */
export function applyUpdate(client: ApiClient, version: string): Promise<ApiResult<UpdateApplied>> {
  return client.post('/api/v1/system/update', { body: { version } })
}

// ── hooks ───────────────────────────────────────────────────────────────────

export function useHostProfile(): UseQueryResult<HostReport, ApiRequestError> {
  const client = useApiClient()
  return useQuery({
    queryKey: HOST_PROFILE_QUERY_KEY,
    queryFn: ({ signal }) => unwrap(fetchHostProfile(client, signal)),
  })
}

export function useCert(): UseQueryResult<CertReport, ApiRequestError> {
  const client = useApiClient()
  return useQuery({
    queryKey: CERT_QUERY_KEY,
    queryFn: ({ signal }) => unwrap(fetchCert(client, signal)),
  })
}

/**
 * The update status. Read-only: it reports what the update policy says is
 * available. Installing is `useApplyUpdate`.
 */
export function useUpdate(): UseQueryResult<UpdateReport, ApiRequestError> {
  const client = useApiClient()
  return useQuery({
    queryKey: UPDATE_QUERY_KEY,
    queryFn: ({ signal }) => unwrap(fetchUpdate(client, signal)),
  })
}

export function useAudit(query: AuditQuery = {}): UseQueryResult<AuditRecord[], ApiRequestError> {
  const client = useApiClient()
  return useQuery({
    queryKey: auditQueryKey(query),
    queryFn: ({ signal }) => unwrap(fetchAudit(client, query, signal)),
  })
}

/**
 * Ask the ACME client to renew now. `202` means the request was sent, not
 * that a certificate was issued — the cert query is invalidated so the page
 * shows the new certificate once the worker installs it.
 */
export function useRequestCertRenew(): UseMutationResult<RenewRequested, ApiRequestError, void> {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(requestCertRenew(client)),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: CERT_QUERY_KEY })
    },
  })
}

/**
 * Install the named update. The server restarts the service after the swap,
 * so the update status is invalidated on success and the page may lose its
 * connection until the new process answers.
 */
export function useApplyUpdate(): UseMutationResult<UpdateApplied, ApiRequestError, string> {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (version: string) => unwrap(applyUpdate(client, version)),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: UPDATE_QUERY_KEY })
    },
  })
}
