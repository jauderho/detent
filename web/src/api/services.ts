/**
 * The `services` resource: the run state of the service a module configures,
 * and the actions that may be taken on it.
 *
 * A service is addressed by its *module* id — `/api/v1/services/{id}` where
 * `id` is the module, not the unit name. The unit the host actually resolved
 * comes back in `ServiceStatus.unit`.
 */

import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useApiClient } from './ApiProvider'
import type { ApiClient, ApiResult } from './client'
import { type ApiRequestError, unwrap } from './query'
import type { components } from './schema'

export type ServiceStatus = components['schemas']['ServiceStatus']
export type ServiceReport = components['schemas']['ServiceReport']
export type ServiceActionRequest = components['schemas']['ServiceActionRequest']
export type ServiceCommand = components['schemas']['ApiServiceCommand']

export const SERVICES_QUERY_KEY = ['services'] as const

export function serviceQueryKey(moduleId: string): readonly [string, string] {
  return ['services', moduleId]
}

// ── requests ────────────────────────────────────────────────────────────────

/** `GET /api/v1/services/{id}`. */
export function fetchServiceStatus(
  client: ApiClient,
  moduleId: string,
  signal?: AbortSignal,
): Promise<ApiResult<ServiceStatus>> {
  return client.get('/api/v1/services/{id}', {
    path: { id: moduleId },
    ...(signal === undefined ? {} : { signal }),
  })
}

/** `POST /api/v1/services/{id}`. Needs the `write` scope. */
export function actOnService(
  client: ApiClient,
  moduleId: string,
  body: ServiceActionRequest,
): Promise<ApiResult<ServiceReport>> {
  return client.post('/api/v1/services/{id}', { path: { id: moduleId }, body })
}

// ── hooks ───────────────────────────────────────────────────────────────────

export function useServiceStatus(moduleId: string): UseQueryResult<ServiceStatus, ApiRequestError> {
  const client = useApiClient()
  return useQuery({
    queryKey: serviceQueryKey(moduleId),
    queryFn: ({ signal }) => unwrap(fetchServiceStatus(client, moduleId, signal)),
  })
}

/** Acting on a unit moves its run state, so the cached status is invalidated. */
export function useServiceAction(
  moduleId: string,
): UseMutationResult<ServiceReport, ApiRequestError, ServiceCommand> {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (action: ServiceCommand) => unwrap(actOnService(client, moduleId, { action })),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: serviceQueryKey(moduleId) })
    },
  })
}
