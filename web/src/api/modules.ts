/**
 * The `modules` resource: the module list, one module's view, and the three
 * calls that act on a candidate model (`validate`, `plan`, `apply`).
 *
 * Request functions first, hooks alongside — the convention `auth.ts` states.
 * A request function takes the client explicitly so it can be called outside
 * React (a router loader, a test); a hook reads the client from context.
 */

import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useApiClient } from './ApiProvider'
import type { ApiClient, ApiResult } from './client'
import { type ApiRequestError, unwrap } from './query'
import type { components } from './schema'

export type ModuleDescriptor = components['schemas']['ModuleDescriptor']
export type ModuleView = components['schemas']['ModuleView']
export type Diagnostics = components['schemas']['Diagnostics']
export type PlanReport = components['schemas']['PlanReport']
export type ApplyReport = components['schemas']['ApplyReport']
export type ApplyRequest = components['schemas']['ApplyRequest']
export type ModelRequest = components['schemas']['ModelRequest']

/** Root of every modules cache entry, so one prefix invalidates them all. */
export const MODULES_QUERY_KEY = ['modules'] as const

export function moduleQueryKey(id: string): readonly [string, string] {
  return ['modules', id]
}

// ── requests ────────────────────────────────────────────────────────────────

/** `GET /api/v1/modules`. */
export function fetchModules(
  client: ApiClient,
  signal?: AbortSignal,
): Promise<ApiResult<ModuleDescriptor[]>> {
  return client.get('/api/v1/modules', signal === undefined ? {} : { signal })
}

/** `GET /api/v1/modules/{id}`. */
export function fetchModule(
  client: ApiClient,
  id: string,
  signal?: AbortSignal,
): Promise<ApiResult<ModuleView>> {
  return client.get('/api/v1/modules/{id}', {
    path: { id },
    ...(signal === undefined ? {} : { signal }),
  })
}

/** `POST /api/v1/modules/{id}/validate`. Writes nothing. */
export function validateModule(
  client: ApiClient,
  id: string,
  body: ModelRequest,
): Promise<ApiResult<Diagnostics>> {
  return client.post('/api/v1/modules/{id}/validate', { path: { id }, body })
}

/** `POST /api/v1/modules/{id}/plan`. Writes nothing; returns the diff. */
export function planModule(
  client: ApiClient,
  id: string,
  body: ModelRequest,
): Promise<ApiResult<PlanReport>> {
  return client.post('/api/v1/modules/{id}/plan', { path: { id }, body })
}

/** `POST /api/v1/modules/{id}/apply`. Needs the `write` scope. */
export function applyModule(
  client: ApiClient,
  id: string,
  body: ApplyRequest,
): Promise<ApiResult<ApplyReport>> {
  return client.post('/api/v1/modules/{id}/apply', { path: { id }, body })
}

// ── hooks ───────────────────────────────────────────────────────────────────

export function useModules(): UseQueryResult<ModuleDescriptor[], ApiRequestError> {
  const client = useApiClient()
  return useQuery({
    queryKey: MODULES_QUERY_KEY,
    queryFn: ({ signal }) => unwrap(fetchModules(client, signal)),
  })
}

export function useModule(id: string): UseQueryResult<ModuleView, ApiRequestError> {
  const client = useApiClient()
  return useQuery({
    queryKey: moduleQueryKey(id),
    queryFn: ({ signal }) => unwrap(fetchModule(client, id, signal)),
  })
}

export function useValidateModule(
  id: string,
): UseMutationResult<Diagnostics, ApiRequestError, ModelRequest> {
  const client = useApiClient()
  return useMutation({
    mutationFn: (body: ModelRequest) => unwrap(validateModule(client, id, body)),
  })
}

export function usePlanModule(
  id: string,
): UseMutationResult<PlanReport, ApiRequestError, ModelRequest> {
  const client = useApiClient()
  return useMutation({
    mutationFn: (body: ModelRequest) => unwrap(planModule(client, id, body)),
  })
}

/**
 * `apply` is the one module call that changes the host, so its success
 * invalidates the module's cached view: the digest, the model on disk and the
 * diagnostics all moved.
 */
export function useApplyModule(
  id: string,
): UseMutationResult<ApplyReport, ApiRequestError, ApplyRequest> {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: ApplyRequest) => unwrap(applyModule(client, id, body)),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: moduleQueryKey(id) })
    },
  })
}
