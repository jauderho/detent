/**
 * The `auth` resource: the three calls docs/API.md documents for a
 * cookie-authenticated browser.
 *
 * Request functions live here rather than in the auth context so the context
 * stays about state and this stays about the wire. Hooks for other resources
 * belong in a sibling file named for the resource.
 */

import type { ApiClient, ApiResult } from './client'
import type { components } from './schema'

export type SessionView = components['schemas']['SessionView']
export type LoginRequest = components['schemas']['LoginRequest']

/** Query key for the session probe; also the prefix the auth cache is cleared by. */
export const SESSION_QUERY_KEY = ['auth', 'session'] as const

/**
 * `GET /api/v1/auth/session`.
 *
 * `401` is an ordinary answer here — it means "nobody is signed in" — so it
 * is kept away from the global signed-out handler. The caller reads the
 * result instead.
 */
export function fetchSession(
  client: ApiClient,
  signal?: AbortSignal,
): Promise<ApiResult<SessionView>> {
  return client.get('/api/v1/auth/session', {
    suppressUnauthorizedEvent: true,
    ...(signal === undefined ? {} : { signal }),
  })
}

/**
 * `POST /api/v1/auth/login`.
 *
 * `401` here means the credentials were refused, not that a session expired,
 * so it too bypasses the global handler: firing it would clear the very error
 * the login form is about to display.
 */
export function login(
  client: ApiClient,
  credentials: LoginRequest,
): Promise<ApiResult<SessionView>> {
  return client.post('/api/v1/auth/login', {
    body: credentials,
    suppressUnauthorizedEvent: true,
  })
}

/** `POST /api/v1/auth/logout`. Answers `204` with no body. */
export function logout(client: ApiClient): Promise<ApiResult<undefined>> {
  return client.post('/api/v1/auth/logout', { suppressUnauthorizedEvent: true })
}
