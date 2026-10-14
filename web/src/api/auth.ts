/**
 * The `auth` resource: the calls docs/API.md documents for a
 * cookie-authenticated browser — session, password and second factor.
 *
 * Request functions live here rather than in the auth context so the context
 * stays about state and this stays about the wire. Hooks for other resources
 * belong in a sibling file named for the resource.
 */

import type { ApiClient, ApiResult } from './client'
import type { components } from './schema'

export type SessionView = components['schemas']['SessionView']
export type LoginRequest = components['schemas']['LoginRequest']
export type PasswordChangeRequest = components['schemas']['PasswordChangeRequest']

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

/**
 * `POST /api/v1/auth/password`.
 *
 * `401` here means the current password was refused, not that the session is
 * gone, so it bypasses the global handler like a refused login does.
 */
export function changePassword(
  client: ApiClient,
  request: PasswordChangeRequest,
): Promise<ApiResult<SessionView>> {
  return client.post('/api/v1/auth/password', {
    body: request,
    suppressUnauthorizedEvent: true,
  })
}

/** `POST /api/v1/auth/logout`. Answers `204` with no body. */
export function logout(client: ApiClient): Promise<ApiResult<undefined>> {
  return client.post('/api/v1/auth/logout', { suppressUnauthorizedEvent: true })
}

export type TotpStatus = components['schemas']['TotpStatus']
export type TotpEnrolment = components['schemas']['TotpEnrolment']
export type TotpEnrolRequest = components['schemas']['TotpEnrolRequest']
export type TotpConfirmRequest = components['schemas']['TotpConfirmRequest']
export type TotpDisableRequest = components['schemas']['TotpDisableRequest']

/**
 * Query key for the second-factor status. Outside the `auth` prefix on
 * purpose: it describes one account, so a new sign-in drops it.
 */
export const TOTP_QUERY_KEY = ['account', 'totp'] as const

/** `GET /api/v1/auth/totp`. A `401` here is a dead session, like any page read. */
export function fetchTotpStatus(
  client: ApiClient,
  signal?: AbortSignal,
): Promise<ApiResult<TotpStatus>> {
  return client.get('/api/v1/auth/totp', signal === undefined ? {} : { signal })
}

/**
 * `POST /api/v1/auth/totp/enrol`.
 *
 * `401` means the password was refused, not that the session is gone.
 */
export function startTotpEnrolment(
  client: ApiClient,
  request: TotpEnrolRequest,
): Promise<ApiResult<TotpEnrolment>> {
  return client.post('/api/v1/auth/totp/enrol', {
    body: request,
    suppressUnauthorizedEvent: true,
  })
}

/**
 * `POST /api/v1/auth/totp/confirm`. Answers a new session.
 *
 * `401` means the code was refused, not that the session is gone.
 */
export function confirmTotp(
  client: ApiClient,
  request: TotpConfirmRequest,
): Promise<ApiResult<SessionView>> {
  return client.post('/api/v1/auth/totp/confirm', {
    body: request,
    suppressUnauthorizedEvent: true,
  })
}

/**
 * `POST /api/v1/auth/totp/disable`. Answers a new session.
 *
 * `401` means the password or the code was refused.
 */
export function disableTotp(
  client: ApiClient,
  request: TotpDisableRequest,
): Promise<ApiResult<SessionView>> {
  return client.post('/api/v1/auth/totp/disable', {
    body: request,
    suppressUnauthorizedEvent: true,
  })
}
