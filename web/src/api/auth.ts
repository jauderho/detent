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

export type ReauthRequest = components['schemas']['ReauthRequest']
export type StepUp = components['schemas']['StepUp']

/**
 * `POST /api/v1/auth/reauth`: the password again, and a code when the
 * account has a second factor. For five minutes after it, the session may
 * apply, restore, update and renew the certificate.
 *
 * `401` means the password or the code was refused, not that the session is
 * gone, so it bypasses the global handler like a refused login does.
 */
export function reauth(client: ApiClient, request: ReauthRequest): Promise<ApiResult<StepUp>> {
  return client.post('/api/v1/auth/reauth', {
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

export type Notices = components['schemas']['Notices']
export type NoticeChange = components['schemas']['Change']

/**
 * Query key for the notices of this sign-in. Outside the `auth` prefix on
 * purpose: they describe one account, so the next sign-in drops them.
 */
export const NOTICES_QUERY_KEY = ['account', 'notices'] as const

/** `GET /api/v1/auth/notices`. Read once, right after a sign-in. */
export function fetchNotices(client: ApiClient): Promise<ApiResult<Notices>> {
  return client.get('/api/v1/auth/notices', { suppressUnauthorizedEvent: true })
}

export type SessionSummary = components['schemas']['SessionSummary']
export type RevokedSessions = components['schemas']['RevokedSessions']

/**
 * Query key for the session list. Outside the `auth` prefix on purpose: it
 * describes one account, so a new sign-in drops it.
 */
export const SESSIONS_QUERY_KEY = ['account', 'sessions'] as const

/** `GET /api/v1/auth/sessions`. Only the sessions of the signed-in account. */
export function fetchSessions(
  client: ApiClient,
  signal?: AbortSignal,
): Promise<ApiResult<SessionSummary[]>> {
  return client.get('/api/v1/auth/sessions', signal === undefined ? {} : { signal })
}

/** `POST /api/v1/auth/sessions/{handle}/revoke`. Answers `204` with no body. */
export function revokeSession(client: ApiClient, handle: string): Promise<ApiResult<undefined>> {
  return client.post('/api/v1/auth/sessions/{handle}/revoke', { path: { handle } })
}

/** `POST /api/v1/auth/sessions/revoke-others`. The current session stays. */
export function revokeOtherSessions(client: ApiClient): Promise<ApiResult<RevokedSessions>> {
  return client.post('/api/v1/auth/sessions/revoke-others', {})
}

export type TokenView = components['schemas']['TokenView']
export type TokenRequest = components['schemas']['TokenRequest']
export type IssuedToken = components['schemas']['IssuedToken']

/**
 * Query key for the API token list. Outside the `auth` prefix on purpose:
 * a new sign-in reads it again.
 */
export const TOKENS_QUERY_KEY = ['account', 'tokens'] as const

/** `GET /api/v1/auth/tokens`. Every token on the host, never its value. */
export function fetchTokens(
  client: ApiClient,
  signal?: AbortSignal,
): Promise<ApiResult<TokenView[]>> {
  return client.get('/api/v1/auth/tokens', signal === undefined ? {} : { signal })
}

/**
 * `POST /api/v1/auth/tokens`. Needs a step-up. The answer carries the token
 * value; this is the only time the host sends it.
 */
export function createToken(
  client: ApiClient,
  request: TokenRequest,
): Promise<ApiResult<IssuedToken>> {
  return client.post('/api/v1/auth/tokens', { body: request })
}

/** `POST /api/v1/auth/tokens/{id}/revoke`. Needs a step-up. Answers `204`. */
export function revokeToken(client: ApiClient, id: string): Promise<ApiResult<undefined>> {
  return client.post('/api/v1/auth/tokens/{id}/revoke', { path: { id } })
}
