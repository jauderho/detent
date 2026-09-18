/**
 * The bridge between `ApiClient`, whose failures are values, and React Query,
 * whose failures are thrown.
 *
 * `client.ts` resolves an expected failure to `{ ok: false, error }` on
 * purpose: a caller that must branch on a `409` should not have to catch. But
 * a `useQuery` that never rejects has no `isError`, no `error`, and no way to
 * tell a loaded panel from a failed one. So exactly one place converts, and it
 * converts into a real `Error` subclass carrying the original `ApiError` —
 * never a bare object, never a string, and never the server's `message_id` as
 * the message a person might see.
 */

import { useLocalization } from '@fluent/react'
import type { ApiError, ApiResult } from './client'
import { resolveApiError } from './messages'

/**
 * A rejected API call.
 *
 * The `Error` message is a fixed developer string, not copy: everything a
 * person reads comes from `resolveApiError(l10n, error.apiError)`.
 */
export class ApiRequestError extends Error {
  readonly apiError: ApiError

  constructor(apiError: ApiError) {
    super('detent api request failed')
    this.name = 'ApiRequestError'
    this.apiError = apiError
  }
}

/** Resolves an `ApiResult` to its data, or rejects with an `ApiRequestError`. */
export async function unwrap<T>(result: Promise<ApiResult<T>>): Promise<T> {
  const settled = await result
  if (settled.ok) return settled.data
  throw new ApiRequestError(settled.error)
}

/**
 * The `ApiError` behind anything React Query put in `error`.
 *
 * A query function can also throw for reasons the client never produced — an
 * abort, a bug in a `select`. Those are reported as `malformed` with no
 * status rather than surfaced raw, because there is no localized sentence for
 * "something we did not anticipate" beyond the one `malformed` already has.
 */
export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiRequestError) return error.apiError
  return { kind: 'malformed', status: 0 }
}

/**
 * One localized sentence for anything a query or mutation failed with.
 *
 * Components call this rather than reading `messageId` themselves, which is
 * what keeps a raw id from reaching the DOM.
 */
export function useApiErrorMessage(): (error: unknown) => string {
  const { l10n } = useLocalization()
  return (error: unknown) => resolveApiError(l10n, toApiError(error))
}
