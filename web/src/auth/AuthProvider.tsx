/**
 * Who is signed in, for the whole console.
 *
 * The one rule this file exists to enforce (PLAN §2.7, docs/API.md
 * "authentication"): **a `401` is the only thing that means "the session is
 * gone."** The server ends a session on 15 minutes of idleness, on 8 hours
 * absolute, when somebody signs in again, and on restart — no client-side
 * timer can predict any of those, and one that tried would either sign the
 * operator out early or leave a dead session on screen. So the console does
 * not run one. `SessionView.expires_in_secs` is published as a *readout*, not
 * as authority.
 *
 * The `401` path, end to end:
 *
 *   1. `ApiClient` sees a `401` on any call that did not opt out and calls the
 *      handler registered here — once per response, with no retries, because
 *      `queryClient.ts` turns retries off.
 *   2. The handler drops the CSRF token and writes `null` into the session
 *      cache entry. It navigates nowhere and refetches nothing.
 *   3. The `null` re-renders `RequireAuth`, which sends the operator to
 *      `/login` with the address they were on.
 *
 * That is why there is no redirect loop: the two calls that can legitimately
 * answer `401` — the session probe and the login attempt — pass
 * `suppressUnauthorizedEvent`, so neither can re-enter step 1, and step 2
 * issues no request that could produce another `401`.
 */

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo } from 'react'
import { useApiClient } from '@/api/ApiProvider'
import {
  fetchSession,
  type LoginRequest,
  login as postLogin,
  logout as postLogout,
  SESSION_QUERY_KEY,
  type SessionView,
} from '@/api/auth'
import type { ApiClient, ApiError, ApiResult } from '@/api/client'
import { ApiRequestError, toApiError } from '@/api/query'

const MS_PER_SECOND = 1000

/** The cache prefix the session lives under; everything else is host data. */
const AUTH_SCOPE: string = SESSION_QUERY_KEY[0]

/** `loading` is the first session probe; it is not "signed out yet". */
export type AuthStatus = 'loading' | 'authenticated' | 'signed-out'

export type AuthContextValue = {
  readonly status: AuthStatus
  /** The signed-in session, or `null` when nobody is. Never holds a session id. */
  readonly session: SessionView | null
  /**
   * When the session expires, as epoch milliseconds, derived from the
   * `expires_in_secs` the server reported and when it reported it. For display
   * only — expiry is decided by the server, and observed as a `401`.
   */
  readonly expiresAt: number | null
  /** Why the session probe itself failed, when it failed for a reason other than `401`. */
  readonly probeError: ApiError | null
  login(credentials: LoginRequest): Promise<ApiResult<SessionView>>
  logout(): Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

/**
 * The session probe.
 *
 * `401` is folded to `null` rather than thrown: "nobody is signed in" is an
 * answer, not a failure, and throwing it would put the login screen behind an
 * error state.
 */
async function probeSession(client: ApiClient, signal: AbortSignal): Promise<SessionView | null> {
  const result = await fetchSession(client, signal)
  if (result.ok) return result.data
  if (result.error.kind === 'http' && result.error.status === 401) return null
  throw new ApiRequestError(result.error)
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const client = useApiClient()
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: SESSION_QUERY_KEY,
    queryFn: ({ signal }) => probeSession(client, signal),
  })

  const session = query.data ?? null

  // The CSRF token lives in the client's closure and nowhere else: not in
  // storage, not in a URL, not in this component's state.
  useEffect(() => {
    client.setCsrfToken(session === null ? null : session.csrf_token)
  }, [client, session])

  useEffect(() => {
    client.setUnauthorizedHandler(() => {
      client.setCsrfToken(null)
      // `setQueryData`, not `invalidateQueries`: writing the answer is what
      // keeps a dead session from being probed again on the way out.
      queryClient.setQueryData<SessionView | null>(SESSION_QUERY_KEY, null)
    })
    return () => {
      client.setUnauthorizedHandler(null)
    }
  }, [client, queryClient])

  const login = useCallback(
    async (credentials: LoginRequest): Promise<ApiResult<SessionView>> => {
      const result = await postLogin(client, credentials)
      if (!result.ok) return result
      // Whatever a previous operator read on this tab is not this session's to
      // see. Dropped here rather than on the way out because sign-in happens
      // with no data page mounted, so nothing is left to refetch it; the
      // session entry itself is kept and overwritten a line later.
      queryClient.removeQueries({ predicate: (query) => query.queryKey[0] !== AUTH_SCOPE })
      queryClient.setQueryData<SessionView | null>(SESSION_QUERY_KEY, result.data)
      client.setCsrfToken(result.data.csrf_token)
      return result
    },
    [client, queryClient],
  )

  const logout = useCallback(async (): Promise<void> => {
    // The answer is deliberately ignored: a refused logout still means this
    // browser is finished with the session, and the cookie is gone either way.
    await postLogout(client)
    client.setCsrfToken(null)
    // Only the session is written here: the pages still mounted behind the
    // guard would refetch anything removed under them, and every one of those
    // requests would be a `401` chasing a session that is already gone. What
    // they cached is unreachable from the login screen and expires with
    // `DEFAULT_GC_TIME_MS`; the next sign-in drops it outright.
    queryClient.setQueryData<SessionView | null>(SESSION_QUERY_KEY, null)
  }, [client, queryClient])

  const value = useMemo<AuthContextValue>(() => {
    const status: AuthStatus = query.isPending
      ? 'loading'
      : session === null
        ? 'signed-out'
        : 'authenticated'
    return {
      status,
      session,
      expiresAt:
        session === null ? null : query.dataUpdatedAt + session.expires_in_secs * MS_PER_SECOND,
      probeError: query.error === null ? null : toApiError(query.error),
      login,
      logout,
    }
  }, [query.isPending, query.dataUpdatedAt, query.error, session, login, logout])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (value === null) {
    throw new Error('useAuth must be used inside <AuthProvider>')
  }
  return value
}
