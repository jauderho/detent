/**
 * The auth guard. Every route but `/login` renders inside it.
 *
 * It is the only thing that navigates on a lost session, and it navigates
 * exactly once: `AuthProvider`'s `401` handler writes `null` into the session
 * cache and stops, this reads the `null` and replaces the current history
 * entry with `/login`, and `/login` issues no request that could `401` again.
 *
 * `replace` rather than a push, so a dead address does not accumulate in the
 * back stack; `state.from` so the operator lands back where they were.
 */

import { Localized } from '@fluent/react'
import { Navigate, Outlet, useLocation } from 'react-router'
import { useAuth } from '@/auth/AuthProvider'
import { ROUTES } from './paths'

/** What `/login` reads back out of history state. */
export type LoginLocationState = { readonly from?: string }

export function RequireAuth() {
  const { status } = useAuth()
  const location = useLocation()

  if (status === 'loading') {
    return (
      <p className="lbl" style={{ padding: 24 }}>
        <Localized id="auth-checking">
          <span>checking this session</span>
        </Localized>
      </p>
    )
  }

  if (status === 'signed-out') {
    const from = `${location.pathname}${location.search}`
    const state: LoginLocationState = { from }
    return <Navigate to={ROUTES.login} replace state={state} />
  }

  return <Outlet />
}
