/**
 * "May this caller write?" — asked once, answered with a localized reason.
 *
 * A read-only operator should see a `restart` control that is visibly
 * unavailable and says why, not one that looks live until the server answers
 * `403`. Every write control therefore goes through this gate. See
 * `scopes.ts` for why this is a courtesy rather than a control.
 */

import { useLocalization } from '@fluent/react'
import type { ReactNode } from 'react'
import { useAuth } from './AuthProvider'
import { hasScope, SCOPE_WRITE } from './scopes'

export type WriteGateState = {
  /** Whether the signed-in session carries the `write` scope. */
  readonly canWrite: boolean
  /**
   * Localized explanation of why not, or `undefined` when writing is allowed.
   * Suitable for a `title`, a tooltip, or a line under a disabled control.
   */
  readonly reason: string | undefined
}

/** The gate's state for the current session. */
export function useWriteGate(): WriteGateState {
  const { l10n } = useLocalization()
  const { status, session } = useAuth()

  if (status !== 'authenticated' || session === null) {
    return { canWrite: false, reason: l10n.getString('scope-gate-signed-out') }
  }
  if (!hasScope(session.scopes, SCOPE_WRITE)) {
    return { canWrite: false, reason: l10n.getString('scope-gate-read-only') }
  }
  return { canWrite: true, reason: undefined }
}

/** The boolean alone, for a caller that has its own copy. */
export function useCanWrite(): boolean {
  return useWriteGate().canWrite
}

export type WriteGateProps = {
  /**
   * Render prop rather than plain children: a gated control has to *receive*
   * the answer — as `disabled`, as a `title` — and hiding it instead would
   * leave the operator wondering where the control went.
   */
  children: (state: WriteGateState) => ReactNode
}

export function WriteGate({ children }: WriteGateProps) {
  const state = useWriteGate()
  return <>{children(state)}</>
}
