/**
 * The pending-commit slot in the app shell.
 *
 * docs/API.md, "the commit-confirm flow": an `apply` on a module that can lock
 * an administrator out arms a window instead of finalizing, and if nobody
 * confirms before the deadline the privileged monitor rolls the change back on
 * its own. That window belongs to the *shell*, not to the page that started
 * it: the operator who applied a network change and then walked to the modules
 * list must still see the clock running.
 *
 * So the armed commit lives here, above the router, and any page that receives
 * a `PendingCommit` from an `apply` hands it over with `arm`. The banner
 * clears itself when the countdown reaches zero — the monitor has rolled the
 * change back by then, and a window that has closed is not pending.
 *
 * The confirm and roll-back controls are the next wave's; the requests they
 * will call already exist in `src/api/commits.ts`.
 */

import { Localized, useLocalization } from '@fluent/react'
import { createContext, type ReactNode, useCallback, useContext, useMemo, useState } from 'react'
import type { PendingCommit } from '@/api/commits'
import { Banner } from '@/components/Banner'
import { Countdown } from '@/components/Countdown'

export type PendingCommitContextValue = {
  readonly pending: PendingCommit | null
  /** Records the window an `apply` just armed. */
  arm(commit: PendingCommit): void
  /** Clears it — confirmed, rolled back, or expired. */
  clear(): void
}

const PendingCommitContext = createContext<PendingCommitContextValue | null>(null)

export function PendingCommitProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingCommit | null>(null)

  const arm = useCallback((commit: PendingCommit) => {
    setPending(commit)
  }, [])
  const clear = useCallback(() => {
    setPending(null)
  }, [])

  const value = useMemo<PendingCommitContextValue>(
    () => ({ pending, arm, clear }),
    [pending, arm, clear],
  )

  return <PendingCommitContext.Provider value={value}>{children}</PendingCommitContext.Provider>
}

export function usePendingCommit(): PendingCommitContextValue {
  const value = useContext(PendingCommitContext)
  if (value === null) {
    throw new Error('usePendingCommit must be used inside <PendingCommitProvider>')
  }
  return value
}

const SLOT_STYLE = { paddingTop: 12 } as const

/**
 * Renders nothing until a commit is armed, so the shell can keep the slot
 * unconditionally.
 */
export function PendingCommitSlot() {
  const { l10n } = useLocalization()
  const { pending, clear } = usePendingCommit()

  if (pending === null) {
    return null
  }

  const deadline = Date.parse(pending.deadline)
  // An unparseable deadline is not a reason to hide the fact that a change is
  // pending; it is a reason not to show a clock counting from nowhere.
  const hasDeadline = !Number.isNaN(deadline)

  return (
    <div className="wrap" style={SLOT_STYLE}>
      <Banner
        tone="amber"
        actions={
          hasDeadline ? (
            <Countdown
              deadline={deadline}
              onExpire={clear}
              label={l10n.getString('pending-commit-countdown-label')}
            />
          ) : undefined
        }
      >
        <Localized id="pending-commit-message">
          <span>a configuration change is waiting to be confirmed.</span>
        </Localized>
      </Banner>
    </div>
  )
}
