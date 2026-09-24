/**
 * The pending-commit slot in the app shell.
 */

import { Localized, useLocalization } from '@fluent/react'
import { createContext, type ReactNode, useCallback, useContext, useMemo, useState } from 'react'
import { type PendingCommit, useConfirmCommit } from '@/api/commits'
import { useApiErrorMessage } from '@/api/query'
import { Banner } from '@/components/Banner'
import { Button } from '@/components/Button'
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

/** Renders the pending state and its confirmation action in the shell. */
export function PendingCommitSlot() {
  const { l10n } = useLocalization()
  const { pending, clear } = usePendingCommit()
  const confirm = useConfirmCommit()
  const errorMessage = useApiErrorMessage()

  if (pending === null) {
    return null
  }

  const deadline = Date.parse(pending.deadline)
  const hasDeadline = !Number.isNaN(deadline)

  return (
    <div className="wrap" style={SLOT_STYLE}>
      <Banner
        tone="amber"
        actions={
          <>
            {hasDeadline ? (
              <Countdown
                deadline={deadline}
                onExpire={clear}
                label={l10n.getString('pending-commit-countdown-label')}
              />
            ) : null}
            <Button
              variant="primary"
              disabled={confirm.isPending}
              onClick={() => confirm.mutate(pending.commit_id, { onSuccess: clear })}
            >
              {confirm.isPending
                ? l10n.getString('pending-commit-confirming')
                : l10n.getString('pending-commit-confirm')}
            </Button>
          </>
        }
      >
        <Localized id="pending-commit-message">
          <span>a configuration change is waiting to be confirmed.</span>
        </Localized>
        {confirm.isError ? <div role="alert">{errorMessage(confirm.error)}</div> : null}
      </Banner>
    </div>
  )
}
