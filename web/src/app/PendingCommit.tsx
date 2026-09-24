/**
 * The pending-commit slot in the app shell.
 */

import { Localized, useLocalization } from '@fluent/react'
import { useQueryClient } from '@tanstack/react-query'
import { createContext, type ReactNode, useCallback, useContext, useMemo } from 'react'
import {
  PENDING_COMMIT_QUERY_KEY,
  type PendingCommit,
  useConfirmCommit,
  usePendingCommitQuery,
  useRollbackCommit,
} from '@/api/commits'
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
  const queryClient = useQueryClient()
  const query = usePendingCommitQuery()
  const pending = query.data ?? null

  const arm = useCallback(
    (commit: PendingCommit) => {
      queryClient.setQueryData(PENDING_COMMIT_QUERY_KEY, commit)
    },
    [queryClient],
  )
  const clear = useCallback(() => {
    queryClient.setQueryData(PENDING_COMMIT_QUERY_KEY, null)
  }, [queryClient])

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
  const rollback = useRollbackCommit()
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
              disabled={confirm.isPending || rollback.isPending}
              onClick={() => confirm.mutate(pending.commit_id, { onSuccess: clear })}
            >
              {confirm.isPending
                ? l10n.getString('pending-commit-confirming')
                : l10n.getString('pending-commit-confirm')}
            </Button>
            <Button
              disabled={confirm.isPending || rollback.isPending}
              onClick={() => rollback.mutate(pending.commit_id, { onSuccess: clear })}
            >
              {l10n.getString('audit-op-rollback-commit')}
            </Button>
          </>
        }
      >
        <Localized id="pending-commit-message">
          <span>a configuration change is waiting to be confirmed.</span>
        </Localized>
        {confirm.isError || rollback.isError ? (
          <div role="alert">{errorMessage(confirm.error ?? rollback.error)}</div>
        ) : null}
      </Banner>
    </div>
  )
}
