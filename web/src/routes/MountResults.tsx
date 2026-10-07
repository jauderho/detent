/**
 * What a `mounts` apply did with the fstab entries it added or changed
 * (`ApplyReport.mounts`; `[mounts] activate_new_entries` on the host).
 *
 * One banner. `blue` when there is nothing to act on; `amber` when no unit
 * could start or a unit did not end up mounted (AESTHETIC_CONTRACT.md §12:
 * tone carries meaning only). The write and the commit-confirm window stay
 * either way, so this only informs the confirm-or-roll-back decision.
 *
 * Each state caption is a literal `getString` id, for `bun run i18n:check`
 * (see `serviceLabels.ts`).
 */

import type { ReactLocalization } from '@fluent/react'
import { useLocalization } from '@fluent/react'
import type { MountReportState, MountsReport } from '@/api/modules'
import { Banner } from '@/components/Banner'

/** What happened to one mount unit, as a word. */
export function mountStateLabel(l10n: ReactLocalization, state: MountReportState): string {
  switch (state) {
    case 'mounted':
      return l10n.getString('module-mount-state-mounted')
    case 'already_mounted':
      return l10n.getString('module-mount-state-already-mounted')
    case 'pending':
      return l10n.getString('module-mount-state-pending')
    case 'failed':
      return l10n.getString('module-mount-state-failed')
    case 'protected':
      return l10n.getString('module-mount-state-protected')
    case 'stopped':
      return l10n.getString('module-mount-state-stopped')
  }
}

/** States that ask the operator to look before confirming. */
const ATTENTION: ReadonlySet<MountReportState> = new Set(['pending', 'failed', 'protected'])

export function MountResults({ mounts }: { mounts: MountsReport }) {
  const { l10n } = useLocalization()
  if (!mounts.activated) {
    return <Banner tone="blue">{l10n.getString('module-mounts-off')}</Banner>
  }
  if (mounts.error !== null && mounts.error !== undefined) {
    return (
      <Banner tone="amber">
        {l10n.getString('module-mounts-error', { reason: mounts.error })}
      </Banner>
    )
  }
  if (mounts.units.length === 0) {
    return <Banner tone="blue">{l10n.getString('module-mounts-none')}</Banner>
  }
  const attention = mounts.units.some((unit) => ATTENTION.has(unit.state))
  return (
    <Banner tone={attention ? 'amber' : 'blue'}>
      <p>{l10n.getString('module-mounts-units')}</p>
      <ul className="flex flex-col gap-1">
        {mounts.units.map((unit) => (
          <li key={unit.unit}>
            <span className="verbatim">{unit.mountpoint}</span> —{' '}
            {mountStateLabel(l10n, unit.state)}
            {unit.detail === '' ? null : (
              <>
                {' — '}
                <span className="verbatim">{unit.detail}</span>
              </>
            )}
          </li>
        ))}
      </ul>
    </Banner>
  )
}
