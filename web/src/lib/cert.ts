/**
 * Shared certificate helpers: one expiry rule for dashboard + certificates page.
 *
 * Both render the same `CertReport` with the same 30-day/expired amber rule,
 * so the tone logic lives here rather than in either route module — a page
 * importing from another page would couple two lazy-loaded routes and invite
 * a future import cycle.
 */

import type { ReactLocalization } from '@fluent/react'
import type { CertReport } from '@/api/system'
import { formatUnixSeconds, localeOf } from '@/lib/format'

/** Expiry tone: amber once inside 30 days or past expiry, blue otherwise. */
export function certTone(report: CertReport): 'blue' | 'amber' {
  if (report.not_after_unix === null || report.not_after_unix === undefined) return 'blue'
  const leftMs = report.not_after_unix * 1000 - Date.now()
  return leftMs < 30 * 86_400 * 1000 ? 'amber' : 'blue'
}

export function certExpired(report: CertReport): boolean {
  return (
    report.not_after_unix !== null &&
    report.not_after_unix !== undefined &&
    report.not_after_unix * 1000 < Date.now()
  )
}

export function certGridItems(
  l10n: ReactLocalization,
  report: CertReport,
): [string, string, string] {
  const locale = localeOf(l10n)
  const unknown = l10n.getString('state-unknown')
  const expires =
    report.not_after_unix === null || report.not_after_unix === undefined
      ? unknown
      : (formatUnixSeconds(locale, report.not_after_unix) ?? unknown)
  const used =
    report.lifetime_used_percent === null || report.lifetime_used_percent === undefined
      ? unknown
      : `${new Intl.NumberFormat(locale).format(report.lifetime_used_percent)}%`
  return [report.fingerprint, expires, used]
}
