/**
 * Shared certificate helpers: one expiry rule for dashboard + certificates page.
 *
 * Both render the same `CertReport` with the same amber rule, so the tone
 * logic lives here rather than in either route module — a page importing
 * from another page would couple two lazy-loaded routes and invite a future
 * import cycle. The rule mirrors `detent-acme::schedule::warning_for`
 * (50 % half / 75 % quarter by lifetime used) with the 30-day wall-clock
 * floor the dashboard already used as a fallback for long-lived bootstrap
 * certs.
 */

import type { ReactLocalization } from '@fluent/react'
import type { CertReport } from '@/api/system'
import { formatUnixSeconds, localeOf } from '@/lib/format'

/**
 * Expiry tone: amber once half the lifetime is used, or inside 30 days of
 * expiry even when the lifetime is unknown.
 */
export function certTone(report: CertReport): 'blue' | 'amber' {
  if (certExpired(report)) return 'amber'
  if (
    report.lifetime_used_percent !== null &&
    report.lifetime_used_percent !== undefined &&
    report.lifetime_used_percent >= 50
  )
    return 'amber'
  if (report.not_after_unix === null || report.not_after_unix === undefined) return 'blue'
  const leftMs = report.not_after_unix * 1000 - Date.now()
  return leftMs < 30 * 86_400 * 1000 ? 'amber' : 'blue'
}

/** Lifetime warning level: `half` at 50 %, `quarter` at 75 % used. */
export function certWarning(report: CertReport): 'half' | 'quarter' | null {
  const used = report.lifetime_used_percent
  if (used === null || used === undefined) return null
  if (used >= 75) return 'quarter'
  if (used >= 50) return 'half'
  return null
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
