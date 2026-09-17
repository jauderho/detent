/**
 * Locale-aware formatting for the values the API returns.
 *
 * The API speaks three different time shapes — an RFC 3339 string in the audit
 * log, Unix seconds on a backup, and a `{ secs_since_epoch, nanos_since_epoch }`
 * pair on a service status — because each mirrors how the Rust type behind it
 * serializes. Every one of them reaches an operator as a date, so the
 * conversion belongs here rather than three times over in three pages.
 *
 * Nothing here throws. A timestamp the host sent that this console cannot read
 * is a reason to show a placeholder, never to blank a table row or fail a
 * render: `null` comes back and the caller substitutes its own "unknown"
 * string, which it has to have anyway for the fields the API marks optional.
 */

import type { ReactLocalization } from '@fluent/react'
import type { components } from '@/api/schema'
import { DEFAULT_LOCALE } from '@/i18n'

/** How a service status carries the instant it entered its current state. */
export type SystemTimeView = components['schemas']['SystemTimeView']

/** Bytes per binary unit step. */
const BYTES_PER_UNIT = 1024

/** The units `formatBytes` will climb to, largest meaningful first. */
const BYTE_UNITS = ['B', 'KiB', 'MiB', 'GiB'] as const

const DATE_TIME_OPTIONS: Intl.DateTimeFormatOptions = {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
}

/**
 * The locale the bundles were negotiated for.
 *
 * Read from the localization rather than from `navigator` so that formatting
 * follows the bundle the operator is actually reading: the two diverge the
 * moment a requested language is one this build does not ship, which is
 * exactly when a mismatch would be least obvious.
 */
export function localeOf(l10n: ReactLocalization): string {
  for (const bundle of l10n.bundles) {
    const locale = bundle.locales[0]
    if (locale !== undefined) return locale
  }
  return DEFAULT_LOCALE
}

/** A date and time in the operator's locale, or `null` for an unusable value. */
export function formatDateTime(locale: string, ms: number): string | null {
  if (!Number.isFinite(ms)) return null
  const date = new Date(ms)
  if (Number.isNaN(date.getTime())) return null
  return new Intl.DateTimeFormat(locale, DATE_TIME_OPTIONS).format(date)
}

/** An RFC 3339 timestamp, as the audit log carries it. */
export function formatRfc3339(locale: string, timestamp: string): string | null {
  return formatDateTime(locale, Date.parse(timestamp))
}

/** Unix seconds, as a backup's `created_unix_s` carries them. */
export function formatUnixSeconds(locale: string, seconds: number): string | null {
  if (!Number.isFinite(seconds)) return null
  return formatDateTime(locale, seconds * 1000)
}

/**
 * `SystemTimeView`, as a service status carries it. The nanoseconds are
 * dropped deliberately — the display resolution is one second, and rounding a
 * unit nobody sees would only risk moving the second.
 */
export function formatSystemTime(locale: string, time: SystemTimeView): string | null {
  return formatUnixSeconds(locale, time.secs_since_epoch)
}

/**
 * A byte count, climbing binary units and keeping one decimal above `B`.
 *
 * Localized through `Intl.NumberFormat` so the decimal separator follows the
 * operator's locale; the unit suffix is not translated, because `KiB` is the
 * IEC symbol rather than an English word.
 */
export function formatBytes(locale: string, bytes: number): string | null {
  if (!Number.isFinite(bytes) || bytes < 0) return null

  let value = bytes
  let unit = 0
  while (value >= BYTES_PER_UNIT && unit < BYTE_UNITS.length - 1) {
    value /= BYTES_PER_UNIT
    unit += 1
  }

  const fractionDigits = unit === 0 ? 0 : 1
  const formatted = new Intl.NumberFormat(locale, {
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
  }).format(value)
  return `${formatted} ${BYTE_UNITS[unit]}`
}

/**
 * The leading characters of a digest, for a column that cannot carry 64 of
 * them. Never shortens a value that is already short enough, so a caller
 * cannot be misled into thinking it truncated something it did not.
 */
export function shortDigest(digest: string, length = 12): string {
  return digest.length <= length ? digest : `${digest.slice(0, length)}…`
}
