import { FluentBundle } from '@fluent/bundle'
import { ReactLocalization } from '@fluent/react'
import { describe, expect, it } from 'vitest'
import {
  formatBytes,
  formatDateTime,
  formatRfc3339,
  formatSystemTime,
  formatUnixSeconds,
  localeOf,
  shortDigest,
} from '../format'

/** 2026-09-16T12:34:56Z, the instant every case below formats. */
const INSTANT_MS = Date.UTC(2026, 8, 16, 12, 34, 56)
const INSTANT_S = INSTANT_MS / 1000

describe('localeOf', () => {
  it('reads the locale the bundles were negotiated for', () => {
    const l10n = new ReactLocalization([new FluentBundle('fr-FR')])
    expect(localeOf(l10n)).toBe('fr-FR')
  })

  it('falls back to the default when there are no bundles', () => {
    expect(localeOf(new ReactLocalization([]))).toBe('en-US')
  })
})

describe('formatDateTime', () => {
  it('formats an instant in the given locale', () => {
    const formatted = formatDateTime('en-US', INSTANT_MS)
    expect(formatted).not.toBeNull()
    expect(formatted).toContain('2026')
  })

  it('answers null rather than "Invalid Date" for an unusable value', () => {
    expect(formatDateTime('en-US', Number.NaN)).toBeNull()
    expect(formatDateTime('en-US', Number.POSITIVE_INFINITY)).toBeNull()
  })

  it('renders the same instant differently in two locales', () => {
    // Proof the locale argument is honored rather than ignored: the two
    // formats differ in month naming and field order.
    expect(formatDateTime('en-US', INSTANT_MS)).not.toBe(formatDateTime('ja-JP', INSTANT_MS))
  })
})

describe('the three API time shapes', () => {
  it('agree on one instant', () => {
    const expected = formatDateTime('en-US', INSTANT_MS)
    expect(formatRfc3339('en-US', new Date(INSTANT_MS).toISOString())).toBe(expected)
    expect(formatUnixSeconds('en-US', INSTANT_S)).toBe(expected)
    expect(
      formatSystemTime('en-US', { secs_since_epoch: INSTANT_S, nanos_since_epoch: 500_000_000 }),
    ).toBe(expected)
  })

  it('answer null for a timestamp that cannot be read', () => {
    expect(formatRfc3339('en-US', 'not a date')).toBeNull()
    expect(formatUnixSeconds('en-US', Number.NaN)).toBeNull()
  })
})

describe('formatBytes', () => {
  it('climbs binary units and keeps one decimal above bytes', () => {
    expect(formatBytes('en-US', 0)).toBe('0 B')
    expect(formatBytes('en-US', 512)).toBe('512 B')
    expect(formatBytes('en-US', 1024)).toBe('1.0 KiB')
    expect(formatBytes('en-US', 1536)).toBe('1.5 KiB')
    expect(formatBytes('en-US', 1024 * 1024)).toBe('1.0 MiB')
    expect(formatBytes('en-US', 1024 * 1024 * 1024)).toBe('1.0 GiB')
  })

  it('stops at the largest unit it knows rather than inventing one', () => {
    expect(formatBytes('en-US', 4096 * 1024 * 1024 * 1024)).toBe('4,096.0 GiB')
  })

  it('localizes the decimal separator', () => {
    expect(formatBytes('de-DE', 1536)).toBe('1,5 KiB')
  })

  it('answers null for a value that is not a byte count', () => {
    expect(formatBytes('en-US', -1)).toBeNull()
    expect(formatBytes('en-US', Number.NaN)).toBeNull()
  })
})

describe('shortDigest', () => {
  it('truncates a full digest and marks that it did', () => {
    const digest = 'a'.repeat(64)
    expect(shortDigest(digest)).toBe(`${'a'.repeat(12)}…`)
  })

  it('leaves a value that already fits untouched', () => {
    expect(shortDigest('abc')).toBe('abc')
    expect(shortDigest('a'.repeat(12))).toBe('a'.repeat(12))
  })
})
