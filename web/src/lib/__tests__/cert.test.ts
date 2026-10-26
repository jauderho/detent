import { describe, expect, it } from 'bun:test'
import { createLocalization } from '@/i18n'
import { certExpired, certGridItems } from '../cert'

const l10n = createLocalization(['en-US'])
const BASE = { fingerprint: 'AA:BB', lifetime_used_percent: 10, not_after_unix: 2_000_000_000 }

describe('certExpired', () => {
  it('is true once the end time has passed', () => {
    expect(certExpired({ ...BASE, not_after_unix: 1 })).toBe(true)
  })

  it('is false for a future end time and for an unknown one', () => {
    expect(certExpired(BASE)).toBe(false)
    expect(certExpired({ ...BASE, not_after_unix: null })).toBe(false)
  })
})

describe('certGridItems', () => {
  it('formats the expiry and the lifetime used', () => {
    const [fingerprint, expires, used] = certGridItems(l10n, BASE)
    expect(fingerprint).toBe('AA:BB')
    expect(expires).not.toBe('unknown')
    expect(used).toBe('10%')
  })

  it('shows unknown for an absent expiry', () => {
    expect(certGridItems(l10n, { ...BASE, not_after_unix: null })[1]).toBe('unknown')
  })

  it('shows unknown for an absent lifetime used', () => {
    expect(certGridItems(l10n, { ...BASE, lifetime_used_percent: null })[2]).toBe('unknown')
  })
})
