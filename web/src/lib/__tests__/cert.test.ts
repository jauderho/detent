import { describe, expect, it } from 'bun:test'
import { createApiClient } from '@/api/client'
import { createLocalization } from '@/i18n'
import { stubFetch } from '@/test/providers'
import { certExpired, certGridItems } from '../cert'

const l10n = createLocalization(['en-US'])
const BASE = { fingerprint: 'AA:BB', lifetime_used_percent: 10, not_after_unix: 2_000_000_000 }

describe('certExpired', () => {
  it('is true once the end time has passed', () => {
    expect(certExpired({ ...BASE, not_after_unix: 1 })).toBe(true)
  })

  it('judges the end time on the host clock, not the browser clock', async () => {
    const dated = (when: number) =>
      new Response(null, { status: 204, headers: { Date: new Date(when).toUTCString() } })
    const hourAhead = Date.now() + 3_600_000
    const { fetch } = stubFetch([dated(hourAhead), dated(Date.now())])
    const client = createApiClient({ fetch })
    const endsInHalfAnHour = { ...BASE, not_after_unix: Math.floor(Date.now() / 1000) + 1_800 }

    await client.post('/api/v1/auth/logout', {})
    expect(certExpired(endsInHalfAnHour)).toBe(true)
    await client.post('/api/v1/auth/logout', {})
    expect(certExpired(endsInHalfAnHour)).toBe(false)
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
