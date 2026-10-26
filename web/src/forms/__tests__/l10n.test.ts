import { describe, expect, it } from 'bun:test'
import { createLocalization } from '@/i18n'
import { joinLines, optionalMessage } from '../l10n'

describe('optionalMessage', () => {
  const l10n = createLocalization(['en-US'])

  it('formats a message the loaded bundles define', () => {
    expect(optionalMessage(l10n, 'forms-list-empty')).toBe('nothing here yet.')
  })

  it('passes the arguments to the message', () => {
    const text = optionalMessage(l10n, 'login-retry-after', { seconds: 7 })
    expect(text?.replace(/[\u2068\u2069]/g, '')).toContain('wait 7 seconds')
  })

  it('returns undefined for an absent, empty or unknown id', () => {
    expect(optionalMessage(l10n, undefined)).toBeUndefined()
    expect(optionalMessage(l10n, '')).toBeUndefined()
    expect(optionalMessage(l10n, 'no-such-message')).toBeUndefined()
  })
})

describe('joinLines', () => {
  it('joins the present parts and drops the absent ones', () => {
    expect(joinLines(['a', undefined, '', 'b'])).toBe('a · b')
  })

  it('returns undefined when no part is present', () => {
    expect(joinLines([undefined, ''])).toBeUndefined()
  })
})
