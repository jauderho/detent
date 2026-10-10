import { describe, expect, it } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  ALIASES,
  AVAILABLE_LOCALES,
  DEFAULT_LOCALE,
  isLocale,
  matchLocale,
  negotiateLocales,
  PSEUDO_LOCALE,
  SHIPPED_LOCALES,
} from '../locales'

/** The owner's decision of 2026-10-10: exactly these twelve, no right-to-left locale. */
const OWNER_LOCALES = [
  'bn-BD',
  'de-DE',
  'en-GB',
  'en-US',
  'es-ES',
  'fr-FR',
  'hi-IN',
  'ja-JP',
  'pt-BR',
  'ru-RU',
  'zh-CN',
  'zh-TW',
]

describe('the shipped locale list', () => {
  it('is the twelve locales the owner approved, and the pseudo-locale on top', () => {
    expect([...(SHIPPED_LOCALES as readonly string[])].sort()).toEqual(OWNER_LOCALES)
    expect(AVAILABLE_LOCALES).toEqual([...SHIPPED_LOCALES, PSEUDO_LOCALE])
    expect(DEFAULT_LOCALE).toBe('en-US')
  })

  it('has no right-to-left language', () => {
    const rtl = ['ar', 'he', 'fa', 'ur']
    for (const locale of SHIPPED_LOCALES) {
      expect(rtl).not.toContain(locale.split('-')[0])
    }
  })

  it('knows its own tags', () => {
    expect(isLocale('de-DE')).toBe(true)
    expect(isLocale('qps-ploc')).toBe(true)
    expect(isLocale('de')).toBe(false)
    expect(isLocale(null)).toBe(false)
  })
})

describe('matchLocale', () => {
  // The same table as `regional_and_script_tags_negotiate_to_the_documented_locale`
  // in crates/detent-i18n/src/lib.rs.
  const table: [string, string][] = [
    ['en', 'en-US'],
    ['en-US', 'en-US'],
    ['en-CA', 'en-US'],
    ['en-GB', 'en-GB'],
    ['en-AU', 'en-GB'],
    ['en-NZ', 'en-GB'],
    ['en-IE', 'en-GB'],
    ['en-IN', 'en-GB'],
    ['zh', 'zh-CN'],
    ['zh-CN', 'zh-CN'],
    ['zh-Hans', 'zh-CN'],
    ['zh-Hans-CN', 'zh-CN'],
    ['zh-SG', 'zh-CN'],
    ['zh-TW', 'zh-TW'],
    ['zh-Hant', 'zh-TW'],
    ['zh-Hant-TW', 'zh-TW'],
    ['zh-HK', 'zh-TW'],
    ['zh-Hant-HK', 'zh-TW'],
    ['zh-MO', 'zh-TW'],
    ['zh-Hant-CN', 'zh-TW'],
    ['pt', 'pt-BR'],
    ['pt-PT', 'pt-BR'],
    ['es', 'es-ES'],
    ['es-MX', 'es-ES'],
    ['es-419', 'es-ES'],
    ['de', 'de-DE'],
    ['de-AT', 'de-DE'],
    ['de-CH', 'de-DE'],
    ['fr', 'fr-FR'],
    ['fr-CA', 'fr-FR'],
    ['ja', 'ja-JP'],
    ['ru', 'ru-RU'],
    ['hi', 'hi-IN'],
    ['bn', 'bn-BD'],
    ['bn-IN', 'bn-BD'],
  ]

  it('maps regional and script tags to the documented locale', () => {
    for (const [requested, expected] of table) {
      expect([requested, matchLocale(requested)]).toEqual([requested, expected])
    }
  })

  it('reads a tag in any letter case', () => {
    expect(matchLocale('DE-de')).toBe('de-DE')
    expect(matchLocale('zh-hant-hk')).toBe('zh-TW')
  })

  it('keeps the pseudo-locale to its own tag', () => {
    expect(matchLocale('qps-ploc')).toBe('qps-ploc')
    expect(matchLocale('qps')).toBeNull()
  })

  it('has no answer for a language that is not shipped, or for a bad tag', () => {
    for (const tag of ['ar', 'ar-SA', 'he', 'ko-KR', 'sv', '', '!!!', 'de_DE']) {
      expect([tag, matchLocale(tag)]).toEqual([tag, null])
    }
  })
})

describe('ALIASES', () => {
  it('has canonical keys and shipped targets', () => {
    for (const [from, to] of Object.entries(ALIASES)) {
      expect(new Intl.Locale(from).toString()).toBe(from)
      expect(SHIPPED_LOCALES as readonly string[]).toContain(to)
    }
  })

  it('is the table in crates/detent-i18n/src/lib.rs', () => {
    const rust = readFileSync(
      join(import.meta.dir, '..', '..', '..', '..', 'crates', 'detent-i18n', 'src', 'lib.rs'),
      'utf8',
    )
    const block = /const ALIASES[^=]*=\s*&\[([\s\S]*?)\];/.exec(rust)?.[1] ?? ''
    const rows = [...block.matchAll(/\("([^"]+)",\s*"([^"]+)"\)/g)].map((m) => [m[1], m[2]])
    expect(rows.length).toBeGreaterThan(0)
    expect(Object.fromEntries(rows)).toEqual({ ...ALIASES })
  })
})

describe('negotiateLocales', () => {
  it('returns matched requested locales', () => {
    expect(negotiateLocales(['en-US'])).toEqual(['en-US'])
  })

  it('falls back to en-US when nothing matches', () => {
    expect(negotiateLocales(['ko-KR', 'sv-SE'])).toEqual(['en-US'])
    expect(negotiateLocales([])).toEqual(['en-US'])
  })

  it('keeps priority order, and a locale only once', () => {
    expect(negotiateLocales(['fr-CA', 'de', 'fr-FR', 'ko'])).toEqual(['fr-FR', 'de-DE'])
  })
})
