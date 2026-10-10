/**
 * Which locales the console ships, and how a browser's language tags map to
 * them. No imports, so `scripts/i18n-check.ts` can read it under plain Bun.
 *
 * A locale is shipped when its directory exists under `locales/`; this list
 * names the ones the project has decided to ship (the owner's decision of
 * 2026-10-10: twelve locales, no right-to-left script). A directory that is
 * not listed here fails `bun run i18n:check`, and a listed locale whose
 * directory is not there yet loads as English.
 */

/** The twelve locales detent ships, in picker order. */
export const SHIPPED_LOCALES = [
  'en-US',
  'en-GB',
  'zh-CN',
  'zh-TW',
  'es-ES',
  'pt-BR',
  'ja-JP',
  'fr-FR',
  'de-DE',
  'ru-RU',
  'hi-IN',
  'bn-BD',
] as const

/**
 * The pseudo-locale (`locales/qps-ploc/`), generated from en-US by
 * `scripts/gen-pseudo.ts`. It marks every string in `[…]` so a missed string
 * or a broken layout shows at a glance. Offered in the picker, never a language.
 */
export const PSEUDO_LOCALE = 'qps-ploc'

export const AVAILABLE_LOCALES = [...SHIPPED_LOCALES, PSEUDO_LOCALE] as const
export type AvailableLocale = (typeof AVAILABLE_LOCALES)[number]
export const DEFAULT_LOCALE: AvailableLocale = 'en-US'

/**
 * Requested tags that map to a locale the language alone does not pick. A key
 * is `language`, `language-Script`, `language-REGION` or
 * `language-Script-REGION`; the most specific key is tried first, so a script
 * wins over a region (`zh-Hant-CN` is Traditional). A bare language with no row
 * picks the first shipped locale of that language.
 *
 * The same table is `ALIASES` in `crates/detent-i18n/src/lib.rs`; a test keeps
 * the two equal.
 */
export const ALIASES: Readonly<Record<string, AvailableLocale>> = {
  en: 'en-US',
  'en-AU': 'en-GB',
  'en-HK': 'en-GB',
  'en-IE': 'en-GB',
  'en-IN': 'en-GB',
  'en-NZ': 'en-GB',
  'en-SG': 'en-GB',
  'en-ZA': 'en-GB',
  zh: 'zh-CN',
  'zh-Hans': 'zh-CN',
  'zh-SG': 'zh-CN',
  'zh-Hant': 'zh-TW',
  'zh-HK': 'zh-TW',
  'zh-MO': 'zh-TW',
  pt: 'pt-BR',
  es: 'es-ES',
}

/** The language subtag of a shipped tag: `zh-TW` is `zh`. */
function languageOf(tag: string): string {
  return tag.split('-')[0] ?? tag
}

/** Whether `value` is one of the locales the console can offer. */
export function isLocale(value: string | null): value is AvailableLocale {
  return (AVAILABLE_LOCALES as readonly string[]).includes(value ?? '')
}

/**
 * The shipped locale that best answers one language tag, or null.
 *
 * An exact tag wins; then an `ALIASES` row (`zh-HK` is `zh-TW`); then the first
 * shipped locale of the same language (`de-AT` is `de-DE`). The pseudo-locale
 * answers only to its own tag. A tag `Intl.Locale` cannot parse answers to
 * nothing.
 */
export function matchLocale(tag: string): AvailableLocale | null {
  // Before parsing: `Intl.Locale` reads the `ploc` of `qps-ploc` as a script and
  // would write it back as `qps-Ploc`.
  if (isLocale(tag)) return tag
  let parsed: Intl.Locale
  try {
    parsed = new Intl.Locale(tag)
  } catch {
    return null
  }
  if (isLocale(parsed.baseName)) return parsed.baseName
  const { language, script, region } = parsed
  const keys = [
    script && region ? `${language}-${script}-${region}` : null,
    script ? `${language}-${script}` : null,
    region ? `${language}-${region}` : null,
    language,
  ]
  for (const key of keys) {
    const alias = key === null ? undefined : ALIASES[key]
    if (alias !== undefined) return alias
  }
  return SHIPPED_LOCALES.find((shipped) => languageOf(shipped) === language) ?? null
}

/**
 * Negotiates `navigator.languages` against the locales we ship: every request
 * that matches, in priority order and without repeats, or en-US when none does.
 */
export function negotiateLocales(requested: readonly string[]): AvailableLocale[] {
  const matched = new Set<AvailableLocale>()
  for (const tag of requested) {
    const locale = matchLocale(tag)
    if (locale !== null) matched.add(locale)
  }
  return matched.size > 0 ? [...matched] : [DEFAULT_LOCALE]
}
