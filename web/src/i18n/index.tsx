import { FluentBundle, FluentResource } from '@fluent/bundle'
import { LocalizationProvider, ReactLocalization } from '@fluent/react'
import { type ReactNode, useCallback, useEffect, useState } from 'react'
// Vite `?raw` import: bundled as a string asset, never fetched over the
// network. Path reaches the repo-root locales/ tree (outside web/), allowed
// by `server.fs.allow` in vite.config.ts.
import enUSSource from '../../../locales/en-US/web.ftl?raw'
import qpsPlocSource from '../../../locales/qps-ploc/web.ftl?raw'
import { getItem, setItem } from '../lib/storage'

export const AVAILABLE_LOCALES = ['en-US', 'qps-ploc'] as const
export type AvailableLocale = (typeof AVAILABLE_LOCALES)[number]
export const DEFAULT_LOCALE: AvailableLocale = 'en-US'

const RESOURCES: Record<AvailableLocale, string> = {
  'en-US': enUSSource,
  'qps-ploc': qpsPlocSource,
}

const STORAGE_KEY = 'detent-locale'

function isLocale(value: string | null): value is AvailableLocale {
  return (AVAILABLE_LOCALES as readonly string[]).includes(value ?? '')
}

/** Reads the persisted locale, defaulting to en-US. */
export function readLocale(): AvailableLocale {
  const stored = getItem(STORAGE_KEY)
  return isLocale(stored) ? stored : DEFAULT_LOCALE
}

/**
 * React hook for the active locale. Reads from localStorage on mount and
 * persists changes. Mirrors `useTheme()` in `lib/theme.ts`.
 */
export function useLocale(): {
  locale: AvailableLocale
  setLocale: (locale: AvailableLocale) => void
} {
  const [locale, setLocaleState] = useState<AvailableLocale>(readLocale)

  useEffect(() => {
    setItem(STORAGE_KEY, locale)
  }, [locale])

  const setLocale = useCallback((next: AvailableLocale) => {
    setLocaleState(next)
  }, [])

  return { locale, setLocale }
}

function buildBundle(locale: AvailableLocale): FluentBundle {
  const bundle = new FluentBundle(locale)
  const resource = new FluentResource(RESOURCES[locale])
  const errors = bundle.addResource(resource)
  for (const error of errors) {
    // A malformed .ftl entry should never crash the app; surface it loudly
    // in dev instead.
    console.error(`[i18n] failed to parse ${locale}/web.ftl:`, error)
  }
  return bundle
}

/** Negotiates `navigator.languages` against the locales we ship, falling back to en-US. */
export function negotiateLocales(requested: readonly string[]): AvailableLocale[] {
  const matched = requested.filter((tag): tag is AvailableLocale =>
    AVAILABLE_LOCALES.includes(tag as AvailableLocale),
  )
  return matched.length > 0 ? matched : [DEFAULT_LOCALE]
}

export function createLocalization(
  requested: readonly string[] = navigator.languages,
): ReactLocalization {
  const locales = negotiateLocales(requested)
  const bundles = locales.map(buildBundle)
  return new ReactLocalization(bundles)
}

export function AppLocalizationProvider({ children }: { children: ReactNode }) {
  const { locale } = useLocale()
  const l10n = createLocalization([locale, DEFAULT_LOCALE])
  return <LocalizationProvider l10n={l10n}>{children}</LocalizationProvider>
}
