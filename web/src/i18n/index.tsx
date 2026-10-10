import { FluentBundle, FluentResource } from '@fluent/bundle'
import { LocalizationProvider, ReactLocalization } from '@fluent/react'
import { type ReactNode, useCallback, useEffect, useState, useSyncExternalStore } from 'react'
// Vite `?raw` import: bundled as a string asset, never fetched over the
// network. Path reaches the repo-root locales/ tree (outside web/), allowed
// by `server.fs.allow` in vite.config.ts. Only en-US is imported statically,
// because every other locale falls back to it; the rest load on demand (see
// `importSource`).
import enUSSource from '../../../locales/en-US/web.ftl?raw'
import { getItem, setItem } from '../lib/storage'
import { type AvailableLocale, DEFAULT_LOCALE, matchLocale, negotiateLocales } from './locales'

export {
  AVAILABLE_LOCALES,
  type AvailableLocale,
  DEFAULT_LOCALE,
  negotiateLocales,
} from './locales'

const STORAGE_KEY = 'detent-locale'

/** The `web.ftl` text of every locale loaded so far. */
const SOURCES = new Map<AvailableLocale, string>([[DEFAULT_LOCALE, enUSSource]])

/** Loads that are running or done, so one locale is fetched once. */
const LOADING = new Map<AvailableLocale, Promise<void>>()

/**
 * Vite turns this one expression into a chunk per `locales/<tag>/web.ftl`, so
 * the console downloads only the locale in use. A tag with no directory under
 * `locales/` has no chunk, and the import rejects.
 */
async function importSource(locale: AvailableLocale): Promise<string> {
  const module: { default: string } = await import(`../../../locales/${locale}/web.ftl?raw`)
  return module.default
}

/** Fetches the `web.ftl` text of one locale; tests pass their own. */
export type SourceImporter = typeof importSource

/**
 * Loads one locale's messages. Resolves at once for a locale already loaded;
 * rejects when the locale cannot be fetched, and a later call tries again.
 */
export function loadLocale(
  locale: AvailableLocale,
  importer: SourceImporter = importSource,
): Promise<void> {
  if (SOURCES.has(locale)) return Promise.resolve()
  const running = LOADING.get(locale)
  if (running !== undefined) return running
  const started = importer(locale).then(
    (source) => {
      SOURCES.set(locale, source)
    },
    (error: unknown) => {
      LOADING.delete(locale)
      throw error
    },
  )
  LOADING.set(locale, started)
  return started
}

/** Reads the persisted locale, defaulting to en-US. */
export function readLocale(): AvailableLocale {
  const stored = getItem(STORAGE_KEY)
  return (stored === null ? null : matchLocale(stored)) ?? DEFAULT_LOCALE
}

/** Everything that renders the active locale: the provider and the picker. */
const LISTENERS = new Set<() => void>()

function subscribe(listener: () => void): () => void {
  LISTENERS.add(listener)
  return () => {
    LISTENERS.delete(listener)
  }
}

/**
 * React hook for the active locale. The choice lives in localStorage, so the
 * status-bar picker and `AppLocalizationProvider` read one value: a change in
 * one is seen by the other at once, not at the next page load.
 */
export function useLocale(): {
  locale: AvailableLocale
  setLocale: (locale: AvailableLocale) => void
} {
  const locale = useSyncExternalStore(subscribe, readLocale)

  const setLocale = useCallback((next: AvailableLocale) => {
    setItem(STORAGE_KEY, next)
    for (const listener of LISTENERS) listener()
  }, [])

  return { locale, setLocale }
}

function buildBundle(locale: AvailableLocale, source: string): FluentBundle {
  const bundle = new FluentBundle(locale)
  const resource = new FluentResource(source)
  const errors = bundle.addResource(resource)
  for (const error of errors) {
    // A malformed .ftl entry should never crash the app; surface it loudly
    // in dev instead.
    console.error(`[i18n] failed to parse ${locale}/web.ftl:`, error)
  }
  return bundle
}

/**
 * A localization for `requested`, from the locales in `sources`. A requested
 * locale that is not there is left out; if none is, the result is English.
 */
export function buildLocalization(
  requested: readonly string[],
  sources: ReadonlyMap<AvailableLocale, string>,
): ReactLocalization {
  const bundles = negotiateLocales(requested).flatMap((locale) => {
    const source = sources.get(locale)
    return source === undefined ? [] : [buildBundle(locale, source)]
  })
  return new ReactLocalization(
    bundles.length > 0 ? bundles : [buildBundle(DEFAULT_LOCALE, enUSSource)],
  )
}

/**
 * Synchronous: uses the locales loaded so far, which is only en-US until
 * `loadLocale` has run for another one.
 */
export function createLocalization(
  requested: readonly string[] = navigator.languages,
): ReactLocalization {
  return buildLocalization(requested, SOURCES)
}

/**
 * Loads every locale `requested` negotiates to, then builds the localization.
 * A locale that fails to load is logged and left out, so the console falls
 * back to English instead of breaking.
 */
export async function loadLocalization(
  requested: readonly string[] = navigator.languages,
  importer: SourceImporter = importSource,
): Promise<ReactLocalization> {
  const locales = negotiateLocales(requested)
  const results = await Promise.allSettled(locales.map((locale) => loadLocale(locale, importer)))
  results.forEach((result, index) => {
    if (result.status === 'rejected') {
      console.error(`[i18n] failed to load ${locales[index]}/web.ftl:`, result.reason)
    }
  })
  return createLocalization(requested)
}

type Built = { locale: AvailableLocale; l10n: ReactLocalization }

/**
 * Provides the messages of the chosen locale. The first paint waits for them
 * (a blank for the time one small chunk takes, rather than a flash of English),
 * and a later switch keeps the old language on screen until the new one is in.
 */
export function AppLocalizationProvider({ children }: { children: ReactNode }) {
  const { locale } = useLocale()
  const [built, setBuilt] = useState<Built | null>(() =>
    SOURCES.has(locale) ? { locale, l10n: createLocalization([locale, DEFAULT_LOCALE]) } : null,
  )

  useEffect(() => {
    if (built?.locale === locale) return
    let current = true
    void loadLocalization([locale, DEFAULT_LOCALE]).then((l10n) => {
      if (current) setBuilt({ locale, l10n })
    })
    return () => {
      current = false
    }
  }, [locale, built])

  if (built === null) return null
  return <LocalizationProvider l10n={built.l10n}>{children}</LocalizationProvider>
}
