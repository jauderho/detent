import { FluentBundle, FluentResource } from '@fluent/bundle'
import { LocalizationProvider, ReactLocalization } from '@fluent/react'
import type { ReactNode } from 'react'
// Vite `?raw` import: bundled as a string asset, never fetched over the
// network. Path reaches the repo-root locales/ tree (outside web/), allowed
// by `server.fs.allow` in vite.config.ts.
import enUSSource from '../../../locales/en-US/web.ftl?raw'

export const AVAILABLE_LOCALES = ['en-US'] as const
export type AvailableLocale = (typeof AVAILABLE_LOCALES)[number]
export const DEFAULT_LOCALE: AvailableLocale = 'en-US'

const RESOURCES: Record<AvailableLocale, string> = {
  'en-US': enUSSource,
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
  const l10n = createLocalization()
  return <LocalizationProvider l10n={l10n}>{children}</LocalizationProvider>
}
