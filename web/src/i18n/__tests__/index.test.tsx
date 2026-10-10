import { afterEach, describe, expect, it } from 'bun:test'
import { FluentBundle } from '@fluent/bundle'
import { useLocalization } from '@fluent/react'
import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  AppLocalizationProvider,
  AVAILABLE_LOCALES,
  type AvailableLocale,
  buildLocalization,
  createLocalization,
  loadLocale,
  loadLocalization,
  negotiateLocales,
  readLocale,
  useLocale,
} from '@/i18n'

afterEach(() => {
  localStorage.clear()
})

/** Runs `body` with `console.error` recorded instead of printed. */
async function recordingErrors(body: () => Promise<void> | void): Promise<unknown[]> {
  const messages: unknown[] = []
  const original = console.error
  console.error = (message?: unknown) => {
    messages.push(message)
  }
  try {
    await body()
  } finally {
    console.error = original
  }
  return messages
}

describe('negotiateLocales', () => {
  it('is the negotiation of the locales module', () => {
    expect(negotiateLocales(['de-AT', 'ja'])).toEqual(['de-DE', 'ja-JP'])
    expect(negotiateLocales(['qps-ploc'])).toEqual(['qps-ploc'])
  })
})

describe('AVAILABLE_LOCALES', () => {
  it('offers the twelve shipped locales and the pseudo-locale', () => {
    expect(AVAILABLE_LOCALES).toHaveLength(13)
    expect(AVAILABLE_LOCALES).toContain('en-US')
    expect(AVAILABLE_LOCALES).toContain('de-DE')
    expect(AVAILABLE_LOCALES).toContain('ja-JP')
    expect(AVAILABLE_LOCALES).toContain('qps-ploc')
  })
})

describe('loadLocale', () => {
  it('has en-US without a fetch', async () => {
    let calls = 0
    await loadLocale('en-US', () => {
      calls += 1
      return Promise.resolve('')
    })

    expect(calls).toBe(0)
  })

  it('fetches a locale once, even when asked twice at the same time', async () => {
    let calls = 0
    const importer = () => {
      calls += 1
      return Promise.resolve('status-brand = test brand\n')
    }
    await Promise.all([loadLocale('es-ES', importer), loadLocale('es-ES', importer)])
    await loadLocale('es-ES', importer)

    expect(calls).toBe(1)
    expect(createLocalization(['es-ES']).getString('status-brand')).toBe('test brand')
  })

  it('rejects when the locale cannot be fetched, and tries again next time', async () => {
    await expect(loadLocale('pt-BR', () => Promise.reject(new Error('offline')))).rejects.toThrow(
      'offline',
    )
    await loadLocale('pt-BR', () => Promise.resolve('status-brand = marca\n'))

    expect(createLocalization(['pt-BR']).getString('status-brand')).toBe('marca')
  })

  it('reads the real locale files through the dynamic import', async () => {
    await loadLocale('de-DE')

    expect(createLocalization(['de-DE']).getString('nav-modules')).toBe('Module')
  })
})

describe('buildLocalization', () => {
  it('leaves out a requested locale that is not loaded', () => {
    const l10n = buildLocalization(
      ['ru-RU', 'en-US'],
      new Map([['en-US', 'status-brand = brand\n']]),
    )

    expect(l10n.getString('status-brand')).toBe('brand')
    expect([...l10n.bundles].map((bundle) => bundle.locales[0])).toEqual(['en-US'])
  })

  it('is English when nothing requested is loaded', () => {
    const l10n = buildLocalization(['ru-RU'], new Map())

    expect(l10n.getString('nav-modules')).not.toBe('nav-modules')
  })
})

describe('createLocalization', () => {
  it('builds a bundle for qps-ploc', async () => {
    await loadLocale('qps-ploc')
    const l10n = createLocalization(['qps-ploc'])
    expect(l10n).toBeDefined()
    expect(l10n.getString('status-brand')).toBe('[detent]')
  })

  it('renders the shipped translations, with plural selectors and placeables', async () => {
    await Promise.all([loadLocale('de-DE'), loadLocale('ja-JP')])

    const de = createLocalization(['de-DE'])
    expect(de.getString('nav-modules')).toBe('Module')
    expect(de.getString('dashboard-modules-count', { count: 1 })).toContain('ein Modul')
    expect(de.getString('dashboard-update-install', { tag: 'v1.2.3' })).toContain('v1.2.3')

    const ja = createLocalization(['ja-JP'])
    expect(ja.getString('nav-modules')).toBe('モジュール')
    expect(ja.getString('dashboard-modules-count', { count: 1 })).toContain('個のモジュール')
    expect(ja.getString('dashboard-update-install', { tag: 'v1.2.3' })).toContain('v1.2.3')
  })

  it('surfaces Fluent parse errors without throwing', async () => {
    const originalAddResource = FluentBundle.prototype.addResource
    FluentBundle.prototype.addResource = () => [new Error('malformed entry')]
    let messages: unknown[]
    try {
      messages = await recordingErrors(() => {
        expect(createLocalization(['en-US'])).toBeDefined()
      })
    } finally {
      FluentBundle.prototype.addResource = originalAddResource
    }

    expect(String(messages[0])).toContain('[i18n] failed to parse')
  })
})

describe('loadLocalization', () => {
  it('loads what was asked for before it builds', async () => {
    const l10n = await loadLocalization(['ja-JP', 'en-US'])

    expect(l10n.getString('nav-modules')).toBe('モジュール')
  })

  it('logs a locale that fails to load and falls back to English', async () => {
    const messages = await recordingErrors(async () => {
      const l10n = await loadLocalization(['fr-FR', 'en-US'], () =>
        Promise.reject(new Error('404')),
      )

      expect(l10n.getString('nav-modules')).not.toBe('nav-modules')
    })

    expect(String(messages[0])).toContain('[i18n] failed to load fr-FR/web.ftl')
  })
})

describe('AppLocalizationProvider', () => {
  it('renders children inside a localization provider', () => {
    render(
      <AppLocalizationProvider>
        <span>localized child</span>
      </AppLocalizationProvider>,
    )

    expect(screen.getByText('localized child')).toBeInTheDocument()
  })

  it('waits for a stored locale to load, then shows it', async () => {
    localStorage.setItem('detent-locale', 'ja')
    function Probe() {
      return <span>{useLocalization().l10n.getString('nav-modules')}</span>
    }
    render(
      <AppLocalizationProvider>
        <Probe />
      </AppLocalizationProvider>,
    )

    expect(await screen.findByText('モジュール')).toBeInTheDocument()
  })

  it('keeps the old language until the new one is in', async () => {
    let switchTo: (locale: AvailableLocale) => void = () => undefined
    function Probe() {
      switchTo = useLocale().setLocale
      return <span>{useLocalization().l10n.getString('nav-modules')}</span>
    }
    render(
      <AppLocalizationProvider>
        <Probe />
      </AppLocalizationProvider>,
    )
    expect(screen.getByText('modules')).toBeInTheDocument()

    await act(async () => {
      switchTo('de-DE')
    })

    expect(await screen.findByText('Module')).toBeInTheDocument()
  })
})

describe('readLocale', () => {
  it('reads an old bare tag as its regional locale', () => {
    localStorage.setItem('detent-locale', 'de')

    expect(readLocale()).toBe('de-DE')
  })

  it('is en-US when nothing, or nothing usable, is stored', () => {
    expect(readLocale()).toBe('en-US')
    localStorage.setItem('detent-locale', 'tlh-XX-bad')

    expect(readLocale()).toBe('en-US')
  })
})

describe('useLocale', () => {
  it('persists locale changes to localStorage', async () => {
    function LocaleDisplay() {
      const { locale, setLocale } = useLocale()
      return (
        <>
          <span data-testid="locale">{locale}</span>
          <button type="button" onClick={() => setLocale('qps-ploc')}>
            switch
          </button>
        </>
      )
    }

    render(<LocaleDisplay />)
    expect(screen.getByTestId('locale')).toHaveTextContent('en-US')

    await userEvent.click(screen.getByRole('button', { name: 'switch' }))
    expect(screen.getByTestId('locale')).toHaveTextContent('qps-ploc')
    expect(localStorage.getItem('detent-locale')).toBe('qps-ploc')
  })
})
