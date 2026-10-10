import { describe, expect, it } from 'bun:test'
import { FluentBundle } from '@fluent/bundle'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  AppLocalizationProvider,
  AVAILABLE_LOCALES,
  createLocalization,
  negotiateLocales,
  useLocale,
} from '@/i18n'

describe('negotiateLocales', () => {
  it('returns matched requested locales', () => {
    expect(negotiateLocales(['en-US'])).toEqual(['en-US'])
  })

  it('falls back to en-US when nothing matches', () => {
    expect(negotiateLocales(['ko-KR', 'sv-SE'])).toEqual(['en-US'])
  })

  it('matches qps-ploc when requested', () => {
    expect(negotiateLocales(['qps-ploc'])).toEqual(['qps-ploc'])
  })

  it('matches the shipped translations when requested', () => {
    expect(negotiateLocales(['de-DE', 'ja-JP'])).toEqual(['de-DE', 'ja-JP'])
  })
})

describe('AVAILABLE_LOCALES', () => {
  it('includes en-US, de-DE, ja-JP and qps-ploc', () => {
    expect(AVAILABLE_LOCALES).toContain('en-US')
    expect(AVAILABLE_LOCALES).toContain('de-DE')
    expect(AVAILABLE_LOCALES).toContain('ja-JP')
    expect(AVAILABLE_LOCALES).toContain('qps-ploc')
  })
})

describe('createLocalization', () => {
  it('builds a bundle for qps-ploc', () => {
    const l10n = createLocalization(['qps-ploc'])
    expect(l10n).toBeDefined()
    expect(l10n.getString('status-brand')).toBe('[detent]')
  })

  it('renders the shipped translations, with plural selectors and placeables', () => {
    const de = createLocalization(['de-DE'])
    expect(de.getString('nav-modules')).toBe('Module')
    expect(de.getString('dashboard-modules-count', { count: 1 })).toContain('ein Modul')
    expect(de.getString('dashboard-update-install', { tag: 'v1.2.3' })).toContain('v1.2.3')

    const ja = createLocalization(['ja-JP'])
    expect(ja.getString('nav-modules')).toBe('モジュール')
    expect(ja.getString('dashboard-modules-count', { count: 1 })).toContain('個のモジュール')
    expect(ja.getString('dashboard-update-install', { tag: 'v1.2.3' })).toContain('v1.2.3')
  })

  it('surfaces Fluent parse errors without throwing', () => {
    let firstMessage: unknown
    const originalError = console.error
    console.error = (message?: unknown) => {
      firstMessage ??= message
    }

    const originalAddResource = FluentBundle.prototype.addResource
    FluentBundle.prototype.addResource = () => [new Error('malformed entry')]
    try {
      const l10n = createLocalization(['en-US'])
      expect(l10n).toBeDefined()
      expect(String(firstMessage)).toContain('[i18n] failed to parse')
    } finally {
      FluentBundle.prototype.addResource = originalAddResource
      console.error = originalError
    }
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
