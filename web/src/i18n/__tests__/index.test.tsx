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
    expect(negotiateLocales(['fr-FR', 'de-DE'])).toEqual(['en-US'])
  })

  it('matches qps-ploc when requested', () => {
    expect(negotiateLocales(['qps-ploc'])).toEqual(['qps-ploc'])
  })
})

describe('AVAILABLE_LOCALES', () => {
  it('includes both en-US and qps-ploc', () => {
    expect(AVAILABLE_LOCALES).toContain('en-US')
    expect(AVAILABLE_LOCALES).toContain('qps-ploc')
  })
})

describe('createLocalization', () => {
  it('builds a bundle for qps-ploc', () => {
    const l10n = createLocalization(['qps-ploc'])
    expect(l10n).toBeDefined()
    expect(l10n.getString('status-brand')).toBe('[detent]')
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
