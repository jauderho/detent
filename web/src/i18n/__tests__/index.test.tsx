import { describe, expect, it } from 'bun:test'
import { FluentBundle } from '@fluent/bundle'
import { render, screen } from '@testing-library/react'
import { AppLocalizationProvider, createLocalization, negotiateLocales } from '@/i18n'

describe('negotiateLocales', () => {
  it('returns matched requested locales', () => {
    expect(negotiateLocales(['en-US'])).toEqual(['en-US'])
  })

  it('falls back to en-US when nothing matches', () => {
    expect(negotiateLocales(['fr-FR', 'de-DE'])).toEqual(['en-US'])
  })
})

describe('createLocalization', () => {
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
