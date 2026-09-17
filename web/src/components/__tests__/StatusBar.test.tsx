import { describe, expect, it } from 'bun:test'
import { LocalizationProvider, type ReactLocalization } from '@fluent/react'
import { render, screen } from '@testing-library/react'
import { createLocalization } from '@/i18n'
import { StatusBar } from '../StatusBar'

function renderWithL10n(l10n: ReactLocalization) {
  return render(
    <LocalizationProvider l10n={l10n}>
      <StatusBar />
    </LocalizationProvider>,
  )
}

describe('StatusBar', () => {
  it('renders labels resolved from the en-US Fluent bundle', () => {
    renderWithL10n(createLocalization(['en-US']))

    expect(screen.getByText('detent')).toBeInTheDocument()
    expect(screen.getByText('system online')).toBeInTheDocument()
    expect(screen.getByText('utc')).toBeInTheDocument()
    expect(screen.getByText('mode')).toBeInTheDocument()
  })

  // PLAN §4.4 promises 390px with no horizontal scroll. The four status
  // segments are fixed nowrap content that overflowed (scrollWidth 487);
  // the `online-label` hook below is what the narrow CSS hides. If the class
  it('marks the online label for the narrow-viewport CSS', () => {
    const { container } = renderWithL10n(createLocalization(['en-US']))

    // `<Localized>` renders its own child span, so the hook lives on the
    // wrapper, not on the text node `getByText` returns.
    const hook = container.querySelector('.status .online-label')
    expect(hook).not.toBeNull()
    expect(hook?.textContent).toBe('system online')
  })

  it('renders a locale selector with all available locales', () => {
    renderWithL10n(createLocalization(['en-US']))
    const select = screen.getByRole('combobox', { name: 'interface language' })
    expect(select).toBeInTheDocument()
    expect(select).toHaveValue('en-US')
    expect(screen.getByRole('option', { name: 'en-US' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'qps-ploc' })).toBeInTheDocument()
  })

  it('renders a live tabular-nums UTC clock', () => {
    renderWithL10n(createLocalization(['en-US']))
    const clock = screen.getByText(/^\d{2}:\d{2}:\d{2}$/)
    expect(clock).toBeInTheDocument()
    expect(clock.className).toContain('tabular-nums')
  })

  it('ticks every second and clears the interval on unmount', () => {
    const callbacks: Array<() => void> = []
    const cleared: number[] = []

    const originalSetInterval = window.setInterval
    const originalClearInterval = window.clearInterval

    window.setInterval = ((callback: () => void) => {
      callbacks.push(callback)
      return callbacks.length
    }) as unknown as typeof window.setInterval

    window.clearInterval = ((id: number | undefined) => {
      if (id !== undefined) cleared.push(id)
    }) as unknown as typeof window.clearInterval

    try {
      const { unmount } = renderWithL10n(createLocalization(['en-US']))
      expect(callbacks.length).toBe(1)
      expect(cleared.length).toBe(0)

      const tick = callbacks[0]
      expect(tick).toBeDefined()
      tick?.()
      expect(screen.getByText(/^\d{2}:\d{2}:\d{2}$/)).toBeInTheDocument()

      unmount()
      expect(cleared).toContain(1)
    } finally {
      window.setInterval = originalSetInterval
      window.clearInterval = originalClearInterval
    }
  })
})
