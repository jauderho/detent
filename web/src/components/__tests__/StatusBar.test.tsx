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
