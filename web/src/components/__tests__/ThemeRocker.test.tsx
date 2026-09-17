import { afterEach, describe, expect, it } from 'bun:test'
import { LocalizationProvider } from '@fluent/react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createLocalization } from '@/i18n'
import { ThemeRocker } from '../ThemeRocker'

afterEach(() => {
  window.localStorage.clear()
  document.documentElement.removeAttribute('data-theme')
})

describe('ThemeRocker', () => {
  it('toggles data-theme, persists the choice, and updates aria-pressed', async () => {
    document.documentElement.setAttribute('data-theme', 'dark')
    render(
      <LocalizationProvider l10n={createLocalization(['en-US'])}>
        <ThemeRocker />
      </LocalizationProvider>,
    )

    const rocker = screen.getByRole('button', { name: /toggle light and dark mode/i })
    expect(rocker).toHaveAttribute('aria-pressed', 'false')

    await userEvent.click(rocker)

    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(window.localStorage.getItem('detent-theme')).toBe('light')
    expect(rocker).toHaveAttribute('aria-pressed', 'true')
  })

  it('is keyboard operable', async () => {
    document.documentElement.setAttribute('data-theme', 'dark')
    render(
      <LocalizationProvider l10n={createLocalization(['en-US'])}>
        <ThemeRocker />
      </LocalizationProvider>,
    )

    const rocker = screen.getByRole('button', { name: /toggle light and dark mode/i })
    rocker.focus()
    await userEvent.keyboard('{Enter}')

    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })
})
