import { useCallback, useEffect, useState } from 'react'
import { getItem, setItem } from './storage'

export type Theme = 'dark' | 'light'

const STORAGE_KEY = 'detent-theme'

function isTheme(value: string | null): value is Theme {
  return value === 'dark' || value === 'light'
}

/**
 * Reads the persisted theme, defaulting to dark.
 *
 * Deliberately does **not** consult `prefers-color-scheme`. AGENTS.md fixes
 * the default as dark, and an OS preference that silently overrode it meant
 * the console opened light on a light-preferring desktop — not the documented
 * behaviour, and not what an operator who never touched the toggle was
 * promised. The toggle is one click and its choice is remembered, so honouring
 * the system setting buys little and costs a stated guarantee.
 */
export function readTheme(): Theme {
  const stored = getItem(STORAGE_KEY)
  return isTheme(stored) ? stored : 'dark'
}

/** Applies the theme to `<html data-theme>` and persists it. */
export function applyTheme(theme: Theme): void {
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('data-theme', theme)
  }
  setItem(STORAGE_KEY, theme)
}

/** Reads the theme currently set on `<html data-theme>`, if any. */
export function currentDomTheme(): Theme | null {
  if (typeof document === 'undefined') return null
  const value = document.documentElement.getAttribute('data-theme')
  return isTheme(value) ? value : null
}

export function useTheme(): {
  theme: Theme
  toggleTheme: () => void
  setTheme: (theme: Theme) => void
} {
  const [theme, setThemeState] = useState<Theme>(() => currentDomTheme() ?? readTheme())

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next)
  }, [])

  const toggleTheme = useCallback(() => {
    setThemeState((prev) => (prev === 'dark' ? 'light' : 'dark'))
  }, [])

  return { theme, toggleTheme, setTheme }
}
