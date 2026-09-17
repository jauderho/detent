/**
 * `readTheme` has two branches — stored value, else dark — and the second one
 * is a stated guarantee (AGENTS.md: "defaulting to dark"), not a fallback that
 * the environment gets a say in. It used to consult `prefers-color-scheme`,
 * which made this file's result depend on the DOM shim: jsdom reported no
 * preference and the default looked correct, happy-dom reports light and it
 * was not. The `stubColorScheme` case below is the tripwire for that returning.
 */

import { afterEach, describe, expect, it } from 'bun:test'
import { act, renderHook } from '@testing-library/react'
import { applyTheme, readTheme, useTheme } from '../theme'

const REAL_MATCH_MEDIA = window.matchMedia

/** Makes `(prefers-color-scheme: light)` answer `matches`. */
function stubColorScheme(light: boolean): void {
  window.matchMedia = ((query: string) => ({
    matches: light && query.includes('light'),
    media: query,
    onchange: null,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia
}

afterEach(() => {
  window.matchMedia = REAL_MATCH_MEDIA
  window.localStorage.clear()
  document.documentElement.removeAttribute('data-theme')
})

describe('applyTheme / readTheme', () => {
  it('applyTheme sets data-theme and persists to localStorage', () => {
    applyTheme('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(window.localStorage.getItem('detent-theme')).toBe('light')
  })

  it('readTheme returns the persisted theme', () => {
    applyTheme('light')
    expect(readTheme()).toBe('light')
  })

  it('readTheme defaults to dark when nothing is stored', () => {
    expect(readTheme()).toBe('dark')
  })

  it('readTheme ignores a light OS preference', () => {
    stubColorScheme(true)
    expect(readTheme()).toBe('dark')
  })
})

describe('useTheme', () => {
  it('toggleTheme flips data-theme and persists it', () => {
    document.documentElement.setAttribute('data-theme', 'dark')
    const { result } = renderHook(() => useTheme())

    expect(result.current.theme).toBe('dark')

    act(() => {
      result.current.toggleTheme()
    })

    expect(result.current.theme).toBe('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(window.localStorage.getItem('detent-theme')).toBe('light')
  })

  it('setTheme applies an explicit theme value', () => {
    document.documentElement.setAttribute('data-theme', 'dark')
    const { result } = renderHook(() => useTheme())

    act(() => {
      result.current.setTheme('light')
    })

    expect(result.current.theme).toBe('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(window.localStorage.getItem('detent-theme')).toBe('light')
  })
})
