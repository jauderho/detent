import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { applyTheme, readTheme, useTheme } from '../theme'

afterEach(() => {
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
})
