import { afterEach, describe, expect, it, vi } from 'vitest'
import { getItem, removeItem, setItem } from '../storage'

describe('storage', () => {
  afterEach(() => {
    window.localStorage.clear()
    vi.restoreAllMocks()
  })

  it('round-trips a value through setItem/getItem', () => {
    expect(setItem('k', 'v')).toBe(true)
    expect(getItem('k')).toBe('v')
  })

  it('returns null for a missing key', () => {
    expect(getItem('missing')).toBeNull()
  })

  it('removeItem clears a stored value', () => {
    setItem('k', 'v')
    expect(removeItem('k')).toBe(true)
    expect(getItem('k')).toBeNull()
  })

  it('getItem never throws when localStorage.getItem throws', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('quota', 'SecurityError')
    })
    expect(() => getItem('k')).not.toThrow()
    expect(getItem('k')).toBeNull()
  })

  it('setItem never throws and returns false when localStorage.setItem throws', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('quota exceeded', 'QuotaExceededError')
    })
    expect(() => setItem('k', 'v')).not.toThrow()
    expect(setItem('k', 'v')).toBe(false)
  })
})
