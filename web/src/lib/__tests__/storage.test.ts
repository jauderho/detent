/**
 * `storage.ts` exists to never throw. Proving that needs a `localStorage` that
 * does throw, which is harder to arrange than it looks: happy-dom's `Storage`
 * is a proxy, so a spy on `Storage.prototype.setItem` — or even on the
 * instance — is simply not consulted when the method is called. Both
 * techniques install cleanly and intercept nothing, which is the worst kind of
 * test: green, and testing the happy path twice.
 *
 * So the whole accessor is swapped instead. `window.localStorage` is a
 * configurable getter, so a case can hand back an object whose methods throw
 * the real `DOMException`s a browser raises — `SecurityError` in privacy mode,
 * `QuotaExceededError` when the origin is full — and put the original back
 * afterwards.
 */

import { afterEach, describe, expect, it } from 'bun:test'
import { getItem, removeItem, setItem } from '../storage'

/** The real accessor, captured once so every case can restore it. */
const REAL_LOCAL_STORAGE = Object.getOwnPropertyDescriptor(window, 'localStorage')

/** Points `window.localStorage` at a store whose every method throws `error`. */
function withThrowingStorage(error: DOMException): void {
  const throwing = {
    getItem: () => {
      throw error
    },
    setItem: () => {
      throw error
    },
    removeItem: () => {
      throw error
    },
    clear: () => {
      throw error
    },
    key: () => {
      throw error
    },
    length: 0,
  }
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    get: () => throwing,
  })
}

describe('storage', () => {
  afterEach(() => {
    if (REAL_LOCAL_STORAGE !== undefined) {
      Object.defineProperty(window, 'localStorage', REAL_LOCAL_STORAGE)
    }
    window.localStorage.clear()
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

  it('getItem never throws when localStorage is denied', () => {
    withThrowingStorage(new DOMException('denied', 'SecurityError'))
    expect(() => getItem('k')).not.toThrow()
    expect(getItem('k')).toBeNull()
  })

  it('setItem never throws and returns false when the quota is exceeded', () => {
    withThrowingStorage(new DOMException('quota exceeded', 'QuotaExceededError'))
    expect(() => setItem('k', 'v')).not.toThrow()
    expect(setItem('k', 'v')).toBe(false)
  })

  it('removeItem never throws and returns false when localStorage is denied', () => {
    withThrowingStorage(new DOMException('denied', 'SecurityError'))
    expect(() => removeItem('k')).not.toThrow()
    expect(removeItem('k')).toBe(false)
  })

  // The tripwire for the failure mode this file's doc comment describes: if a
  // future change makes `withThrowingStorage` stop intercepting, the three
  // cases above would pass by testing nothing. This one fails instead.
  it('the throwing stub is actually reached', () => {
    withThrowingStorage(new DOMException('denied', 'SecurityError'))
    expect(() => window.localStorage.getItem('k')).toThrow()
  })
})
