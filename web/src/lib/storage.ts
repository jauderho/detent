/**
 * Typed localStorage helper. Never throws: SSR (no `window`), quota errors,
 * privacy-mode `SecurityError`s, and any other DOM exception are swallowed
 * and reported as a no-op / `null` result.
 */

function hasLocalStorage(): boolean {
  return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined'
}

export function getItem(key: string): string | null {
  if (!hasLocalStorage()) return null
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

export function setItem(key: string, value: string): boolean {
  if (!hasLocalStorage()) return false
  try {
    window.localStorage.setItem(key, value)
    return true
  } catch {
    return false
  }
}

export function removeItem(key: string): boolean {
  if (!hasLocalStorage()) return false
  try {
    window.localStorage.removeItem(key)
    return true
  } catch {
    return false
  }
}
