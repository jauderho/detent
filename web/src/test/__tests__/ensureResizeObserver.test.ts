import { describe, expect, it } from 'bun:test'
import { ensureResizeObserver } from '../ensureResizeObserver'

describe('ensureResizeObserver', () => {
  it('leaves a target that already has one alone', () => {
    const sentinel = class {}
    const target: Record<string, unknown> = { ResizeObserver: sentinel }

    ensureResizeObserver(target)

    expect(target.ResizeObserver).toBe(sentinel)
  })

  it('installs a no-op shim when none exists', () => {
    const target: Record<string, unknown> = {}

    ensureResizeObserver(target)

    const Shims = target.ResizeObserver as new () => {
      observe: () => void
      unobserve: () => void
      disconnect: () => void
    }
    const shim = new Shims()
    expect(() => {
      shim.observe()
      shim.unobserve()
      shim.disconnect()
    }).not.toThrow()
  })
})
