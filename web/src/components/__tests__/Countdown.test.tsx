import { afterEach, describe, expect, it, jest, mock, spyOn } from 'bun:test'
import { act, screen } from '@testing-library/react'
import { renderWithL10n } from '@/test/l10n'
import { Countdown, formatMmSs, remainingSeconds } from '../Countdown'

/**
 * Replaces the DOM's `matchMedia` so the reduced-motion branch can be
 * exercised. The original is captured once and put back after every test, so
 * a case that stubs it cannot leak a preference into the next one.
 */
const REAL_MATCH_MEDIA = globalThis.matchMedia

function stubReducedMotion(reduce: boolean): void {
  globalThis.matchMedia = ((query: string) => ({
    matches: reduce && query.includes('prefers-reduced-motion'),
    media: query,
    onchange: null,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => false,
  })) as unknown as typeof globalThis.matchMedia
}

afterEach(() => {
  globalThis.matchMedia = REAL_MATCH_MEDIA
  jest.useRealTimers()
  jest.restoreAllMocks()
})

describe('countdown math', () => {
  it('rounds partial seconds up and clamps at zero', () => {
    expect(remainingSeconds(10_000, 8_500)).toBe(2)
    expect(remainingSeconds(10_000, 10_000)).toBe(0)
    expect(remainingSeconds(10_000, 99_000)).toBe(0)
  })

  it('formats mm:ss with padded, tabular-friendly digits', () => {
    expect(formatMmSs(0)).toBe('00:00')
    expect(formatMmSs(9)).toBe('00:09')
    expect(formatMmSs(600)).toBe('10:00')
    expect(formatMmSs(3_599)).toBe('59:59')
  })
})

describe('Countdown', () => {
  it('ticks down once a second and fires onExpire exactly once', () => {
    stubReducedMotion(false)
    jest.useFakeTimers()
    const onExpire = mock()
    const deadline = Date.now() + 3_000

    renderWithL10n(<Countdown deadline={deadline} onExpire={onExpire} label="commit window" />)
    expect(screen.getByLabelText('commit window')).toHaveTextContent('00:03')

    act(() => {
      jest.advanceTimersByTime(1_000)
    })
    expect(screen.getByLabelText('commit window')).toHaveTextContent('00:02')
    expect(onExpire).not.toHaveBeenCalled()

    act(() => {
      jest.advanceTimersByTime(2_000)
    })
    expect(screen.getByLabelText('commit window')).toHaveTextContent('00:00')
    expect(onExpire).toHaveBeenCalledTimes(1)

    act(() => {
      jest.advanceTimersByTime(5_000)
    })
    expect(onExpire).toHaveBeenCalledTimes(1)
  })

  it('clears its interval on unmount and stops calling back', () => {
    stubReducedMotion(false)
    jest.useFakeTimers()
    const clearInterval = spyOn(window, 'clearInterval')
    const onExpire = mock()

    const { unmount } = renderWithL10n(
      <Countdown deadline={Date.now() + 5_000} onExpire={onExpire} label="commit window" />,
    )
    unmount()

    expect(clearInterval).toHaveBeenCalled()
    act(() => {
      jest.advanceTimersByTime(10_000)
    })
    expect(onExpire).not.toHaveBeenCalled()
  })

  it('keeps ticking under prefers-reduced-motion, because the value is the information', () => {
    // Deliberate exception to AESTHETIC_CONTRACT.md §9's "one static frame":
    // this is the commit-confirm window. A frame frozen at 02:00 while 30s
    // have elapsed tells the operator they have time they do not have.
    stubReducedMotion(true)
    jest.useFakeTimers()
    const onExpire = mock()

    renderWithL10n(
      <Countdown deadline={Date.now() + 120_000} onExpire={onExpire} label="commit window" />,
    )
    expect(screen.getByLabelText('commit window')).toHaveTextContent('02:00')

    act(() => {
      jest.advanceTimersByTime(30_000)
    })
    expect(screen.getByLabelText('commit window')).toHaveTextContent('01:30')
    expect(onExpire).not.toHaveBeenCalled()

    act(() => {
      jest.advanceTimersByTime(90_000)
    })
    expect(screen.getByLabelText('commit window')).toHaveTextContent('00:00')
    expect(onExpire).toHaveBeenCalledTimes(1)
  })

  it('falls back to the localized accessible name', () => {
    stubReducedMotion(false)
    renderWithL10n(<Countdown deadline={Date.now() + 60_000} />)

    expect(screen.getByLabelText('time remaining')).toHaveTextContent('01:00')
  })
})
