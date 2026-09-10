import { useLocalization } from '@fluent/react'
import { useEffect, useRef, useState } from 'react'
import { Readout, Screen } from './Screen'

/**
 * The commit-confirm window — a `Screen`-styled monospace `mm:ss` readout
 * that counts down to a deadline and fires `onExpire` once when it lands on
 * zero. Realizes AESTHETIC_CONTRACT.md §4 (never-themed lit surface) and §1
 * (`tabular-nums` on every readout).
 *
 * §9: the per-second tick is a `setInterval` cleaned up on unmount.
 *
 * It keeps ticking under `prefers-reduced-motion`, which is a deliberate
 * exception to §9's "the LCD paints one static frame". §9 is about decorative
 * motion — the blink, the marquee, the equalizer sweep — and freezing those
 * costs the user nothing. Here the changing value *is* the information: this
 * is the commit-confirm window, and a frame frozen at `02:00` while ninety
 * seconds have actually elapsed tells the operator they have time they do not
 * have, moments before the configuration rolls back under them. A digit
 * replacing itself once a second is also not a vestibular trigger, which is
 * what the reduced-motion preference exists to suppress.
 */
const TICK_MS = 1000

/** Below this many seconds the readout switches to the §4 alert tone. */
const WARN_THRESHOLD_SECONDS = 30

export function remainingSeconds(deadline: number, now: number): number {
  return Math.max(0, Math.ceil((deadline - now) / TICK_MS))
}

export function formatMmSs(totalSeconds: number): string {
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
}

export type CountdownProps = {
  /** Deadline as epoch milliseconds. */
  deadline: number
  /** Fired once when the countdown reaches zero. */
  onExpire?: (() => void) | undefined
  /** Localized accessible name for the readout. */
  label?: string | undefined
  className?: string | undefined
}

export function Countdown({ deadline, onExpire, label, className }: CountdownProps) {
  const { l10n } = useLocalization()
  const [now, setNow] = useState<number>(() => Date.now())
  const remaining = remainingSeconds(deadline, now)

  useEffect(() => {
    const id = window.setInterval(() => {
      setNow(Date.now())
    }, TICK_MS)
    return () => {
      window.clearInterval(id)
    }
  }, [])

  const firedForRef = useRef<number | null>(null)
  useEffect(() => {
    if (remaining > 0 || firedForRef.current === deadline) return
    firedForRef.current = deadline
    onExpire?.()
  }, [remaining, deadline, onExpire])

  return (
    <Screen className={className}>
      <Readout
        value={formatMmSs(remaining)}
        tone={remaining <= WARN_THRESHOLD_SECONDS ? 'amber' : 'blue'}
        label={label ?? l10n.getString('component-countdown-remaining')}
      />
    </Screen>
  )
}
