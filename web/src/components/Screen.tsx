import type { CSSProperties, ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { SCREEN_BG, SCREEN_BORDER, SCREEN_MUTED } from '@/styles/screen-constants'

/**
 * AESTHETIC_CONTRACT.md §4 — the never-themed surface. A screen keeps the
 * sanctioned dark constants (`#06121f` fill, `#0a3252` hairline) in *both*
 * themes and lights its text with `--screen-blue` / `--amber`, which are fixed
 * across themes. Wiring a screen to `--ink*` or letting it invert with
 * `data-theme` is the §12 anti-pattern this component exists to prevent.
 *
 * The constants are applied inline rather than through a class so that no
 * stylesheet or theme flip can reach them.
 */
export const SCREEN_SURFACE_STYLE: CSSProperties = {
  background: SCREEN_BG,
  borderStyle: 'solid',
  borderWidth: 1,
  borderColor: SCREEN_BORDER,
  borderRadius: 0,
}

export type ScreenProps = {
  children: ReactNode
  className?: string | undefined
  style?: CSSProperties | undefined
}

export function Screen({ children, className, style }: ScreenProps) {
  return (
    <div className={cn('screen', className)} style={{ ...SCREEN_SURFACE_STYLE, ...style }}>
      {children}
    </div>
  )
}

/** `blue` is a normal lit value; `amber` is a §4/§12 alert value. */
export type ReadoutTone = 'blue' | 'amber'

const TONE_COLOR: Record<ReadoutTone, string> = {
  blue: 'var(--screen-blue)',
  amber: 'var(--amber)',
}

export type ReadoutProps = {
  /** Already formatted for display — the caller owns locale-aware formatting. */
  value: string
  /** Optional unit suffix, set in mono at the §4 inner-screen gray. */
  unit?: string | undefined
  tone?: ReadoutTone | undefined
  /** Accessible name when the surrounding markup does not supply one. */
  label?: string | undefined
  className?: string | undefined
}

/**
 * A lit, tabular-nums value on a screen — §1 ("tabular numerals on every
 * readout") and §2 (readouts are always IBM Plex Mono).
 */
export function Readout({ value, unit, tone = 'blue', label, className }: ReadoutProps) {
  return (
    <output
      className={cn('readout', 'read', className)}
      style={{ color: TONE_COLOR[tone], textShadow: '0 0 8px currentColor' }}
      aria-label={label}
      aria-live="off"
    >
      <span>{value}</span>
      {unit === undefined ? null : (
        <span className="readout-unit" style={{ color: SCREEN_MUTED, textShadow: 'none' }}>
          {unit}
        </span>
      )}
    </output>
  )
}
