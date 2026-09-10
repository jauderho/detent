import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { Led } from './Led'

/**
 * A full-width hairline strip for the pending-commit / warning state —
 * AESTHETIC_CONTRACT.md §6 (LED as the indicator) and §12 (tone carries
 * meaning only, never decoration): `amber` means needs attention, `blue`
 * means informational. There is no third hue.
 *
 * The message stays `--ink` rather than taking the tone color: amber type on
 * the cream chassis does not clear the §11 4.5:1 floor, while an amber LED
 * glows in both themes.
 */
export type BannerTone = 'amber' | 'blue'

const TONE_LED = {
  amber: 'rec',
  blue: 'blue',
} as const

const TONE_ROLE = {
  amber: 'alert',
  blue: 'status',
} as const

export type BannerProps = {
  tone: BannerTone
  /** Localized message — the caller owns the copy. */
  children: ReactNode
  /** Right-aligned control slot (review, commit, discard). */
  actions?: ReactNode
  className?: string | undefined
}

export function Banner({ tone, children, actions, className }: BannerProps) {
  return (
    <div className={cn('banner', tone, className)} role={TONE_ROLE[tone]}>
      <Led variant={TONE_LED[tone]} />
      <div className="banner-msg">{children}</div>
      {actions === undefined ? null : <div className="banner-actions">{actions}</div>}
    </div>
  )
}
