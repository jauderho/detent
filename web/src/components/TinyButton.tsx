import type { ComponentProps } from 'react'
import { cn } from '@/lib/utils'

/**
 * The `.tinybtn` of AESTHETIC_CONTRACT.md §6 — the 9px UPPERCASE module
 * control (play / clr / rnd / snd, ±). The `on` state is a `--blue` fill with
 * `--cta-ink`, and is surfaced to assistive tech as `aria-pressed`.
 */
export type TinyButtonProps = Omit<ComponentProps<'button'>, 'type'> & {
  /** Lit state — `--blue` fill + `--cta-ink`. */
  on?: boolean | undefined
  type?: 'button' | 'submit' | 'reset' | undefined
}

export function TinyButton({ on, className, type, ...props }: TinyButtonProps) {
  return (
    <button
      type={type ?? 'button'}
      aria-pressed={on}
      className={cn('tinybtn', on && 'on', className)}
      {...props}
    />
  )
}
