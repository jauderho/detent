import type { ComponentProps, ReactNode } from 'react'
import { cn } from '@/lib/utils'

/**
 * The `.btn` of AESTHETIC_CONTRACT.md §6 — `--panel-2` fill, 1px `--line-2`,
 * radius 0, `transition: none`, 11px UPPERCASE caption at 0.1em tracking.
 * `.primary` is a `--blue` fill with `--cta-ink`, hovering to `--blue-bright`
 * and pressing to `translateY(1px)`.
 *
 * This exists instead of restyling `components/ui/button.tsx`: the generated
 * shadcn primitive carries `rounded-md`, `shadow-xs` and `transition-all`,
 * all three of which are §1 violations.
 */
export type ButtonVariant = 'default' | 'primary'

export type ButtonProps = Omit<ComponentProps<'button'>, 'type'> & {
  variant?: ButtonVariant | undefined
  /** Narrowed to the three valid values; defaults to a non-submitting control. */
  type?: 'button' | 'submit' | 'reset' | undefined
}

export function Button({ variant = 'default', className, type, ...props }: ButtonProps) {
  return (
    <button
      type={type ?? 'button'}
      className={cn('btn', variant === 'primary' && 'primary', className)}
      {...props}
    />
  )
}

export type ButtonGroupProps = {
  children: ReactNode
  className?: string | undefined
  /** Accessible name for the group of related controls. */
  label?: string | undefined
}

/**
 * Adjacent buttons share an edge — `border-left: none` on the joint (§6).
 * A `<fieldset>` because it natively carries `role="group"`; its default
 * border, padding and margin are reset in `.btngroup`.
 */
export function ButtonGroup({ children, className, label }: ButtonGroupProps) {
  return (
    <fieldset className={cn('btngroup', className)} aria-label={label}>
      {children}
    </fieldset>
  )
}
