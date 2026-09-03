import { cn } from '@/lib/utils'

export type LedVariant = 'on' | 'rec' | 'blue' | 'off'

const VARIANT_CLASSES: Record<LedVariant, string> = {
  on: 'bg-[var(--green)] shadow-[0_0_6px_var(--green)]',
  rec: 'bg-[var(--amber)] shadow-[0_0_6px_var(--amber)] animate-led-blink',
  blue: 'bg-[var(--screen-blue)] shadow-[0_0_7px_var(--screen-blue)]',
  off: 'bg-[var(--ink-faint)]',
}

export function Led({ variant = 'off', className }: { variant?: LedVariant; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn('inline-block h-[7px] w-[7px]', VARIANT_CLASSES[variant], className)}
    />
  )
}
