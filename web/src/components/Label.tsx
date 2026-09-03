import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

/** The `.lbl` silk-screen label — see AESTHETIC_CONTRACT.md §2 / §6. */
export function Label({
  children,
  variant,
  className,
}: {
  children: ReactNode
  variant?: 'blue' | 'dim'
  className?: string
}) {
  return <span className={cn('lbl', variant, className)}>{children}</span>
}
