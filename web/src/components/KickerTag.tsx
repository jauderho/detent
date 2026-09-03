import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

/** A bordered tag chip for the `.kicker` row — model · class · revision. */
export function KickerTag({
  children,
  variant,
  className,
}: {
  children: ReactNode
  variant?: 'blue'
  className?: string
}) {
  return <span className={cn('tag', variant, className)}>{children}</span>
}
