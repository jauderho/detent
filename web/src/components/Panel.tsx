import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { Label } from './Label'

/**
 * A hairline-bordered zone — AESTHETIC_CONTRACT.md §5 (hairline zoning) and
 * §6. 1px `--line` border, zero radius, no elevation shadow, with an optional
 * silk-screen header row (`.lbl` plus a right-aligned slot) separated from the
 * body by a hairline. The workhorse container for every admin surface.
 */
export type PanelProps = {
  /** Silk-screen caption for the header row. Omit for a bare zone. */
  label?: string | undefined
  /** Right-aligned header slot — controls, LEDs, a readout. */
  action?: ReactNode
  children: ReactNode
  className?: string | undefined
  /** Escape hatch for panels whose body sets its own padding (grids, tables). */
  bodyClassName?: string | undefined
}

export function Panel({ label, action, children, className, bodyClassName }: PanelProps) {
  const hasHead = label !== undefined || action !== undefined

  return (
    <section className={cn('panel', className)}>
      {hasHead ? (
        <div className="panel-head">
          {label === undefined ? <span /> : <Label>{label}</Label>}
          {action === undefined ? null : <div className="panel-head-slot">{action}</div>}
        </div>
      ) : null}
      <div className={cn('panel-body', bodyClassName)}>{children}</div>
    </section>
  )
}
