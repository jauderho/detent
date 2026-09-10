import { Children, type CSSProperties, createContext, type ReactNode, useContext } from 'react'
import { cn } from '@/lib/utils'

/**
 * The zoned grid of AESTHETIC_CONTRACT.md §5: cells separated by 1px borders,
 * the last column's `border-right` and the last row's `border-bottom` stripped,
 * `:hover` shifting to `--panel` and never to a new hue.
 *
 * The declared column count reaches CSS as the `--cols` custom property rather
 * than as `grid-template-columns`, so the §5 reflow media queries (multi-column
 * → 2-up → 1-up) can still override it; the `is-last-col` / `is-last-row`
 * classes below are likewise re-derived in CSS at each breakpoint.
 */
type GridPosition = {
  index: number
  columns: number
  total: number
}

const GridPositionContext = createContext<GridPosition | null>(null)

export type HairlineGridProps = {
  /** Columns at the widest breakpoint. Reflows to 2-up then 1-up. */
  columns: number
  children: ReactNode
  className?: string | undefined
}

export function HairlineGrid({ columns, children, className }: HairlineGridProps) {
  const items = Children.toArray(children)
  const safeColumns = Math.max(1, Math.floor(columns))
  const style = { '--cols': String(safeColumns) } as CSSProperties

  return (
    <div className={cn('hgrid', className)} style={style}>
      {items.map((child, index) => (
        <GridPositionContext.Provider
          // Children.toArray assigns stable keys derived from each child's own
          // key or position; index is the only identity a positional cell has.
          key={`cell-${index.toString()}`}
          value={{ index, columns: safeColumns, total: items.length }}
        >
          {child}
        </GridPositionContext.Provider>
      ))}
    </div>
  )
}

export type GridCellProps = {
  children: ReactNode
  className?: string | undefined
}

export function GridCell({ children, className }: GridCellProps) {
  const position = useContext(GridPositionContext)
  const isLastCol =
    position === null ||
    (position.index + 1) % position.columns === 0 ||
    position.index === position.total - 1
  const isLastRow =
    position === null ||
    Math.floor(position.index / position.columns) ===
      Math.ceil(position.total / position.columns) - 1

  return (
    <div className={cn('cell', isLastCol && 'is-last-col', isLastRow && 'is-last-row', className)}>
      {children}
    </div>
  )
}
