import { useLocalization } from '@fluent/react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

/**
 * A hairline-zoned table — AESTHETIC_CONTRACT.md §5 (hairline zoning, rows
 * hover to `--panel` and never to a new hue) and §6. Column headers are
 * silk-screen `.lbl` captions; numeric columns are right-aligned and carry
 * `tabular-nums`, per the §1 non-negotiable.
 *
 * Generic over the row type — the caller owns formatting, so every cell value
 * arrives already localized.
 */
export type DataTableColumn<Row> = {
  /** Stable column identity; also the React key. */
  key: string
  /** Localized header text. */
  header: string
  /** Right-aligns and applies `tabular-nums`. */
  numeric?: boolean | undefined
  render: (row: Row) => ReactNode
}

export type DataTableProps<Row> = {
  columns: readonly DataTableColumn<Row>[]
  rows: readonly Row[]
  getRowKey: (row: Row) => string
  /** Visible caption, doubling as the table's accessible name. */
  caption?: string | undefined
  /** Shown instead of rows when `rows` is empty. Defaults to a generic string. */
  emptyMessage?: string | undefined
  className?: string | undefined
}

export function DataTable<Row>({
  columns,
  rows,
  getRowKey,
  caption,
  emptyMessage,
  className,
}: DataTableProps<Row>) {
  const { l10n } = useLocalization()

  return (
    <table className={cn('dtable', className)}>
      {caption === undefined ? null : <caption className="lbl">{caption}</caption>}
      <thead>
        <tr>
          {columns.map((column) => (
            <th
              key={column.key}
              scope="col"
              className={cn('lbl', column.numeric === true && 'num')}
            >
              {column.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.length === 0 ? (
          <tr>
            <td className="empty" colSpan={columns.length}>
              {emptyMessage ?? l10n.getString('component-table-empty')}
            </td>
          </tr>
        ) : (
          rows.map((row) => (
            <tr key={getRowKey(row)}>
              {columns.map((column) => (
                <td key={column.key} className={cn(column.numeric === true && 'num')}>
                  {column.render(row)}
                </td>
              ))}
            </tr>
          ))
        )}
      </tbody>
    </table>
  )
}
