import { screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { renderWithL10n } from '@/test/l10n'
import { DataTable, type DataTableColumn } from '../DataTable'

type Service = {
  id: string
  name: string
  restarts: number
}

const COLUMNS: readonly DataTableColumn<Service>[] = [
  { key: 'name', header: 'service', render: (row) => row.name },
  { key: 'restarts', header: 'restarts', numeric: true, render: (row) => String(row.restarts) },
]

const ROWS: readonly Service[] = [
  { id: 'a', name: 'chrony', restarts: 0 },
  { id: 'b', name: 'resolved', restarts: 12 },
]

function renderTable(rows: readonly Service[], emptyMessage?: string) {
  return renderWithL10n(
    <DataTable
      columns={COLUMNS}
      rows={rows}
      getRowKey={(row) => row.id}
      caption="services"
      emptyMessage={emptyMessage}
    />,
  )
}

describe('DataTable', () => {
  it('renders silk-screen column headers scoped to their column', () => {
    renderTable(ROWS)
    const header = screen.getByRole('columnheader', { name: 'service' })

    expect(header).toHaveClass('lbl')
    expect(header).toHaveAttribute('scope', 'col')
  })

  it('marks numeric columns for tabular-nums alignment', () => {
    renderTable(ROWS)

    expect(screen.getByRole('columnheader', { name: 'restarts' })).toHaveClass('num')
    expect(screen.getByRole('cell', { name: '12' })).toHaveClass('num')
    expect(screen.getByRole('cell', { name: 'chrony' })).not.toHaveClass('num')
  })

  it('renders one row per record via the caller-supplied renderers', () => {
    renderTable(ROWS)
    const body = screen.getAllByRole('rowgroup')[1]
    expect(body).toBeDefined()
    if (body === undefined) return

    expect(within(body).getAllByRole('row')).toHaveLength(2)
    expect(screen.getByRole('table', { name: 'services' })).toBeInTheDocument()
  })

  it('falls back to the localized empty state', () => {
    renderTable([])

    const empty = screen.getByRole('cell', { name: 'no records' })
    expect(empty).toHaveClass('empty')
    expect(empty).toHaveAttribute('colspan', '2')
  })

  it('prefers a caller-supplied empty message', () => {
    renderTable([], 'no services configured')

    expect(screen.getByText('no services configured')).toBeInTheDocument()
  })
})
