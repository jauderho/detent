import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { GridCell, HairlineGrid } from '../HairlineGrid'

function renderGrid(columns: number, count: number) {
  const { container } = render(
    <HairlineGrid columns={columns}>
      {Array.from({ length: count }, (_unused, index) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: fixed-length positional fixture.
        <GridCell key={index}>{String(index)}</GridCell>
      ))}
    </HairlineGrid>,
  )
  return Array.from(container.querySelectorAll<HTMLElement>('.hgrid > .cell'))
}

describe('HairlineGrid', () => {
  it('strips border-right only on the last column', () => {
    const cells = renderGrid(3, 6)
    const lastCol = cells.map((cell) => cell.classList.contains('is-last-col'))

    expect(lastCol).toEqual([false, false, true, false, false, true])
  })

  it('strips border-bottom only on the last row', () => {
    const cells = renderGrid(3, 6)
    const lastRow = cells.map((cell) => cell.classList.contains('is-last-row'))

    expect(lastRow).toEqual([false, false, false, true, true, true])
  })

  it('treats a trailing partial row as both last column and last row', () => {
    const cells = renderGrid(3, 5)

    expect(cells[2]?.classList.contains('is-last-col')).toBe(true)
    // index 4 ends the grid without ending a column, but nothing sits to its
    // right, so its border-right is stripped too.
    expect(cells[4]?.classList.contains('is-last-col')).toBe(true)
    expect(cells[3]?.classList.contains('is-last-col')).toBe(false)
    expect(cells[3]?.classList.contains('is-last-row')).toBe(true)
    expect(cells[2]?.classList.contains('is-last-row')).toBe(false)
  })

  it('publishes the column count as --cols so the reflow media queries win', () => {
    const { container } = render(
      <HairlineGrid columns={4}>
        <GridCell>a</GridCell>
      </HairlineGrid>,
    )
    const grid = container.querySelector<HTMLElement>('.hgrid')

    expect(grid?.style.getPropertyValue('--cols')).toBe('4')
    expect(grid?.style.gridTemplateColumns).toBe('')
  })

  it('clamps a nonsensical column count to one', () => {
    const { container } = render(
      <HairlineGrid columns={0}>
        <GridCell>a</GridCell>
      </HairlineGrid>,
    )

    expect(container.querySelector<HTMLElement>('.hgrid')?.style.getPropertyValue('--cols')).toBe(
      '1',
    )
  })

  it('marks a standalone cell as last column and last row', () => {
    const { container } = render(<GridCell>orphan</GridCell>)
    const cell = container.querySelector<HTMLElement>('.cell')

    expect(cell?.classList.contains('is-last-col')).toBe(true)
    expect(cell?.classList.contains('is-last-row')).toBe(true)
  })
})
