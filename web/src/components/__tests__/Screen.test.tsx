import { afterEach, describe, expect, it } from 'bun:test'
import { render, screen } from '@testing-library/react'
import { SCREEN_BG, SCREEN_BORDER } from '@/styles/screen-constants'
import { Readout, Screen } from '../Screen'

/**
 * Colours are compared across themes rather than against a literal string.
 * How a DOM serializes an inline colour is its own business — jsdom rewrote
 * `#06121f` as `rgb(6, 18, 31)` and happy-dom hands back what was authored —
 * and pinning one spelling tests the engine, not the component. What §4
 * actually promises is that the value does not move when the theme does, and
 * that it is the sanctioned constant; both are asserted without caring how it
 * is written.
 */
function colorsOf(surface: HTMLElement): { background: string; border: string } {
  const computed = window.getComputedStyle(surface)
  return { background: computed.backgroundColor, border: computed.borderColor }
}

afterEach(() => {
  document.documentElement.removeAttribute('data-theme')
})

describe('Screen', () => {
  it('pins the AESTHETIC_CONTRACT §4 constants', () => {
    expect(SCREEN_BG).toBe('#06121f')
    expect(SCREEN_BORDER).toBe('#0a3252')
  })

  it('does not change with data-theme', () => {
    const { container } = render(<Screen>lit</Screen>)
    const surface = container.querySelector<HTMLElement>('.screen')
    expect(surface).not.toBeNull()
    if (surface === null) return

    document.documentElement.setAttribute('data-theme', 'dark')
    const dark = colorsOf(surface)

    document.documentElement.setAttribute('data-theme', 'light')
    const light = colorsOf(surface)

    expect(light).toEqual(dark)
    // And they are the §4 constants, not merely stable at some other value:
    // the inline style is what the component wrote, whatever the DOM's own
    // serialization of it.
    expect(surface.style.background).toBe(SCREEN_BG)
    expect(surface.style.borderColor).toBe(SCREEN_BORDER)
  })

  it('keeps a zero radius', () => {
    const { container } = render(<Screen>lit</Screen>)
    const surface = container.querySelector<HTMLElement>('.screen')

    expect(surface?.style.borderRadius).toBe('0px')
  })
})

describe('Readout', () => {
  it('renders a tabular-nums lit value with a mono unit suffix', () => {
    render(<Readout value="18:04:22" unit="utc" label="clock" />)
    const readout = screen.getByLabelText('clock')

    expect(readout).toHaveClass('readout', 'read')
    expect(readout).toHaveTextContent('18:04:22')
    expect(screen.getByText('utc')).toHaveClass('readout-unit')
  })

  it('lights blue by default and amber for alert values', () => {
    const { rerender } = render(<Readout value="04" label="v" />)
    expect(screen.getByLabelText('v').style.color).toBe('var(--screen-blue)')

    rerender(<Readout value="04" tone="amber" label="v" />)
    expect(screen.getByLabelText('v').style.color).toBe('var(--amber)')
  })

  it('omits the unit element when no unit is given', () => {
    const { container } = render(<Readout value="04" />)

    expect(container.querySelector('.readout-unit')).toBeNull()
  })
})
