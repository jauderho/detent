import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { SCREEN_BG, SCREEN_BORDER } from '@/styles/screen-constants'
import { Readout, Screen } from '../Screen'

const SCREEN_BG_RGB = 'rgb(6, 18, 31)'
const SCREEN_BORDER_RGB = 'rgb(10, 50, 82)'

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
    const dark = window.getComputedStyle(surface)
    expect(dark.backgroundColor).toBe(SCREEN_BG_RGB)
    expect(dark.borderColor).toBe(SCREEN_BORDER_RGB)

    document.documentElement.setAttribute('data-theme', 'light')
    const light = window.getComputedStyle(surface)
    expect(light.backgroundColor).toBe(SCREEN_BG_RGB)
    expect(light.borderColor).toBe(SCREEN_BORDER_RGB)
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
