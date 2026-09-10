import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Panel } from '../Panel'

describe('Panel', () => {
  it('renders a silk-screen header with the right-aligned action slot', () => {
    render(
      <Panel label="services" action={<span data-testid="slot">04</span>}>
        <p>body</p>
      </Panel>,
    )

    const label = screen.getByText('services')
    expect(label).toHaveClass('lbl')
    expect(screen.getByTestId('slot')).toBeInTheDocument()
    expect(screen.getByText('body')).toBeInTheDocument()
  })

  it('omits the header row entirely when neither label nor action is given', () => {
    const { container } = render(<Panel>body</Panel>)

    expect(container.querySelector('.panel-head')).toBeNull()
    expect(container.querySelector('.panel-body')).not.toBeNull()
  })

  it('renders a header when only an action is supplied', () => {
    const { container } = render(<Panel action={<button type="button">go</button>}>body</Panel>)

    expect(container.querySelector('.panel-head')).not.toBeNull()
  })
})
