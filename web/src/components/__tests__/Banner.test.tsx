import { describe, expect, it } from 'bun:test'
import { render, screen } from '@testing-library/react'
import { Banner } from '../Banner'
import { Button } from '../Button'

describe('Banner', () => {
  it('announces the amber tone as an alert with a blinking amber LED', () => {
    const { container } = render(<Banner tone="amber">pending commit</Banner>)
    const banner = screen.getByRole('alert')

    expect(banner).toHaveClass('banner', 'amber')
    expect(banner).toHaveTextContent('pending commit')
    expect(container.querySelector('.animate-led-blink')).not.toBeNull()
  })

  it('announces the blue tone as a passive status', () => {
    const { container } = render(<Banner tone="blue">update available</Banner>)
    const banner = screen.getByRole('status')

    expect(banner).toHaveClass('banner', 'blue')
    expect(container.querySelector('.animate-led-blink')).toBeNull()
  })

  it('renders the actions slot only when supplied', () => {
    const { container, rerender } = render(<Banner tone="amber">pending commit</Banner>)
    expect(container.querySelector('.banner-actions')).toBeNull()

    rerender(
      <Banner tone="amber" actions={<Button variant="primary">commit</Button>}>
        pending commit
      </Banner>,
    )
    expect(screen.getByRole('button', { name: 'commit' })).toBeInTheDocument()
    expect(container.querySelector('.banner-actions')).not.toBeNull()
  })
})
