import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { Button, ButtonGroup } from '../Button'

describe('Button', () => {
  it('renders the .btn caption control and defaults to a non-submitting type', () => {
    render(<Button>commit</Button>)
    const button = screen.getByRole('button', { name: 'commit' })

    expect(button).toHaveClass('btn')
    expect(button).not.toHaveClass('primary')
    expect(button).toHaveAttribute('type', 'button')
  })

  it('applies the primary variant', () => {
    render(<Button variant="primary">commit</Button>)

    expect(screen.getByRole('button', { name: 'commit' })).toHaveClass('btn', 'primary')
  })

  it('honors an explicit submit type', () => {
    render(<Button type="submit">commit</Button>)

    expect(screen.getByRole('button', { name: 'commit' })).toHaveAttribute('type', 'submit')
  })

  it('is keyboard operable and blocks activation when disabled', async () => {
    const onClick = vi.fn()
    render(
      <>
        <Button onClick={onClick}>go</Button>
        <Button onClick={onClick} disabled>
          stop
        </Button>
      </>,
    )

    const go = screen.getByRole('button', { name: 'go' })
    go.focus()
    expect(go).toHaveFocus()
    await userEvent.keyboard('{Enter}')
    expect(onClick).toHaveBeenCalledTimes(1)

    await userEvent.click(screen.getByRole('button', { name: 'stop' }))
    expect(onClick).toHaveBeenCalledTimes(1)
  })
})

describe('ButtonGroup', () => {
  it('groups adjacent buttons under an accessible name', () => {
    render(
      <ButtonGroup label="transport">
        <Button>play</Button>
        <Button>stop</Button>
      </ButtonGroup>,
    )

    const group = screen.getByRole('group', { name: 'transport' })
    expect(group).toHaveClass('btngroup')
    expect(group.querySelectorAll('.btn')).toHaveLength(2)
  })
})
