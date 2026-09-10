import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TinyButton } from '../TinyButton'

describe('TinyButton', () => {
  it('renders the 9px module control unlit by default', () => {
    render(<TinyButton>clr</TinyButton>)
    const button = screen.getByRole('button', { name: 'clr' })

    expect(button).toHaveClass('tinybtn')
    expect(button).not.toHaveClass('on')
    expect(button).toHaveAttribute('type', 'button')
  })

  it('exposes the lit state as aria-pressed', () => {
    render(<TinyButton on>rec</TinyButton>)
    const button = screen.getByRole('button', { name: 'rec', pressed: true })

    expect(button).toHaveClass('tinybtn', 'on')
  })

  it('fires onClick from the keyboard', async () => {
    const onClick = vi.fn()
    render(<TinyButton onClick={onClick}>rnd</TinyButton>)

    screen.getByRole('button', { name: 'rnd' }).focus()
    await userEvent.keyboard(' ')

    expect(onClick).toHaveBeenCalledTimes(1)
  })
})
