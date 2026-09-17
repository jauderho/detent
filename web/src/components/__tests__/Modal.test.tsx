import { describe, expect, it, mock } from 'bun:test'
import { fireEvent, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { renderWithL10n } from '@/test/l10n'
import { Button } from '../Button'
import { Modal } from '../Modal'

function Fixture() {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button
        onClick={() => {
          setOpen(true)
        }}
      >
        review
      </Button>
      <Modal
        open={open}
        onClose={() => {
          setOpen(false)
        }}
        title="pending diff"
        footer={<Button variant="primary">commit</Button>}
      >
        <Button>discard</Button>
      </Modal>
    </>
  )
}

describe('Modal', () => {
  it('carries the dialog role, modal flag and an accessible name', () => {
    renderWithL10n(
      <Modal open onClose={mock()} title="pending diff">
        body
      </Modal>,
    )
    const dialog = screen.getByRole('dialog', { name: 'pending diff' })

    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).toHaveClass('modal')
  })

  it('renders nothing while closed', () => {
    renderWithL10n(
      <Modal open={false} onClose={mock()} title="pending diff">
        body
      </Modal>,
    )

    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('moves focus to the first focusable control on open', () => {
    renderWithL10n(
      <Modal open onClose={mock()} title="pending diff">
        <Button>discard</Button>
      </Modal>,
    )

    expect(screen.getByRole('button', { name: 'close' })).toHaveFocus()
  })

  it('closes on Escape', async () => {
    const onClose = mock()
    renderWithL10n(
      <Modal open onClose={onClose} title="pending diff">
        <Button>discard</Button>
      </Modal>,
    )

    await userEvent.keyboard('{Escape}')

    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('traps Tab inside the dialog', () => {
    renderWithL10n(
      <Modal
        open
        onClose={mock()}
        title="pending diff"
        footer={<Button variant="primary">commit</Button>}
      >
        <Button>discard</Button>
      </Modal>,
    )

    const close = screen.getByRole('button', { name: 'close' })
    const commit = screen.getByRole('button', { name: 'commit' })
    const dialog = screen.getByRole('dialog')

    commit.focus()
    fireEvent.keyDown(dialog, { key: 'Tab' })
    expect(close).toHaveFocus()

    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true })
    expect(commit).toHaveFocus()
  })

  it('restores focus to the trigger when it closes', async () => {
    renderWithL10n(<Fixture />)
    const trigger = screen.getByRole('button', { name: 'review' })

    await userEvent.click(trigger)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'close' })).toHaveFocus()

    await userEvent.click(screen.getByRole('button', { name: 'close' }))

    expect(screen.queryByRole('dialog')).toBeNull()
    expect(trigger).toHaveFocus()
  })
})
