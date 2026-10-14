import { describe, expect, it } from 'bun:test'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithL10n } from '@/test/l10n'
import { PasswordField } from '../PasswordField'

describe('PasswordField', () => {
  it('masks the value until the reveal toggle is pressed, and masks it again', async () => {
    const user = userEvent.setup()
    renderWithL10n(<PasswordField label="secret" name="secret" defaultValue="hunter2" />)
    const input = screen.getByLabelText('secret')
    const toggle = screen.getByRole('button', { name: 'show password' })

    expect(input).toHaveAttribute('type', 'password')
    expect(toggle).toHaveAttribute('aria-pressed', 'false')

    await user.click(toggle)
    expect(input).toHaveAttribute('type', 'text')
    expect(toggle).toHaveAttribute('aria-pressed', 'true')

    await user.click(toggle)
    expect(input).toHaveAttribute('type', 'password')
    expect(toggle).toHaveAttribute('aria-pressed', 'false')
  })

  it('is reachable and operable from the keyboard', async () => {
    const user = userEvent.setup()
    renderWithL10n(<PasswordField label="secret" name="secret" />)
    await user.tab()
    await user.tab()
    const toggle = screen.getByRole('button', { name: 'show password' })
    expect(toggle).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(screen.getByLabelText('secret')).toHaveAttribute('type', 'text')
  })
})
