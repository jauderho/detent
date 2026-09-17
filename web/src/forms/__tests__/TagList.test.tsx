import { describe, expect, it, mock } from 'bun:test'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithL10n } from '@/test/l10n'
import { TagList } from '../TagList'

describe('TagList', () => {
  it('renders the description and error text when provided', () => {
    renderWithL10n(
      <TagList
        label="tags"
        items={['a']}
        description="A helpful note"
        error="Something went wrong"
        onChange={mock()}
      />,
    )

    expect(screen.getByText('A helpful note')).toBeInTheDocument()
    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    expect(
      screen.getByRole('textbox', {
        name: (name) => name.replace(/[\u2068\u2069]/g, '') === 'tags item 1',
      }),
    ).toHaveAttribute('aria-invalid', 'true')
  })

  it('moves an item down in place', async () => {
    const onChange = mock()
    renderWithL10n(<TagList label="tags" items={['a', 'b']} onChange={onChange} />)

    await userEvent.click(
      screen.getByRole('button', {
        name: (name) => name.replace(/[\u2068\u2069]/g, '') === 'move tags item 1 down',
      }),
    )
    expect(onChange).toHaveBeenLastCalledWith(['b', 'a'])
  })
})
