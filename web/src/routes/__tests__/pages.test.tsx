/**
 * The not-found page.
 */

import { describe, expect, it } from 'bun:test'
import { screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { renderWithL10n } from '@/test/l10n'
import { NotFoundPage } from '../pages'
import { ROUTES } from '../paths'

describe('NotFoundPage', () => {
  it('says the address names nothing and links to the dashboard', () => {
    renderWithL10n(
      <MemoryRouter>
        <NotFoundPage />
      </MemoryRouter>,
    )
    expect(screen.getByText('no such page')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'go to the dashboard' })).toHaveAttribute(
      'href',
      ROUTES.dashboard,
    )
  })
})
