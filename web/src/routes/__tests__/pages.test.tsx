/**
 * Placeholder pages for sections that are not built yet.
 */

import { describe, expect, it } from 'bun:test'
import { screen } from '@testing-library/react'
import { renderWithL10n } from '@/test/l10n'
import { CertificatesPage, SettingsPage } from '../pages'

describe('placeholder pages', () => {
  it('renders the certificates placeholder', () => {
    renderWithL10n(<CertificatesPage />)
    expect(screen.getByText('certificates')).toBeInTheDocument()
    expect(screen.getByText('this section is not built yet.')).toBeInTheDocument()
  })

  it('renders the settings placeholder', () => {
    renderWithL10n(<SettingsPage />)
    expect(screen.getByText('settings')).toBeInTheDocument()
    expect(screen.getByText('this section is not built yet.')).toBeInTheDocument()
  })
})
