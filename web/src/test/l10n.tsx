import { LocalizationProvider } from '@fluent/react'
import { type RenderResult, render } from '@testing-library/react'
import type { ReactNode } from 'react'
import { createLocalization } from '@/i18n'

/** Renders `ui` inside the real en-US Fluent bundle, as the app does. */
export function renderWithL10n(ui: ReactNode): RenderResult {
  return render(
    <LocalizationProvider l10n={createLocalization(['en-US'])}>{ui}</LocalizationProvider>,
  )
}
