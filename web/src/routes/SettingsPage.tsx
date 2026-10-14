/**
 * Settings for the signed-in account. Today that is the second factor only;
 * user and token management have no endpoints yet (docs/API.md).
 */

import { useLocalization } from '@fluent/react'
import { TotpPanel } from './TotpPanel'

const PAGE_STYLE = { paddingTop: 24, paddingBottom: 24 } as const

const TITLE_STYLE = {
  fontFamily: '"Archivo Variable", "Archivo", sans-serif',
  fontWeight: 700,
  fontSize: 22,
  letterSpacing: '-0.02em',
  marginBottom: 16,
} as const

export function SettingsPage() {
  const { l10n } = useLocalization()
  return (
    <section className="wrap" style={PAGE_STYLE}>
      <h1 style={TITLE_STYLE}>{l10n.getString('page-settings-title')}</h1>
      <TotpPanel />
    </section>
  )
}
