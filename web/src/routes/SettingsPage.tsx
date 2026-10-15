/**
 * Settings for the signed-in account: the second factor and the active
 * sessions. User and token management have no endpoints yet (docs/API.md).
 */

import { useLocalization } from '@fluent/react'
import { SessionsPanel } from './SessionsPanel'
import { TotpPanel } from './TotpPanel'

const PAGE_STYLE = { paddingTop: 24, paddingBottom: 24 } as const

const TITLE_STYLE = {
  fontFamily: '"Archivo Variable", "Archivo", sans-serif',
  fontWeight: 700,
  fontSize: 22,
  letterSpacing: '-0.02em',
  marginBottom: 16,
} as const

// `minmax(0, 1fr)`, not the implicit `auto` track: an `auto` track grows to its
// widest table and pushes the panel past the viewport.
const PANELS_STYLE = { display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: 16 } as const

export function SettingsPage() {
  const { l10n } = useLocalization()
  return (
    <section className="wrap" style={PAGE_STYLE}>
      <h1 style={TITLE_STYLE}>{l10n.getString('page-settings-title')}</h1>
      <div style={PANELS_STYLE}>
        <TotpPanel />
        <SessionsPanel />
      </div>
    </section>
  )
}
