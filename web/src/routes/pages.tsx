/**
 * The routed sections that are still placeholders, plus the not-found page.
 *
 * Settings stays a named placeholder: it needs the user- and token-management
 * endpoints `docs/API.md` does not describe. Certificates graduated to its own
 * `CertificatesPage` once `GET /api/v1/system/cert` landed. A placeholder that
 * says so is honest; a page built against an endpoint that does not exist is
 * not.
 *
 * Every other section now has its own file — see `AppRoutes`.
 */

import { Localized, useLocalization } from '@fluent/react'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { Panel } from '@/components/Panel'
import { ROUTES } from './paths'

const SECTION_STYLE = { paddingTop: 24, paddingBottom: 24 } as const

function Section({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section className="wrap" style={SECTION_STYLE}>
      <Panel label={label}>{children}</Panel>
    </section>
  )
}

function Placeholder({ label }: { label: string }) {
  return (
    <Section label={label}>
      <Localized id="page-placeholder-body">
        <p>this section is not built yet.</p>
      </Localized>
    </Section>
  )
}

export function CertificatesPage() {
  const { l10n } = useLocalization()
  return <Placeholder label={l10n.getString('page-certificates-title')} />
}

export function SettingsPage() {
  const { l10n } = useLocalization()
  return <Placeholder label={l10n.getString('page-settings-title')} />
}

export function NotFoundPage() {
  const { l10n } = useLocalization()
  return (
    <Section label={l10n.getString('page-not-found-title')}>
      <Localized id="page-not-found-body">
        <p>that address does not name anything in this console.</p>
      </Localized>
      <p style={{ marginTop: 12 }}>
        <Link className="btn" to={ROUTES.dashboard}>
          <Localized id="page-not-found-home">
            <span>go to the dashboard</span>
          </Localized>
        </Link>
      </p>
    </Section>
  )
}
