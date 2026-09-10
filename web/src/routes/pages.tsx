/**
 * The routed sections, as named placeholders.
 *
 * Each one exists so the router, the guard and the nav can be exercised end to
 * end before the sections themselves land; each is a hairline `Panel`
 * (AESTHETIC_CONTRACT.md §5/§6) carrying its own silk-screen caption and
 * nothing else. A later wave replaces the body, not the route.
 */

import { Localized, useLocalization } from '@fluent/react'
import type { ReactNode } from 'react'
import { Link, useParams } from 'react-router'
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

export function DashboardPage() {
  const { l10n } = useLocalization()
  return <Placeholder label={l10n.getString('page-dashboard-title')} />
}

export function ModulesPage() {
  const { l10n } = useLocalization()
  return <Placeholder label={l10n.getString('page-modules-title')} />
}

export function ModuleDetailPage() {
  const { l10n } = useLocalization()
  const params = useParams()
  const id = params.id
  if (id === undefined) {
    return <NotFoundPage />
  }
  return <Placeholder label={l10n.getString('page-module-detail-title', { module: id })} />
}

export function ServicesPage() {
  const { l10n } = useLocalization()
  return <Placeholder label={l10n.getString('page-services-title')} />
}

export function BackupsPage() {
  const { l10n } = useLocalization()
  return <Placeholder label={l10n.getString('page-backups-title')} />
}

export function AuditPage() {
  const { l10n } = useLocalization()
  return <Placeholder label={l10n.getString('page-audit-title')} />
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
