/**
 * The not-found page.
 *
 * Every section has its own file — see `AppRoutes`.
 */

import { Localized, useLocalization } from '@fluent/react'
import { Link } from 'react-router'
import { Panel } from '@/components/Panel'
import { ROUTES } from './paths'

const SECTION_STYLE = { paddingTop: 24, paddingBottom: 24 } as const

export function NotFoundPage() {
  const { l10n } = useLocalization()
  return (
    <section className="wrap" style={SECTION_STYLE}>
      <Panel label={l10n.getString('page-not-found-title')}>
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
      </Panel>
    </section>
  )
}
