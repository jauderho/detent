/**
 * The dashboard's `CertPanel` is the same data in miniature — three readouts
 * plus its own banner. Both import the tone rule from `@/lib/cert` so the two
 * can never disagree about whether the certificate is expiring: same report,
 * same 30-day/expired threshold, same amber banner.
 */

import { Localized, useLocalization } from '@fluent/react'
import { useApiErrorMessage } from '@/api/query'
import type { CertReport } from '@/api/system'
import { useCert } from '@/api/system'
import { Banner } from '@/components/Banner'
import { GridCell, HairlineGrid } from '@/components/HairlineGrid'
import { Label } from '@/components/Label'
import { Panel } from '@/components/Panel'
import { Readout, Screen } from '@/components/Screen'
import { certExpired, certGridItems, certTone, certWarning } from '@/lib/cert'

const PAGE_STYLE = { paddingTop: 24, paddingBottom: 24 } as const

const TITLE_STYLE = {
  fontFamily: '"Archivo Variable", "Archivo", sans-serif',
  fontWeight: 700,
  fontSize: 22,
  letterSpacing: '-0.02em',
  marginBottom: 16,
} as const

function CertGrid({ report }: { report: CertReport }) {
  const { l10n } = useLocalization()
  const [fingerprint, expires, used] = certGridItems(l10n, report)
  const expired = certExpired(report)
  const warning = certWarning(report)
  const tone = certTone(report)
  return (
    <>
      <HairlineGrid columns={3}>
        <GridCell>
          <Label>{l10n.getString('dashboard-cert-fingerprint')}</Label>
          <Screen>
            {/* Host text, never localized — verbatim so case survives. */}
            <span className="verbatim" style={{ wordBreak: 'break-all' }}>
              <Readout value={fingerprint} tone={tone} />
            </span>
          </Screen>
        </GridCell>
        <GridCell>
          <Label>{l10n.getString('dashboard-cert-expires')}</Label>
          <Screen>
            <Readout value={expires} tone={tone} />
          </Screen>
        </GridCell>
        <GridCell>
          <Label>{l10n.getString('dashboard-cert-lifetime-used')}</Label>
          <Screen>
            <Readout value={used} tone={tone} />
          </Screen>
        </GridCell>
      </HairlineGrid>
      {expired ? (
        <Banner tone="amber">{l10n.getString('dashboard-cert-expired')}</Banner>
      ) : warning === 'quarter' ? (
        <Banner tone="amber">{l10n.getString('dashboard-cert-quarter')}</Banner>
      ) : warning === 'half' ? (
        <Banner tone="amber">{l10n.getString('dashboard-cert-half')}</Banner>
      ) : tone === 'amber' ? (
        <Banner tone="amber">{l10n.getString('dashboard-cert-expiring-soon')}</Banner>
      ) : null}
    </>
  )
}

export function CertificatesPage() {
  const { l10n } = useLocalization()
  const query = useCert()
  const errorMessage = useApiErrorMessage()

  return (
    <section className="wrap" style={PAGE_STYLE}>
      <h1 style={TITLE_STYLE}>
        <Localized id="page-certificates-title">
          <span>certificates</span>
        </Localized>
      </h1>
      <Panel label={l10n.getString('dashboard-cert-panel')}>
        {query.isPending ? (
          <Localized id="state-loading">
            <p>loading</p>
          </Localized>
        ) : query.isError ? (
          <Banner tone="amber">{errorMessage(query.error)}</Banner>
        ) : (
          <CertGrid report={query.data} />
        )}
      </Panel>
    </section>
  )
}
