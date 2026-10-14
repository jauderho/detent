/**
 * What changed on this account since the previous sign-in (ASVS 2.2.3, 2.5.5).
 *
 * `AuthProvider.login` reads `GET /api/v1/auth/notices` once and writes the
 * answer into the cache; this slot only shows it. There is no request here,
 * so a page reload does not bring a dismissed notice back, and an account with
 * nothing to report shows nothing at all. Dismissing writes `null` to the same
 * cache entry. The next sign-in drops the entry with the rest of the
 * per-account data.
 *
 * `blue` rather than `amber`: the banner is `role="status"` (polite), which
 * is what the owner asked for, and the strip is information the operator
 * checks against what they know they did.
 */

import { useLocalization } from '@fluent/react'
import { skipToken, useQuery, useQueryClient } from '@tanstack/react-query'
import { NOTICES_QUERY_KEY, type NoticeChange, type Notices } from '@/api/auth'
import { Banner } from '@/components/Banner'
import { Button } from '@/components/Button'
import { formatRfc3339, localeOf } from '@/lib/format'

const SLOT_STYLE = { paddingTop: 12 } as const
const LIST_STYLE = { margin: '6px 0 0', paddingLeft: 18 } as const

/** The unformatted value stands in for a time the browser cannot parse. */
function timeOf(locale: string, timestamp: string): string {
  return formatRfc3339(locale, timestamp) ?? timestamp
}

export function CredentialNotices() {
  const { l10n } = useLocalization()
  const queryClient = useQueryClient()
  const { data } = useQuery<Notices | null>({
    queryKey: NOTICES_QUERY_KEY,
    queryFn: skipToken,
    staleTime: Number.POSITIVE_INFINITY,
  })

  if (data === undefined || data === null) return null
  if (data.changes.length === 0 && data.failed_sign_ins === 0) return null

  const locale = localeOf(l10n)

  /** One line per change; the ids are literal so `i18n:check` can see them. */
  function describe(change: NoticeChange): string {
    const source =
      change.source === 'cli'
        ? l10n.getString('notices-source-cli')
        : l10n.getString('notices-source-session')
    return l10n.getString('notices-item', {
      change: kindText(change.change),
      time: timeOf(locale, change.at),
      // An address is data, not prose: it follows the source after a comma.
      source: change.client_ip == null ? source : `${source}, ${change.client_ip}`,
    })
  }

  /** A kind this build does not know stands as the server wrote it. */
  function kindText(kind: string): string {
    switch (kind) {
      case 'password_changed':
        return l10n.getString('notices-password-changed')
      case 'totp_enabled':
        return l10n.getString('notices-totp-enabled')
      case 'totp_disabled':
        return l10n.getString('notices-totp-disabled')
      case 'token_issued':
        return l10n.getString('notices-token-issued')
      case 'token_revoked':
        return l10n.getString('notices-token-revoked')
      default:
        return kind
    }
  }

  // The log can hold two identical changes in one second, so a row's key is
  // its position in the (fixed, newest-first) answer.
  const rows = data.changes.map((change, id) => ({ id, text: describe(change) }))

  return (
    <div className="wrap" style={SLOT_STYLE}>
      <Banner
        tone="blue"
        actions={
          <Button
            onClick={() => {
              queryClient.setQueryData<Notices | null>(NOTICES_QUERY_KEY, null)
            }}
          >
            {l10n.getString('notices-dismiss')}
          </Button>
        }
      >
        <div>{l10n.getString('notices-heading', { time: timeOf(locale, data.since ?? '') })}</div>
        {data.failed_sign_ins === 0 ? null : (
          <div>{l10n.getString('notices-failed', { count: data.failed_sign_ins })}</div>
        )}
        {rows.length === 0 ? null : (
          <ul style={LIST_STYLE}>
            {rows.map((row) => (
              <li key={row.id}>{row.text}</li>
            ))}
          </ul>
        )}
      </Banner>
    </div>
  )
}
