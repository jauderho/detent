import { describe, expect, it } from 'bun:test'
import { LocalizationProvider } from '@fluent/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { NOTICES_QUERY_KEY, type Notices } from '@/api/auth'
import { createQueryClient } from '@/api/queryClient'
import { createLocalization } from '@/i18n'
import { formatRfc3339 } from '@/lib/format'
import { CredentialNotices } from '../CredentialNotices'

/** Fluent wraps every placeable in bidi isolate marks (U+2068 / U+2069). */
const ISOLATES = /[\u2068\u2069]/g

function textOf(element: HTMLElement): string {
  return (element.textContent ?? '').replace(ISOLATES, '')
}

const SINCE = '2026-10-10T08:00:00Z'
const AT = '2026-10-11T09:30:00Z'

const QUIET: Notices = { since: SINCE, failed_sign_ins: 0, changes: [] }

function renderNotices(notices: Notices | null | undefined) {
  const queryClient = createQueryClient()
  if (notices !== undefined) queryClient.setQueryData(NOTICES_QUERY_KEY, notices)
  const view = render(
    <LocalizationProvider l10n={createLocalization(['en-US'])}>
      <QueryClientProvider client={queryClient}>
        <CredentialNotices />
      </QueryClientProvider>
    </LocalizationProvider>,
  )
  return { ...view, queryClient }
}

describe('CredentialNotices', () => {
  it('shows nothing before the notices are read, after dismissal, or when none apply', () => {
    for (const notices of [undefined, null, QUIET]) {
      const { container, unmount } = renderNotices(notices)
      expect(container).toBeEmptyDOMElement()
      unmount()
    }
  })

  it('lists each change with its time, source and address, as a polite status', () => {
    renderNotices({
      since: SINCE,
      failed_sign_ins: 0,
      changes: [
        { at: AT, change: 'password_changed', source: 'cli', client_ip: null },
        { at: AT, change: 'totp_enabled', source: 'session', client_ip: '198.51.100.9' },
        { at: AT, change: 'totp_disabled', source: 'session' },
        { at: AT, change: 'token_issued', source: 'cli' },
        { at: AT, change: 'token_revoked', source: 'cli' },
        { at: AT, change: 'something_new', source: 'cli' },
      ],
    })

    const banner = screen.getByRole('status')
    const time = formatRfc3339('en-US', AT) ?? ''
    expect(textOf(banner)).toContain(`since your last sign-in on ${formatRfc3339('en-US', SINCE)}:`)
    const items = within(banner).getAllByRole('listitem')
    expect(items.map(textOf)).toEqual([
      `password changed, ${time} (command line)`,
      `second factor turned on, ${time} (console, 198.51.100.9)`,
      `second factor turned off, ${time} (console)`,
      `api token issued, ${time} (command line)`,
      `api token revoked, ${time} (command line)`,
      `something_new, ${time} (command line)`,
    ])
  })

  it('states the refused sign-ins, with or without changes', () => {
    renderNotices({ since: SINCE, failed_sign_ins: 3, changes: [] })

    const banner = screen.getByRole('status')
    expect(textOf(banner)).toContain('refused sign-in attempts since then: 3')
    expect(within(banner).queryByRole('list')).toBeNull()
  })

  it('names an unparsable time as it came', () => {
    renderNotices({
      since: 'yesterday',
      failed_sign_ins: 1,
      changes: [],
    })

    expect(textOf(screen.getByRole('status'))).toContain('sign-in on yesterday:')
  })

  it('is dismissed from the keyboard and stays dismissed', async () => {
    const user = userEvent.setup()
    const { container, queryClient } = renderNotices({
      since: SINCE,
      failed_sign_ins: 2,
      changes: [],
    })

    await user.tab()
    expect(screen.getByRole('button', { name: 'dismiss' })).toHaveFocus()
    await user.keyboard('{Enter}')

    expect(container).toBeEmptyDOMElement()
    expect(queryClient.getQueryData(NOTICES_QUERY_KEY)).toBeNull()
  })
})
