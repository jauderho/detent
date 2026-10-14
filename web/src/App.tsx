/**
 * The app shell: status bar, section strip, the pending-commit slot, and
 * whatever the router resolved beneath them.
 *
 * Everything with an opinion lives elsewhere — the providers are wired in
 * `main.tsx`, the addresses in `routes/paths.ts`, the guard in
 * `routes/RequireAuth.tsx`. This file is the layout and nothing else.
 */

import { useLocalization } from '@fluent/react'
import { CredentialNotices } from './app/CredentialNotices'
import { PendingCommitSlot } from './app/PendingCommit'
import { StatusBar } from './components/StatusBar'
import { AppNav } from './routes/AppNav'
import { AppRoutes } from './routes/AppRoutes'

/** The `<main>` landmark the skip link moves focus to. */
const MAIN_ID = 'main'

function App() {
  const { l10n } = useLocalization()

  return (
    <>
      {/* First focusable element (WCAG 2.4.1). Focus is moved by script rather
          than by the fragment so the address bar and the router stay put. */}
      <a
        className="btn primary skip-link"
        href={`#${MAIN_ID}`}
        onClick={(event) => {
          event.preventDefault()
          document.getElementById(MAIN_ID)?.focus()
        }}
      >
        {l10n.getString('status-skip-link')}
      </a>
      <StatusBar />
      <AppNav />
      <PendingCommitSlot />
      <CredentialNotices />
      <main id={MAIN_ID} tabIndex={-1}>
        <AppRoutes />
      </main>
    </>
  )
}

export default App
