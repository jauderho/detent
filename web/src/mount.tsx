/**
 * Mounts the console into `rootEl`, with the provider order `main.tsx` owns.
 *
 * The order matters and lives here so both the entrypoint and the test suite
 * share it: `ApiProvider` owns the one `ApiClient` — the CSRF token lives in
 * its closure, so a second instance would issue mutations without one — and
 * the `QueryClient` the session cache sits in, so `AuthProvider` must be
 * inside it. `AuthProvider` is inside the router because the guard it feeds
 * navigates.
 *
 * `main.tsx` calls this once with `#root`; the test suite calls it with its
 * own fixtures. A null element throws — the console has nowhere to mount, so
 * failing loudly beats rendering into nothing.
 */

import { StrictMode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { BrowserRouter } from 'react-router'
import App from './App.tsx'
import { ApiProvider } from './api/ApiProvider'
import { PendingCommitProvider } from './app/PendingCommit'
import { AuthProvider } from './auth/AuthProvider'
import { AppLocalizationProvider } from './i18n'

export function mountApp(rootEl: HTMLElement | null): Root {
  if (!rootEl) {
    throw new Error('#root element not found')
  }
  const root = createRoot(rootEl)
  root.render(
    <StrictMode>
      <AppLocalizationProvider>
        <ApiProvider>
          <BrowserRouter>
            <AuthProvider>
              <PendingCommitProvider>
                <App />
              </PendingCommitProvider>
            </AuthProvider>
          </BrowserRouter>
        </ApiProvider>
      </AppLocalizationProvider>
    </StrictMode>,
  )
  return root
}
