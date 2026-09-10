import '@fontsource/ibm-plex-mono/300.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'
import '@fontsource/ibm-plex-mono/600.css'
import '@fontsource-variable/archivo/standard.css'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router'
import App from './App.tsx'
import { ApiProvider } from './api/ApiProvider'
import { PendingCommitProvider } from './app/PendingCommit'
import { AuthProvider } from './auth/AuthProvider'
import { AppLocalizationProvider } from './i18n'
import './index.css'

const rootEl = document.getElementById('root')
if (!rootEl) {
  throw new Error('#root element not found')
}

// Order matters. `ApiProvider` owns the one `ApiClient` — the CSRF token lives
// in its closure, so a second instance would issue mutations without one — and
// the `QueryClient` the session cache sits in, so `AuthProvider` must be
// inside it. `AuthProvider` is inside the router because the guard it feeds
// navigates.
createRoot(rootEl).render(
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
