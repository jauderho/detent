import '@fontsource/ibm-plex-mono/300.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'
import '@fontsource/ibm-plex-mono/600.css'
import '@fontsource-variable/archivo/standard.css'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import { AppLocalizationProvider } from './i18n'
import './index.css'

const rootEl = document.getElementById('root')
if (!rootEl) {
  throw new Error('#root element not found')
}

createRoot(rootEl).render(
  <StrictMode>
    <AppLocalizationProvider>
      <App />
    </AppLocalizationProvider>
  </StrictMode>,
)
