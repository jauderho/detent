/**
 * The app shell: status bar, section strip, the pending-commit slot, and
 * whatever the router resolved beneath them.
 *
 * Everything with an opinion lives elsewhere — the providers are wired in
 * `main.tsx`, the addresses in `routes/paths.ts`, the guard in
 * `routes/RequireAuth.tsx`. This file is the layout and nothing else.
 */

import { PendingCommitSlot } from './app/PendingCommit'
import { StatusBar } from './components/StatusBar'
import { AppNav } from './routes/AppNav'
import { AppRoutes } from './routes/AppRoutes'

function App() {
  return (
    <>
      <StatusBar />
      <AppNav />
      <PendingCommitSlot />
      <main>
        <AppRoutes />
      </main>
    </>
  )
}

export default App
