/**
 * Puts one `ApiClient` and one `QueryClient` in context for the whole app.
 *
 * One client instance per app matters: the CSRF token lives inside its
 * closure, so a second instance would issue mutations without one.
 */

import type { QueryClient } from '@tanstack/react-query'
import { QueryClientProvider } from '@tanstack/react-query'
import { createContext, type ReactNode, useContext, useState } from 'react'
import { type ApiClient, createApiClient } from './client'
import { createQueryClient } from './queryClient'

const ApiClientContext = createContext<ApiClient | null>(null)

export type ApiProviderProps = {
  children: ReactNode
  /** Injected by tests; the app builds its own. */
  client?: ApiClient | undefined
  queryClient?: QueryClient | undefined
}

export function ApiProvider({ children, client, queryClient }: ApiProviderProps) {
  const [ownClient] = useState(() => client ?? createApiClient())
  const [ownQueryClient] = useState(() => queryClient ?? createQueryClient())

  return (
    <ApiClientContext.Provider value={client ?? ownClient}>
      <QueryClientProvider client={queryClient ?? ownQueryClient}>{children}</QueryClientProvider>
    </ApiClientContext.Provider>
  )
}

export function useApiClient(): ApiClient {
  const client = useContext(ApiClientContext)
  if (client === null) {
    throw new Error('useApiClient must be used inside <ApiProvider>')
  }
  return client
}
