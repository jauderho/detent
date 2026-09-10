/**
 * React Query defaults for an admin console.
 *
 * The console watches one host, not a feed. Refetching every panel the moment
 * a window regains focus would stampede a single small server for data that
 * changes when an operator changes it, so focus refetching is off and
 * staleness is measured in tens of seconds.
 *
 * Retries are off on purpose. `ApiClient` resolves expected failures instead
 * of throwing, so a retry could only ever repeat a request that already got a
 * definite answer — a `401` that must send the operator to the login screen,
 * or a `403` that will be refused again.
 */

import { QueryClient } from '@tanstack/react-query'

/** How long a fetched answer is served without going back to the host. */
export const DEFAULT_STALE_TIME_MS = 30_000

/** How long an unused answer is kept before it is dropped. */
export const DEFAULT_GC_TIME_MS = 5 * 60_000

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: DEFAULT_STALE_TIME_MS,
        gcTime: DEFAULT_GC_TIME_MS,
        refetchOnWindowFocus: false,
        refetchOnReconnect: true,
        retry: false,
      },
      mutations: {
        retry: false,
      },
    },
  })
}
