import { LocalizationProvider } from '@fluent/react'
import { type RenderResult, render } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter } from 'react-router'
import { ApiProvider } from '@/api/ApiProvider'
import { type ApiClient, createApiClient } from '@/api/client'
import { createQueryClient } from '@/api/queryClient'
import { PendingCommitProvider } from '@/app/PendingCommit'
import { AuthProvider } from '@/auth/AuthProvider'
import { createLocalization } from '@/i18n'

export type StubCall = { url: string; init: RequestInit }

export type FetchStub = {
  fetch: typeof globalThis.fetch
  calls: StubCall[]
  /** Queues one more answer; the last queued answer repeats. */
  push(response: Response): void
}

/**
 * A `fetch` that answers from a queue and records what it was asked for. No
 * test in this suite reaches the network.
 */
export function stubFetch(responses: readonly Response[] = []): FetchStub {
  const queue = [...responses]
  const calls: StubCall[] = []
  let index = 0
  const fetch = (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} })
    const response = queue[Math.min(index, queue.length - 1)]
    index += 1
    if (response === undefined) {
      return Promise.reject(new TypeError('stubFetch: no response configured'))
    }
    // A `Response` body can only be read once; each call gets its own copy.
    return Promise.resolve(response.clone())
  }
  return {
    fetch: fetch as unknown as typeof globalThis.fetch,
    calls,
    push(response) {
      queue.push(response)
    },
  }
}

export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
}

export function errorResponse(status: number, messageId: string, code = 'error'): Response {
  return jsonResponse({ code, message_id: messageId }, { status })
}

export type ProviderOptions = {
  /** The client to put in context; built from `fetch` when omitted. */
  client?: ApiClient
  /** A stubbed transport for the client this helper builds. */
  fetch?: typeof globalThis.fetch
  /** The address the memory router starts on. */
  route?: string
}

/**
 * Renders `ui` under the same providers `main.tsx` wires, with a memory router
 * and a fresh `QueryClient` per test so no cache leaks between them.
 */
export function renderWithProviders(ui: ReactNode, options: ProviderOptions = {}): RenderResult {
  const client =
    options.client ?? createApiClient(options.fetch === undefined ? {} : { fetch: options.fetch })
  return render(
    <LocalizationProvider l10n={createLocalization(['en-US'])}>
      <ApiProvider client={client} queryClient={createQueryClient()}>
        <MemoryRouter initialEntries={[options.route ?? '/']}>
          <AuthProvider>
            <PendingCommitProvider>{ui}</PendingCommitProvider>
          </AuthProvider>
        </MemoryRouter>
      </ApiProvider>
    </LocalizationProvider>,
  )
}
