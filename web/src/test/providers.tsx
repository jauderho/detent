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
 * One rule for [`stubFetchByUrl`]: a pattern, and what to answer with.
 *
 * The pattern is matched as a substring of the request URL, optionally
 * prefixed with a method — `'/api/v1/modules'` matches any request whose URL
 * contains that, while `'POST /api/v1/modules/hosts/apply'` matches only the
 * write. Rules are tried in order, so put the specific ones first.
 */
export type UrlRule = readonly [pattern: string, respond: () => Response]

export type UrlFetchStub = {
  fetch: typeof globalThis.fetch
  calls: StubCall[]
}

/**
 * A `fetch` that answers by matching the request URL rather than by call order.
 *
 * **This is the right stub for any page that issues more than one request.**
 * [`stubFetch`] answers from a queue, which silently assumes the requests
 * arrive in the order the test queued the answers — and every page in this
 * console fires its own query concurrently with `AuthProvider`'s session
 * probe, so that assumption is not something a test can hold. When the order
 * flips, one panel is handed another panel's JSON and the failure looks like a
 * bug in the page.
 *
 * `stubFetch` remains correct for a single-request test, and for one that is
 * deliberately exercising a sequence of answers to the *same* endpoint.
 */
export function stubFetchByUrl(rules: readonly UrlRule[]): UrlFetchStub {
  const calls: StubCall[] = []
  const fetch = (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    calls.push({ url, init: init ?? {} })

    const rule = rules.find(([pattern]) => {
      const space = pattern.indexOf(' ')
      if (space === -1) return url.includes(pattern)
      return (
        method === pattern.slice(0, space).toUpperCase() && url.includes(pattern.slice(space + 1))
      )
    })
    if (rule === undefined) {
      return Promise.reject(new TypeError(`stubFetchByUrl: no rule matches ${method} ${url}`))
    }
    // A `Response` body can only be read once, and a rule may match repeatedly.
    return Promise.resolve(rule[1]().clone())
  }
  return { fetch: fetch as unknown as typeof globalThis.fetch, calls }
}

/**
 * A `fetch` that answers from a queue and records what it was asked for. No
 * test in this suite reaches the network.
 *
 * Answers strictly in call order. Use [`stubFetchByUrl`] instead whenever the
 * component under test can have two requests in flight at once — which is
 * every page that renders alongside `AuthProvider`'s session probe.
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
