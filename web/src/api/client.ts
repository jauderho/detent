/**
 * The typed fetch wrapper every request in the console goes through.
 *
 * Everything about a call — its path, its method, its path parameters, its
 * query, its body and the shape it resolves to — is derived from the
 * generated `paths` type in `schema.d.ts`, so a backend change that
 * regenerates the document breaks compilation here rather than at runtime.
 *
 * Two rules are enforced centrally because forgetting either is a security
 * bug, not a style slip (docs/API.md, "CSRF"):
 *
 *   * every non-`GET` request carries `X-Detent-CSRF`; the other two checks
 *     (`Sec-Fetch-Site` and `Origin`) are forbidden header names that only the
 *     browser may set, so there is nothing to do for them here;
 *   * every request sends its cookie, and nothing ever puts the session id or
 *     the CSRF token in a URL, in storage, or in a log.
 *
 * Expected API failures are values, not exceptions: `request` resolves to a
 * discriminated `ApiResult`. Only a programming error throws.
 */

import type { components, paths } from './schema'

/** The header docs/API.md requires on every cookie-authenticated mutation. */
export const CSRF_HEADER = 'X-Detent-CSRF'

/** A validation finding, as a rejected `apply` returns it. */
export type Diagnostic = components['schemas']['Diagnostic']

/** The methods this API exposes to a browser. */
export type HttpMethod = 'get' | 'post'

// ── result types ────────────────────────────────────────────────────────────

/** A failure the server described in the `{ code, message_id }` shape. */
export type HttpApiError = {
  readonly kind: 'http'
  readonly status: number
  /** The stable machine class: `unauthorized`, `forbidden`, `rate_limited`, … */
  readonly code: string
  /** A Fluent id. Resolve it through `resolveMessage`; never render it raw. */
  readonly messageId: string
  /** Seconds from a `Retry-After` header, when the answer carried one. */
  readonly retryAfterSeconds: number | null
  /** The findings a rejected `apply` reports alongside its 422. */
  readonly diagnostics: readonly Diagnostic[] | null
}

/** The request never reached a server, or the connection died mid-answer. */
export type NetworkApiError = { readonly kind: 'network' }

/** A body arrived but is not the shape the endpoint documents. */
export type MalformedApiError = { readonly kind: 'malformed'; readonly status: number }

export type ApiError = HttpApiError | NetworkApiError | MalformedApiError

export type ApiResult<T> =
  | { readonly ok: true; readonly status: number; readonly data: T }
  | { readonly ok: false; readonly error: ApiError }

// ── schema-derived request and response types ───────────────────────────────

type JsonContent<T> = T extends { content: { 'application/json': infer B } } ? B : never

type ResponsesOf<O> = O extends { responses: infer R } ? R : never

/**
 * What a successful call resolves to: the `200` body, or `undefined` for the
 * one endpoint (`logout`) whose success is a bodiless `204`.
 *
 * `undefined` rather than `void`: this is a data position, not a return type,
 * and `void` in one reads as "ignore me" while the value here is genuinely
 * `undefined` and is compared against.
 */
type OkData<O> =
  ResponsesOf<O> extends { 200: infer Ok }
    ? JsonContent<Ok>
    : ResponsesOf<O> extends { 204: unknown }
      ? undefined
      : never

/**
 * `never` when the operation documents no body. openapi-typescript writes
 * `requestBody?: never` in that case, and an optional property does not
 * satisfy a required one, so the conditional simply fails to match.
 */
type BodyOf<O> = O extends { requestBody: infer RB } ? JsonContent<NonNullable<RB>> : never

type PathParamsOf<O> = O extends { parameters: { path: infer P } } ? P : never

type QueryParamsOf<O> = O extends { parameters: { query?: infer Q } }
  ? Exclude<Q, undefined>
  : never

/** Operations reachable at `path` with `method`. */
type Operation<P extends keyof paths, M extends HttpMethod> = M extends keyof paths[P]
  ? paths[P][M]
  : never

/** Paths that answer `method`. */
export type PathsFor<M extends HttpMethod> = {
  [P in keyof paths]: paths[P] extends Record<M, never> ? never : P
}[keyof paths]

export type CallOptions = {
  /** Aborts the request; React Query supplies one per query. */
  readonly signal?: AbortSignal
  /**
   * Keeps a `401` from firing the global signed-out handler. Set on the two
   * calls for which a `401` is an ordinary answer rather than an expiry: the
   * session probe and the login attempt.
   */
  readonly suppressUnauthorizedEvent?: boolean
}

// `[X] extends [never]` rather than `X extends never`: the naked form
// distributes over `never` and collapses the whole conditional to `never`.
type RequestOptions<O> = CallOptions &
  ([PathParamsOf<O>] extends [never] ? unknown : { readonly path: PathParamsOf<O> }) &
  ([QueryParamsOf<O>] extends [never] ? unknown : { readonly query?: QueryParamsOf<O> }) &
  ([BodyOf<O>] extends [never] ? unknown : { readonly body: BodyOf<O> })

// ── parsing ─────────────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function toStringArgs(value: unknown): Record<string, string> | null {
  if (!isRecord(value)) return null
  const args: Record<string, string> = {}
  for (const [key, item] of Object.entries(value)) {
    if (typeof item !== 'string') return null
    args[key] = item
  }
  return args
}

function toSpan(value: unknown): components['schemas']['Span'] | null {
  if (!isRecord(value)) return null
  const { start, end } = value
  if (typeof start !== 'number' || typeof end !== 'number') return null
  return { start, end }
}

const SEVERITIES = ['error', 'warning', 'recommendation'] as const

function isSeverity(value: unknown): value is components['schemas']['Severity'] {
  return SEVERITIES.some((severity) => severity === value)
}

/**
 * Narrows the `diagnostics` field of an error body.
 *
 * The generated type is `Record<string, never>` — utoipa cannot describe
 * `detent_core::diag::Diagnostics` without giving `detent-core` a `utoipa`
 * dependency — so this is the one place the shape is checked by hand rather
 * than by the compiler. Anything that does not match is reported as absent.
 */
function toDiagnostics(value: unknown): readonly Diagnostic[] | null {
  if (!Array.isArray(value)) return null
  const out: Diagnostic[] = []
  for (const item of value) {
    if (!isRecord(item)) return null
    const args = toStringArgs(item.args)
    if (args === null || typeof item.id !== 'string' || !isSeverity(item.severity)) return null
    const span = toSpan(item.span)
    out.push({
      args,
      id: item.id,
      severity: item.severity,
      ...(typeof item.field === 'string' ? { field: item.field } : {}),
      ...(span === null ? {} : { span }),
    })
  }
  return out
}

/** `Retry-After` is seconds here, but the HTTP-date form is handled anyway. */
function parseRetryAfter(header: string | null, now: number): number | null {
  if (header === null) return null
  const seconds = Number(header.trim())
  if (Number.isFinite(seconds) && seconds >= 0) return Math.round(seconds)
  const at = Date.parse(header)
  if (Number.isNaN(at)) return null
  return Math.max(0, Math.round((at - now) / 1000))
}

function parseErrorBody(body: unknown, status: number, retryAfter: number | null): ApiError {
  if (!isRecord(body) || typeof body.code !== 'string' || typeof body.message_id !== 'string') {
    return { kind: 'malformed', status }
  }
  return {
    kind: 'http',
    status,
    code: body.code,
    messageId: body.message_id,
    retryAfterSeconds: retryAfter,
    diagnostics: toDiagnostics(body.diagnostics),
  }
}

// ── url building ────────────────────────────────────────────────────────────

const PATH_PARAM = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g

function fillPath(template: string, params: Record<string, unknown> | undefined): string {
  return template.replace(PATH_PARAM, (_match, name: string) => {
    const value = params?.[name]
    if (value === undefined || value === null) {
      throw new Error(`api: missing path parameter "${name}" for ${template}`)
    }
    return encodeURIComponent(String(value))
  })
}

function buildQuery(params: Record<string, unknown> | undefined): string {
  if (params === undefined) return ''
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue
    search.append(key, String(value))
  }
  const text = search.toString()
  return text === '' ? '' : `?${text}`
}

// ── the client ──────────────────────────────────────────────────────────────

export type ApiClientOptions = {
  /** Prefix for every request. Empty means same-origin, which is the app. */
  readonly baseUrl?: string
  /** Injected in tests; defaults to the global `fetch`. */
  readonly fetch?: typeof globalThis.fetch
  /** Reads the clock for `Retry-After` dates; injected in tests. */
  readonly now?: () => number
}

export type UnauthorizedHandler = () => void

/**
 * A request-shaped view of the API. One instance per app; it holds the CSRF
 * token in a closure so nothing can serialize it by accident.
 */
export type ApiClient = {
  request<P extends keyof paths, M extends HttpMethod & keyof paths[P]>(
    path: P,
    method: M,
    options: RequestOptions<Operation<P, M>>,
  ): Promise<ApiResult<OkData<Operation<P, M>>>>
  get<P extends PathsFor<'get'>>(
    path: P,
    options: RequestOptions<Operation<P, 'get'>>,
  ): Promise<ApiResult<OkData<Operation<P, 'get'>>>>
  post<P extends PathsFor<'post'>>(
    path: P,
    options: RequestOptions<Operation<P, 'post'>>,
  ): Promise<ApiResult<OkData<Operation<P, 'post'>>>>
  /** The token from `GET /auth/session`. Memory only — never persisted. */
  setCsrfToken(token: string | null): void
  hasCsrfToken(): boolean
  /** Called once per `401` that was not explicitly suppressed. */
  setUnauthorizedHandler(handler: UnauthorizedHandler | null): void
}

export function createApiClient(options: ApiClientOptions = {}): ApiClient {
  const baseUrl = options.baseUrl ?? ''
  const doFetch = options.fetch ?? ((...args) => globalThis.fetch(...args))
  const now = options.now ?? (() => Date.now())

  let csrfToken: string | null = null
  let onUnauthorized: UnauthorizedHandler | null = null

  async function request(
    path: string,
    method: HttpMethod,
    options: Record<string, unknown>,
  ): Promise<ApiResult<unknown>> {
    const pathParams = isRecord(options.path) ? options.path : undefined
    const queryParams = isRecord(options.query) ? options.query : undefined
    const hasBody = 'body' in options && options.body !== undefined
    const url = `${baseUrl}${fillPath(path, pathParams)}${buildQuery(queryParams)}`

    const headers = new Headers({ Accept: 'application/json' })
    if (hasBody) headers.set('Content-Type', 'application/json')
    // `Sec-Fetch-Site` and `Origin` are forbidden header names: the browser
    // sets them, and an attempt to set them here would be dropped. The token
    // is the only one of the three checks a client can satisfy itself.
    if (method !== 'get' && csrfToken !== null) headers.set(CSRF_HEADER, csrfToken)

    let response: Response
    try {
      response = await doFetch(url, {
        method: method.toUpperCase(),
        headers,
        credentials: 'same-origin',
        ...(hasBody ? { body: JSON.stringify(options.body) } : {}),
        ...(options.signal instanceof AbortSignal ? { signal: options.signal } : {}),
      })
    } catch {
      return { ok: false, error: { kind: 'network' } }
    }

    if (response.status === 401 && options.suppressUnauthorizedEvent !== true) {
      onUnauthorized?.()
    }

    if (response.status === 204) {
      return { ok: true, status: response.status, data: undefined }
    }

    let body: unknown
    try {
      body = await response.json()
    } catch {
      // A body that is not JSON is unusable either way: the endpoint promised
      // one, and an error we cannot read is an error we cannot localize.
      return { ok: false, error: { kind: 'malformed', status: response.status } }
    }

    if (!response.ok) {
      const retryAfter = parseRetryAfter(response.headers.get('Retry-After'), now())
      return { ok: false, error: parseErrorBody(body, response.status, retryAfter) }
    }
    return { ok: true, status: response.status, data: body }
  }

  const client: ApiClient = {
    request: (path, method, options) =>
      request(String(path), method, options as Record<string, unknown>) as never,
    get: (path, options) =>
      request(String(path), 'get', options as Record<string, unknown>) as never,
    post: (path, options) =>
      request(String(path), 'post', options as Record<string, unknown>) as never,
    setCsrfToken(token) {
      csrfToken = token
    },
    hasCsrfToken() {
      return csrfToken !== null
    },
    setUnauthorizedHandler(handler) {
      onUnauthorized = handler
    },
  }
  return client
}
