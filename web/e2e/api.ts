/**
 * The stub `detent` host these runs talk to.
 *
 * Every fixture below is shaped by `docs/openapi.json`, and the values are
 * deliberately **mixed case** — `NetworkManager`, `GNU inetutils`, a diff
 * containing `NewHost.Example`. The console's body style is
 * `text-transform: lowercase`, so a host identifier that survives to the
 * screen intact is the assertion; one that arrives as `networkmanager` is a
 * daemon name an operator cannot paste into a shell, and a lowercased diff is
 * not the bytes that would be written.
 */

import type { Page, Route } from '@playwright/test'

export const SESSION = {
  csrf_token: 'csrf-e2e',
  expires_in_secs: 900,
  scopes: ['read', 'write'] as const,
  subject: 'Operator',
  totp_satisfied: false,
}

export const READ_ONLY_SESSION = { ...SESSION, scopes: ['read'] as const }

export const HOSTS_DESCRIPTOR = {
  id: 'hosts',
  display_name_id: 'module-hosts-name',
  targets: [{ path: '/etc/hosts', kind: 'file', mode: 420, owner: 'root' }],
  upstream: { project: 'GNU inetutils', tracked_version: '2.5' },
  services: [
    { units: { systemd: ['nscd.service'], openrc: [], bsdrc: [] }, actions: ['restart', 'reload'] },
  ],
  checks: [],
  commit_confirm: true,
  security_notes: ['sec-hosts-no-wildcards'],
}

export const HOST_REPORT = {
  profile: {
    os: 'linux',
    init: 'systemd',
    hostname: 'k001',
    service_versions: {},
    ram_mib: 7900,
  },
  distro_id: 'debian',
  distro_version_id: '13',
  network_backend: 'NetworkManager',
  resolver_backend: 'systemd-resolved',
  notes: ['Landlock is not compiled into this kernel'],
}
export const CERT_REPORT = {
  fingerprint:
    'E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55',
  lifetime_used_percent: 10,
  not_after_unix: 2_000_000_000,
}

export const AUDIT_RECORDS = [
  {
    ts: '2026-09-16T12:34:56Z',
    who: 'Operator',
    kind: 'session',
    op: 'apply',
    result: 'ok',
    module: 'hosts',
  },
  {
    ts: '2026-09-16T12:30:01Z',
    who: 'token:CI-ReadOnly',
    kind: 'token',
    op: 'plan',
    result: 'denied',
    module: 'hosts',
  },
]

export const UNIFIED_DIFF = [
  '--- a/etc/hosts',
  '+++ b/etc/hosts',
  '@@ -1,2 +1,3 @@',
  ' 127.0.0.1\tlocalhost',
  '-192.168.1.9\tOldName',
  '+192.168.1.9\tNewHost.Example',
  '',
].join('\n')

export const MODULE_VIEW = {
  descriptor: HOSTS_DESCRIPTOR,
  current_hash: 'b'.repeat(64),
  diagnostics: [],
  model: { entries: [{ address: '127.0.0.1', names: ['localhost'] }] },
  schema: {
    type: 'object',
    properties: {
      entries: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            address: { type: 'string', format: 'ip' },
            names: { type: 'array', items: { type: 'string' } },
          },
          required: ['address'],
        },
      },
    },
  },
}

export const PLAN_REPORT = {
  module: 'hosts',
  path: '/etc/hosts',
  diff: [],
  rendered: '',
  unified_diff: UNIFIED_DIFF,
  affected_services: [{ unit: 'nscd.service', actions: ['restart'] }],
  checks: [{ program: '/usr/bin/HostsLint', passed: true, detail: 'ok', exit_code: 0 }],
  diagnostics: [],
  current_hash: 'b'.repeat(64),
  would_change: true,
}

export const APPLY_REPORT = {
  module: 'hosts',
  path: '/etc/hosts',
  new_hash: 'c'.repeat(64),
  created: false,
  backed_up: true,
  prev_hash: 'b'.repeat(64),
  commit: {
    commit_id: 1,
    timeout_s: 120,
    deadline: new Date(Date.now() + 120_000).toISOString(),
    rollback_targets: 1,
  },
  service: null,
}

/** Every request this stub records, so a test can assert what was sent. */
export type RecordedCall = { method: string; url: string; body: unknown }

export type StubOptions = {
  /** Sign in with `read` only, to exercise the write gate. */
  readOnly?: boolean
  /** Answer `GET /api/v1/system/profile` with this status instead of 200. */
  profileStatus?: number
}

/**
 * Routes `**\/api/v1/**` to the fixtures above and returns the call log.
 *
 * Installed before `page.goto`, so `AuthProvider`'s session probe is answered
 * by the stub rather than reaching a real host.
 */
export async function stubApi(page: Page, options: StubOptions = {}): Promise<RecordedCall[]> {
  const calls: RecordedCall[] = []
  // The session probe answers 401 until a login lands, so `signIn` drives the
  // real form rather than arriving already authenticated. Answering it 200
  // from the start would skip LoginPage entirely and quietly delete the only
  // e2e coverage the sign-in screen has.
  let signedIn = false
  let pendingCommit: typeof APPLY_REPORT.commit = null

  const json = (route: Route, body: unknown, status = 200) =>
    route.fulfill({
      status,
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify(body),
    })

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname
    const method = request.method()
    let body: unknown = null
    try {
      body = request.postData() === null ? null : JSON.parse(request.postData() ?? 'null')
    } catch {
      body = request.postData()
    }
    calls.push({ method, url: url.pathname + url.search, body })

    const session = options.readOnly === true ? READ_ONLY_SESSION : SESSION

    if (path.endsWith('/auth/login')) {
      signedIn = true
      return json(route, session)
    }
    if (path.endsWith('/auth/session')) {
      return signedIn
        ? json(route, session)
        : json(route, { code: 'unauthorized', message_id: 'web-auth-unauthenticated' }, 401)
    }
    if (path.endsWith('/auth/logout')) {
      signedIn = false
      return route.fulfill({ status: 204, body: '' })
    }
    if (path.endsWith('/system/profile')) {
      return options.profileStatus === undefined
        ? json(route, HOST_REPORT)
        : json(route, { code: 'error', message_id: 'ops-privsep-failed' }, options.profileStatus)
    }
    if (path.endsWith('/system/cert')) {
      return json(route, CERT_REPORT)
    }
    if (path.endsWith('/commits/pending')) {
      return json(route, pendingCommit)
    }
    if (path.endsWith('/audit')) {
      return json(route, AUDIT_RECORDS)
    }
    if (path.endsWith('/plan')) {
      return json(route, PLAN_REPORT)
    }
    if (path.endsWith('/validate')) {
      return json(route, [])
    }
    if (path.endsWith('/apply')) {
      pendingCommit = APPLY_REPORT.commit
      return json(route, APPLY_REPORT)
    }
    if (path.endsWith('/confirm')) {
      return json(route, { commit_id: 1, targets: 1 })
    }
    if (path.endsWith('/backups')) {
      return json(route, [
        {
          id: 0,
          target: 0,
          name: 'hosts.20260916T123456Z',
          created_unix_s: 1_789_605_296,
          digest: 'a'.repeat(64),
          len: 4096,
        },
      ])
    }
    if (path.includes('/services/')) {
      return json(route, {
        unit: 'nscd.service',
        state: 'active',
        enabled: true,
        since: { secs_since_epoch: 1_789_600_000, nanos_since_epoch: 0 },
      })
    }
    if (/\/modules\/[^/]+$/.test(path)) {
      return json(route, MODULE_VIEW)
    }
    if (path.endsWith('/modules')) {
      return json(route, [HOSTS_DESCRIPTOR])
    }
    return json(route, { code: 'not_found', message_id: 'ops-unknown-module' }, 404)
  })

  return calls
}

/** Signs in through the real form and waits for the console to appear. */
export async function signIn(page: Page): Promise<void> {
  await page.goto('/')
  await page.getByLabel('user name').fill('operator')
  await page.getByLabel('password').fill('correct horse battery staple')
  await page.getByRole('button', { name: 'sign in' }).click()
  await page.getByRole('navigation', { name: 'sections' }).waitFor()
}
