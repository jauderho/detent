/**
 * Every address the console answers on, in one place.
 *
 * Route strings are constants rather than literals sprinkled through the tree
 * so a guard, a redirect and a nav link cannot drift apart — the class of bug
 * that produces a redirect loop.
 */

export const ROUTES = {
  login: '/login',
  dashboard: '/',
  modules: '/modules',
  moduleDetail: '/modules/:id',
  services: '/services',
  backups: '/backups',
  audit: '/audit',
  certificates: '/certificates',
  settings: '/settings',
} as const

/** The address of one module's page. */
export function moduleDetailPath(id: string): string {
  return `${ROUTES.modules}/${encodeURIComponent(id)}`
}

/**
 * Where to send somebody after they sign in.
 *
 * Only a same-site absolute path is honored: a `from` that arrived as
 * `//evil.example` or `https://evil.example` would be an open redirect, and a
 * login screen is exactly where one is worth the most.
 */
export function safeRedirect(from: string | undefined): string {
  if (from === undefined) return ROUTES.dashboard
  if (!from.startsWith('/') || from.startsWith('//')) return ROUTES.dashboard
  if (from.startsWith(ROUTES.login)) return ROUTES.dashboard
  return from
}
