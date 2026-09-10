/**
 * Scope names, and the one question the interface asks about them.
 *
 * docs/API.md, "scopes": every credential holds `read`, or `read` and `write`
 * together. `write` is required for anything that changes the host — applying
 * a module, confirming or rolling back a commit, restoring a backup, acting on
 * a service — and a request that reaches such an endpoint without it is
 * refused with `403` and `web-denied-scope` before anything is read or
 * written.
 *
 * The check here is a **courtesy**, not a control: it exists so a control the
 * caller may not use is disabled with a reason instead of failing at click
 * time. The server remains the authority, and a scope-less request is refused
 * whatever this file believes.
 */

export const SCOPE_READ = 'read'
export const SCOPE_WRITE = 'write'

export function hasScope(scopes: readonly string[], scope: string): boolean {
  return scopes.includes(scope)
}
