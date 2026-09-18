/**
 * The scope name `ScopeGate.tsx` checks for.
 *
 * docs/API.md, "scopes": every credential holds `read`, or `read` and `write`
 * together. `write` is required for anything that changes the host — applying
 * a module, confirming or rolling back a commit, restoring a backup, acting on
 * a service — and a request that reaches such an endpoint without it is
 * refused with `403` and `web-denied-scope` before anything is read or
 * written.
 *
 * The check in `ScopeGate.tsx` is a **courtesy**, not a control: it exists so
 * a control the caller may not use is disabled with a reason instead of
 * failing at click time. The server remains the authority, and a scope-less
 * request is refused whatever that check believes.
 */

export const SCOPE_WRITE = 'write'
