# ADR-007: Sessions and CSRF
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

The web UI is the primary front for a privileged admin tool (§1.1). It must
resist CSRF from a compromised browser tab and must not rely on the cookie
alone as proof of legitimate origin, since cookies are sent ambiently by
browsers (§2.7, §3 threat model).

## Decision

Server-side, in-memory sessions (restart = logout), a 32-byte CSPRNG session
id in an `__Host-detent_session` cookie with `Secure; HttpOnly;
SameSite=Strict; Path=/`, idle timeout 15 min, absolute timeout 8 h, rotated
on login and privilege change, invalidated on explicit logout (§2.7). CSRF
defense in depth for all non-GET requests: `Sec-Fetch-Site` must be
same-origin (or absent, and only for non-browser token auth), `Origin` must
equal the configured host, and `X-Detent-CSRF` must equal the per-session
token delivered via `/api/v1/auth/session` (§1.3, §2.7). GET requests never
mutate state. API tokens (`Authorization: Bearer`, 32-byte random, stored
SHA-256, scoped `read|write`) skip the CSRF checks only because they carry no
ambient cookie authority (§2.7).

## Consequences

Positive:
- Defense in depth: CSRF is blocked by three independent checks
  (Fetch-Metadata, Origin, per-session token header), not by
  `SameSite=Strict` alone.
- In-memory sessions avoid a persistent session store and its own attack
  surface; the single-admin model makes "logout on restart" an accepted
  tradeoff (§7 risk register).
- Bearer-token clients (CLI, future MCP/API automation, §2.6) are not forced
  through a browser-oriented CSRF flow.

Negative:
- Sessions do not survive a daemon restart, which is a usability cost for a
  single admin session (documented, accepted per §7 risk register; revisit
  if multi-admin arrives).
- Every non-GET handler must implement the full checklist (Appendix D), which
  is more per-handler surface than relying on `SameSite=Strict` alone.

## Alternatives considered

- Cookie-only reliance (`SameSite=Strict` with no Origin/Fetch-Metadata/token
  checks) — rejected: "Defense in depth; no cookie-only reliance" (§1.3 Why).
- Persistent (disk or external) session store — not chosen; §2.7 and §7
  specify in-memory sessions and accept the restart-logout tradeoff.

## References

PLAN.md §1.3 (ADR-007 row), §2.7, §3, §7 (risk register), Appendix D (web
request checklist).
