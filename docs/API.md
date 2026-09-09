# detent API

`detent-web` serves one JSON API under `/api/v1`, over TLS 1.3 only. The
machine-readable reference is [`openapi.json`](openapi.json), generated from
the handler source by `utoipa` and checked in so it can never drift silently —
`cargo test -p detent-web api::openapi` fails, and names the regeneration
command, the moment the code and the document disagree. This page is the
prose a human needs before opening that file; it does not restate every
endpoint.

## Authentication

Two credential kinds are accepted, and a request may carry at most one of
them — presenting both is refused rather than resolved, so neither can
silently upgrade the other's authority:

- **A session cookie** (`__Host-detent_session`), issued by
  `POST /api/v1/auth/login` with a user name and password (and a TOTP code,
  once an account has one enrolled). The cookie is `Secure`, `HttpOnly`,
  `SameSite=Strict`, and carries no `Domain`, so script cannot read it and no
  sibling host can plant one. Sessions live in memory only: a restart is a
  logout for everybody. Idle sessions time out after 15 minutes, every
  session after 8 hours regardless of activity, and signing in again
  invalidates whatever session the request arrived with.
- **A bearer token** (`Authorization: Bearer <token>`), issued out of band
  (`detent token create`) with a scope and an optional expiry. A token
  establishes no session — there is nothing for `/api/v1/auth/session` to
  describe and nothing for `/api/v1/auth/logout` to end.

`GET /api/v1/auth/session` returns the signed-in caller's scopes, remaining
time, and the CSRF token described below. `/api/v1/openapi.json` and
`/healthz` are the only endpoints that need no credential at all.

## Scopes

Every credential holds `read`, or `read` and `write` together — there is no
scope that grants `write` without `read`. `read` covers every endpoint that
does not change the host: listing and reading modules, planning, validating,
reading backups and service status, the audit log, the host profile.
`write` is required for anything that does: applying a module, confirming or
rolling back a commit, restoring a backup, and acting on a service. A request
that reaches a `write` endpoint without the scope is refused with `403` and
`message_id: "web-denied-scope"` before anything is read or written.

## CSRF

A cookie carries ambient authority a bearer token does not, so every
non-`GET` request authenticated by cookie must additionally satisfy all
three of PLAN §2.7's checks: `Sec-Fetch-Site: same-origin`, an `Origin` header
matching the configured host, and an `X-Detent-CSRF` header equal to the
token `GET /api/v1/auth/session` returned. Any one missing or wrong is a
`403` with `message_id: "web-auth-csrf-rejected"`. A bearer-authenticated
request skips all three checks — it has no cookie to abuse in the first
place. `GET` never mutates, so it is never subject to these checks.

## Error shape

Every failure, from every endpoint, is exactly:

```json
{ "code": "not_found", "message_id": "ops-unknown-module" }
```

`code` is a small, stable, machine-readable class derived from the HTTP
status (`bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`,
`unprocessable`, `rate_limited`, `unavailable`, `internal`, …). `message_id`
is a Fluent id a front end resolves to a localized sentence; it is never a
raw Rust error string, a stack trace, or anything that reveals the
implementation. A `429` additionally carries a `Retry-After` header. A `422`
from a rejected `apply` additionally carries a `diagnostics` array — the same
validation findings `POST .../validate` would have reported — so a client can
show exactly what was wrong with the candidate model without a second round
trip.

An unknown or malformed module/service id and one that is simply not
compiled into this build are indistinguishable: both answer `404` with
`message_id: "ops-unknown-module"`. That is deliberate — it means a
path-traversal attempt or an oversized id gets the same boring answer a
typo would, never a 500, and never a hint about what *would* have been a
valid id.

## The commit-confirm flow

A module whose descriptor requests it (anything that can lock an
administrator out — network configuration is the canonical example) does not
finalize an `apply` immediately. Instead:

1. `POST /api/v1/modules/{id}/apply` writes the change and arms a
   commit-confirm window. The response's `commit` field carries the
   `commit_id` to confirm or roll back, the deadline, and how many targets a
   timeout would restore.
2. Before the deadline, the caller either:
   - `POST /api/v1/commits/{id}/confirm` — the change stays, or
   - `POST /api/v1/commits/{id}/rollback` — every write since the commit was
     armed is undone immediately, rather than waiting for the deadline.
3. If neither happens before the deadline, the privileged monitor rolls the
   commit back on its own — a client that vanishes mid-change (the network
   configuration it just broke is the worst case) cannot leave the host
   half-configured forever.

Confirming or rolling back an id that was already settled, or that never
existed, answers `409` rather than `404`: the id is not malformed or
unregistered, the commit it named has simply already been decided one way or
the other.

## Design notes

- `GET /api/v1/openapi.json` is served **unauthenticated**. PLAN §2.6 lists it
  in the same breath as the API surface it describes, with no auth
  requirement, and a front end needs the document before it has a session to
  authenticate with. It reveals shapes and error ids, nothing secret.
- Every ops-layer response type this document cannot describe precisely
  without giving `detent-ops` a dependency on `utoipa` (PLAN §2.1 keeps that
  crate front-end agnostic) is documented as a loose, untyped object in
  `openapi.json`, with a comment on the handler naming the real Rust type it
  mirrors. Request bodies are web-layer types and are always precise.
