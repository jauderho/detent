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
time, and the CSRF token described below. Every route under `/api/v1` needs a
credential; `POST /api/v1/auth/login` and `/healthz` are the only endpoints
that do not.

## Scopes

Every credential holds `read`, or `read` and `write` together — there is no
scope that grants `write` without `read`. `read` covers every endpoint that
does not change the host: listing and reading modules, planning, validating,
reading backups and service status, the audit log, the host profile, the
update status.
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

## Update status

`GET /api/v1/system/update` reports what the update policy says about this
build, read-only. It performs the same check `detent update --check` does:
the running version is compared against the release feed under the
`[update]` policy from `detent.toml` (`min_age_days`), and the answer is
`update_available`, `current`, `tag`, `published` and `security` — the same
`UpdateReport` schema the console's dashboard shows. A policy refusal (the
release is too young, or older than the running build) is folded into the
report with `update_available: false`, never an error; an unreachable feed
answers `503` with `message_id: "web-update-check-failed"`, refuse-closed,
because a check that cannot reach the release server must not be reported as
"up to date".

`POST /api/v1/system/update` installs the named update. It takes a `write`-scoped, CSRF-checked `{"version": ...}` body (`UpdateApplyRequest`, `deny_unknown_fields`), authorizes against `Operation::UpdateApply` (`detent-web/src/authz.rs`), executes through the operations engine, and writes one audit record on success *and* on refusal (PLAN §2.5). The engine bridges the release tag to the content-addressed staged file (`<state_root>/update/staged/<hex sha256>`) and drives the privileged monitor's binary swap (`Request::ReplaceBinary` in `crates/detent-platform/src/privsep/proto.rs`, answered by `privsep/monitor.rs`), which keeps the previous binary at `<target>.prev`. `GET /api/v1/system/update` installs nothing, ever.

## Design notes

- `GET /api/v1/openapi.json` **needs a credential**, like everything else under
  `/api/v1`. It is a map of the whole surface — every path, parameter and body
  shape — and nothing needs it before sign-in: the console's typed client is
  generated from the checked-in copy at build time, never fetched at runtime.
  `/healthz` is the only route in the document that stays open, because a
  liveness probe has no credential to present and its body is a constant.
- Every response body names a schema, so a typed client can be generated from
  `openapi.json`. The types come from `detent-core`, `detent-ops` and
  `detent-platform`, which PLAN §2.1 keeps front-end agnostic: each of those
  crates carries an **optional, off-by-default `openapi` feature** that adds
  `utoipa::ToSchema` to the types that reach a response body.
- **Nothing about the document is compiled into a release build.** That feature
  — and `utoipa` itself — are `detent-web` **dev-dependencies**, and every
  `#[utoipa::path]` and `ToSchema` derive is `#[cfg_attr(test, ...)]`. The
  document is generated by the test suite; at run time
  `GET /api/v1/openapi.json` serves an `include_str!` of the checked-in file.
  This is sound because a test already fails if that file and the document this
  build would generate differ by a byte, so the constant cannot go stale. It is
  worth about 280 KiB of binary: utoipa's runtime schema builders are never
  compiled, rather than compiled and then stripped, and `utoipa` does not appear
  in the release dependency graph at all.
- The one exception is `GET /api/v1/openapi.json`, described as a plain
  object: it returns this document, and naming its schema would mean carrying
  a copy of the OpenAPI meta-schema.

## MCP surface

The optional `mcp` feature ships an `rmcp` server (`crates/detent-mcp`)
that exposes every `Operation` variant as one tool (`list_modules`,
`get_module`, `validate`, `plan`, `apply`, `confirm_commit`,
`rollback_commit`, `list_backups`, `restore`, `service_status`,
`service_action`, `host_profile`, `audit_query`, `update_status`,
`cert_status`, `cert_renew`, `update_apply`). Tool inputs mirror the REST
request shapes above (`model`, `expected_hash` as 64 lowercase hex,
`service_action`, `confirm_secs`, `commit_id`, `backup_id`, `audit_query`,
`version`), so the JSON Schema an MCP client sees is the same JSON Schema
a REST client sees; `Operation` is the shared truth and nothing here
re-declares it. Auth is API-token only (`DETENT_MCP_TOKEN`), checked on
every tool call alongside the same policy the REST layer enforces; a
server built without a verifier fails closed. The server is
transport-agnostic (stdio or streamable HTTP); the default build excludes
it entirely (no `rmcp` in the graph).

## OpenAPI <-> MCP schema parity

Two tests pin the two surfaces together so neither drifts silently:
`the_merged_table_registers_every_endpoint_and_no_get_mutates`
(`crates/detent-web/src/api/mod.rs`) asserts the REST route table holds
all 17 routes, and `every_operation_has_a_tool`
(`crates/detent-mcp/src/mcp.rs`) asserts the MCP router holds all 17
tools, one per `Operation` variant. A new `Operation` must add both a
route and a tool or one of the two fails.
