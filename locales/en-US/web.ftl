## detent web admin UI — en-US
## Source of truth for every user-facing string in web/src. IDs referenced via
## <Localized id="…"> or l10n.getString("…"). Keep alphabetized by section.

## Nameplate / hero
app-designation = detent.
app-lede = the busybox of config files — one console for hosts, resolver, chrony, mounts, and more.
kicker-model = dt-7
kicker-class = config console
kicker-rev = rev. e

## Status bar
status-brand = detent
status-online = system online
status-clock-label = utc
status-mode-label = mode
theme-toggle-aria = toggle light and dark mode
theme-toggle-title = toggle light / dark

## catfu component layer
## Chrome the shared components render themselves. Content strings (field
## captions, table headers, banner copy) are supplied by the calling page.
component-countdown-remaining = time remaining
component-field-info = more information
component-modal-close = close
component-switch-off = off
component-switch-on = on
component-table-empty = no records

## hstats readout strip
hstat-services-active-label = services active
hstat-pending-commit-label = pending commit
hstat-cert-expiry-label = cert time-to-expiry
hstat-update-state-label = update state
hstat-uptime-label = uptime

## API failures
## docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
## Fluent id. src/api/messages.ts resolves it here; an id this build does not
## know falls back to `api-error-unknown`, so an id is never rendered raw.
##
## The first three are the console's own — a failure that never reached a
## server has no `message_id` to resolve. The rest mirror the ids the server
## sends, argument-free: locales/en-US/core.ftl interpolates `{$path}`,
## `{$reason}` and friends, and the API deliberately sends none of them.
api-error-network = the console could not reach this host.
api-error-malformed = this host sent an answer the console could not read.
api-error-unknown = this host reported a failure the console has no description for.
core-edit-index-out-of-range = internal error: an edit addressed a line outside the file.
core-edit-line-break = a value may not contain a line break or a null byte.
core-edit-unsupported = this edit cannot be expressed in the file's format.
core-model-shape = the supplied configuration does not have the expected shape.
core-model-unrepresentable = this file contains something the editor cannot represent.
core-parse-malformed = this file does not match the format its module expects.
ops-audit-failed = the audit log could not be read.
ops-denied = you are not permitted to do that.
ops-hash-conflict = the file changed on disk since it was read; re-read it and try again.
ops-invalid-model = that configuration is not valid.
ops-no-service = this module controls no service on this host, so it cannot be restarted.
ops-no-target = this module manages no file on this host.
ops-privsep-failed = the privileged helper refused or could not complete the request.
ops-service-failed = the service action did not complete.
ops-unknown-module = there is no module by that name in this build.
ops-unsupported = that is not supported in this build.
web-api-unexpected-outcome = the operation completed but its result could not be rendered.
web-auth-ambiguous-credentials = send either a session cookie or a bearer token, not both.
web-auth-argon2-params = the configured argon2 parameters are not usable.
web-auth-csrf-rejected = this request did not pass its cross-site checks; reload the page and try again.
web-auth-entropy-unavailable = the system random number generator failed, so no credential could be issued.
web-auth-hash-failed = the password could not be hashed.
web-auth-invalid-credentials = the user name, password or code was not correct.
web-auth-rate-limited = too many attempts; wait a moment and try again.
web-auth-session-limit = too many sessions are open; wait for one to expire and sign in again.
web-auth-store-malformed = a credential file on this host is not valid.
web-auth-store-unreadable = a credential file on this host could not be read.
web-auth-store-unwritable = a credential file on this host could not be prepared for writing.
web-auth-store-write-failed = a credential file on this host could not be written.
web-auth-token-limit = this host already holds the maximum number of api tokens.
web-auth-token-unknown = that api token does not exist, is revoked, or has expired.
web-auth-totp-secret-invalid = that authenticator secret is not valid base32.
web-auth-unauthenticated = sign in to do that.
web-auth-user-exists = a user by that name already exists.
web-auth-user-name-invalid = that user name is not usable; use 1 to 32 of `a-z`, `0-9`, `.`, `_` or `-`, starting with a letter or a digit.
web-auth-user-unknown = there is no user by that name.
web-denied-scope = this credential does not carry the scope that action needs.
web-engine-stopped = the operations engine is no longer running; retry once the service is back.
web-request-malformed = the request body is not the shape this endpoint expects.
web-request-too-deep = the request body is nested too deeply.

## Sign in
login-title = sign in
login-panel-label = session
login-username-label = user name
login-password-label = password
login-totp-label = authenticator code
login-totp-description = six digits from the authenticator enrolled for this account.
login-totp-reveal = use an authenticator code
login-submit = sign in
login-submitting = signing in
login-retry-after = too many attempts; wait {$seconds} seconds and try again.

## Session and scope
auth-checking = checking this session
auth-sign-out = sign out
scope-gate-read-only = this session carries read access only; it cannot change anything on this host.
scope-gate-signed-out = sign in to change anything on this host.

## Navigation
nav-label = sections
nav-dashboard = dashboard
nav-modules = modules
nav-services = services
nav-backups = backups
nav-audit = audit
nav-certificates = certificates
nav-settings = settings

## Routed pages
## Every section beyond sign-in is a named placeholder until its own wave.
page-placeholder-body = this section is not built yet.
page-dashboard-title = dashboard
page-modules-title = modules
page-module-detail-title = module {$module}
page-services-title = services
page-backups-title = backups
page-audit-title = audit log
page-certificates-title = certificates
page-settings-title = settings
page-not-found-title = no such page
page-not-found-body = that address does not name anything in this console.
page-not-found-home = go to the dashboard

## Pending commit
pending-commit-message = a configuration change is waiting to be confirmed; it rolls back on its own when this window closes.
pending-commit-countdown-label = time left to confirm

## Schema-driven module forms
## Chrome the form engine (web/src/forms) renders around a module's schema.
## Field captions come from the schema's own property names, and a field's
## tooltip and recommendation are Fluent ids in the *module's* locale file, not
## here — a missing one degrades to no tooltip and is never rendered raw.
forms-advanced-toggle = advanced
forms-badge-security-high = high security impact
forms-badge-deprecated = deprecated in {$version}
forms-diagnostic-at-field = {$field}: {$message}
forms-diagnostic-unknown = this host reported a check result this build has no description for ({$id}).
forms-item-add-caption = add
forms-item-move-down-caption = dn
forms-item-move-up-caption = up
forms-item-remove-caption = del
forms-list-empty = nothing here yet.
forms-option-none = none
forms-row-add = add a row to {$field}
forms-row-label = row {$index}
forms-row-move-down = move {$field} row {$index} down
forms-row-move-up = move {$field} row {$index} up
forms-row-remove = remove {$field} row {$index}
forms-tag-add = add an item to {$field}
forms-tag-item = {$field} item {$index}
forms-tag-move-down = move {$field} item {$index} down
forms-tag-move-up = move {$field} item {$index} up
forms-tag-remove = remove {$field} item {$index}
forms-unsupported-note = this build cannot edit this value. it is shown as stored and is left unchanged.

## Form validation
## Mirrors the schema constraints for immediate feedback. The server is the
## authority: a clean pass here is not a promise that apply will succeed.
forms-error-enum = choose one of the listed values.
forms-error-format-ip = this is not a valid ip address.
forms-error-integer = use a whole number.
forms-error-max-length = use at most {$max} characters.
forms-error-maximum = use {$max} or less.
forms-error-min-length = use at least {$min} characters.
forms-error-minimum = use {$min} or more.
forms-error-pattern = this value does not match the form this field accepts.
forms-error-required = this field is required.
forms-error-type = this value is not the kind of value this field holds.
