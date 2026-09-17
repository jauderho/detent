## detent-core — en-US
## Fluent messages for diagnostics and UI hints emitted by config modules built on
## detent-core. IDs are module-prefixed (e.g. `hosts-`); each module crate's test
## suite asserts every `MessageId` it uses has an entry here. Keep alphabetized by
## module prefix.

## hosts module — display name, security notes, schema tooltips
hosts-name = hosts
hosts-note-spoofing = entries here override dns; a wrong or malicious entry silently redirects lookups.
hosts-tip-entries = the address-to-name mappings in /etc/hosts, in file order.
hosts-tip-ip = the address the names below resolve to.
hosts-tip-hostnames = the names that resolve to this address, canonical name first.
hosts-tip-comment = the inline comment on this entry, if any.

## hosts module — validation diagnostics
hosts-invalid-hostname = `{$name}` is not a valid hostname.
hosts-duplicate-canonical = `{$name}` is the canonical name of more than one entry.
hosts-no-hostnames = this entry has no hostnames.
hosts-hostname-is-ip = `{$name}` is an address literal, not a hostname.
hosts-ipv6-zone-unsupported = `{$name}` carries an ipv6 zone id, which /etc/hosts does not support.
hosts-hostname-multiple-ips = `{$name}` resolves to more than one address of the same family.
hosts-localhost-not-loopback = `localhost` points at `{$ip}`, which is not a loopback address.
hosts-missing-localhost = there is no `localhost` entry.
hosts-missing-ipv6-localhost = there is no ipv6 `localhost` entry.
hosts-too-many-entries = this file has {$count} entries; consider dns instead.

## detent-core — parse, model, and edit errors
## These are the failures a module's own document model can raise, so they are
## prefixed `core-` rather than with a module id.
core-parse-malformed = this file does not match the format `{$module}` expects: {$reason}
core-model-shape = the supplied configuration does not have the expected shape: {$reason}
core-model-unrepresentable = this file contains something the editor cannot represent: {$reason}
core-edit-line-break = a value may not contain a line break or a null byte; `{$value}` does.
core-edit-index-out-of-range = internal error: line {$index} is outside a file of {$len} lines.
core-edit-unsupported = this edit cannot be expressed in the file's format: {$reason}

## operations layer — errors surfaced by detent-ops
ops-unknown-module = there is no module named `{$module}` in this build.
ops-invalid-model = the configuration for `{$module}` is not valid: {$reason}
ops-hash-conflict = `{$path}` changed on disk since it was read; re-read it and try again.
ops-privsep-failed = the privileged helper refused or could not complete the request: {$reason}
ops-service-failed = the service action did not complete: {$reason}
ops-no-target = `{$module}` manages no file on this host.
ops-no-service = `{$module}` controls no service on this host, so it cannot be restarted.
ops-audit-failed = the audit log could not be read: {$reason}
ops-unsupported = {$what} is not supported in this build.
ops-denied = you are not permitted to do that.

## detent-web — configuration, TLS, the operations bridge, and the listener
web-config-unreadable = `{$path}` could not be read: {$reason}
web-config-malformed = `{$path}` is not a valid detent configuration: {$reason}
web-config-zero-value = `{$field}` must be greater than zero.
web-config-weak-argon2 = `auth.argon2.m_kib` is {$m}, below the minimum of {$min} kib.
web-tls-generate-failed = the bootstrap certificate could not be generated: {$reason}
web-tls-key-rejected = the certificate and its private key were rejected: {$reason}
web-tls-no-provider = this build has no usable tls crypto provider.
web-tls-store-unreadable = `{$path}` could not be read: {$reason}
web-tls-store-unwritable = `{$path}` could not be prepared for writing: {$reason}
web-tls-store-write-failed = `{$path}` could not be written: {$reason}
web-tls-acme-pem-rejected = the issued certificate or key was not usable PEM.
web-engine-stopped = the operations engine is no longer running; retry once the service is back.
web-server-bind-failed = `{$addr}` could not be listened on: {$reason}
web-server-address-unknown = the listening address could not be read back: {$reason}

## detent-web — auth: passwords, sessions, api tokens, totp, csrf
web-auth-entropy-unavailable = the system random number generator failed, so no credential could be issued.
web-auth-argon2-params = the configured argon2 parameters are not usable: {$reason}
web-auth-hash-failed = the password could not be hashed.
web-auth-user-name-invalid = `{$name}` is not a usable user name; use 1 to 32 of `a-z`, `0-9`, `.`, `_` or `-`, starting with a letter or a digit.
web-auth-user-exists = a user named `{$name}` already exists.
web-auth-user-unknown = there is no user named `{$name}`.
web-auth-invalid-credentials = the user name, password or code was not correct.
web-auth-rate-limited = too many attempts; wait {$seconds} seconds and try again.
web-auth-session-limit = too many sessions are open; wait for one to expire and sign in again.
web-auth-unauthenticated = sign in to do that.
web-auth-ambiguous-credentials = send either a session cookie or a bearer token, not both.
web-auth-csrf-rejected = this request did not pass its cross-site checks.
web-auth-token-unknown = that api token does not exist, is revoked, or has expired.
web-auth-token-limit = this host already holds the maximum number of api tokens.
web-auth-totp-secret-invalid = that authenticator secret is not valid base32.
web-auth-store-unreadable = `{$path}` could not be read: {$reason}
web-auth-store-unwritable = `{$path}` could not be prepared for writing: {$reason}
web-auth-store-write-failed = `{$path}` could not be written: {$reason}
web-auth-store-malformed = `{$path}` is not a valid detent credential file: {$reason}
web-denied-scope = this credential does not carry the `{$scope}` scope.

## detent-web — the api surface
web-request-malformed = the request body is not the shape this endpoint expects.
web-request-too-deep = the request body is nested too deeply.
web-api-unexpected-outcome = the operation completed but its result could not be rendered.
