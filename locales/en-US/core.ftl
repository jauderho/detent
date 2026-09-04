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
