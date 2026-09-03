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
