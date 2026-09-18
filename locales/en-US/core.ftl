## detent-core — en-US
## Fluent messages for diagnostics and UI hints emitted by config modules built on
## detent-core. IDs are module-prefixed (e.g. `hosts-`); each module crate's test
## suite asserts every `MessageId` it uses has an entry here. Keep alphabetized by
## module prefix.

## chrony module — display name, security notes, schema tooltips
chrony-name = chrony
chrony-note-precedence = this file overrides the compiled-in defaults; a wrong value silently changes how the host keeps time.
chrony-tip-settings = the chrony.conf directives this module models, in file order; anything else in the file is preserved untouched.
chrony-tip-key = the directive name, one word, case-insensitive.
chrony-tip-value = the value of this directive, up to the end of the line; empty for valueless directives such as `rtcsync`.
chrony-rec-value = prefer an explicit value over relying on the compiled-in default.

## chrony module — validation diagnostics
chrony-invalid-key = `{$key}` is not a valid chrony directive name.
chrony-duplicate-key = `{$key}` is set more than once; the last value wins.
chrony-too-many-settings = this file has {$count} settings; split it into drop-in files under /etc/chrony/conf.d.
chrony-allow-open = `allow {$value}` serves time to the whole internet; allow only the networks that need it.
chrony-missing-makestep = makestep is not set; at startup the clock can drift unbounded instead of being stepped into range.
chrony-missing-rtcsync = rtcsync is not set; the hardware clock will drift relative to the system clock.
chrony-rec-nts = the pool {$pool} is used without the nts option; prefer nts-capable sources so time cannot be spoofed.
chrony-cmdport-open = cmdport is {$port}; set cmdport 0 unless chronyc must reach this host over the network.

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

## mounts module — display name, security notes, schema tooltips
mounts-name = mounts
mounts-note-boot = a bad /etc/fstab can leave the host unbootable at the next restart; every change needs a second confirmation.
mounts-tip-entries = the mount entries in /etc/fstab, in file order.
mounts-tip-spec = what is mounted: a device, `UUID=...`/`LABEL=...`, an nfs export, or `none` for swap.
mounts-tip-mountpoint = where the filesystem is mounted, or `none`/`swap` for swap.
mounts-tip-fstype = the filesystem type, e.g. ext4, or `swap`.
mounts-tip-options = the comma-separated mount options, e.g. defaults,nosuid.
mounts-tip-dump = the dump(8) backup frequency; almost always 0.
mounts-tip-pass = the fsck pass number: 1 for root, 2 for other checked filesystems, 0 to skip.
mounts-rec-options = guard user-writable data with nosuid, nodev and noexec; prefer x-systemd.automount on network filesystems.

## mounts module — validation diagnostics
mounts-empty-spec = entry {$index} has an empty spec (first column).
mounts-empty-mountpoint = entry {$index} has an empty mount point (second column).
mounts-invalid-fstype = `{$fstype}` is not a valid filesystem type.
mounts-pass-too-high = entry {$index} has pass `{$pass}`; fsck runs at most 2 passes.
mounts-root-pass = the root filesystem should have pass 1, not `{$pass}`.
mounts-missing-nofail = `{$mountpoint}` is removable media without `nofail`; the boot hangs when it is unplugged.
mounts-missing-guards = `{$mountpoint}` mounts user-writable data without `{$missing}`; add them.
mounts-network-automount = `{$mountpoint}` is a network filesystem without `x-systemd.automount`; the boot waits for the network.
mounts-noauto-without-user = `noauto` without `user`: only root can mount it, defeating the point.

## nfs module — display name, security notes, schema tooltips
nfs-name = nfs
nfs-note-live-state = exports are enforced by the kernel on every mount; a wrong line silently changes which hosts can read which filesystems.
nfs-tip-entries = the exports in /etc/exports, in file order.
nfs-tip-path = the export point: an absolute directory path on this host.
nfs-tip-clients = the hosts allowed to mount this export, in match order; the first matching specification wins.
nfs-tip-host = the client specification: a name, address, address/netmask, wildcard, `*` (every client), or @netgroup.
nfs-tip-options = this client's export options, comma-separated; an empty list takes the file defaults.
nfs-rec-options = state rw/ro, sync/async, root_squash and subtree handling explicitly; defaults drift between nfs-utils releases.

## nfs module — validation diagnostics
nfs-empty-path = an export point is empty.
nfs-relative-path = `{$path}` is not absolute; an export point must start with `/`.
nfs-empty-host = a client of `{$path}` has no host specification.
nfs-invalid-option = `{$option}` is not a valid export option; options are bare tokens with no whitespace or parentheses.
nfs-no-root-squash = `{$host}` mounts with no_root_squash and keeps root privileges on the export.
nfs-sec-sys-only = `{$host}` negotiates only sec=sys; add krb5p for cryptographic protection.
nfs-world-export = `{$host}` is reachable read-write by every client.
nfs-subtree-undecided = `{$host}` states neither subtree_check nor no_subtree_check; upstream changed the default, so say which one you want.
nfs-root-squash-undecided = `{$host}` states neither root_squash nor no_root_squash; say which one you want.
nfs-sync-undecided = `{$host}` states neither sync nor async; prefer sync, which commits writes to stable storage.

## resolver module — display name, security notes, schema tooltips
resolver-name = resolver
resolver-note-managed-symlink = on this host /etc/resolv.conf is managed by a resolver backend; detent refuses to edit a managed symlink target and configures the backend instead.
resolver-tip-resolv = the /etc/resolv.conf directives this module models; anything else in the file is preserved untouched.
resolver-tip-resolved = the systemd-resolved settings, in file order. Changing them restarts systemd-resolved.
resolver-tip-unbound = the unbound.conf items this module models, in file order. Changing them restarts unbound.

## resolver module — validation diagnostics
resolver-no-nameserver = no nameserver is configured.
resolver-duplicate-nameserver = `{$ip}` appears as more than one nameserver.
resolver-too-many-nameservers = this file lists {$count} nameservers; glibc reads at most {$max}.
resolver-invalid-domain = `{$domain}` is not a valid domain name.
resolver-unknown-option = `{$option}` is not an option glibc's resolv.conf parser accepts.
resolver-search-and-domain = both `search` and `domain` are present; glibc ignores `domain` when `search` is set.
resolver-no-config = this model configures no resolver backend at all.
resolver-backend-missing = these settings configure {$service}, which was not detected on this host.
resolver-rec-dnssec = DNSSEC is set to allow-downgrade; `DNSSEC=yes` validates strictly and is recommended where upstream data allows it.
resolver-rec-dot = DNSOverTLS is opportunistic, which downgrades to plaintext; `DNSOverTLS=yes` requires TLS instead.
resolver-unknown-hardening = `{$key}` is not a directive this module models for unbound.
resolver-unbound-misplaced = `{$key}` belongs in the {$section} section of unbound.conf, not here.
resolver-invalid-forward-addr = `{$addr}` is not a valid forward-addr of the form ip[@port][#auth-name].
resolver-invalid-forward-name = `{$name}` is not a valid forward-zone name.
resolver-forward-tls-no-auth = this zone forwards over TLS without an `#auth-name` on its forward-addr, so the TLS connection is not authenticated.
resolver-rec-hardening = `{$key}` is disabled; enabling it hardens unbound against upstream spoofing and delegation abuse.
resolver-forward-zone-unnamed = a forward-zone: without a name: forwards nothing and weakens the config; give every zone a name.

## samba module — display name, security notes, schema tooltips
samba-name = samba
samba-note-guest-access = guest access is granted per share at connection time; a wrong value exposes files without a password.
samba-tip-entries = the smb.conf entries this module models, in file order: `[section]` headers and directives alike.
samba-tip-section = the section name for a `[section]` header; empty for a plain directive line.
samba-tip-key = the parameter name, case-insensitive and possibly multi-word (`guest ok`).
samba-tip-value = the value of the parameter, up to the end of the line; `%` macros are preserved verbatim.
samba-rec-value = prefer an explicit hardened value over relying on upstream's compiled-in default.

## samba module — validation diagnostics
samba-empty-key = a directive has no parameter name.
samba-empty-section = a section header is empty.
samba-guest-ok = `guest ok` is set to {$value}; unauthenticated clients can connect to every share that inherits it.
samba-map-to-guest = `map to guest` is {$value}; anything but Never turns failed logins into guest sessions.
samba-min-protocol = `server min protocol` is {$value}; set at least SMB3_00 and drop the SMB1-era protocol levels.
samba-smb-encrypt = `smb encrypt` is {$value}; set required so SMB traffic cannot travel unencrypted.
samba-restrict-anonymous = `restrict anonymous` is {$value}; 2 hides the share list from anonymous users.
samba-rec-server-signing = `server signing` is {$value}; set mandatory so SMB traffic is cryptographically signed.
samba-rec-load-printers = `load printers` is {$value}; set no unless this host actually shares printers.
samba-rec-interfaces = no `interfaces` directive is set; bind samba to explicit addresses instead of listening on every interface.

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
