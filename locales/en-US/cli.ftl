## detent CLI — en-US
## Source of truth for every string the `detent` binary prints at runtime. IDs are
## referenced from crates/detent/src through `MessageId::new("cli-…")`; that crate's
## `cli_message_ids_and_the_catalogue_agree` test fails on an id used but not defined
## here, and on an id defined here but never used. clap's own --help/--version text is
## the one documented exception (see crates/detent/src/cli.rs).
##
## Identifiers — module ids, paths, unit names, digests, enum wire names such as
## `restart` or `active` — are interpolated verbatim and must not be translated.
## Keep alphabetized by section.

## severity words, prefixed to every rendered diagnostic
cli-severity-error = error
cli-severity-warning = warning
cli-severity-recommendation = note

## yes/no, used wherever a flag is rendered
cli-yes = yes
cli-no = no

## progress notes, printed on stderr under --verbose
cli-note-settings = locale {$locale}, state root {$state}, config {$config}
cli-note-operation = running {$operation} for {$module}

## failures that stop a command before the operations layer sees it
cli-bad-stdin = the model could not be read from stdin: {$reason}
cli-bad-json = the model on stdin is not valid json: {$reason}
cli-bad-hash = `{$value}` is not a sha-256 digest of 64 hex characters.
cli-start-failed = the privileged helper could not be started: {$reason}
cli-monitor-stop = the privileged helper did not stop cleanly: {$reason}
cli-monitor-busy = another detent monitor already owns this state root; retry through the web UI or run `detent serve`.
cli-monitor-lock-unavailable = the state lock in {$path} cannot be taken, so this command cannot change anything; run it as a user who can write that directory, or pass --state-root.
cli-commit-recovered = recovered unconfirmed commit {$commit}; restored {$restored} targets with {$failures} failures.
cli-commit-confirm-needs-serve = this module requires commit-confirm; use the web UI or `detent serve` so the confirmation window remains enforced.
cli-config-load-failed = the configuration at {$path} could not be loaded: {$reason}
cli-no-command = no command was given.

## self-test probe and self-update (PLAN §2.9)
cli-self-test = version {$version} features {$features}
cli-update-available = update available: {$tag} published {$published}
cli-update-security-available = security update available: {$tag} published {$published}
cli-update-none = no update available (current {$current})
cli-update-held-young = {$tag} is newer than {$current} but younger than {$days} day(s); the age gate holds it
cli-update-held-rejected = {$tag} is newer than {$current} but was rolled back on this host; it is skipped
cli-verify-bundle-ok = {$file} is attested for {$tag}
cli-update-failed = update failed: {$reason}
cli-update-installed = installed {$tag}; the binary it replaced is kept at {$previous}
cli-update-not-restarted = the service was not restarted, so the new binary is not running yet: {$reason}
cli-update-rolled-back = rolled back: {$reason}
cli-update-rollback-failed = the update failed ({$reason}) and the rollback also failed ({$error}); this host needs attention

## config
cli-module-line = {$id}  {$name}
cli-no-model = this module manages no file on this host yet, so there is no model to show.
cli-valid = this configuration is valid.
cli-plan-no-change = {$module} is already what {$path} contains; nothing would change.
cli-plan-service = applying this would affect {$unit}.
cli-plan-hash = the file now hashes to {$hash}; pass it as --expect-hash to refuse a racing edit.
cli-check-ran = the upstream validator {$program} ran; passed: {$passed}. {$detail}
cli-check-skipped = the upstream validator {$program} did not run. {$detail}
cli-applied = {$module} was written to {$path}.
cli-applied-hash = it hashed to {$prev} and now hashes to {$new}; backup kept: {$backup}
cli-mounts-off = mounts: activation is off ([mounts] activate_new_entries); new fstab entries take effect at the next boot or mount.
cli-mounts-error = mounts: no mount unit was started: {$reason}
cli-mounts-none = mounts: no new fstab entry to mount.
cli-mounts-unit = mount {$mountpoint} ({$unit}): {$state}
cli-mounts-unit-detail = mount {$mountpoint} ({$unit}): {$state}: {$detail}
cli-commit-armed = commit {$id} must be confirmed within {$seconds} seconds, by {$deadline}, or it is rolled back.
cli-commit-confirmed = commit {$id} is confirmed and will not be rolled back.
cli-commit-rolled-back = commit {$id} was rolled back; {$targets} targets were put back.

## backups
cli-no-backups = no backups have been kept for this module yet.
cli-backup-line = {$id}  {$name}  {$bytes} bytes  {$digest}
cli-restored = target {$target} was put back and now hashes to {$hash}.

## services
cli-service-status = {$unit} is {$state}; starts at boot: {$enabled}
cli-serviced = {$unit} was asked to {$action}; running now: {$active}

## host
cli-host-profile = {$hostname}: {$os}, init {$init}, {$ram} mib of ram
cli-host-service-version = installed {$service} is version {$version}
cli-host-backends = network backend {$network}, resolver backend {$resolver}, distro {$distro} {$version}
cli-host-note = detection note: {$note}

## audit
cli-no-audit = the audit log has no matching records.
cli-audit-line = {$ts}  {$who}  {$op}  {$module}  {$result}  {$error}

## --dryrun
cli-dryrun-apply = dry run: this is what would be written to {$path} for {$module}.
cli-dryrun-operation = dry run: {$operation} would run for {$module}.
cli-dryrun-nothing = dry run: nothing was changed.
cli-dryrun-serve = dry run: the monitor and worker would start with {$modules} modules and {$targets} targets, rooted at {$state}.
cli-dryrun-serve-mounts = dry run: after a mounts apply, the runner would start the mount units of new fstab entries (mounts.activate_new_entries = true).
cli-dryrun-cert-renew = dry run: would ask the server at {$address} (as {$name}) to renew its certificate now; nothing was sent.

## serve
cli-serve-monitor = the worker started as pid {$pid}; privileges dropped: {$dropped}
cli-serve-worker = the worker is running; its http server arrives in phase 4. handshake: {$greeted}
cli-serve-failed = the monitor and worker could not be started: {$reason}
cli-serve-stopped = the pair stopped unexpectedly: {$reason} {$status}
cli-serve-privileged-port = port {$port} needs cap_net_bind_service or a monitor-passed socket, neither of which this build supports; use a port of 1024 or higher, or put a reverse proxy in front.
cli-serve-privilege-mode = the configured privilege mode does not match this process, so the service did not start: {$reason}
cli-serve-acme-unsupported = this build has no dns-01 providers (feature acme-dns-providers), so it cannot obtain acme certificates; set tls.bootstrap to "self-signed" in {$path}.
cli-serve-acme-setting-missing = tls.bootstrap is "acme", but {$setting} is not set in {$path}.
cli-serve-acme-path-outside = {$setting} ({$value}) is not under the state root {$root}: the confined processes write only there.
cli-serve-acme-credentials-dir = the acme credentials directory {$path} could not be prepared: {$reason}
cli-serve-secrets-failed = the secrets file {$path} was refused: {$reason}
cli-serve-acme-secret-missing = acme.provider is set, but {$path} has no dns_provider secret in its [acme] table.
cli-serve-acme-provider-invalid = the dns-01 provider in acme.provider cannot be used: {$reason}
cli-serve-acme-providers-not-built = this build has no dns-01 providers (feature acme-dns-providers); remove [acme.provider] from {$path}.
cli-serve-handshake-failed = the worker could not complete its handshake with the monitor.
cli-serve-auth-failed = the account, token and session store could not be opened: {$reason}
cli-serve-tls-failed = the tls certificate could not be prepared: {$reason}
cli-serve-cert-fingerprint = tls bootstrap certificate fingerprint (sha-256): {$fingerprint}
cli-serve-web-failed = the web server could not start: {$reason}
cli-serve-web-stopped = the web server did not stop cleanly: {$reason}
cli-serve-listening = listening on {$addr}
cli-serve-confinement-degraded = confinement degraded: {$detail}
cli-mcp-missing-token = {$var} is not set; mint one with `detent token create` and export it before starting the mcp server.
cli-mcp-serve-failed = the mcp server could not start: {$reason}
cli-mcp-listening = mcp serving {$transport}
cli-mcp-http-needs-privsep = mcp http transport cannot run as root or with capabilities: the network parser would run with root-like power; run as a non-root user with no capabilities or use the stdio transport.
cli-mcp-bind-not-loopback = mcp http bind must be loopback (127.0.0.1 or ::1); the bearer is plaintext on the wire.
cli-dryrun-mcp = dry run: mcp would serve {$transport} on {$addr} with scope {$scope}.

## setup, user, token
cli-setup-exists = a user named `{$name}` already exists on this host; pass --force to overwrite it.
cli-setup-created = the administrator account `{$name}` was created.
cli-user-created = the account `{$name}` was created.
cli-user-passwd = the password for `{$name}` was changed.
cli-user-removed = the account `{$name}` was removed.
cli-totp-uri = add this to your authenticator application: {$uri}
cli-totp-secret = or type this key into it: {$secret}
cli-totp-code-prompt = code from your authenticator:
cli-totp-code-empty = a code may not be empty.
cli-totp-code-wrong = that code is not valid, so the second factor was not turned on.
cli-user-totp-enabled = the second factor for `{$name}` was turned on.
cli-totp-disable-prompt = turn off the second factor for `{$name}`? [y/N]
cli-totp-disable-cancelled = the second factor for `{$name}` was left on.
cli-user-totp-disabled = the second factor for `{$name}` was turned off.
cli-token-created = token {$id} ({$label}) was created; it will not be shown again: {$token}
cli-token-revoked = token {$id} was revoked.
cli-token-no-tokens = no tokens have been issued.
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = the request could not be completed: {$reason}
cli-audit-failed = the change was made, but its audit record could not be written: {$reason}
cli-state-command-as-root = detent {$command} must not run as root: the files it writes would belong to root, and the service could not read them. Run it as the service account instead: sudo -u {$account} detent {$command}

## cert status
cli-cert-source = source: {$source}
cli-cert-fingerprint = fingerprint (sha-256): {$fingerprint}
cli-cert-not-after = expires: {$not_after}
cli-cert-not-after-unknown = expiry: unknown (the certificate did not parse).
cli-cert-lifetime = lifetime used: {$percent} (warning: {$warning}).
cli-cert-lifetime-no-warning = lifetime used: {$percent} (no warning).
cli-cert-lifetime-unknown = lifetime used: unknown (the certificate did not parse).
cli-cert-missing = no certificate is stored in {$path}; start the server once so it writes one.
cli-cert-unreadable = the certificate in {$path} could not be read: {$reason}

## cert renew
cli-cert-renew-requested = renewal requested: the server asked its ACME client to renew now. Check the result with `detent cert status`.
cli-cert-renew-token-refused = the token was refused (HTTP {$status}); it needs write scope: `detent token create <name> --write`.
cli-cert-renew-not-acme = the server runs no ACME process (`tls.bootstrap` is not `acme`), so there is nothing to renew.
cli-cert-renew-server-error = the server answered HTTP {$status}: {$message_id}
cli-cert-renew-server-error-bare = the server answered HTTP {$status}.
cli-cert-renew-unreachable = could not talk to the server at {$address}: {$reason}
cli-cert-renew-no-token = no API token: pass --token-file <path> or set {$var}. Mint a write token with `detent token create <name> --write`.
cli-cert-renew-bad-token = the token from {$source} was refused: {$reason}
cli-cert-renew-ca-unreadable = the CA file {$path} could not be read: {$reason}

## password entry (setup, user add, user passwd)
cli-password-prompt = password:
cli-password-confirm = confirm password:
cli-password-mismatch = the passwords did not match.
cli-password-empty = a password may not be empty.

## doctor
cli-status-ok = ok
cli-status-warn = warn
cli-status-fail = fail
cli-doctor-modules = modules compiled into this build: {$detail}
cli-doctor-state-root = state directory {$detail}
cli-doctor-config = configuration file {$detail}
cli-doctor-privsep = privilege separation can fork a working pair: {$detail}
cli-doctor-landlock = landlock: {$detail}
cli-doctor-seccomp = seccomp: {$detail}
cli-doctor-confinement = sandbox confinement: {$detail}
cli-doctor-serve-confinement = confinement at the last serve start: {$detail}
cli-doctor-mounts = mount activation after an fstab apply: {$detail}
cli-doctor-privilege-mode = privilege mode: {$detail}
cli-doctor-service-account = service account: {$detail}
cli-doctor-state-owner = state directory owner: {$detail}
cli-doctor-backups-dir = backups directory: {$detail}
cli-doctor-polkit-rule = polkit rule: {$detail}
cli-doctor-polkit-daemon = polkit daemon: {$detail}
cli-doctor-unit-capabilities = service unit identity and capabilities: {$detail}
