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
cli-commit-recovered = recovered unconfirmed commit {$commit}; restored {$restored} targets with {$failures} failures.
cli-commit-confirm-needs-serve = this module requires commit-confirm; use the web UI or `detent serve` so the confirmation window remains enforced.
cli-config-load-failed = the configuration at {$path} could not be loaded: {$reason}
cli-no-command = no command was given.

## self-test probe and self-update (PLAN §2.9)
cli-self-test = version {$version} features {$features}
cli-update-available = update available: {$tag} published {$published}
cli-update-security-available = security update available: {$tag} published {$published}
cli-update-none = no update available (current {$current})
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

## serve
cli-serve-monitor = the worker started as pid {$pid}; privileges dropped: {$dropped}
cli-serve-worker = the worker is running; its http server arrives in phase 4. handshake: {$greeted}
cli-serve-failed = the monitor and worker could not be started: {$reason}
cli-serve-stopped = the pair stopped unexpectedly: {$reason} {$status}
cli-serve-privileged-port = port {$port} needs cap_net_bind_service or a monitor-passed socket, neither of which this build supports; use a port of 1024 or higher, or put a reverse proxy in front.
cli-serve-acme-unsupported = this build cannot bootstrap acme certificates yet; set tls.bootstrap to "self-signed" in {$path}.
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
cli-mcp-http-needs-privsep = mcp http transport cannot run as root: the network parser would share the root monitor process; run as a non-root user or use the stdio transport.
cli-mcp-bind-not-loopback = mcp http bind must be loopback (127.0.0.1 or ::1); the bearer is plaintext on the wire.
cli-dryrun-mcp = dry run: mcp would serve {$transport} on {$addr} with scope {$scope}.

## setup, user, token
cli-setup-exists = a user named `{$name}` already exists on this host; pass --force to overwrite it.
cli-setup-created = the administrator account `{$name}` was created.
cli-user-created = the account `{$name}` was created.
cli-user-passwd = the password for `{$name}` was changed.
cli-user-removed = the account `{$name}` was removed.
cli-token-created = token {$id} ({$label}) was created; it will not be shown again: {$token}
cli-token-revoked = token {$id} was revoked.
cli-token-no-tokens = no tokens have been issued.
cli-token-line = {$id}  {$label}  {$scopes}  {$created}  {$expires}
cli-credential-failed = the request could not be completed: {$reason}

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
