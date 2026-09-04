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
