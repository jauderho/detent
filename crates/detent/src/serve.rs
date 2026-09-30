//! `detent serve`: the process model (PLAN §2.4, ADR-001).
//!
//! This is the one command that really forks:
//!
//! ```text
//! detent serve ──spawn_runner──▶ runner (child, privileged, not confined)
//!              ──spawn_pair──▶ monitor (this process, privileged, confined)
//!                              worker  (child, unprivileged, confined)
//!                                 │
//!                                 ├─ OpsEngine::new (client, registry, host)
//!                                 ├─ detent_web::spawn_engine ──▶ EngineHandle
//!                                 ├─ AuthState::open (users, tokens, sessions)
//!                                 ├─ tls::load_or_bootstrap ──▶ fingerprint logged
//!                                 └─ Server::bind ──▶ Server::serve(sigterm|sigint)
//! ```
//!
//! The monitor serves the closed privsep protocol until the worker asks it to
//! stop, then reaps the child and exits with the child's status. With the
//! `web` feature (the default) the worker runs the real `detent-web` server on
//! a `tokio` runtime built inside this one function — never process-wide, so
//! every other command keeps paying nothing for a runtime it never starts.
//! Without `web` the worker only proves the fork, the credential drop and the
//! handshake work end to end.
//!
//! # Confinement
//!
//! Unlike a one-shot command ([`crate::run`]), `serve` installs the real
//! Landlock/seccomp/capability policy through
//! [`detent_platform::sandbox::Hooks`], for both halves, at the one point in the
//! process lifetime where it is possible. That is irreversible for both
//! processes, which is exactly why no other command does it and why `doctor`
//! only reads what the kernel advertises.
//!
//! A seccomp filter also binds every child of the process that installed it,
//! so the monitor does not start validators or service commands itself. The
//! runner, forked before any confinement, runs them for it by allow-list id
//! (STAGE3 H6, [`detent_platform::privsep::runner`]).

use detent_core::diag::MessageId;
use detent_platform::privsep::allowlist::{Allowlist, Config};
use detent_platform::privsep::monitor::{
    DEFAULT_STAGING_DIR, ExitReason, Hooks, Monitor, MonitorError,
};
use detent_platform::privsep::runner::RunnerClient;
use detent_platform::privsep::spawn::{
    AcmeHandle, Role, RunnerHandle, SpawnConfig, SpawnError, abort_child, reap_child, spawn_pair,
    spawn_runner,
};
#[cfg(feature = "web")]
use detent_platform::privsep::transport::Channel;
use detent_platform::sandbox::{
    Confinement, Hooks as SandboxHooks, LandlockOutcome, LandlockStatus, Outcome, Policy,
};
#[cfg(feature = "web")]
use detent_platform::service;

use crate::output::{Exit, Renderer};
use crate::run::{Settings, Streams};

/// Lowest port a worker with no `CAP_NET_BIND_SERVICE` and no monitor-passed
/// socket may bind — neither of which this build implements (see
/// [`run`]'s port check).
#[cfg(feature = "web")]
const PRIVILEGED_PORT_CEILING: u16 = 1024;

/// Starts the pair, or explains why it could not.
///
/// # Errors
///
/// Whatever the streams report.
pub fn run(
    dryrun: bool,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    crate::run::init_tracing();
    let host = detent_platform::host::detect_real();
    let registry = detent_modules::modules();
    let descriptors: Vec<_> = registry.iter().map(|entry| entry.descriptor()).collect();
    let allow =
        match Allowlist::from_modules(&descriptors, &Config::with_state_root(&settings.state_root))
        {
            Ok(allow) => allow,
            Err(err) => {
                renderer.line(
                    streams.notes,
                    MessageId::new("cli-start-failed"),
                    &[("reason", &err.to_string())],
                )?;
                return Ok(Exit::Failed);
            }
        };

    #[cfg(feature = "web")]
    let (config, provider) = match preflight_web_config(settings, renderer, streams)? {
        Ok(checked) => checked,
        Err(exit) => return Ok(exit),
    };

    if dryrun {
        return report_dry_run(descriptors.len(), &allow, settings, renderer, streams);
    }

    let hooks = SandboxHooks::new(Policy::monitor(&allow), Policy::worker(&allow));
    // Nothing buffered may be inherited by a child that exits without flushing.
    streams.out.flush()?;
    streams.notes.flush()?;

    // Before the pair, so the monitor's confinement never reaches the
    // runner or the validators and service commands it starts.
    let runner = match start_runner(&allow, host.profile.init, renderer, streams)? {
        Ok(runner) => runner,
        Err(exit) => return Ok(exit),
    };

    // After the runner and before the pair (ADR-015): only when preflight
    // built a provider, that is with `tls.bootstrap = "acme"`.
    #[cfg(feature = "web")]
    let (hooks, acme, runner, config) = match provider {
        None => (hooks, None::<AcmeHandle>, runner, config),
        #[cfg(feature = "acme-dns-providers")]
        Some(provider) => {
            match start_acme(provider, hooks, runner, config, settings, renderer, streams)? {
                Ok(started) => started,
                Err(exit) => return Ok(exit),
            }
        }
    };
    #[cfg(not(feature = "web"))]
    let acme: Option<AcmeHandle> = None;

    let spawned = match start_pair(&hooks, renderer, streams)? {
        Ok(spawned) => spawned,
        Err(exit) => return Ok(exit),
    };

    match spawned.role {
        Role::Worker(client) => {
            // The worker must hold no way to reach the runner.
            drop(runner);
            // The child. It must never return into `main`, or the process tree
            // ends up with two copies of the CLI.
            #[cfg(feature = "web")]
            {
                report_confinement(&hooks, &settings.state_root, "worker", renderer, streams);
                // The worker keeps its end of the acme channel.
                let config = WorkerConfig {
                    web: config,
                    acme: acme.map(|acme| acme.channel),
                };
                let status =
                    run_worker(*client, host, registry, config, settings, renderer, streams);
                let _ = streams.out.flush();
                let _ = streams.notes.flush();
                abort_child(status);
            }
            #[cfg(not(feature = "web"))]
            {
                drop(acme);
                let mut client = client;
                let greeted = client.hello().is_ok();
                let _ = renderer.line(
                    streams.out,
                    MessageId::new("cli-serve-worker"),
                    &[("greeted", if greeted { "1" } else { "0" })],
                );
                let stopped = client.shutdown().is_ok();
                let _ = streams.out.flush();
                let _ = streams.notes.flush();
                abort_child(i32::from(!(greeted && stopped)));
            }
        }
        Role::Monitor(handle) => {
            // The monitor never talks to the acme process: it drops the
            // channel here and keeps only the pid, to reap it.
            let acme_pid = acme.map(|acme| acme.child_pid);
            report_confinement(&hooks, &settings.state_root, "monitor", renderer, streams);
            let exit = run_monitor(
                &host,
                allow,
                handle,
                runner,
                spawned.dropped_privileges,
                renderer,
                streams,
            );
            // Last, after the worker and the runner: the acme process ends
            // when the worker's end of its channel closes. The monitor has
            // no `CAP_KILL`, so it only waits. Not after a monitor failure,
            // when the worker may still run.
            if let (Ok(_), Some(acme_pid)) = (&exit, acme_pid) {
                reap_child(acme_pid);
            }
            exit
        }
    }
}

/// Describes what `serve` would start, without forking.
fn report_dry_run(
    modules: usize,
    allow: &Allowlist,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    renderer.line(
        streams.out,
        MessageId::new("cli-dryrun-serve"),
        &[
            ("modules", &modules.to_string()),
            ("targets", &allow.target_count().to_string()),
            ("state", &settings.state_root.display().to_string()),
        ],
    )?;
    Ok(Exit::Ok)
}

/// Forks the monitor/worker pair, or reports why it could not.
fn start_pair(
    hooks: &SandboxHooks,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Result<detent_platform::privsep::spawn::Spawned, Exit>> {
    match spawn_pair(&SpawnConfig::default(), hooks) {
        Ok(spawned) => Ok(Ok(spawned)),
        Err(err) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-serve-failed"),
                &[("reason", &err.to_string())],
            )?;
            Ok(Err(exit_for_spawn(&err)))
        }
    }
}

/// Forks the runner (STAGE3 H6), or reports why it could not.
fn start_runner(
    allow: &Allowlist,
    init: detent_core::descriptor::InitSystem,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Result<RunnerHandle, Exit>> {
    match spawn_runner(allow, std::path::Path::new(DEFAULT_STAGING_DIR), init) {
        Ok(runner) => Ok(Ok(runner)),
        Err(err) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-serve-failed"),
                &[("reason", &err.to_string())],
            )?;
            Ok(Err(exit_for_spawn(&err)))
        }
    }
}

/// What [`start_acme`] gives back: the hooks with the acme policy, the acme
/// handle, and the runner handle and configuration the child dropped.
#[cfg(all(feature = "web", feature = "acme-dns-providers"))]
type AcmeStarted = (
    SandboxHooks,
    Option<AcmeHandle>,
    RunnerHandle,
    detent_web::Config,
);

/// Forks the acme process (ADR-015) with the provider preflight built, or
/// reports why it could not.
///
/// The process drops `runner` and `config` first (they are its `inherited`
/// value) and keeps only the issuer (settings, provider and secret) and
/// `tls.cert_dir`. The caller gets `hooks` back with the acme policy,
/// the acme handle, and `runner` and `config` unchanged.
#[cfg(all(feature = "web", feature = "acme-dns-providers"))]
fn start_acme(
    provider: Provider,
    hooks: SandboxHooks,
    runner: RunnerHandle,
    config: detent_web::Config,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Result<AcmeStarted, Exit>> {
    let issuer =
        match crate::acme::AcmeIssuer::new(&config.acme, provider, crate::acme::ORDER_POLICY) {
            Ok(issuer) => issuer,
            Err(setting) => {
                // Dropping the runner handle closes its channel: the runner
                // ends, and is reaped here as on a spawn failure below.
                let runner_pid = runner.child_pid;
                drop(runner);
                reap_child(runner_pid);
                renderer.line(
                    streams.notes,
                    MessageId::new("cli-serve-acme-setting-missing"),
                    &[
                        ("setting", &format!("acme.{setting}")),
                        ("path", &settings.config_path.display().to_string()),
                    ],
                )?;
                return Ok(Err(Exit::Failed));
            }
        };
    // Preflight refused a credentials path without a parent. An empty path
    // here gives the process no writable directory: it fails closed.
    let credentials_dir = config
        .acme
        .credentials_path
        .as_deref()
        .and_then(std::path::Path::parent)
        .unwrap_or(std::path::Path::new(""));
    if let Err(err) = prepare_credentials_dir(credentials_dir, &settings.state_root) {
        let runner_pid = runner.child_pid;
        drop(runner);
        reap_child(runner_pid);
        renderer.line(
            streams.notes,
            MessageId::new("cli-serve-acme-credentials-dir"),
            &[
                ("path", &credentials_dir.display().to_string()),
                ("reason", &err.to_string()),
            ],
        )?;
        return Ok(Err(Exit::Failed));
    }
    let hooks = hooks.with_acme(Policy::acme(credentials_dir));
    let runner_pid = runner.child_pid;
    let cert_dir = config.tls.cert_dir.clone();
    match crate::acme::fork_acme(
        &SpawnConfig::default(),
        &hooks,
        issuer,
        cert_dir,
        (runner, config),
    ) {
        Ok((acme, (runner, config))) => Ok(Ok((hooks, Some(acme), runner, config))),
        Err(err) => {
            // `spawn_acme` dropped the runner channel with the error, so the
            // runner ends.
            reap_child(runner_pid);
            renderer.line(
                streams.notes,
                MessageId::new("cli-serve-failed"),
                &[("reason", &err.to_string())],
            )?;
            Ok(Err(exit_for_spawn(&err)))
        }
    }
}

/// Creates `dir`, the directory of `acme.credentials_path`, before the acme
/// process forks. Landlock skips a path that does not exist, and the acme
/// process may write nothing else, so it could not create the directory
/// itself. Each missing level is made `0700`; each level made here and `dir`
/// itself get the owner of `state_root` (the worker account, whose uid the
/// acme process runs as), and `dir` gets mode `0700`.
///
/// This process is root and the state root belongs to the worker, so no step
/// follows a symlink: the walk starts at `state_root` and opens each level
/// with `O_NOFOLLOW | O_DIRECTORY`, and the owner and mode are set through
/// the open descriptor.
///
/// # Errors
///
/// `InvalidInput` when `dir` is not under `state_root` (preflight refuses
/// that first), and the I/O error of the first step that fails.
#[cfg(all(feature = "web", feature = "acme-dns-providers"))]
fn prepare_credentials_dir(
    dir: &std::path::Path,
    state_root: &std::path::Path,
) -> std::io::Result<()> {
    use rustix::fs::{CWD, Gid, Mode, OFlags, Uid, fchmod, fchown, fstat, mkdirat, openat};
    use rustix::io::Errno;

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let private = Mode::from_bits_truncate(0o700);
    let relative = std::path::absolute(dir)?
        .strip_prefix(std::path::absolute(state_root)?)
        .map(std::path::Path::to_path_buf)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut level = openat(CWD, state_root, flags, Mode::empty())?;
    let root = fstat(&level)?;
    let owner = (
        Some(Uid::from_raw(root.st_uid)),
        Some(Gid::from_raw(root.st_gid)),
    );
    for part in relative.components() {
        if !matches!(part, std::path::Component::Normal(_)) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let created = match mkdirat(&level, part.as_os_str(), private) {
            Err(Errno::EXIST) => false,
            made => made.map(|()| true)?,
        };
        level = openat(&level, part.as_os_str(), flags, Mode::empty())?;
        if created {
            fchown(&level, owner.0, owner.1)?;
        }
    }
    fchown(&level, owner.0, owner.1)?;
    fchmod(&level, private)?;
    Ok(())
}

/// Read this process's confinement (just installed by `spawn_pair`), note
/// every degraded step, and persist it for doctor/UI (STAGE3 M2). `role` is
/// `monitor` or `worker`: each role writes its own record.
fn report_confinement(
    hooks: &SandboxHooks,
    state_root: &std::path::Path,
    role: &'static str,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) {
    let Some(confinement) = hooks.confinement() else {
        return;
    };
    for note in degradation_notes(confinement) {
        let _ = renderer.line(
            streams.notes,
            MessageId::new("cli-serve-confinement-degraded"),
            &[("detail", &note)],
        );
        tracing::warn!(detail = %note, "confinement degraded");
    }
    if let Err(err) = record_confinement(confinement, state_root, role) {
        tracing::warn!(error = %err, role, "confinement record not written");
    }
}

/// Directory under the state root that holds each role's confinement record.
pub(crate) const CONFINEMENT_DIR: &str = "state";
/// The roles that record their confinement, one file each.
pub(crate) const CONFINEMENT_ROLES: [&str; 2] = ["monitor", "worker"];

/// File name of `role`'s record inside [`CONFINEMENT_DIR`].
pub(crate) fn confinement_record_name(role: &str) -> String {
    format!("confinement-{role}.json")
}

/// Write `role`'s confinement to `<state_root>/state/confinement-<role>.json`.
///
/// The state root belongs to the worker, and the monitor writing here is
/// root, so no step follows a symlink: the directories are opened with
/// `O_NOFOLLOW | O_DIRECTORY`, an existing record that is not a regular file
/// is refused, and the bytes go to an `O_EXCL | O_NOFOLLOW` temp file that is
/// renamed over the record.
fn record_confinement(
    confinement: &Confinement,
    state_root: &std::path::Path,
    role: &str,
) -> std::io::Result<()> {
    use rustix::fs::{
        AtFlags, CWD, FileType, Gid, Mode, OFlags, Uid, fchown, fstat, mkdirat, openat, renameat,
        statat, unlinkat,
    };
    use rustix::io::Errno;
    use std::io::Write as _;

    let json = serde_json::to_vec_pretty(confinement).map_err(std::io::Error::other)?;
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    // `openat(CWD, …)`, not `open`: rustix issues `open(2)` for `open` on
    // x86_64, and the worker's seccomp table allows only `openat`.
    let root = openat(CWD, state_root, dir_flags, Mode::empty())?;
    let created = match mkdirat(&root, CONFINEMENT_DIR, Mode::from_bits_truncate(0o700)) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(err) => return Err(err.into()),
    };
    let dir = openat(&root, CONFINEMENT_DIR, dir_flags, Mode::empty())?;
    // The worker keeps its own state here too (`detent_web::auth`): a
    // directory the root monitor created must belong to the state root's
    // owner. Only a creator that is not that owner calls `fchown`: the worker
    // creates it as its own owner and never does, because its seccomp table
    // has no `fchown`.
    if created {
        let (owner, made) = (fstat(&root)?, fstat(&dir)?);
        if (made.st_uid, made.st_gid) != (owner.st_uid, owner.st_gid) {
            fchown(
                &dir,
                Some(Uid::from_raw(owner.st_uid)),
                Some(Gid::from_raw(owner.st_gid)),
            )?;
        }
    }
    let name = confinement_record_name(role);
    match statat(&dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile => {
            return Err(std::io::Error::other(format!(
                "{name} is not a regular file"
            )));
        }
        Ok(_) | Err(Errno::NOENT) => {}
        Err(err) => return Err(err.into()),
    }
    let tmp = format!(".{name}.tmp.{}", std::process::id());
    match unlinkat(&dir, tmp.as_str(), AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(err) => return Err(err.into()),
    }
    let fd = openat(
        &dir,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )?;
    let mut file = std::fs::File::from(fd);
    let written = file
        .write_all(&json)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            renameat(&dir, tmp.as_str(), &dir, name.as_str()).map_err(std::io::Error::from)
        });
    if let Err(err) = written {
        let _ = unlinkat(&dir, tmp.as_str(), AtFlags::empty());
        return Err(err);
    }
    Ok(())
}

/// Which confinement steps did not fully apply, as human-readable lines
/// (STAGE3 M2). Pure so the spec test pins it without a fork: every
/// non-`Applied` field names itself and its detail.
pub(crate) fn degradation_notes(confinement: &Confinement) -> Vec<String> {
    let mut notes = Vec::new();
    for (name, outcome) in [
        ("no_new_privs", &confinement.no_new_privs),
        ("dumpable", &confinement.dumpable_cleared),
        ("caps", &confinement.caps),
        ("seccomp", &confinement.seccomp),
    ] {
        if let Outcome::Unavailable { reason } | Outcome::Skipped { reason } = outcome {
            notes.push(format!("{name}: {reason}"));
        }
    }
    match &confinement.landlock {
        LandlockOutcome::Applied { abi, status } => {
            if *status != LandlockStatus::FullyEnforced {
                notes.push(format!("landlock: abi {abi} status {status:?}"));
            }
        }
        LandlockOutcome::Unavailable { reason } | LandlockOutcome::Skipped { reason } => {
            notes.push(format!("landlock: {reason}"));
        }
    }
    notes
}

/// The privileged side: serves the closed privsep protocol until the worker
/// asks it to stop, then reaps it and reports.
fn run_monitor(
    host: &detent_platform::host::Detected,
    allow: Allowlist,
    mut handle: detent_platform::privsep::spawn::MonitorHandle,
    runner: RunnerHandle,
    dropped_privileges: bool,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    renderer.line(
        streams.notes,
        MessageId::new("cli-serve-monitor"),
        &[
            ("pid", &handle.child_pid.to_string()),
            ("dropped", if dropped_privileges { "1" } else { "0" }),
        ],
    )?;
    // The monitor writes targets, backups and commit-confirm state, so it
    // must hold the real lock: refuse now rather than on the first write.
    let state_lock = match Monitor::lock_exclusive(allow.state_root()) {
        Ok(lock) => lock,
        Err(MonitorError::LockUnavailable) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-monitor-lock-unavailable"),
                &[("path", &allow.state_root().display().to_string())],
            )?;
            return Ok(Exit::Failed);
        }
        Err(err) => return Err(std::io::Error::other(err)),
    };
    let runner_pid = runner.child_pid;
    let client = RunnerClient::new(runner.channel, &allow);
    let mut monitor = Monitor::new(
        allow,
        Hooks {
            checks: &client,
            services: &client,
        },
    );
    report_recovery(renderer, streams, &monitor)?;
    monitor.set_host_profile(host.profile.clone());
    let served = monitor.serve_locked(&mut handle.channel, state_lock);
    let status = handle.wait();
    // Closing the channel stops the runner.
    drop(monitor);
    drop(client);
    reap_child(runner_pid);
    match (served, status) {
        (Ok(ExitReason::Shutdown), Ok(Some(0))) => Ok(Exit::Ok),
        (served, status) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-serve-stopped"),
                &[
                    ("reason", &format!("{served:?}")),
                    ("status", &format!("{status:?}")),
                ],
            )?;
            Ok(Exit::Failed)
        }
    }
}

fn report_recovery(
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
    monitor: &Monitor<'_>,
) -> std::io::Result<()> {
    let Some(recovered) = monitor.recover_pending().map_err(std::io::Error::other)? else {
        return Ok(());
    };
    renderer.line(
        streams.notes,
        MessageId::new("cli-commit-recovered"),
        &[
            ("commit", &recovered.commit.get().to_string()),
            ("restored", &recovered.restored.to_string()),
            ("failures", &recovered.failures.len().to_string()),
        ],
    )
}

/// A dns-01 provider with its secret, built by [`preflight_dns_provider`].
#[cfg(all(feature = "web", feature = "acme-dns-providers"))]
type Provider = Box<dyn detent_acme::DnsProvider>;

/// This build has no dns-01 providers, so preflight never yields one.
#[cfg(all(feature = "web", not(feature = "acme-dns-providers")))]
type Provider = std::convert::Infallible;

/// Loads and validates `detent.toml`, and rejects a listen port this build
/// cannot bind (see [`PRIVILEGED_PORT_CEILING`]). With `tls.bootstrap =
/// "acme"` it checks the `[acme]` settings ([`preflight_acme`]). When
/// `[acme.provider]` is set, it also checks the provider and its secret
/// ([`preflight_dns_provider`]).
///
/// The outer `Result` is an I/O failure while reporting; the inner one is
/// either the loaded configuration or the exit code already reported for it.
/// With the configuration comes the built provider when `tls.bootstrap =
/// "acme"`: the acme process takes it. A provider set without it is only
/// checked, and dropped here with its secret.
#[cfg(feature = "web")]
fn preflight_web_config(
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Result<(detent_web::Config, Option<Provider>), Exit>> {
    let config = match settings.load_web_config() {
        Ok(config) => config,
        Err(err) => {
            let exit = crate::run::report_web_config_error(&err, settings, renderer, streams)?;
            return Ok(Err(exit));
        }
    };
    if config.listen.addr.port() != 0 && config.listen.addr.port() < PRIVILEGED_PORT_CEILING {
        renderer.line(
            streams.notes,
            MessageId::new("cli-serve-privileged-port"),
            &[("port", &config.listen.addr.port().to_string())],
        )?;
        return Ok(Err(Exit::Failed));
    }
    let acme = config.tls.bootstrap == detent_web::Bootstrap::Acme;
    if acme && let Err(exit) = preflight_acme(&config, settings, renderer, streams)? {
        return Ok(Err(exit));
    }
    let provider = match &config.acme.provider {
        Some(provider) => match preflight_dns_provider(provider, settings, renderer, streams)? {
            Ok(provider) => Some(provider),
            Err(exit) => return Ok(Err(exit)),
        },
        None => None,
    };
    Ok(Ok((config, provider.filter(|_| acme))))
}

/// Checks `tls.bootstrap = "acme"`: every `[acme]` setting the acme
/// process needs is set, and the two directories the confined processes
/// write are under the state root. The acme process writes only the
/// directory of `acme.credentials_path` (`Policy::acme`); the worker writes
/// `tls.cert_dir` and may write only under the state root
/// (`Policy::worker`).
///
/// Same outer/inner `Result` split as [`preflight_web_config`].
#[cfg(all(feature = "web", feature = "acme-dns-providers"))]
fn preflight_acme(
    config: &detent_web::Config,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Result<(), Exit>> {
    let acme = &config.acme;
    let missing = [
        ("acme.directory_url", acme.directory_url.is_none()),
        ("acme.domains", acme.domains.is_empty()),
        ("acme.credentials_path", acme.credentials_path.is_none()),
        ("acme.provider", acme.provider.is_none()),
    ]
    .into_iter()
    .find_map(|(setting, missing)| missing.then_some(setting));
    if let Some(setting) = missing {
        renderer.line(
            streams.notes,
            MessageId::new("cli-serve-acme-setting-missing"),
            &[
                ("setting", setting),
                ("path", &settings.config_path.display().to_string()),
            ],
        )?;
        return Ok(Err(Exit::Failed));
    }
    let credentials = acme
        .credentials_path
        .as_deref()
        .unwrap_or(std::path::Path::new(""));
    let cert_dir = config.tls.cert_dir.as_path();
    for (setting, value, dir) in [
        ("acme.credentials_path", credentials, credentials.parent()),
        ("tls.cert_dir", cert_dir, Some(cert_dir)),
    ] {
        if !dir.is_some_and(|dir| lexically_under(dir, &settings.state_root)) {
            renderer.line(
                streams.notes,
                MessageId::new("cli-serve-acme-path-outside"),
                &[
                    ("setting", setting),
                    ("value", &value.display().to_string()),
                    ("root", &settings.state_root.display().to_string()),
                ],
            )?;
            return Ok(Err(Exit::Failed));
        }
    }
    Ok(Ok(()))
}

/// This build has no dns-01 providers, so it cannot obtain an ACME
/// certificate: `tls.bootstrap = "acme"` is refused.
#[cfg(all(feature = "web", not(feature = "acme-dns-providers")))]
fn preflight_acme(
    _config: &detent_web::Config,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Result<(), Exit>> {
    renderer.line(
        streams.notes,
        MessageId::new("cli-serve-acme-unsupported"),
        &[("path", &settings.config_path.display().to_string())],
    )?;
    Ok(Err(Exit::Failed))
}

/// True when `path` is `root` or under it. Both are made absolute and
/// compared by components; no symlink is followed. A path with a `..`
/// component is never under `root`.
#[cfg(all(feature = "web", feature = "acme-dns-providers"))]
fn lexically_under(path: &std::path::Path, root: &std::path::Path) -> bool {
    match (std::path::absolute(path), std::path::absolute(root)) {
        (Ok(path), Ok(root)) => {
            !path
                .components()
                .any(|part| part == std::path::Component::ParentDir)
                && path.starts_with(root)
        }
        _ => false,
    }
}

/// Checks `[acme.provider]` before the fork, while this process can still
/// read the `0600` `secrets.toml`: the file passes
/// [`detent_web::secrets::load`], it holds `[acme] dns_provider`, and the
/// provider builds from both. It returns the built provider: the secret is
/// read here, as root, before any fork, and only the acme process keeps it.
///
/// Same outer/inner `Result` split as [`preflight_web_config`].
#[cfg(feature = "web")]
fn preflight_dns_provider(
    provider: &detent_web::DnsProviderConfig,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Result<Provider, Exit>> {
    let path = settings.secrets_path();
    let secrets = match detent_web::secrets::load(&path) {
        Ok(secrets) => secrets,
        Err(err) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-serve-secrets-failed"),
                &[
                    ("path", &path.display().to_string()),
                    ("reason", &err.to_string()),
                ],
            )?;
            return Ok(Err(Exit::Failed));
        }
    };
    let Some(secret) = secrets.dns_provider() else {
        renderer.line(
            streams.notes,
            MessageId::new("cli-serve-acme-secret-missing"),
            &[("path", &path.display().to_string())],
        )?;
        return Ok(Err(Exit::Failed));
    };
    check_dns_provider(provider, secret, settings, renderer, streams)
}

/// Builds the provider from its settings and secret.
#[cfg(all(feature = "web", feature = "acme-dns-providers"))]
fn check_dns_provider(
    provider: &detent_web::DnsProviderConfig,
    secret: &detent_web::secrets::Secret,
    _settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Result<Provider, Exit>> {
    match build_dns_provider(provider, secret) {
        Ok(provider) => Ok(Ok(provider)),
        Err(err) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-serve-acme-provider-invalid"),
                &[("reason", &err.to_string())],
            )?;
            Ok(Err(Exit::Failed))
        }
    }
}

/// This build has no dns-01 providers, so a configured one is refused.
#[cfg(all(feature = "web", not(feature = "acme-dns-providers")))]
fn check_dns_provider(
    _provider: &detent_web::DnsProviderConfig,
    _secret: &detent_web::secrets::Secret,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Result<Provider, Exit>> {
    renderer.line(
        streams.notes,
        MessageId::new("cli-serve-acme-providers-not-built"),
        &[("path", &settings.config_path.display().to_string())],
    )?;
    Ok(Err(Exit::Failed))
}

/// The dns-01 provider `[acme.provider]` names, with its secret from
/// `secrets.toml`.
///
/// # Errors
///
/// The constructor's [`detent_acme::AcmeError`]. Its text never quotes the
/// secret: each constructor reports a bad secret with a fixed sentence.
#[cfg(all(feature = "web", feature = "acme-dns-providers"))]
fn build_dns_provider(
    provider: &detent_web::DnsProviderConfig,
    secret: &detent_web::secrets::Secret,
) -> Result<Box<dyn detent_acme::DnsProvider>, detent_acme::AcmeError> {
    use detent_web::DnsProviderConfig as Kind;
    let secret = secret.expose();
    Ok(match provider {
        Kind::Cloudflare { zone_id } => Box::new(detent_acme::CloudflareProvider::new(
            secret,
            zone_id.as_str(),
        )?),
        Kind::AcmeDns { server, username } => Box::new(detent_acme::AcmeDnsProvider::new(
            server.as_str(),
            username.as_str(),
            secret,
        )?),
        Kind::Desec { domain } => {
            Box::new(detent_acme::DeSecProvider::new(secret, domain.as_str())?)
        }
        Kind::Rfc2136 {
            server,
            zone,
            key_name,
            algorithm,
        } => Box::new(detent_acme::Rfc2136Provider::new(
            server.as_str(),
            zone.as_str(),
            key_name.as_str(),
            secret,
            algorithm.as_str(),
        )?),
    })
}

/// Runs the real `detent-web` server: the operations engine on its own
/// thread, the account/token/session stores, TLS 1.3 over a bootstrap
/// certificate, and the `/api/v1` surface — all on a `tokio` runtime built
/// right here, torn down when this function returns. No other command in
/// this crate ever builds one.
///
/// Returns the status [`abort_child`] should exit the worker with.
#[cfg(feature = "web")]
fn run_worker(
    client: detent_platform::privsep::worker::Client,
    host: detent_platform::host::Detected,
    registry: Vec<Box<dyn detent_core::module::DynModule>>,
    config: WorkerConfig,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> i32 {
    let Some(prepared) =
        prepare_worker(client, host, registry, config, settings, renderer, streams)
    else {
        return 1;
    };
    let PreparedWorker {
        runtime,
        server,
        engine_thread,
        sweeper: _sweeper,
    } = prepared;
    let _ = renderer.line(
        streams.notes,
        MessageId::new("cli-serve-listening"),
        &[("addr", &server.local_addr().to_string())],
    );
    // Runs until SIGTERM or SIGINT; then the accept loop stops and in-flight
    // connections get `server::SHUTDOWN_GRACE` to finish (`Server::serve`'s
    // own contract). Not exercised in-process: it blocks on a real process
    // signal, which a shared test harness has no safe way to deliver to only
    // this test (see `docs/spikes/m1-e2e.md` for the real-process run).
    runtime.block_on(server.serve(shutdown_signal()));

    // `router`/`state`/`server` are gone by now, taking the last `EngineHandle`
    // with them (`EngineThread::join`'s own contract), so this does not hang.
    match engine_thread.join() {
        Ok(()) => 0,
        Err(err) => {
            let _ = renderer.line(
                streams.notes,
                MessageId::new("cli-serve-web-stopped"),
                &[("reason", &err.to_string())],
            );
            1
        }
    }
}

/// What the worker is started with: `detent.toml`, and its end of the acme
/// channel when the acme process runs.
#[cfg(feature = "web")]
struct WorkerConfig {
    /// The loaded `detent.toml`.
    web: detent_web::Config,
    /// The worker's end of the acme channel.
    acme: Option<Channel>,
}

/// Everything [`run_worker`] needs before it can block on
/// [`serve`](detent_web::Server::serve): the runtime it will drive that call
/// with, the bound listener, and the engine thread to join afterwards.
#[cfg(feature = "web")]
struct PreparedWorker {
    /// Drives `server.serve(..)` and nothing else; built inside
    /// [`run_worker`]'s call, never process-wide.
    runtime: tokio::runtime::Runtime,
    /// Bound and ready; not yet serving.
    server: detent_web::Server,
    /// Joined once `server.serve(..)` returns.
    engine_thread: detent_web::EngineThread,
    /// The auth-state sweep, spawned on `runtime`; it ends with the stores.
    sweeper: tokio::task::JoinHandle<()>,
}

/// The handshake, the operations engine, the account/token/session stores,
/// the `tokio` runtime, and the bound TLS listener — everything up to but
/// not including the blocking `server.serve(..)` call, so this half of
/// [`run_worker`] is testable without a real process signal.
///
/// `None` on any failure; the caller has already been told why through
/// `renderer`.
#[cfg(feature = "web")]
fn prepare_worker(
    mut client: detent_platform::privsep::worker::Client,
    host: detent_platform::host::Detected,
    registry: Vec<Box<dyn detent_core::module::DynModule>>,
    config: WorkerConfig,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> Option<PreparedWorker> {
    use detent_ops::{AuditSink, FileAudit, OpsEngine};

    if client.hello().is_err() {
        let _ = renderer.line(
            streams.notes,
            MessageId::new("cli-serve-handshake-failed"),
            &[],
        );
        return None;
    }

    let ram_mib = host.profile.ram_mib;
    let init = host.profile.init;
    let mut hostnames = config.web.tls.hostnames.clone();
    hostnames.push(host.profile.hostname.clone());

    let audit: Box<dyn AuditSink> = Box::new(FileAudit::under_state_root(&settings.state_root));
    let mut engine = OpsEngine::new(registry, client, host, audit, service::for_host(init));
    engine.set_state_root(settings.state_root.clone());
    let (engine_handle, engine_thread) = detent_web::spawn_engine(engine);

    let auth_state =
        match detent_web::AuthState::open(&settings.state_root, &config.web.auth, ram_mib) {
            Ok(state) => state,
            Err(err) => {
                let _ = renderer.line(
                    streams.notes,
                    MessageId::new("cli-serve-auth-failed"),
                    &[("reason", &err.to_string())],
                );
                return None;
            }
        };

    // Built inside this one function, never process-wide: a one-shot command
    // must not pay for a runtime it never starts.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            let _ = renderer.line(
                streams.notes,
                MessageId::new("cli-serve-web-failed"),
                &[("reason", &err.to_string())],
            );
            return None;
        }
    };

    // The auth state was opened before this runtime existed, so its sweep
    // starts here, on the runtime that will drive `serve`.
    let sweeper = {
        let _entered = runtime.enter();
        auth_state.start_sweeper()
    };
    let server = runtime.block_on(bind_web_server(
        config,
        &hostnames,
        engine_handle,
        auth_state,
        settings.state_root.clone(),
        renderer,
        streams,
    ))?;
    Some(PreparedWorker {
        runtime,
        server,
        engine_thread,
        sweeper,
    })
}

/// Bootstraps or reuses the TLS certificate, logs its fingerprint for
/// trust-on-first-use, assembles the application state, and binds the
/// listener — everything between the operations engine being ready and the
/// server being ready to [`serve`](detent_web::Server::serve).
///
/// With `config.acme`, the worker's end of the acme channel, it splits the
/// channel and starts the thread that installs each certificate the acme
/// process sends into the store ([`crate::acme::spawn_installs`]) once the
/// store exists. The other half goes into the web state, for
/// `POST /api/v1/system/cert/renew`.
///
/// `None` on any failure; the caller has already been told why through
/// `renderer`.
#[cfg(feature = "web")]
async fn bind_web_server(
    config: WorkerConfig,
    hostnames: &[String],
    engine_handle: detent_web::EngineHandle,
    auth_state: detent_web::AuthState,
    state_root: std::path::PathBuf,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> Option<detent_web::Server> {
    let tls_failed =
        |err: &dyn std::fmt::Display, renderer: &Renderer<'_>, streams: &mut Streams<'_>| {
            let _ = renderer.line(
                streams.notes,
                MessageId::new("cli-serve-tls-failed"),
                &[("reason", &err.to_string())],
            );
        };
    let WorkerConfig { web: config, acme } = config;

    // A renewed pair survives a restart: prefer the stored ACME chain over
    // the bootstrap pair, whose fingerprint stays the TOFU anchor until the
    // first renewal lands.
    let cert = match detent_web::serving_pair(&config.tls.cert_dir) {
        Ok(Some(pair)) => pair,
        Ok(None) => match detent_web::load_or_bootstrap(
            &config.tls.cert_dir,
            hostnames,
            config.tls.bootstrap == detent_web::Bootstrap::Acme,
        ) {
            Ok(cert) => cert,
            Err(err) => {
                tls_failed(&err, renderer, streams);
                return None;
            }
        },
        Err(err) => {
            tls_failed(&err, renderer, streams);
            return None;
        }
    };
    // Trust-on-first-use: this is the operator's only way to verify the
    // bootstrap certificate, so it must reach the journal every start, not
    // only under --verbose.
    let _ = renderer.line(
        streams.notes,
        MessageId::new("cli-serve-cert-fingerprint"),
        &[("fingerprint", &cert.fingerprint())],
    );
    let store = match detent_web::CertStore::new(&cert) {
        Ok(store) => store,
        Err(err) => {
            tls_failed(&err, renderer, streams);
            return None;
        }
    };
    let store = std::sync::Arc::new(store);
    #[cfg(feature = "acme-dns-providers")]
    let renewer = acme.and_then(|channel| {
        crate::acme::spawn_installs(
            channel,
            config.acme.domains.clone(),
            config.tls.cert_dir.clone(),
            std::sync::Arc::clone(&store),
        )
        .inspect_err(|err| tracing::warn!(reason = %err, "the worker cannot start its acme thread"))
        .ok()
    });
    #[cfg(not(feature = "acme-dns-providers"))]
    drop(acme);
    let tls_config = match detent_web::server_config_from_store(
        std::sync::Arc::clone(&store),
        detent_web::tls::ALPN_H2_HTTP11,
    ) {
        Ok(tls_config) => tls_config,
        Err(err) => {
            tls_failed(&err, renderer, streams);
            return None;
        }
    };

    let origin = detent_web::Origin::for_config(&config);
    let state = detent_web::AppState::new(
        engine_handle,
        auth_state,
        config,
        origin,
        std::sync::Arc::clone(&store),
        state_root,
    );
    #[cfg(feature = "acme-dns-providers")]
    let state = match renewer {
        Some((_thread, renewer)) => state.with_cert_renewer(std::sync::Arc::new(renewer)),
        None => state,
    };
    let bind_config = std::sync::Arc::clone(&state.config);
    let router = detent_web::router(state);

    match detent_web::Server::bind(&bind_config, tls_config, router).await {
        Ok(server) => Some(server),
        Err(err) => {
            let _ = renderer.line(
                streams.notes,
                MessageId::new("cli-serve-web-failed"),
                &[("reason", &err.to_string())],
            );
            None
        }
    }
}

/// Resolves on `SIGTERM` or `SIGINT`, for [`run_worker`]'s graceful shutdown.
///
/// If this process cannot register a signal handler at all (an exhausted
/// signal slot, on some platform), the future is left pending rather than
/// resolving immediately — the worker keeps serving, and the operator still
/// has `SIGKILL`.
#[cfg(feature = "web")]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(mut terminate), Ok(mut interrupt)) => {
            tokio::select! {
                () = async { let _ = terminate.recv().await; } => {},
                () = async { let _ = interrupt.recv().await; } => {},
            }
        }
        _ => std::future::pending::<()>().await,
    }
}

/// A spawn failure that is about credentials is a privilege problem; anything
/// else is an operational failure.
fn exit_for_spawn(error: &SpawnError) -> Exit {
    match *error {
        SpawnError::Account(_) | SpawnError::DropPrivileges { .. } => Exit::Privilege,
        _ => Exit::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Confinement, Exit, LandlockOutcome, LandlockStatus, Outcome, degradation_notes,
        exit_for_spawn, record_confinement, report_recovery, run,
    };
    use crate::i18n::Messages;
    use crate::output::Renderer;
    use crate::run::{Settings, Streams};
    use detent_platform::privsep::allowlist::Config as AllowConfig;
    use detent_platform::privsep::monitor::{
        Hooks as MonitorHooks, Monitor, PENDING_COMMIT_MARKER, PendingCommitMarker, RollbackEntry,
    };
    use detent_platform::privsep::proto::CommitId;
    use detent_platform::privsep::spawn::SpawnError;
    use detent_platform::privsep::users::LookupError;
    use std::path::PathBuf;

    type R = Result<(), Box<dyn std::error::Error>>;

    /// The real fork is never exercised in-process: `spawn_pair` here installs
    /// the production Landlock/seccomp policy on *this* process (see the module
    /// docs), which cannot be undone and would poison every test that follows on
    /// the same harness thread. `detent doctor`'s privsep probe covers the fork
    /// itself with `NoSandbox`, and `docs/spikes/m1-e2e.md` runs `serve` for
    /// real.
    #[test]
    fn a_dry_run_describes_the_pair_without_forking() -> R {
        let messages = Messages::new(Some("en-US"));
        let renderer = Renderer {
            messages: &messages,
            json: false,
            verbose: true,
        };
        let dir = tempfile::TempDir::new()?;
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = run(
            true,
            &Settings {
                state_root: dir.path().to_path_buf(),
                config_path: PathBuf::from("/etc/detent/detent.toml"),
            },
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        let text = String::from_utf8(out)?;
        assert!(!text.is_empty());
        assert!(!text.contains("cli-dryrun"), "{text}");
        Ok(())
    }

    #[test]
    fn run_monitor_recovers_a_leftover_marker() -> R {
        let dir = tempfile::TempDir::new()?;
        let state = dir.path().join("state");
        let target = dir.path().join("target.conf");
        let backup = dir.path().join("target.conf.v1");
        std::fs::create_dir_all(&state)?;
        std::fs::write(&target, b"v2")?;
        std::fs::write(&backup, b"v1")?;
        std::fs::write(
            state.join(PENDING_COMMIT_MARKER),
            serde_json::to_vec(&PendingCommitMarker {
                commit: CommitId(7).get(),
                deadline_unix_ms: 0,
                entries: vec![RollbackEntry {
                    target: 0,
                    path: target.clone(),
                    backup,
                    new_digest: None,
                }],
                service: None,
            })?,
        )?;
        let allow = detent_platform::privsep::allowlist::Allowlist::from_modules(
            &[],
            &AllowConfig::with_state_root(&state),
        )?;
        let monitor = Monitor::new(allow, MonitorHooks::default());
        let messages = Messages::new(Some("en-US"));
        let renderer = Renderer {
            messages: &messages,
            json: false,
            verbose: true,
        };
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        report_recovery(
            &renderer,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
            &monitor,
        )?;
        assert_eq!(std::fs::read(&target)?, b"v1");
        assert!(!state.join(PENDING_COMMIT_MARKER).exists());
        assert!(String::from_utf8(notes)?.contains("commit 7"));
        Ok(())
    }

    #[test]
    fn a_missing_landlock_is_reported_at_startup() {
        use detent_platform::sandbox::{Confinement, LandlockOutcome, Outcome};
        let full = Confinement {
            no_new_privs: Outcome::Applied,
            dumpable_cleared: Outcome::Applied,
            caps: Outcome::Applied,
            landlock: LandlockOutcome::Applied {
                abi: 1,
                status: detent_platform::sandbox::LandlockStatus::FullyEnforced,
            },
            seccomp: Outcome::Applied,
        };
        assert!(degradation_notes(&full).is_empty());
        let degraded = Confinement {
            landlock: LandlockOutcome::Unavailable {
                reason: "old kernel".to_owned(),
            },
            ..full.clone()
        };
        let notes = degradation_notes(&degraded);
        assert_eq!(notes, vec!["landlock: old kernel".to_owned()]);
        for status in [
            detent_platform::sandbox::LandlockStatus::PartiallyEnforced,
            detent_platform::sandbox::LandlockStatus::NotEnforced,
        ] {
            let partial = Confinement {
                landlock: LandlockOutcome::Applied { abi: 1, status },
                ..full.clone()
            };
            let notes = degradation_notes(&partial);
            assert_eq!(notes.len(), 1, "status {status:?} must be reported");
            assert!(
                notes
                    .first()
                    .is_some_and(|note| note.starts_with("landlock:")),
                "note: {notes:?}",
            );
        }
    }

    fn full_confinement() -> Confinement {
        Confinement {
            no_new_privs: Outcome::Applied,
            dumpable_cleared: Outcome::Applied,
            caps: Outcome::Applied,
            landlock: LandlockOutcome::Applied {
                abi: 1,
                status: LandlockStatus::FullyEnforced,
            },
            seccomp: Outcome::Applied,
        }
    }

    fn no_landlock() -> Confinement {
        Confinement {
            landlock: LandlockOutcome::Unavailable {
                reason: "old kernel".to_owned(),
            },
            ..full_confinement()
        }
    }

    #[test]
    fn each_role_writes_its_own_confinement_record() -> R {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::TempDir::new()?;
        record_confinement(&full_confinement(), dir.path(), "monitor")?;
        record_confinement(&no_landlock(), dir.path(), "worker")?;
        let outcome = |role: &str| -> Result<String, Box<dyn std::error::Error>> {
            let path = dir.path().join(format!("state/confinement-{role}.json"));
            let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
            Ok(json
                .pointer("/landlock/outcome")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned())
        };
        assert_eq!(outcome("monitor")?, "applied");
        assert_eq!(outcome("worker")?, "unavailable");
        let (root, state) = (
            std::fs::metadata(dir.path())?,
            std::fs::metadata(dir.path().join("state"))?,
        );
        assert_eq!((state.uid(), state.gid()), (root.uid(), root.gid()));
        Ok(())
    }

    /// Confines the forked child with `policy` as `role`, and leaves this
    /// (test) process unconfined.
    struct ConfineChildAs(
        detent_platform::sandbox::Role,
        detent_platform::sandbox::Policy,
    );

    impl detent_platform::privsep::spawn::SandboxHooks for ConfineChildAs {
        fn confine_worker(&self) -> Result<(), detent_platform::privsep::spawn::SandboxError> {
            detent_platform::sandbox::confine(self.0, &self.1)
                .map(|_| ())
                .map_err(|err| detent_platform::privsep::spawn::SandboxError(err.to_string()))
        }
    }

    /// Fork, confine the child with `role`'s production policy, and have it
    /// record its confinement into a state root with no `state/` yet. The
    /// record is written after confinement in `serve`, so every syscall on
    /// its path must be in that role's seccomp table.
    fn record_in_a_confined_child(role: detent_platform::sandbox::Role, name: &str) -> R {
        use detent_platform::privsep::allowlist::Allowlist;
        use detent_platform::privsep::spawn::{
            Role, SpawnConfig, abort_confined_child, spawn_pair,
        };
        use detent_platform::sandbox::Policy;

        let dir = tempfile::TempDir::new()?;
        let state_root = dir.path().join("root");
        std::fs::create_dir(&state_root)?;
        let allow = Allowlist::from_modules(&[], &AllowConfig::with_state_root(&state_root))?;
        let policy = match role {
            // What is under test is the syscall set of the record path, so
            // the capability cut stays optional here: an unprivileged run (CI)
            // cannot shrink its bounding set, and `require_caps` would stop
            // the child before it records anything.
            detent_platform::sandbox::Role::Monitor => Policy {
                require_caps: false,
                ..Policy::monitor(&allow)
            },
            detent_platform::sandbox::Role::Worker => Policy::worker(&allow),
            detent_platform::sandbox::Role::Acme => Policy::acme(&state_root),
        };
        let spawned = spawn_pair(&SpawnConfig::unprivileged(), &ConfineChildAs(role, policy))?;
        match spawned.role {
            Role::Worker(_client) => {
                let ok = record_confinement(&full_confinement(), &state_root, name).is_ok();
                abort_confined_child(i32::from(!ok));
            }
            Role::Monitor(handle) => {
                assert_eq!(
                    handle.wait()?,
                    Some(0),
                    "child exited non-zero or was killed by a signal"
                );
                assert!(
                    state_root
                        .join(format!("state/confinement-{name}.json"))
                        .is_file()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn a_confined_worker_records_its_confinement_on_a_first_start() -> R {
        record_in_a_confined_child(detent_platform::sandbox::Role::Worker, "worker")
    }

    #[test]
    fn a_confined_monitor_records_its_confinement_on_a_first_start() -> R {
        record_in_a_confined_child(detent_platform::sandbox::Role::Monitor, "monitor")
    }

    #[test]
    fn the_confinement_record_is_never_written_through_a_symlink() -> R {
        let dir = tempfile::TempDir::new()?;
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"victim")?;
        std::fs::create_dir(dir.path().join("state"))?;
        std::os::unix::fs::symlink(&victim, dir.path().join("state/confinement-monitor.json"))?;
        assert!(record_confinement(&full_confinement(), dir.path(), "monitor").is_err());
        assert_eq!(std::fs::read(&victim)?, b"victim");
        Ok(())
    }

    #[test]
    fn the_confinement_record_refuses_a_symlinked_state_directory() -> R {
        let dir = tempfile::TempDir::new()?;
        let root = dir.path().join("root");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&root)?;
        std::fs::create_dir(&elsewhere)?;
        std::os::unix::fs::symlink(&elsewhere, root.join("state"))?;
        assert!(record_confinement(&full_confinement(), &root, "monitor").is_err());
        assert_eq!(std::fs::read_dir(&elsewhere)?.count(), 0);
        Ok(())
    }

    #[test]
    fn a_credential_failure_is_a_privilege_problem() {
        assert_eq!(
            exit_for_spawn(&SpawnError::Account(LookupError::NotFound(
                "detent".to_owned()
            ))),
            Exit::Privilege
        );
        assert_eq!(
            exit_for_spawn(&SpawnError::DropPrivileges {
                uid: 1,
                source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            }),
            Exit::Privilege
        );
        assert_eq!(
            exit_for_spawn(&SpawnError::Fork(std::io::Error::from(
                std::io::ErrorKind::WouldBlock
            ))),
            Exit::Failed
        );
    }
}

/// Everything that does not need a real fork: `preflight_web_config`'s
/// checks, and `bind_web_server`'s TLS/state/listener assembly against a
/// real (in-process, unprivileged) operations engine. The fork itself, the
/// `tokio` runtime `run_worker` builds, and `shutdown_signal`'s wait for a
/// real `SIGTERM`/`SIGINT` are not exercised here for the same reason
/// `spawn_pair` is not in `tests` above — see `docs/spikes/m1-e2e.md` for the
/// real-process run.
#[cfg(all(test, feature = "web"))]
mod web_tests {
    use super::{bind_web_server, preflight_web_config, run, run_monitor};
    use crate::i18n::Messages;
    use crate::output::{Exit, Renderer};
    use crate::run::Settings;
    use detent_core::descriptor::InitSystem;
    use detent_ops::{NullAudit, OpsEngine};
    use detent_platform::host::Detected;
    use detent_platform::privsep::allowlist::{Allowlist, Config as AllowConfig};
    use detent_platform::privsep::monitor::{Hooks as MonitorHooks, Monitor};
    use detent_platform::privsep::spawn::{MonitorHandle, RunnerHandle};
    use detent_platform::privsep::transport::Channel;
    use detent_platform::privsep::worker::Client;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    type R = Result<(), Box<dyn std::error::Error>>;

    fn renderer(messages: &Messages) -> Renderer<'_> {
        Renderer {
            messages,
            json: false,
            verbose: true,
        }
    }

    fn settings(root: &std::path::Path, config_path: std::path::PathBuf) -> Settings {
        Settings {
            state_root: root.to_path_buf(),
            config_path,
        }
    }

    /// A working `EngineHandle`/`EngineThread` pair over a real (but
    /// unprivileged, in-process) monitor thread — the same construction
    /// `detent-web`'s own `engine::tests::Fixture` uses, built here from the
    /// public API because `bind_web_server` needs a real handle: nothing in
    /// this crate can forge one.
    fn engine_fixture(
        state_root: &std::path::Path,
    ) -> Result<
        (
            detent_web::EngineHandle,
            detent_web::EngineThread,
            std::thread::JoinHandle<()>,
        ),
        Box<dyn std::error::Error>,
    > {
        let allow = Allowlist::from_modules(&[], &AllowConfig::with_state_root(state_root))?;
        let (monitor_end, worker_end) = Channel::pair()?;
        let monitor = std::thread::spawn(move || {
            let mut channel = monitor_end;
            // Shown with the failing test's output: a monitor that stops
            // before the handshake otherwise surfaces only as `Channel(Closed)`.
            if let Err(err) = Monitor::new(allow, MonitorHooks::default()).serve(&mut channel) {
                eprintln!("engine_fixture monitor stopped: {err:?}");
            }
        });
        let mut client = Client::new(worker_end);
        client.hello()?;
        let engine = OpsEngine::new(
            Vec::new(),
            client,
            Detected::default(),
            Box::new(NullAudit),
            detent_platform::service::for_host(InitSystem::Systemd),
        );
        let (handle, thread) = detent_web::spawn_engine(engine);
        Ok((handle, thread, monitor))
    }

    /// `config`, with no acme process.
    fn worker_config(config: detent_web::Config) -> super::WorkerConfig {
        super::WorkerConfig {
            web: config,
            acme: None,
        }
    }

    fn cheap_web_config(dir: &std::path::Path) -> detent_web::Config {
        detent_web::Config {
            listen: detent_web::ListenConfig {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                ..detent_web::ListenConfig::default()
            },
            tls: detent_web::TlsConfig {
                cert_dir: dir.join("certs"),
                ..detent_web::TlsConfig::default()
            },
            auth: detent_web::AuthConfig {
                argon2: detent_web::Argon2Params {
                    m_kib: Some(8),
                    t: 1,
                    p: 1,
                },
                ..detent_web::AuthConfig::default()
            },
            ..detent_web::Config::default()
        }
    }

    #[test]
    fn preflight_accepts_the_documented_defaults() -> R {
        let dir = tempfile::TempDir::new()?;
        let settings = settings(dir.path(), dir.path().join("absent.toml"));
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let outcome = preflight_web_config(
            &settings,
            &renderer,
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert!(outcome.is_ok(), "{:?}", outcome.as_ref().err());
        Ok(())
    }

    #[test]
    fn preflight_refuses_a_malformed_file_a_privileged_port_and_acme() -> R {
        let dir = tempfile::TempDir::new()?;
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);

        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "not toml")?;
        let cases = [
            (bad, None::<&str>),
            (
                dir.path().join("absent.toml"),
                Some("[listen]\naddr = \"127.0.0.1:80\"\n"),
            ),
            (
                dir.path().join("absent2.toml"),
                Some("[tls]\nbootstrap = \"acme\"\n"),
            ),
        ];
        for (path, contents) in cases {
            if let Some(contents) = contents {
                std::fs::write(&path, contents)?;
            }
            let settings = settings(dir.path(), path.clone());
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let mut input = std::io::empty();
            let outcome = preflight_web_config(
                &settings,
                &renderer,
                &mut crate::run::Streams {
                    input: &mut input,
                    out: &mut out,
                    notes: &mut notes,
                },
            )?;
            assert_eq!(outcome.err(), Some(Exit::Failed), "{path:?}");
            assert!(!notes.is_empty(), "{path:?}");
        }
        Ok(())
    }

    /// A Cloudflare zone id that the constructor accepts.
    const ZONE_ID: &str = "0123456789abcdef0123456789abcdef";

    /// Writes `detent.toml` with `provider` as `[acme.provider]`, and, when
    /// `secrets` is set, `secrets.toml` next to it with `mode`. Then runs
    /// `preflight_web_config` and returns its outcome and the notes.
    fn preflight_with(
        provider: &str,
        secrets: Option<(&str, u32)>,
    ) -> Result<(Result<(), Exit>, String), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::TempDir::new()?;
        let config_path = dir.path().join("detent.toml");
        std::fs::write(&config_path, format!("[acme.provider]\n{provider}"))?;
        if let Some((text, mode)) = secrets {
            let path = dir.path().join("secrets.toml");
            std::fs::write(&path, text)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        }
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let outcome = preflight_web_config(
            &settings(dir.path(), config_path),
            &renderer,
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        Ok((outcome.map(drop), String::from_utf8(notes)?))
    }

    fn cloudflare() -> String {
        format!("kind = \"cloudflare\"\nzone_id = \"{ZONE_ID}\"\n")
    }

    fn secret_file(value: &str) -> String {
        format!("[acme]\ndns_provider = \"{value}\"\n")
    }

    #[test]
    fn preflight_refuses_a_secrets_file_it_cannot_trust() -> R {
        let (outcome, notes) = preflight_with(
            &cloudflare(),
            Some((&secret_file("not-a-real-token"), 0o644)),
        )?;
        assert_eq!(outcome, Err(Exit::Failed));
        assert!(notes.contains("secrets.toml"), "{notes}");
        assert!(notes.contains("was refused"), "{notes}");
        assert!(!notes.contains("not-a-real-token"), "{notes}");
        Ok(())
    }

    #[test]
    fn preflight_refuses_a_provider_without_its_secret() -> R {
        for secrets in [None, Some(("[acme]\n", 0o600))] {
            let (outcome, notes) = preflight_with(&cloudflare(), secrets)?;
            assert_eq!(outcome, Err(Exit::Failed), "{secrets:?}");
            assert!(notes.contains("dns_provider"), "{notes}");
            assert!(notes.contains("secrets.toml"), "{notes}");
        }
        Ok(())
    }

    #[test]
    fn preflight_does_not_read_secrets_when_no_provider_is_set() -> R {
        let dir = tempfile::TempDir::new()?;
        let config_path = dir.path().join("detent.toml");
        std::fs::write(&config_path, "[acme]\ndomains = [\"box.example\"]\n")?;
        // A secrets path that `load` would refuse: it is not read at all.
        std::fs::create_dir(dir.path().join("secrets.toml"))?;
        let messages = Messages::new(Some("en-US"));
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let outcome = preflight_web_config(
            &settings(dir.path(), config_path),
            &renderer(&messages),
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert!(outcome.is_ok(), "{:?}", outcome.as_ref().err());
        assert!(notes.is_empty(), "{}", String::from_utf8_lossy(&notes));
        Ok(())
    }

    #[cfg(feature = "acme-dns-providers")]
    #[test]
    fn preflight_builds_each_configured_provider() -> R {
        let tsig = "czNjcjN0LWtleQ==";
        for (provider, value) in [
            (cloudflare(), "not-a-real-token"),
            (
                "kind = \"acme-dns\"\nserver = \"https://auth.example\"\nusername = \"sub\"\n"
                    .to_owned(),
                "not-a-real-password",
            ),
            (
                "kind = \"desec\"\ndomain = \"example.com\"\n".to_owned(),
                "not-a-real-token",
            ),
            (
                "kind = \"rfc2136\"\nserver = \"ns1.example.com:53\"\nzone = \"example.com\"\n\
                 key_name = \"k.example.com\"\nalgorithm = \"hmac-sha256\"\n"
                    .to_owned(),
                tsig,
            ),
        ] {
            let (outcome, notes) = preflight_with(&provider, Some((&secret_file(value), 0o600)))?;
            assert_eq!(outcome, Ok(()), "{provider}: {notes}");
        }
        Ok(())
    }

    #[cfg(feature = "acme-dns-providers")]
    #[test]
    fn preflight_refuses_a_provider_that_does_not_build_and_quotes_no_secret() -> R {
        let bad = "not a real token";
        for (provider, value) in [
            (cloudflare(), bad),
            (
                "kind = \"cloudflare\"\nzone_id = \"short\"\n".to_owned(),
                "not-a-real-token",
            ),
            (
                "kind = \"acme-dns\"\nserver = \"https://auth.example\"\nusername = \"sub\"\n"
                    .to_owned(),
                bad,
            ),
            (
                "kind = \"desec\"\ndomain = \"example.com\"\n".to_owned(),
                bad,
            ),
            (
                "kind = \"rfc2136\"\nserver = \"ns1.example.com:53\"\nzone = \"example.com\"\n\
                 key_name = \"k.example.com\"\nalgorithm = \"hmac-sha256\"\n"
                    .to_owned(),
                bad,
            ),
        ] {
            let (outcome, notes) = preflight_with(&provider, Some((&secret_file(value), 0o600)))?;
            assert_eq!(outcome, Err(Exit::Failed), "{provider}");
            assert!(notes.contains("cannot be used"), "{notes}");
            assert!(!notes.contains(value), "{notes}");
        }
        Ok(())
    }

    /// A stand-in secret: low entropy on purpose (CI runs gitleaks).
    const SECRET: &str = "not-a-real-token";

    /// A `detent.toml` with `tls.bootstrap = "acme"` and every `[acme]`
    /// setting the acme process needs, its paths under `root`.
    fn complete_acme(root: &std::path::Path) -> String {
        format!(
            "[tls]\nbootstrap = \"acme\"\ncert_dir = \"{root}/certs\"\n\n\
             [acme]\ndirectory_url = \"https://127.0.0.1:9/dir\"\n\
             domains = [\"box.example\"]\n\
             credentials_path = \"{root}/acme/account.json\"\n\n\
             [acme.provider]\n{}",
            cloudflare(),
            root = root.display(),
        )
    }

    /// `text` without the lines that start with one of `keys`.
    #[cfg(feature = "acme-dns-providers")]
    fn without(text: &str, keys: &[&str]) -> String {
        text.lines()
            .filter(|line| !keys.iter().any(|key| line.starts_with(key)))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Runs `preflight_web_config` on `config` with a good `secrets.toml`
    /// next to it and `state_root` as the state root. Returns whether it
    /// passed with a provider, and the notes.
    fn preflight_acme(
        dir: &std::path::Path,
        config: &str,
        state_root: &std::path::Path,
    ) -> Result<(Result<bool, Exit>, String), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;
        let config_path = dir.join("detent.toml");
        std::fs::write(&config_path, config)?;
        let secrets = dir.join("secrets.toml");
        std::fs::write(&secrets, secret_file(SECRET))?;
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o600))?;
        let messages = Messages::new(Some("en-US"));
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let outcome = preflight_web_config(
            &settings(state_root, config_path),
            &renderer(&messages),
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        let notes = String::from_utf8(notes)?;
        assert!(!notes.contains(SECRET), "{notes}");
        Ok((outcome.map(|(_, provider)| provider.is_some()), notes))
    }

    #[cfg(feature = "acme-dns-providers")]
    #[test]
    fn preflight_passes_a_complete_acme_config_with_its_provider() -> R {
        let dir = tempfile::TempDir::new()?;
        let (outcome, notes) = preflight_acme(dir.path(), &complete_acme(dir.path()), dir.path())?;
        assert_eq!(outcome, Ok(true), "{notes}");
        assert!(notes.is_empty(), "{notes}");
        Ok(())
    }

    #[cfg(feature = "acme-dns-providers")]
    #[test]
    fn preflight_names_each_missing_acme_setting() -> R {
        for (keys, setting) in [
            (&["directory_url"][..], "acme.directory_url"),
            (&["domains"][..], "acme.domains"),
            (&["credentials_path"][..], "acme.credentials_path"),
            (&["[acme.provider]", "kind", "zone_id"][..], "acme.provider"),
        ] {
            let dir = tempfile::TempDir::new()?;
            let config = without(&complete_acme(dir.path()), keys);
            let (outcome, notes) = preflight_acme(dir.path(), &config, dir.path())?;
            assert_eq!(outcome, Err(Exit::Failed), "{setting}");
            assert!(notes.contains(setting), "{setting}: {notes}");
            assert!(notes.contains("is not set"), "{setting}: {notes}");
        }
        Ok(())
    }

    /// The acme process writes only its credentials directory and the
    /// worker only the state root: both directories must be under it. The
    /// check is lexical: a `..` component is refused.
    #[cfg(feature = "acme-dns-providers")]
    #[test]
    fn preflight_refuses_acme_paths_outside_the_state_root() -> R {
        let dir = tempfile::TempDir::new()?;
        let root = dir.path().join("root");
        let complete = complete_acme(&root);
        let outside = dir.path().join("elsewhere").display().to_string();
        let escape = root.join("../elsewhere").display().to_string();
        for (keys, line, setting) in [
            (
                "credentials_path",
                format!("credentials_path = \"{outside}/account.json\""),
                "acme.credentials_path",
            ),
            (
                "credentials_path",
                format!("credentials_path = \"{escape}/account.json\""),
                "acme.credentials_path",
            ),
            (
                "cert_dir",
                format!("cert_dir = \"{outside}\""),
                "tls.cert_dir",
            ),
            (
                "cert_dir",
                format!("cert_dir = \"{escape}\""),
                "tls.cert_dir",
            ),
        ] {
            let config = complete
                .lines()
                .map(|old| {
                    if old.starts_with(keys) {
                        line.as_str()
                    } else {
                        old
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let (outcome, notes) = preflight_acme(dir.path(), &config, &root)?;
            assert_eq!(outcome, Err(Exit::Failed), "{line}");
            assert!(notes.contains(setting), "{line}: {notes}");
            assert!(notes.contains("state root"), "{line}: {notes}");
        }
        Ok(())
    }

    /// A provider without `bootstrap = "acme"` is checked as before, and
    /// preflight yields none: no acme process starts.
    #[cfg(feature = "acme-dns-providers")]
    #[test]
    fn preflight_checks_a_provider_without_acme_and_yields_none() -> R {
        let dir = tempfile::TempDir::new()?;
        let config = format!("[acme.provider]\n{}", cloudflare());
        let (outcome, notes) = preflight_acme(dir.path(), &config, dir.path())?;
        assert_eq!(outcome, Ok(false), "{notes}");
        let self_signed = complete_acme(dir.path()).replace("\"acme\"", "\"self-signed\"");
        let (outcome, notes) = preflight_acme(dir.path(), &self_signed, dir.path())?;
        assert_eq!(outcome, Ok(false), "{notes}");
        Ok(())
    }

    /// `start_acme` forks the acme process with the production spawn
    /// configuration and gives back the runner handle and the configuration
    /// it passed to the child. As root without the `detent` account (a
    /// developer container), the fork is refused before it happens: the
    /// runner is reaped and the failure is a privilege problem.
    #[cfg(feature = "acme-dns-providers")]
    #[test]
    fn start_acme_forks_the_acme_process_and_gives_back_the_runner() -> R {
        use detent_platform::privsep::spawn::is_root;
        use detent_platform::sandbox::{Hooks as SandboxHooks, Policy};
        let dir = tempfile::TempDir::new()?;
        let allow = Allowlist::from_modules(&[], &AllowConfig::with_state_root(dir.path()))?;
        let hooks = SandboxHooks::new(Policy::monitor(&allow), Policy::worker(&allow));
        let mut config = cheap_web_config(dir.path());
        config.acme = detent_web::AcmeConfig {
            directory_url: Some("https://127.0.0.1:9/dir".to_owned()),
            domains: vec!["box.example".to_owned()],
            credentials_path: Some(dir.path().join("acme/account.json")),
            ..detent_web::AcmeConfig::default()
        };
        let provider = Box::new(detent_acme::CloudflareProvider::new(SECRET, ZONE_ID)?);
        let runner = idle_runner()?;
        let runner_pid = runner.child_pid;
        let messages = Messages::new(Some("en-US"));
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let started = super::start_acme(
            provider,
            hooks,
            runner,
            config.clone(),
            &settings(dir.path(), dir.path().join("detent.toml")),
            &renderer(&messages),
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        let notes = String::from_utf8(notes)?;
        assert!(!notes.contains(SECRET), "{notes}");
        match started {
            Ok((_, Some(acme), runner, back)) => {
                assert_eq!(runner.child_pid, runner_pid);
                assert_eq!(back, config);
                // The child's greeting sees the channel closed: it exits 1.
                acme.channel.shutdown_write()?;
                assert_eq!(acme.wait()?, Some(1));
            }
            Ok((_, None, _, _)) => return Err("no acme handle".into()),
            Err(exit) => {
                assert!(is_root(), "{notes}");
                assert_eq!(exit, Exit::Privilege, "{notes}");
                assert!(notes.contains("worker account"), "{notes}");
            }
        }
        Ok(())
    }

    /// `start_acme` checks the `[acme]` settings again before it forks:
    /// with one missing it names it, forks nothing, and reaps the runner.
    #[cfg(feature = "acme-dns-providers")]
    #[test]
    fn start_acme_names_a_missing_setting_and_reaps_the_runner() -> R {
        use detent_platform::sandbox::{Hooks as SandboxHooks, Policy};
        let dir = tempfile::TempDir::new()?;
        let allow = Allowlist::from_modules(&[], &AllowConfig::with_state_root(dir.path()))?;
        let hooks = SandboxHooks::new(Policy::monitor(&allow), Policy::worker(&allow));
        let mut config = cheap_web_config(dir.path());
        config.acme = detent_web::AcmeConfig {
            domains: vec!["box.example".to_owned()],
            credentials_path: Some(dir.path().join("acme/account.json")),
            ..detent_web::AcmeConfig::default()
        };
        let provider = Box::new(detent_acme::CloudflareProvider::new(SECRET, ZONE_ID)?);
        let runner = idle_runner()?;
        let runner_pid = runner.child_pid;
        let messages = Messages::new(Some("en-US"));
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let started = super::start_acme(
            provider,
            hooks,
            runner,
            config,
            &settings(dir.path(), dir.path().join("detent.toml")),
            &renderer(&messages),
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        let notes = String::from_utf8(notes)?;
        assert_eq!(started.err(), Some(Exit::Failed), "{notes}");
        assert!(notes.contains("acme.directory_url"), "{notes}");
        assert!(!notes.contains(SECRET), "{notes}");
        // Reaped already: there is no child left to wait for.
        let pid = rustix::process::Pid::from_raw(runner_pid).ok_or("pid")?;
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).err(),
            Some(rustix::io::Errno::CHILD)
        );
        Ok(())
    }

    /// Runs `start_acme` with `credentials_path` and a complete `[acme]`
    /// table. Returns its outcome (the acme child already reaped) and the
    /// notes.
    #[cfg(feature = "acme-dns-providers")]
    fn start_acme_with(
        root: &std::path::Path,
        credentials_path: std::path::PathBuf,
    ) -> Result<(Result<(), Exit>, String), Box<dyn std::error::Error>> {
        use detent_platform::sandbox::{Hooks as SandboxHooks, Policy};
        let allow = Allowlist::from_modules(&[], &AllowConfig::with_state_root(root))?;
        let hooks = SandboxHooks::new(Policy::monitor(&allow), Policy::worker(&allow));
        let mut config = cheap_web_config(root);
        config.acme = detent_web::AcmeConfig {
            directory_url: Some("https://127.0.0.1:9/dir".to_owned()),
            domains: vec!["box.example".to_owned()],
            credentials_path: Some(credentials_path),
            ..detent_web::AcmeConfig::default()
        };
        let provider = Box::new(detent_acme::CloudflareProvider::new(SECRET, ZONE_ID)?);
        let messages = Messages::new(Some("en-US"));
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let started = super::start_acme(
            provider,
            hooks,
            idle_runner()?,
            config,
            &settings(root, root.join("detent.toml")),
            &renderer(&messages),
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        let outcome = match started {
            Ok((_, acme, _, _)) => {
                if let Some(acme) = acme {
                    acme.channel.shutdown_write()?;
                    acme.wait()?;
                }
                Ok(())
            }
            Err(exit) => Err(exit),
        };
        Ok((outcome, String::from_utf8(notes)?))
    }

    /// The acme process may write only the directory of
    /// `acme.credentials_path`, and Landlock skips a path that does not
    /// exist: `start_acme` creates it before the fork, each missing level
    /// `0700` and owned by the state root's owner (the worker account).
    #[cfg(feature = "acme-dns-providers")]
    #[test]
    fn start_acme_prepares_the_credentials_directory() -> R {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = tempfile::TempDir::new()?;
        let root = dir.path();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))?;
        let credentials = root.join("acme/keys");
        let (_, notes) = start_acme_with(root, credentials.join("account.json"))?;
        assert!(!notes.contains("could not be prepared"), "{notes}");
        let owner = std::fs::metadata(root)?;
        for made in [root.join("acme"), credentials.clone()] {
            let meta = std::fs::symlink_metadata(&made)?;
            assert!(meta.is_dir(), "{}", made.display());
            assert_eq!(meta.mode() & 0o7777, 0o700, "{}", made.display());
            assert_eq!((meta.uid(), meta.gid()), (owner.uid(), owner.gid()));
        }
        // An existing directory is tightened to 0700.
        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o755))?;
        let (_, notes) = start_acme_with(root, credentials.join("account.json"))?;
        assert!(!notes.contains("could not be prepared"), "{notes}");
        assert_eq!(
            std::fs::metadata(&credentials)?.mode() & 0o7777,
            0o700,
            "existing directory"
        );
        Ok(())
    }

    /// No step follows a symlink: a credentials directory (or a level above
    /// it) that is a symlink is refused, nothing is forked, and the target
    /// keeps its mode.
    #[cfg(feature = "acme-dns-providers")]
    #[test]
    fn start_acme_refuses_a_symlinked_credentials_directory() -> R {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = tempfile::TempDir::new()?;
        let root = dir.path().join("root");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&root)?;
        std::fs::create_dir(&elsewhere)?;
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755))?;
        std::os::unix::fs::symlink(&elsewhere, root.join("acme"))?;
        for credentials in ["acme/account.json", "acme/keys/account.json"] {
            let (outcome, notes) = start_acme_with(&root, root.join(credentials))?;
            assert_eq!(outcome, Err(Exit::Failed), "{credentials}: {notes}");
            assert!(notes.contains("could not be prepared"), "{notes}");
            assert!(!notes.contains(SECRET), "{notes}");
        }
        assert_eq!(std::fs::metadata(&elsewhere)?.mode() & 0o7777, 0o755);
        assert!(!elsewhere.join("keys").exists());
        Ok(())
    }

    /// Preflight already refuses a credentials directory outside the state
    /// root; the preparation refuses it again rather than create it.
    #[cfg(feature = "acme-dns-providers")]
    #[test]
    fn preparing_the_credentials_directory_refuses_a_path_outside_the_state_root() -> R {
        let dir = tempfile::TempDir::new()?;
        let root = dir.path().join("root");
        std::fs::create_dir(&root)?;
        let outside = dir.path().join("elsewhere");
        for path in [outside.clone(), root.join("../elsewhere")] {
            let err = super::prepare_credentials_dir(&path, &root)
                .err()
                .ok_or("an outside path was prepared")?;
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidInput,
                "{}",
                path.display()
            );
        }
        assert!(!outside.exists());
        Ok(())
    }

    #[cfg(not(feature = "acme-dns-providers"))]
    #[test]
    fn preflight_refuses_acme_in_a_build_without_providers() -> R {
        let dir = tempfile::TempDir::new()?;
        let (outcome, notes) = preflight_acme(dir.path(), &complete_acme(dir.path()), dir.path())?;
        assert_eq!(outcome, Err(Exit::Failed));
        assert!(notes.contains("acme-dns-providers"), "{notes}");
        assert!(notes.contains("self-signed"), "{notes}");
        Ok(())
    }

    #[cfg(not(feature = "acme-dns-providers"))]
    #[test]
    fn preflight_refuses_a_provider_this_build_cannot_use() -> R {
        let (outcome, notes) = preflight_with(
            &cloudflare(),
            Some((&secret_file("not-a-real-token"), 0o600)),
        )?;
        assert_eq!(outcome, Err(Exit::Failed));
        assert!(notes.contains("acme-dns-providers"), "{notes}");
        Ok(())
    }

    /// With the worker's end of the acme channel, the bound worker answers
    /// the acme process on its own thread.
    #[cfg(feature = "acme-dns-providers")]
    #[tokio::test]
    async fn bind_web_server_answers_the_acme_process_once_bound() -> R {
        let dir = tempfile::TempDir::new()?;
        let (handle, thread, monitor) = engine_fixture(dir.path())?;
        let auth_state =
            detent_web::AuthState::open(dir.path(), &detent_web::AuthConfig::default(), 4096)?;
        let (acme_end, worker_end) = Channel::pair()?;
        let messages = Messages::new(Some("en-US"));
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let bound = bind_web_server(
            super::WorkerConfig {
                web: cheap_web_config(dir.path()),
                acme: Some(worker_end),
            },
            &["box.example".to_owned()],
            handle,
            auth_state,
            dir.path().to_path_buf(),
            &renderer(&messages),
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )
        .await
        .ok_or("bind_web_server must succeed against a fresh temp dir")?;
        let mut client = detent_platform::privsep::acme::AcmeClient::new(acme_end);
        client.hello()?;
        drop(client);
        drop(bound);
        thread.join().map_err(|err| format!("{err:?}"))?;
        monitor.join().map_err(|_| "monitor thread panicked")?;
        Ok(())
    }

    /// The whole `bind_web_server` path against a real, temporary certificate
    /// store and a real (in-process) engine: TLS bootstrap, the fingerprint
    /// note, `AppState`/`Router` assembly, and a real listener bound on an
    /// ephemeral port.
    #[tokio::test]
    async fn bind_web_server_bootstraps_tls_and_binds_a_real_listener() -> R {
        let dir = tempfile::TempDir::new()?;
        let (handle, thread, monitor) = engine_fixture(dir.path())?;
        let auth_state =
            detent_web::AuthState::open(dir.path(), &detent_web::AuthConfig::default(), 4096)?;
        let config = cheap_web_config(dir.path());
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let mut streams = crate::run::Streams {
            input: &mut input,
            out: &mut out,
            notes: &mut notes,
        };

        let bound = bind_web_server(
            worker_config(config),
            &["box.example".to_owned()],
            handle,
            auth_state,
            dir.path().to_path_buf(),
            &renderer,
            &mut streams,
        )
        .await
        .ok_or("bind_web_server must succeed against a fresh temp dir")?;
        assert_ne!(bound.local_addr().port(), 0);
        let certs = dir.path().join("certs");
        assert!(
            certs.join("bootstrap.pair").exists() || certs.join("bootstrap.cert.der").exists(),
            "bootstrap cert missing in {certs:?}: {:?}",
            std::fs::read_dir(&certs)
                .map(|r| r
                    .filter_map(Result::ok)
                    .map(|e| e.file_name())
                    .collect::<Vec<_>>())
                .unwrap_or_default()
        );
        let text = String::from_utf8(notes)?;
        assert!(text.contains("fingerprint"), "{text}");
        drop(bound);
        thread.join().map_err(|err| format!("{err:?}"))?;
        monitor.join().map_err(|_| "monitor thread panicked")?;
        Ok(())
    }

    /// A certificate directory that cannot be prepared (a file sits where the
    /// directory should be) is a clean `None`, not a panic — the negative
    /// twin of the test above, and the only branch it does not exercise.
    #[tokio::test]
    async fn bind_web_server_reports_a_tls_failure_as_none() -> R {
        let dir = tempfile::TempDir::new()?;
        let (handle, thread, monitor) = engine_fixture(dir.path())?;
        let auth_state =
            detent_web::AuthState::open(dir.path(), &detent_web::AuthConfig::default(), 4096)?;
        let mut config = cheap_web_config(dir.path());
        // A file where the certificate directory should be: `create_dir_all`
        // fails, exactly as `tls::tests::a_directory_that_cannot_be_created`
        // exercises the same failure inside `detent-web` itself.
        config.tls.cert_dir = dir.path().join("not-a-directory");
        std::fs::write(&config.tls.cert_dir, b"x")?;
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let mut streams = crate::run::Streams {
            input: &mut input,
            out: &mut out,
            notes: &mut notes,
        };

        let server = bind_web_server(
            worker_config(config),
            &["box.example".to_owned()],
            handle,
            auth_state,
            dir.path().to_path_buf(),
            &renderer,
            &mut streams,
        )
        .await;
        assert!(server.is_none());
        let text = String::from_utf8(notes)?;
        assert!(text.contains("tls"), "{text}");

        thread.join().map_err(|err| format!("{err:?}"))?;
        monitor.join().map_err(|_| "monitor thread panicked")?;
        Ok(())
    }

    /// A port already held by another socket makes `Server::bind` itself
    /// fail — the one `bind_web_server` failure branch neither test above
    /// exercises. TLS bootstrap still runs first, so this proves the
    /// fingerprint note is unconditional even on a startup that ultimately
    /// fails.
    #[tokio::test]
    async fn bind_web_server_reports_a_bind_failure_as_none() -> R {
        let dir = tempfile::TempDir::new()?;
        let (handle, thread, monitor) = engine_fixture(dir.path())?;
        let auth_state =
            detent_web::AuthState::open(dir.path(), &detent_web::AuthConfig::default(), 4096)?;
        let mut config = cheap_web_config(dir.path());
        let blocker = std::net::TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        config.listen.addr = blocker.local_addr()?;
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let mut streams = crate::run::Streams {
            input: &mut input,
            out: &mut out,
            notes: &mut notes,
        };

        let server = bind_web_server(
            worker_config(config),
            &["box.example".to_owned()],
            handle,
            auth_state,
            dir.path().to_path_buf(),
            &renderer,
            &mut streams,
        )
        .await;
        assert!(server.is_none());
        let text = String::from_utf8(notes)?;
        assert!(
            text.contains("web-failed") || text.contains("could not start"),
            "{text}"
        );
        drop(blocker);

        thread.join().map_err(|err| format!("{err:?}"))?;
        monitor.join().map_err(|_| "monitor thread panicked")?;
        Ok(())
    }

    /// `prepare_worker`'s auth-store failure branch: a file where
    /// `<state_root>/state` should be makes `AuthState::open`'s
    /// `UserStore::load` fail, the same technique
    /// `webadmin::tests::a_store_that_cannot_be_opened_is_a_credential_failure`
    /// uses against the same stores.
    #[test]
    fn prepare_worker_reports_an_auth_failure_as_none() -> R {
        let dir = tempfile::TempDir::new()?;
        std::fs::write(dir.path().join("state"), b"not a directory")?;
        let allow = Allowlist::from_modules(&[], &AllowConfig::with_state_root(dir.path()))?;
        let (monitor_end, worker_end) = Channel::pair()?;
        let monitor = std::thread::spawn(move || {
            let mut channel = monitor_end;
            let _ = Monitor::new(allow, MonitorHooks::default()).serve(&mut channel);
        });
        let client = Client::new(worker_end);
        let config = cheap_web_config(dir.path());
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let mut streams = crate::run::Streams {
            input: &mut input,
            out: &mut out,
            notes: &mut notes,
        };

        let prepared = super::prepare_worker(
            client,
            Detected::default(),
            Vec::new(),
            worker_config(config),
            &settings(dir.path(), dir.path().join("absent.toml")),
            &renderer,
            &mut streams,
        );
        assert!(prepared.is_none());
        let text = String::from_utf8(notes)?;
        assert!(text.contains("account, token and session store"), "{text}");
        monitor.join().map_err(|_| "monitor thread panicked")?;
        Ok(())
    }

    /// `run_worker`'s early exit: a handshake that never completes (the
    /// monitor end is dropped before `hello` round-trips) makes
    /// `prepare_worker` return `None`, and `run_worker` reports failure (`1`)
    /// without ever binding a listener — the status [`abort_child`] would
    /// exit the worker with.
    #[test]
    fn run_worker_reports_a_failed_handshake_as_exit_one() -> R {
        let dir = tempfile::TempDir::new()?;
        let (monitor_end, worker_end) = Channel::pair()?;
        drop(monitor_end);
        let client = Client::new(worker_end);
        let config = cheap_web_config(dir.path());
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let status = super::run_worker(
            client,
            Detected::default(),
            Vec::new(),
            worker_config(config),
            &settings(dir.path(), dir.path().join("absent.toml")),
            &renderer,
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        );
        assert_eq!(status, 1);
        assert!(out.is_empty());
        assert!(!notes.is_empty());
        Ok(())
    }

    /// `prepare_worker`: the handshake, the engine, the account/token/session
    /// stores, the runtime, and a real bound listener — everything
    /// `run_worker` does short of the blocking `server.serve(..)` call. This
    /// is the largest slice of the real worker path that can run without a
    /// process signal; only that final blocking call and the `SIGTERM`/
    /// `SIGINT` wait inside `shutdown_signal` are not exercised here.
    #[test]
    fn prepare_worker_reaches_a_bound_listener() -> R {
        let dir = tempfile::TempDir::new()?;
        let allow = Allowlist::from_modules(&[], &AllowConfig::with_state_root(dir.path()))?;
        let (monitor_end, worker_end) = Channel::pair()?;
        let monitor = std::thread::spawn(move || {
            let mut channel = monitor_end;
            let _ = Monitor::new(allow, MonitorHooks::default()).serve(&mut channel);
        });
        let client = Client::new(worker_end);
        let config = cheap_web_config(dir.path());
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let mut streams = crate::run::Streams {
            input: &mut input,
            out: &mut out,
            notes: &mut notes,
        };

        let prepared = super::prepare_worker(
            client,
            Detected::default(),
            Vec::new(),
            worker_config(config),
            &settings(dir.path(), dir.path().join("absent.toml")),
            &renderer,
            &mut streams,
        )
        .ok_or("prepare_worker must succeed against a fresh temp dir")?;
        assert_ne!(prepared.server.local_addr().port(), 0);
        // The auth-state sweep runs in production, not only under tests that
        // happen to open the stores inside a runtime (STAGE3 L-WEB16). Drive
        // the runtime once so a task that ends at once would show as finished.
        prepared
            .runtime
            .block_on(async { tokio::time::sleep(std::time::Duration::from_millis(20)).await });
        assert!(
            !prepared.sweeper.is_finished(),
            "the auth-state sweeper must be running"
        );

        // `run_worker` itself drops `server`/`state` before joining, releasing
        // the last `EngineHandle`; do the same here rather than calling the
        // blocking `serve(shutdown_signal())`.
        drop(prepared.server);
        prepared
            .engine_thread
            .join()
            .map_err(|err| format!("{err:?}"))?;
        monitor.join().map_err(|_| "monitor thread panicked")?;
        Ok(())
    }

    /// A handshake that never completes (the monitor end is dropped before
    /// `hello` can round-trip) is `None`, not a hang or a panic.
    #[test]
    fn prepare_worker_reports_a_failed_handshake_as_none() -> R {
        let dir = tempfile::TempDir::new()?;
        let (monitor_end, worker_end) = Channel::pair()?;
        drop(monitor_end);
        let client = Client::new(worker_end);
        let config = cheap_web_config(dir.path());
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let mut streams = crate::run::Streams {
            input: &mut input,
            out: &mut out,
            notes: &mut notes,
        };

        let prepared = super::prepare_worker(
            client,
            Detected::default(),
            Vec::new(),
            worker_config(config),
            &settings(dir.path(), dir.path().join("absent.toml")),
            &renderer,
            &mut streams,
        );
        assert!(prepared.is_none());
        assert!(!notes.is_empty());
        Ok(())
    }

    /// `run_monitor` needs a real, reapable pid to prove its success path —
    /// `handle.wait()` calls the real `waitpid(2)`. A `spawn_pair`-forked
    /// worker is the production source of one, but forking here would be a
    /// real fork on a thread the shared, already-multi-threaded test harness
    /// owns (unsafe: `spawn_pair`'s own contract requires forking before any
    /// runtime or thread pool starts, which is never true inside `cargo
    /// test`). A `true` child spawned by `std::process::Command` is real and
    /// reapable without that hazard — `run_monitor` only cares that the pid
    /// exists and exits 0, not what process it is.
    /// A runner handle with a real, reapable pid (see the test below for why
    /// not a fork) whose channel nobody answers; these tests run no checks.
    fn idle_runner() -> Result<RunnerHandle, Box<dyn std::error::Error>> {
        let (monitor_end, _runner_end) = Channel::pair()?;
        let child = std::process::Command::new("true").spawn()?;
        Ok(RunnerHandle {
            child_pid: i32::try_from(child.id())?,
            channel: monitor_end,
        })
    }

    #[test]
    fn run_monitor_reports_success_when_the_worker_shuts_down_cleanly() -> R {
        let dir = tempfile::TempDir::new()?;
        let allow = Allowlist::from_modules(&[], &AllowConfig::with_state_root(dir.path()))?;
        let (monitor_end, worker_end) = Channel::pair()?;
        let worker = std::thread::spawn(move || {
            let mut client = Client::new(worker_end);
            let _ = client.hello();
            let _ = client.shutdown();
        });
        let child = std::process::Command::new("true").spawn()?;
        let handle = MonitorHandle {
            child_pid: i32::try_from(child.id())?,
            channel: monitor_end,
        };
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let exit = run_monitor(
            &Detected::default(),
            allow,
            handle,
            idle_runner()?,
            true,
            &renderer,
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));
        worker.join().map_err(|_| "worker thread panicked")?;
        Ok(())
    }

    /// `run` itself, called with a malformed `detent.toml`, reports the
    /// failure and returns before `spawn_pair` is ever called — the `Err`
    /// arm of `run`'s own `preflight_web_config` match, which
    /// `preflight_web_config`'s own tests above cannot reach because they
    /// call the function directly rather than through `run`. Safe to run
    /// in-process because the config error is caught before any fork.
    #[test]
    fn run_reports_a_malformed_configuration_before_ever_forking() -> R {
        let dir = tempfile::TempDir::new()?;
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "not toml")?;
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let exit = run(
            false,
            &settings(dir.path(), bad),
            &renderer,
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(!notes.is_empty());
        Ok(())
    }

    /// A worker that never shuts down the monitor cleanly (the channel is
    /// simply dropped) is `Exit::Failed`, not a hang.
    #[test]
    fn run_monitor_reports_failure_when_the_worker_vanishes() -> R {
        let dir = tempfile::TempDir::new()?;
        let allow = Allowlist::from_modules(&[], &AllowConfig::with_state_root(dir.path()))?;
        let (monitor_end, worker_end) = Channel::pair()?;
        drop(worker_end);
        let child = std::process::Command::new("true").spawn()?;
        let handle = MonitorHandle {
            child_pid: i32::try_from(child.id())?,
            channel: monitor_end,
        };
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let mut input = std::io::empty();
        let exit = run_monitor(
            &Detected::default(),
            allow,
            handle,
            idle_runner()?,
            false,
            &renderer,
            &mut crate::run::Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(!notes.is_empty());
        Ok(())
    }

    /// A restart reuses the certificate the first start stored: the same
    /// fingerprint is logged both times, so the operator's trust-on-first-use
    /// pin survives a restart.
    #[tokio::test]
    async fn bind_web_server_reuses_the_stored_certificate_on_restart() -> R {
        let dir = tempfile::TempDir::new()?;
        let messages = Messages::new(Some("en-US"));
        let renderer = renderer(&messages);
        let mut fingerprints = Vec::new();
        for start in 0..2 {
            // Each start gets its own monitor state root: the monitor's
            // `flock` belongs to the open file, and a child that a parallel
            // test forks at that moment keeps a copy of it, so a second
            // monitor on the same root could see it still held (`Busy`).
            // What is under test is the certificate in `dir`, not the lock.
            let monitor_root = dir.path().join(format!("monitor-{start}"));
            std::fs::create_dir(&monitor_root)?;
            let (handle, thread, monitor) = engine_fixture(&monitor_root)?;
            let auth_state =
                detent_web::AuthState::open(dir.path(), &detent_web::AuthConfig::default(), 4096)?;
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let mut input = std::io::empty();
            let bound = bind_web_server(
                worker_config(cheap_web_config(dir.path())),
                &["box.example".to_owned()],
                handle,
                auth_state,
                dir.path().to_path_buf(),
                &renderer,
                &mut crate::run::Streams {
                    input: &mut input,
                    out: &mut out,
                    notes: &mut notes,
                },
            )
            .await
            .ok_or("bind_web_server must succeed")?;
            drop(bound);
            thread.join().map_err(|err| format!("{err:?}"))?;
            monitor.join().map_err(|_| "monitor thread panicked")?;
            let text = String::from_utf8(notes)?;
            let line = text
                .lines()
                .find(|line| line.contains("fingerprint"))
                .ok_or_else(|| format!("no fingerprint note in {text}"))?
                .to_owned();
            fingerprints.push(line);
        }
        assert_eq!(
            fingerprints.first(),
            fingerprints.get(1),
            "{fingerprints:?}"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // `detent cert renew` against a real listener: the same router, TLS and
    // auth state `bind_web_server` assembles, with a renewer that counts.
    // -----------------------------------------------------------------------

    /// A renewer that counts requests, and fails each one when `fail`.
    #[derive(Debug, Default)]
    struct CountingRenewer {
        calls: std::sync::atomic::AtomicUsize,
        fail: bool,
    }

    impl detent_web::CertRenewer for CountingRenewer {
        fn renew_now(&self) -> Result<(), String> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail {
                Err("the channel is closed".to_owned())
            } else {
                Ok(())
            }
        }
    }

    impl CountingRenewer {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// A running server with a bootstrap certificate for `box.example`, a
    /// write and a read token, and a `detent.toml` that points at both.
    struct RenewServer {
        dir: tempfile::TempDir,
        settings: Settings,
        write: String,
        read: String,
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        serving: Option<std::thread::JoinHandle<()>>,
        engine: Option<(detent_web::EngineThread, std::thread::JoinHandle<()>)>,
    }

    impl RenewServer {
        fn start(
            renewer: Option<std::sync::Arc<CountingRenewer>>,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let dir = tempfile::TempDir::new()?;
            let (handle, thread, monitor) = engine_fixture(dir.path())?;
            let auth_state =
                detent_web::AuthState::open(dir.path(), &detent_web::AuthConfig::default(), 4096)?;
            let (write, _) =
                auth_state
                    .tokens
                    .issue("renew-write", detent_web::authz::Scope::Write, None)?;
            let (read, _) =
                auth_state
                    .tokens
                    .issue("renew-read", detent_web::authz::Scope::Read, None)?;
            let config = cheap_web_config(dir.path());
            let pair = detent_web::load_or_bootstrap(
                &config.tls.cert_dir,
                &["box.example".to_owned()],
                false,
            )?;
            let store = std::sync::Arc::new(detent_web::CertStore::new(&pair)?);
            let tls = detent_web::server_config_from_store(
                std::sync::Arc::clone(&store),
                detent_web::tls::ALPN_H2_HTTP11,
            )?;
            let origin = detent_web::Origin::for_config(&config);
            let state = detent_web::AppState::new(
                handle,
                auth_state,
                config.clone(),
                origin,
                store,
                dir.path().to_path_buf(),
            );
            let state = match renewer {
                Some(renewer) => state.with_cert_renewer(renewer),
                None => state,
            };
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let server = runtime.block_on(detent_web::Server::bind(
                &config,
                tls,
                detent_web::router(state),
            ))?;
            let addr = server.local_addr();
            let (shutdown, stop) = tokio::sync::oneshot::channel::<()>();
            let serving = std::thread::spawn(move || {
                runtime.block_on(server.serve(async {
                    let _ = stop.await;
                }));
            });
            let config_path = dir.path().join("detent.toml");
            std::fs::write(
                &config_path,
                format!(
                    "[listen]\naddr = \"{addr}\"\n[tls]\ncert_dir = {:?}\n",
                    config.tls.cert_dir.display().to_string()
                ),
            )?;
            Ok(Self {
                settings: settings(dir.path(), config_path),
                dir,
                write: write.expose().to_owned(),
                read: read.expose().to_owned(),
                shutdown: Some(shutdown),
                serving: Some(serving),
                engine: Some((thread, monitor)),
            })
        }

        /// `detent cert renew` with `token` in `DETENT_TOKEN`, under a log
        /// capture: exit, stdout, stderr and the log lines.
        fn renew(
            &self,
            args: &crate::cli::RenewArgs,
            token: &str,
            json: bool,
        ) -> Result<(Exit, String, String, String), Box<dyn std::error::Error>> {
            let messages = Messages::new(Some("en-US"));
            let renderer = Renderer {
                messages: &messages,
                json,
                verbose: true,
            };
            let mut input = std::io::empty();
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let (exit, logs) = crate::tests_support::capture(|| {
                crate::renew::run(
                    args,
                    false,
                    Some(token.into()),
                    &self.settings,
                    &renderer,
                    &mut crate::run::Streams {
                        input: &mut input,
                        out: &mut out,
                        notes: &mut notes,
                    },
                )
            });
            Ok((
                exit?,
                String::from_utf8(out)?,
                String::from_utf8(notes)?,
                logs,
            ))
        }

        /// The address the server listens on, as `detent.toml` names it.
        #[cfg(feature = "mcp")]
        fn listen_addr(&self) -> Result<String, Box<dyn std::error::Error>> {
            let text = std::fs::read_to_string(&self.settings.config_path)?;
            Ok(text
                .lines()
                .find_map(|line| line.strip_prefix("addr = \""))
                .and_then(|rest| rest.strip_suffix('"'))
                .ok_or("no listen address in detent.toml")?
                .to_owned())
        }

        fn stop(mut self) -> R {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            if let Some(serving) = self.serving.take() {
                serving.join().map_err(|_| "the server thread panicked")?;
            }
            if let Some((thread, monitor)) = self.engine.take() {
                thread.join().map_err(|err| format!("{err:?}"))?;
                monitor.join().map_err(|_| "monitor thread panicked")?;
            }
            Ok(())
        }
    }

    fn renew_args(
        url: Option<&str>,
        ca_file: Option<std::path::PathBuf>,
    ) -> Result<crate::cli::RenewArgs, String> {
        Ok(crate::cli::RenewArgs {
            token_file: None,
            url: url.map(crate::cli::parse_https_url).transpose()?,
            ca_file,
        })
    }

    /// Fails when any output or log line holds any form of `tokens`.
    fn assert_no_token(what: &str, texts: &[&str], tokens: &[&str]) {
        for text in texts {
            crate::tests_support::assert_clean(what, text, tokens);
        }
    }

    #[test]
    fn cert_renew_is_accepted_for_a_write_token_and_refused_for_a_read_one() -> R {
        let renewer = std::sync::Arc::new(CountingRenewer::default());
        let server = RenewServer::start(Some(std::sync::Arc::clone(&renewer)))?;
        let tokens = [server.write.as_str(), server.read.as_str()];

        let (exit, out, notes, logs) =
            server.renew(&renew_args(None, None)?, &server.write, false)?;
        assert_eq!(exit, Exit::Ok, "{notes}");
        assert!(out.contains("renewal requested"), "{out}");
        assert_eq!(renewer.calls(), 1);
        assert_no_token("a requested renewal", &[&out, &notes, &logs], &tokens);

        let (exit, out, notes, logs) =
            server.renew(&renew_args(None, None)?, &server.write, true)?;
        assert_eq!(exit, Exit::Ok, "{notes}");
        let parsed: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(
            parsed.pointer("/outcome").and_then(|v| v.as_str()),
            Some("requested")
        );
        assert_eq!(
            parsed
                .pointer("/status")
                .and_then(serde_json::Value::as_u64),
            Some(202)
        );
        assert_eq!(renewer.calls(), 2);
        assert_no_token("a JSON renewal", &[&out, &notes, &logs], &tokens);

        // A read token over a token file: the same answer the web button
        // gets, and the renewer is not asked.
        let token_file = server.dir.path().join("read-token");
        std::fs::write(&token_file, format!("{}\n", server.read))?;
        std::fs::set_permissions(
            &token_file,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )?;
        let mut args = renew_args(None, None)?;
        args.token_file = Some(token_file);
        let (exit, out, notes, logs) = server.renew(&args, &server.write, false)?;
        assert_eq!(exit, Exit::Failed);
        assert!(
            notes.contains("HTTP 403") && notes.contains("write scope"),
            "{notes}"
        );
        assert_no_token("a read token", &[&out, &notes, &logs], &tokens);

        let unknown = "0".repeat(64);
        let (exit, out, notes, logs) = server.renew(&renew_args(None, None)?, &unknown, false)?;
        assert_eq!(exit, Exit::Failed);
        assert!(notes.contains("HTTP 401"), "{notes}");
        assert_no_token("an unknown token", &[&out, &notes, &logs], &[&unknown]);
        assert_eq!(renewer.calls(), 2);

        // Every answer after authorization is in the auth log, as for the
        // button.
        let audit =
            std::fs::read_to_string(server.dir.path().join("audit").join("detent-auth.jsonl"))?;
        assert_eq!(audit.matches("cert_renew_requested").count(), 2, "{audit}");
        assert_no_token("the auth log", &[&audit], &tokens);
        server.stop()
    }

    #[test]
    fn cert_renew_reports_a_server_without_acme_and_a_closed_channel() -> R {
        let server = RenewServer::start(None)?;
        let (exit, out, notes, logs) =
            server.renew(&renew_args(None, None)?, &server.write, false)?;
        assert_eq!(exit, Exit::Failed);
        assert!(notes.contains("no ACME process"), "{notes}");
        assert_no_token("a 409", &[&out, &notes, &logs], &[&server.write]);
        server.stop()?;

        let renewer = std::sync::Arc::new(CountingRenewer {
            fail: true,
            ..CountingRenewer::default()
        });
        let server = RenewServer::start(Some(std::sync::Arc::clone(&renewer)))?;
        let (exit, out, notes, logs) =
            server.renew(&renew_args(None, None)?, &server.write, false)?;
        assert_eq!(exit, Exit::Failed);
        assert!(
            notes.contains("HTTP 503: web-cert-renew-unavailable"),
            "{notes}"
        );
        assert_eq!(renewer.calls(), 1);
        assert_no_token("a 503", &[&out, &notes, &logs], &[&server.write]);
        let (exit, out, _, _) = server.renew(&renew_args(None, None)?, &server.write, true)?;
        assert_eq!(exit, Exit::Failed);
        let parsed: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(
            parsed.pointer("/message_id").and_then(|v| v.as_str()),
            Some("web-cert-renew-unavailable")
        );
        server.stop()
    }

    /// PEM text of a DER certificate.
    fn pem(der: &[u8]) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            crate::tests_support::base64(der, false)
        )
    }

    #[test]
    fn cert_renew_trusts_only_the_served_certificate_or_the_ca_file() -> R {
        let renewer = std::sync::Arc::new(CountingRenewer::default());
        let server = RenewServer::start(Some(std::sync::Arc::clone(&renewer)))?;
        let pair = detent_web::serving_pair(&server.dir.path().join("certs"))?
            .ok_or("the server stored no certificate")?;
        let text = std::fs::read_to_string(&server.settings.config_path)?;
        let addr = text
            .lines()
            .find_map(|line| line.strip_prefix("addr = \""))
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or("no listen address in detent.toml")?
            .to_owned();
        let url = format!("https://{addr}");

        // `--url` with the served certificate as the CA file: the IP is
        // verified against the certificate's IP name.
        let ca = server.dir.path().join("served.pem");
        std::fs::write(&ca, pem(pair.cert_der()))?;
        let (exit, _, notes, _) =
            server.renew(&renew_args(Some(&url), Some(ca))?, &server.write, false)?;
        assert_eq!(exit, Exit::Ok, "{notes}");
        assert_eq!(renewer.calls(), 1);

        // Another certificate as the CA file: the handshake fails.
        let other = detent_web::bootstrap_self_signed(&["box.example".to_owned()])?;
        let wrong_ca = server.dir.path().join("other.pem");
        std::fs::write(&wrong_ca, pem(other.cert_der()))?;
        let (exit, out, notes, logs) = server.renew(
            &renew_args(Some(&url), Some(wrong_ca))?,
            &server.write,
            false,
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(
            notes.contains(&addr) && notes.contains("TLS handshake failed"),
            "{notes}"
        );
        assert_no_token("a wrong CA", &[&out, &notes, &logs], &[&server.write]);

        // Another certificate in `tls.cert_dir`: the pin fails.
        let other_dir = server.dir.path().join("other-certs");
        detent_web::tls::store_bootstrap(&other_dir, &other)?;
        let wrong_config = server.dir.path().join("wrong.toml");
        std::fs::write(
            &wrong_config,
            format!(
                "[listen]\naddr = \"{addr}\"\n[tls]\ncert_dir = {:?}\n",
                other_dir.display().to_string()
            ),
        )?;
        let wrong = RenewServer {
            settings: settings(server.dir.path(), wrong_config),
            ..server
        };
        let (exit, out, notes, logs) =
            wrong.renew(&renew_args(None, None)?, &wrong.write, false)?;
        assert_eq!(exit, Exit::Failed);
        assert!(notes.contains("TLS handshake failed"), "{notes}");
        assert_no_token("a wrong pin", &[&out, &notes, &logs], &[&wrong.write]);
        assert_eq!(renewer.calls(), 1);
        wrong.stop()
    }

    // -----------------------------------------------------------------------
    // The `detent mcp` certificate tools against the same real listener: a
    // session with the hook `detent mcp` installs, run as a token.
    // -----------------------------------------------------------------------

    /// A monitor-backed session (its own state root: the server holds the
    /// other one) whose engine has the certificate hook for `settings` and
    /// `token`.
    #[cfg(feature = "mcp")]
    fn mcp_session(
        settings: &Settings,
        token: &str,
    ) -> Result<crate::tests_support::Harness, Box<dyn std::error::Error>> {
        let mut harness = crate::tests_support::Harness::start(b"v1\n", false)?;
        harness
            .session
            .set_cert_front_end(crate::mcp::cert_front_end(settings, token));
        Ok(harness)
    }

    /// One operation as a token of `scope`, the way a tool call runs.
    #[cfg(feature = "mcp")]
    fn mcp_call(
        harness: &mut crate::tests_support::Harness,
        op: detent_ops::Operation,
        scope: detent_web::authz::Scope,
    ) -> Result<detent_ops::OpOutcome, detent_ops::OpsError> {
        let who = detent_ops::Identity::new("token:t1", detent_ops::IdentityKind::Token);
        let authz = detent_web::authz::ScopedAuthz::new(detent_web::authz::Scopes::of(scope));
        match harness.session.execute_as(op, false, &who, &authz)? {
            crate::run::Executed::Ran(outcome) => Ok(outcome),
            crate::run::Executed::WouldRun(_) => Err(detent_ops::OpsError::Unsupported {
                what: "dryrun_mutation",
            }),
        }
    }

    /// One audit record, as `(result, error id)`.
    #[cfg(feature = "mcp")]
    type Logged = (detent_ops::AuditResult, Option<String>);

    /// The `CertRenew` records of the session's audit log.
    #[cfg(feature = "mcp")]
    fn renew_records(
        harness: &mut crate::tests_support::Harness,
    ) -> Result<Vec<Logged>, Box<dyn std::error::Error>> {
        let audit = mcp_call(
            harness,
            detent_ops::Operation::AuditQuery(detent_ops::AuditQuery::default()),
            detent_web::authz::Scope::Read,
        )?;
        let mut records = crate::tests_support::records_of(audit).ok_or("audit answers records")?;
        records.reverse();
        Ok(records
            .into_iter()
            .filter(|record| record.op == detent_ops::OpKind::CertRenew)
            .map(|record| (record.result, record.error_id))
            .collect())
    }

    /// `detent.toml` text for `addr` and `cert_dir`.
    #[cfg(feature = "mcp")]
    fn config_text(addr: &str, cert_dir: &std::path::Path) -> String {
        format!(
            "[listen]\naddr = \"{addr}\"\n[tls]\ncert_dir = {:?}\n",
            cert_dir.display().to_string()
        )
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn mcp_cert_status_reports_the_certificate_the_server_serves() -> R {
        use detent_ops::{OpOutcome, Operation};
        let server = RenewServer::start(None)?;
        let mut mcp = mcp_session(&server.settings, &server.read)?;
        let pair = detent_web::serving_pair(&server.dir.path().join("certs"))?
            .ok_or("the server stored no certificate")?;

        let outcome = mcp_call(
            &mut mcp,
            Operation::CertStatus,
            detent_web::authz::Scope::Read,
        )?;
        let OpOutcome::CertStatus(ref report) = outcome else {
            return Err(format!("CertStatus answered {outcome:?}").into());
        };
        assert_eq!(report.fingerprint, pair.fingerprint());
        assert!(report.not_after_unix.is_some(), "{report:?}");
        assert_eq!(report.renewal_due, Some(false));
        // The JSON carries the REST field names.
        let json = serde_json::to_value(&outcome)?;
        let mut names: Vec<&str> = json
            .pointer("/cert_status")
            .and_then(serde_json::Value::as_object)
            .ok_or("the answer has no cert_status object")?
            .keys()
            .map(String::as_str)
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "expiry_warning",
                "fingerprint",
                "lifetime_used_percent",
                "not_after_unix",
                "renewal_due",
            ]
        );
        // Read-only: nothing is audited.
        assert!(renew_records(&mut mcp)?.is_empty());
        server.stop()
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn mcp_cert_renew_asks_the_server_once_for_a_write_token_and_never_for_a_read_one() -> R {
        use detent_ops::{AuditResult, OpOutcome, Operation, OpsError};
        use detent_web::authz::Scope;
        let renewer = std::sync::Arc::new(CountingRenewer::default());
        let server = RenewServer::start(Some(std::sync::Arc::clone(&renewer)))?;
        let mut mcp = mcp_session(&server.settings, &server.write)?;

        let outcome = mcp_call(&mut mcp, Operation::CertRenew, Scope::Write)?;
        assert!(
            matches!(outcome, OpOutcome::CertRenewRequested),
            "{outcome:?}"
        );
        assert_eq!(renewer.calls(), 1);
        assert_eq!(
            renew_records(&mut mcp)?,
            [(AuditResult::Started, None), (AuditResult::Ok, None)]
        );

        // A read token: the engine refuses before the hook, so the server is
        // not even contacted (its auth log holds one request only).
        let refused = mcp_call(&mut mcp, Operation::CertRenew, Scope::Read);
        assert!(matches!(refused, Err(OpsError::Denied(_))), "{refused:?}");
        assert_eq!(renewer.calls(), 1);
        let records = renew_records(&mut mcp)?;
        assert_eq!(records.len(), 3, "{records:?}");
        assert_eq!(
            records.last().map(|(result, _)| *result),
            Some(AuditResult::Denied)
        );
        let audit =
            std::fs::read_to_string(server.dir.path().join("audit").join("detent-auth.jsonl"))?;
        assert_eq!(audit.matches("cert_renew_requested").count(), 1, "{audit}");
        server.stop()
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn mcp_cert_renew_tells_the_servers_refusals_apart() -> R {
        use detent_ops::{AuditResult, Operation, OpsError};
        use detent_web::authz::Scope;
        let cert_error = |result: Result<_, OpsError>| match result {
            Err(OpsError::Cert { id, reason }) => Ok((id.as_str(), reason)),
            other => Err(format!("expected a certificate error, got {other:?}")),
        };

        // A token the server does not know: 401.
        let renewer = std::sync::Arc::new(CountingRenewer::default());
        let server = RenewServer::start(Some(std::sync::Arc::clone(&renewer)))?;
        let unknown = "0".repeat(64);
        let mut mcp = mcp_session(&server.settings, &unknown)?;
        let (id, reason) = cert_error(mcp_call(&mut mcp, Operation::CertRenew, Scope::Write))?;
        assert_eq!(id, "cli-cert-renew-token-refused");
        assert!(reason.contains("HTTP 401"), "{reason}");
        assert_eq!(renewer.calls(), 0);
        // The refusal is audited with its id.
        assert_eq!(
            renew_records(&mut mcp)?,
            [
                (AuditResult::Started, None),
                (
                    AuditResult::Error,
                    Some("cli-cert-renew-token-refused".to_owned())
                ),
            ]
        );
        // A read-only token at the server although the engine let it by: 403.
        let mut mcp = mcp_session(&server.settings, &server.read)?;
        let (id, reason) = cert_error(mcp_call(&mut mcp, Operation::CertRenew, Scope::Write))?;
        assert_eq!(id, "cli-cert-renew-token-refused");
        assert!(reason.contains("HTTP 403"), "{reason}");
        assert_eq!(renewer.calls(), 0);
        server.stop()?;

        // No acme process: 409.
        let server = RenewServer::start(None)?;
        let mut mcp = mcp_session(&server.settings, &server.write)?;
        let (id, _) = cert_error(mcp_call(&mut mcp, Operation::CertRenew, Scope::Write))?;
        assert_eq!(id, "cli-cert-renew-not-acme");
        server.stop()?;

        // The acme channel is closed: 503 with the server's own id.
        let renewer = std::sync::Arc::new(CountingRenewer {
            fail: true,
            ..CountingRenewer::default()
        });
        let server = RenewServer::start(Some(std::sync::Arc::clone(&renewer)))?;
        let mut mcp = mcp_session(&server.settings, &server.write)?;
        let (id, reason) = cert_error(mcp_call(&mut mcp, Operation::CertRenew, Scope::Write))?;
        assert_eq!(id, "cli-cert-renew-server-error");
        assert!(
            reason.contains("HTTP 503: web-cert-renew-unavailable"),
            "{reason}"
        );
        assert_eq!(renewer.calls(), 1);
        server.stop()
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn mcp_cert_tools_name_the_address_they_could_not_use() -> R {
        use detent_ops::{Operation, OpsError};
        use detent_web::authz::Scope;
        let cert_error = |result: Result<_, OpsError>| match result {
            Err(OpsError::Cert { id, reason }) => Ok((id.as_str(), reason)),
            other => Err(format!("expected a certificate error, got {other:?}")),
        };
        let renewer = std::sync::Arc::new(CountingRenewer::default());
        let server = RenewServer::start(Some(std::sync::Arc::clone(&renewer)))?;
        let certs = server.dir.path().join("certs");

        // Nothing listens on the configured address.
        let closed = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .to_string();
        let path = server.dir.path().join("closed.toml");
        std::fs::write(&path, config_text(&closed, &certs))?;
        let mut mcp = mcp_session(&settings(server.dir.path(), path), &server.write)?;
        let (id, reason) = cert_error(mcp_call(&mut mcp, Operation::CertRenew, Scope::Write))?;
        assert_eq!(id, "cli-cert-renew-unreachable");
        assert!(reason.contains(&closed), "{reason}");

        // Another certificate in `tls.cert_dir`: the pin fails.
        let addr = server.listen_addr()?;
        let other = detent_web::bootstrap_self_signed(&["box.example".to_owned()])?;
        let other_certs = server.dir.path().join("other-certs");
        detent_web::tls::store_bootstrap(&other_certs, &other)?;
        let path = server.dir.path().join("wrong.toml");
        std::fs::write(&path, config_text(&addr, &other_certs))?;
        let mut mcp = mcp_session(&settings(server.dir.path(), path), &server.write)?;
        let (id, reason) = cert_error(mcp_call(&mut mcp, Operation::CertRenew, Scope::Write))?;
        assert_eq!(id, "cli-cert-renew-unreachable");
        assert!(
            reason.contains(&addr) && reason.contains("TLS handshake failed"),
            "{reason}"
        );
        assert_eq!(renewer.calls(), 0);

        // No certificate stored: both tools say where.
        let empty = server.dir.path().join("no-certs");
        let path = server.dir.path().join("empty.toml");
        std::fs::write(&path, config_text(&addr, &empty))?;
        let mut mcp = mcp_session(&settings(server.dir.path(), path), &server.write)?;
        for op in [Operation::CertStatus, Operation::CertRenew] {
            let (id, reason) = cert_error(mcp_call(&mut mcp, op, Scope::Write))?;
            assert_eq!(id, "cli-cert-missing");
            assert!(reason.contains(&empty.display().to_string()), "{reason}");
        }

        // A configuration that does not parse.
        let path = server.dir.path().join("broken.toml");
        std::fs::write(&path, "listen = [")?;
        let mut mcp = mcp_session(&settings(server.dir.path(), path.clone()), &server.write)?;
        for op in [Operation::CertStatus, Operation::CertRenew] {
            let (id, reason) = cert_error(mcp_call(&mut mcp, op, Scope::Write))?;
            assert_eq!(id, "cli-config-load-failed");
            assert!(reason.contains(&path.display().to_string()), "{reason}");
        }
        assert_eq!(renewer.calls(), 0);
        server.stop()
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn the_token_never_reaches_a_tool_answer_an_error_or_a_log_line() -> R {
        use detent_ops::{Operation, OpsError};
        use detent_web::authz::Scope;
        let renewer = std::sync::Arc::new(CountingRenewer::default());
        let server = RenewServer::start(Some(std::sync::Arc::clone(&renewer)))?;
        let token = server.write.clone();
        let tokens = [token.as_str()];
        let addr = server.listen_addr()?;
        let certs = server.dir.path().join("certs");
        let closed = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .to_string();

        // Each way a request ends: accepted, refused by the engine, not
        // accepted by the server, not sent because the port is closed, and
        // not sent because the certificate does not match.
        let other = detent_web::bootstrap_self_signed(&["box.example".to_owned()])?;
        let other_certs = server.dir.path().join("other-certs");
        detent_web::tls::store_bootstrap(&other_certs, &other)?;
        let mut seen = Vec::new();
        let ((), logs) = crate::tests_support::capture(|| {
            for (name, config, scope) in [
                ("good", config_text(&addr, &certs), Scope::Write),
                ("read", config_text(&addr, &certs), Scope::Read),
                ("closed", config_text(&closed, &certs), Scope::Write),
                ("pinned", config_text(&addr, &other_certs), Scope::Write),
            ] {
                let path = server.dir.path().join(format!("{name}.toml"));
                if std::fs::write(&path, config).is_err() {
                    continue;
                }
                let Ok(mut mcp) = mcp_session(&settings(server.dir.path(), path), &token) else {
                    continue;
                };
                for op in [Operation::CertStatus, Operation::CertRenew] {
                    let text = match mcp_call(&mut mcp, op, scope) {
                        Ok(outcome) => format!(
                            "{outcome:?} {}",
                            serde_json::to_string(&outcome).unwrap_or_default()
                        ),
                        Err(err) => {
                            format!("{err} {err:?} {}", OpsError::message_id(&err).as_str())
                        }
                    };
                    seen.push(text);
                }
            }
        });
        assert!(seen.len() >= 8, "{seen:?}");
        assert!(
            seen.iter().any(|text| text.contains("CertRenewRequested")),
            "{seen:?}"
        );
        assert!(seen.iter().any(|text| text.contains(&closed)), "{seen:?}");
        for text in &seen {
            crate::tests_support::assert_clean("a tool answer", text, &tokens);
        }
        crate::tests_support::assert_clean("the log", &logs, &tokens);
        server.stop()
    }
}
#[cfg(test)]
mod dry_run_tests {
    use super::run;
    use crate::i18n::Messages;
    use crate::output::{Exit, Renderer};
    use crate::run::{Settings, Streams};
    #[test]
    fn a_dry_run_names_modules_targets_and_state() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let root = dir.path().join("state");
        std::fs::create_dir(&root)?;
        let settings = Settings {
            state_root: root.clone(),
            config_path: dir.path().join("detent.toml"),
        };
        let messages = Messages::new(Some("en-US"));
        let renderer = Renderer {
            messages: &messages,
            json: false,
            verbose: false,
        };
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = run(
            true,
            &settings,
            &renderer,
            &mut Streams {
                input: &mut std::io::empty(),
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        let text = String::from_utf8(out)?;
        assert!(text.contains(&root.display().to_string()), "{text}");
        Ok(())
    }
}
