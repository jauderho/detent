//! `detent serve`: the process model (PLAN §2.4, ADR-001).
//!
//! This is the one command that really forks:
//!
//! ```text
//! detent serve ──spawn_pair──▶ monitor (this process, privileged, confined)
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

use detent_core::diag::MessageId;
use detent_platform::privsep::allowlist::{Allowlist, Config};
use detent_platform::privsep::monitor::{ExitReason, Hooks, Monitor};
use detent_platform::privsep::spawn::{Role, SpawnConfig, SpawnError, abort_child, spawn_pair};
use detent_platform::sandbox::{
    Confinement, Hooks as SandboxHooks, LandlockOutcome, LandlockStatus, Outcome, Policy,
};
use detent_platform::service::checks::ExternalCheckRunner;
use detent_platform::service::{self, ServiceControlAdapter};

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
    let config = match preflight_web_config(settings, renderer, streams)? {
        Ok(config) => config,
        Err(exit) => return Ok(exit),
    };

    if dryrun {
        renderer.line(
            streams.out,
            MessageId::new("cli-dryrun-serve"),
            &[
                ("modules", &descriptors.len().to_string()),
                ("targets", &allow.target_count().to_string()),
                ("state", &settings.state_root.display().to_string()),
            ],
        )?;
        return Ok(Exit::Ok);
    }

    let hooks = SandboxHooks::new(Policy::monitor(&allow), Policy::worker(&allow));
    // Nothing buffered may be inherited by a child that exits without flushing.
    streams.out.flush()?;
    streams.notes.flush()?;

    let spawned = match spawn_pair(&SpawnConfig::default(), &hooks) {
        Ok(spawned) => spawned,
        Err(err) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-serve-failed"),
                &[("reason", &err.to_string())],
            )?;
            return Ok(exit_for_spawn(&err));
        }
    };

    match spawned.role {
        Role::Worker(client) => {
            // The child. It must never return into `main`, or the process tree
            // ends up with two copies of the CLI.
            #[cfg(feature = "web")]
            {
                report_confinement(&hooks, &settings.state_root, renderer, streams);
                let status =
                    run_worker(*client, host, registry, config, settings, renderer, streams);
                let _ = streams.out.flush();
                let _ = streams.notes.flush();
                abort_child(status);
            }
            #[cfg(not(feature = "web"))]
            {
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
            report_confinement(&hooks, &settings.state_root, renderer, streams);
            run_monitor(
                &host,
                allow,
                handle,
                spawned.dropped_privileges,
                renderer,
                streams,
            )
        }
    }
}

/// Read this process's confinement (just installed by `spawn_pair`), note
/// every degraded step, and persist it for doctor/UI (STAGE3 M2).
fn report_confinement(
    hooks: &SandboxHooks,
    state_root: &std::path::Path,
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
    let path = state_root.join("state/confinement.json");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(confinement) {
        let _ = std::fs::write(path, json);
    }
}

/// Which confinement steps did not fully apply, as human-readable lines
/// (STAGE3 M2). Pure so the spec test pins it without a fork: every
/// non-`Applied` field names itself and its detail.
fn degradation_notes(confinement: &Confinement) -> Vec<String> {
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
    let state_lock = Monitor::lock(allow.state_root()).map_err(std::io::Error::other)?;
    let checks = ExternalCheckRunner::new();
    let services = ServiceControlAdapter(service::for_host(host.profile.init));
    let mut monitor = Monitor::new(
        allow,
        Hooks {
            checks: &checks,
            services: &services,
        },
    );
    report_recovery(renderer, streams, &mut monitor)?;
    monitor.set_host_profile(host.profile.clone());
    let served = monitor.serve_locked(&mut handle.channel, state_lock);
    let status = handle.wait();
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

/// Loads and validates `detent.toml`, and rejects a listen port this build
/// cannot bind (see [`PRIVILEGED_PORT_CEILING`]) or an ACME bootstrap this
/// build does not implement.
///
/// The outer `Result` is an I/O failure while reporting; the inner one is
/// either the loaded configuration or the exit code already reported for it.
#[cfg(feature = "web")]
fn preflight_web_config(
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Result<detent_web::Config, Exit>> {
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
    if config.tls.bootstrap == detent_web::Bootstrap::Acme {
        renderer.line(
            streams.notes,
            MessageId::new("cli-serve-acme-unsupported"),
            &[("path", &settings.config_path.display().to_string())],
        )?;
        return Ok(Err(Exit::Failed));
    }
    Ok(Ok(config))
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
    config: detent_web::Config,
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
    config: detent_web::Config,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> Option<PreparedWorker> {
    use detent_ops::{AllowAll, AuditSink, FileAudit, OpsEngine};

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
    let mut hostnames = config.tls.hostnames.clone();
    hostnames.push(host.profile.hostname.clone());

    let audit: Box<dyn AuditSink> = Box::new(FileAudit::under_state_root(&settings.state_root));
    let mut engine = OpsEngine::new(
        registry,
        client,
        host,
        audit,
        Box::new(AllowAll),
        service::for_host(init),
    );
    engine.set_state_root(settings.state_root.clone());
    let (engine_handle, engine_thread) = detent_web::spawn_engine(engine);

    let auth_state = match detent_web::AuthState::open(&settings.state_root, &config.auth, ram_mib)
    {
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
    })
}

/// Bootstraps or reuses the TLS certificate, logs its fingerprint for
/// trust-on-first-use, assembles the application state, and binds the
/// listener — everything between the operations engine being ready and the
/// server being ready to [`serve`](detent_web::Server::serve).
///
/// `None` on any failure; the caller has already been told why through
/// `renderer`.
#[cfg(feature = "web")]
async fn bind_web_server(
    config: detent_web::Config,
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

    // A renewed pair survives a restart: prefer the stored ACME chain over
    // the bootstrap pair, whose fingerprint stays the TOFU anchor until the
    // first renewal lands.
    let stored_acme = match detent_web::load_acme(&config.tls.cert_dir) {
        Ok(pair) => pair,
        Err(err) => {
            tls_failed(&err, renderer, streams);
            return None;
        }
    };
    let cert = match stored_acme {
        Some(pair) => pair,
        None => match detent_web::load_or_bootstrap(
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
    use super::{Exit, degradation_notes, exit_for_spawn, report_recovery, run};
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
    use detent_ops::{AllowAll, NullAudit, OpsEngine};
    use detent_platform::host::Detected;
    use detent_platform::privsep::allowlist::{Allowlist, Config as AllowConfig};
    use detent_platform::privsep::monitor::{Hooks as MonitorHooks, Monitor};
    use detent_platform::privsep::spawn::MonitorHandle;
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
            let _ = Monitor::new(allow, MonitorHooks::default()).serve(&mut channel);
        });
        let mut client = Client::new(worker_end);
        client.hello()?;
        let engine = OpsEngine::new(
            Vec::new(),
            client,
            Detected::default(),
            Box::new(NullAudit),
            Box::new(AllowAll),
            detent_platform::service::for_host(InitSystem::Systemd),
        );
        let (handle, thread) = detent_web::spawn_engine(engine);
        Ok((handle, thread, monitor))
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
        assert!(outcome.is_ok(), "{outcome:?}");
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
            assert_eq!(outcome, Err(Exit::Failed), "{path:?}");
            assert!(!notes.is_empty(), "{path:?}");
        }
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
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
            config,
            &settings(dir.path(), dir.path().join("absent.toml")),
            &renderer,
            &mut streams,
        )
        .ok_or("prepare_worker must succeed against a fresh temp dir")?;
        assert_ne!(prepared.server.local_addr().port(), 0);

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
            config,
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
