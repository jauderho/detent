//! Turning a parsed [`Cli`] into an [`Operation`] and back into output.
//!
//! # The process model of a one-shot command (deviation from PLAN §2.4)
//!
//! `detent serve` forks a real privsep pair ([`crate::serve`]). A one-shot
//! command runs the monitor on a **background thread of the same process**,
//! joined by the same `SOCK_SEQPACKET` pair and speaking the same closed
//! protocol against the same allow-list ([`Session::start`]).
//!
//! That is deliberate. The privsep boundary of ADR-001 protects the privileged
//! monitor from the *network-facing* worker: TLS, HTTP, ACME and the UI all live
//! on the worker side, and a compromise there must not become a compromise of
//! `/etc`. A one-shot CLI has no network-facing side — its authority is already
//! the uid that typed the command (`detent_ops::identity`), and it would fork to
//! talk to a copy of itself with exactly the same privileges. What the monitor
//! *does* still buy here is its allow-list discipline: the CLI can only name
//! ids, so a module bug still cannot make it write a path no descriptor
//! declared. `detent doctor` exercises the real fork, so the spawning path is
//! not left untested.
//!
//! # `--dryrun`
//!
//! Every mutating operation is intercepted before it reaches the engine
//! ([`Session::execute`]): an `Apply` is replaced by the `Plan` it implies, so
//! the diff is still printed, and every other mutation prints what it would have
//! done. The audit sink is [`NullAudit`] for the whole run, so a dry run leaves
//! no trace of its own either.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread::JoinHandle;

use detent_core::descriptor::{HostProfile, ModuleDescriptor};
use detent_core::diag::MessageId;
use detent_core::module::DynModule;
use detent_ops::report::OpOutcome;
use detent_ops::{
    AllowAll, AuditQuery, AuditSink, FileAudit, Identity, NullAudit, OpKind, Operation, OpsEngine,
    OpsError,
};
use detent_platform::fs::atomic::Sha256Digest;
use detent_platform::host::Detected;
use detent_platform::privsep::allowlist::{Allowlist, Config, DEFAULT_STATE_ROOT};
use detent_platform::privsep::monitor::{ExitReason, Hooks, Monitor, MonitorError};
use detent_platform::privsep::proto::{BackupId, CommitId};
use detent_platform::privsep::transport::Channel;
use detent_platform::privsep::worker::Client;
use detent_platform::service::checks::ExternalCheckRunner;
use detent_platform::service::{self, ServiceControlAdapter};
use serde::Serialize;
use serde_json::Value;

use crate::cli::{BackupAction, Cli, Command, CommitAction, ConfigAction};
use crate::i18n::Messages;
use crate::output::{ErrorContext, Exit, Renderer};

/// The default configuration file (PLAN §2.10).
pub const DEFAULT_CONFIG_PATH: &str = "/etc/detent/detent.toml";

/// The streams a run reads from and writes to, injected so every path is
/// testable without a subprocess.
pub struct Streams<'a> {
    /// Where a JSON model is read from.
    pub input: &'a mut dyn Read,
    /// Where data goes.
    pub out: &'a mut dyn Write,
    /// Where notes, diagnostics and errors go.
    pub notes: &'a mut dyn Write,
}

/// A failure that is the caller's fault: bad arguments, or bad stdin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError {
    /// The Fluent id of the complaint.
    pub id: MessageId,
    /// The offending value or the parser's reason.
    pub detail: String,
}

/// Everything resolved before any work happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Root of detent's mutable state (PLAN §2.10).
    pub state_root: PathBuf,
    /// The configuration file this run would read.
    ///
    /// Parsed on demand by [`Settings::load_web_config`], not eagerly here:
    /// `detent.toml`'s `[listen]`/`[tls]`/`[auth]` tables are consumed only by
    /// `serve`, `setup`, `user` and `token` (PLAN §2.10), all of which exist
    /// only when the `web` feature is compiled in. A one-shot command such as
    /// `host` or `config <module> get` never reads this file, so a malformed
    /// `detent.toml` does not stop it — and in a `--no-default-features`
    /// build with no `web`, this path is carried but never opened at all.
    pub config_path: PathBuf,
}

impl Settings {
    /// Resolves the paths from the global flags and the documented defaults.
    #[must_use]
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            state_root: cli
                .state_root
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_ROOT)),
            config_path: cli
                .config
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
        }
    }

    /// Reads and validates [`config_path`](Self::config_path) as a
    /// `detent-web` configuration.
    ///
    /// A missing file is [`detent_web::Config::default`] — the documented
    /// defaults, not a failure. Only compiled when the `web` feature is,
    /// since nothing else in this crate has a use for `[listen]`/`[tls]`/
    /// `[auth]`.
    ///
    /// # Errors
    ///
    /// [`detent_web::ConfigError`] when the file exists but cannot be read,
    /// is not valid TOML, carries an unknown key, or holds a value
    /// [`detent_web::Config::validate`] refuses.
    #[cfg(feature = "web")]
    pub fn load_web_config(&self) -> Result<detent_web::Config, detent_web::ConfigError> {
        detent_web::Config::load(&self.config_path)
    }
}

/// Renders a [`detent_web::ConfigError`] as a startup failure.
///
/// Shared by `serve` ([`crate::serve`]) and the web-admin commands
/// ([`crate::webadmin`]): each is the first thing in its run to touch
/// `detent.toml`, and a malformed file is a clean, localized exit rather than
/// a bare `Err` debug print.
///
/// # Errors
///
/// Whatever the streams report.
#[cfg(feature = "web")]
pub(crate) fn report_web_config_error(
    err: &detent_web::ConfigError,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    renderer.line(
        streams.notes,
        MessageId::new("cli-config-load-failed"),
        &[
            ("path", &settings.config_path.display().to_string()),
            ("reason", &err.to_string()),
        ],
    )?;
    Ok(Exit::Failed)
}

/// Runs one parsed command to completion and reports the exit code.
///
/// Never returns `Err`: a stream that cannot be written to is itself an exit
/// code, and there is nowhere left to report it.
#[must_use]
pub fn run(cli: &Cli, streams: &mut Streams<'_>) -> Exit {
    let messages = Messages::new(cli.locale.as_deref());
    let renderer = Renderer {
        messages: &messages,
        json: cli.json,
        verbose: cli.verbose,
    };
    match dispatch(cli, &renderer, streams) {
        Ok(exit) => exit,
        // The only errors reaching here are write failures on a stream we
        // would have to use to report them.
        Err(_) => Exit::Failed,
    }
}

/// Dispatches one command.
fn dispatch(
    cli: &Cli,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    // `detent --self-test` is the whole command (PLAN §2.9 step 5): with a
    // subcommand it is a usage error, never a silently ignored flag.
    if cli.self_test && cli.command.is_some() {
        writeln!(
            streams.out,
            "{}",
            renderer.messages.get(MessageId::new("cli-no-command"))
        )?;
        return Ok(Exit::Usage);
    }
    let settings = Settings::from_cli(cli);
    renderer.note(
        streams.notes,
        MessageId::new("cli-note-settings"),
        &[
            ("locale", renderer.messages.locale()),
            ("state", &settings.state_root.display().to_string()),
            ("config", &settings.config_path.display().to_string()),
        ],
    )?;

    match &cli.command {
        // `detent --self-test` (PLAN §2.9 step 5): the updater's health probe.
        // It is the whole command; anything else without a subcommand is a
        // usage error.
        None if cli.self_test => self_test(cli, renderer, streams),
        None => {
            renderer.note(streams.notes, MessageId::new("cli-note-settings"), &[])?;
            writeln!(
                streams.out,
                "{}",
                renderer.messages.get(MessageId::new("cli-no-command"))
            )?;
            Ok(Exit::Usage)
        }
        Some(Command::Completions { shell }) => {
            crate::completions::write(streams.out, *shell)?;
            Ok(Exit::Ok)
        }
        Some(Command::Doctor) => crate::doctor::report(&settings, renderer, streams),
        Some(Command::Serve) => crate::serve::run(cli.dryrun, &settings, renderer, streams),
        #[cfg(feature = "web")]
        Some(Command::Setup(args)) => {
            crate::webadmin::setup(args, cli.dryrun, &settings, renderer, streams)
        }
        #[cfg(feature = "web")]
        Some(Command::User { action }) => {
            crate::webadmin::user(action, cli.dryrun, &settings, renderer, streams)
        }
        #[cfg(feature = "web")]
        Some(Command::Token { action }) => {
            crate::webadmin::token(action, cli.dryrun, &settings, renderer, streams)
        }
        #[cfg(feature = "update")]
        Some(Command::Update(args)) => run_update(args, cli, renderer, streams),
        Some(Command::Config {
            module,
            action: ConfigAction::Defaults,
        }) => defaults(
            &detent_modules::modules(),
            &detent_platform::host::detect_real().profile,
            module,
            renderer,
            streams,
        ),
        _ => operate(cli, &settings, renderer, streams),
    }
}

/// `config <module> defaults`: the module's own defaults for this host.
///
/// This is the one command with no [`Operation`]: PLAN §2.5's operation set has
/// no `Defaults`, because computing a default model reads nothing privileged —
/// it is a pure function of the module and the detected host profile
/// (`DynModule::defaults_json`). Routing it through the monitor would buy
/// nothing and cost a socket.
fn defaults(
    registry: &[Box<dyn DynModule>],
    profile: &HostProfile,
    module: &str,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let Some(found) = registry.iter().find(|entry| entry.id() == module) else {
        return renderer.error(
            streams.notes,
            &OpsError::UnknownModule {
                id: module.to_owned(),
            },
            ErrorContext {
                module: Some(module),
                path: None,
            },
        );
    };
    match found.defaults_json(profile) {
        Ok(model) => {
            let text = serde_json::to_string_pretty(&model).map_err(std::io::Error::other)?;
            writeln!(streams.out, "{text}")?;
            Ok(Exit::Ok)
        }
        Err(err) => renderer.error(
            streams.notes,
            &OpsError::Module(err),
            ErrorContext {
                module: Some(module),
                path: None,
            },
        ),
    }
}

/// Everything that goes through the operations layer.
fn operate(
    cli: &Cli,
    settings: &Settings,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let operation = match operation_for(cli, streams.input) {
        Ok(operation) => operation,
        Err(usage) => {
            renderer.line(
                streams.notes,
                usage.id,
                &[("reason", &usage.detail), ("value", &usage.detail)],
            )?;
            return Ok(Exit::Usage);
        }
    };

    let host = detent_platform::host::detect_real();
    let registry = detent_modules::modules();
    let descriptors: Vec<&'static ModuleDescriptor> =
        registry.iter().map(|entry| entry.descriptor()).collect();
    let module = operation.module().map(ToOwned::to_owned);
    let path = module
        .as_deref()
        .and_then(|id| target_path(&descriptors, id, &host.profile));
    let context = ErrorContext {
        module: module.as_deref(),
        path,
    };
    let kind = operation.kind();

    let mut session = match Session::start(settings, host, registry, &descriptors, cli.dryrun) {
        Ok(session) => session,
        Err(err) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-start-failed"),
                &[("reason", &err)],
            )?;
            return Ok(Exit::Failed);
        }
    };

    renderer.note(
        streams.notes,
        MessageId::new("cli-note-operation"),
        &[
            ("operation", &crate::output::token(&kind)),
            ("module", context.module.unwrap_or_default()),
        ],
    )?;

    let exit = match session.execute(operation, cli.dryrun) {
        Ok(Executed::Ran(outcome)) => {
            renderer.outcome(streams.out, streams.notes, &outcome)?;
            Exit::Ok
        }
        Ok(Executed::WouldRun(report)) => {
            renderer.dry_run(streams.out, streams.notes, &report)?;
            Exit::Ok
        }
        Err(err) => renderer.error(streams.notes, &err, context)?,
    };
    if let Err(stop) = session.finish() {
        renderer.note(
            streams.notes,
            MessageId::new("cli-monitor-stop"),
            &[("reason", &stop)],
        )?;
    }
    Ok(exit)
}

/// The file a module manages on this host: the first target its own detector
/// accepts, falling back to the first declared one — the same rule
/// `detent_ops`'s engine applies when it resolves wiring.
#[must_use]
pub fn target_path(
    descriptors: &[&'static ModuleDescriptor],
    module: &str,
    profile: &HostProfile,
) -> Option<&'static str> {
    let descriptor = descriptors.iter().find(|entry| entry.id == module)?;
    descriptor
        .targets
        .iter()
        .find(|target| (target.backend_detect)(profile))
        .or_else(|| descriptor.targets.first())
        .map(|target| target.path.as_str())
}

/// Builds the [`Operation`] a command asks for, reading a model from `input`
/// where one is needed.
///
/// # Errors
///
/// [`UsageError`] when stdin is not JSON, or `--expect-hash` is not a digest.
pub fn operation_for(cli: &Cli, input: &mut dyn Read) -> Result<Operation, UsageError> {
    match &cli.command {
        Some(Command::Config { module, action }) => match action {
            // `defaults` never reaches the engine (see `defaults`); it maps to
            // the same read-only operation only so this function is total.
            ConfigAction::Get | ConfigAction::Defaults => {
                Ok(Operation::GetModule { id: module.clone() })
            }
            ConfigAction::Validate => Ok(Operation::Validate {
                id: module.clone(),
                model: read_model(input)?,
            }),
            ConfigAction::Plan => Ok(Operation::Plan {
                id: module.clone(),
                model: read_model(input)?,
            }),
            ConfigAction::Apply(args) => {
                let model = read_model(input)?;
                let expected_hash = match args.expect_hash {
                    Some(ref hex) => Some(parse_digest(hex)?),
                    None => None,
                };
                Ok(Operation::Apply {
                    id: module.clone(),
                    model,
                    expected_hash,
                    service_action: args.service.command(),
                    confirm: args.confirm,
                })
            }
        },
        Some(Command::Commit { action }) => Ok(match action {
            CommitAction::Confirm { id } => Operation::ConfirmCommit {
                commit_id: CommitId(*id),
            },
            CommitAction::Rollback { id } => Operation::RollbackCommit {
                commit_id: CommitId(*id),
            },
        }),
        Some(Command::Service { module, action }) => Ok(match action.command() {
            Some(command) => Operation::ServiceAction {
                id: module.clone(),
                action: command,
            },
            None => Operation::ServiceStatus { id: module.clone() },
        }),
        Some(Command::Backup { action }) => Ok(match action {
            BackupAction::List { module } => Operation::ListBackups { id: module.clone() },
            BackupAction::Restore { module, backup_id } => Operation::Restore {
                id: module.clone(),
                backup_id: BackupId(*backup_id),
            },
        }),
        Some(Command::Audit(args)) => Ok(Operation::AuditQuery(AuditQuery {
            module: args.module.clone(),
            who: args.who.clone(),
            limit: args.limit,
        })),
        Some(Command::Host) => Ok(Operation::HostProfile),
        // `dispatch` routes these away before an operation is needed; they
        // answer ListModules only so `operation_for` stays total.
        Some(_) | None => Ok(Operation::ListModules),
    }
}

/// The running build's own feature set, minus the JSON shape: the module ids
/// plus the compiled-in feature gates. `cfg!` per feature so the probe
/// reports this build, not the superset.
fn compiled_feature_ids() -> Vec<String> {
    let modules = detent_modules::modules();
    let mut features: Vec<String> = modules.iter().map(|entry| entry.id().to_owned()).collect();
    if cfg!(feature = "web") {
        features.push("web".to_owned());
    }
    if cfg!(feature = "ui") {
        features.push("ui".to_owned());
    }
    if cfg!(feature = "acme-dns01") {
        features.push("acme-dns01".to_owned());
    }
    if cfg!(feature = "acme-dns-providers") {
        features.push("acme-dns-providers".to_owned());
    }
    if cfg!(feature = "acme-attest") {
        features.push("acme-attest".to_owned());
    }
    if cfg!(feature = "update") {
        features.push("update".to_owned());
    }
    if cfg!(feature = "mcp") {
        features.push("mcp".to_owned());
    }
    if cfg!(feature = "init-systemd") {
        features.push("init-systemd".to_owned());
    }
    if cfg!(feature = "init-openrc") {
        features.push("init-openrc".to_owned());
    }
    if cfg!(feature = "init-bsdrc") {
        features.push("init-bsdrc".to_owned());
    }
    if cfg!(feature = "crypto-aws-lc") {
        features.push("crypto-aws-lc".to_owned());
    }
    if cfg!(feature = "crypto-ring") {
        features.push("crypto-ring".to_owned());
    }
    features.sort();
    features.dedup();
    features
}

/// What `detent --self-test` prints (shape mirrors
/// `detent_update::FeatureSet` so the updater's `covers` check reads either).
#[derive(serde::Serialize)]
struct SelfTestReport {
    version: String,
    features: Vec<String>,
}

/// `detent --self-test` (PLAN §2.9 step 5): the updater's health probe on a
/// freshly staged binary. Prints the running version and the compiled
/// feature set, as JSON under `--json`, one line per id otherwise.
///
/// Ungated: a minimal build without `update` still answers the probe. The
/// shape matches `detent_update::FeatureSet` so the updater's `covers` check
/// reads either one.
fn self_test(
    _cli: &Cli,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let features = compiled_feature_ids();
    let set = SelfTestReport {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        features,
    };
    if renderer.json {
        let text = serde_json::to_string_pretty(&set).map_err(std::io::Error::other)?;
        writeln!(streams.out, "{text}")?;
    } else {
        renderer.line(
            streams.out,
            MessageId::new("cli-self-test"),
            &[
                ("version", &set.version),
                ("features", &set.features.join(" ")),
            ],
        )?;
    }
    Ok(Exit::Ok)
}

/// `detent update …` (PLAN §2.9): `--check` reports; the bare form verifies,
/// self-tests and then swaps the candidate over this process's own
/// executable, which is also where it stages the download so the swap's
/// rename stays on one filesystem.
#[cfg(feature = "update")]
fn run_update(
    args: &crate::cli::UpdateArgs,
    cli: &Cli,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    use detent_update::Policy;
    use detent_update::fetch::RealTransport;
    let current = match semver::Version::parse(env!("CARGO_PKG_VERSION")) {
        Ok(version) => version,
        Err(err) => {
            return failed(renderer, streams, &err.to_string());
        }
    };
    let transport = match RealTransport::new() {
        Ok(transport) => transport,
        Err(err) => {
            return failed(renderer, streams, &err.to_string());
        }
    };
    let trust = match detent_update::trust::embedded() {
        Ok(trust) => trust,
        Err(err) => {
            return failed(renderer, streams, &err.to_string());
        }
    };
    // The running binary is both the swap's target and the staging dir's
    // parent: without it there is nothing to install over, so refuse here
    // rather than download into a directory the rename could not leave.
    let target = match std::env::current_exe() {
        Ok(target) => target,
        Err(err) => {
            return failed(renderer, streams, &err.to_string());
        }
    };
    let staging_parent = target
        .parent()
        .map_or_else(std::env::temp_dir, std::path::Path::to_path_buf);
    let config_path = Settings::from_cli(cli).config_path;
    run_update_on(
        &transport,
        &current,
        &Policy {
            min_age_days: Policy::default().min_age_days,
            allow_downgrade: args.allow_downgrade,
        },
        time::OffsetDateTime::now_utc(),
        &trust,
        args.check,
        &staging_parent,
        &|path| detent_update::update::confirm_features(path, &current_features()),
        // The swap runs in this process, with whatever privileges the
        // operator has (PLAN §2.9 step 5b); there is no privsep path.
        &|candidate| detent_update::install::swap(candidate, &target),
        &|| restart_and_check(&config_path),
        renderer,
        streams,
    )
}

/// The systemd/OpenRC names detent's own service may carry. `packaging/`
/// installs it as `detent`; the `.service` suffix is what `systemctl` prints,
/// so both resolve.
#[cfg(feature = "update")]
const DETENT_UNITS: detent_core::descriptor::UnitNames = detent_core::descriptor::UnitNames {
    systemd: &["detent.service", "detent"],
    openrc: &["detent"],
    bsdrc: &["detent"],
};

/// Restarts detent's own service and asks the listener whether it came back.
///
/// Reads `detent.toml` for the address to poll and the certificate to pin —
/// the health check is the only reason this command needs the config at all,
/// and a config it cannot read means a check it cannot make.
#[cfg(feature = "update")]
fn restart_and_check(config_path: &std::path::Path) -> RestartOutcome {
    use detent_core::descriptor::ServiceAction;
    use detent_platform::service::ServiceError;

    let config = match detent_web::Config::load(config_path) {
        Ok(config) => config,
        Err(err) => return RestartOutcome::Unhealthy(err.to_string()),
    };
    let manager =
        detent_platform::service::for_host(detent_platform::host::detect_real().profile.init);
    match manager.act(&DETENT_UNITS, ServiceAction::Restart) {
        Ok(_) => {}
        // Nothing to restart: this host does not run detent as a service.
        // The binary is installed and sound, so this is not a rollback.
        // `Unsupported` is NullManager (no init system) and LaunchdManager
        // (macOS is status-only by design): both mean no service to restart.
        Err(
            err @ (ServiceError::NoKnownUnit { .. }
            | ServiceError::Unavailable(_)
            | ServiceError::Unsupported(_)),
        ) => {
            return RestartOutcome::NotAService(err.to_string());
        }
        Err(err) => return RestartOutcome::Unhealthy(err.to_string()),
    }

    let cert_path = config
        .tls
        .cert_dir
        .join(detent_web::tls::BOOTSTRAP_CERT_FILE);
    let cert = match std::fs::read(&cert_path) {
        Ok(cert) => cert,
        Err(err) => {
            return RestartOutcome::Unhealthy(format!("{}: {err}", cert_path.display()));
        }
    };
    match detent_update::health::wait_healthy(
        config.listen.addr,
        &cert,
        detent_update::health::DEADLINE,
    ) {
        Ok(()) => RestartOutcome::Healthy,
        Err(err) => RestartOutcome::Unhealthy(err.to_string()),
    }
}

/// The running build's own feature set, as the updater's `covers` check reads
/// it (PLAN §2.9 step 5).
#[cfg(feature = "update")]
fn current_features() -> detent_update::FeatureSet {
    detent_update::FeatureSet {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        features: compiled_feature_ids(),
    }
}

/// The self-test probe run on a verified candidate (PLAN §2.9 step 5): the
/// candidate binary's own `--self-test --json`, feature-checked against the
/// running build. A seam so hermetic tests record when the probe ran
/// without executing anything.
#[cfg(feature = "update")]
type FeatureProbe =
    dyn Fn(&std::path::Path) -> Result<detent_update::FeatureSet, detent_update::UpdateError>;

/// The atomic swap run on a probed candidate (PLAN §2.9 step 5b). A seam for
/// the same reason as [`FeatureProbe`]: hermetic tests drive both outcomes
/// without replacing the test runner's own executable.
#[cfg(feature = "update")]
type BinarySwap<'a> =
    dyn Fn(&std::path::Path) -> Result<detent_update::Installed, detent_update::UpdateError> + 'a;

/// Restarts the service and reports whether it came back serving.
///
/// One seam, not two: the restart and the health check are a single question
/// — "is the new binary running and serving?" — and splitting them would let
/// a test assert a restart that no health check followed, which is exactly
/// the bug this step exists to prevent. Real implementation in
/// [`restart_and_check`]; the tests substitute an answer.
#[cfg(feature = "update")]
type RestartCheck<'a> = dyn Fn() -> RestartOutcome + 'a;

/// What restarting the service achieved.
#[cfg(feature = "update")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartOutcome {
    /// Restarted, and `/healthz` answered in time.
    Healthy,
    /// This host does not run detent under its init system, so there was
    /// nothing to restart. **Not** a rollback: the binary is sound, it simply
    /// is not a managed service, and someone invoked the CLI by hand.
    NotAService(String),
    /// Restarted but never became healthy, or could not be restarted at all.
    /// The swap must be undone.
    Unhealthy(String),
}

/// The policy half of `run_update`, behind a `Transport` seam so tests run
/// hermetic: pick `--check` vs bare-update without touching the network.
/// The trust root and the candidate self-test probe are injected the same
/// way, so the full bare-`update` order (verify → self-test → refuse) is
/// observable with zero subprocesses.
#[cfg(feature = "update")]
#[allow(clippy::too_many_arguments)]
fn run_update_on(
    transport: &dyn detent_update::fetch::Transport,
    current: &semver::Version,
    policy: &detent_update::Policy,
    now: time::OffsetDateTime,
    trust: &detent_update::TrustRoot,
    check_only: bool,
    staging_parent: &std::path::Path,
    probe: &FeatureProbe,
    swap: &BinarySwap<'_>,
    restart: &RestartCheck<'_>,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    if check_only {
        return check_report(transport, current, policy, now, renderer, streams);
    }
    apply_update(
        transport,
        current,
        policy,
        now,
        trust,
        staging_parent,
        probe,
        swap,
        restart,
        renderer,
        streams,
    )
}

/// The `--check` half of `run_update`: resolve the policy, print the report.
#[cfg(feature = "update")]
fn check_report(
    transport: &dyn detent_update::fetch::Transport,
    current: &semver::Version,
    policy: &detent_update::Policy,
    now: time::OffsetDateTime,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let report = match detent_update::update::check(transport, current, policy, now) {
        Ok(report) => report,
        Err(err) => {
            return failed(renderer, streams, &err.to_string());
        }
    };
    if renderer.json {
        let text = serde_json::to_string_pretty(&report).map_err(std::io::Error::other)?;
        writeln!(streams.out, "{text}")?;
    } else if report.update_available {
        render_available(&report, renderer, streams)?;
    } else {
        renderer.line(
            streams.out,
            MessageId::new("cli-update-none"),
            &[("current", &report.current)],
        )?;
    }
    Ok(Exit::Ok)
}

/// The human half of a positive `--check`: the security line when the
/// release body carries the marker, the plain line otherwise.
#[cfg(feature = "update")]
fn render_available(
    report: &detent_update::CheckReport,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<()> {
    let args = [
        ("tag", report.tag.as_deref().unwrap_or_default()),
        ("published", report.published.as_deref().unwrap_or_default()),
    ];
    if report.security {
        renderer.line(
            streams.out,
            MessageId::new("cli-update-security-available"),
            &args,
        )?;
    } else {
        renderer.line(streams.out, MessageId::new("cli-update-available"), &args)?;
    }
    Ok(())
}

/// The bare-`update` half: verify into staging, run the candidate's own
/// self-test probe (feature-checked), and only then swap it over the running
/// binary. Every earlier refusal leaves the binary untouched.
#[cfg(feature = "update")]
#[allow(clippy::too_many_arguments)]
fn apply_update(
    transport: &dyn detent_update::fetch::Transport,
    current: &semver::Version,
    policy: &detent_update::Policy,
    now: time::OffsetDateTime,
    trust: &detent_update::TrustRoot,
    staging_parent: &std::path::Path,
    probe: &FeatureProbe,
    swap: &BinarySwap<'_>,
    restart: &RestartCheck<'_>,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    match detent_update::update::prepare(transport, current, policy, now, trust, staging_parent) {
        Ok(candidate) => {
            // §2.9 step 5's first half: the verified candidate must run and
            // cover this build's feature set before anything is installed.
            match probe(&candidate.binary_path) {
                Ok(_) => install_candidate(&candidate, swap, restart, renderer, streams),
                Err(err) => failed(renderer, streams, &err.to_string()),
            }
        }
        Err(err) => failed(renderer, streams, &err.to_string()),
    }
}

/// §2.9 step 5b+5c: the atomic swap, then the restart-and-`GET /healthz`
/// check. `Healthy` (or `NotAService`, where there is nothing to restart)
/// keeps the install; `Unhealthy` rolls back via
/// [`detent_update::Installed::rollback`] and restarts again.
#[cfg(feature = "update")]
fn install_candidate(
    candidate: &detent_update::StagedUpdate,
    swap: &BinarySwap<'_>,
    restart: &RestartCheck<'_>,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    let installed = match swap(&candidate.binary_path) {
        Ok(installed) => installed,
        Err(err) => return failed(renderer, streams, &err.to_string()),
    };
    let previous = installed.previous().display().to_string();
    let args = [
        ("tag", candidate.tag.as_str()),
        ("previous", previous.as_str()),
    ];

    match restart() {
        RestartOutcome::Healthy => {
            renderer.line(streams.out, MessageId::new("cli-update-installed"), &args)?;
            Ok(Exit::Ok)
        }
        // The binary installed and is sound; this host just does not run it
        // under an init system. Rolling back a good binary because the host
        // has no systemd would be wrong, so this succeeds and says so.
        RestartOutcome::NotAService(reason) => {
            renderer.line(streams.out, MessageId::new("cli-update-installed"), &args)?;
            renderer.line(
                streams.notes,
                MessageId::new("cli-update-not-restarted"),
                &[("reason", &reason)],
            )?;
            Ok(Exit::Ok)
        }
        RestartOutcome::Unhealthy(reason) => {
            roll_back(installed, &reason, restart, renderer, streams)
        }
    }
}

/// Puts the previous binary back and restarts again.
///
/// Two ways to fail, and they are not the same: a rollback that restores
/// service leaves the host exactly as it started, which is a failed update; a
/// rollback that cannot restore service leaves a host only a human can fix,
/// and must say so rather than report a tidy failure.
#[cfg(feature = "update")]
fn roll_back(
    installed: detent_update::Installed,
    reason: &str,
    restart: &RestartCheck<'_>,
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
) -> std::io::Result<Exit> {
    if let Err(err) = installed.rollback() {
        renderer.line(
            streams.notes,
            MessageId::new("cli-update-rollback-failed"),
            &[("reason", reason), ("error", &err.to_string())],
        )?;
        return Ok(Exit::Failed);
    }
    match restart() {
        RestartOutcome::Healthy | RestartOutcome::NotAService(_) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-update-rolled-back"),
                &[("reason", reason)],
            )?;
            Ok(Exit::Failed)
        }
        RestartOutcome::Unhealthy(after) => {
            renderer.line(
                streams.notes,
                MessageId::new("cli-update-rollback-failed"),
                &[("reason", reason), ("error", &after)],
            )?;
            Ok(Exit::Failed)
        }
    }
}

/// One localized failure line on `notes`, always `Failed` — never `Usage`,
/// so a refused update cannot be mistaken for a misspelled command.
#[cfg(feature = "update")]
fn failed(
    renderer: &Renderer<'_>,
    streams: &mut Streams<'_>,
    reason: &str,
) -> std::io::Result<Exit> {
    renderer.line(
        streams.notes,
        MessageId::new("cli-update-failed"),
        &[("reason", reason)],
    )?;
    Ok(Exit::Failed)
}

/// Reads a JSON model from `input`.
fn read_model(input: &mut dyn Read) -> Result<Value, UsageError> {
    let mut raw = String::new();
    input.read_to_string(&mut raw).map_err(|err| UsageError {
        id: MessageId::new("cli-bad-stdin"),
        detail: err.to_string(),
    })?;
    serde_json::from_str(&raw).map_err(|err| UsageError {
        id: MessageId::new("cli-bad-json"),
        detail: err.to_string(),
    })
}

/// Parses `--expect-hash`.
fn parse_digest(hex: &str) -> Result<Sha256Digest, UsageError> {
    hex.parse().map_err(|_| UsageError {
        id: MessageId::new("cli-bad-hash"),
        detail: hex.to_owned(),
    })
}

/// What [`Session::execute`] did.
#[derive(Debug)]
pub enum Executed {
    /// The operation ran.
    Ran(OpOutcome),
    /// `--dryrun` stopped a mutation, and this is what it would have done.
    WouldRun(Box<DryRun>),
}

/// What a dry run would have done.
#[derive(Debug, Clone, Serialize)]
pub struct DryRun {
    /// Always true, so a JSON consumer cannot mistake this for a real result.
    pub dryrun: bool,
    /// The operation that was withheld.
    pub operation: OpKind,
    /// The module it was about.
    pub module: Option<String>,
    /// For a withheld `Apply`, the plan it would have written.
    pub plan: Option<detent_ops::PlanReport>,
}

/// The monitor thread plus the engine that talks to it.
pub struct Session {
    engine: OpsEngine,
    monitor: Option<JoinHandle<Result<ExitReason, MonitorError>>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("running", &self.monitor.is_some())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Starts a monitor for `descriptors` and an engine over `registry`.
    ///
    /// # Errors
    ///
    /// A short untranslated reason (for `{$reason}` of `cli-start-failed`) when
    /// the allow-list, the socket pair, or the handshake fails.
    pub fn start(
        settings: &Settings,
        host: Detected,
        registry: Vec<Box<dyn DynModule>>,
        descriptors: &[&'static ModuleDescriptor],
        dryrun: bool,
    ) -> Result<Self, String> {
        let config = Config::with_state_root(&settings.state_root);
        let allow = Allowlist::from_modules(descriptors, &config).map_err(|err| err.to_string())?;
        let (monitor_end, worker_end) = Channel::pair().map_err(|err| err.to_string())?;

        let init = host.profile.init;
        let monitor = std::thread::spawn(move || {
            // Both collaborators are built inside the thread: `Hooks` borrows
            // them, and `&dyn CheckRunner` is not `Send`, so they cannot be
            // captured from outside.
            let checks = ExternalCheckRunner::new();
            let services = ServiceControlAdapter(service::for_host(init));
            let mut channel = monitor_end;
            Monitor::new(
                allow,
                Hooks {
                    checks: &checks,
                    services: &services,
                },
            )
            .serve(&mut channel)
        });

        let mut client = Client::new(worker_end);
        client.hello().map_err(|err| err.to_string())?;

        let audit: Box<dyn AuditSink> = if dryrun {
            Box::new(NullAudit)
        } else {
            Box::new(FileAudit::under_state_root(&settings.state_root))
        };
        let engine = OpsEngine::new(
            registry,
            client,
            host,
            audit,
            Box::new(AllowAll),
            service::for_host(init),
        );
        Ok(Self {
            engine,
            monitor: Some(monitor),
        })
    }

    /// Runs one operation as the local caller, honouring `--dryrun`.
    ///
    /// # Errors
    ///
    /// Whatever the operations layer reports.
    pub fn execute(&mut self, operation: Operation, dryrun: bool) -> Result<Executed, OpsError> {
        if !dryrun || !operation.is_mutating() {
            return self.engine.execute(operation, &caller()).map(Executed::Ran);
        }
        let kind = operation.kind();
        let module = operation.module().map(ToOwned::to_owned);
        // An apply still shows its diff: the plan it implies writes nothing.
        let plan = match operation {
            Operation::Apply { id, model, .. } => {
                match self
                    .engine
                    .execute(Operation::Plan { id, model }, &caller())?
                {
                    OpOutcome::Planned(plan) => Some(*plan),
                    _ => None,
                }
            }
            _ => None,
        };
        Ok(Executed::WouldRun(Box::new(DryRun {
            dryrun: true,
            operation: kind,
            module,
            plan,
        })))
    }

    /// Stops the monitor and joins its thread.
    ///
    /// # Errors
    ///
    /// A short untranslated reason when the monitor did not stop cleanly.
    pub fn finish(&mut self) -> Result<(), String> {
        let shutdown = self.engine.shutdown().map_err(|err| err.to_string());
        let joined = match self.monitor.take() {
            Some(handle) => handle
                .join()
                .map_err(|_| "monitor thread panicked".to_owned()),
            None => Ok(Ok(ExitReason::Shutdown)),
        };
        shutdown?;
        match joined? {
            Ok(ExitReason::Shutdown) => Ok(()),
            Ok(other) => Err(format!("{other:?}")),
            Err(err) => Err(err.to_string()),
        }
    }
}

/// The identity a local CLI run acts as: its authority is the uid of the
/// process (`detent_ops::identity`), and the name is for the audit log.
fn caller() -> Identity {
    let uid = rustix::process::geteuid().as_raw();
    let name = ["SUDO_USER", "USER", "LOGNAME"]
        .into_iter()
        .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| format!("uid:{uid}"));
    Identity::local(name)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_CONFIG_PATH, Session, Settings, Streams, caller, operation_for, run, target_path,
    };
    use crate::cli::Cli;
    use crate::output::Exit;
    use clap::Parser as _;
    use detent_core::descriptor::ModuleDescriptor;
    use detent_ops::{OpKind, Operation};
    use std::path::{Path, PathBuf};

    type R = Result<(), Box<dyn std::error::Error>>;

    fn parse(argv: &[&str]) -> Result<Cli, Box<dyn std::error::Error>> {
        Ok(Cli::try_parse_from(argv)?)
    }

    fn kind_of(argv: &[&str], stdin: &str) -> Result<OpKind, Box<dyn std::error::Error>> {
        let cli = parse(argv)?;
        let mut input = stdin.as_bytes();
        Ok(operation_for(&cli, &mut input)
            .map_err(|usage| usage.id.as_str())?
            .kind())
    }

    #[test]
    fn settings_default_to_the_documented_paths() -> R {
        let settings = Settings::from_cli(&parse(&["detent", "host"])?);
        assert_eq!(settings.state_root, PathBuf::from("/var/lib/detent"));
        assert_eq!(settings.config_path, PathBuf::from(DEFAULT_CONFIG_PATH));

        let settings = Settings::from_cli(&parse(&[
            "detent",
            "host",
            "--state-root",
            "/tmp/s",
            "--config",
            "/tmp/c.toml",
        ])?);
        assert_eq!(settings.state_root, PathBuf::from("/tmp/s"));
        assert_eq!(settings.config_path, PathBuf::from("/tmp/c.toml"));
        assert_eq!(settings.clone(), settings);
        assert!(format!("{settings:?}").contains("/tmp/s"));
        Ok(())
    }

    #[test]
    fn every_command_maps_to_the_operation_it_names() -> R {
        let model = r#"{"entries":[]}"#;
        for (argv, expected) in [
            (vec!["detent", "config", "hosts", "get"], OpKind::GetModule),
            (
                vec!["detent", "config", "hosts", "validate"],
                OpKind::Validate,
            ),
            (vec!["detent", "config", "hosts", "plan"], OpKind::Plan),
            (vec!["detent", "config", "hosts", "apply"], OpKind::Apply),
            (
                vec!["detent", "config", "hosts", "defaults"],
                OpKind::GetModule,
            ),
            (
                vec!["detent", "commit", "confirm", "1"],
                OpKind::ConfirmCommit,
            ),
            (
                vec!["detent", "commit", "rollback", "1"],
                OpKind::RollbackCommit,
            ),
            (
                vec!["detent", "service", "hosts", "status"],
                OpKind::ServiceStatus,
            ),
            (
                vec!["detent", "service", "hosts", "restart"],
                OpKind::ServiceAction,
            ),
            (
                vec!["detent", "backup", "list", "hosts"],
                OpKind::ListBackups,
            ),
            (
                vec!["detent", "backup", "restore", "hosts", "0"],
                OpKind::Restore,
            ),
            (vec!["detent", "audit"], OpKind::AuditQuery),
            (vec!["detent", "host"], OpKind::HostProfile),
            (vec!["detent", "doctor"], OpKind::ListModules),
            (vec!["detent", "serve"], OpKind::ListModules),
            (vec!["detent", "completions", "bash"], OpKind::ListModules),
        ] {
            assert_eq!(kind_of(&argv, model)?, expected, "{argv:?}");
        }
        Ok(())
    }

    #[test]
    fn apply_carries_its_flags_into_the_operation() -> R {
        let digest = detent_platform::fs::atomic::Sha256Digest::of(b"x").to_string();
        let cli = parse(&[
            "detent",
            "config",
            "hosts",
            "apply",
            "--service",
            "reload",
            "--confirm",
            "30s",
            "--expect-hash",
            &digest,
        ])?;
        let mut input = r#"{"entries":[]}"#.as_bytes();
        let operation = operation_for(&cli, &mut input).map_err(|usage| usage.id.as_str())?;
        assert!(matches!(
            operation,
            Operation::Apply {
                service_action: Some(detent_ops::ServiceCommand::Reload),
                confirm: Some(window),
                expected_hash: Some(_),
                ..
            } if window == std::time::Duration::from_secs(30)
        ));
        Ok(())
    }

    #[test]
    fn audit_filters_reach_the_query() -> R {
        let cli = parse(&["detent", "audit", "--module", "hosts", "--limit", "2"])?;
        let mut input = std::io::empty();
        let operation = operation_for(&cli, &mut input).map_err(|usage| usage.id.as_str())?;
        assert!(matches!(
            operation,
            Operation::AuditQuery(ref query)
                if query.module.as_deref() == Some("hosts") && query.limit == Some(2)
        ));
        Ok(())
    }

    #[test]
    fn malformed_stdin_and_digests_are_usage_errors() -> R {
        struct Unreadable;
        impl std::io::Read for Unreadable {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            }
        }

        let cli = parse(&["detent", "config", "hosts", "apply"])?;
        let mut input = "not json".as_bytes();
        assert_eq!(
            operation_for(&cli, &mut input).err().map(|err| err.id),
            Some(detent_core::diag::MessageId::new("cli-bad-json"))
        );

        let cli = parse(&["detent", "config", "hosts", "apply", "--expect-hash", "xyz"])?;
        let mut input = "{}".as_bytes();
        let err = operation_for(&cli, &mut input).err().ok_or("must fail")?;
        assert_eq!(err.id, detent_core::diag::MessageId::new("cli-bad-hash"));
        assert_eq!(err.detail, "xyz");
        assert_eq!(err.clone(), err);
        assert!(format!("{err:?}").contains("xyz"));

        let cli = parse(&["detent", "config", "hosts", "plan"])?;
        assert_eq!(
            operation_for(&cli, &mut Unreadable).err().map(|err| err.id),
            Some(detent_core::diag::MessageId::new("cli-bad-stdin"))
        );
        Ok(())
    }

    #[test]
    fn a_usage_error_from_stdin_exits_two() -> R {
        let mut input = "not json".as_bytes();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let cli = parse(&["detent", "config", "hosts", "apply"])?;
        let exit = run(
            &cli,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        );
        assert_eq!(exit, Exit::Usage);
        assert!(out.is_empty());
        assert!(!notes.is_empty());
        Ok(())
    }

    #[test]
    fn self_test_reports_the_compiled_feature_gates() -> R {
        let (exit, out, _) = run_with(&["detent", "--self-test", "--json"])?;
        assert_eq!(exit, Exit::Ok);
        let parsed: serde_json::Value = serde_json::from_str(&out)?;
        let features: Vec<String> =
            serde_json::from_value(parsed.get("features").cloned().unwrap_or_default())?;
        let gated = [
            (cfg!(feature = "web"), "web"),
            (cfg!(feature = "update"), "update"),
            (cfg!(feature = "init-systemd"), "init-systemd"),
            (cfg!(feature = "crypto-aws-lc"), "crypto-aws-lc"),
        ];
        for (compiled, name) in gated {
            assert_eq!(features.iter().any(|got| got == name), compiled, "{name}");
        }
        let (exit, out, _) = run_with(&["detent", "--self-test"])?;
        assert_eq!(exit, Exit::Ok);
        assert!(out.contains("version"), "{out}");
        let (exit, out, _) = run_with(&["detent"])?;
        assert_eq!(exit, Exit::Usage);
        assert!(!out.is_empty());
        Ok(())
    }

    #[test]
    fn self_test_with_a_subcommand_is_usage() -> R {
        let cli = parse(&["detent", "--self-test", "doctor"])?;
        assert!(cli.self_test && cli.command.is_some());
        let exit = run(
            &cli,
            &mut Streams {
                input: &mut std::io::empty(),
                out: &mut Vec::new(),
                notes: &mut Vec::new(),
            },
        );
        assert_eq!(exit, Exit::Usage);
        Ok(())
    }
    #[cfg(feature = "web")]
    #[test]
    fn web_config_errors_report_the_path_and_fail() -> R {
        use crate::i18n::Messages;
        use crate::output::Renderer;
        let messages = Messages::new(Some("en-US"));
        let renderer = Renderer {
            messages: &messages,
            json: false,
            verbose: false,
        };
        let settings = Settings::from_cli(&parse(&["detent", "host"])?);
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = super::report_web_config_error(
            &detent_web::ConfigError::ZeroValue {
                field: "listen.max_connections",
            },
            &settings,
            &renderer,
            &mut Streams {
                input: &mut std::io::empty(),
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(String::from_utf8(notes)?.contains("listen.max_connections"));
        Ok(())
    }

    #[test]
    fn run_maps_a_broken_stream_to_failure() -> R {
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }
        let cli = parse(&["detent"])?;
        let exit = run(
            &cli,
            &mut Streams {
                input: &mut std::io::empty(),
                out: &mut Broken,
                notes: &mut Broken,
            },
        );
        assert_eq!(exit, Exit::Failed);
        Ok(())
    }
    #[cfg(feature = "update")]
    #[test]
    fn run_update_on_routes_check_and_bare_update() -> R {
        let current = semver::Version::new(0, 0, 1);
        let policy = detent_update::Policy::default();
        let trust = fixture_trust()?;
        // `--check` reports and succeeds without ever probing a candidate.
        let never = probe_log();
        let never_swapped = probe_log();
        let feed = OneFeed {
            tag: "v0.0.2",
            body: "",
            when: "2020-01-01T00:00:00Z".to_owned(),
        };
        let run = run_update_hermetic(
            &feed,
            &current,
            &policy,
            &trust,
            &recording_ok_probe(&never, &[]),
            &unreachable_swap(&never_swapped),
            &healthy_restart(),
            true,
        )?;
        assert_eq!(run.exit, Exit::Ok);
        assert!(run.out.contains("v0.0.2"), "{}", run.out);
        assert!(never.borrow().is_empty(), "--check must not probe");
        assert!(never_swapped.borrow().is_empty(), "--check must not swap");
        // The bare form lands on `failed` when the feed is unreachable.
        let never = probe_log();
        let never_swapped = probe_log();
        let run = run_update_hermetic(
            &FailingFeed,
            &current,
            &policy,
            &trust,
            &recording_ok_probe(&never, &[]),
            &unreachable_swap(&never_swapped),
            &healthy_restart(),
            false,
        )?;
        assert_eq!(run.exit, Exit::Failed);
        assert!(run.out.is_empty());
        assert!(!run.notes.is_empty());
        assert!(never.borrow().is_empty());
        assert!(never_swapped.borrow().is_empty());
        Ok(())
    }
    #[cfg(feature = "update")]
    #[test]
    fn a_failed_check_is_a_localized_failure_not_usage() -> R {
        let current = semver::Version::new(0, 0, 1);
        let policy = detent_update::Policy::default();
        // FailingFeed refuses the list call: `check_report` must land on
        // `failed`, never Usage, so a refused update is not mistaken for a
        // misspelled command.
        let run = run_update_hermetic(
            &FailingFeed,
            &current,
            &policy,
            &fixture_trust()?,
            &recording_ok_probe(&probe_log(), &[]),
            &unreachable_swap(&probe_log()),
            &healthy_restart(),
            true,
        )?;
        assert_eq!(run.exit, Exit::Failed);
        assert!(run.out.is_empty());
        assert!(run.notes.contains("update failed"), "{}", run.notes);
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn bare_update_refuses_a_downgrade_without_allow_downgrade() -> R {
        let current = semver::Version::new(0, 0, 1);
        let trust = fixture_trust()?;
        let feed = VerifiableFeed {
            tag: "v0.0.0".to_owned(),
            body: String::new(),
            when: "2020-01-01T00:00:00Z".to_owned(),
            binary: binary_fixture()?,
        };
        let never = probe_log();
        let never_swapped = probe_log();
        let run = run_update_hermetic(
            &feed,
            &current,
            &detent_update::Policy::default(),
            &trust,
            &recording_ok_probe(&never, &[]),
            &unreachable_swap(&never_swapped),
            &healthy_restart(),
            false,
        )?;
        assert_eq!(run.exit, Exit::Failed);
        assert!(run.notes.contains("update failed"), "{}", run.notes);
        assert!(run.notes.contains("no update to install"), "{}", run.notes);
        assert!(
            never.borrow().is_empty(),
            "a downgrade must be refused before the probe runs"
        );
        assert!(never_swapped.borrow().is_empty(), "nothing may be swapped");
        // With `--allow-downgrade` the gate opens and the flow moves on to
        // verification — which refuses the mis-tagged candidate.
        let run = run_update_hermetic(
            &feed,
            &current,
            &detent_update::Policy {
                allow_downgrade: true,
                ..detent_update::Policy::default()
            },
            &trust,
            &recording_ok_probe(&probe_log(), &[]),
            &unreachable_swap(&probe_log()),
            &healthy_restart(),
            false,
        )?;
        assert_eq!(run.exit, Exit::Failed);
        assert!(
            !run.notes.contains("no update to install"),
            "allow_downgrade must get past the policy gate: {}",
            run.notes
        );
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn min_age_gate_and_the_security_bypass() -> R {
        let current = semver::Version::new(0, 0, 1);
        let trust = fixture_trust()?;
        // One day old: below the default two-day gate.
        let young = fixed_now()? - time::Duration::days(1);
        let when = young.format(&time::format_description::well_known::Rfc3339)?;
        let young_feed = VerifiableFeed {
            tag: "v0.0.2".to_owned(),
            body: String::new(),
            when: when.clone(),
            binary: binary_fixture()?,
        };
        let never = probe_log();
        let never_swapped = probe_log();
        let run = run_update_hermetic(
            &young_feed,
            &current,
            &detent_update::Policy::default(),
            &trust,
            &recording_ok_probe(&never, &[]),
            &unreachable_swap(&never_swapped),
            &healthy_restart(),
            false,
        )?;
        assert_eq!(run.exit, Exit::Failed);
        assert!(run.notes.contains("no update to install"), "{}", run.notes);
        assert!(
            never.borrow().is_empty(),
            "a too-young release must be refused before the probe"
        );
        assert!(never_swapped.borrow().is_empty(), "nothing may be swapped");
        // The same release carrying `detent-security: true` bypasses the gate
        // and drives the whole flow through verification and the probe into
        // the swap.
        let security = VerifiableFeed {
            body: "detent-security: true".to_owned(),
            ..young_feed
        };
        let calls = probe_log();
        let swaps = probe_log();
        let (_home, target) = install_target()?;
        let run = run_update_hermetic(
            &security,
            &current,
            &detent_update::Policy::default(),
            &trust,
            &recording_ok_probe(&calls, &["hosts", "web", "update"]),
            &recording_swap(&swaps, &target),
            &healthy_restart(),
            false,
        )?;
        assert_eq!(run.exit, Exit::Ok);
        assert!(
            run.out.contains("installed v0.0.2"),
            "the bypassed release must reach the probe and the swap: {}",
            run.out
        );
        assert_eq!(calls.borrow().len(), 1, "the self-test probe must run once");
        assert_eq!(swaps.borrow().len(), 1, "the swap must run once");
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn refusal_order_verify_then_self_test_then_swap() -> R {
        let current = semver::Version::new(0, 0, 1);
        let trust = fixture_trust()?;
        // Step 1: verification fails (the feed JSON is served as the SUMS
        // file), so the self-test probe must never run and nothing may be
        // installed.
        let calls = probe_log();
        let swaps = probe_log();
        let run = run_update_hermetic(
            &OneFeed {
                tag: "v0.0.2",
                body: "",
                when: "2020-01-01T00:00:00Z".to_owned(),
            },
            &current,
            &detent_update::Policy::default(),
            &trust,
            &recording_ok_probe(&calls, &[]),
            &unreachable_swap(&swaps),
            &healthy_restart(),
            false,
        )?;
        assert_eq!(run.exit, Exit::Failed);
        assert!(
            calls.borrow().is_empty(),
            "a failed verification must never run the probe"
        );
        assert!(
            swaps.borrow().is_empty(),
            "a failed verification must never swap"
        );
        assert!(run.out.is_empty(), "{}", run.out);
        // Step 2: on a fully verified candidate, a failing self-test refuses
        // before the swap runs.
        let calls = probe_log();
        let swaps = probe_log();
        let run = run_update_hermetic(
            &verified_feed()?,
            &current,
            &detent_update::Policy::default(),
            &trust,
            &recording_err_probe(&calls, make_self_test_failure),
            &unreachable_swap(&swaps),
            &healthy_restart(),
            false,
        )?;
        assert_eq!(run.exit, Exit::Failed);
        assert_eq!(
            calls.borrow().len(),
            1,
            "the probe runs on a verified candidate"
        );
        assert!(
            swaps.borrow().is_empty(),
            "a failed self-test must never swap"
        );
        assert!(run.out.is_empty(), "{}", run.out);
        assert!(run.notes.contains("self-test"), "{}", run.notes);
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn a_failed_swap_is_a_localized_failure_and_installs_nothing() -> R {
        // The swap points at a target that is not there: the flow gets all
        // the way through the probe, then refuses, and `update` reports the
        // failure rather than claiming an install.
        let home = tempfile::TempDir::new()?;
        let absent = home.path().join("detent");
        let swaps = probe_log();
        let run = run_update_hermetic(
            &verified_feed()?,
            &semver::Version::new(0, 0, 1),
            &detent_update::Policy::default(),
            &fixture_trust()?,
            &recording_ok_probe(&probe_log(), &["hosts", "web", "update"]),
            &recording_swap(&swaps, &absent),
            &healthy_restart(),
            false,
        )?;
        assert_eq!(run.exit, Exit::Failed);
        assert_eq!(swaps.borrow().len(), 1, "the swap is attempted once");
        assert!(run.out.is_empty(), "nothing may be claimed installed");
        assert!(run.notes.contains("update failed"), "{}", run.notes);
        assert!(!absent.exists(), "a failed swap must not create the target");
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn a_fully_verified_candidate_is_installed() -> R {
        // End to end over the synthetic-but-real Sigstore fixtures: policy
        // pass, SUMS match, bundle verifies, the candidate's own path is
        // probed, and only then the real atomic swap runs.
        let calls = probe_log();
        let swaps = probe_log();
        let (_home, target) = install_target()?;
        let run = run_update_hermetic(
            &verified_feed()?,
            &semver::Version::new(0, 0, 1),
            &detent_update::Policy::default(),
            &fixture_trust()?,
            &recording_ok_probe(&calls, &["hosts", "web", "update"]),
            &recording_swap(&swaps, &target),
            &healthy_restart(),
            false,
        )?;
        assert_eq!(run.exit, Exit::Ok);
        assert!(run.notes.is_empty(), "{}", run.notes);
        assert!(run.out.contains("installed v0.0.2"), "{}", run.out);
        let previous = target.with_file_name("detent.prev");
        assert!(
            run.out.contains(&previous.display().to_string()),
            "the line must name where the old binary is kept: {}",
            run.out
        );
        assert_eq!(
            std::fs::read(&target)?,
            binary_fixture()?,
            "the target must hold the verified candidate"
        );
        assert_eq!(
            std::fs::read(&previous)?,
            RUNNING_BINARY,
            "the replaced binary must be kept"
        );
        let calls = calls.borrow();
        assert_eq!(calls.len(), 1, "the self-test probe must run exactly once");
        assert_eq!(
            calls
                .first()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str()),
            Some(detent_update::fetch::asset_name().as_str()),
            "the probe must run on the staged candidate"
        );
        assert_eq!(
            swaps.borrow().as_slice(),
            calls.as_slice(),
            "the swap must install exactly the binary that was probed"
        );
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn an_unhealthy_restart_rolls_back_and_restores_the_previous_binary() -> R {
        // Swap installs, the first restart reports an unhealthy listener, the
        // rollback puts the previous binary back and the second restart is
        // healthy: a failed update that leaves the host as it started.
        let calls = probe_log();
        let swaps = probe_log();
        let (_home, target) = install_target()?;
        let attempts = std::rc::Rc::new(std::cell::Cell::new(0));
        let restart = {
            let attempts = attempts.clone();
            move || {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    super::RestartOutcome::Unhealthy("listener never answered".to_owned())
                } else {
                    super::RestartOutcome::Healthy
                }
            }
        };
        let run = run_update_hermetic(
            &verified_feed()?,
            &semver::Version::new(0, 0, 1),
            &detent_update::Policy::default(),
            &fixture_trust()?,
            &recording_ok_probe(&calls, &["hosts", "web", "update"]),
            &recording_swap(&swaps, &target),
            &restart,
            false,
        )?;
        assert_eq!(run.exit, Exit::Failed);
        assert!(run.notes.contains("rolled back"), "{}", run.notes);
        assert_eq!(attempts.get(), 2, "the rollback must restart again");
        assert_eq!(
            std::fs::read(&target)?,
            RUNNING_BINARY,
            "the target must hold the previous binary again"
        );
        assert!(
            !target.with_file_name("detent.prev").exists(),
            "the rollback must consume the kept binary"
        );
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn a_rollback_that_cannot_restore_service_says_so_loudly() -> R {
        // The post-rollback restart also fails: the binary is the original
        // again, but the host is not serving, and only a human can fix that.
        let calls = probe_log();
        let swaps = probe_log();
        let (_home, target) = install_target()?;
        let restart = || super::RestartOutcome::Unhealthy("listener never answered".to_owned());
        let run = run_update_hermetic(
            &verified_feed()?,
            &semver::Version::new(0, 0, 1),
            &detent_update::Policy::default(),
            &fixture_trust()?,
            &recording_ok_probe(&calls, &["hosts", "web", "update"]),
            &recording_swap(&swaps, &target),
            &restart,
            false,
        )?;
        assert_eq!(run.exit, Exit::Failed);
        assert!(run.notes.contains("needs attention"), "{}", run.notes);
        assert_eq!(
            std::fs::read(&target)?,
            RUNNING_BINARY,
            "the rollback must still have restored the previous binary"
        );
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn no_service_manager_installs_without_rollback() -> R {
        // Nothing to restart on this host: the installed binary is sound, so
        // the flow succeeds and says the service was not restarted.
        let calls = probe_log();
        let swaps = probe_log();
        let (_home, target) = install_target()?;
        let restart = || super::RestartOutcome::NotAService("no init system".to_owned());
        let run = run_update_hermetic(
            &verified_feed()?,
            &semver::Version::new(0, 0, 1),
            &detent_update::Policy::default(),
            &fixture_trust()?,
            &recording_ok_probe(&calls, &["hosts", "web", "update"]),
            &recording_swap(&swaps, &target),
            &restart,
            false,
        )?;
        assert_eq!(run.exit, Exit::Ok);
        assert!(run.out.contains("installed v0.0.2"), "{}", run.out);
        assert!(run.notes.contains("not restarted"), "{}", run.notes);
        assert_eq!(
            std::fs::read(&target)?,
            binary_fixture()?,
            "the install must stand: no rollback without a service"
        );
        Ok(())
    }

    fn run_with(argv: &[&str]) -> Result<(Exit, String, String), Box<dyn std::error::Error>> {
        let cli = parse(argv)?;
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = run(
            &cli,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        );
        Ok((exit, String::from_utf8(out)?, String::from_utf8(notes)?))
    }

    // -- update-flow hermetic helpers ---------------------------------------
    //
    // The bare-`update` flow is exercised end to end against the
    // detent-update fixtures (a synthetic-but-real Sigstore bundle): policy,
    // SUMS cross-check and all six verification steps run for real, and the
    // only seams are the `Transport` and the candidate self-test probe, so
    // no test touches the network or executes a downloaded binary.

    #[cfg(feature = "update")]
    fn fixed_now() -> Result<time::OffsetDateTime, Box<dyn std::error::Error>> {
        Ok(time::OffsetDateTime::from_unix_timestamp(1_786_780_800)?)
    }

    #[cfg(feature = "update")]
    fn update_fixtures() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../detent-update/tests/fixtures")
    }

    #[cfg(feature = "update")]
    fn binary_fixture() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(std::fs::read(update_fixtures().join("binary.bin"))?)
    }

    /// The fixture trust root: the embedded one is still a placeholder, so
    /// hermetic verification runs through the fixture PEMs instead.
    #[cfg(feature = "update")]
    fn fixture_trust() -> Result<detent_update::TrustRoot, Box<dyn std::error::Error>> {
        let dir = update_fixtures();
        let root = std::fs::read_to_string(dir.join("fulcio-root.pem"))?;
        let rekor = std::fs::read_to_string(dir.join("rekor-pub.pem"))?;
        Ok(detent_update::trust::from_pems(&root, &rekor)?)
    }

    /// Every call a probe seam received, for the order assertions.
    #[cfg(feature = "update")]
    type ProbeLog = std::rc::Rc<std::cell::RefCell<Vec<std::path::PathBuf>>>;

    #[cfg(feature = "update")]
    fn probe_log() -> ProbeLog {
        std::rc::Rc::default()
    }

    /// A probe that records each path it is handed and answers a superset.
    #[cfg(feature = "update")]
    fn recording_ok_probe(
        log: &ProbeLog,
        features: &[&str],
    ) -> impl Fn(&std::path::Path) -> Result<detent_update::FeatureSet, detent_update::UpdateError> + use<>
    {
        let log = log.clone();
        let set = detent_update::FeatureSet {
            version: "0.0.2".to_owned(),
            features: features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
        };
        move |path| {
            log.borrow_mut().push(path.to_owned());
            Ok(set.clone())
        }
    }

    /// A probe that records each path it is handed and answers a fresh error.
    #[cfg(feature = "update")]
    fn recording_err_probe(
        log: &ProbeLog,
        make: fn() -> detent_update::UpdateError,
    ) -> impl Fn(&std::path::Path) -> Result<detent_update::FeatureSet, detent_update::UpdateError> + use<>
    {
        let log = log.clone();
        move |path| {
            log.borrow_mut().push(path.to_owned());
            Err(make())
        }
    }

    /// A stand-in for the installed binary: a file in a temp dir the real
    /// swap can replace, so no test ever touches the runner's own executable.
    #[cfg(feature = "update")]
    fn install_target()
    -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
        let home = tempfile::TempDir::new()?;
        let target = home.path().join("detent");
        std::fs::write(&target, RUNNING_BINARY)?;
        Ok((home, target))
    }

    /// The bytes [`install_target`] starts with, so a test can tell the
    /// replaced binary from the candidate.
    #[cfg(feature = "update")]
    const RUNNING_BINARY: &[u8] = b"the binary this test is replacing\n";

    /// A swap seam that records each candidate it is handed and performs the
    /// real atomic swap onto `target`.
    #[cfg(feature = "update")]
    fn recording_swap(
        log: &ProbeLog,
        target: &std::path::Path,
    ) -> impl Fn(&std::path::Path) -> Result<detent_update::Installed, detent_update::UpdateError> + use<>
    {
        let log = log.clone();
        let target = target.to_path_buf();
        move |candidate| {
            log.borrow_mut().push(candidate.to_owned());
            detent_update::install::swap(candidate, &target)
        }
    }

    /// A swap seam that must never run: it points at a path that is not
    /// there, so a test that reaches it fails on the refusal too.
    #[cfg(feature = "update")]
    fn unreachable_swap(
        log: &ProbeLog,
    ) -> impl Fn(&std::path::Path) -> Result<detent_update::Installed, detent_update::UpdateError> + use<>
    {
        recording_swap(log, std::path::Path::new("/detent-must-not-be-swapped"))
    }

    #[cfg(feature = "update")]
    fn make_self_test_failure() -> detent_update::UpdateError {
        detent_update::UpdateError::SelfTest("exit status: 1".to_owned())
    }

    /// The release feed whose assets verify against the fixture bundle.
    #[cfg(feature = "update")]
    fn verified_feed() -> Result<VerifiableFeed, Box<dyn std::error::Error>> {
        Ok(VerifiableFeed {
            tag: "v0.0.2".to_owned(),
            body: String::new(),
            when: "2020-01-01T00:00:00Z".to_owned(),
            binary: binary_fixture()?,
        })
    }

    /// A restart that always reports a serving listener: the default for
    /// tests about the steps *before* the restart.
    #[cfg(feature = "update")]
    fn healthy_restart() -> impl Fn() -> super::RestartOutcome {
        || super::RestartOutcome::Healthy
    }

    #[cfg(feature = "update")]
    struct BareRun {
        exit: Exit,
        out: String,
        notes: String,
    }

    /// Runs the bare-`update` flow with a fixed clock and no subprocesses.
    #[cfg(feature = "update")]
    #[allow(clippy::too_many_arguments)]
    fn run_update_hermetic(
        feed: &impl detent_update::fetch::Transport,
        current: &semver::Version,
        policy: &detent_update::Policy,
        trust: &detent_update::TrustRoot,
        probe: &super::FeatureProbe,
        swap: &super::BinarySwap<'_>,
        restart: &super::RestartCheck<'_>,
        check_only: bool,
    ) -> Result<BareRun, Box<dyn std::error::Error>> {
        let messages = crate::i18n::Messages::new(Some("en-US"));
        let renderer = crate::output::Renderer {
            messages: &messages,
            json: false,
            verbose: false,
        };
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = super::run_update_on(
            feed,
            current,
            policy,
            fixed_now()?,
            trust,
            check_only,
            &std::env::temp_dir(),
            probe,
            swap,
            restart,
            &renderer,
            &mut Streams {
                input: &mut std::io::empty(),
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        Ok(BareRun {
            exit,
            out: String::from_utf8(out)?,
            notes: String::from_utf8(notes)?,
        })
    }

    /// A feed whose assets verify end to end: the fixture binary bytes with a
    /// minted SUMS line and the fixture Sigstore bundle, one URL route each.
    #[cfg(feature = "update")]
    struct VerifiableFeed {
        tag: String,
        body: String,
        when: String,
        binary: Vec<u8>,
    }

    #[cfg(feature = "update")]
    impl detent_update::fetch::Transport for VerifiableFeed {
        fn get(
            &self,
            url: &str,
            _cap: u64,
            sink: &mut dyn std::io::Write,
        ) -> Result<u64, detent_update::fetch::FetchError> {
            let bad = |reason: String| detent_update::fetch::FetchError::BadJson(reason);
            let bytes = if url == detent_update::fetch::RELEASES_URL {
                serde_json::to_vec(&serde_json::json!([{
                    "tag_name": self.tag,
                    "draft": false,
                    "prerelease": false,
                    "published_at": self.when,
                    "body": self.body,
                    "assets": [
                        {"name": detent_update::fetch::asset_name(), "browser_download_url": "https://example.invalid/b"},
                        {"name": "SHA256SUMS", "browser_download_url": "https://example.invalid/s"},
                        {"name": format!("{}.sigstore.json", detent_update::fetch::asset_name()), "browser_download_url": "https://example.invalid/j"},
                    ],
                }]))
                .map_err(|err| bad(err.to_string()))?
            } else if url.ends_with("/s") {
                let mut hex = String::with_capacity(64);
                for byte in detent_update::fetch::sha256_of(&self.binary) {
                    use std::fmt::Write as _;
                    let _ = write!(hex, "{byte:02x}");
                }
                format!("{}  {}\n", hex, detent_update::fetch::asset_name()).into_bytes()
            } else if url.ends_with("/b") {
                self.binary.clone()
            } else if url.ends_with("/j") {
                std::fs::read(update_fixtures().join("valid.json"))
                    .map_err(|err| bad(err.to_string()))?
            } else {
                return Err(bad(format!("unexpected url {url}")));
            };
            std::io::Write::write_all(sink, &bytes).map_err(|err| bad(err.to_string()))?;
            Ok(bytes.len() as u64)
        }
    }

    #[cfg(feature = "update")]
    struct OneFeed {
        tag: &'static str,
        body: &'static str,
        when: String,
    }

    #[cfg(feature = "update")]
    impl detent_update::fetch::Transport for OneFeed {
        fn get(
            &self,
            _url: &str,
            _cap: u64,
            sink: &mut dyn std::io::Write,
        ) -> Result<u64, detent_update::fetch::FetchError> {
            let triple = detent_update::fetch::target_triple();
            let doc = serde_json::json!([{
                "tag_name": self.tag,
                "draft": false,
                "prerelease": false,
                "published_at": self.when,
                "body": self.body,
                "assets": [
                    {"name": format!("detent-{triple}"), "browser_download_url": "https://example.invalid/b"},
                    {"name": "SHA256SUMS", "browser_download_url": "https://example.invalid/s"},
                    {"name": format!("detent-{triple}.sigstore.json"), "browser_download_url": "https://example.invalid/j"},
                ],
            }]);
            let bytes = serde_json::to_vec(&doc)
                .map_err(|err| detent_update::fetch::FetchError::BadJson(err.to_string()))?;
            let len = bytes.len() as u64;
            std::io::Write::write_all(sink, &bytes)
                .map_err(|err| detent_update::fetch::FetchError::BadJson(err.to_string()))?;
            Ok(len)
        }
    }

    #[cfg(feature = "update")]
    struct FailingFeed;

    #[cfg(feature = "update")]
    impl detent_update::fetch::Transport for FailingFeed {
        fn get(
            &self,
            url: &str,
            _cap: u64,
            _sink: &mut dyn std::io::Write,
        ) -> Result<u64, detent_update::fetch::FetchError> {
            Err(detent_update::fetch::FetchError::Unreachable {
                url: url.to_owned(),
                reason: "offline".to_owned(),
            })
        }
    }

    #[cfg(feature = "update")]
    #[test]
    fn update_check_report_renders_all_four_shapes() -> R {
        use detent_update::{CheckReport, Policy};
        let current = semver::Version::new(0, 0, 1);
        let policy = Policy::default();
        let now = time::OffsetDateTime::now_utc();
        let when = "2020-01-01T00:00:00Z";
        let messages = crate::i18n::Messages::new(Some("en-US"));
        let renderer = crate::output::Renderer {
            messages: &messages,
            json: false,
            verbose: false,
        };
        for (tag, body, available, security) in [
            ("v0.0.2", "", true, false),
            ("v0.0.2", "detent-security: true", true, true),
            ("v0.0.0", "", false, false),
        ] {
            let feed = OneFeed {
                tag,
                body,
                when: when.to_owned(),
            };
            let report: CheckReport = detent_update::update::check(&feed, &current, &policy, now)?;
            assert_eq!(report.update_available, available, "{tag} {body}");
            assert_eq!(report.security, security);
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let exit = super::check_report(
                &feed,
                &current,
                &policy,
                now,
                &renderer,
                &mut Streams {
                    input: &mut std::io::empty(),
                    out: &mut out,
                    notes: &mut notes,
                },
            )?;
            assert_eq!(exit, Exit::Ok);
            let text = String::from_utf8(out)?;
            if available {
                assert!(text.contains("v0.0.2"), "{text}");
            } else {
                assert!(text.contains("0.0.1"), "{text}");
            }
        }
        let messages_json = crate::i18n::Messages::new(Some("en-US"));
        let renderer_json = crate::output::Renderer {
            messages: &messages_json,
            json: true,
            verbose: false,
        };
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = super::check_report(
            &OneFeed {
                tag: "v0.0.2",
                body: "",
                when: when.to_owned(),
            },
            &current,
            &policy,
            now,
            &renderer_json,
            &mut Streams {
                input: &mut std::io::empty(),
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        let parsed: serde_json::Value = serde_json::from_slice(&out)?;
        assert_eq!(parsed.get("tag"), Some(&serde_json::json!("v0.0.2")));
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = super::check_report(
            &FailingFeed,
            &current,
            &policy,
            now,
            &renderer,
            &mut Streams {
                input: &mut std::io::empty(),
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty());
        assert!(!notes.is_empty());
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn failed_is_always_a_localized_failure_never_usage() -> R {
        let messages = crate::i18n::Messages::new(Some("en-US"));
        let renderer = crate::output::Renderer {
            messages: &messages,
            json: false,
            verbose: false,
        };
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = super::failed(
            &renderer,
            &mut Streams {
                input: &mut std::io::empty(),
                out: &mut out,
                notes: &mut notes,
            },
            "offline",
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty());
        assert!(String::from_utf8(notes)?.contains("offline"));
        Ok(())
    }
    #[cfg(feature = "update")]
    #[test]
    fn update_and_dispatch_only_arms_map_without_side_effects() -> R {
        let mut input = std::io::empty();
        let cli = parse(&["detent", "update", "--check"])?;
        assert!(matches!(
            operation_for(&cli, &mut input).map_err(|usage| usage.id.as_str())?,
            Operation::ListModules
        ));
        let cli = parse(&["detent", "update"])?;
        assert!(matches!(
            operation_for(&cli, &mut input).map_err(|usage| usage.id.as_str())?,
            Operation::ListModules
        ));
        let cli = parse(&["detent", "serve"])?;
        assert!(matches!(
            operation_for(&cli, &mut input).map_err(|usage| usage.id.as_str())?,
            Operation::ListModules
        ));
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn the_embedded_trust_root_refuses_until_the_first_release() {
        // A placeholder trust root must refuse closed (run_update resolves it
        // before anything is fetched), never degrade to system CAs.
        assert!(matches!(
            detent_update::trust::embedded(),
            Err(detent_update::VerificationError::TrustRootUnavailable)
        ));
    }
    #[cfg(feature = "update")]
    #[test]
    fn update_check_none_renders_current_and_succeeds() -> R {
        let messages = crate::i18n::Messages::new(Some("en-US"));
        let renderer = crate::output::Renderer {
            messages: &messages,
            json: false,
            verbose: false,
        };
        let current = semver::Version::new(0, 0, 1);
        let policy = detent_update::Policy::default();
        let now = time::OffsetDateTime::now_utc();
        let feed = OneFeed {
            tag: "v0.0.0",
            body: "",
            when: "2020-01-01T00:00:00Z".to_owned(),
        };
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = super::check_report(
            &feed,
            &current,
            &policy,
            now,
            &renderer,
            &mut Streams {
                input: &mut std::io::empty(),
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Ok);
        assert!(String::from_utf8(out)?.contains("0.0.1"));
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn update_check_offline_fails_closed() -> R {
        let messages = crate::i18n::Messages::new(Some("en-US"));
        let renderer = crate::output::Renderer {
            messages: &messages,
            json: false,
            verbose: false,
        };
        let current = semver::Version::new(0, 0, 1);
        let policy = detent_update::Policy::default();
        let now = time::OffsetDateTime::now_utc();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = super::check_report(
            &FailingFeed,
            &current,
            &policy,
            now,
            &renderer,
            &mut Streams {
                input: &mut std::io::empty(),
                out: &mut out,
                notes: &mut notes,
            },
        )?;
        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty());
        assert!(!notes.is_empty());
        Ok(())
    }

    #[cfg(feature = "update")]
    #[test]
    fn update_operation_maps_without_side_effects() -> R {
        let cli = parse(&["detent", "update", "--check"])?;
        let mut input = std::io::empty();
        assert!(matches!(
            operation_for(&cli, &mut input).map_err(|usage| usage.id.as_str())?,
            Operation::ListModules
        ));
        Ok(())
    }

    #[test]
    fn the_target_path_follows_the_module_detector() {
        let descriptors: Vec<&'static ModuleDescriptor> = detent_modules::modules()
            .iter()
            .map(|entry| entry.descriptor())
            .collect();
        let profile = detent_platform::host::detect_real().profile;
        assert_eq!(target_path(&descriptors, "nope", &profile), None);
        if descriptors.iter().any(|entry| entry.id == "hosts") {
            assert_eq!(
                target_path(&descriptors, "hosts", &profile),
                Some("/etc/hosts")
            );
        }
    }

    #[test]
    fn the_caller_is_named_for_the_audit_log() {
        let who = caller();
        assert!(!who.subject.is_empty());
        assert_eq!(who.kind, detent_ops::IdentityKind::LocalUser);
    }

    #[test]
    fn a_session_that_cannot_build_its_allowlist_reports_why() -> R {
        // Two descriptors with the same id: the allow-list refuses, and the
        // failure must surface as a startable-session error, not a panic.
        let descriptor = crate::tests_support::descriptor(Path::new("/etc/hosts"));
        let settings = Settings {
            state_root: PathBuf::from("/tmp/detent-cli-test"),
            config_path: PathBuf::from(DEFAULT_CONFIG_PATH),
        };
        let err = Session::start(
            &settings,
            detent_platform::host::Detected::default(),
            Vec::new(),
            &[descriptor, descriptor],
            true,
        )
        .err()
        .ok_or("a duplicate module id must be refused")?;
        assert!(err.contains("duplicate"), "{err}");
        Ok(())
    }

    #[test]
    fn defaults_prints_a_model_and_reports_a_module_that_cannot_produce_one() -> R {
        let messages = crate::i18n::Messages::new(Some("en-US"));
        let renderer = crate::output::Renderer {
            messages: &messages,
            json: false,
            verbose: false,
        };
        let descriptor = crate::tests_support::descriptor(Path::new("/etc/fake.conf"));
        let profile = detent_core::descriptor::HostProfile::default_for_tests();

        for (broken, module, expected) in [
            (false, crate::tests_support::MODULE, Exit::Ok),
            (true, crate::tests_support::MODULE, Exit::Failed),
            (false, "nope", Exit::Failed),
        ] {
            let registry = crate::tests_support::registry(descriptor, broken);
            let mut input = std::io::empty();
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let exit = super::defaults(
                &registry,
                &profile,
                module,
                &renderer,
                &mut Streams {
                    input: &mut input,
                    out: &mut out,
                    notes: &mut notes,
                },
            )?;
            assert_eq!(exit, expected, "{module} broken={broken}");
            if expected == Exit::Ok {
                let parsed: serde_json::Value = serde_json::from_slice(&out)?;
                assert!(parsed.pointer("/text").is_some(), "{parsed}");
            } else {
                assert!(out.is_empty());
                assert!(!notes.is_empty());
            }
        }
        Ok(())
    }

    // --- a real engine over a real monitor, on a temporary target ------------

    /// `--dryrun` must leave the target byte-for-byte and mtime-for-mtime
    /// untouched, while still producing the diff it would have written.
    #[test]
    fn a_dry_run_apply_changes_nothing_on_disk() -> R {
        let mut fx = crate::tests_support::Harness::start(b"v1\n", true)?;
        let before = std::fs::metadata(&fx.target)?.modified()?;
        let operation = Operation::Apply {
            id: crate::tests_support::MODULE.to_owned(),
            model: serde_json::json!({"text": "v2\n"}),
            expected_hash: None,
            service_action: None,
            confirm: None,
        };
        let executed = fx.session.execute(operation, true)?;
        let report = crate::tests_support::withheld_of(executed)
            .ok_or("a dry run must withhold the apply")?;
        assert!(report.dryrun);
        assert_eq!(report.operation, OpKind::Apply);
        let plan = report.plan.ok_or("a withheld apply still plans")?;
        assert!(plan.would_change);
        assert!(plan.unified_diff.contains("+v2"), "{}", plan.unified_diff);

        assert_eq!(fx.contents()?, b"v1\n");
        assert_eq!(std::fs::metadata(&fx.target)?.modified()?, before);
        // A dry run keeps no audit trail of its own either.
        assert!(!fx.state_root.join("audit").exists());
        fx.session.finish()?;
        Ok(())
    }

    #[test]
    fn a_dry_run_withholds_every_other_mutation_too() -> R {
        let mut fx = crate::tests_support::Harness::start(b"v1\n", true)?;
        for operation in [
            Operation::Restore {
                id: crate::tests_support::MODULE.to_owned(),
                backup_id: detent_platform::privsep::proto::BackupId(0),
            },
            Operation::ServiceAction {
                id: crate::tests_support::MODULE.to_owned(),
                action: detent_ops::ServiceCommand::Restart,
            },
            Operation::ConfirmCommit {
                commit_id: detent_platform::privsep::proto::CommitId(1),
            },
        ] {
            let kind = operation.kind();
            let executed = fx.session.execute(operation, true)?;
            let report = crate::tests_support::withheld_of(executed)
                .ok_or("a dry run must withhold every mutation")?;
            assert_eq!(report.operation, kind);
            assert!(report.plan.is_none());
            assert!(format!("{report:?}").contains("dryrun"));
        }
        assert_eq!(fx.contents()?, b"v1\n");
        fx.session.finish()?;
        Ok(())
    }

    /// The full round trip a headless operator performs: read the model, plan a
    /// change, apply it, list the backup it left, restore it, and read the
    /// audit log back — all against a real monitor over a temporary file.
    #[test]
    fn get_plan_apply_backup_restore_and_audit_round_trip() -> R {
        let mut fx = crate::tests_support::Harness::start(b"v1\n", false)?;
        let module = crate::tests_support::MODULE.to_owned();

        let got = crate::tests_support::ran_of(
            fx.session
                .execute(Operation::GetModule { id: module.clone() }, false)?,
        )
        .ok_or("get must run")?;
        let view = crate::tests_support::module_of(got).ok_or("get answers with a view")?;
        assert_eq!(
            view.model
                .as_ref()
                .and_then(|model| model.pointer("/text"))
                .and_then(|text| text.as_str()),
            Some("v1\n")
        );
        let current = view.current_hash.ok_or("the file has a digest")?;

        let planned = crate::tests_support::ran_of(fx.session.execute(
            Operation::Plan {
                id: module.clone(),
                model: serde_json::json!({"text": "v2\n"}),
            },
            false,
        )?)
        .ok_or("plan must run")?;
        let plan = crate::tests_support::plan_of(planned).ok_or("plan answers with a plan")?;
        assert!(plan.would_change && plan.unified_diff.contains("+v2"));
        assert_eq!(plan.current_hash, current);

        let applied = crate::tests_support::ran_of(fx.session.execute(
            Operation::Apply {
                id: module.clone(),
                model: serde_json::json!({"text": "v2\n"}),
                expected_hash: Some(current),
                service_action: None,
                confirm: None,
            },
            false,
        )?)
        .ok_or("apply must run")?;
        assert!(matches!(
            applied,
            detent_ops::report::OpOutcome::Applied(ref report) if report.backed_up
        ));
        assert_eq!(fx.contents()?, b"v2\n");

        let listed = crate::tests_support::ran_of(
            fx.session
                .execute(Operation::ListBackups { id: module.clone() }, false)?,
        )
        .ok_or("backup list must run")?;
        let backups =
            crate::tests_support::backups_of(listed).ok_or("backup list answers with a listing")?;
        let backup = backups.first().ok_or("the apply kept a backup")?.id;

        fx.session.execute(
            Operation::Restore {
                id: module.clone(),
                backup_id: backup,
            },
            false,
        )?;
        assert_eq!(fx.contents()?, b"v1\n");

        let audit = crate::tests_support::ran_of(fx.session.execute(
            Operation::AuditQuery(detent_ops::AuditQuery::default()),
            false,
        )?)
        .ok_or("audit must run")?;
        let records =
            crate::tests_support::records_of(audit).ok_or("audit answers with records")?;
        // Nothing in a real run is a withheld mutation.
        assert!(
            crate::tests_support::withheld_of(fx.session.execute(Operation::HostProfile, false)?)
                .is_none()
        );
        // Apply and Restore are the two mutations; both were recorded.
        assert_eq!(records.len(), 2, "{records:?}");
        assert!(fx.state_root.join("audit").is_dir());

        fx.session.finish()?;
        Ok(())
    }

    /// A model the module refuses, and a model it cannot even render: both
    /// leave the file alone and come back as operations errors the renderer
    /// knows how to explain.
    #[test]
    fn an_invalid_model_is_refused_before_anything_is_written() -> R {
        let mut fx = crate::tests_support::Harness::start(b"v1\n", false)?;
        let messages = crate::i18n::Messages::new(Some("en-US"));
        let renderer = crate::output::Renderer {
            messages: &messages,
            json: false,
            verbose: false,
        };
        for (model, privileged) in [
            (serde_json::json!({"text": "BAD\n"}), false),
            (serde_json::json!({"nothing": true}), false),
        ] {
            let err = fx
                .session
                .execute(
                    Operation::Apply {
                        id: crate::tests_support::MODULE.to_owned(),
                        model,
                        expected_hash: None,
                        service_action: None,
                        confirm: None,
                    },
                    false,
                )
                .err()
                .ok_or("the apply must be refused")?;
            let mut notes = Vec::new();
            let exit = renderer.error(
                &mut notes,
                &err,
                crate::output::ErrorContext {
                    module: Some(crate::tests_support::MODULE),
                    path: Some("/etc/fake.conf"),
                },
            )?;
            assert_eq!(exit == Exit::Privilege, privileged);
            assert!(!String::from_utf8(notes)?.is_empty());
        }
        assert_eq!(fx.contents()?, b"v1\n");
        fx.session.finish()?;
        Ok(())
    }

    #[test]
    fn a_failing_operation_reports_the_error_and_still_shuts_down() -> R {
        let mut fx = crate::tests_support::Harness::start(b"v1\n", false)?;
        let err = fx
            .session
            .execute(
                Operation::GetModule {
                    id: "nope".to_owned(),
                },
                false,
            )
            .err()
            .ok_or("an unknown module must fail")?;
        assert!(matches!(err, detent_ops::OpsError::UnknownModule { .. }));
        assert!(format!("{:?}", fx.session).contains("running"));
        fx.session.finish()?;
        // A second shutdown has nothing left to join and says so rather than
        // hanging.
        assert!(fx.session.finish().is_err());
        Ok(())
    }

    // --- the whole binary path, against the real module registry -------------

    /// Drives `run` itself, so `dispatch`, `operate`, session start-up and
    /// rendering are all exercised with the modules this build really has. Only
    /// read-only commands: a test must never write `/etc`.
    #[test]
    fn read_only_commands_run_end_to_end_against_the_real_registry() -> R {
        let dir = tempfile::TempDir::new()?;
        let state = dir.path().join("state").display().to_string();
        for argv in [
            vec!["detent", "host", "--state-root", &state],
            vec!["detent", "host", "--json", "--state-root", &state],
            vec!["detent", "audit", "--limit", "1", "--state-root", &state],
            vec!["detent", "doctor", "--state-root", &state],
            vec!["detent", "completions", "bash"],
        ] {
            let cli = parse(&argv)?;
            let mut input = std::io::empty();
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let exit = run(
                &cli,
                &mut Streams {
                    input: &mut input,
                    out: &mut out,
                    notes: &mut notes,
                },
            );
            assert_eq!(
                exit,
                Exit::Ok,
                "{argv:?}: {}",
                String::from_utf8_lossy(&notes)
            );
            assert!(!out.is_empty(), "{argv:?} printed nothing");
        }
        Ok(())
    }

    /// `config <module> …` against the compiled-in `hosts` module and the real
    /// `/etc/hosts`, which every supported host has and which nothing here
    /// writes. Skipped when the module is not compiled in.
    #[test]
    fn hosts_commands_read_the_real_file_without_touching_it() -> R {
        let registry = detent_modules::modules();
        if !registry.iter().any(|entry| entry.id() == "hosts") || !Path::new("/etc/hosts").exists()
        {
            return Ok(());
        }
        let dir = tempfile::TempDir::new()?;
        let state = dir.path().join("state").display().to_string();
        let before = std::fs::read("/etc/hosts")?;
        let mtime = std::fs::metadata("/etc/hosts")?.modified()?;

        // `get` prints the model, and that model is what `plan`, `validate` and
        // a dry-run `apply` are then fed.
        let cli = parse(&["detent", "config", "hosts", "get", "--state-root", &state])?;
        let mut input = std::io::empty();
        let mut model = Vec::new();
        let mut notes = Vec::new();
        assert_eq!(
            run(
                &cli,
                &mut Streams {
                    input: &mut input,
                    out: &mut model,
                    notes: &mut notes,
                },
            ),
            Exit::Ok,
            "{}",
            String::from_utf8_lossy(&notes)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&model)?;
        assert!(parsed.pointer("/entries").is_some(), "{parsed}");

        for argv in [
            vec![
                "detent",
                "config",
                "hosts",
                "validate",
                "--state-root",
                &state,
            ],
            vec!["detent", "config", "hosts", "plan", "--state-root", &state],
            vec![
                "detent",
                "config",
                "hosts",
                "apply",
                "--dryrun",
                "--state-root",
                &state,
            ],
            vec![
                "detent",
                "config",
                "hosts",
                "apply",
                "--dryrun",
                "--json",
                "--state-root",
                &state,
            ],
            vec![
                "detent",
                "config",
                "hosts",
                "defaults",
                "--state-root",
                &state,
            ],
        ] {
            let cli = parse(&argv)?;
            let mut input = model.as_slice();
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let exit = run(
                &cli,
                &mut Streams {
                    input: &mut input,
                    out: &mut out,
                    notes: &mut notes,
                },
            );
            assert_eq!(
                exit,
                Exit::Ok,
                "{argv:?}: {}",
                String::from_utf8_lossy(&notes)
            );
        }

        assert_eq!(std::fs::read("/etc/hosts")?, before);
        assert_eq!(std::fs::metadata("/etc/hosts")?.modified()?, mtime);
        Ok(())
    }

    #[test]
    fn an_unknown_module_is_reported_by_defaults_and_by_the_operations_layer() -> R {
        let dir = tempfile::TempDir::new()?;
        let state = dir.path().join("state").display().to_string();
        for argv in [
            vec![
                "detent",
                "config",
                "nope",
                "defaults",
                "--state-root",
                &state,
            ],
            vec!["detent", "config", "nope", "get", "--state-root", &state],
            vec![
                "detent",
                "config",
                "nope",
                "get",
                "--json",
                "--state-root",
                &state,
            ],
        ] {
            let cli = parse(&argv)?;
            let mut input = std::io::empty();
            let mut out = Vec::new();
            let mut notes = Vec::new();
            let exit = run(
                &cli,
                &mut Streams {
                    input: &mut input,
                    out: &mut out,
                    notes: &mut notes,
                },
            );
            assert_eq!(exit, Exit::Failed, "{argv:?}");
            assert!(out.is_empty(), "{argv:?} wrote data for a failure");
            assert!(!notes.is_empty());
        }
        Ok(())
    }

    /// `commit rollback` is wired even though the operations layer answers
    /// `Unsupported` today: the error surfaces as an ordinary failure rather
    /// than being special-cased in the CLI.
    #[test]
    fn commit_rollback_surfaces_whatever_the_operations_layer_says() -> R {
        let dir = tempfile::TempDir::new()?;
        let state = dir.path().join("state").display().to_string();
        let cli = parse(&["detent", "commit", "rollback", "1", "--state-root", &state])?;
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = run(
            &cli,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        );
        assert_ne!(exit, Exit::Usage);
        assert!(!notes.is_empty());
        Ok(())
    }

    /// `setup`, `user add` and `token create` each reach `dispatch`'s own
    /// match arm (not just `webadmin`'s functions, which the module's own
    /// tests call directly) through the one public entry point, `run`.
    #[cfg(feature = "web")]
    #[test]
    fn setup_user_and_token_commands_are_wired_through_dispatch() -> R {
        let dir = tempfile::TempDir::new()?;
        let state = dir.path().display().to_string();
        let config = dir.path().join("absent.toml").display().to_string();

        let cli = parse(&[
            "detent",
            "--state-root",
            &state,
            "--config",
            &config,
            "setup",
        ])?;
        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = run(
            &cli,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        );
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));

        let cli = parse(&[
            "detent",
            "--state-root",
            &state,
            "--config",
            &config,
            "user",
            "add",
            "bob",
        ])?;
        let mut input = b"hunter22\nhunter22\n".as_slice();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = run(
            &cli,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        );
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));

        let cli = parse(&[
            "detent",
            "--state-root",
            &state,
            "--config",
            &config,
            "token",
            "create",
            "ci",
        ])?;
        let mut input = std::io::empty();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        let exit = run(
            &cli,
            &mut Streams {
                input: &mut input,
                out: &mut out,
                notes: &mut notes,
            },
        );
        assert_eq!(exit, Exit::Ok, "{}", String::from_utf8_lossy(&notes));
        Ok(())
    }
}
