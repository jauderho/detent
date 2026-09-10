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

    match cli.command {
        Command::Completions { shell } => {
            crate::completions::write(streams.out, shell)?;
            Ok(Exit::Ok)
        }
        Command::Doctor => crate::doctor::report(&settings, renderer, streams),
        Command::Serve => crate::serve::run(cli.dryrun, &settings, renderer, streams),
        #[cfg(feature = "web")]
        Command::Setup(ref args) => {
            crate::webadmin::setup(args, cli.dryrun, &settings, renderer, streams)
        }
        #[cfg(feature = "web")]
        Command::User { ref action } => {
            crate::webadmin::user(action, cli.dryrun, &settings, renderer, streams)
        }
        #[cfg(feature = "web")]
        Command::Token { ref action } => {
            crate::webadmin::token(action, cli.dryrun, &settings, renderer, streams)
        }
        Command::Config {
            ref module,
            action: ConfigAction::Defaults,
        } => defaults(
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
    match cli.command {
        Command::Config {
            ref module,
            ref action,
        } => match *action {
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
            ConfigAction::Apply(ref args) => {
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
        Command::Commit { ref action } => Ok(match *action {
            CommitAction::Confirm { id } => Operation::ConfirmCommit {
                commit_id: CommitId(id),
            },
            CommitAction::Rollback { id } => Operation::RollbackCommit {
                commit_id: CommitId(id),
            },
        }),
        Command::Service { ref module, action } => Ok(match action.command() {
            Some(command) => Operation::ServiceAction {
                id: module.clone(),
                action: command,
            },
            None => Operation::ServiceStatus { id: module.clone() },
        }),
        Command::Backup { ref action } => Ok(match *action {
            BackupAction::List { ref module } => Operation::ListBackups { id: module.clone() },
            BackupAction::Restore {
                ref module,
                backup_id,
            } => Operation::Restore {
                id: module.clone(),
                backup_id: BackupId(backup_id),
            },
        }),
        Command::Audit(ref args) => Ok(Operation::AuditQuery(AuditQuery {
            module: args.module.clone(),
            who: args.who.clone(),
            limit: args.limit,
        })),
        Command::Host => Ok(Operation::HostProfile),
        // `dispatch` routes these away before an operation is needed.
        Command::Serve | Command::Doctor | Command::Completions { .. } => {
            Ok(Operation::ListModules)
        }
        #[cfg(feature = "web")]
        Command::Setup(_) | Command::User { .. } | Command::Token { .. } => {
            Ok(Operation::ListModules)
        }
    }
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
