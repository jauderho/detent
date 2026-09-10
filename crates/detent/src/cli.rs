//! The clap command tree (PLAN §2.6) and the small value parsers it needs.
//!
//! # The one place English is hardcoded
//!
//! Every string `detent` *prints at runtime* is a Fluent id (PLAN §4.3, see
//! [`crate::i18n`]). clap's own `--help` text is the documented exception:
//! `#[command(about = …)]` and `#[arg(help = …)]` take `&'static str` at type
//! definition time, long before a locale is negotiated, so a runtime-resolved
//! string cannot be handed to them. Translating the help output would mean
//! rebuilding the whole [`Cli`] command tree per locale at startup, which costs
//! more than it buys for a v1 whose only compiled locale is `en-US`.
//!
//! # Exit codes
//!
//! Documented in the `--help` epilogue ([`AFTER_HELP`]) and implemented in
//! [`crate::output::Exit`]: `0` success, `1` the operation failed, `2` usage
//! error, `3` a permission or privilege problem.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use detent_ops::ServiceCommand;

/// Text appended to `detent --help`.
pub const AFTER_HELP: &str = "\
Exit codes:
  0  success
  1  the operation failed
  2  usage error (bad arguments, malformed JSON on stdin)
  3  permission or privilege problem

Every command reads its model from stdin as JSON where one is needed, and
writes JSON to stdout under --json.";

/// detent: the busybox of config files.
#[derive(Debug, Parser)]
#[command(
    name = "detent",
    version,
    about = "detent: the busybox of config files",
    after_help = AFTER_HELP,
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Print what would happen without making changes.
    #[arg(long, global = true)]
    pub dryrun: bool,

    /// Emit step-level progress and key variable state on stderr.
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,

    /// Emit machine-readable JSON on stdout instead of human text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Path to detent.toml (default: /etc/detent/detent.toml).
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// BCP-47 locale tag for messages (default: from the locale environment).
    #[arg(long, global = true, value_name = "TAG")]
    pub locale: Option<String>,

    /// Root of detent's mutable state (default: /var/lib/detent).
    #[arg(long, global = true, value_name = "PATH")]
    pub state_root: Option<PathBuf>,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands (PLAN §2.6).
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the privileged monitor and the unprivileged worker.
    Serve,
    /// Read, check, preview and write one module's configuration.
    Config {
        /// Module id, e.g. `hosts`.
        module: String,
        /// What to do with it.
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Confirm or roll back a pending commit-confirm window.
    Commit {
        /// What to do with it.
        #[command(subcommand)]
        action: CommitAction,
    },
    /// Query or drive the service a module owns.
    Service {
        /// Module id, e.g. `chrony`.
        module: String,
        /// What to do with it.
        #[command(subcommand)]
        action: ServiceSubcommand,
    },
    /// List and restore the backups the monitor retains.
    Backup {
        /// What to do with them.
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Read the audit log back.
    Audit(AuditArgs),
    /// Report the detected host profile and facts.
    Host,
    /// Check this host for common misconfigurations.
    Doctor,
    /// First-run bootstrap: create the initial administrator account.
    #[cfg(feature = "web")]
    Setup(SetupArgs),
    /// Manage web ui / api accounts.
    #[cfg(feature = "web")]
    User {
        /// What to do.
        #[command(subcommand)]
        action: UserAction,
    },
    /// Manage api tokens.
    #[cfg(feature = "web")]
    Token {
        /// What to do.
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Print a shell completion script.
    Completions {
        /// Which shell to generate for.
        shell: Shell,
    },
}

/// `detent setup`.
#[cfg(feature = "web")]
#[derive(Debug, Args)]
pub struct SetupArgs {
    /// Login name of the initial administrator account.
    #[arg(long, default_value = "admin", value_name = "NAME")]
    pub name: String,
    /// Overwrite the account if one by that name already exists.
    #[arg(long)]
    pub force: bool,
}

/// `detent user …`.
#[cfg(feature = "web")]
#[derive(Debug, Subcommand)]
pub enum UserAction {
    /// Create a new account.
    Add {
        /// Login name.
        name: String,
    },
    /// Change a user's password.
    Passwd {
        /// Login name.
        name: String,
    },
    /// Remove a user.
    Rm {
        /// Login name.
        name: String,
    },
}

/// `detent token …`.
#[cfg(feature = "web")]
#[derive(Debug, Subcommand)]
pub enum TokenAction {
    /// Mint a new token. Printed once; only its digest is kept.
    Create {
        /// What the operator calls it.
        label: String,
        /// Grant write access in addition to read.
        #[arg(long)]
        write: bool,
        /// Expire this many seconds from now, rather than never.
        #[arg(long, value_name = "SECONDS")]
        expires_secs: Option<i64>,
    },
    /// Revoke a token so it stops working immediately.
    Revoke {
        /// The id `token create` or `token list` reported.
        id: String,
    },
    /// List every token, without its secret.
    List,
}

/// `detent config <module> …`.
#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Print the current model as JSON.
    Get,
    /// Validate a model read from stdin.
    Validate,
    /// Diff a model read from stdin against the file on disk.
    Plan,
    /// Write a model read from stdin.
    Apply(ApplyArgs),
    /// Print the module's default model for this host.
    Defaults,
}

/// `detent config <module> apply …`.
#[derive(Debug, Args)]
pub struct ApplyArgs {
    /// What to do to the module's service afterwards.
    #[arg(long, value_name = "ACTION", default_value = "none")]
    pub service: ServiceOption,

    /// Arm commit-confirm for this long, e.g. `90s` or `2m`.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub confirm: Option<Duration>,

    /// Refuse to write unless the file still hashes to this (64 hex chars).
    #[arg(long, value_name = "HEX")]
    pub expect_hash: Option<String>,
}

/// `detent commit …`.
#[derive(Debug, Subcommand)]
pub enum CommitAction {
    /// Confirm a pending commit before its deadline.
    Confirm {
        /// The commit id `apply` reported.
        id: u32,
    },
    /// Roll a pending commit back immediately.
    Rollback {
        /// The commit id `apply` reported.
        id: u32,
    },
}

/// `detent service <module> …`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum ServiceSubcommand {
    /// Report the unit's run state.
    Status,
    /// Start the unit.
    Start,
    /// Stop the unit.
    Stop,
    /// Restart the unit.
    Restart,
}

impl ServiceSubcommand {
    /// The operation-layer command, or `None` for the read-only `status`.
    #[must_use]
    pub const fn command(self) -> Option<ServiceCommand> {
        match self {
            Self::Status => None,
            Self::Start => Some(ServiceCommand::Start),
            Self::Stop => Some(ServiceCommand::Stop),
            Self::Restart => Some(ServiceCommand::Restart),
        }
    }
}

/// `detent backup …`.
#[derive(Debug, Subcommand)]
pub enum BackupAction {
    /// List the backups retained for a module, newest first.
    List {
        /// Module id.
        module: String,
    },
    /// Put one of those backups back.
    Restore {
        /// Module id.
        module: String,
        /// Index from `backup list`.
        backup_id: u32,
    },
}

/// `detent audit …`.
#[derive(Debug, Default, Args)]
pub struct AuditArgs {
    /// Only records about this module.
    #[arg(long, value_name = "ID")]
    pub module: Option<String>,
    /// Only records from this subject.
    #[arg(long, value_name = "SUBJECT")]
    pub who: Option<String>,
    /// At most this many records, newest first.
    #[arg(long, value_name = "N")]
    pub limit: Option<usize>,
}

/// `--service` on `config apply`: a service command, or explicitly nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum ServiceOption {
    /// Full restart.
    Restart,
    /// Reload configuration in place.
    Reload,
    /// Start a stopped unit.
    Start,
    /// Stop a running unit.
    Stop,
    /// Leave the service alone.
    None,
}

impl ServiceOption {
    /// The operation-layer command, or `None` for `none`.
    #[must_use]
    pub const fn command(self) -> Option<ServiceCommand> {
        match self {
            Self::Restart => Some(ServiceCommand::Restart),
            Self::Reload => Some(ServiceCommand::Reload),
            Self::Start => Some(ServiceCommand::Start),
            Self::Stop => Some(ServiceCommand::Stop),
            Self::None => None,
        }
    }
}

/// Shells [`Command::Completions`] can generate for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum Shell {
    /// GNU bash.
    Bash,
    /// Z shell.
    Zsh,
    /// fish.
    Fish,
}

/// Parses `90s`, `2m`, `1h` or a bare number of seconds.
///
/// # Errors
///
/// A short English message when the value is not a positive count with an
/// optional `s`/`m`/`h` suffix. clap owns this text and prints it as part of a
/// usage error, which is the same exception [`AFTER_HELP`] documents.
pub fn parse_duration(raw: &str) -> Result<Duration, String> {
    let trimmed = raw.trim();
    let (digits, multiplier) = match trimmed.strip_suffix('s') {
        Some(rest) => (rest, 1_u64),
        None => match trimmed.strip_suffix('m') {
            Some(rest) => (rest, 60),
            None => match trimmed.strip_suffix('h') {
                Some(rest) => (rest, 3600),
                None => (trimmed, 1),
            },
        },
    };
    let value: u64 = digits
        .parse()
        .map_err(|_| format!("`{raw}` is not a duration such as `90s`, `2m` or `1h`"))?;
    value
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("`{raw}` is longer than this program can represent"))
}

#[cfg(test)]
mod tests {
    use super::{
        AFTER_HELP, Cli, Command, CommitAction, ConfigAction, ServiceOption, ServiceSubcommand,
        Shell, parse_duration,
    };
    use clap::{CommandFactory as _, Parser as _};
    use detent_ops::ServiceCommand;
    use std::time::Duration;

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn the_command_tree_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    /// The help text is a UX surface: a snapshot makes an accidental change to
    /// it show up as a diff in review rather than as a surprise in a release.
    /// Both snapshots are taken the way a user sees them — by parsing `--help`,
    /// so clap propagates the global options — and are regenerated with
    /// `cargo run -p detent -- [config <m>] --help > <file>`.
    #[test]
    fn help_output_matches_its_snapshot() -> R {
        // `help.txt` was captured with the `web` feature on (the default): it
        // lists `setup`/`user`/`token`, which only exist in that build. A
        // `--no-default-features` build has no use for a second snapshot of
        // its own, so it skips the one comparison that would depend on it.
        for (argv, snapshot, file, needs_web) in [
            (
                vec!["detent", "--help"],
                include_str!("../tests/snapshots/help.txt"),
                "help.txt",
                true,
            ),
            (
                vec!["detent", "config", "hosts", "apply", "--help"],
                include_str!("../tests/snapshots/help-config-apply.txt"),
                "help-config-apply.txt",
                false,
            ),
        ] {
            if needs_web && !cfg!(feature = "web") {
                continue;
            }
            let rendered = Cli::try_parse_from(argv)
                .err()
                .map(|error| error.to_string())
                .ok_or("--help must stop parsing")?;
            assert_eq!(
                rendered.trim_end(),
                snapshot.trim_end(),
                "help changed; regenerate crates/detent/tests/snapshots/{file}"
            );
        }
        Ok(())
    }

    #[test]
    fn global_flags_are_accepted_after_the_subcommand() -> R {
        let cli = Cli::try_parse_from([
            "detent",
            "host",
            "--dryrun",
            "-v",
            "--json",
            "--config",
            "/tmp/detent.toml",
            "--locale",
            "de-DE",
            "--state-root",
            "/tmp/state",
        ])?;
        assert!(cli.dryrun && cli.verbose && cli.json);
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/tmp/detent.toml"))
        );
        assert_eq!(cli.locale.as_deref(), Some("de-DE"));
        assert_eq!(
            cli.state_root.as_deref(),
            Some(std::path::Path::new("/tmp/state"))
        );
        assert!(matches!(cli.command, Command::Host));
        Ok(())
    }

    #[test]
    fn every_subcommand_parses() -> R {
        assert!(matches!(
            Cli::try_parse_from(["detent", "serve"])?.command,
            Command::Serve
        ));
        assert!(matches!(
            Cli::try_parse_from(["detent", "doctor"])?.command,
            Command::Doctor
        ));
        assert!(matches!(
            Cli::try_parse_from(["detent", "host"])?.command,
            Command::Host
        ));
        assert!(matches!(
            Cli::try_parse_from(["detent", "completions", "zsh"])?.command,
            Command::Completions { shell: Shell::Zsh }
        ));
        assert!(matches!(
            Cli::try_parse_from(["detent", "commit", "confirm", "7"])?.command,
            Command::Commit {
                action: CommitAction::Confirm { id: 7 }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["detent", "commit", "rollback", "7"])?.command,
            Command::Commit {
                action: CommitAction::Rollback { id: 7 }
            }
        ));
        Ok(())
    }

    /// The module and action of a `config` command, or `None` for any other.
    fn config_of(cli: Cli) -> Option<(String, ConfigAction)> {
        match cli.command {
            Command::Config { module, action } => Some((module, action)),
            _ => None,
        }
    }

    /// The arguments of `config … apply`, or `None` for any other action.
    fn apply_of(action: ConfigAction) -> Option<super::ApplyArgs> {
        match action {
            ConfigAction::Apply(args) => Some(args),
            _ => None,
        }
    }

    /// The stable name of a config action, for a table-driven test.
    const fn action_name(action: &ConfigAction) -> &'static str {
        match *action {
            ConfigAction::Get => "get",
            ConfigAction::Validate => "validate",
            ConfigAction::Plan => "plan",
            ConfigAction::Apply(_) => "apply",
            ConfigAction::Defaults => "defaults",
        }
    }

    /// The action of a `backup` command, or `None` for any other.
    fn backup_of(cli: Cli) -> Option<super::BackupAction> {
        match cli.command {
            Command::Backup { action } => Some(action),
            _ => None,
        }
    }

    /// The arguments of an `audit` command, or `None` for any other.
    fn audit_of(cli: Cli) -> Option<super::AuditArgs> {
        match cli.command {
            Command::Audit(args) => Some(args),
            _ => None,
        }
    }

    /// The module and action of a `service` command, or `None` for any other.
    fn service_of(cli: Cli) -> Option<(String, ServiceSubcommand)> {
        match cli.command {
            Command::Service { module, action } => Some((module, action)),
            _ => None,
        }
    }

    #[test]
    fn the_extractors_only_match_their_own_command() -> R {
        // Exercises the "some other command" arm of each helper above, which the
        // positive tests never reach.
        let other = || Cli::try_parse_from(["detent", "host"]);
        assert!(config_of(other()?).is_none());
        assert!(backup_of(other()?).is_none());
        assert!(audit_of(other()?).is_none());
        assert!(service_of(other()?).is_none());
        assert!(apply_of(ConfigAction::Get).is_none());
        Ok(())
    }

    #[test]
    fn config_actions_carry_their_module_and_flags() -> R {
        for expected in ["get", "validate", "plan", "apply", "defaults"] {
            let cli = Cli::try_parse_from(["detent", "config", "hosts", expected])?;
            let (module, action) = config_of(cli).ok_or("config must parse as Config")?;
            assert_eq!(module, "hosts");
            assert_eq!(action_name(&action), expected);
        }

        let cli = Cli::try_parse_from([
            "detent",
            "config",
            "hosts",
            "apply",
            "--service",
            "reload",
            "--confirm",
            "2m",
            "--expect-hash",
            "abc",
        ])?;
        let (_, action) = config_of(cli).ok_or("config must parse as Config")?;
        let apply = apply_of(action).ok_or("apply must parse as Apply")?;
        assert_eq!(apply.service, ServiceOption::Reload);
        assert_eq!(apply.confirm, Some(Duration::from_secs(120)));
        assert_eq!(apply.expect_hash.as_deref(), Some("abc"));
        Ok(())
    }

    #[test]
    fn apply_defaults_to_touching_no_service_and_arming_nothing() -> R {
        let cli = Cli::try_parse_from(["detent", "config", "hosts", "apply"])?;
        let (_, action) = config_of(cli).ok_or("config must parse as Config")?;
        let apply = apply_of(action).ok_or("apply must parse as Apply")?;
        assert_eq!(apply.service, ServiceOption::None);
        assert_eq!(apply.confirm, None);
        assert_eq!(apply.expect_hash, None);
        Ok(())
    }

    #[test]
    fn backup_and_audit_arguments_parse() -> R {
        let cli = Cli::try_parse_from(["detent", "backup", "restore", "hosts", "3"])?;
        let action = backup_of(cli).ok_or("backup must parse as Backup")?;
        assert!(matches!(
            action,
            super::BackupAction::Restore { ref module, backup_id: 3 } if module == "hosts"
        ));

        let cli = Cli::try_parse_from(["detent", "backup", "list", "hosts"])?;
        let action = backup_of(cli).ok_or("backup must parse as Backup")?;
        assert!(matches!(
            action,
            super::BackupAction::List { ref module } if module == "hosts"
        ));

        let cli = Cli::try_parse_from([
            "detent", "audit", "--module", "hosts", "--who", "root", "--limit", "5",
        ])?;
        let args = audit_of(cli).ok_or("audit must parse as Audit")?;
        assert_eq!(args.module.as_deref(), Some("hosts"));
        assert_eq!(args.who.as_deref(), Some("root"));
        assert_eq!(args.limit, Some(5));
        Ok(())
    }

    #[test]
    fn service_subcommands_map_to_operation_commands() -> R {
        for (name, expected) in [
            ("status", None),
            ("start", Some(ServiceCommand::Start)),
            ("stop", Some(ServiceCommand::Stop)),
            ("restart", Some(ServiceCommand::Restart)),
        ] {
            let cli = Cli::try_parse_from(["detent", "service", "chrony", name])?;
            let (module, action) = service_of(cli).ok_or("service must parse as Service")?;
            assert_eq!(module, "chrony");
            assert_eq!(action.command(), expected);
        }
        assert_eq!(ServiceSubcommand::Status.command(), None);
        Ok(())
    }

    #[test]
    fn service_options_map_to_operation_commands() {
        assert_eq!(
            ServiceOption::Restart.command(),
            Some(ServiceCommand::Restart)
        );
        assert_eq!(
            ServiceOption::Reload.command(),
            Some(ServiceCommand::Reload)
        );
        assert_eq!(ServiceOption::Start.command(), Some(ServiceCommand::Start));
        assert_eq!(ServiceOption::Stop.command(), Some(ServiceCommand::Stop));
        assert_eq!(ServiceOption::None.command(), None);
    }

    #[test]
    fn bad_input_is_a_usage_error() {
        for argv in [
            vec!["detent"],
            vec!["detent", "nope"],
            vec!["detent", "config", "hosts"],
            vec!["detent", "config", "hosts", "nope"],
            vec!["detent", "config", "hosts", "apply", "--service", "nope"],
            vec!["detent", "config", "hosts", "apply", "--confirm", "soon"],
            vec!["detent", "commit", "confirm", "not-a-number"],
            vec!["detent", "commit"],
            vec!["detent", "backup", "restore", "hosts"],
            vec!["detent", "audit", "--limit", "many"],
            vec!["detent", "completions", "csh"],
            vec!["detent", "service", "chrony", "reload"],
        ] {
            assert!(
                Cli::try_parse_from(argv.clone()).is_err(),
                "{argv:?} must not parse"
            );
        }
    }

    #[test]
    fn durations_accept_bare_seconds_and_suffixes() {
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration(" 90s "), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("2m"), Ok(Duration::from_secs(120)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_secs(3600)));
        assert_eq!(parse_duration("0s"), Ok(Duration::ZERO));
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("-1s").is_err());
        assert!(parse_duration("").is_err());
        assert!(
            parse_duration("18446744073709551615h")
                .err()
                .is_some_and(|err| err.contains("represent"))
        );
    }

    #[test]
    fn the_help_epilogue_documents_every_exit_code() {
        for code in ["0", "1", "2", "3"] {
            assert!(
                AFTER_HELP.contains(code),
                "exit code {code} is undocumented"
            );
        }
    }
}
