//! `detent serve`: the process model (PLAN §2.4, ADR-001).
//!
//! This is the skeleton the web server plugs into in Phase 4, and it is the one
//! command that really forks:
//!
//! ```text
//! detent serve ──spawn_pair──▶ monitor (this process, privileged, confined)
//!                              worker  (child, unprivileged, confined)
//! ```
//!
//! The monitor serves the closed privsep protocol until the worker asks it to
//! stop, then reaps the child and exits with the child's status. The worker is
//! where TLS, HTTP, the API and the UI will live; today it says so and exits
//! cleanly, which is enough to prove the fork, the credential drop and the
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
use detent_platform::sandbox::{Hooks as SandboxHooks, Policy};
use detent_platform::service::checks::ExternalCheckRunner;
use detent_platform::service::{self, ServiceControlAdapter};

use crate::output::{Exit, Renderer};
use crate::run::{Settings, Streams};

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
        Role::Worker(mut client) => {
            // The child. It must never return into `main`, or the process tree
            // ends up with two copies of the CLI.
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
        Role::Monitor(handle) => {
            let mut handle = handle;
            renderer.line(
                streams.notes,
                MessageId::new("cli-serve-monitor"),
                &[
                    ("pid", &handle.child_pid.to_string()),
                    (
                        "dropped",
                        if spawned.dropped_privileges { "1" } else { "0" },
                    ),
                ],
            )?;
            let served = Monitor::new(
                allow,
                Hooks {
                    checks: &ExternalCheckRunner::new(),
                    services: &ServiceControlAdapter(service::for_host(host.profile.init)),
                },
            )
            .serve(&mut handle.channel);
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
    use super::{Exit, exit_for_spawn, run};
    use crate::i18n::Messages;
    use crate::output::Renderer;
    use crate::run::{Settings, Streams};
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
