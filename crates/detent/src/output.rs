//! Rendering one [`OpOutcome`] or one [`OpsError`], and the process exit code.
//!
//! Two shapes, one source of truth:
//!
//! * `--json` writes `serde_json::to_string_pretty(&outcome)` — the same
//!   structures the web API will serve, with no CLI-specific DTO in between;
//! * otherwise a localized human rendering, every sentence of which is a Fluent
//!   id resolved through [`Messages`] (PLAN §4.3).
//!
//! # Identifiers are data, not prose
//!
//! Module ids, target paths, unit names, digests, and the wire names of enums
//! (`apply`, `active`, `restart`) are interpolated verbatim, exactly as the JSON
//! form spells them. They are identifiers an operator greps and pastes back into
//! another command, not sentences: translating `active` to `aktiv` would make
//! the human and JSON outputs disagree about the same value. Everything around
//! them is localized.
//!
//! # Exit codes (PLAN §2.6; repeated in `detent --help`)
//!
//! `0` success, `1` the operation failed, `2` usage error, `3` permission or
//! privilege problem.

use std::io::Write;

use detent_core::descriptor::HostProfile;
use detent_core::diag::MessageId;
use detent_core::module::{DynError, EditError, ModelError, ParseError};
use detent_ops::report::{ApplyReport, HostReport, OpOutcome, ServiceReport};
use detent_ops::{AuditRecord, OpsError, PlanReport};
use detent_platform::privsep::proto::BackupInfo;
use serde::Serialize;

use crate::i18n::Messages;
use crate::run::DryRun;

/// What the process exits with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The command did what it was asked to.
    Ok,
    /// The operation was well-formed but failed.
    Failed,
    /// The arguments, or the JSON on stdin, could not be used.
    Usage,
    /// The caller lacks the privilege the command needs.
    Privilege,
}

impl Exit {
    /// The numeric status.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Failed => 1,
            Self::Usage => 2,
            Self::Privilege => 3,
        }
    }
}

/// The exit code for `error`.
///
/// [`OpsError::Denied`] is the authorization refusal itself. The monitor's
/// `ProtoError::Io` carries a deliberately coarse summary with no path in it
/// (`privsep::proto`), of the form `openat: permission denied`; matching its
/// `ErrorKind` text is the only signal available on this side of the socket,
/// and getting it wrong only costs the difference between exit 1 and exit 3.
#[must_use]
pub fn exit_for(error: &OpsError) -> Exit {
    let denied = matches!(*error, OpsError::Denied(_));
    if denied || error.to_string().contains("permission denied") {
        Exit::Privilege
    } else {
        Exit::Failed
    }
}

/// Everything the error renderer knows that the error itself does not carry.
#[derive(Debug, Clone, Copy, Default)]
pub struct ErrorContext<'a> {
    /// The module the command was about.
    pub module: Option<&'a str>,
    /// The file that module manages on this host.
    pub path: Option<&'a str>,
}

/// Renders outcomes and errors to a pair of streams.
#[derive(Debug)]
pub struct Renderer<'a> {
    /// The message catalogue.
    pub messages: &'a Messages,
    /// Emit JSON instead of human text.
    pub json: bool,
    /// Emit step-level progress on the note stream.
    pub verbose: bool,
}

impl Renderer<'_> {
    /// Writes one localized line to `stream`.
    ///
    /// # Errors
    ///
    /// Whatever `stream` reports.
    pub fn line(
        &self,
        stream: &mut dyn Write,
        id: MessageId,
        args: &[(&str, &str)],
    ) -> std::io::Result<()> {
        writeln!(stream, "{}", self.messages.format(id, args))
    }

    /// Writes one localized line to `stream`, but only under `--verbose`.
    ///
    /// # Errors
    ///
    /// Whatever `stream` reports.
    pub fn note(
        &self,
        stream: &mut dyn Write,
        id: MessageId,
        args: &[(&str, &str)],
    ) -> std::io::Result<()> {
        if self.verbose {
            self.line(stream, id, args)?;
        }
        Ok(())
    }

    /// Renders `outcome`: data on `out`, notes and diagnostics on `notes`.
    ///
    /// # Errors
    ///
    /// Whatever the streams report.
    pub fn outcome(
        &self,
        out: &mut dyn Write,
        notes: &mut dyn Write,
        outcome: &OpOutcome,
    ) -> std::io::Result<()> {
        if self.json {
            return write_json(out, outcome);
        }
        match *outcome {
            OpOutcome::Modules(ref descriptors) => {
                for descriptor in descriptors {
                    self.line(
                        out,
                        MessageId::new("cli-module-line"),
                        &[
                            ("id", descriptor.id),
                            ("name", &self.messages.get(descriptor.display_name_id)),
                        ],
                    )?;
                }
                Ok(())
            }
            OpOutcome::Module(ref view) => {
                match view.model {
                    Some(ref model) => write_json(out, model)?,
                    None => self.line(notes, MessageId::new("cli-no-model"), &[])?,
                }
                self.diagnostics(notes, &view.diagnostics)
            }
            OpOutcome::Validated(ref diagnostics) => {
                if diagnostics.is_empty() {
                    return self.line(out, MessageId::new("cli-valid"), &[]);
                }
                self.diagnostics(out, diagnostics)
            }
            OpOutcome::Planned(ref plan) => self.plan(out, notes, plan),
            OpOutcome::Applied(ref report) => self.applied(out, report),
            OpOutcome::CommitConfirmed { commit_id } => self.line(
                out,
                MessageId::new("cli-commit-confirmed"),
                &[("id", &commit_id.to_string())],
            ),
            OpOutcome::RolledBack {
                commit_id,
                restored,
            } => self.line(
                out,
                MessageId::new("cli-commit-rolled-back"),
                &[
                    ("id", &commit_id.to_string()),
                    ("targets", &restored.to_string()),
                ],
            ),
            OpOutcome::Backups(ref backups) => self.backups(out, backups),
            OpOutcome::Restored { target, new_hash } => self.line(
                out,
                MessageId::new("cli-restored"),
                &[
                    ("target", &target.to_string()),
                    ("hash", &new_hash.to_string()),
                ],
            ),
            OpOutcome::Status(ref status) => self.line(
                out,
                MessageId::new("cli-service-status"),
                &[
                    ("unit", &status.unit),
                    ("state", &token(&status.state)),
                    (
                        "enabled",
                        &status
                            .enabled
                            .map_or_else(String::new, |flag| self.yes_no(flag)),
                    ),
                ],
            ),
            OpOutcome::Serviced(ref report) => self.serviced(out, report),
            OpOutcome::Host(ref host) => self.host_report(out, notes, host),
            OpOutcome::Audit(ref records) => self.audit(out, records),
            // Unreachable: the engine answers `UpdateApply` as `Unsupported`
            // until the `ReplaceBinary` monitor wiring lands, so this arm only
            // exists to keep the match exhaustive.
            OpOutcome::UpdateApplied { .. } => {
                Err(std::io::Error::other("update install is not wired yet"))
            }
        }
    }

    /// What an apply wrote, what it hashed to, and what it armed.
    fn applied(&self, out: &mut dyn Write, report: &ApplyReport) -> std::io::Result<()> {
        self.line(
            out,
            MessageId::new("cli-applied"),
            &[("module", &report.module), ("path", &report.path)],
        )?;
        self.line(
            out,
            MessageId::new("cli-applied-hash"),
            &[
                (
                    "prev",
                    &report
                        .prev_hash
                        .map(|hash| hash.to_string())
                        .unwrap_or_default(),
                ),
                ("new", &report.new_hash.to_string()),
                ("backup", &self.yes_no(report.backed_up)),
            ],
        )?;
        if let Some(ref service) = report.service {
            self.serviced(out, service)?;
        }
        if let Some(ref commit) = report.commit {
            self.line(
                out,
                MessageId::new("cli-commit-armed"),
                &[
                    ("id", &commit.commit_id.to_string()),
                    ("seconds", &commit.timeout_s.to_string()),
                    ("deadline", &commit.deadline),
                ],
            )?;
        }
        Ok(())
    }

    /// One line per service action.
    fn serviced(&self, out: &mut dyn Write, report: &ServiceReport) -> std::io::Result<()> {
        self.line(
            out,
            MessageId::new("cli-serviced"),
            &[
                ("unit", &report.unit),
                ("action", &token(&report.action)),
                ("active", &self.yes_no(report.active)),
            ],
        )
    }

    /// One line per retained backup, newest first.
    fn backups(&self, out: &mut dyn Write, backups: &[BackupInfo]) -> std::io::Result<()> {
        if backups.is_empty() {
            return self.line(out, MessageId::new("cli-no-backups"), &[]);
        }
        for backup in backups {
            self.line(
                out,
                MessageId::new("cli-backup-line"),
                &[
                    ("id", &backup.id.to_string()),
                    ("name", &backup.name),
                    ("bytes", &backup.len.to_string()),
                    ("digest", &backup.digest.to_string()),
                ],
            )?;
        }
        Ok(())
    }

    /// The detected host: profile, backends, and any detection caveats.
    fn host_report(
        &self,
        out: &mut dyn Write,
        notes: &mut dyn Write,
        host: &HostReport,
    ) -> std::io::Result<()> {
        self.host(out, &host.profile)?;
        self.line(
            out,
            MessageId::new("cli-host-backends"),
            &[
                ("network", host.network_backend),
                ("resolver", host.resolver_backend),
                ("distro", host.distro_id.as_deref().unwrap_or_default()),
                (
                    "version",
                    host.distro_version_id.as_deref().unwrap_or_default(),
                ),
            ],
        )?;
        for note in &host.notes {
            self.line(notes, MessageId::new("cli-host-note"), &[("note", note)])?;
        }
        Ok(())
    }

    /// One line per audit record, newest first.
    fn audit(&self, out: &mut dyn Write, records: &[AuditRecord]) -> std::io::Result<()> {
        if records.is_empty() {
            return self.line(out, MessageId::new("cli-no-audit"), &[]);
        }
        for record in records {
            self.line(
                out,
                MessageId::new("cli-audit-line"),
                &[
                    ("ts", &record.ts),
                    ("who", &record.who),
                    ("op", &token(&record.op)),
                    ("module", record.module.as_deref().unwrap_or_default()),
                    ("result", &token(&record.result)),
                    ("error", record.error_id.as_deref().unwrap_or_default()),
                ],
            )?;
        }
        Ok(())
    }

    /// Renders what `--dryrun` withheld: for an `Apply`, the plan it implies,
    /// so the diff is still shown; for any other mutation, what it would have
    /// done.
    ///
    /// # Errors
    ///
    /// Whatever the streams report.
    pub fn dry_run(
        &self,
        out: &mut dyn Write,
        notes: &mut dyn Write,
        report: &DryRun,
    ) -> std::io::Result<()> {
        if self.json {
            return write_json(out, report);
        }
        let module = report.module.as_deref().unwrap_or_default();
        match report.plan {
            Some(ref plan) => {
                self.line(
                    notes,
                    MessageId::new("cli-dryrun-apply"),
                    &[("module", module), ("path", &plan.path)],
                )?;
                self.plan(out, notes, plan)?;
            }
            None => self.line(
                out,
                MessageId::new("cli-dryrun-operation"),
                &[("operation", &token(&report.operation)), ("module", module)],
            )?,
        }
        self.line(notes, MessageId::new("cli-dryrun-nothing"), &[])
    }

    /// The `plan` rendering: the unified diff is the payload, everything else
    /// is commentary (PLAN §2.6).
    fn plan(
        &self,
        out: &mut dyn Write,
        notes: &mut dyn Write,
        plan: &PlanReport,
    ) -> std::io::Result<()> {
        if plan.would_change {
            write!(out, "{}", plan.unified_diff)?;
        } else {
            self.line(
                notes,
                MessageId::new("cli-plan-no-change"),
                &[("module", &plan.module), ("path", &plan.path)],
            )?;
        }
        for check in &plan.checks {
            let id = if check.ran {
                MessageId::new("cli-check-ran")
            } else {
                MessageId::new("cli-check-skipped")
            };
            self.line(
                notes,
                id,
                &[
                    ("program", &check.program),
                    ("passed", &self.yes_no(check.passed)),
                    ("detail", &check.detail),
                ],
            )?;
        }
        for service in &plan.affected_services {
            self.line(
                notes,
                MessageId::new("cli-plan-service"),
                &[("unit", &service.unit)],
            )?;
        }
        self.note(
            notes,
            MessageId::new("cli-plan-hash"),
            &[("hash", &plan.current_hash.to_string())],
        )?;
        self.diagnostics(notes, &plan.diagnostics)
    }

    /// The host profile, shared by `host` and `doctor`.
    ///
    /// # Errors
    ///
    /// Whatever `stream` reports.
    pub fn host(&self, stream: &mut dyn Write, profile: &HostProfile) -> std::io::Result<()> {
        self.line(
            stream,
            MessageId::new("cli-host-profile"),
            &[
                ("hostname", &profile.hostname),
                ("os", &token(&profile.os)),
                ("init", &token(&profile.init)),
                ("ram", &profile.ram_mib.to_string()),
            ],
        )?;
        for (service, version) in &profile.service_versions {
            self.line(
                stream,
                MessageId::new("cli-host-service-version"),
                &[("service", service), ("version", version)],
            )?;
        }
        Ok(())
    }

    /// Renders every diagnostic, one localized line each.
    ///
    /// # Errors
    ///
    /// Whatever `stream` reports.
    pub fn diagnostics(
        &self,
        stream: &mut dyn Write,
        diagnostics: &detent_core::diag::Diagnostics,
    ) -> std::io::Result<()> {
        for line in self.messages.diagnostics(diagnostics) {
            writeln!(stream, "{line}")?;
        }
        Ok(())
    }

    /// Renders `error` and returns the exit code it deserves.
    ///
    /// # Errors
    ///
    /// Whatever `stream` reports.
    pub fn error(
        &self,
        stream: &mut dyn Write,
        error: &OpsError,
        context: ErrorContext<'_>,
    ) -> std::io::Result<Exit> {
        let id = error.message_id();
        let reason = self.reason(error);
        let args: Vec<(&str, &str)> = vec![
            ("module", context.module.unwrap_or_default()),
            ("path", context.path.unwrap_or_default()),
            ("reason", &reason),
            ("what", &reason),
            ("value", &reason),
        ];
        if self.json {
            write_json(
                stream,
                &ErrorReport {
                    id: id.as_str(),
                    message: self.messages.format(id, &args),
                    module: context.module,
                    detail: error.to_string(),
                },
            )?;
        } else {
            writeln!(stream, "{}", self.messages.format(id, &args))?;
            if let OpsError::Invalid { ref diagnostics } = *error {
                self.diagnostics(stream, diagnostics)?;
            }
        }
        Ok(exit_for(error))
    }

    /// The `{$reason}`/`{$what}` argument for an error message: the detail the
    /// catalogue expects, taken from the most specific field the variant has.
    fn reason(&self, error: &OpsError) -> String {
        match *error {
            OpsError::Invalid { ref diagnostics } => {
                self.messages.diagnostics(diagnostics).join("; ")
            }
            OpsError::Module(ref err) => module_detail(err),
            OpsError::Unsupported { what } => what.to_owned(),
            OpsError::Privsep(ref err) => err.to_string(),
            OpsError::Service(ref err) => err.to_string(),
            OpsError::Audit(ref err) => err.to_string(),
            _ => error.to_string(),
        }
    }

    /// The localized `yes`/`no` a flag renders as.
    fn yes_no(&self, flag: bool) -> String {
        let id = if flag {
            MessageId::new("cli-yes")
        } else {
            MessageId::new("cli-no")
        };
        self.messages.get(id)
    }
}

/// The JSON body of a failure under `--json`.
#[derive(Debug, Serialize)]
struct ErrorReport<'a> {
    /// The Fluent id, so a caller can localize it itself.
    id: &'a str,
    /// The rendered sentence.
    message: String,
    /// The module the command was about.
    module: Option<&'a str>,
    /// The untranslated internal detail, for a log.
    detail: String,
}

/// The wire name of a serializable enum, e.g. `restart`, used verbatim as an
/// identifier (see the module docs). Falls back to `Debug` for the shapes
/// `serde_json` cannot render as a bare string, which none of the enums used
/// here are.
///
/// Public within the crate so `run`'s progress notes name an operation the same
/// way `--json` does.
pub fn token<T: Serialize + std::fmt::Debug>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|json| json.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| format!("{value:?}"))
}

/// The detail string a module error carries.
fn module_detail(error: &DynError) -> String {
    match *error {
        DynError::Parse(ParseError::Malformed { ref message, .. })
        | DynError::Model(
            ModelError::Shape { ref message } | ModelError::Unrepresentable { ref message, .. },
        )
        | DynError::Edit(EditError::Unsupported { ref message }) => message.clone(),
        DynError::Edit(EditError::LineBreakInValue { ref value }) => value.clone(),
        DynError::Edit(EditError::IndexOutOfRange { index, len }) => format!("{index}/{len}"),
    }
}

/// Pretty JSON plus a trailing newline.
fn write_json<T: Serialize>(stream: &mut dyn Write, value: &T) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(value).map_err(std::io::Error::other)?;
    writeln!(stream, "{text}")
}

#[cfg(test)]
mod tests {
    use super::{ErrorContext, Exit, Renderer, exit_for, module_detail, token, write_json};
    use crate::i18n::Messages;
    use detent_core::descriptor::{HostProfile, InitSystem, Os};
    use detent_core::diag::{Diagnostic, Diagnostics, MessageId, Severity};
    use detent_core::module::{DynError, EditError, ModelError, ParseError};
    use detent_ops::authz::Denied;
    use detent_ops::report::OpOutcome;
    use detent_ops::{OpsError, ServiceCommand};
    use detent_platform::fs::atomic::Sha256Digest;
    use detent_platform::privsep::proto::TargetId;
    use detent_platform::privsep::worker::ClientError;
    use detent_platform::service::{ServiceError, ServiceStatus, State};

    type R = Result<(), Box<dyn std::error::Error>>;

    fn messages() -> Messages {
        Messages::new(Some("en-US"))
    }

    fn renderer(messages: &Messages, json: bool) -> Renderer<'_> {
        Renderer {
            messages,
            json,
            verbose: true,
        }
    }

    fn render(
        outcome: &OpOutcome,
        json: bool,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        let messages = messages();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        renderer(&messages, json).outcome(&mut out, &mut notes, outcome)?;
        Ok((String::from_utf8(out)?, String::from_utf8(notes)?))
    }

    #[test]
    fn exit_codes_are_the_documented_numbers() {
        assert_eq!(Exit::Ok.code(), 0);
        assert_eq!(Exit::Failed.code(), 1);
        assert_eq!(Exit::Usage.code(), 2);
        assert_eq!(Exit::Privilege.code(), 3);
        assert_eq!(Exit::Ok, Exit::Ok);
        assert!(format!("{:?}", Exit::Usage).contains("Usage"));
    }

    #[test]
    fn a_refusal_and_a_permission_error_exit_three() {
        assert_eq!(
            exit_for(&OpsError::from(Denied::new(MessageId::new("ops-denied")))),
            Exit::Privilege
        );
        assert_eq!(
            exit_for(&OpsError::Privsep(ClientError::Remote(
                detent_platform::privsep::proto::ProtoError::Io(
                    "openat: permission denied".to_owned()
                )
            ))),
            Exit::Privilege
        );
        assert_eq!(
            exit_for(&OpsError::NoService {
                module: "hosts".to_owned()
            }),
            Exit::Failed
        );
    }

    #[test]
    fn every_outcome_variant_renders_as_valid_json() -> R {
        for outcome in crate::tests_support::every_outcome() {
            let (out, notes) = render(&outcome, true)?;
            let parsed: serde_json::Value = serde_json::from_str(&out)?;
            assert!(parsed.is_object(), "{out}");
            assert!(notes.is_empty(), "json mode writes nothing to notes");
        }
        Ok(())
    }

    #[test]
    fn every_outcome_variant_renders_as_localized_text() -> R {
        for outcome in crate::tests_support::every_outcome() {
            let (out, notes) = render(&outcome, false)?;
            let text = format!("{out}{notes}");
            assert!(!text.is_empty(), "{outcome:?} rendered nothing");
            // A bare Fluent id would mean a message is missing from cli.ftl.
            assert!(
                !text.contains("cli-"),
                "{outcome:?} rendered an unresolved id: {text}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_plan_prints_the_diff_and_keeps_commentary_off_stdout() -> R {
        let outcome = OpOutcome::Planned(Box::new(crate::tests_support::planned(true)));
        let (out, notes) = render(&outcome, false)?;
        assert!(out.starts_with("--- "), "{out}");
        assert!(out.contains("+new\n"), "{out}");
        assert!(notes.contains("/nonexistent/check"), "{notes}");
        assert!(notes.contains("fake.service"), "{notes}");

        let unchanged = OpOutcome::Planned(Box::new(crate::tests_support::planned(false)));
        let (out, notes) = render(&unchanged, false)?;
        assert!(out.is_empty(), "an unchanged plan prints no diff: {out}");
        assert!(!notes.is_empty());
        Ok(())
    }

    #[test]
    fn a_module_view_prints_its_model_and_its_diagnostics() -> R {
        let (out, notes) = render(&crate::tests_support::module_view(true), false)?;
        assert!(out.contains("\"text\""), "{out}");
        assert!(notes.contains("no hostnames"), "{notes}");

        let (out, notes) = render(&crate::tests_support::module_view(false), false)?;
        assert!(out.is_empty(), "{out}");
        assert!(!notes.is_empty());
        Ok(())
    }

    #[test]
    fn empty_listings_say_so_rather_than_printing_nothing() -> R {
        for outcome in [
            OpOutcome::Backups(Vec::new()),
            OpOutcome::Audit(Vec::new()),
            OpOutcome::Validated(Diagnostics::new()),
        ] {
            let (out, _) = render(&outcome, false)?;
            assert!(!out.trim().is_empty(), "{outcome:?} printed nothing");
        }
        Ok(())
    }

    #[test]
    fn a_status_without_an_enabled_flag_still_renders() -> R {
        let outcome = OpOutcome::Status(ServiceStatus {
            unit: "fake.service".to_owned(),
            state: State::Inactive,
            enabled: None,
            since: None,
        });
        let (out, _) = render(&outcome, false)?;
        assert!(out.contains("inactive"), "{out}");
        Ok(())
    }

    #[test]
    fn errors_render_localized_text_and_json_and_report_their_exit_code() -> R {
        let messages = messages();
        let context = ErrorContext {
            module: Some("hosts"),
            path: Some("/etc/hosts"),
        };
        let errors = vec![
            OpsError::UnknownModule {
                id: "nope".to_owned(),
            },
            OpsError::from(Denied::new(MessageId::new("ops-denied"))),
            OpsError::Invalid {
                diagnostics: Box::new(
                    std::iter::once(Diagnostic::new(
                        Severity::Error,
                        MessageId::new("hosts-no-hostnames"),
                    ))
                    .collect(),
                ),
            },
            OpsError::HashConflict {
                expected: Sha256Digest::of(b"a"),
                actual: None,
            },
            OpsError::from(DynError::from(ParseError::Malformed {
                message: "planted".to_owned(),
                span: None,
            })),
            OpsError::from(ClientError::NotGreeted),
            OpsError::from(ServiceError::Unavailable("no systemctl".to_owned())),
            OpsError::NoTarget {
                module: "hosts".to_owned(),
            },
            OpsError::NoService {
                module: "hosts".to_owned(),
            },
            OpsError::from(detent_ops::audit::AuditError::Encode("bad".to_owned())),
            OpsError::Unsupported { what: "rollback" },
        ];
        for error in errors {
            let mut text = Vec::new();
            let exit = renderer(&messages, false).error(&mut text, &error, context)?;
            let rendered = String::from_utf8(text)?;
            assert!(!rendered.is_empty());
            assert!(
                !rendered.contains(error.message_id().as_str()),
                "{error:?} rendered an unresolved id: {rendered}"
            );
            assert!(matches!(exit, Exit::Failed | Exit::Privilege));

            let mut json = Vec::new();
            renderer(&messages, true).error(&mut json, &error, context)?;
            let parsed: serde_json::Value = serde_json::from_slice(&json)?;
            assert_eq!(
                parsed.pointer("/id").and_then(|v| v.as_str()),
                Some(error.message_id().as_str())
            );
            assert!(parsed.pointer("/message").is_some());
            assert_eq!(
                parsed.pointer("/module").and_then(|v| v.as_str()),
                Some("hosts")
            );
        }
        Ok(())
    }

    #[test]
    fn an_error_without_context_still_renders() -> R {
        let messages = messages();
        let mut text = Vec::new();
        renderer(&messages, false).error(
            &mut text,
            &OpsError::NoTarget {
                module: "hosts".to_owned(),
            },
            ErrorContext::default(),
        )?;
        assert!(!String::from_utf8(text)?.is_empty());
        Ok(())
    }

    #[test]
    fn module_errors_surface_the_field_their_message_needs() {
        assert_eq!(
            module_detail(&DynError::from(ParseError::Malformed {
                message: "m".to_owned(),
                span: None
            })),
            "m"
        );
        assert_eq!(
            module_detail(&DynError::from(ModelError::Shape {
                message: "s".to_owned()
            })),
            "s"
        );
        assert_eq!(
            module_detail(&DynError::from(ModelError::Unrepresentable {
                message: "u".to_owned(),
                span: None
            })),
            "u"
        );
        assert_eq!(
            module_detail(&DynError::from(EditError::Unsupported {
                message: "e".to_owned()
            })),
            "e"
        );
        assert_eq!(
            module_detail(&DynError::from(EditError::LineBreakInValue {
                value: "v".to_owned()
            })),
            "v"
        );
        assert_eq!(
            module_detail(&DynError::from(EditError::IndexOutOfRange {
                index: 1,
                len: 2
            })),
            "1/2"
        );
    }

    #[test]
    fn notes_are_silent_unless_verbose() -> R {
        let messages = messages();
        let quiet = Renderer {
            messages: &messages,
            json: false,
            verbose: false,
        };
        let mut sink = Vec::new();
        quiet.note(&mut sink, MessageId::new("cli-valid"), &[])?;
        assert!(sink.is_empty());
        quiet.line(&mut sink, MessageId::new("cli-valid"), &[])?;
        assert!(!sink.is_empty());
        Ok(())
    }

    #[test]
    fn a_host_profile_lists_its_probed_service_versions() -> R {
        let messages = messages();
        let mut profile = HostProfile {
            os: Os::Linux,
            init: InitSystem::Systemd,
            hostname: "box".to_owned(),
            service_versions: std::collections::BTreeMap::new(),
            ram_mib: 512,
        };
        profile
            .service_versions
            .insert("chrony".to_owned(), "4.5".to_owned());
        let mut out = Vec::new();
        renderer(&messages, false).host(&mut out, &profile)?;
        let text = String::from_utf8(out)?;
        assert!(text.contains("box") && text.contains("chrony") && text.contains("4.5"));
        Ok(())
    }

    #[test]
    fn identifiers_render_as_their_wire_names() {
        assert_eq!(token(&ServiceCommand::Restart), "restart");
        assert_eq!(token(&State::Active), "active");
        assert_eq!(token(&Os::Linux), "linux");
        // A shape with no bare-string form falls back to Debug rather than
        // rendering nothing.
        assert_eq!(token(&(1, 2)), "(1, 2)");
    }

    /// Every rendering path propagates a stream failure instead of swallowing
    /// it. Sweeping all of them (rather than one) is what exercises the `?` on
    /// each individual `writeln!`, which an in-memory sink never reaches.
    #[test]
    fn a_write_failure_is_reported_rather_than_ignored() {
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let messages = messages();
        let mut broken = Broken;
        assert!(std::io::Write::flush(&mut broken).is_ok());
        // The skip-branch variants `every_outcome` never carries: no commit,
        // no model, and an unchanged plan.
        let outcomes = {
            let mut outcomes = crate::tests_support::every_outcome();
            outcomes.push(crate::tests_support::applied_without_commit());
            outcomes.push(crate::tests_support::module_view(false));
            outcomes.push(OpOutcome::Planned(Box::new(crate::tests_support::planned(
                false,
            ))));
            outcomes
        };
        // A writer that fails only part-way through reaches the second and
        // later `?` of a multi-line rendering.
        for allow in 0..20_usize {
            let renderer = renderer(&messages, false);
            for outcome in &outcomes {
                let mut failing = crate::tests_support::FailAfter::new(allow);
                let mut notes = crate::tests_support::FailAfter::new(allow);
                let _ = renderer.outcome(&mut failing, &mut notes, outcome);
            }
            for report in [
                crate::tests_support::dry_run(true),
                crate::tests_support::dry_run(false),
                crate::tests_support::dry_run_plan(crate::tests_support::planned(false)),
            ] {
                let mut failing = crate::tests_support::FailAfter::new(allow);
                let mut notes = crate::tests_support::FailAfter::new(allow);
                let _ = renderer.dry_run(&mut failing, &mut notes, &report);
            }
            let mut failing = crate::tests_support::FailAfter::new(allow);
            let _ = renderer.error(
                &mut failing,
                &OpsError::Invalid {
                    diagnostics: Box::new(
                        std::iter::once(Diagnostic::new(
                            Severity::Error,
                            MessageId::new("hosts-no-hostnames"),
                        ))
                        .collect(),
                    ),
                },
                ErrorContext::default(),
            );
            // The host fixture carries no probed service versions, so its
            // version line needs its own failing writer.
            let mut profile = crate::tests_support::host_profile();
            profile
                .service_versions
                .insert("chrony".to_owned(), "4.5".to_owned());
            let mut failing = crate::tests_support::FailAfter::new(allow);
            let _ = renderer.host(&mut failing, &profile);
        }
        for json in [false, true] {
            let renderer = renderer(&messages, json);
            for outcome in &outcomes {
                // Either stream may be the one that fails: `Module` and `Host`
                // write to both. Evaluate both sides before asserting, so a
                // failure on the left cannot mask what the right would show.
                let first = renderer
                    .outcome(&mut broken, &mut std::io::sink(), outcome)
                    .is_err();
                let second = renderer
                    .outcome(&mut std::io::sink(), &mut broken, outcome)
                    .is_err();
                assert!(first || second, "{outcome:?} swallowed a write failure");
            }
            assert!(
                renderer
                    .error(
                        &mut broken,
                        &OpsError::NoTarget {
                            module: "hosts".to_owned()
                        },
                        ErrorContext::default(),
                    )
                    .is_err()
            );
            for with_plan in [false, true] {
                let report = crate::tests_support::dry_run(with_plan);
                let first = renderer
                    .dry_run(&mut broken, &mut std::io::sink(), &report)
                    .is_err();
                let second = renderer
                    .dry_run(&mut std::io::sink(), &mut broken, &report)
                    .is_err();
                assert!(
                    first || second,
                    "a withheld mutation swallowed a write failure"
                );
            }
        }
        assert!(write_json(&mut broken, &serde_json::json!({})).is_err());
    }

    #[test]
    fn an_apply_without_a_commit_armed_skips_the_commit_line() -> R {
        // `every_outcome` always arms a commit, so 254-255 only run when one
        // is absent — and 244 only runs when the previous write already
        // failed (FailAfter), since `applied` is two lines, not one.
        let messages = messages();
        let outcome = crate::tests_support::applied_without_commit();
        let (out, notes) = render(&outcome, false)?;
        assert!(out.contains("fake"), "{out}{notes}");
        for allow in 0..=1_usize {
            let mut failing = crate::tests_support::FailAfter::new(allow);
            let mut notes = Vec::new();
            let _ = renderer(&messages, false).outcome(&mut failing, &mut notes, &outcome);
        }
        Ok(())
    }

    #[test]
    fn a_dry_run_renders_the_plan_it_withheld_and_says_nothing_changed() -> R {
        let messages = messages();
        for json in [false, true] {
            for with_plan in [false, true] {
                let mut out = Vec::new();
                let mut notes = Vec::new();
                renderer(&messages, json).dry_run(
                    &mut out,
                    &mut notes,
                    &crate::tests_support::dry_run(with_plan),
                )?;
                let text = String::from_utf8(out)?;
                if json {
                    let parsed: serde_json::Value = serde_json::from_str(&text)?;
                    assert_eq!(
                        parsed
                            .pointer("/dryrun")
                            .and_then(serde_json::Value::as_bool),
                        Some(true)
                    );
                    assert!(parsed.pointer("/plan").is_some(), "{parsed}");
                } else {
                    let notes = String::from_utf8(notes)?;
                    assert!(!notes.is_empty());
                    assert!(!notes.contains("cli-dryrun"), "{notes}");
                    assert_eq!(text.starts_with("--- "), with_plan, "{text}");
                }
            }
        }
        Ok(())
    }
    #[test]
    fn an_applied_outcome_without_service_or_commit_skips_both_lines() -> R {
        let (out, notes) = render(&crate::tests_support::applied_without_commit(), false)?;
        assert!(out.contains("/etc/fake.conf"), "{out}{notes}");
        assert!(!notes.contains("cli-commit-armed"), "{notes}");
        assert!(!notes.contains("cli-serviced"), "{notes}");
        Ok(())
    }

    #[test]
    fn a_restored_outcome_names_the_target_and_the_digest() -> R {
        let (out, _) = render(
            &OpOutcome::Restored {
                target: TargetId(0),
                new_hash: Sha256Digest::of(b"x"),
            },
            false,
        )?;
        assert!(out.contains(&Sha256Digest::of(b"x").to_string()), "{out}");
        Ok(())
    }
    #[test]
    fn a_plan_with_nothing_to_change_names_module_and_path() -> R {
        let mut report = crate::tests_support::planned(true);
        report.would_change = false;
        report.unified_diff.clear();
        let module = report.module.clone();
        let path = report.path.clone();
        let messages = messages();
        let mut out = Vec::new();
        let mut notes = Vec::new();
        renderer(&messages, false).dry_run(
            &mut out,
            &mut notes,
            &crate::tests_support::dry_run_plan(report),
        )?;
        assert!(out.is_empty());
        let notes = String::from_utf8(notes)?;
        assert!(notes.contains(&module), "{notes}");
        assert!(notes.contains(&path), "{notes}");
        Ok(())
    }
}
