//! `systemctl`-backed [`ServiceManager`] (PLAN §1.6: Linux tier 1).
//!
//! `since` (`ServiceStatus::since`) is always `None` in v1: `systemctl show`
//! prints `ActiveEnterTimestamp` as a human-readable calendar string (e.g.
//! `"Mon 2026-09-01 10:00:00 UTC"`), and this crate's `time` dependency is
//! built without the `parsing` feature (PLAN §4.2 / root `Cargo.toml` pins
//! `formatting, macros` only). Adding calendar parsing would need a new
//! dependency or feature, which this subtask does not add; the field stays
//! `None` rather than guessed.

use std::collections::HashMap;

use detent_core::descriptor::{ServiceAction, UnitNames};

use super::exec::{self, ACTION_TIMEOUT, ProcessRunner, RealProcessRunner, STATUS_TIMEOUT};
use super::{
    ActionOutcome, AltCache, MOUNT_WAIT, MountUnitState, ServiceError, ServiceManager,
    ServiceStatus, State, UPDATE_UNIT, UpdateStart, validate_mount_unit_name, validate_unit_name,
};
use crate::privsep::proto::is_release_tag;

/// Absolute paths `systemctl` may live at, most common first.
const SYSTEMCTL_CANDIDATES: &[&str] = &["/usr/bin/systemctl", "/bin/systemctl"];

/// Absolute paths `systemd-run` may live at, most common first.
const SYSTEMD_RUN_CANDIDATES: &[&str] = &["/usr/bin/systemd-run", "/bin/systemd-run"];

/// The whole `systemd-run` argv for [`ServiceManager::start_update`]: fixed
/// literals, the installed binary and the tag. `--collect` unloads the unit
/// when it ends, also after a failure, so a refused update does not keep the
/// name and block the next start.
#[must_use]
pub fn update_unit_args(binary: &str, tag: &str) -> Vec<String> {
    vec![
        format!("--unit={UPDATE_UNIT}"),
        "--collect".to_owned(),
        binary.to_owned(),
        "update".to_owned(),
        "--tag".to_owned(),
        tag.to_owned(),
    ]
}

/// Properties requested from `systemctl show`. A fixed, compile-time
/// literal: no user input ever reaches this argv position.
const SHOW_PROPERTIES: &str =
    "--property=LoadState,ActiveState,SubState,UnitFileState,ActiveEnterTimestamp";

/// Properties `systemctl show` reports for a mount unit. A fixed literal.
const MOUNT_PROPERTIES: &str = "--property=ActiveState,Result";

/// Drives systemd via the `systemctl` binary. See the module docs at
/// [`crate::service`] for why this uses `systemctl` rather than `zbus`.
pub struct SystemdManager {
    runner: Box<dyn ProcessRunner>,
    cache: AltCache,
}

impl std::fmt::Debug for SystemdManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SystemdManager { .. }")
    }
}

impl SystemdManager {
    /// Builds a manager backed by the real `systemctl` binary.
    #[must_use]
    pub fn new() -> Self {
        Self::with_runner(Box::new(RealProcessRunner))
    }

    /// Builds a manager backed by `runner`, for tests.
    #[must_use]
    pub fn with_runner(runner: Box<dyn ProcessRunner>) -> Self {
        Self {
            runner,
            cache: AltCache::default(),
        }
    }

    fn program(&self) -> Result<&'static str, ServiceError> {
        exec::resolve_program(self.runner.as_ref(), SYSTEMCTL_CANDIDATES).ok_or_else(|| {
            ServiceError::Unavailable("systemctl was not found on this host".to_owned())
        })
    }

    /// Runs `systemctl show <unit> <SHOW_PROPERTIES>` and parses the
    /// `key=value` lines it prints.
    fn show(
        &self,
        program: &'static str,
        unit: &str,
    ) -> Result<HashMap<String, String>, ServiceError> {
        let args = vec![
            "show".to_owned(),
            unit.to_owned(),
            SHOW_PROPERTIES.to_owned(),
        ];
        let output = self
            .runner
            .run(program, &args, STATUS_TIMEOUT)
            .map_err(|err| ServiceError::Failed(err.to_string()))?;
        if output.timed_out {
            return Err(ServiceError::Failed(format!(
                "systemctl show {unit} timed out"
            )));
        }
        Ok(parse_key_values(&output.stdout))
    }

    /// Resolves `units.systemd` to the first alternative that actually
    /// exists on this host, caching the answer.
    ///
    /// A cache miss's *last* probe (the one that succeeded) already carries
    /// fresh `systemctl show` properties, so [`Resolved::Fresh`] returns
    /// them for [`ServiceManager::status`] to reuse instead of spawning a
    /// second, redundant `systemctl show` immediately after the first. A
    /// cache hit only has a unit name, so the caller must query fresh state
    /// itself.
    fn resolve(&self, units: &UnitNames) -> Result<Resolved, ServiceError> {
        if let Some(hit) = self.cache.get(units.systemd) {
            return Ok(Resolved::Cached(hit));
        }
        let program = self.program()?;
        let mut tried = Vec::new();
        for alt in units.systemd {
            validate_unit_name(alt)?;
            tried.push((*alt).to_owned());
            let props = self.show(program, alt)?;
            let load_state = props.get("LoadState").map_or("", String::as_str);
            if !load_state.is_empty() && load_state != "not-found" {
                self.cache.set(units.systemd, alt);
                return Ok(Resolved::Fresh((*alt).to_owned(), props));
            }
        }
        Err(ServiceError::NoKnownUnit { tried })
    }
}

impl SystemdManager {
    /// Runs `systemctl <verb> -- <units>` once, with `timeout`. `--` keeps
    /// a unit name from ever being read as an option.
    fn run_on_units(
        &self,
        program: &'static str,
        verb: &str,
        units: &[String],
        timeout: std::time::Duration,
    ) -> Result<super::exec::ProcessOutput, ServiceError> {
        let mut args = vec![verb.to_owned(), "--".to_owned()];
        args.extend(units.iter().cloned());
        self.runner
            .run(program, &args, timeout)
            .map_err(|err| ServiceError::Failed(err.to_string()))
    }

    /// The `ActiveState` of `unit`.
    fn mount_unit_state(&self, program: &'static str, unit: &str) -> Result<State, ServiceError> {
        let args = vec![
            "show".to_owned(),
            MOUNT_PROPERTIES.to_owned(),
            "--".to_owned(),
            unit.to_owned(),
        ];
        let output = self
            .runner
            .run(program, &args, STATUS_TIMEOUT)
            .map_err(|err| ServiceError::Failed(err.to_string()))?;
        if output.timed_out {
            return Err(ServiceError::Failed(format!(
                "systemctl show {unit} timed out"
            )));
        }
        let props = parse_key_values(&output.stdout);
        Ok(parse_active_state(
            props.get("ActiveState").map(String::as_str),
        ))
    }

    /// The state of each unit in `units`, read with `systemctl show`.
    /// `judge` maps each read state to the reported state and detail.
    fn read_mount_states(
        &self,
        program: &'static str,
        units: &[String],
        judge: impl Fn(State) -> (State, String),
    ) -> Result<Vec<MountUnitState>, ServiceError> {
        units
            .iter()
            .map(|unit| {
                let (state, detail) = judge(self.mount_unit_state(program, unit)?);
                Ok(MountUnitState {
                    unit: unit.clone(),
                    state,
                    detail,
                })
            })
            .collect()
    }

    /// The `systemctl` program, once every name in `units` passed
    /// [`validate_mount_unit_name`].
    fn mount_program(&self, units: &[String]) -> Result<&'static str, ServiceError> {
        for unit in units {
            validate_mount_unit_name(unit)?;
        }
        self.program()
    }
}

/// A short detail for a `systemctl` call that did not succeed within
/// `timeout`.
fn failure_detail(
    verb: &str,
    output: &super::exec::ProcessOutput,
    timeout: std::time::Duration,
) -> String {
    if output.timed_out {
        format!(
            "systemctl {verb} timed out after {}s; the job goes on in systemd",
            timeout.as_secs()
        )
    } else {
        format!(
            "systemctl {verb} exited {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

/// The result of [`SystemdManager::resolve`].
enum Resolved {
    /// Resolved from the cache: only the unit name is known, not its
    /// current state.
    Cached(String),
    /// Resolved just now: the unit name and the `systemctl show` properties
    /// from the probe that found it, still fresh.
    Fresh(String, HashMap<String, String>),
}

impl Resolved {
    fn into_unit(self) -> String {
        match self {
            Self::Cached(unit) | Self::Fresh(unit, _) => unit,
        }
    }
}

impl Default for SystemdManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager for SystemdManager {
    fn status(&self, units: &UnitNames) -> Result<ServiceStatus, ServiceError> {
        let (unit, props) = match self.resolve(units)? {
            Resolved::Fresh(unit, props) => (unit, props),
            Resolved::Cached(unit) => {
                let program = self.program()?;
                let props = self.show(program, &unit)?;
                (unit, props)
            }
        };
        Ok(ServiceStatus {
            unit,
            state: parse_active_state(props.get("ActiveState").map(String::as_str)),
            enabled: parse_enabled(props.get("UnitFileState").map(String::as_str)),
            since: None,
        })
    }

    fn act(&self, units: &UnitNames, action: ServiceAction) -> Result<ActionOutcome, ServiceError> {
        let unit = self.resolve(units)?.into_unit();
        let program = self.program()?;
        let verb = action_verb(action);
        let args = vec![verb.to_owned(), unit.clone()];
        let output = self
            .runner
            .run(program, &args, ACTION_TIMEOUT)
            .map_err(|err| ServiceError::Failed(err.to_string()))?;
        let succeeded = !output.timed_out && output.status == Some(0);
        let active = succeeded && !matches!(action, ServiceAction::Stop);
        let detail = if succeeded {
            format!("systemctl {verb} {unit} succeeded")
        } else if output.timed_out {
            format!("systemctl {verb} {unit} timed out")
        } else {
            format!(
                "systemctl {verb} {unit} exited {:?}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        };
        Ok(ActionOutcome {
            unit,
            action,
            succeeded,
            active,
            detail,
        })
    }

    fn reload_unit_files(&self) -> Result<String, ServiceError> {
        let program = self.program()?;
        let output = self
            .runner
            .run(program, &["daemon-reload".to_owned()], ACTION_TIMEOUT)
            .map_err(|err| ServiceError::Failed(err.to_string()))?;
        if output.timed_out {
            Err(ServiceError::Failed(
                "systemctl daemon-reload timed out".to_owned(),
            ))
        } else if output.status == Some(0) {
            Ok("systemctl daemon-reload succeeded".to_owned())
        } else {
            Err(ServiceError::Failed(format!(
                "systemctl daemon-reload exited {:?}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    fn mount_unit_states(&self, units: &[String]) -> Result<Vec<MountUnitState>, ServiceError> {
        let program = self.mount_program(units)?;
        self.read_mount_states(program, units, |state| (state, String::new()))
    }

    fn start_mount_units(&self, units: &[String]) -> Result<Vec<MountUnitState>, ServiceError> {
        let program = self.mount_program(units)?;
        let output = self.run_on_units(program, "start", units, MOUNT_WAIT)?;
        let succeeded = !output.timed_out && output.status == Some(0);
        let detail = if succeeded {
            String::new()
        } else {
            failure_detail("start", &output, MOUNT_WAIT)
        };
        self.read_mount_states(program, units, |state| match state {
            State::Active => (State::Active, String::new()),
            // A job that has not finished yet goes on in systemd.
            State::Inactive | State::Activating if output.timed_out => {
                (State::Activating, detail.clone())
            }
            // The start job ended and the unit is not mounted: it failed,
            // or a dependency (the device) did.
            State::Inactive | State::Failed => (State::Failed, detail.clone()),
            other => (other, detail.clone()),
        })
    }

    fn stop_mount_units(&self, units: &[String]) -> Result<Vec<MountUnitState>, ServiceError> {
        let program = self.mount_program(units)?;
        let output = self.run_on_units(program, "stop", units, ACTION_TIMEOUT)?;
        let detail = if !output.timed_out && output.status == Some(0) {
            String::new()
        } else {
            failure_detail("stop", &output, ACTION_TIMEOUT)
        };
        self.read_mount_states(program, units, |state| (state, detail.clone()))
    }

    fn start_update(
        &self,
        binary: &std::path::Path,
        tag: &str,
    ) -> Result<UpdateStart, ServiceError> {
        if !is_release_tag(tag) {
            return Err(ServiceError::InvalidUnitName(tag.to_owned()));
        }
        let Some(binary) = binary.to_str().filter(|_| binary.is_absolute()) else {
            return Err(ServiceError::InvalidUnitName(binary.display().to_string()));
        };
        let program = exec::resolve_program(self.runner.as_ref(), SYSTEMD_RUN_CANDIDATES)
            .ok_or_else(|| {
                ServiceError::Unavailable("systemd-run was not found on this host".to_owned())
            })?;
        let output = self
            .runner
            .run(program, &update_unit_args(binary, tag), ACTION_TIMEOUT)
            .map_err(|err| ServiceError::Failed(err.to_string()))?;
        if !output.timed_out && output.status == Some(0) {
            return Ok(UpdateStart::Started(format!(
                "started {UPDATE_UNIT}.service for {tag}"
            )));
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        // systemd refuses a second transient unit with a name in use:
        // "Unit detent-update.service was already loaded or has a fragment
        // file." (older: "... already exists.").
        if !output.timed_out
            && stderr.contains(&format!("{UPDATE_UNIT}.service"))
            && stderr.contains("already")
        {
            return Ok(UpdateStart::AlreadyRunning);
        }
        Err(ServiceError::Failed(if output.timed_out {
            format!("systemd-run timed out after {}s", ACTION_TIMEOUT.as_secs())
        } else {
            format!("systemd-run exited {:?}: {}", output.status, stderr.trim())
        }))
    }
}

const fn action_verb(action: ServiceAction) -> &'static str {
    match action {
        ServiceAction::Restart => "restart",
        ServiceAction::Reload => "reload",
        ServiceAction::Start => "start",
        ServiceAction::Stop => "stop",
    }
}

fn parse_key_values(bytes: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = HashMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            out.insert(key.to_owned(), value.to_owned());
        }
    }
    out
}

fn parse_active_state(value: Option<&str>) -> State {
    match value {
        Some("active") => State::Active,
        Some("inactive") => State::Inactive,
        Some("failed") => State::Failed,
        Some("activating") => State::Activating,
        Some("deactivating") => State::Deactivating,
        _ => State::Unknown,
    }
}

fn parse_enabled(value: Option<&str>) -> Option<bool> {
    match value {
        Some("enabled" | "enabled-runtime" | "static" | "indirect" | "alias") => Some(true),
        Some("disabled" | "masked" | "linked") => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{SystemdManager, parse_active_state, parse_enabled, parse_key_values};
    use crate::service::State;

    #[test]
    fn debug_format_mentions_the_type_name() {
        assert!(format!("{:?}", SystemdManager::new()).contains("SystemdManager"));
    }

    #[test]
    fn default_constructs_without_panicking() {
        let _ = SystemdManager::default();
    }

    #[test]
    fn parses_key_value_lines() {
        let map = parse_key_values(b"LoadState=loaded\nActiveState=active\n");
        assert_eq!(map.get("LoadState").map(String::as_str), Some("loaded"));
        assert_eq!(map.get("ActiveState").map(String::as_str), Some("active"));
    }

    #[test]
    fn malformed_line_without_equals_is_skipped() {
        let map = parse_key_values(b"not-a-key-value-line\nActiveState=active\n");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn every_active_state_maps_to_the_right_variant() {
        assert_eq!(parse_active_state(Some("active")), State::Active);
        assert_eq!(parse_active_state(Some("inactive")), State::Inactive);
        assert_eq!(parse_active_state(Some("failed")), State::Failed);
        assert_eq!(parse_active_state(Some("activating")), State::Activating);
        assert_eq!(
            parse_active_state(Some("deactivating")),
            State::Deactivating
        );
        assert_eq!(parse_active_state(Some("garbage")), State::Unknown);
        assert_eq!(parse_active_state(None), State::Unknown);
    }

    #[test]
    fn enabled_states_map_to_some_true_or_false() {
        assert_eq!(parse_enabled(Some("enabled")), Some(true));
        assert_eq!(parse_enabled(Some("static")), Some(true));
        assert_eq!(parse_enabled(Some("disabled")), Some(false));
        assert_eq!(parse_enabled(Some("masked")), Some(false));
        assert_eq!(parse_enabled(Some("garbage")), None);
        assert_eq!(parse_enabled(None), None);
    }
}
