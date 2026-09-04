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
    ActionOutcome, AltCache, ServiceError, ServiceManager, ServiceStatus, State, validate_unit_name,
};

/// Absolute paths `systemctl` may live at, most common first.
const SYSTEMCTL_CANDIDATES: &[&str] = &["/usr/bin/systemctl", "/bin/systemctl"];

/// Properties requested from `systemctl show`. A fixed, compile-time
/// literal: no user input ever reaches this argv position.
const SHOW_PROPERTIES: &str =
    "--property=LoadState,ActiveState,SubState,UnitFileState,ActiveEnterTimestamp";

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
