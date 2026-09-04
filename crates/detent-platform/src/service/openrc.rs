//! `rc-service`-backed [`ServiceManager`] for `OpenRC` hosts (PLAN §1.6).
//!
//! `enabled` and `since` (`ServiceStatus`) are always `None` in v1:
//! `OpenRC` exposes enablement via `rc-update show`, a separate
//! multi-service listing this module does not parse, and `rc-service`'s
//! plain-text `status` output carries no wall-clock "entered this state"
//! timestamp analogous to systemd's `ActiveEnterTimestamp`. Both fields are
//! left `None` rather than guessed.
//!
//! Assumption flagged for verification against a real `OpenRC` host: the
//! secondary candidate `/usr/sbin/service` is assumed to accept the same
//! `<name> <command>` / `-e <name>` argv shape as `/sbin/rc-service`. This
//! module was developed and unit-tested against a fake process runner on
//! macOS; it has not been exercised against a real `rc-service` binary.

use detent_core::descriptor::{ServiceAction, UnitNames};

use super::exec::{self, ACTION_TIMEOUT, ProcessRunner, RealProcessRunner, STATUS_TIMEOUT};
use super::{
    ActionOutcome, AltCache, ServiceError, ServiceManager, ServiceStatus, State, validate_unit_name,
};

/// Absolute paths that dispatch `OpenRC` service commands, most common
/// first.
const OPENRC_CANDIDATES: &[&str] = &["/sbin/rc-service", "/usr/sbin/service"];

/// Drives `OpenRC` via `rc-service` (or the `service` wrapper).
pub struct OpenRcManager {
    runner: Box<dyn ProcessRunner>,
    cache: AltCache,
}

impl std::fmt::Debug for OpenRcManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpenRcManager { .. }")
    }
}

impl OpenRcManager {
    /// Builds a manager backed by the real `rc-service` binary.
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
        exec::resolve_program(self.runner.as_ref(), OPENRC_CANDIDATES).ok_or_else(|| {
            ServiceError::Unavailable("rc-service was not found on this host".to_owned())
        })
    }

    fn exists(&self, program: &'static str, name: &str) -> Result<bool, ServiceError> {
        let args = vec!["-e".to_owned(), name.to_owned()];
        let output = self
            .runner
            .run(program, &args, STATUS_TIMEOUT)
            .map_err(|err| ServiceError::Failed(err.to_string()))?;
        Ok(!output.timed_out && output.status == Some(0))
    }

    fn resolve(&self, units: &UnitNames) -> Result<String, ServiceError> {
        if let Some(hit) = self.cache.get(units.openrc) {
            return Ok(hit);
        }
        let program = self.program()?;
        let mut tried = Vec::new();
        for alt in units.openrc {
            validate_unit_name(alt)?;
            tried.push((*alt).to_owned());
            if self.exists(program, alt)? {
                self.cache.set(units.openrc, alt);
                return Ok((*alt).to_owned());
            }
        }
        Err(ServiceError::NoKnownUnit { tried })
    }
}

impl Default for OpenRcManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager for OpenRcManager {
    fn status(&self, units: &UnitNames) -> Result<ServiceStatus, ServiceError> {
        let program = self.program()?;
        let unit = self.resolve(units)?;
        let args = vec![unit.clone(), "status".to_owned()];
        let output = self
            .runner
            .run(program, &args, STATUS_TIMEOUT)
            .map_err(|err| ServiceError::Failed(err.to_string()))?;
        let state = if output.timed_out {
            State::Unknown
        } else {
            parse_status_text(&output.stdout)
        };
        Ok(ServiceStatus {
            unit,
            state,
            enabled: None,
            since: None,
        })
    }

    fn act(&self, units: &UnitNames, action: ServiceAction) -> Result<ActionOutcome, ServiceError> {
        let program = self.program()?;
        let unit = self.resolve(units)?;
        let verb = action_verb(action);
        let args = vec![unit.clone(), verb.to_owned()];
        let output = self
            .runner
            .run(program, &args, ACTION_TIMEOUT)
            .map_err(|err| ServiceError::Failed(err.to_string()))?;
        let succeeded = !output.timed_out && output.status == Some(0);
        let active = succeeded && !matches!(action, ServiceAction::Stop);
        let detail = if succeeded {
            format!("rc-service {unit} {verb} succeeded")
        } else if output.timed_out {
            format!("rc-service {unit} {verb} timed out")
        } else {
            format!(
                "rc-service {unit} {verb} exited {:?}: {}",
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

fn parse_status_text(bytes: &[u8]) -> State {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    if text.contains("started") {
        State::Active
    } else if text.contains("stopping") {
        State::Deactivating
    } else if text.contains("starting") {
        State::Activating
    } else if text.contains("crashed") {
        State::Failed
    } else if text.contains("stopped") {
        State::Inactive
    } else {
        State::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::{OpenRcManager, parse_status_text};
    use crate::service::State;

    #[test]
    fn debug_format_mentions_the_type_name() {
        assert!(format!("{:?}", OpenRcManager::new()).contains("OpenRcManager"));
    }

    #[test]
    fn default_constructs_without_panicking() {
        let _ = OpenRcManager::default();
    }

    #[test]
    fn recognises_every_status_keyword() {
        assert_eq!(parse_status_text(b" * status:  started"), State::Active);
        assert_eq!(parse_status_text(b" * status:  stopped"), State::Inactive);
        assert_eq!(parse_status_text(b" * status:  crashed"), State::Failed);
        assert_eq!(
            parse_status_text(b" * status:  starting"),
            State::Activating
        );
        assert_eq!(
            parse_status_text(b" * status:  stopping"),
            State::Deactivating
        );
        assert_eq!(parse_status_text(b"garbage output"), State::Unknown);
    }
}
