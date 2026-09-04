//! `launchctl`-backed [`ServiceManager`] for macOS (PLAN §1.6: macOS is a
//! dev/host platform — build, test, core, CLI, and web only, no service
//! management promised).
//!
//! `act` always returns [`ServiceError::Unsupported`] without spawning any
//! process, per the task brief: v1 is status-only on macOS.
//!
//! Known gap, flagged rather than silently worked around:
//! [`UnitNames`](detent_core::descriptor::UnitNames) has `systemd`, `openrc`,
//! and `bsdrc` fields but no `launchd` field, so there is no dedicated list
//! of launchd labels (which conventionally look like `org.chrony.chronyd`,
//! not `chronyd.service`) to probe. `status` reuses `units.systemd` as a
//! best-effort candidate list until `UnitNames` gains a proper field —
//! `detent-core::descriptor` is out of scope for this subtask.

use detent_core::descriptor::{ServiceAction, UnitNames};

use super::exec::{self, ProcessRunner, RealProcessRunner, STATUS_TIMEOUT};
use super::{
    ActionOutcome, AltCache, ServiceError, ServiceManager, ServiceStatus, State, validate_unit_name,
};

/// Absolute paths `launchctl` may live at.
const LAUNCHCTL_CANDIDATES: &[&str] = &["/bin/launchctl"];

/// Status-only launchd backend.
pub struct LaunchdManager {
    runner: Box<dyn ProcessRunner>,
    cache: AltCache,
}

impl std::fmt::Debug for LaunchdManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LaunchdManager { .. }")
    }
}

impl LaunchdManager {
    /// Builds a manager backed by the real `launchctl` binary.
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
        exec::resolve_program(self.runner.as_ref(), LAUNCHCTL_CANDIDATES).ok_or_else(|| {
            ServiceError::Unavailable("launchctl was not found on this host".to_owned())
        })
    }

    fn list(
        &self,
        program: &'static str,
        label: &str,
    ) -> Result<exec::ProcessOutput, ServiceError> {
        let args = vec!["list".to_owned(), label.to_owned()];
        self.runner
            .run(program, &args, STATUS_TIMEOUT)
            .map_err(|err| ServiceError::Failed(err.to_string()))
    }

    /// Resolves `units.systemd` (see the module docs for why) to the first
    /// label `launchctl list` reports as loaded, caching the answer. A
    /// cache miss's successful probe already carries the `launchctl list`
    /// output for that label, which [`ServiceManager::status`] reuses
    /// instead of listing it again immediately after.
    fn resolve(
        &self,
        units: &UnitNames,
    ) -> Result<(String, Option<exec::ProcessOutput>), ServiceError> {
        if let Some(hit) = self.cache.get(units.systemd) {
            return Ok((hit, None));
        }
        let program = self.program()?;
        let mut tried = Vec::new();
        for label in units.systemd {
            validate_unit_name(label)?;
            tried.push((*label).to_owned());
            let output = self.list(program, label)?;
            if !output.timed_out && output.status == Some(0) {
                self.cache.set(units.systemd, label);
                return Ok(((*label).to_owned(), Some(output)));
            }
        }
        Err(ServiceError::NoKnownUnit { tried })
    }
}

impl Default for LaunchdManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager for LaunchdManager {
    fn status(&self, units: &UnitNames) -> Result<ServiceStatus, ServiceError> {
        let (label, output) = match self.resolve(units)? {
            (label, Some(output)) => (label, output),
            (label, None) => {
                let program = self.program()?;
                let output = self.list(program, &label)?;
                (label, output)
            }
        };
        let active = !output.timed_out
            && output.status == Some(0)
            && String::from_utf8_lossy(&output.stdout).contains("\"PID\"");
        Ok(ServiceStatus {
            unit: label,
            state: if active {
                State::Active
            } else {
                State::Inactive
            },
            enabled: None,
            since: None,
        })
    }

    fn act(
        &self,
        _units: &UnitNames,
        _action: ServiceAction,
    ) -> Result<ActionOutcome, ServiceError> {
        Err(ServiceError::Unsupported(
            "detent does not manage services on macOS: it is a dev/host platform only (PLAN §1.6)"
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::LaunchdManager;

    #[test]
    fn debug_format_mentions_the_type_name() {
        assert!(format!("{:?}", LaunchdManager::new()).contains("LaunchdManager"));
    }

    #[test]
    fn default_constructs_without_panicking() {
        let _ = LaunchdManager::default();
    }
}
