//! Service manager abstraction: systemd, `OpenRC`, and launchd backends, plus
//! the process execution discipline they and [`checks::ExternalCheckRunner`]
//! share (PLAN §1.6, §2.3, §2.4; Phase 2 task 4).
//!
//! # Why `systemctl` instead of `zbus`
//!
//! systemd exposes a D-Bus API (`org.freedesktop.systemd1`) that `zbus`
//! could drive without spawning a process. This subtask uses the
//! `systemctl` binary instead, for three reasons:
//!
//! - The monitor (PLAN §2.4) is deliberately synchronous — "no tokio, no
//!   TLS, no HTTP" — and `zbus`'s async connection would pull an async
//!   runtime into a process that otherwise has none.
//! - `systemctl` also covers `OpenRC` containers and other hosts where the
//!   system bus is not running, without a second code path.
//! - It keeps the dependency surface smaller: PLAN §4.2 lists `zbus` behind
//!   the optional `init-systemd` feature, not as a base dependency.
//!
//! `zbus` remains a reasonable later optimization once the monitor's
//! synchronous-loop constraint is revisited; PLAN §4.2 already reserves the
//! feature flag for it.
//!
//! # Process execution discipline (PLAN §2.4)
//!
//! Every backend and [`checks::ExternalCheckRunner`] runs external commands
//! through [`exec::ProcessRunner`]: absolute program paths only, chosen from
//! a compile-time candidate list; argv assembled from fixed literals plus a
//! validated unit name or a monitor-owned temp-file path; environment
//! cleared except `LC_ALL=C`; stdout/stderr capped at [`exec::OUTPUT_CAP`]
//! bytes; and a wall-clock timeout after which the child is killed and
//! reaped. There is no shell anywhere in this module tree.
//!
//! # Unit-name alternatives
//!
//! [`detent_core::descriptor::UnitNames`] carries a list of alternatives per
//! init system because distributions disagree (`chronyd.service` on Fedora,
//! `chrony.service` on Debian). Each backend probes the alternatives in
//! order the first time it is asked about a given [`UnitNames`] value and
//! caches which one actually exists on this host (`AltCache`, private), so
//! repeat calls cost one process spawn instead of one per alternative.

pub mod checks;
pub mod exec;
mod launchd;
mod openrc;
mod systemd;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use detent_core::descriptor::{InitSystem, ServiceAction, ServiceBinding, UnitNames};

pub use launchd::LaunchdManager;
pub use openrc::OpenRcManager;
pub use systemd::{SystemdManager, update_unit_args};

use crate::privsep::monitor::{HookError, ServiceControl};
use crate::privsep::proto::{BindingId, ServiceOutcome};

/// Longest a unit name may be. Chosen generously above any real systemd or
/// `OpenRC` name; the actual gate is the charset check in
/// [`validate_unit_name`].
const MAX_UNIT_NAME_LEN: usize = 256;

/// Validates a unit/service name before it is ever used as a process
/// argument: `[A-Za-z0-9._@-]+`, no `/`, no `..`, bounded length.
///
/// Every backend calls this on each alternative before probing it, so an
/// invalid name never reaches [`exec::ProcessRunner::run`].
///
/// # Errors
///
/// [`ServiceError::InvalidUnitName`] when `name` fails the check.
pub fn validate_unit_name(name: &str) -> Result<(), ServiceError> {
    let valid_len = !name.is_empty() && name.len() <= MAX_UNIT_NAME_LEN;
    let valid_charset = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'));
    if valid_len && valid_charset && !name.contains("..") {
        Ok(())
    } else {
        Err(ServiceError::InvalidUnitName(name.to_owned()))
    }
}

/// How long [`ServiceManager::start_mount_units`] waits for the start jobs.
/// A job still running then (an unreachable network share) goes on in the
/// init system; its unit is reported as [`State::Activating`]. It runs
/// inside an apply request, after the check, the write and daemon-reload, so
/// it stays well below the web server's default request timeout (30 s).
pub const MOUNT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Validates a mount unit name before it is ever used as a process
/// argument: it ends in `.mount` or `.automount`, does not start with `-`,
/// and holds only what `systemd-escape --path` writes (`[A-Za-z0-9:_.\-]`).
///
/// # Errors
///
/// [`ServiceError::InvalidUnitName`] when `name` fails the check.
pub fn validate_mount_unit_name(name: &str) -> Result<(), ServiceError> {
    let stem = name
        .strip_suffix(".mount")
        .or_else(|| name.strip_suffix(".automount"));
    let valid = name.len() <= MAX_UNIT_NAME_LEN
        && stem.is_some_and(|stem| !stem.is_empty() && !stem.starts_with('-'))
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '\\' | '-'));
    if valid {
        Ok(())
    } else {
        Err(ServiceError::InvalidUnitName(name.to_owned()))
    }
}

/// The transient unit [`ServiceManager::start_update`] runs the CLI
/// updater in (`detent-update.service`).
pub const UPDATE_UNIT: &str = "detent-update";

/// What every backend but systemd answers for [`ServiceManager::start_update`].
const UPDATE_NEEDS_SYSTEMD: &str = "starting an update from the web or MCP needs systemd; run `detent update --tag <tag>` on the host";

/// What [`ServiceManager::start_update`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateStart {
    /// The unit runs; a short detail.
    Started(String),
    /// A unit named [`UPDATE_UNIT`] is already there: an update runs.
    AlreadyRunning,
}

/// One mount unit and its state, as a [`ServiceManager`] found or left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountUnitState {
    /// The unit name.
    pub unit: String,
    /// Its state after the call.
    pub state: State,
    /// A short detail: the init system's message for a failure, or empty.
    pub detail: String,
}

/// What every backend but systemd answers for mount units.
const MOUNT_UNITS_NEED_SYSTEMD: &str = "mount units need systemd; on this init system the new fstab entries take effect at the next mount or boot";

/// The run state of a service, as reported by [`ServiceManager::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Running.
    Active,
    /// Not running, not failed.
    Inactive,
    /// Exited with an error, or crashed.
    Failed,
    /// Transitioning to active.
    Activating,
    /// Transitioning to inactive.
    Deactivating,
    /// State could not be determined from the backend's output.
    Unknown,
}

/// How `serde` renders a [`SystemTime`]: two integers, not an RFC 3339
/// string.
///
/// It exists only so the `openapi` feature has something accurate to point
/// [`ServiceStatus::since`] at — `utoipa` has no schema for [`SystemTime`],
/// and describing it as a string would misdescribe the bytes clients receive.
/// Nothing constructs one.
#[cfg(feature = "openapi")]
#[derive(Debug, utoipa::ToSchema)]
pub struct SystemTimeView {
    /// Whole seconds since the Unix epoch.
    pub secs_since_epoch: u64,
    /// Nanoseconds within that second.
    pub nanos_since_epoch: u32,
}

/// The result of a [`ServiceManager::status`] call.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServiceStatus {
    /// The unit name actually resolved and queried, i.e. the alternative
    /// from [`UnitNames`] that exists on this host.
    pub unit: String,
    /// Current run state.
    pub state: State,
    /// Whether the unit starts automatically at boot, when the backend can
    /// determine it.
    pub enabled: Option<bool>,
    /// When the unit entered its current state, when the backend can
    /// determine it.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<SystemTimeView>))]
    pub since: Option<SystemTime>,
}

/// The result of a [`ServiceManager::act`] call.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ActionOutcome {
    /// The unit name actually resolved and acted on.
    pub unit: String,
    /// The action that was applied.
    pub action: ServiceAction,
    /// True when the backend reported the action succeeded (process exit 0,
    /// no timeout).
    pub succeeded: bool,
    /// Best-effort expectation of whether the unit is active after the
    /// action, derived from `action` and `succeeded` rather than a second
    /// query: a successful `Stop` is not active, every other successful
    /// action is. Callers needing a verified post-action state should call
    /// [`ServiceManager::status`] separately.
    pub active: bool,
    /// A short human-readable detail string.
    pub detail: String,
}

/// What may go wrong operating a service.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServiceError {
    /// None of a [`UnitNames`] alternatives resolved on this host.
    #[error("no known unit name resolved on this host (tried {tried:?})")]
    NoKnownUnit {
        /// Every alternative that was tried, in order.
        tried: Vec<String>,
    },
    /// A unit/service name failed [`validate_unit_name`] before any process
    /// was spawned.
    #[error("invalid unit name: {0:?}")]
    InvalidUnitName(String),
    /// This backend does not support the requested operation.
    #[error("{0}")]
    Unsupported(String),
    /// No backend program (e.g. `systemctl`) is present on this host.
    #[error("{0}")]
    Unavailable(String),
    /// The backend program ran but reported failure, or could not be run.
    #[error("{0}")]
    Failed(String),
}

impl From<ServiceError> for HookError {
    fn from(err: ServiceError) -> Self {
        match err {
            ServiceError::NoKnownUnit { .. }
            | ServiceError::InvalidUnitName(_)
            | ServiceError::Unsupported(_)
            | ServiceError::Unavailable(_) => Self::Unavailable(err.to_string()),
            ServiceError::Failed(message) => Self::Failed(message),
        }
    }
}

/// Drives one host's service manager: query status, and start/stop/restart/
/// reload a unit.
pub trait ServiceManager: Send + Sync {
    /// Resolves `units` against this backend and reports the resulting
    /// state.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NoKnownUnit`] when no alternative exists on this
    /// host, [`ServiceError::Unavailable`] when no backend program is
    /// present, [`ServiceError::Failed`] when the backend ran but the query
    /// itself failed.
    fn status(&self, units: &UnitNames) -> Result<ServiceStatus, ServiceError>;

    /// Applies `action` to the unit `units` resolves to.
    ///
    /// # Errors
    ///
    /// Same as [`ServiceManager::status`], plus [`ServiceError::Unsupported`]
    /// on backends (launchd) that do not implement mutation.
    fn act(&self, units: &UnitNames, action: ServiceAction) -> Result<ActionOutcome, ServiceError>;

    /// Asks the init system to re-read its unit files, for a module whose
    /// descriptor sets `reload_unit_files` (`mounts`: `/etc/fstab`).
    ///
    /// systemd runs `systemctl daemon-reload`, so its generators (e.g.
    /// `systemd-fstab-generator`) run again. Every other init system has no
    /// generated units: its backend runs nothing and says so in the detail.
    /// Returns a short detail string.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Unavailable`] when the backend program is absent,
    /// [`ServiceError::Failed`] when it ran and did not exit 0 (or timed
    /// out). Unlike [`ServiceManager::act`], a failure is an error, not an
    /// outcome: there is no unit whose state could be reported instead.
    fn reload_unit_files(&self) -> Result<String, ServiceError>;

    /// The state of each mount unit in `units`, in order. Acts on nothing.
    ///
    /// # Errors
    ///
    /// [`ServiceError::InvalidUnitName`] before any process runs when a name
    /// fails [`validate_mount_unit_name`]; [`ServiceError::Unsupported`] on
    /// every backend but systemd; [`ServiceError::Unavailable`] and
    /// [`ServiceError::Failed`] as for [`ServiceManager::status`].
    fn mount_unit_states(&self, _units: &[String]) -> Result<Vec<MountUnitState>, ServiceError> {
        Err(ServiceError::Unsupported(
            MOUNT_UNITS_NEED_SYSTEMD.to_owned(),
        ))
    }

    /// Starts the mount units in `units`, waits at most [`MOUNT_WAIT`] for
    /// their jobs, and reports each unit's state then: [`State::Active`]
    /// (mounted), [`State::Activating`] (still pending), or
    /// [`State::Failed`] with the init system's message.
    ///
    /// # Errors
    ///
    /// As [`ServiceManager::mount_unit_states`].
    fn start_mount_units(&self, _units: &[String]) -> Result<Vec<MountUnitState>, ServiceError> {
        Err(ServiceError::Unsupported(
            MOUNT_UNITS_NEED_SYSTEMD.to_owned(),
        ))
    }

    /// Stops the mount units in `units` and reports each unit's state then.
    ///
    /// # Errors
    ///
    /// As [`ServiceManager::mount_unit_states`].
    fn stop_mount_units(&self, _units: &[String]) -> Result<Vec<MountUnitState>, ServiceError> {
        Err(ServiceError::Unsupported(
            MOUNT_UNITS_NEED_SYSTEMD.to_owned(),
        ))
    }

    /// Starts `binary update --tag <tag>` in the transient unit
    /// [`UPDATE_UNIT`], outside detent's own service, so the updater lives
    /// through the service restart it does. Returns once the unit runs; it
    /// does not wait for the update.
    ///
    /// # Errors
    ///
    /// [`ServiceError::InvalidUnitName`] before any process runs when `tag`
    /// fails [`is_release_tag`](crate::privsep::proto::is_release_tag) or
    /// `binary` is not an absolute UTF-8 path; [`ServiceError::Unsupported`]
    /// on every backend but systemd; [`ServiceError::Unavailable`] when
    /// `systemd-run` is absent; [`ServiceError::Failed`] when it failed.
    fn start_update(
        &self,
        _binary: &std::path::Path,
        _tag: &str,
    ) -> Result<UpdateStart, ServiceError> {
        Err(ServiceError::Unsupported(UPDATE_NEEDS_SYSTEMD.to_owned()))
    }
}

/// The installed detent binary, from [`std::env::current_exe`]'s answer
/// `exe`: an absolute path. After the file was replaced under a running
/// process, Linux names the old inode `<path> (deleted)`; the suffix is
/// removed, because the path now holds the newer installed binary.
///
/// # Errors
///
/// [`ServiceError::Failed`] when `exe` is an error or not absolute.
pub fn installed_binary(
    exe: std::io::Result<std::path::PathBuf>,
) -> Result<std::path::PathBuf, ServiceError> {
    let exe = exe.map_err(|err| {
        ServiceError::Failed(format!("the installed binary cannot be found: {err}"))
    })?;
    let exe = match exe
        .to_str()
        .and_then(|path| path.strip_suffix(" (deleted)"))
    {
        Some(path) => std::path::PathBuf::from(path),
        None => exe,
    };
    if exe.is_absolute() {
        Ok(exe)
    } else {
        Err(ServiceError::Failed(
            "the installed binary path is not absolute".to_owned(),
        ))
    }
}

/// A [`ServiceManager`] for hosts with no supported init system.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullManager;

impl ServiceManager for NullManager {
    fn status(&self, _units: &UnitNames) -> Result<ServiceStatus, ServiceError> {
        Err(ServiceError::Unsupported(
            "no supported service manager was detected on this host".to_owned(),
        ))
    }

    fn act(
        &self,
        _units: &UnitNames,
        _action: ServiceAction,
    ) -> Result<ActionOutcome, ServiceError> {
        Err(ServiceError::Unsupported(
            "no supported service manager was detected on this host".to_owned(),
        ))
    }

    fn reload_unit_files(&self) -> Result<String, ServiceError> {
        Ok("no init system was detected: no unit files to reload".to_owned())
    }
}

/// Selects a [`ServiceManager`] for `init`, reusing host detection
/// (`detent_platform::host::detect`) rather than re-probing which init
/// system is present.
///
/// Deviation from the task brief: the brief names `HostFacts` as the
/// parameter, but [`crate::host::HostFacts`] does not carry the detected
/// init system — `HostProfile::init` (`detent_core::descriptor`) does, and
/// `HostFacts` has no equivalent field at all. Taking [`InitSystem`]
/// directly is the minimal way to "reuse this detection, do not re-detect"
/// without importing a struct this function does not otherwise need.
#[must_use]
pub fn for_host(init: InitSystem) -> Box<dyn ServiceManager> {
    match init {
        InitSystem::Systemd => Box::new(SystemdManager::new()),
        InitSystem::OpenRc => Box::new(OpenRcManager::new()),
        InitSystem::Launchd => Box::new(LaunchdManager::new()),
        InitSystem::None => Box::new(NullManager),
    }
}

/// Adapts any [`ServiceManager`] to the monitor's [`ServiceControl`] hook,
/// so [`for_host`]'s result can be used as `Hooks::services`
/// (`crate::privsep::monitor::Hooks`) instead of the default `NoServices`.
///
/// A newtype rather than `impl ServiceControl for dyn ServiceManager`:
/// Rust does not coerce `&dyn ServiceManager` to `&dyn ServiceControl` just
/// because a manual `impl` connects the two traits (that coercion is only
/// automatic for an actual supertrait relationship, i.e. "trait upcasting"),
/// so a plain blanket impl on the trait object type is unusable at the
/// call site that needs it. Wrapping the manager in a concrete struct sidesteps
/// that: `&ServiceControlAdapter` coerces to `&dyn ServiceControl` the
/// ordinary way, same as any other concrete type implementing a trait.
pub struct ServiceControlAdapter(pub Box<dyn ServiceManager>);

impl ServiceControl for ServiceControlAdapter {
    fn service(
        &self,
        binding: &ServiceBinding,
        action: ServiceAction,
    ) -> Result<ServiceOutcome, HookError> {
        let outcome = self.0.act(&binding.units, action)?;
        Ok(ServiceOutcome {
            binding: BindingId(0),
            active: outcome.active,
            detail: outcome.detail,
        })
    }

    fn reload_unit_files(&self) -> Result<String, HookError> {
        self.0.reload_unit_files().map_err(HookError::from)
    }

    fn mount_unit_states(&self, units: &[String]) -> Result<Vec<MountUnitState>, HookError> {
        self.0.mount_unit_states(units).map_err(HookError::from)
    }

    fn start_mount_units(&self, units: &[String]) -> Result<Vec<MountUnitState>, HookError> {
        self.0.start_mount_units(units).map_err(HookError::from)
    }

    fn stop_mount_units(&self, units: &[String]) -> Result<Vec<MountUnitState>, HookError> {
        self.0.stop_mount_units(units).map_err(HookError::from)
    }

    /// The binary is this process's own executable ([`installed_binary`]),
    /// never a path from the socket.
    fn start_update(&self, tag: &str) -> Result<UpdateStart, HookError> {
        let binary = installed_binary(std::env::current_exe())?;
        self.0.start_update(&binary, tag).map_err(HookError::from)
    }
}

/// Caches which alternative of a `&'static [&'static str]` list resolved to
/// an existing unit/service, keyed by the list's own address. Every such
/// list lives in a `'static` [`UnitNames`] value, so its address is stable
/// for the process lifetime and distinct per declaration — this avoids
/// requiring [`UnitNames`] itself to be `Hash`.
#[derive(Debug, Default)]
struct AltCache(Mutex<HashMap<usize, String>>);

impl AltCache {
    fn get(&self, alts: &'static [&'static str]) -> Option<String> {
        let key = alts.as_ptr() as usize;
        self.0.lock().ok()?.get(&key).cloned()
    }

    fn set(&self, alts: &'static [&'static str], resolved: &str) {
        let key = alts.as_ptr() as usize;
        if let Ok(mut cache) = self.0.lock() {
            cache.insert(key, resolved.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActionOutcome, NullManager, ServiceControlAdapter, ServiceError, ServiceManager,
        ServiceStatus, UpdateStart, for_host, installed_binary, validate_unit_name,
    };
    use detent_core::descriptor::{InitSystem, ServiceAction, ServiceBinding, UnitNames};

    #[test]
    fn null_manager_reports_unsupported_for_status_and_act() {
        let units = UnitNames {
            systemd: &[],
            openrc: &[],
            bsdrc: &[],
        };
        assert!(matches!(
            NullManager.status(&units),
            Err(ServiceError::Unsupported(_))
        ));
        assert!(matches!(
            NullManager.act(&units, ServiceAction::Restart),
            Err(ServiceError::Unsupported(_))
        ));
    }

    #[test]
    fn null_manager_has_no_unit_files_to_reload() {
        assert!(matches!(
            NullManager.reload_unit_files(),
            Ok(detail) if detail.contains("no init system")
        ));
    }

    #[test]
    fn for_host_selects_a_backend_per_init_system() {
        // Per-backend behavior is covered in each backend's own tests and
        // in tests/service_manager.rs; this only confirms `for_host`
        // dispatches to the right constructor for every `InitSystem`
        // variant, including the `None` (`NullManager`) arm.
        let _ = for_host(InitSystem::Systemd);
        let _ = for_host(InitSystem::OpenRc);
        let _ = for_host(InitSystem::Launchd);
        let none = for_host(InitSystem::None);
        let units = UnitNames {
            systemd: &[],
            openrc: &[],
            bsdrc: &[],
        };
        assert!(matches!(
            none.status(&units),
            Err(ServiceError::Unsupported(_))
        ));
    }

    #[test]
    fn valid_names_are_accepted() {
        assert!(validate_unit_name("chronyd.service").is_ok());
        assert!(validate_unit_name("chrony@1.service").is_ok());
        assert!(validate_unit_name("a").is_ok());
        assert!(validate_unit_name(&"a".repeat(256)).is_ok());
    }

    #[test]
    fn empty_name_is_rejected() {
        assert!(matches!(
            validate_unit_name(""),
            Err(ServiceError::InvalidUnitName(_))
        ));
    }

    #[test]
    fn overlong_name_is_rejected() {
        assert!(matches!(
            validate_unit_name(&"a".repeat(257)),
            Err(ServiceError::InvalidUnitName(_))
        ));
    }

    #[test]
    fn path_traversal_is_rejected() {
        assert!(matches!(
            validate_unit_name("../evil"),
            Err(ServiceError::InvalidUnitName(_))
        ));
    }

    #[test]
    fn embedded_slash_is_rejected() {
        assert!(matches!(
            validate_unit_name("a/b"),
            Err(ServiceError::InvalidUnitName(_))
        ));
    }

    #[test]
    fn whitespace_is_rejected() {
        assert!(matches!(
            validate_unit_name("a b"),
            Err(ServiceError::InvalidUnitName(_))
        ));
    }

    #[test]
    fn shell_metacharacters_are_rejected() {
        for name in [";rm -rf /", "$(reboot)", "a;b", "a`b`"] {
            assert!(
                matches!(
                    validate_unit_name(name),
                    Err(ServiceError::InvalidUnitName(_))
                ),
                "expected {name:?} to be rejected"
            );
        }
    }

    #[test]
    fn embedded_newline_is_rejected() {
        assert!(matches!(
            validate_unit_name("a\nb"),
            Err(ServiceError::InvalidUnitName(_))
        ));
    }

    #[test]
    fn service_error_maps_to_hook_error() {
        use crate::privsep::monitor::HookError;
        let unavailable: HookError = ServiceError::Unavailable("no systemctl".to_owned()).into();
        assert!(matches!(unavailable, HookError::Unavailable(_)));
        let failed: HookError = ServiceError::Failed("boom".to_owned()).into();
        assert!(matches!(failed, HookError::Failed(_)));
        let no_known: HookError = ServiceError::NoKnownUnit {
            tried: vec!["a".to_owned()],
        }
        .into();
        assert!(matches!(no_known, HookError::Unavailable(_)));
        let invalid: HookError = ServiceError::InvalidUnitName("x/y".to_owned()).into();
        assert!(matches!(invalid, HookError::Unavailable(_)));
        let unsupported: HookError = ServiceError::Unsupported("no".to_owned()).into();
        assert!(matches!(unsupported, HookError::Unavailable(_)));
    }

    /// A stub `ServiceManager` whose `status` is never exercised by the
    /// adapter tests below (the adapter only ever calls `act`); it still
    /// returns a well-formed `Err` rather than an `unimplemented!()` panic,
    /// matching this crate's "no panics in test bodies either" convention.
    struct AlwaysActive;
    impl ServiceManager for AlwaysActive {
        fn status(&self, _units: &UnitNames) -> Result<ServiceStatus, ServiceError> {
            Err(ServiceError::Unsupported(
                "not exercised by this test".to_owned(),
            ))
        }

        fn act(
            &self,
            units: &UnitNames,
            action: ServiceAction,
        ) -> Result<ActionOutcome, ServiceError> {
            Ok(ActionOutcome {
                unit: units
                    .systemd
                    .first()
                    .copied()
                    .unwrap_or_default()
                    .to_owned(),
                action,
                succeeded: true,
                active: true,
                detail: "delegated".to_owned(),
            })
        }

        fn reload_unit_files(&self) -> Result<String, ServiceError> {
            Ok("reloaded".to_owned())
        }
    }

    #[test]
    fn service_control_adapter_delegates_to_the_wrapped_manager() {
        use crate::privsep::monitor::ServiceControl;
        let binding = ServiceBinding {
            units: UnitNames {
                systemd: &["chronyd.service"],
                openrc: &[],
                bsdrc: &[],
            },
            actions: &[ServiceAction::Restart],
        };
        let adapter = ServiceControlAdapter(Box::new(AlwaysActive));
        let result = adapter.service(&binding, ServiceAction::Restart);
        assert!(result.is_ok());
        if let Ok(outcome) = result {
            assert!(outcome.active);
            assert_eq!(outcome.detail, "delegated");
        }
        // `AlwaysActive::status` is never reached through the adapter (which
        // only ever calls `act`); call it directly so its documented stub
        // body is itself covered rather than merely declared.
        assert!(matches!(
            AlwaysActive.status(&binding.units),
            Err(ServiceError::Unsupported(_))
        ));
    }

    #[test]
    fn service_control_adapter_forwards_a_unit_files_reload() {
        use crate::privsep::monitor::{NoServices, ServiceControl};
        let adapter = ServiceControlAdapter(Box::new(AlwaysActive));
        assert_eq!(adapter.reload_unit_files(), Ok("reloaded".to_owned()));
        assert!(matches!(
            NoServices.reload_unit_files(),
            Err(crate::privsep::monitor::HookError::Unavailable(_))
        ));
    }

    /// Answers `start_update` with the binary and the tag it was given.
    struct UpdateEcho;

    impl ServiceManager for UpdateEcho {
        fn status(&self, _units: &UnitNames) -> Result<ServiceStatus, ServiceError> {
            Err(ServiceError::Unsupported("not used".to_owned()))
        }

        fn act(
            &self,
            _units: &UnitNames,
            _action: ServiceAction,
        ) -> Result<ActionOutcome, ServiceError> {
            Err(ServiceError::Unsupported("not used".to_owned()))
        }

        fn reload_unit_files(&self) -> Result<String, ServiceError> {
            Err(ServiceError::Unsupported("not used".to_owned()))
        }

        fn start_update(
            &self,
            binary: &std::path::Path,
            tag: &str,
        ) -> Result<UpdateStart, ServiceError> {
            Ok(UpdateStart::Started(format!("{} {tag}", binary.display())))
        }
    }

    #[test]
    fn the_adapter_starts_the_update_with_this_process_executable()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::privsep::monitor::ServiceControl;
        let adapter = ServiceControlAdapter(Box::new(UpdateEcho));
        assert_eq!(
            adapter.start_update("v1.2.3"),
            Ok(UpdateStart::Started(format!(
                "{} v1.2.3",
                std::env::current_exe()?.display()
            )))
        );
        let units = UnitNames {
            systemd: &[],
            openrc: &[],
            bsdrc: &[],
        };
        assert!(adapter.0.status(&units).is_err());
        assert!(adapter.0.act(&units, ServiceAction::Restart).is_err());
        assert!(adapter.0.reload_unit_files().is_err());
        Ok(())
    }

    #[test]
    fn only_systemd_can_start_an_update() {
        use crate::privsep::monitor::{HookError, ServiceControl};
        let null = ServiceControlAdapter(Box::new(NullManager));
        assert!(matches!(
            null.start_update("v1.2.3"),
            Err(HookError::Unavailable(message)) if message.contains("needs systemd")
        ));
    }

    #[test]
    fn the_installed_binary_is_absolute_and_loses_the_deleted_suffix() {
        use std::path::PathBuf;
        assert_eq!(
            installed_binary(Ok(PathBuf::from("/usr/local/bin/detent"))),
            Ok(PathBuf::from("/usr/local/bin/detent"))
        );
        assert_eq!(
            installed_binary(Ok(PathBuf::from("/usr/local/bin/detent (deleted)"))),
            Ok(PathBuf::from("/usr/local/bin/detent"))
        );
        assert!(matches!(
            installed_binary(Ok(PathBuf::from("detent"))),
            Err(ServiceError::Failed(_))
        ));
        assert!(matches!(
            installed_binary(Err(std::io::Error::from(std::io::ErrorKind::NotFound))),
            Err(ServiceError::Failed(_))
        ));
    }

    #[test]
    fn service_control_adapter_propagates_errors_from_the_wrapped_manager() {
        use crate::privsep::monitor::ServiceControl;
        let binding = ServiceBinding {
            units: UnitNames {
                systemd: &[],
                openrc: &[],
                bsdrc: &[],
            },
            actions: &[ServiceAction::Restart],
        };
        let adapter = ServiceControlAdapter(Box::new(NullManager));
        assert!(adapter.service(&binding, ServiceAction::Restart).is_err());
    }
}
