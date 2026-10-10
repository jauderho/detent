//! The runner: an unconfined helper that runs validators and service
//! commands for the monitor (STAGE3 H6).
//!
//! A seccomp filter is inherited by every child and can never be removed, so
//! a program the confined monitor starts itself runs under the monitor's
//! filter: `uname`, `getuid`, `socket` and the rest of what real validators
//! and `systemctl` need kill it with `SIGSYS`. The runner is forked *before*
//! the monitor confines itself ([`spawn_runner`](super::spawn::spawn_runner)),
//! so its children run with the host's normal environment.
//!
//! ```text
//!   serve ──fork──▶ runner (root, not confined)
//!     │                ▲ RunnerRequest { check id | binding id + action | status | reload }
//!     └──fork──▶ worker│
//!   monitor (confined) ┘ RunnerResponse
//! ```
//!
//! The runner is the more privileged process, so it trusts the monitor no
//! more than it must. It takes only ids into its own copy of the allow-list
//! and the file name of a candidate: never a path, a program or an argument.
//! It works out the candidate's directory itself, from the check's module
//! ([`Allowlist::candidate_dir`]: beside the module's primary target, or the
//! staging directory when the module has no file target), and beside a
//! target it accepts only a [`CANDIDATE_PREFIX`] file, in a directory that
//! passes the monitor's own trust check (owned by root or the runner's euid,
//! no group or other write bit, not a symlink). A compromised monitor
//! can run only the declared validators on such files, the declared
//! service actions, a read of the state of an allow-listed binding's unit
//! (`systemctl show` with a fixed property list), a unit-file reload when an
//! enabled module declares `reload_unit_files`, and, with `[mounts]
//! activate_new_entries`, the start of the mount units the runner works out
//! itself from an allow-listed target and a stop of only the units it recorded
//! ([`mounts`](super::mounts)), and the start of the CLI updater for a
//! valid release tag in the transient unit `detent-update` (the argv is
//! fixed here, the binary is the runner's own executable; the updater
//! still applies the release policy and verifies the release) — nothing it
//! could not already ask for through the protocol.

use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use detent_core::descriptor::{
    ExternalCheck, HostProfile, ServiceAction as CoreServiceAction, ServiceBinding,
};
use serde::{Deserialize, Serialize};

use super::allowlist::{Allowlist, CANDIDATE_PREFIX};
use super::monitor::{
    CheckRunner, DirOwner, HookError, Hooks, ServiceControl, require_trusted_dir,
};
use super::mounts;
use super::proto::{
    BindingId, CheckId, CheckOutcome, MountOutcome, ServiceAction, ServiceOutcome, TargetId,
    UnitStatus, is_release_tag,
};
use super::transport::{Channel, ChannelError};
use crate::service::UpdateStart;

/// How long either side waits on the runner channel. Longer than any single
/// validator or service action (`service::exec::ACTION_TIMEOUT`) plus the
/// status queries that resolve a unit first.
pub const RUNNER_TIMEOUT: Duration = Duration::from_secs(120);

/// What the monitor asks of the runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunnerRequest {
    /// Run allow-listed check `check` on the candidate file `candidate`.
    Check {
        /// Index into the allow-list's check table.
        check: CheckId,
        /// File name (one path component) inside the check's candidate
        /// directory, which the runner derives itself.
        candidate: String,
    },
    /// Apply `action` to allow-listed binding `binding`.
    Service {
        /// Index into the allow-list's binding table.
        binding: BindingId,
        /// The action; it must be one the binding declares.
        action: ServiceAction,
    },
    /// Ask the init system to re-read its unit files. Allowed only when an
    /// enabled module declares `reload_unit_files`.
    ReloadUnitFiles,
    /// Start the mount units of the entries an apply added to allow-listed
    /// target `target`. Allowed only with `[mounts] activate_new_entries`;
    /// the runner works the units out itself
    /// ([`mounts`](super::mounts)).
    StartAddedMounts {
        /// Index into the allow-list's target table.
        target: TargetId,
    },
    /// Stop the mount units the last start recorded (a rollback).
    StopStartedMounts,
    /// Forget the mount units the last start recorded (a confirm).
    ForgetStartedMounts,
    /// Start the CLI updater for release `tag` in the transient unit
    /// `detent-update` (BUGFIX E16). The runner checks the tag again
    /// ([`is_release_tag`]) and uses its own executable as the binary.
    StartUpdate {
        /// Release tag, e.g. `v1.2.3`.
        tag: String,
    },
    /// Read the state of the unit allow-listed binding `binding` names. The
    /// unit comes from the runner's own allow-list, and any binding is
    /// allowed, because the read changes nothing. Appended last, as the
    /// protocol's enums are.
    ServiceStatus {
        /// Index into the allow-list's binding table.
        binding: BindingId,
    },
}

/// The runner's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunnerResponse {
    /// The check ran.
    Checked(CheckOutcome),
    /// The service action ran.
    Serviced(ServiceOutcome),
    /// The unit files were reloaded; a short detail.
    Reloaded(String),
    /// What a mount start or stop did, one entry per unit.
    Mounts(Vec<MountOutcome>),
    /// The record of started mount units is gone.
    Forgotten,
    /// The subsystem is absent on this host.
    Unavailable(String),
    /// The request was refused or the subsystem failed.
    Failed(String),
    /// The update unit runs; a short detail.
    UpdateStarted(String),
    /// The update unit was already there.
    UpdateRunning,
    /// The state of the unit a [`RunnerRequest::ServiceStatus`] named.
    UnitStatus(UnitStatus),
}

/// Answer requests on `channel` with `hooks` until the monitor goes away.
///
/// Every id is looked up in `allow`; a candidate must be a regular file
/// directly inside the check's candidate directory for `profile` (the
/// monitor's own profile), or inside `staging_dir` when its module has no
/// file target.
pub fn serve_runner(
    allow: &Allowlist,
    staging_dir: &Path,
    profile: &HostProfile,
    hooks: &Hooks<'_>,
    channel: &mut Channel,
) {
    loop {
        let request = match channel.recv::<RunnerRequest>() {
            Ok(request) => request,
            // Idle between requests: keep waiting.
            Err(ChannelError::Timeout) => continue,
            // Closed, or a peer speaking nonsense: stop.
            Err(_) => return,
        };
        let response = answer(allow, staging_dir, profile, hooks, request);
        if channel.send(&response).is_err() {
            return;
        }
    }
}

fn answer(
    allow: &Allowlist,
    staging_dir: &Path,
    profile: &HostProfile,
    hooks: &Hooks<'_>,
    request: RunnerRequest,
) -> RunnerResponse {
    let outcome = match request {
        RunnerRequest::Check { check, candidate } => {
            let Some(entry) = allow.check(check) else {
                return RunnerResponse::Failed("unknown check".to_owned());
            };
            // The same directory the monitor wrote to, worked out here
            // from the check's module, not taken from the monitor. Beside
            // real configuration only a candidate-named file in a directory
            // that passes the monitor's own trust check is accepted. When
            // that directory was read-only for the monitor, the candidate
            // is in staging instead, under the same name rules.
            let path = match allow.candidate_dir(entry.module, profile) {
                Some(dir)
                    if candidate.starts_with(CANDIDATE_PREFIX)
                        && require_trusted_dir(
                            dir,
                            "candidate directory",
                            DirOwner::EuidOrRoot,
                        )
                        .is_ok() =>
                {
                    staged_candidate(dir, &candidate)
                        .or_else(|| staged_candidate(staging_dir, &candidate))
                }
                Some(_) => None,
                None => staged_candidate(staging_dir, &candidate),
            };
            let Some(path) = path else {
                return RunnerResponse::Failed("candidate is not a staged file".to_owned());
            };
            hooks
                .checks
                .run_check(entry.check, &path)
                .map(RunnerResponse::Checked)
        }
        RunnerRequest::Service { binding, action } => {
            let Some(entry) = allow.binding(binding) else {
                return RunnerResponse::Failed("unknown service binding".to_owned());
            };
            let Some(core) = action
                .to_core()
                .filter(|core| entry.binding.actions.contains(core))
            else {
                return RunnerResponse::Failed(
                    "service action is not allowed for this binding".to_owned(),
                );
            };
            hooks
                .services
                .service(entry.binding, core)
                .map(RunnerResponse::Serviced)
        }
        RunnerRequest::ReloadUnitFiles => {
            if !allow.reloads_unit_files() {
                return RunnerResponse::Failed("no enabled module reloads unit files".to_owned());
            }
            hooks
                .services
                .reload_unit_files()
                .map(RunnerResponse::Reloaded)
        }
        RunnerRequest::StartAddedMounts { target } => match mounts::record_dir(staging_dir) {
            Some(dir) => {
                mounts::start_added(allow, dir, hooks.services, target).map(RunnerResponse::Mounts)
            }
            None => Err(no_record_dir()),
        },
        RunnerRequest::StopStartedMounts => match mounts::record_dir(staging_dir) {
            Some(dir) => {
                mounts::stop_started(allow, dir, hooks.services).map(RunnerResponse::Mounts)
            }
            None => Err(no_record_dir()),
        },
        RunnerRequest::ForgetStartedMounts => match mounts::record_dir(staging_dir) {
            Some(dir) => mounts::forget_started(dir).map(|()| RunnerResponse::Forgotten),
            None => Err(no_record_dir()),
        },
        RunnerRequest::StartUpdate { tag } => {
            if !is_release_tag(&tag) {
                return RunnerResponse::Failed("not a release tag".to_owned());
            }
            hooks
                .services
                .start_update(&tag)
                .map(|started| match started {
                    UpdateStart::Started(detail) => RunnerResponse::UpdateStarted(detail),
                    UpdateStart::AlreadyRunning => RunnerResponse::UpdateRunning,
                })
        }
        RunnerRequest::ServiceStatus { binding } => {
            let Some(entry) = allow.binding(binding) else {
                return RunnerResponse::Failed("unknown service binding".to_owned());
            };
            hooks
                .services
                .service_status(entry.binding)
                .map(RunnerResponse::UnitStatus)
        }
    };
    outcome.unwrap_or_else(|err| match err {
        HookError::Unavailable(message) => RunnerResponse::Unavailable(message),
        HookError::Failed(message) => RunnerResponse::Failed(message),
    })
}

/// The staging directory has no parent to keep the mount record in.
fn no_record_dir() -> HookError {
    HookError::Failed("the staging directory has no parent for the mount record".to_owned())
}

/// `dir/name` when `name` is one plain path component and names a regular
/// file there (not a symlink).
fn staged_candidate(dir: &Path, name: &str) -> Option<PathBuf> {
    let mut parts = Path::new(name).components();
    if !matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(_)), None)
    ) {
        return None;
    }
    let path = dir.join(name);
    std::fs::symlink_metadata(&path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .map(|_| path)
}

/// The monitor's side: a [`CheckRunner`] and [`ServiceControl`] that forward
/// each call to the runner by id.
///
/// Any channel failure leaves the runner's state unknown (a late answer
/// would pair with the next request), so the client stops using the channel
/// and every later call is [`HookError::Unavailable`]: apply fails closed.
pub struct RunnerClient {
    channel: Mutex<Option<Channel>>,
    checks: Vec<(&'static ExternalCheck, CheckId)>,
    bindings: Vec<(&'static ServiceBinding, BindingId)>,
}

impl std::fmt::Debug for RunnerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerClient")
            .field("checks", &self.checks.len())
            .field("bindings", &self.bindings.len())
            .finish_non_exhaustive()
    }
}

impl RunnerClient {
    /// A client on `channel` for the checks and bindings in `allow`.
    #[must_use]
    pub fn new(channel: Channel, allow: &Allowlist) -> Self {
        let checks = (0..allow.check_count())
            .filter_map(|index| u16::try_from(index).ok())
            .filter_map(|index| allow.check(CheckId(index)))
            .map(|entry| (entry.check, entry.id))
            .collect();
        let bindings = (0..allow.binding_count())
            .filter_map(|index| u16::try_from(index).ok())
            .filter_map(|index| allow.binding(BindingId(index)))
            .map(|entry| (entry.binding, entry.id))
            .collect();
        Self {
            channel: Mutex::new(Some(channel)),
            checks,
            bindings,
        }
    }

    fn call(&self, request: &RunnerRequest) -> Result<RunnerResponse, HookError> {
        let gone = || HookError::Unavailable("the runner is not available".to_owned());
        let mut guard = self.channel.lock().map_err(|_| gone())?;
        let answer = match guard.as_mut() {
            Some(channel) => channel
                .send(request)
                .and_then(|()| channel.recv::<RunnerResponse>()),
            None => return Err(gone()),
        };
        answer.map_err(|err| {
            *guard = None;
            HookError::Unavailable(format!("the runner stopped answering: {err}"))
        })
    }
}

/// The hook result a runner answer stands for; `expect` names the variant
/// that carries a success.
fn hook_result<T>(
    response: RunnerResponse,
    expect: impl FnOnce(RunnerResponse) -> Option<T>,
) -> Result<T, HookError> {
    match response {
        RunnerResponse::Unavailable(message) => Err(HookError::Unavailable(message)),
        RunnerResponse::Failed(message) => Err(HookError::Failed(message)),
        other => {
            expect(other).ok_or_else(|| HookError::Failed("unexpected runner answer".to_owned()))
        }
    }
}

impl CheckRunner for RunnerClient {
    fn run_check(
        &self,
        check: &ExternalCheck,
        candidate: &Path,
    ) -> Result<CheckOutcome, HookError> {
        let Some(&(_, id)) = self
            .checks
            .iter()
            .find(|(known, _)| std::ptr::eq(*known, check))
        else {
            return Err(HookError::Failed(
                "check is not in the allow-list".to_owned(),
            ));
        };
        let Some(name) = candidate.file_name().and_then(|name| name.to_str()) else {
            return Err(HookError::Failed("candidate has no file name".to_owned()));
        };
        let response = self.call(&RunnerRequest::Check {
            check: id,
            candidate: name.to_owned(),
        })?;
        hook_result(response, |response| match response {
            RunnerResponse::Checked(outcome) => Some(outcome),
            _ => None,
        })
    }
}

impl ServiceControl for RunnerClient {
    fn service(
        &self,
        binding: &ServiceBinding,
        action: CoreServiceAction,
    ) -> Result<ServiceOutcome, HookError> {
        let Some(&(_, id)) = self
            .bindings
            .iter()
            .find(|(known, _)| std::ptr::eq(*known, binding))
        else {
            return Err(HookError::Failed(
                "service binding is not in the allow-list".to_owned(),
            ));
        };
        let response = self.call(&RunnerRequest::Service {
            binding: id,
            action: action.into(),
        })?;
        hook_result(response, |response| match response {
            RunnerResponse::Serviced(outcome) => Some(outcome),
            _ => None,
        })
    }

    fn service_status(&self, binding: &ServiceBinding) -> Result<UnitStatus, HookError> {
        let Some(&(_, id)) = self
            .bindings
            .iter()
            .find(|(known, _)| std::ptr::eq(*known, binding))
        else {
            return Err(HookError::Failed(
                "service binding is not in the allow-list".to_owned(),
            ));
        };
        let response = self.call(&RunnerRequest::ServiceStatus { binding: id })?;
        hook_result(response, |response| match response {
            RunnerResponse::UnitStatus(status) => Some(status),
            _ => None,
        })
    }

    fn reload_unit_files(&self) -> Result<String, HookError> {
        let response = self.call(&RunnerRequest::ReloadUnitFiles)?;
        hook_result(response, |response| match response {
            RunnerResponse::Reloaded(detail) => Some(detail),
            _ => None,
        })
    }

    fn start_added_mounts(&self, target: TargetId) -> Result<Vec<MountOutcome>, HookError> {
        let response = self.call(&RunnerRequest::StartAddedMounts { target })?;
        hook_result(response, |response| match response {
            RunnerResponse::Mounts(outcomes) => Some(outcomes),
            _ => None,
        })
    }

    fn stop_started_mounts(&self) -> Result<Vec<MountOutcome>, HookError> {
        let response = self.call(&RunnerRequest::StopStartedMounts)?;
        hook_result(response, |response| match response {
            RunnerResponse::Mounts(outcomes) => Some(outcomes),
            _ => None,
        })
    }

    fn forget_started_mounts(&self) -> Result<(), HookError> {
        let response = self.call(&RunnerRequest::ForgetStartedMounts)?;
        hook_result(response, |response| match response {
            RunnerResponse::Forgotten => Some(()),
            _ => None,
        })
    }

    fn start_update(&self, tag: &str) -> Result<UpdateStart, HookError> {
        let response = self.call(&RunnerRequest::StartUpdate {
            tag: tag.to_owned(),
        })?;
        hook_result(response, |response| match response {
            RunnerResponse::UpdateStarted(detail) => Some(UpdateStart::Started(detail)),
            RunnerResponse::UpdateRunning => Some(UpdateStart::AlreadyRunning),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use detent_core::descriptor::{
        ArgTemplate, CheckExpectation, ExternalCheck, HostProfile, ModuleDescriptor, Owner,
        PathSpec, ServiceAction as CoreServiceAction, ServiceBinding, Target, TargetKind,
        UnitNames, Upstream,
    };
    use detent_core::diag::MessageId;

    use super::{RunnerClient, RunnerRequest, RunnerResponse, answer, serve_runner};
    use crate::fs::atomic::{WriteRequest, write_atomic};
    use crate::privsep::allowlist::{Allowlist, Config};
    use crate::privsep::monitor::{CheckRunner, HookError, Hooks, ServiceControl};
    use crate::privsep::proto::{BindingId, CheckId, CheckOutcome, ServiceAction, ServiceOutcome};
    use crate::privsep::proto::{MountState, TargetId, UnitState, UnitStatus};
    use crate::privsep::transport::Channel;
    use crate::service::{MountUnitState, State, UpdateStart};
    use detent_core::descriptor::MountUnit;

    type R = Result<(), Box<dyn std::error::Error>>;

    const fn always(_: &HostProfile) -> bool {
        true
    }

    static CHECKS: &[ExternalCheck] = &[ExternalCheck {
        program: PathSpec::new("/bin/true"),
        args: &[ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
    }];
    static SERVICES: &[ServiceBinding] = &[ServiceBinding {
        units: UnitNames {
            systemd: &["fake.service"],
            openrc: &[],
            bsdrc: &[],
        },
        actions: &[CoreServiceAction::Restart],
    }];
    /// Its only target is a drop-in directory, so its candidates are staged.
    static MODULE: ModuleDescriptor = ModuleDescriptor {
        id: "fake",
        display_name_id: MessageId::new("fake-name"),
        targets: &[Target {
            path: PathSpec::new("/etc/hosts.d"),
            kind: TargetKind::DropInDir,
            mode: 0o644,
            owner: Owner::Root,
            backend_detect: always,
        }],
        upstream: Upstream {
            project: "test",
            repo_url: "https://example.invalid/test",
            tracked_version: "1.0",
            release_feed: None,
            docs: &[],
        },
        services: SERVICES,
        checks: CHECKS,
        commit_confirm: false,
        reload_unit_files: false,
        added_mounts: None,
        security_notes: &[],
    };
    /// Equal in value to `CHECKS[0]` but not the allow-listed declaration.
    static STRANGER: ExternalCheck = ExternalCheck {
        program: PathSpec::new("/bin/true"),
        args: &[ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
    };

    /// Echoes the candidate path; a candidate whose contents name a hook
    /// error returns that error instead.
    struct Fake;

    impl CheckRunner for Fake {
        fn run_check(
            &self,
            _check: &ExternalCheck,
            candidate: &Path,
        ) -> Result<CheckOutcome, HookError> {
            match std::fs::read_to_string(candidate)
                .unwrap_or_default()
                .as_str()
            {
                "unavailable" => Err(HookError::Unavailable("no validator".to_owned())),
                "failed" => Err(HookError::Failed("validator crashed".to_owned())),
                _ => Ok(CheckOutcome {
                    check: CheckId(0),
                    passed: true,
                    exit_code: Some(0),
                    detail: candidate.display().to_string(),
                }),
            }
        }
    }

    impl ServiceControl for Fake {
        fn service(
            &self,
            _binding: &ServiceBinding,
            action: CoreServiceAction,
        ) -> Result<ServiceOutcome, HookError> {
            Ok(ServiceOutcome {
                binding: BindingId(0),
                active: true,
                detail: format!("{action:?}"),
            })
        }

        /// The unit of the binding it is given, so a test sees which one the
        /// runner chose; `fake.service` is the fixture's only unit.
        fn service_status(&self, binding: &ServiceBinding) -> Result<UnitStatus, HookError> {
            Ok(UnitStatus {
                unit: binding
                    .units
                    .systemd
                    .first()
                    .copied()
                    .unwrap_or_default()
                    .to_owned(),
                state: UnitState::Active,
                enabled: None,
                since: None,
            })
        }

        fn reload_unit_files(&self) -> Result<String, HookError> {
            Ok("reloaded".to_owned())
        }

        fn mount_unit_states(&self, units: &[String]) -> Result<Vec<MountUnitState>, HookError> {
            Ok(unit_states(units, State::Inactive))
        }

        fn start_mount_units(&self, units: &[String]) -> Result<Vec<MountUnitState>, HookError> {
            Ok(unit_states(units, State::Active))
        }

        fn stop_mount_units(&self, units: &[String]) -> Result<Vec<MountUnitState>, HookError> {
            Ok(unit_states(units, State::Inactive))
        }

        /// `v98.0.0` is already running; `v97.0.0` fails; the rest start.
        fn start_update(&self, tag: &str) -> Result<UpdateStart, HookError> {
            match tag {
                "v98.0.0" => Ok(UpdateStart::AlreadyRunning),
                "v97.0.0" => Err(HookError::Failed("systemd-run exited 1".to_owned())),
                _ => Ok(UpdateStart::Started(format!("started {tag}"))),
            }
        }
    }

    fn unit_states(units: &[String], state: State) -> Vec<MountUnitState> {
        units
            .iter()
            .map(|unit| MountUnitState {
                unit: unit.clone(),
                state,
                detail: String::new(),
            })
            .collect()
    }

    fn one_mount(_previous: &str, _current: &str) -> Vec<MountUnit> {
        vec![MountUnit {
            mountpoint: "/srv/x".to_owned(),
            unit: "srv-x.mount".to_owned(),
        }]
    }

    static FILED_CHECKS: &[ExternalCheck] = &[ExternalCheck {
        program: PathSpec::new("/bin/true"),
        args: &[ArgTemplate::TempFile],
        expects: CheckExpectation::ExitZero,
    }];

    /// The id of [`FILED_CHECKS`]' check in the fixture's allow-list.
    const FILED_CHECK: CheckId = CheckId(1);

    const fn never(_: &HostProfile) -> bool {
        false
    }

    /// A module with two file targets, `first/first.conf` (never detected)
    /// and `second/second.conf` (always), under `root`.
    fn filed_module(root: &Path) -> &'static ModuleDescriptor {
        let target = |name: &str, backend_detect: fn(&HostProfile) -> bool| Target {
            path: PathSpec::new(Box::leak(
                root.join(name).display().to_string().into_boxed_str(),
            )),
            kind: TargetKind::File,
            mode: 0o644,
            owner: Owner::Root,
            backend_detect,
        };
        let targets = Box::leak(Box::new([
            target("first/first.conf", never),
            target("second/second.conf", always),
        ]));
        Box::leak(Box::new(ModuleDescriptor {
            id: "filed",
            targets,
            services: &[],
            checks: FILED_CHECKS,
            reload_unit_files: true,
            ..MODULE
        }))
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        staging: std::path::PathBuf,
        /// The directory of `filed`'s undetected first target.
        first: std::path::PathBuf,
        /// The directory of `filed`'s primary target.
        second: std::path::PathBuf,
        allow: Allowlist,
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let dir = tempfile::TempDir::new()?;
        let staging = dir.path().join("staging");
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        for made in [&staging, &first, &second] {
            std::fs::create_dir_all(made)?;
            // Trusted target directories whatever the umask.
            std::fs::set_permissions(
                made,
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
            )?;
        }
        let allow = Allowlist::from_modules(
            &[&MODULE, filed_module(dir.path())],
            &Config::with_state_root(dir.path().join("s")),
        )?;
        Ok(Fixture {
            _dir: dir,
            staging,
            first,
            second,
            allow,
        })
    }

    fn profile() -> HostProfile {
        HostProfile::default_for_tests()
    }

    /// Run `test` against a client whose runner serves [`Fake`] on a thread.
    fn with_runner(fx: &Fixture, test: impl FnOnce(&RunnerClient) -> R) -> R {
        let (monitor_end, mut runner_end) = Channel::pair()?;
        let allow = fx.allow.clone();
        let staging = fx.staging.clone();
        let runner = std::thread::spawn(move || {
            let hooks = Hooks {
                checks: &Fake,
                services: &Fake,
            };
            serve_runner(&allow, &staging, &profile(), &hooks, &mut runner_end);
        });
        let client = RunnerClient::new(monitor_end, &fx.allow);
        let result = test(&client);
        drop(client);
        runner.join().map_err(|_| "runner thread panicked")?;
        result
    }

    fn check() -> Result<&'static ExternalCheck, &'static str> {
        CHECKS.first().ok_or("the fixture declares a check")
    }

    fn binding() -> Result<&'static ServiceBinding, &'static str> {
        SERVICES.first().ok_or("the fixture declares a binding")
    }

    #[test]
    fn a_check_runs_on_the_staged_candidate_by_id() -> R {
        let fx = fixture()?;
        let candidate = fx.staging.join("detent-validate-1");
        std::fs::write(&candidate, b"text")?;
        with_runner(&fx, |client| {
            let outcome = client.run_check(check()?, &candidate)?;
            assert!(outcome.passed);
            assert_eq!(outcome.detail, candidate.display().to_string());
            assert!(format!("{client:?}").contains("RunnerClient"));
            Ok(())
        })
    }

    #[test]
    fn a_service_action_is_forwarded_by_id() -> R {
        let fx = fixture()?;
        with_runner(&fx, |client| {
            let outcome = client.service(binding()?, CoreServiceAction::Restart)?;
            assert_eq!(outcome.detail, "Restart");
            Ok(())
        })
    }

    #[test]
    fn a_service_status_is_forwarded_by_id_and_names_the_allow_listed_unit() -> R {
        let fx = fixture()?;
        with_runner(&fx, |client| {
            let status = client.service_status(binding()?)?;
            assert_eq!(status.unit, "fake.service");
            assert_eq!(status.state, UnitState::Active);
            Ok(())
        })
    }

    /// A status read takes a binding id and nothing else: the runner refuses
    /// an id outside its allow-list and never names a unit of its own accord.
    #[test]
    fn the_runner_refuses_a_status_for_a_binding_outside_the_allow_list() -> R {
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &Fake,
            services: &Fake,
        };
        for binding in [BindingId(1), BindingId(9)] {
            let response = answer(
                &fx.allow,
                &fx.staging,
                &profile(),
                &hooks,
                RunnerRequest::ServiceStatus { binding },
            );
            assert!(
                matches!(response, RunnerResponse::Failed(_)),
                "{binding:?} answered {response:?}"
            );
        }
        let response = answer(
            &fx.allow,
            &fx.staging,
            &profile(),
            &hooks,
            RunnerRequest::ServiceStatus {
                binding: BindingId(0),
            },
        );
        assert!(
            matches!(response, RunnerResponse::UnitStatus(ref status) if status.unit == "fake.service"),
            "answered {response:?}"
        );
        Ok(())
    }

    #[test]
    fn a_unit_files_reload_is_forwarded() -> R {
        let fx = fixture()?;
        with_runner(&fx, |client| {
            assert_eq!(client.reload_unit_files()?, "reloaded");
            Ok(())
        })
    }

    /// With no enabled module that declares `reload_unit_files`, the runner
    /// refuses the reload: a compromised monitor gains nothing new.
    #[test]
    fn the_runner_refuses_a_reload_no_module_declares() -> R {
        let dir = tempfile::TempDir::new()?;
        let allow = Allowlist::from_modules(&[&MODULE], &Config::with_state_root(dir.path()))?;
        let hooks = Hooks {
            checks: &Fake,
            services: &Fake,
        };
        let response = answer(
            &allow,
            dir.path(),
            &profile(),
            &hooks,
            RunnerRequest::ReloadUnitFiles,
        );
        assert!(
            matches!(response, RunnerResponse::Failed(_)),
            "answered {response:?}"
        );
        Ok(())
    }

    #[test]
    fn hook_errors_keep_their_kind_across_the_runner() -> R {
        let fx = fixture()?;
        let unavailable = fx.staging.join("a");
        let failed = fx.staging.join("b");
        std::fs::write(&unavailable, b"unavailable")?;
        std::fs::write(&failed, b"failed")?;
        with_runner(&fx, |client| {
            assert!(matches!(
                client.run_check(check()?, &unavailable),
                Err(HookError::Unavailable(_))
            ));
            assert!(matches!(
                client.run_check(check()?, &failed),
                Err(HookError::Failed(_))
            ));
            Ok(())
        })
    }

    #[test]
    fn the_client_sends_only_allow_listed_declarations() -> R {
        let fx = fixture()?;
        let stranger_binding = ServiceBinding {
            units: UnitNames {
                systemd: &["fake.service"],
                openrc: &[],
                bsdrc: &[],
            },
            actions: &[CoreServiceAction::Restart],
        };
        with_runner(&fx, |client| {
            assert!(matches!(
                client.run_check(&STRANGER, &fx.staging.join("x")),
                Err(HookError::Failed(_))
            ));
            assert!(matches!(
                client.run_check(check()?, Path::new("/")),
                Err(HookError::Failed(_))
            ));
            assert!(matches!(
                client.service(&stranger_binding, CoreServiceAction::Restart),
                Err(HookError::Failed(_))
            ));
            assert!(matches!(
                client.service_status(&stranger_binding),
                Err(HookError::Failed(_))
            ));
            Ok(())
        })
    }

    /// The primary target of `filed` in a fixture whose `filed` declares
    /// mounts, with activation on and one backup.
    const MOUNTED_TARGET: TargetId = TargetId(2);

    fn mounted_fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let fx = fixture()?;
        let root = fx.staging.parent().ok_or("staging has a parent")?;
        let filed = Box::leak(Box::new(ModuleDescriptor {
            added_mounts: Some(one_mount),
            ..*filed_module(root)
        }));
        let allow = Allowlist::from_modules(
            &[&MODULE, filed],
            &Config {
                activate_mounts: true,
                ..Config::with_state_root(root.join("s"))
            },
        )?;
        let target = allow.target(MOUNTED_TARGET).ok_or("target")?;
        std::fs::write(&target.path, b"before")?;
        write_atomic(&WriteRequest {
            create_missing: true,
            ..WriteRequest::new(&target.path, b"after", &target.backup_dir)
        })?;
        Ok(Fixture { allow, ..fx })
    }

    #[test]
    fn added_mounts_start_stop_and_forget_through_the_runner() -> R {
        let fx = mounted_fixture()?;
        with_runner(&fx, |client| {
            let started = client.start_added_mounts(MOUNTED_TARGET)?;
            assert_eq!(
                started
                    .iter()
                    .map(|o| (o.unit.as_str(), o.state))
                    .collect::<Vec<_>>(),
                vec![("srv-x.mount", MountState::Mounted)]
            );
            let stopped = client.stop_started_mounts()?;
            assert_eq!(
                stopped.iter().map(|o| o.state).collect::<Vec<_>>(),
                vec![MountState::Stopped]
            );
            client.start_added_mounts(MOUNTED_TARGET)?;
            client.forget_started_mounts()?;
            assert!(client.stop_started_mounts()?.is_empty());
            Ok(())
        })
    }

    #[test]
    fn the_runner_refuses_to_start_mounts_when_activation_is_off() -> R {
        let fx = fixture()?;
        with_runner(&fx, |client| {
            assert!(matches!(
                client.start_added_mounts(MOUNTED_TARGET),
                Err(HookError::Failed(_))
            ));
            Ok(())
        })
    }

    /// The monitor puts the candidate in its staging directory when the
    /// target directory is read-only for it (`ProtectSystem=strict`). The
    /// runner looks there itself when the trusted target directory lacks the
    /// name; a name without the candidate prefix is refused in either.
    #[test]
    fn the_runner_finds_a_candidate_in_staging_when_the_target_directory_lacks_it() -> R {
        let fx = fixture()?;
        let staged = fx.staging.join(".detent-candidate-staged");
        std::fs::write(&staged, b"x")?;
        std::fs::write(fx.staging.join("plain"), b"x")?;
        std::fs::write(fx.second.join("plain"), b"x")?;
        let hooks = Hooks {
            checks: &Fake,
            services: &Fake,
        };
        let ask = |name: &str| {
            answer(
                &fx.allow,
                &fx.staging,
                &profile(),
                &hooks,
                filed_check(name),
            )
        };
        let response = ask(".detent-candidate-staged");
        assert!(
            matches!(&response, RunnerResponse::Checked(outcome) if outcome.detail == staged.display().to_string()),
            "answered {response:?}"
        );
        for name in ["plain", ".detent-candidate-missing"] {
            let response = ask(name);
            assert!(
                matches!(response, RunnerResponse::Failed(_)),
                "{name} answered {response:?}"
            );
        }
        // An untrusted target directory is still refused: no staging lookup.
        std::fs::set_permissions(
            &fx.second,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o775),
        )?;
        let response = ask(".detent-candidate-staged");
        assert!(
            matches!(response, RunnerResponse::Failed(_)),
            "answered {response:?}"
        );
        Ok(())
    }

    /// The runner refuses what the monitor cannot legitimately ask for.
    #[test]
    fn the_runner_refuses_anything_outside_the_allow_list() -> R {
        let fx = fixture()?;
        std::fs::write(fx.staging.join("real"), b"x")?;
        std::fs::create_dir(fx.staging.join("dir"))?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(fx.staging.join("real"), fx.staging.join("link"))?;
        let hooks = Hooks {
            checks: &Fake,
            services: &Fake,
        };
        let check = |name: &str| RunnerRequest::Check {
            check: CheckId(0),
            candidate: name.to_owned(),
        };
        let refused = [
            check("../real"),
            check("dir/real"),
            check(""),
            check("missing"),
            check("dir"),
            check("link"),
            check("/etc/hosts"),
            RunnerRequest::Check {
                check: CheckId(9),
                candidate: "real".to_owned(),
            },
            RunnerRequest::Service {
                binding: BindingId(9),
                action: ServiceAction::Restart,
            },
            RunnerRequest::Service {
                binding: BindingId(0),
                action: ServiceAction::Stop,
            },
            RunnerRequest::Service {
                binding: BindingId(0),
                action: ServiceAction::Status,
            },
        ];
        for request in refused {
            let response = answer(&fx.allow, &fx.staging, &profile(), &hooks, request.clone());
            assert!(
                matches!(response, RunnerResponse::Failed(_)),
                "{request:?} answered {response:?}"
            );
        }
        assert!(matches!(
            answer(&fx.allow, &fx.staging, &profile(), &hooks, check("real")),
            RunnerResponse::Checked(_)
        ));
        Ok(())
    }

    fn filed_check(name: &str) -> RunnerRequest {
        RunnerRequest::Check {
            check: FILED_CHECK,
            candidate: name.to_owned(),
        }
    }

    /// A module with a file target has its candidate beside its primary
    /// target: the runner resolves the directory itself, from the check id.
    #[test]
    fn the_runner_finds_a_candidate_beside_the_primary_target() -> R {
        let fx = fixture()?;
        let candidate = fx.second.join(".detent-candidate-x");
        std::fs::write(&candidate, b"x")?;
        let hooks = Hooks {
            checks: &Fake,
            services: &Fake,
        };
        let response = answer(
            &fx.allow,
            &fx.staging,
            &profile(),
            &hooks,
            filed_check(".detent-candidate-x"),
        );
        assert!(
            matches!(&response, RunnerResponse::Checked(outcome) if outcome.detail == candidate.display().to_string()),
            "answered {response:?}"
        );
        Ok(())
    }

    /// In a target directory the runner takes only a regular
    /// `.detent-candidate-` file: never the real configuration beside it,
    /// a symlink, or a file in the wrong directory.
    #[test]
    fn the_runner_refuses_anything_but_a_candidate_in_a_target_directory() -> R {
        let fx = fixture()?;
        std::fs::write(fx.second.join("second.conf"), b"real")?;
        std::fs::write(fx.second.join("x"), b"x")?;
        std::fs::write(fx.staging.join(".detent-candidate-staged"), b"x")?;
        std::fs::write(fx.first.join(".detent-candidate-first"), b"x")?;
        std::fs::write(fx.second.join(".detent-candidate-real"), b"x")?;
        std::os::unix::fs::symlink(
            fx.second.join(".detent-candidate-real"),
            fx.second.join(".detent-candidate-link"),
        )?;
        std::os::unix::fs::symlink(
            fx.second.join("second.conf"),
            fx.second.join(".detent-candidate-conf"),
        )?;
        std::fs::create_dir(fx.second.join(".detent-candidate-dir"))?;
        let hooks = Hooks {
            checks: &Fake,
            services: &Fake,
        };
        for name in [
            "second.conf",
            "x",
            ".detent-candidate-first",
            ".detent-candidate-link",
            ".detent-candidate-conf",
            ".detent-candidate-dir",
            ".detent-candidate-missing",
            "../second/.detent-candidate-real",
        ] {
            let response = answer(
                &fx.allow,
                &fx.staging,
                &profile(),
                &hooks,
                filed_check(name),
            );
            assert!(
                matches!(response, RunnerResponse::Failed(_)),
                "{name} answered {response:?}"
            );
        }
        Ok(())
    }

    /// Defense in depth: the runner applies the monitor's target-directory
    /// check itself, so a candidate in a directory others can write to is
    /// never handed to a validator.
    #[test]
    fn the_runner_refuses_a_candidate_in_a_group_writable_target_directory() -> R {
        let fx = fixture()?;
        std::fs::write(fx.second.join(".detent-candidate-x"), b"x")?;
        std::fs::set_permissions(
            &fx.second,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o775),
        )?;
        let hooks = Hooks {
            checks: &Fake,
            services: &Fake,
        };
        let response = answer(
            &fx.allow,
            &fx.staging,
            &profile(),
            &hooks,
            filed_check(".detent-candidate-x"),
        );
        assert!(
            matches!(response, RunnerResponse::Failed(_)),
            "answered {response:?}"
        );
        Ok(())
    }

    #[test]
    fn a_runner_that_is_gone_makes_every_later_call_unavailable() -> R {
        let fx = fixture()?;
        let (monitor_end, runner_end) = Channel::pair()?;
        drop(runner_end);
        let client = RunnerClient::new(monitor_end, &fx.allow);
        let candidate = fx.staging.join("c");
        for _ in 0..2 {
            assert!(matches!(
                client.run_check(check()?, &candidate),
                Err(HookError::Unavailable(_))
            ));
        }
        assert!(matches!(
            client.service(binding()?, CoreServiceAction::Restart),
            Err(HookError::Unavailable(_))
        ));
        assert!(matches!(
            client.reload_unit_files(),
            Err(HookError::Unavailable(_))
        ));
        Ok(())
    }

    #[test]
    fn an_update_start_is_forwarded_and_its_answer_kept() -> R {
        let fx = fixture()?;
        with_runner(&fx, |client| {
            assert_eq!(
                client.start_update("v99.0.0"),
                Ok(UpdateStart::Started("started v99.0.0".to_owned()))
            );
            assert_eq!(
                client.start_update("v98.0.0"),
                Ok(UpdateStart::AlreadyRunning)
            );
            assert_eq!(
                client.start_update("v97.0.0"),
                Err(HookError::Failed("systemd-run exited 1".to_owned()))
            );
            Ok(())
        })
    }

    #[test]
    fn the_runner_refuses_a_tag_that_is_not_a_release_tag() -> R {
        let fx = fixture()?;
        let hooks = Hooks {
            checks: &Fake,
            services: &Fake,
        };
        for tag in ["", "-x", "v1.2.3 x", "v1.2.3/..", "v1.2.3;id", "1.2.3"] {
            assert_eq!(
                answer(
                    &fx.allow,
                    &fx.staging,
                    &profile(),
                    &hooks,
                    RunnerRequest::StartUpdate {
                        tag: tag.to_owned()
                    }
                ),
                RunnerResponse::Failed("not a release tag".to_owned()),
                "{tag:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_mismatched_answer_is_a_failure() -> R {
        let fx = fixture()?;
        let (monitor_end, mut runner_end) = Channel::pair()?;
        let peer = std::thread::spawn(move || {
            for wrong in [
                RunnerResponse::Serviced(ServiceOutcome {
                    binding: BindingId(0),
                    active: true,
                    detail: String::new(),
                }),
                RunnerResponse::Checked(CheckOutcome {
                    check: CheckId(0),
                    passed: true,
                    exit_code: Some(0),
                    detail: String::new(),
                }),
                RunnerResponse::Checked(CheckOutcome {
                    check: CheckId(0),
                    passed: true,
                    exit_code: Some(0),
                    detail: String::new(),
                }),
                RunnerResponse::Forgotten,
            ] {
                if runner_end.recv::<RunnerRequest>().is_err() || runner_end.send(&wrong).is_err() {
                    return;
                }
            }
        });
        let client = RunnerClient::new(monitor_end, &fx.allow);
        assert!(matches!(
            client.run_check(check()?, &fx.staging.join("c")),
            Err(HookError::Failed(_))
        ));
        assert!(matches!(
            client.service(binding()?, CoreServiceAction::Restart),
            Err(HookError::Failed(_))
        ));
        assert!(matches!(
            client.reload_unit_files(),
            Err(HookError::Failed(_))
        ));
        assert!(matches!(
            client.start_update("v99.0.0"),
            Err(HookError::Failed(_))
        ));
        drop(client);
        peer.join().map_err(|_| "peer thread panicked")?;
        Ok(())
    }

    #[test]
    fn the_runner_stops_on_a_frame_it_cannot_decode() -> R {
        let fx = fixture()?;
        let (mut monitor_end, mut runner_end) = Channel::pair()?;
        let allow = fx.allow.clone();
        let staging = fx.staging.clone();
        let runner = std::thread::spawn(move || {
            let hooks = Hooks {
                checks: &Fake,
                services: &Fake,
            };
            serve_runner(&allow, &staging, &profile(), &hooks, &mut runner_end);
        });
        // A `String` is not a `RunnerRequest`.
        monitor_end.send(&"not a request".to_owned())?;
        runner.join().map_err(|_| "runner thread panicked")?;
        Ok(())
    }
}
