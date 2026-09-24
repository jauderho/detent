//! End-to-end tests for the privsep monitor/worker pair (PLAN §2.4, §2.5;
//! ADR-001; Phase 2 tasks 2-3).
//!
//! Each test drives a real [`Monitor`] running in a background thread over a
//! real [`Channel::pair`], talking to it exactly as the worker would (mostly
//! through [`Client`], the typed wrapper `worker.rs` exposes; a few tests use
//! the raw [`Channel`] directly, either because the request has no `Client`
//! method yet (`Mount`, `ReplaceBinary`) or because the test needs to send
//! bytes a well-behaved worker never would).
//!
//! The crate denies `clippy::unwrap_used`/`expect_used`/`panic` in every
//! target, tests included, so each test returns [`TestResult`] and propagates
//! with `?`; the `unreachable!` idiom is used only where the condition is
//! genuinely impossible given a well-formed fixture (a lookup against a table
//! this same test just populated, a thread that only does infallible
//! syscalls).

use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use detent_core::descriptor::{
    ArgTemplate, CheckExpectation, ExternalCheck, HostProfile, ModuleDescriptor, Owner, PathSpec,
    ServiceAction as CoreServiceAction, ServiceBinding, Target, TargetKind, UnitNames, Upstream,
};
use detent_core::diag::MessageId;
use detent_platform::fs::atomic::{Sha256Digest, read_with_digest};
use detent_platform::privsep::allowlist::{Allowlist, Config};
use detent_platform::privsep::monitor::{
    CheckRunner, ExitReason, HookError, Hooks, Monitor, MonitorError, NoChecks,
    PENDING_COMMIT_MARKER, ServiceControl,
};
use detent_platform::privsep::proto::PendingService;
use detent_platform::privsep::proto::{
    BackupId, BindingId, CheckId, CheckOutcome, CommitId, MAX_FRAME, ModuleId, PROTO_VERSION,
    PathKind, ProtoError, Request, Response, ServiceAction, ServiceOutcome, TargetId,
};
use detent_platform::privsep::transport::Channel;
use detent_platform::privsep::worker::{Client, ClientError};
use tempfile::TempDir;

/// Error type for tests; any `?`-able error is acceptable.
type TestResult = Result<(), Box<dyn std::error::Error>>;

/// What a background monitor thread returns.
type ServeResult = Result<ExitReason, MonitorError>;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const fn always(_: &HostProfile) -> bool {
    true
}

static UPSTREAM: Upstream = Upstream {
    project: "test",
    repo_url: "https://example.invalid/test",
    tracked_version: "1.0",
    release_feed: None,
    docs: &[],
};

/// Leak a runtime string to `'static`, the only way to get a `PathSpec` (a
/// compile-time-constant path in production) to point at a temp file.
fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// Leak a runtime value to `'static`, for the same reason.
fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// A one-target, one-check, one-service module descriptor pointing at a real
/// temp file, built fresh for each test so ids never leak between fixtures.
///
/// Every `&'static` slice here is leaked explicitly rather than relying on
/// rvalue static promotion: the descriptor as a whole is assembled at
/// runtime (the target path comes from a `TempDir`), so promotion does not
/// apply to it even where an individual field would otherwise qualify.
fn build_descriptor(target_path: &Path) -> &'static ModuleDescriptor {
    let target_path = leak_str(target_path.display().to_string());
    let targets: &'static [Target] = leak(vec![Target {
        path: PathSpec::new(target_path),
        kind: TargetKind::File,
        mode: 0o644,
        owner: Owner::Root,
        backend_detect: always,
    }])
    .as_slice();
    let actions: &'static [CoreServiceAction] = leak(vec![CoreServiceAction::Restart]).as_slice();
    let services: &'static [ServiceBinding] = leak(vec![ServiceBinding {
        units: UnitNames {
            systemd: &["fake.service"],
            openrc: &[],
            bsdrc: &[],
        },
        actions,
    }])
    .as_slice();
    let args: &'static [ArgTemplate] =
        leak(vec![ArgTemplate::Literal("-p"), ArgTemplate::TempFile]).as_slice();
    let checks: &'static [ExternalCheck] = leak(vec![ExternalCheck {
        program: PathSpec::new("/nonexistent/detent-e2e-check"),
        args,
        expects: CheckExpectation::ExitZero,
    }])
    .as_slice();
    leak(ModuleDescriptor {
        id: "samba",
        display_name_id: MessageId::new("fake-name"),
        targets,
        upstream: UPSTREAM,
        services,
        checks,
        commit_confirm: false,
        security_notes: &[],
    })
}

/// A temp directory holding a target file, plus the module descriptor built
/// over it. State root and target live under the same temp dir but in
/// separate subtrees, as they would in a real deployment (`/etc/...` vs.
/// `/var/lib/detent`).
struct Fixture {
    _dir: TempDir,
    root: PathBuf,
    target: PathBuf,
    module: &'static ModuleDescriptor,
}

impl Fixture {
    fn config(&self) -> Config {
        Config::with_state_root(self.root.join("state"))
    }

    fn allow(&self) -> Result<Allowlist, Box<dyn std::error::Error>> {
        Ok(Allowlist::from_modules(&[self.module], &self.config())?)
    }
}

fn fixture(initial: &[u8]) -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let root = dir.path().to_path_buf();
    let target = root.join("target.conf");
    std::fs::write(&target, initial)?;
    let module = build_descriptor(&target);
    Ok(Fixture {
        _dir: dir,
        root,
        target,
        module,
    })
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Spawn a monitor over one end of a fresh channel and hand back the other.
fn spawn_monitor(
    allow: Allowlist,
) -> Result<(Channel, thread::JoinHandle<ServeResult>), Box<dyn std::error::Error>> {
    let (monitor_end, worker_end) = Channel::pair()?;
    let staging_dir = allow.state_root().with_file_name("monitor-staging");
    let handle = thread::spawn(move || {
        let mut channel = monitor_end;
        let mut monitor = Monitor::new(allow, Hooks::default());
        monitor.set_staging_dir(staging_dir);
        monitor.serve(&mut channel)
    });
    Ok((worker_end, handle))
}

/// As [`spawn_monitor`], already handshaken through a [`Client`].
fn spawn_client(
    allow: Allowlist,
) -> Result<(Client, thread::JoinHandle<ServeResult>), Box<dyn std::error::Error>> {
    let (channel, handle) = spawn_monitor(allow)?;
    let mut client = Client::new(channel);
    client.hello()?;
    Ok((client, handle))
}

struct CountingServices(Arc<AtomicUsize>);

impl ServiceControl for CountingServices {
    fn service(
        &self,
        _binding: &ServiceBinding,
        _action: CoreServiceAction,
    ) -> Result<ServiceOutcome, HookError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(ServiceOutcome {
            binding: BindingId(0),
            active: true,
            detail: "counted".to_owned(),
        })
    }
}

/// Join a monitor thread and assert it exited because of `Shutdown`.
fn join_shutdown(handle: thread::JoinHandle<ServeResult>) {
    join_expect(handle, ExitReason::Shutdown);
}

/// Join a monitor thread and assert it exited with `expected`.
fn join_expect(handle: thread::JoinHandle<ServeResult>, expected: ExitReason) {
    let Ok(result) = handle.join() else {
        unreachable!("the monitor thread only runs infallible syscalls and must not panic")
    };
    assert_eq!(result.ok(), Some(expected));
}

/// The id of the fixture's one target/module/check/binding, resolved through
/// an already-greeted client. These can only be `None` if the fixture and the
/// lookup disagree about the module id, which would be a bug in this file.
fn target_id(client: &Client, fx: &Fixture) -> TargetId {
    let Some(id) = client.target_id("samba", &fx.target.display().to_string(), PathKind::File)
    else {
        unreachable!("the fixture's own module must advertise its own target")
    };
    id
}

fn module_id(client: &Client) -> ModuleId {
    let Some(id) = client.module_id("samba") else {
        unreachable!("the fixture's own module must advertise its own id")
    };
    id
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

#[test]
fn hello_rejects_a_version_mismatch_and_closes_the_channel() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut channel, handle) = spawn_monitor(fx.allow()?)?;

    channel.send(&Request::Hello {
        proto: PROTO_VERSION + 1,
    })?;
    let response: Response = channel.recv()?;
    let Response::Error(ProtoError::VersionMismatch { expected, got }) = response else {
        unreachable!("expected a version mismatch error, got {response:?}")
    };
    assert_eq!(expected, PROTO_VERSION);
    assert_eq!(got, PROTO_VERSION + 1);

    join_expect(handle, ExitReason::ProtocolMismatch);
    Ok(())
}

#[test]
fn hello_accepts_a_matching_version() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;
    assert_eq!(client.tables().map(|ack| ack.proto), Some(PROTO_VERSION));
    assert_eq!(client.tables().map(|ack| ack.modules.len()), Some(1_usize));
    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// Read / write / conflict
// ---------------------------------------------------------------------------

#[test]
fn read_target_returns_current_contents_and_digest() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;
    let target = target_id(&client, &fx);

    let contents = client.read_target(target)?;
    assert_eq!(contents.bytes, b"v1");
    assert_eq!(contents.digest, read_with_digest(&fx.target)?.1);

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

#[test]
fn write_target_conflict_leaves_the_file_untouched_then_succeeds() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;
    let target = target_id(&client, &fx);
    let v1_digest = read_with_digest(&fx.target)?.1;

    let wrong = Sha256Digest::of(b"not the real previous contents");
    let conflict = client.write_target(target, Some(wrong), b"rejected".to_vec());
    assert!(matches!(
        conflict,
        Err(ClientError::Remote(ProtoError::Conflict { .. }))
    ));
    assert_eq!(std::fs::read(&fx.target)?, b"v1");

    let receipt = client.write_target(target, Some(v1_digest), b"v2".to_vec())?;
    assert!(!receipt.created);
    assert!(receipt.backed_up);
    assert_eq!(receipt.prev_digest, Some(v1_digest));
    assert_eq!(std::fs::read(&fx.target)?, b"v2");

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

#[test]
fn list_backups_and_restore_round_trip() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;
    let target = target_id(&client, &fx);
    let module = module_id(&client);

    client.write_target(target, None, b"v2".to_vec())?;
    assert_eq!(std::fs::read(&fx.target)?, b"v2");

    let backups = client.list_backups(module)?;
    let [backup] = backups.as_slice() else {
        unreachable!("exactly one write happened, so exactly one backup exists")
    };
    assert_eq!(backup.target, target);

    let (restored_target, new_digest) = client.restore(module, backup.id)?;
    assert_eq!(restored_target, target);
    assert_eq!(std::fs::read(&fx.target)?, b"v1");
    assert_eq!(new_digest, read_with_digest(&fx.target)?.1);

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// Checks and services with no collaborator wired up
// ---------------------------------------------------------------------------

#[test]
fn run_check_and_service_report_unavailable_with_no_collaborators() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;
    let Some(check) = client.check_id("samba") else {
        unreachable!("the fixture's own module must advertise its own check")
    };
    let Some(binding) = client.binding_id("samba") else {
        unreachable!("the fixture's own module must advertise its own binding")
    };

    let checked = client.run_check(check, b"candidate".to_vec());
    assert!(matches!(
        checked,
        Err(ClientError::Remote(ProtoError::Unavailable(_)))
    ));

    let serviced = client.service(binding, ServiceAction::Restart);
    assert!(matches!(
        serviced,
        Err(ClientError::Remote(ProtoError::Unavailable(_)))
    ));

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// Not-yet-built features
// ---------------------------------------------------------------------------

#[test]
fn mount_still_answers_unsupported() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;
    let target = target_id(&client, &fx);

    client.channel_mut().send(&Request::Mount { target })?;
    let response: Response = client.channel_mut().recv()?;
    assert!(matches!(
        response,
        Response::Error(ProtoError::Unsupported(_))
    ));

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

#[test]
fn replace_binary_rejects_a_missing_staged_file() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;

    client.channel_mut().send(&Request::ReplaceBinary {
        tag: "v0.0.2".to_owned(),
        len: 8,
        sha256: Sha256Digest::of(b"binary"),
    })?;
    let response: Response = client.channel_mut().recv()?;
    assert!(matches!(
        response,
        Response::Error(ProtoError::Io(message)) if message.contains("staged")
    ));

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// Commit-confirm
// ---------------------------------------------------------------------------

/// The wire protocol's `StartConfirmTimer::timeout_s` is whole seconds and
/// `Monitor::start_confirm_timer` clamps it to a minimum of 1
/// (`MAX_CONFIRM_TIMEOUT_S` at the other end); a true ~200 ms timeout is not
/// reachable through the public protocol without changing the wire format,
/// which is out of scope here. This uses the smallest value the protocol
/// allows and polls past it with margin over the monitor's 20 ms deadline
/// check interval.
const CONFIRM_TIMEOUT_S: u16 = 1;
const PAST_CONFIRM_DEADLINE: Duration = Duration::from_millis(1300);

#[test]
fn commit_confirm_expiry_rolls_back_unconfirmed_writes() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;
    let target = target_id(&client, &fx);
    let v1_digest = read_with_digest(&fx.target)?.1;

    client.write_target(target, Some(v1_digest), b"v2".to_vec())?;
    assert_eq!(std::fs::read(&fx.target)?, b"v2");

    let (timeout_s, rollback_targets) =
        client.start_confirm_timer(CommitId(1), CONFIRM_TIMEOUT_S, None)?;
    assert_eq!(timeout_s, CONFIRM_TIMEOUT_S);
    assert_eq!(rollback_targets, 1);

    std::thread::sleep(PAST_CONFIRM_DEADLINE);
    assert_eq!(std::fs::read(&fx.target)?, b"v1");

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

#[test]
fn confirm_commit_within_the_window_keeps_the_change() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;
    let target = target_id(&client, &fx);
    let v1_digest = read_with_digest(&fx.target)?.1;

    client.write_target(target, Some(v1_digest), b"v2".to_vec())?;
    client.start_confirm_timer(CommitId(7), CONFIRM_TIMEOUT_S, None)?;

    // Only one commit may be pending at a time.
    let second = client.start_confirm_timer(CommitId(8), CONFIRM_TIMEOUT_S, None);
    assert!(matches!(
        second,
        Err(ClientError::Remote(ProtoError::CommitPending(CommitId(7))))
    ));

    let confirmed = client.confirm_commit(CommitId(7))?;
    assert_eq!(confirmed, CommitId(7));

    // Nothing is armed under that id any more.
    let repeat = client.confirm_commit(CommitId(7));
    assert!(matches!(
        repeat,
        Err(ClientError::Remote(ProtoError::UnknownId { .. }))
    ));

    // Even past the original window, the confirmed change stands.
    std::thread::sleep(PAST_CONFIRM_DEADLINE);
    assert_eq!(std::fs::read(&fx.target)?, b"v2");

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

#[test]
fn rollback_commit_restores_the_backup_and_clears_the_marker() -> TestResult {
    let fx = fixture(b"v1")?;
    let allow = fx.allow()?;
    let state_root = allow.state_root().to_path_buf();
    let (mut client, handle) = spawn_client(allow)?;
    let target = target_id(&client, &fx);
    let v1_digest = read_with_digest(&fx.target)?.1;

    client.write_target(target, Some(v1_digest), b"v2".to_vec())?;
    assert_eq!(std::fs::read(&fx.target)?, b"v2");
    client.start_confirm_timer(CommitId(9), CONFIRM_TIMEOUT_S, None)?;
    assert!(state_root.join(PENDING_COMMIT_MARKER).is_file());

    let (commit, restored) = client.rollback_commit(CommitId(9))?;
    assert_eq!(commit, CommitId(9));
    assert_eq!(restored, 1);
    assert_eq!(std::fs::read(&fx.target)?, b"v1");
    assert!(!state_root.join(PENDING_COMMIT_MARKER).is_file());

    // A second rollback for the same id finds nothing pending: it must not
    // restore again, and must not resurrect the marker.
    let repeat = client.rollback_commit(CommitId(9));
    assert!(matches!(
        repeat,
        Err(ClientError::Remote(ProtoError::UnknownId { .. }))
    ));
    assert!(!state_root.join(PENDING_COMMIT_MARKER).is_file());

    // Even past the original window, nothing further happens: the manual
    // rollback already discharged the pending commit.
    std::thread::sleep(PAST_CONFIRM_DEADLINE);
    assert_eq!(std::fs::read(&fx.target)?, b"v1");

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

#[test]
fn rollback_journals_every_write_in_the_commit() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;
    let target = target_id(&client, &fx);
    let v1_digest = read_with_digest(&fx.target)?.1;

    let v2 = client.write_target(target, Some(v1_digest), b"v2".to_vec())?;
    client.write_target(target, Some(v2.new_digest), b"v3".to_vec())?;
    let (_, rollback_targets) =
        client.start_confirm_timer(CommitId(10), CONFIRM_TIMEOUT_S, None)?;
    assert_eq!(rollback_targets, 2);

    let (_, restored) = client.rollback_commit(CommitId(10))?;
    assert_eq!(restored, 2);
    assert_eq!(std::fs::read(&fx.target)?, b"v1");
    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

#[test]
fn rollback_replays_the_service_after_restoring_files() -> TestResult {
    let fx = fixture(b"v1")?;
    let (monitor_end, worker_end) = Channel::pair()?;
    let allow = fx.allow()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let monitor_calls = Arc::clone(&calls);
    let handle = thread::spawn(move || {
        let mut channel = monitor_end;
        let services = CountingServices(monitor_calls);
        Monitor::new(
            allow,
            Hooks {
                checks: &NoChecks,
                services: &services,
            },
        )
        .serve(&mut channel)
    });
    let mut client = Client::new(worker_end);
    client.hello()?;
    let target = target_id(&client, &fx);
    let binding = client
        .binding_id("samba")
        .ok_or("the fixture must advertise its service binding")?;
    let v1_digest = read_with_digest(&fx.target)?.1;

    client.write_target(target, Some(v1_digest), b"v2".to_vec())?;
    client.start_confirm_timer(
        CommitId(11),
        CONFIRM_TIMEOUT_S,
        Some(PendingService {
            binding,
            action: ServiceAction::Restart,
        }),
    )?;
    client.service(binding, ServiceAction::Restart)?;
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    client.rollback_commit(CommitId(11))?;
    assert_eq!(std::fs::read(&fx.target)?, b"v1");
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

#[test]
fn rollback_commit_rejects_an_id_that_was_never_armed() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;

    let response = client.rollback_commit(CommitId(42));
    assert!(matches!(
        response,
        Err(ClientError::Remote(ProtoError::UnknownId { .. }))
    ));

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

#[test]
fn rollback_commit_after_the_deadline_already_fired_finds_nothing_pending() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;
    let target = target_id(&client, &fx);
    let v1_digest = read_with_digest(&fx.target)?.1;

    client.write_target(target, Some(v1_digest), b"v2".to_vec())?;
    client.start_confirm_timer(CommitId(2), CONFIRM_TIMEOUT_S, None)?;

    // Let the timer itself take the pending state and roll back first.
    std::thread::sleep(PAST_CONFIRM_DEADLINE);
    assert_eq!(std::fs::read(&fx.target)?, b"v1");

    let response = client.rollback_commit(CommitId(2));
    assert!(matches!(
        response,
        Err(ClientError::Remote(ProtoError::UnknownId { .. }))
    ));

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

#[test]
fn graceful_monitor_exit_restores_a_pending_commit() -> TestResult {
    let fx = fixture(b"v1")?;
    let allow = fx.allow()?;
    let state_root = allow.state_root().to_path_buf();
    let (mut client, handle) = spawn_client(allow)?;
    let target = target_id(&client, &fx);
    let v1_digest = read_with_digest(&fx.target)?.1;

    client.write_target(target, Some(v1_digest), b"v2".to_vec())?;
    client.start_confirm_timer(CommitId(3), CONFIRM_TIMEOUT_S, None)?;
    assert!(state_root.join(PENDING_COMMIT_MARKER).is_file());

    // A graceful monitor exit restores the pending write and clears its marker.
    client.shutdown()?;
    join_shutdown(handle);
    assert_eq!(std::fs::read(&fx.target)?, b"v1");
    assert!(!state_root.join(PENDING_COMMIT_MARKER).is_file());

    Ok(())
}

#[test]
fn a_second_monitor_cannot_take_the_pending_commit_lock() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut first, first_handle) = spawn_client(fx.allow()?)?;
    let (_peer, second_handle) = spawn_monitor(fx.allow()?)?;
    let Ok(second) = second_handle.join() else {
        unreachable!("the second monitor only reports its lock failure")
    };
    assert!(matches!(second, Err(MonitorError::Busy)));
    first.shutdown()?;
    join_shutdown(first_handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// Malformed frames
// ---------------------------------------------------------------------------
#[test]
fn an_oversize_frame_terminates_the_session_with_a_protocol_violation() -> TestResult {
    let fx = fixture(b"v1")?;
    let allow = fx.allow()?;
    let (mut left, right) = UnixStream::pair()?;
    let channel = Channel::new(right)?;
    let handle = thread::spawn(move || {
        let mut channel = channel;
        Monitor::new(allow, Hooks::default()).serve(&mut channel)
    });

    let header = u32::try_from(MAX_FRAME + 1).unwrap_or(u32::MAX);
    left.write_all(&header.to_be_bytes())?;

    join_expect(handle, ExitReason::ProtocolViolation);
    Ok(())
}

#[test]
fn an_undecodable_frame_terminates_the_session_with_a_protocol_violation() -> TestResult {
    let fx = fixture(b"v1")?;
    let allow = fx.allow()?;
    let (mut left, right) = UnixStream::pair()?;
    let channel = Channel::new(right)?;
    let handle = thread::spawn(move || {
        let mut channel = channel;
        Monitor::new(allow, Hooks::default()).serve(&mut channel)
    });

    // Length 4, body = an out-of-range enum discriminant.
    left.write_all(&4_u32.to_be_bytes())?;
    left.write_all(&[250, 0, 0, 0])?;

    join_expect(handle, ExitReason::ProtocolViolation);
    Ok(())
}

// ---------------------------------------------------------------------------
// Exactly one response per request
// ---------------------------------------------------------------------------

#[test]
fn every_request_gets_exactly_one_response() -> TestResult {
    let fx = fixture(b"v1")?;
    let (mut client, handle) = spawn_client(fx.allow()?)?;
    let target = target_id(&client, &fx);
    let module = module_id(&client);

    let requests = [
        Request::ReadTarget { target },
        Request::ReadTarget {
            target: TargetId(999),
        },
        Request::ListBackups { module },
        Request::ListBackups {
            module: ModuleId(999),
        },
        Request::Restore {
            module,
            backup: BackupId(0),
        },
        Request::Mount { target },
        Request::ReplaceBinary {
            tag: "v0.0.2".to_owned(),
            len: 1,
            sha256: Sha256Digest::of(b"x"),
        },
    ];
    let mut responses = 0_usize;
    for request in &requests {
        client.channel_mut().send(request)?;
        let _response: Response = client.channel_mut().recv()?;
        responses += 1;
    }
    assert_eq!(responses, requests.len());

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// An oversize response
// ---------------------------------------------------------------------------

/// A backup listing large enough that the *monitor's own* encoded
/// `Response::Backups(..)` exceeds `MAX_FRAME`, so `Channel::send` fails on
/// the monitor side while answering a legitimate request. This is
/// deterministic (not a race): each planted file becomes one `BackupInfo`
/// entry, and postcard-encoding ~12,000 of them (at roughly 110-120 bytes
/// each) reliably clears the 1 MiB frame limit.
#[test]
fn an_oversize_response_terminates_the_session_with_a_protocol_violation() -> TestResult {
    let fx = fixture(b"v1")?;
    let backup_dir = fx
        .root
        .join("state")
        .join("backups")
        .join("samba")
        .join("0");
    std::fs::create_dir_all(&backup_dir)?;
    let stamp = "2026-01-01T00:00:00.000000000Z";
    for i in 0..12_000_u32 {
        let name = format!("{stamp}-{i:08x}");
        std::fs::write(backup_dir.join(name), b"x")?;
    }

    let (mut client, handle) = spawn_client(fx.allow()?)?;
    let module = module_id(&client);
    client
        .channel_mut()
        .send(&Request::ListBackups { module })?;
    // The monitor's response never arrives: encoding it succeeds but sending
    // it fails the frame-size check, so the monitor closes the channel
    // instead. The client must not receive a well-formed `Response`.
    let result = client.channel_mut().recv::<Response>();
    assert!(result.is_err());

    join_expect(handle, ExitReason::ProtocolViolation);
    Ok(())
}

// ---------------------------------------------------------------------------
// RunCheck / Service success, through real collaborators
// ---------------------------------------------------------------------------

struct OkChecks;
impl CheckRunner for OkChecks {
    fn run_check(
        &self,
        _check: &ExternalCheck,
        _candidate: &Path,
    ) -> Result<CheckOutcome, HookError> {
        Ok(CheckOutcome {
            check: CheckId(0),
            passed: true,
            exit_code: Some(0),
            detail: "ok".to_owned(),
        })
    }
}

struct OkServices;
impl ServiceControl for OkServices {
    fn service(
        &self,
        _binding: &ServiceBinding,
        _action: CoreServiceAction,
    ) -> Result<ServiceOutcome, HookError> {
        Ok(ServiceOutcome {
            binding: BindingId(0),
            active: true,
            detail: "running".to_owned(),
        })
    }
}

static OK_CHECKS: OkChecks = OkChecks;
static OK_SERVICES: OkServices = OkServices;

/// `run_check` and `service` succeeding end to end, through real
/// `CheckRunner`/`ServiceControl` collaborators: covers both the monitor's
/// success arms (also reachable from `privsep::monitor`'s own white-box
/// tests) and, uniquely, `Client::run_check`/`Client::service`'s success
/// arms, which only a real round trip through the wire protocol exercises.
#[test]
fn run_check_and_service_succeed_through_working_collaborators() -> TestResult {
    let fx = fixture(b"v1")?;
    let allow = fx.allow()?;
    let staging_dir = allow.state_root().with_file_name("monitor-staging");
    let (monitor_end, worker_end) = Channel::pair()?;
    let handle = thread::spawn(move || {
        let mut channel = monitor_end;
        let hooks = Hooks {
            checks: &OK_CHECKS,
            services: &OK_SERVICES,
        };
        let mut monitor = Monitor::new(allow, hooks);
        monitor.set_staging_dir(staging_dir);
        monitor.serve(&mut channel)
    });
    let mut client = Client::new(worker_end);
    client.hello()?;
    let Some(check) = client.check_id("samba") else {
        unreachable!("the fixture's own module must advertise its own check")
    };
    let Some(binding) = client.binding_id("samba") else {
        unreachable!("the fixture's own module must advertise its own binding")
    };

    let checked = client.run_check(check, b"candidate".to_vec())?;
    assert!(checked.passed);

    let serviced = client.service(binding, ServiceAction::Restart)?;
    assert!(serviced.active);

    client.shutdown()?;
    join_shutdown(handle);
    Ok(())
}
