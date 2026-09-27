//! Per-architecture seccomp allow-lists for the monitor, worker and acme roles
//! (PLAN §2.4; spike 02).
//!
//! # Derivation
//!
//! The syscall names in [`syscalls_for`] were not guessed. They come from two
//! sources, both grounded in this repository:
//!
//! 1. Reading `fs::atomic` and `privsep::{transport, monitor, worker}` (the
//!    monitor's IPC, filesystem, and timing code paths) to see exactly which
//!    `rustix`/`std` calls they make — e.g. `Channel::send`/`recv` do plain
//!    `read`/`write` on a connected
//!    [`std::os::unix::net::UnixStream`] (no `poll`, because the timeout is
//!    a kernel-level `SO_RCVTIMEO`/`SO_SNDTIMEO` via `setsockopt`, not
//!    userspace polling), and `Instant`/`SystemTime` map to `clock_gettime`,
//!    not `nanosleep`.
//! 2. Running `cargo test -p detent-platform --all-features` under `strace
//!    -f -c` inside `rust:1-bookworm` (`aarch64`, native under `OrbStack`, and
//!    `x86_64` under `--platform linux/amd64` emulation) and cross-checking the
//!    observed syscall names against (1) to separate real monitor/worker
//!    behaviour from test-harness noise. `execve`/`clone` from the initial
//!    process launch stay excluded for that reason — but `clone`/`execve`
//!    *after* confinement were allow-listed so the monitor could spawn
//!    validators and service commands (STAGE3 H6). A child inherits this
//!    filter, so under `serve` those programs now run in the unconfined
//!    runner (`privsep::runner`); the entries stay until a traced run shows
//!    the monitor no longer needs them.
//!
//! `SYSCALL_NUMBERS` itself is not from memory either: both columns were
//! read out of `<asm/unistd.h>` (via `gcc -E -dM -xc - < <(echo '#include
//! <sys/syscall.h>')`) inside `debian:bookworm`, once natively for `aarch64`
//! and once under `x86_64` emulation, so they are the real kernel/libc ABI
//! numbers for the exact distribution this crate is tested against, not a
//! hand-typed table.
//!
//! **Phase 4 addendum (the worker's real `detent-web` server, PLAN §2.6):**
//! the same two sources, plus a third this time — a full end-to-end `strace
//! -f` of `detent serve` itself (not just its test suite) as root inside
//! `rust:1-bookworm`, self-signed TLS, a real client request over HTTPS, and
//! a real `SIGTERM`. That is what caught what reading the dependency tree
//! could not have: `clone`/`clone3`/`rseq`/`set_robust_list`/
//! `sched_getaffinity` for the thread `detent_web::spawn_engine` starts,
//! `socketpair` (not `pipe2`) for `tokio::signal`'s self-pipe, and
//! `rt_sigreturn` — missing from *both* roles since Phase 2, and invisible
//! until something actually delivered a signal to a confined process, at
//! which point it faulted in a `getrandom`/`rt_sigreturn` `EPERM` loop
//! instead of returning from the handler. It also caught a masking bug one
//! level up: an earlier draft of this table listed `epoll_wait`, which has
//! no `aarch64` number, which made [`compile`] return `UnknownSyscall` for
//! the worker on `aarch64` — and `sandbox::linux::install_seccomp` turns
//! that into a silently degraded `Outcome::Unavailable` rather than failing
//! startup, so the worker ran with **no seccomp filter installed at all**
//! until the live trace showed no `seccomp(SECCOMP_SET_MODE_FILTER, …)`
//! call for its pid. `epoll_pwait` (present on both architectures) replaced
//! it.
//!
//! **ADR-015 addendum (the acme process, `ACME`):** traced live with `strace
//! -f` on `x86_64` (glibc test run and a glibc/musl name-lookup probe; see the
//! table's doc comment). That trace also showed two things the tables did
//! not know. glibc on `x86_64` issues `epoll_wait`, not `epoll_pwait`: without
//! it tokio's I/O driver panics on its first poll. `WORKER` lists only
//! `epoll_pwait`, which holds for the shipped musl binary and for aarch64 but
//! not for a glibc `x86_64` build. And **musl's resolver `bind`s its UDP socket
//! to port 0 before each DNS query** (`res_msend`); with `bind` refused, a
//! musl build resolves only names in `/etc/hosts`. The project owner chose
//! to allow `bind` in `ACME` (ADR-015 amended 2026-09-26); `listen` and
//! `accept4` stay refused, so the process still cannot accept a TCP
//! connection.
//!
//! Only `x86_64` and `aarch64` are covered (PLAN §1.6 defers armv7 and riscv64);
//! [`Arch::parse`] and [`Arch::host`] report anything else as
//! [`SeccompError::UnsupportedArch`] rather than failing to compile, so a
//! Linux build for a deferred architecture still links — [`super::confine`]
//! turns that error into a documented `Unavailable` seccomp outcome instead
//! of refusing to start.
//!
//! # Two halves, one portable
//!
//! [`numbers_for`] is pure data: syscall names resolved to raw numbers for a
//! given [`Arch`]. It has no dependency on `seccompiler`, which
//! `crates/detent-platform/Cargo.toml` links only under
//! `cfg(target_os = "linux")`, so it — and the table-correctness tests below
//! — compile and run on macOS too. `compile` is the other half: it turns
//! those numbers into a real `seccompiler::BpfProgram` and is `cfg(target_os
//! = "linux")` because that type does not exist anywhere else.

use super::Role;

/// A syscall table exists for exactly these two PLAN §1.6 tier-1 architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// `x86_64-unknown-linux-musl`.
    X86_64,
    /// `aarch64-unknown-linux-musl`.
    Aarch64,
}

impl Arch {
    /// Parse a `std::env::consts::ARCH`-style name.
    ///
    /// # Errors
    ///
    /// [`SeccompError::UnsupportedArch`] for anything outside PLAN §1.6's
    /// Linux tier-1 set — currently armv7 and riscv64, both deferred.
    pub fn parse(name: &str) -> Result<Self, SeccompError> {
        match name {
            "x86_64" => Ok(Self::X86_64),
            "aarch64" => Ok(Self::Aarch64),
            other => Err(SeccompError::UnsupportedArch(other.to_owned())),
        }
    }

    /// The architecture this binary was compiled for.
    ///
    /// # Errors
    ///
    /// As [`Arch::parse`].
    pub fn host() -> Result<Self, SeccompError> {
        Self::parse(std::env::consts::ARCH)
    }
}

/// Whether a filter blocks a mismatched syscall for real, or only logs it.
///
/// `Log` exists so the table above can be re-derived and CI can run in a
/// mode that never kills a test process: install the filter with `default
/// action = SCMP_ACT_LOG`, run the real workload, and read the kernel audit
/// log for anything outside the allow-list instead of guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeccompMode {
    /// `SCMP_ACT_KILL_PROCESS` (monitor) / `SCMP_ACT_ERRNO(EPERM)` (worker)
    /// for anything not on the list.
    #[default]
    Enforce,
    /// `SCMP_ACT_LOG` for anything not on the list: nothing is blocked, the
    /// kernel just logs it.
    Log,
}

/// Building or installing a seccomp filter failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SeccompError {
    /// [`Arch::parse`]/[`Arch::host`] saw a name outside PLAN §1.6's tier-1 set.
    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),
    /// A name in [`syscalls_for`]'s tables has no entry in
    /// `SYSCALL_NUMBERS`. Only reachable if the two fall out of sync; the
    /// test suite checks they do not.
    #[error("no syscall number known for {0} (table out of sync)")]
    UnknownSyscall(String),
    /// `seccompiler` rejected the filter or the compiled program.
    #[error("cannot build the seccomp filter: {0}")]
    Build(String),
    /// `seccompiler::apply_filter` failed.
    #[error("cannot install the seccomp filter: {0}")]
    Install(String),
}

/// `EPERM` (`errno(3)`). Not available as a constant without a `libc`
/// dependency, which PLAN §4.2 does not list for this crate; `seccompiler`'s
/// own examples hand-write the same literal (see `spikes/xbuild/src/main.rs`).
#[cfg(target_os = "linux")]
const EPERM: u32 = 1;

/// Syscalls the monitor's blocking loop needs after seccomp installs:
/// reading/writing the privsep channel, and the atomic-write/backup protocol
/// in `fs::atomic` (open, read/write, fsync, rename, unlink, mkdir, list
/// backups, preserve owner/mode/xattrs), plus reaping the worker.
const MONITOR: &[&str] = &[
    // IPC (privsep::transport::Channel over a connected UnixStream).
    "read",
    "write",
    "recvfrom",
    "sendto",
    "shutdown",
    "setsockopt", // `Channel::set_read_timeout`, called live during commit-confirm polling.
    // Process/allocator/runtime housekeeping every path below needs.
    "close",
    "fstat",
    "newfstatat",
    "statx",
    "lseek",
    "fcntl",
    "futex",
    "mmap",
    "munmap",
    "mprotect",
    "madvise",
    "mremap",
    "brk",
    "clock_gettime", // `Instant`/`SystemTime::now()`.
    "restart_syscall",
    "getrandom",
    "rt_sigaction",
    "rt_sigprocmask",
    "sigaltstack",
    // The kernel's own way back out of a signal handler (`sigreturn(2)`):
    // without it, a process that has `rt_sigaction`-installed handlers and
    // actually receives a signal cannot resume, and faults on return instead
    // — found live for the worker (below) chasing a `SIGTERM` that never
    // stopped the server; this pre-dated Phase 4 and applies equally to the
    // monitor, which installs handlers via the same `rt_sigaction`.
    "rt_sigreturn",
    "getpid",
    "gettid",
    "exit",
    "exit_group",
    // `fs::atomic`: open/read/write the target and its temp file, fsync,
    // rename, list/rotate backups, preserve owner/mode/xattrs.
    "openat",
    "pread64",
    "pwrite64",
    "renameat",
    "linkat", // `swap_running_binary` hard-links the previous binary.
    "fsync",
    "unlinkat",
    "mkdirat",
    "getdents64",
    "fchmod",
    "fchmodat",
    "fchown",
    "fgetxattr",
    "fsetxattr",
    "flistxattr",
    "lgetxattr",
    "lsetxattr",
    "statfs",
    // The state lock (`Monitor::lock`, called after confinement in `serve`):
    // `create_dir_all` of the state root, then `flock`. On x86_64 glibc and
    // musl issue `mkdir` (the legacy form of `mkdirat`, above); aarch64 has
    // only `mkdirat`. Seen live in the C4 trace (`scripts/acme-serve-check.sh`,
    // x86_64 glibc): `mkdir("/var/lib/detent", 0777) = -1 EEXIST` and
    // `flock(4, LOCK_EX|LOCK_NB) = 0`; without them the filter killed the
    // monitor with `SIGSYS` on every start.
    "mkdir",
    "flock",
    // Reap the worker (`MonitorHandle::wait`, called from the same process
    // that ran `confine_monitor`).
    "wait4",
    // Process creation (`service::exec::run_confined`, called live for every
    // `RunCheck` and `Service` request): `Command::spawn` is `clone`/`clone3`
    // + `execve`/`execveat` in the child, `pipe2`/`dup3` for the piped
    // stdio, `kill`/`tgkill` for the timeout kill, `clock_nanosleep` for the
    // `try_wait` poll loop's sleep (glibc routes it there; `nanosleep` stays
    // as the fallback), `prlimit64` (Rust `std` queries `RLIMIT_NOFILE`
    // while wiring stdio), `faccessat` (the dynamic loader's first call in
    // the exec'd child, `/etc/ld.so.preload`), and `rseq`/`set_robust_list`/
    // `set_tid_address` for the two `spawn_capped_reader` threads glibc
    // starts per child. Traced live in a privileged `debian:bookworm`
    // container: first a fork + pipe + dup2 + exec + nanosleep + kill probe,
    // then the real confined-monitor child spawning `/bin/true` under
    // `strace -f`. That trace killed the child at `prlimit64` (the Rust
    // stdio wiring) and, after allowing it, at the loader's `faccessat` —
    // both fixed here and re-traced green (`NO_SIGSYS`). `sched_getaffinity`
    // stays (glibc thread startup consults it). Remaining H6 work is the
    // testhost2/testhost-arm pass per STAGE3 H6 steps 1 and 4 before closing the item.
    "clone",
    "clone3",
    "execve",
    "execveat",
    "pipe2",
    "dup3",
    "dup2",
    "kill",
    "tgkill",
    "nanosleep",
    "clock_nanosleep", // glibc routes `thread::sleep` here, not `nanosleep`.
    "prlimit64",       // Rust `std` queries `RLIMIT_NOFILE` while wiring stdio.
    "faccessat",       // dynamic loader probes `/etc/ld.so.preload` after `execve`.
    "open", // musl `File::open_c` (null stdio, `PathFd::new`); Trap oracle named `__NR_open` on x86_64.
    "access", // loader fallback probe (`/etc/ld.so.preload`, SELinux config).
    "readlink", // `current_exe` in `Policy::monitor` resolves `/proc/self/exe`.
    "readlinkat", // loader/exe-path resolution variant.
    "ppoll", // loader wait in the `poll`/`ppoll` family.
    "poll", // `coreutils true` (testhost) issues `poll`; number 7, x86_64-only.
    "set_tid_address", // glibc thread startup for the reader threads.
    "arch_prctl",
    "rseq",
    "set_robust_list",
    "sched_getaffinity",
];

/// Syscalls the worker needs. Phase 4 gives the worker a real `detent-web`
/// HTTP/TLS server on a `tokio` runtime (`crates/detent/src/serve.rs`), so
/// this is no longer just the Phase 2 privsep handshake. Every addition below
/// was confirmed against a real, running worker: `strace -f` on
/// `rust:1-bookworm` (aarch64, under `OrbStack` — see `docs/spikes/m1-e2e.md`
/// for the same methodology) with the Phase 2 table installed, which killed
/// the worker with `EPERM` on `clone` the moment `detent_web::spawn_engine`
/// tried to start its background thread; each further syscall below was
/// added and re-traced until a real client request completed and the worker
/// shut down cleanly on `SIGTERM`. The C4 trace (`scripts/acme-serve-check.sh`,
/// CI job `acme-serve`: `x86_64` glibc, a real `serve` through ACME issuance,
/// install and `SIGTERM`) added the `x86_64` legacy forms at the end. Calls it
/// showed refused and tolerated are left out on purpose: `prctl(PR_SET_NAME)`
/// (thread names; std ignores the error), `prctl(PR_SET_VMA)` (mimalloc names
/// its mappings) and `access("/sys/devices/system/node/node1")` (mimalloc's
/// NUMA probe; it then assumes one node).
///
/// **Slice W1 (STAGE4 4.3 item 5):** `fdatasync` added. The C4/S2 traces
/// only ever exercised the ACME install path, so a genuine gap went unseen
/// until slice S2 sent a real `POST /api/v1/system/cert/renew`: both audit
/// writers the confined worker runs (`FileAuthAudit::append` in
/// `detent-web`, `FileAudit` in `detent-ops`) call `File::sync_data()`
/// after each record, which `WORKER` did not allow. Confirmed live:
/// `fdatasync(14) = -1 EPERM`, which made the ops engine fail the operation
/// because its intent record could not be persisted.
const WORKER: &[&str] = &[
    "read",
    "write",
    "recvfrom",
    "sendto",
    "shutdown",
    "close",
    "fstat",
    "newfstatat",
    "statx",
    "lseek",
    "fcntl",
    "futex",
    "mmap",
    "munmap",
    "mprotect",
    "madvise",
    "mremap",
    "brk",
    "clock_gettime",
    "restart_syscall",
    "getrandom",
    "rt_sigaction",
    "rt_sigprocmask",
    "sigaltstack",
    // The syscall a signal handler returns through (see the monitor's copy
    // of this comment above). Without it `tokio::signal::unix::signal`'s
    // handler for `SIGTERM`/`SIGINT` faults on return instead of resuming —
    // confirmed live: a real `SIGTERM` sent to a confined worker produced a
    // tight `getrandom`/`rt_sigreturn` `EPERM` loop under `strace` instead
    // of a clean shutdown, until this was added.
    "rt_sigreturn",
    "getpid",
    "gettid",
    "exit",
    "exit_group",
    // `detent_web::spawn_engine`'s `std::thread::spawn`: the OpsEngine's own
    // dedicated OS thread (`crates/detent-web/src/engine.rs`), started every
    // time regardless of which tokio runtime flavour drives the server.
    // `rseq` is glibc's own doing, not this codebase's: every new thread
    // self-registers a restartable-sequence memory area right after `clone`
    // returns in the child, and treats an `EPERM` there as fatal
    // (`Fatal glibc error: rseq registration failed`, confirmed live —
    // the worker's main thread never calls it post-`exec`, because that
    // registration already happened before the seccomp filter installs, but
    // every thread `spawn_engine` starts afterwards needs it).
    "clone",
    "clone3",
    // glibc's own doing on every new thread, not this codebase's, and each
    // treats an `EPERM` as fatal or near enough not to trust: `rseq`
    // self-registers a restartable-sequence memory area right after `clone`
    // returns in the child (`Fatal glibc error: rseq registration failed`,
    // confirmed live — the worker's own main thread never calls it, because
    // that registration already happened before the seccomp filter
    // installs, but every thread `spawn_engine` starts afterwards needs
    // it); `set_robust_list` registers the new thread's robust-futex list
    // (glibc's `pthread_create`, unconditional); `sched_getaffinity` backs
    // `std::thread::available_parallelism`, which `tokio`'s runtime builder
    // consults even for `new_current_thread`.
    "rseq",
    "set_robust_list",
    "sched_getaffinity",
    // `tokio::runtime::Builder::new_current_thread()` (`prepare_worker`) and
    // `tokio::signal::unix::signal` (`shutdown_signal`): mio's epoll-based
    // reactor and its eventfd2 waker, and the `AF_UNIX`/`SOCK_STREAM`
    // socket pair `tokio::signal` uses to move SIGTERM/SIGINT delivery out
    // of the signal handler (`failed to create UnixStream`, confirmed live,
    // is `tokio-1.53.1`'s own panic message for this exact `EPERM`).
    // `epoll_pwait` only, not `epoll_wait`: `aarch64` has no `epoll_wait`
    // syscall at all (like `poll`/`ppoll` below), and every table entry
    // [`syscalls_for`] actually lists must resolve on both tier-1
    // architectures or `numbers_for`/`compile` fails — confirmed live: an
    // earlier version of this table listed `epoll_wait` too, which made
    // `compile` return `UnknownSyscall` for the worker on `aarch64`, which
    // `sandbox::linux::install_seccomp` silently downgrades to
    // `Outcome::Unavailable` rather than failing the worker's startup — the
    // worker still ran, completely unconfined by seccomp, and `strace`
    // confirmed it: no `seccomp(SECCOMP_SET_MODE_FILTER, …)` call for the
    // worker's pid, only for the monitor's.
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "eventfd2",
    "socketpair",
    // Listening: `detent_web::Server::bind` opens a TCP socket, binds it to
    // `config.listen.addr`, and starts listening; `local_addr()` (logged by
    // `run_worker` as `cli-serve-listening`) reads it back.
    "socket",
    "bind",
    "listen",
    "getsockname",
    "setsockopt",
    // Accepting and serving a connection: tokio's `TcpListener::accept`
    // (`accept4`, non-blocking + close-on-exec in one call) and hyper's
    // vectored writes of a response over the accepted stream.
    "accept4",
    "writev",
    // `tls::load_or_bootstrap`, `AuthState::open` (users/tokens/sessions)
    // and `FileAudit`: every file the worker's own state-root-confined
    // Landlock rules allow it to touch — the bootstrap certificate and key
    // under `tls.cert_dir`, `users.json`/`tokens.json` under
    // `<state_root>/state`, and the audit log under `<state_root>/audit`.
    "openat",
    "pread64",
    "pwrite64",
    "renameat",
    "fsync",
    // The data-only form of `fsync` above: `File::sync_data()`, called by
    // both audit writers the confined worker runs
    // (`detent-web::auth::audit::FileAuthAudit::append` and
    // `detent-ops::audit::FileAudit`) after each record. Seen live in the
    // acme-serve trace: `fdatasync(14) = -1 EPERM` after
    // `POST /api/v1/system/cert/renew`, which made the ops engine fail the
    // operation because its intent record could not be persisted.
    "fdatasync",
    "unlinkat",
    "mkdirat",
    "fchmod",
    "fchmodat",
    "faccessat",
    "getdents64",
    // The x86_64 legacy forms of calls allowed above as `*at`/`epoll_pwait`
    // forms (aarch64 has none of them). Seen live in the C4 trace
    // (`scripts/acme-serve-check.sh`, x86_64 glibc): `tls.cert_dir` is made
    // with `mkdir("/var/lib/detent/certs", 0777)` and `chmod(…, 0700)`, a
    // pair is written with `chmod(…/bootstrap.pair, 0600)` and
    // `unlink(…/bootstrap.cert.der)` of the old file, the directory is opened
    // with `open(…/certs, O_RDONLY|O_DIRECTORY)` (the acme install thread too),
    // and glibc's tokio reactor waits in `epoll_wait` (as in `ACME`).
    // `numbers_for` skips a known name that an arch lacks, so these rows
    // leave the aarch64 filter as it was.
    "mkdir",
    "chmod",
    "unlink",
    "open",
    "epoll_wait",
];

/// Syscalls the acme process needs (ADR-015): an outbound HTTPS/TCP client
/// on a current-thread `tokio` runtime with hyper-rustls, plus glibc/musl
/// name lookup. Derived from [`WORKER`] minus what accepts connections
/// (`listen`, `accept4`) and the worker's own state-file calls, then
/// traced live with `strace -f` in three runs (`x86_64`): the
/// `enforce_mode_acme_reaches_out_but_cannot_listen` test (glibc; `spawn_acme`
/// with the real hooks, `/etc/hosts` lookup, TLS 1.3 fetch through
/// hyper-rustls, a credentials write), and a small probe that resolves a
/// public name through `/etc/resolv.conf` under this filter, built once for
/// glibc and once for musl. The credentials store calls were traced the same
/// way (slice C3b): the test's `write_credentials`, which repeats
/// `detent-acme`'s `write_json_atomically` call for call, and a probe that
/// does the same writes under this filter, built for glibc and for musl.
/// Slice C4 proved the table in a real run: the CI job `acme-serve`
/// (`scripts/acme-serve-check.sh`: `detent serve` as root under `strace
/// -ff`, `x86_64` glibc, Pebble and BIND 9, RFC 2136 with TSIG) orders,
/// installs and serves a certificate with no `EPERM` in the acme process
/// outside the tolerated calls. Observed set after confinement: `brk`,
/// `clone3`, `close`, `connect`, `epoll_create1`, `epoll_ctl`,
/// `epoll_wait`, `eventfd2`, `exit`, `fcntl`, `fsync`, `futex`,
/// `getpeername`, `getpid`, `getrandom`, `getsockname`, `getsockopt`,
/// `gettid`, `madvise`, `mkdir`, `mmap`, `mprotect`, `munmap`,
/// `newfstatat`, `openat`, `read`, `recvfrom`, `rename`, `rseq`,
/// `rt_sigaction`, `rt_sigprocmask`, `sched_getaffinity`, `sendto`,
/// `set_robust_list`, `setsockopt`, `sigaltstack`, `socket`, `socketpair`,
/// `statx`, `write`, `writev`, and `access` (refused, tolerated). That run found `ioctl(FIONBIO)` from
/// `TcpStream::connect_timeout` in the RFC 2136 exchange; `detent-acme`
/// now bounds a blocking `connect` on a thread instead (`tsig::within`).
/// Calls the traces showed refused and tolerated
/// are left out on purpose: `uname` (glibc resolver setup), `ioctl(FIONREAD)`
/// (glibc resolver), `prctl(PR_SET_NAME)` (thread names) and
/// `access("/sys/devices/system/node/node1")` (mimalloc's NUMA probe).
const ACME: &[&str] = &[
    // IPC with the worker (`Channel` over a `UnixStream`), file reads and
    // allocator/runtime housekeeping: all seen live.
    "read",
    "write",
    "close",
    "fstat",
    "newfstatat",
    "lseek",
    "fcntl",
    "futex",
    "mmap",
    "munmap",
    "mprotect",
    "madvise",
    "mremap",
    "brk",
    "getrandom", // rustls key shares and nonces (aws-lc-rs).
    "rt_sigprocmask",
    "sigaltstack",
    "gettid",
    "exit",
    "exit_group",
    // Kept from `WORKER` for the same runtime code, not hit by the traces:
    // `clock_gettime` is the vDSO's syscall fallback, and a process that
    // gets a signal with a handler needs `rt_sigaction`/`rt_sigreturn`/
    // `restart_syscall` (see the `WORKER` comment on `rt_sigreturn`).
    "clock_gettime",
    "restart_syscall",
    "rt_sigaction",
    "rt_sigreturn",
    // Threads: hyper-util's resolver runs `getaddrinfo` on a tokio
    // `spawn_blocking` thread (`clone3` seen; `clone` is what musl's
    // `pthread_create` issues), and glibc registers each new thread (`rseq`,
    // `set_robust_list`); `sched_getaffinity` is the runtime builder's
    // `available_parallelism`.
    "clone",
    "clone3",
    "rseq",
    "set_robust_list",
    "sched_getaffinity",
    // The runtime's reactor and waker. glibc on x86_64 issues `epoll_wait`
    // (seen; its absence made the traced run panic in tokio's I/O driver);
    // musl and every aarch64 libc issue `epoll_pwait`. `epoll_wait` has no
    // aarch64 number, so it resolves on x86_64 only (like `poll`).
    // `socketpair` is tokio's signal-driver pipe, created at runtime build.
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "eventfd2",
    "socketpair",
    // Outbound TCP, all seen: `socket` + non-blocking `connect`, then
    // `getsockopt(SO_ERROR)` for the result; `setsockopt` (`TCP_NODELAY`,
    // `IP_RECVERR` in the glibc resolver); `getpeername`/`getsockname`
    // (hyper-util's connection info, glibc's address sort); `writev`,
    // `recvfrom` and `sendto` for the TLS records; `shutdown` on close. The
    // same `connect` reaches `/var/run/nscd/socket`, which glibc tries first.
    "socket",
    "connect",
    "getsockopt",
    "setsockopt",
    "getpeername",
    "getsockname",
    "writev",
    "recvfrom",
    "sendto",
    "shutdown",
    // Name lookup: `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`
    // (`openat`; musl on x86_64 uses `open`), then the DNS query. glibc:
    // UDP `connect`, `poll` for `POLLOUT`, `sendmmsg` (A and AAAA at once),
    // `recvfrom`. musl: `bind` of its UDP socket to port 0 before each
    // query (`res_msend`), then `sendto`, `poll`, `recvmsg` (see the module
    // docs); glibc also `bind`s the `AF_NETLINK` socket it opens to sort
    // addresses. `bind` without `listen` or `accept4` accepts no TCP
    // connection. aarch64 has no `poll` or `open`: its libcs issue
    // `ppoll`/`openat`.
    "bind",
    "openat",
    "open",
    "poll",
    "ppoll",
    "sendmmsg",
    "recvmsg",
    // The credentials store (`write_json_atomically` in `detent-acme`), all
    // seen: `create_dir_all` of the parent (`mkdir`, then a stat when it
    // exists), `getpid` for the temp file name (`std::process::id`), a stat
    // for a stale temp file and `unlink` to remove it, `openat`/`open` with
    // `O_CREAT|O_EXCL` and mode `0600` (no separate chmod), `fsync` of the
    // file and of the directory, and `rename` over the old file. The stat is
    // `statx` from Rust's std on glibc and `stat` from musl on x86_64; std
    // does not fall back when `statx` answers `EPERM`, so `Path::exists`
    // says "no" and `create_dir_all` fails on an existing directory. x86_64
    // libcs issue `mkdir`, `unlink`, `rename` and (musl) `stat`; aarch64 has
    // none of them, and its libcs issue `mkdirat`, `unlinkat`, `renameat`
    // and `newfstatat` (above) instead (not traced on aarch64).
    "fsync",
    "rename",
    "renameat",
    "getpid",
    "mkdir",
    "mkdirat",
    "unlink",
    "unlinkat",
    "statx",
    "stat",
];

/// The syscall names allowed for `role`, by name (see the module docs for
/// how this list was derived).
#[must_use]
pub const fn syscalls_for(role: Role) -> &'static [&'static str] {
    match role {
        Role::Monitor => MONITOR,
        Role::Worker => WORKER,
        Role::Acme => ACME,
    }
}

/// `(name, x86_64 number, aarch64 number)`, `-1` meaning "no such syscall on
/// this architecture". See the module docs: both columns were read from
/// `<asm/unistd.h>` inside `debian:bookworm`, not typed from memory (the rows
/// the `ACME` table added were read from the `x86_64` `<asm/unistd_64.h>` and
/// the aarch64 `<asm-generic/unistd.h>` of the build container). Every row is
/// used by [`MONITOR`], [`WORKER`] or [`ACME`]. `aarch64` never had `poll`,
/// `open`, `rename`, `epoll_wait`, `mkdir`, `unlink`, `stat` or `chmod`,
/// only their `ppoll`/`openat`/`renameat`/`epoll_pwait`/`mkdirat`/
/// `unlinkat`/`newfstatat`/`fchmodat` forms. The C4 rows (`flock` and
/// `chmod`) were read from the `x86_64` `<asm/unistd_64.h>` and
/// `<asm-generic/unistd.h>` of the build container (Ubuntu 24.04). The W1
/// row (`fdatasync`) was read the same way, from the same container: 75
/// and 83.
const SYSCALL_NUMBERS: &[(&str, i64, i64)] = &[
    ("read", 0, 63),
    ("write", 1, 64),
    ("close", 3, 57),
    ("fstat", 5, 80),
    ("lseek", 8, 62),
    ("mmap", 9, 222),
    ("mprotect", 10, 226),
    ("munmap", 11, 215),
    ("brk", 12, 214),
    ("futex", 202, 98),
    ("rt_sigaction", 13, 134),
    ("rt_sigprocmask", 14, 135),
    ("pread64", 17, 67),
    ("pwrite64", 18, 68),
    ("madvise", 28, 233),
    ("mremap", 25, 216),
    ("fcntl", 72, 25),
    ("fsync", 74, 82),
    ("fdatasync", 75, 83),
    ("fchmod", 91, 52),
    ("fchown", 93, 55),
    ("getpid", 39, 172),
    ("sendto", 44, 206),
    ("recvfrom", 45, 207),
    ("shutdown", 48, 210),
    ("setsockopt", 54, 208),
    ("clock_gettime", 228, 113),
    ("poll", 7, -1),
    ("restart_syscall", 219, 128),
    ("getrandom", 318, 278),
    ("sigaltstack", 131, 132),
    ("rt_sigreturn", 15, 139),
    ("gettid", 186, 178),
    ("exit", 60, 93),
    ("exit_group", 231, 94),
    ("wait4", 61, 260),
    ("open", 2, -1),
    ("openat", 257, 56),
    ("renameat", 264, 38),
    ("linkat", 265, 37),
    ("unlinkat", 263, 35),
    ("mkdirat", 258, 34),
    ("getdents64", 217, 61),
    ("fchmodat", 268, 53),
    ("fgetxattr", 193, 10),
    ("fsetxattr", 190, 7),
    ("flistxattr", 196, 13),
    ("lgetxattr", 192, 9),
    ("lsetxattr", 189, 6),
    ("statfs", 137, 43),
    ("faccessat", 269, 48),
    ("newfstatat", 262, 79),
    ("statx", 332, 291),
    ("rseq", 334, 293),
    ("set_robust_list", 273, 99),
    ("sched_getaffinity", 204, 123),
    ("socketpair", 53, 199),
    ("clone", 56, 220),
    ("clone3", 435, 435),
    ("epoll_create1", 291, 20),
    ("epoll_ctl", 233, 21),
    ("epoll_pwait", 281, 22),
    ("eventfd2", 290, 19),
    ("socket", 41, 198),
    ("bind", 49, 200),
    ("listen", 50, 201),
    ("getsockname", 51, 204),
    ("accept4", 288, 242),
    ("writev", 20, 66),
    ("execve", 59, 221),
    ("execveat", 322, 281),
    ("pipe2", 293, 59),
    ("dup", 32, 23),
    ("dup3", 292, 24),
    ("dup2", 33, -1),
    ("arch_prctl", 158, -1),
    ("access", 21, -1),
    ("readlink", 89, -1),
    ("readlinkat", 267, 78),
    ("ppoll", 271, 73),
    ("kill", 62, 129),
    ("tgkill", 234, 131),
    ("nanosleep", 35, 101),
    ("clock_nanosleep", 230, 115),
    ("prlimit64", 302, 261),
    ("set_tid_address", 218, 96),
    ("connect", 42, 203),
    ("getsockopt", 55, 209),
    ("getpeername", 52, 205),
    ("recvmsg", 47, 212),
    ("sendmmsg", 307, 269),
    ("rename", 82, -1),
    ("epoll_wait", 232, -1),
    ("mkdir", 83, -1),
    ("unlink", 87, -1),
    ("stat", 4, -1),
    ("flock", 73, 32),
    ("chmod", 90, -1),
];

/// `name`'s raw syscall number on `arch`, or `None` if it is not in
/// `SYSCALL_NUMBERS` for that architecture (`poll` has no `aarch64` number:
/// `aarch64` only ever had `ppoll`).
#[must_use]
fn number(name: &str, arch: Arch) -> Option<i64> {
    let (_, x86_64, aarch64) = SYSCALL_NUMBERS.iter().find(|(n, ..)| *n == name)?;
    let raw = match arch {
        Arch::X86_64 => *x86_64,
        Arch::Aarch64 => *aarch64,
    };
    (raw >= 0).then_some(raw)
}

/// The raw syscall numbers `role` needs on `arch`. Pure data: no dependency
/// on `seccompiler`, so this — unlike `compile` — runs on every platform.
///
/// # Errors
///
/// [`SeccompError::UnknownSyscall`] (see `SYSCALL_NUMBERS`'s doc comment).
pub fn numbers_for(role: Role, arch: Arch) -> Result<Vec<i64>, SeccompError> {
    let mut numbers = Vec::new();
    for name in syscalls_for(role) {
        if let Some(number) = number(name, arch) {
            numbers.push(number);
        } else if !SYSCALL_NUMBERS.iter().any(|(known, _, _)| *known == *name) {
            return Err(SeccompError::UnknownSyscall((*name).to_owned()));
        }
    }
    Ok(numbers)
}

/// Build a real `seccompiler::BpfProgram` for `role` on `arch`, without
/// installing it.
///
/// # Errors
///
/// [`SeccompError::UnknownSyscall`] via [`numbers_for`], or
/// [`SeccompError::Build`] when `seccompiler` rejects the filter.
#[cfg(target_os = "linux")]
pub fn compile(
    role: Role,
    arch: Arch,
    mode: SeccompMode,
) -> Result<seccompiler::BpfProgram, SeccompError> {
    use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;

    let target = match arch {
        Arch::X86_64 => TargetArch::x86_64,
        Arch::Aarch64 => TargetArch::aarch64,
    };
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for number in numbers_for(role, arch)? {
        rules.insert(number, Vec::new());
    }
    let default_action = match mode {
        SeccompMode::Log => SeccompAction::Log,
        SeccompMode::Enforce => match role {
            // A privileged, single-threaded, no-thread process taking a
            // syscall its own tiny allow-list did not predict is a serious
            // enough event to end it outright: there is no partial state
            // worth preserving, and no library code downstream that might
            // recover gracefully from an unexpected `EPERM`.
            Role::Monitor => SeccompAction::KillProcess,
            // The worker will eventually run TLS/HTTP/ACME library code
            // (Phase 4) that may already handle an unexpected `EPERM` (e.g.
            // treating an unavailable optional syscall as "not supported")
            // more gracefully than being killed outright; `Errno` keeps that
            // option open without weakening what is actually allowed.
            Role::Worker | Role::Acme => SeccompAction::Errno(EPERM),
        },
    };
    let filter = SeccompFilter::new(rules, default_action, SeccompAction::Allow, target)
        .map_err(|err| SeccompError::Build(err.to_string()))?;
    seccompiler::BpfProgram::try_from(filter).map_err(|err| SeccompError::Build(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{Arch, Role, SeccompError, numbers_for, syscalls_for};

    #[test]
    fn arch_parses_the_two_tier_one_names_and_rejects_others() {
        assert_eq!(Arch::parse("x86_64"), Ok(Arch::X86_64));
        assert_eq!(Arch::parse("aarch64"), Ok(Arch::Aarch64));
        assert_eq!(
            Arch::parse("armv7"),
            Err(SeccompError::UnsupportedArch("armv7".to_owned()))
        );
        assert_eq!(
            Arch::parse("riscv64"),
            Err(SeccompError::UnsupportedArch("riscv64".to_owned()))
        );
        // `Arch::host()` reflects whichever tier-one arch actually runs this
        // test; CI only ever runs on x86_64 or aarch64.
        assert!(Arch::host().is_ok());
    }

    #[test]
    fn every_table_entry_resolves_or_is_arch_specific() -> Result<(), Box<dyn std::error::Error>> {
        for role in [Role::Monitor, Role::Worker, Role::Acme] {
            let names = syscalls_for(role);
            assert!(!names.is_empty());
            for arch in [Arch::X86_64, Arch::Aarch64] {
                let numbers = numbers_for(role, arch)?;
                assert!(
                    !numbers.is_empty(),
                    "{role:?} resolves to nothing on {arch:?}"
                );
                assert!(numbers.len() <= names.len());
                for name in names {
                    assert!(
                        super::number(name, Arch::X86_64).is_some()
                            || super::number(name, Arch::Aarch64).is_some(),
                        "{name} resolves on neither tier-one arch"
                    );
                }
                // Every resolved number is a plausible Linux syscall number:
                // non-negative, and distinct entries resolve to distinct
                // numbers (a collision would mean two different syscalls
                // were accidentally allow-listed as one).
                let mut sorted = numbers.clone();
                sorted.sort_unstable();
                sorted.dedup();
                assert_eq!(
                    sorted.len(),
                    numbers.len(),
                    "{arch:?} has a duplicate number"
                );
                assert!(numbers.iter().all(|n| *n >= 0));
            }
        }
        Ok(())
    }

    #[test]
    fn the_two_tables_share_every_ipc_and_runtime_housekeeping_syscall() {
        // Phase 2's observation (`the worker table will grow independently
        // once Phase 4 adds TLS/HTTP`, in the comment this test used to
        // carry) came true: the worker now needs `clone`/`socket`/`epoll_*`
        // for its `tokio`-driven HTTP server, none of which the
        // single-threaded, network-free monitor touches, so a strict-subset
        // relationship no longer holds. What still must hold is that neither
        // table lost the privsep-channel and allocator/runtime syscalls both
        // roles share — a regression there would be a much quieter break
        // than the compile-time table-correctness checks above would catch.
        let monitor: std::collections::BTreeSet<_> = syscalls_for(Role::Monitor).iter().collect();
        let worker: std::collections::BTreeSet<_> = syscalls_for(Role::Worker).iter().collect();
        for shared in [
            "read",
            "write",
            "close",
            "futex",
            "mmap",
            "munmap",
            "clock_gettime",
            "getrandom",
            "rt_sigaction",
            "getpid",
            "exit_group",
        ] {
            assert!(monitor.contains(&shared), "monitor lost {shared}");
            assert!(worker.contains(&shared), "worker lost {shared}");
        }
    }

    /// ADR-015: the acme process is an outbound client only. It can open a
    /// connection and has nothing that accepts one (`bind` is allowed for
    /// musl's resolver, see the module docs); the worker and the monitor
    /// still cannot connect out.
    #[test]
    fn the_acme_table_connects_out_and_never_accepts() {
        let acme = syscalls_for(Role::Acme);
        for needed in ["socket", "connect", "getsockopt", "getpeername", "ppoll"] {
            assert!(acme.contains(&needed), "acme table lacks {needed}");
            assert!(super::number(needed, Arch::X86_64).is_some());
            assert!(super::number(needed, Arch::Aarch64).is_some());
        }
        for server_only in ["listen", "accept4"] {
            assert!(!acme.contains(&server_only), "acme table has {server_only}");
        }
        for role in [Role::Worker, Role::Monitor] {
            assert!(
                !syscalls_for(role).contains(&"connect"),
                "{role:?} can connect"
            );
        }
    }

    /// C4: the `x86_64` legacy forms the live `serve` trace showed resolve on
    /// `x86_64` only, next to their `*at` forms on both arches; `flock`
    /// resolves on both.
    #[test]
    fn the_monitor_and_worker_tables_carry_the_traced_legacy_forms() {
        let monitor = syscalls_for(Role::Monitor);
        let worker = syscalls_for(Role::Worker);
        for (table, x86_64_only, both) in [
            (monitor, "mkdir", "mkdirat"),
            (worker, "mkdir", "mkdirat"),
            (worker, "chmod", "fchmodat"),
            (worker, "unlink", "unlinkat"),
            (worker, "open", "openat"),
            (worker, "epoll_wait", "epoll_pwait"),
        ] {
            assert!(table.contains(&x86_64_only), "lacks {x86_64_only}");
            assert!(table.contains(&both), "lacks {both}");
            assert!(super::number(x86_64_only, Arch::X86_64).is_some());
            assert!(super::number(x86_64_only, Arch::Aarch64).is_none());
            assert!(super::number(both, Arch::Aarch64).is_some());
        }
        assert!(monitor.contains(&"flock"));
        assert_eq!(super::number("flock", Arch::X86_64), Some(73));
        assert_eq!(super::number("flock", Arch::Aarch64), Some(32));
        assert_eq!(super::number("chmod", Arch::X86_64), Some(90));
        // Refused in the worker and tolerated, never allowed.
        assert!(!worker.contains(&"prctl") && !worker.contains(&"access"));
    }

    /// W1: `fdatasync` (the audit writers' `File::sync_data()`) resolves on
    /// both tier-one arches, unlike the legacy forms above.
    #[test]
    fn the_worker_table_allows_fdatasync_on_both_arches() {
        assert!(syscalls_for(Role::Worker).contains(&"fdatasync"));
        assert_eq!(super::number("fdatasync", Arch::X86_64), Some(75));
        assert_eq!(super::number("fdatasync", Arch::Aarch64), Some(83));
    }

    /// The credentials store calls (slice C3b): each `x86_64` form has no
    /// `aarch64` number, and the table also lists the `aarch64` form.
    #[test]
    fn the_acme_table_writes_credentials_on_both_arches() {
        let acme = syscalls_for(Role::Acme);
        for (x86_64_only, both) in [
            ("mkdir", "mkdirat"),
            ("unlink", "unlinkat"),
            ("rename", "renameat"),
            ("stat", "newfstatat"),
        ] {
            assert!(
                acme.contains(&x86_64_only),
                "acme table lacks {x86_64_only}"
            );
            assert!(acme.contains(&both), "acme table lacks {both}");
            assert!(super::number(x86_64_only, Arch::X86_64).is_some());
            assert!(super::number(x86_64_only, Arch::Aarch64).is_none());
            assert!(super::number(both, Arch::Aarch64).is_some());
        }
        for needed in ["getpid", "statx", "fsync", "openat"] {
            assert!(acme.contains(&needed), "acme table lacks {needed}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_role_compiles_on_both_arches() -> Result<(), SeccompError> {
        for role in [Role::Monitor, Role::Worker, Role::Acme] {
            for arch in [Arch::X86_64, Arch::Aarch64] {
                for mode in [super::SeccompMode::Enforce, super::SeccompMode::Log] {
                    assert!(!super::compile(role, arch, mode)?.is_empty());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn unknown_syscall_names_are_reported_rather_than_panicking() {
        assert_eq!(super::number("not-a-real-syscall", Arch::X86_64), None);
        assert_eq!(super::number("poll", Arch::Aarch64), None);
        assert!(super::number("poll", Arch::X86_64).is_some());
    }

    #[test]
    fn monitor_table_allows_process_creation_on_both_arches() {
        for name in [
            "clone", "clone3", "execve", "execveat", "pipe2", "dup3", "kill", "tgkill",
        ] {
            assert!(
                syscalls_for(Role::Monitor).contains(&name),
                "monitor table is missing {name}"
            );
            assert!(
                super::number(name, Arch::X86_64).is_some(),
                "{name} has no x86_64 number"
            );
            assert!(
                super::number(name, Arch::Aarch64).is_some(),
                "{name} has no aarch64 number"
            );
        }
        for name in ["dup2", "arch_prctl", "access", "readlink", "poll", "open"] {
            assert!(syscalls_for(Role::Monitor).contains(&name));
            assert!(super::number(name, Arch::X86_64).is_some());
            assert!(super::number(name, Arch::Aarch64).is_none());
        }
        for name in ["readlinkat", "ppoll"] {
            assert!(syscalls_for(Role::Monitor).contains(&name));
            assert!(super::number(name, Arch::X86_64).is_some());
            assert!(super::number(name, Arch::Aarch64).is_some());
        }
    }

    #[test]
    fn errors_carry_their_detail_in_display() {
        assert!(
            SeccompError::UnsupportedArch("armv7".to_owned())
                .to_string()
                .contains("armv7")
        );
        assert!(
            SeccompError::UnknownSyscall("bogus".to_owned())
                .to_string()
                .contains("bogus")
        );
        assert!(
            SeccompError::Build("x".to_owned())
                .to_string()
                .contains('x')
        );
        assert!(
            SeccompError::Install("y".to_owned())
                .to_string()
                .contains('y')
        );
    }
}
