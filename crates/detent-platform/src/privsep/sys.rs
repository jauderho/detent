//! The only `unsafe` in the privsep layer, isolated in one small module.
//!
//! Everything else in `privsep` is safe Rust over `rustix` and `std`. Four
//! POSIX calls have no safe wrapper anywhere in the dependency set allowed for
//! this crate:
//!
//! | call | why `rustix` cannot supply it |
//! |---|---|
//! | `fork` | `rustix` exposes only `runtime::kernel_fork`, which is Linux-only, `doc(hidden)`, and documented as undefined behaviour in a process that links libc |
//! | `setgroups` | not wrapped by `rustix` 1.1 |
//! | `setgid` | not wrapped by `rustix` 1.1 |
//! | `setuid` | not wrapped by `rustix` 1.1 |
//! | `_exit` | `std::process::exit` runs `atexit` handlers, which is not async-signal-safe in a forked child |
//!
//! They are declared here rather than by taking a dependency on `libc`, so the
//! crate's dependency set stays exactly what PLAN §4.2 allows. The declarations
//! are the POSIX signatures, and the argument-type difference in `setgroups`
//! between Linux (`size_t`) and macOS (`int`) is spelled out per platform
//! rather than assumed.
//!
//! `#[allow(unsafe_code)]` is applied to the module as a whole precisely so
//! that a reviewer auditing `unsafe` in this crate has one 60-line file to
//! read: every `unsafe` block below carries its own `// SAFETY:` note.
#![allow(unsafe_code)]

use std::ffi::c_int;

#[cfg(target_os = "linux")]
type GroupCount = usize;
#[cfg(not(target_os = "linux"))]
type GroupCount = c_int;

unsafe extern "C" {
    fn fork() -> c_int;
    fn setgroups(size: GroupCount, list: *const u32) -> c_int;
    fn setgid(gid: u32) -> c_int;
    fn setuid(uid: u32) -> c_int;
    fn _exit(status: c_int) -> !;
}

/// Which side of a [`fork_process`] this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The original process; carries the child's pid.
    Parent(i32),
    /// The new process.
    Child,
}

/// `fork(2)`.
///
/// # Safety
///
/// The caller must treat the child as async-signal-safe territory: in a
/// multi-threaded parent, only the calling thread survives, so the child must
/// not touch a lock another thread held at fork time. `detent`'s monitor forks
/// before starting any runtime or thread pool, which is why the split happens
/// first in `main`.
///
/// # Errors
///
/// [`std::io::Error`] from `errno` when the fork fails.
pub unsafe fn fork_process() -> std::io::Result<Side> {
    // SAFETY: `fork` takes no arguments and touches no memory this process
    // owns. The only hazard is what happens *after* it returns in the child,
    // which is the caller's obligation, documented above and enforced by this
    // function being `unsafe`.
    let pid = unsafe { fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        Ok(Side::Child)
    } else {
        Ok(Side::Parent(pid))
    }
}

/// `setgroups(0, NULL)`, `setgid(gid)`, `setuid(uid)`, in that order.
///
/// The order matters: dropping the group list and the gid must happen while
/// the process is still privileged, so this sequence is irreversible only
/// after the final `setuid`.
///
/// # Errors
///
/// [`std::io::Error`] from `errno` at the first call that fails, so a partial
/// drop is always reported rather than silently accepted.
pub fn drop_to(uid: u32, gid: u32) -> std::io::Result<()> {
    // SAFETY: `setgroups(0, NULL)` is the documented way to clear the
    // supplementary group list; POSIX permits a null pointer when the count is
    // zero, so no memory is dereferenced. `setgid` and `setuid` take scalars
    // and dereference nothing. Each return value is checked before the next
    // call, so the process can never end up with a dropped uid but an intact
    // group list.
    unsafe {
        if setgroups(0, std::ptr::null()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if setgid(gid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if setuid(uid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// `_exit(2)`: terminate immediately, without unwinding, flushing, or running
/// `atexit` handlers.
///
/// This is what a forked child must use when it decides not to continue: the
/// handlers registered in the parent belong to the parent's state.
pub fn exit_immediately(status: c_int) -> ! {
    // SAFETY: `_exit` is async-signal-safe by definition and never returns.
    // It takes a scalar and dereferences nothing.
    unsafe { _exit(status) }
}
