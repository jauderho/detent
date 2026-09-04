//! Privilege separation: a small privileged monitor and an unprivileged worker
//! joined by a socket pair (PLAN §2.4, Appendix B; ADR-001).
//!
//! The monitor owns every write to a root-owned file and every service action.
//! It answers only the closed request set in [`proto`], and every request
//! selects an entry of an allow-list table the monitor builds itself at startup
//! from the compiled-in module descriptors — no path, unit name, or program
//! name ever crosses the socket from worker to monitor.

pub mod allowlist;
pub mod monitor;
pub mod proto;
pub mod spawn;
pub mod transport;
pub mod users;
pub mod worker;

mod sys;
