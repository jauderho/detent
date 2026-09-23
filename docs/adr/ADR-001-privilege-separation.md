# ADR-001: Privilege separation, OpenSSH style
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

`detent` runs as a network-facing daemon that must edit root-owned config files
and control system services on Linux and BSD hosts. A single privileged process
handling TLS, HTTP, and ACME directly would put all of that attack surface at
full privilege. The daemon must also work without a systemd dependency, since
tier-2 targets are BSD (§2.1, §2.4).

## Decision

One binary splits into a small privileged **monitor** and an unprivileged
**worker**, joined by a `socketpair(AF_UNIX, SOCK_SEQPACKET)`, exchanging a
fixed, versioned, `postcard`-encoded message protocol. The monitor never runs
tokio, TLS, or HTTP; it only serves a closed request set (`ReadTarget`,
`WriteTarget`, `RunCheck`, `Service`, `ListBackups`, `Restore`, `Mount`,
`ReplaceBinary`, `Shutdown`) indexed by allow-listed ids computed at startup
from enabled modules — no path, unit name, or program name ever crosses the
socket (§2.4, Appendix B). The worker holds all network-facing code (TLS,
HTTP, ACME, update, UI) and drops to an unprivileged user, capabilities, and
sandboxing after fork. No setuid binary is used.

## Consequences

Positive:
 - Confines the network-facing code (TLS/HTTP/ACME) to the unprivileged side;
   a remote compromise of the worker cannot request paths outside the
   allow-list. It CAN still gain root through content: allow-listed targets
   include root-execution vectors (smb.conf `root preexec`, dnsmasq
   `dhcp-script`, `/etc/fstab`, `/etc/exports` `no_root_squash`, ifupdown `up`
   lines), and the monitor writes worker-supplied bytes without content
   validation (STAGE3 H23 step 2, not yet built).

Negative:
- Two-process architecture adds IPC overhead and a protocol to version and
  fuzz (`fuzz_privsep_decode`, per Phase 2).
- Fork-based startup requires care: `CAP_SETUID`/`CAP_SETGID` are needed once
  to drop the worker and must be removed from the monitor's bounding set
  afterward (Appendix C).
- Debugging spans two processes and a serialized protocol instead of one.

## Alternatives considered

- Setuid binary — rejected: the decision explicitly states "No setuid" (§1.3).
- Single privileged process handling network I/O directly — rejected: this is
  the situation privilege separation is designed to avoid; it does not confine
  the network-facing code (§2.4 rationale).

## References

PLAN.md §1.3 (ADR-001 row), §2.1, §2.4, Appendix B, Appendix C.
