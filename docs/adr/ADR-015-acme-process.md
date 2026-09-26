# ADR-015: The ACME client runs in its own confined process

Status: Accepted (2026-09-26)
Deciders: project owner (chose option (b), 2026-09-26)

## Context

Phase 6 renews the serving certificate by ACME dns-01. The ACME client must
open outbound connections: to the CA, and to the dns-01 provider (HTTPS to
Cloudflare, acme-dns or deSEC; TCP to an RFC 2136 primary). ADR-001 put
ACME in the worker, but the worker's seccomp table has no `connect`
(`crates/detent-platform/src/sandbox/seccomp.rs`, `WORKER`), so the worker
cannot reach any of them. Two ways out were considered:

- (a) Add `connect` and the calls DNS and TLS need to the worker table. The
  network-facing process then gains outbound access, which a remote
  attacker who takes the worker can use to send data out.
- (b) Run the ACME client in a separate process with its own confinement.

## Decision

Option (b). `detent serve` forks one more child, the **acme** process, only
when `[tls] bootstrap = "acme"`:

- **When:** after the runner and before the monitor/worker pair, so neither
  the monitor's nor the worker's confinement reaches it, and the pair
  inherits one end of its channel. The monitor drops that end; the worker
  keeps it.
- **Identity:** it hardens itself (`no_new_privs`, `dumpable = 0`) and drops
  to the worker account, like the worker. `dumpable = 0` stops a same-uid
  process from reading its memory through `/proc/<pid>/mem`; the worker's
  seccomp table has no `ptrace` or `process_vm_readv`.
- **Confinement:** Landlock allows writes only to the directory that holds
  the ACME account credentials (under the state root); reads stay open (CA
  root file, `/etc/resolv.conf`, the served certificate in `cert_dir`). A new
  seccomp role `Acme` allows what an outbound HTTPS/TCP client needs
  (`socket`, `connect`, `getsockopt`, `getpeername`, `poll`/`ppoll`, DNS
  lookup calls) and nothing that accepts connections (`bind`, `listen`,
  `accept4`). Every entry is proven by a live `strace -f` run, as the table
  requires. Default action `Errno(EPERM)`, like the worker.
- **Secrets:** the provider (with its secret from `secrets.toml`) is built in
  the privileged parent before the fork and lives only in the acme process
  after it. The worker and the monitor drop it.
- **Work:** a current-thread runtime runs the renewal loop: order at start
  when the served certificate is the bootstrap one, then check every hour
  (ARI window, else two thirds of the lifetime), with bounded backoff after
  a failure. Expiry warnings at 50 % and 25 % go to the log.
- **Hand-over:** it sends each issued chain and key to the worker over a
  `socketpair` with a small versioned message set (`Install`, and in a later
  slice `RenewNow` and `Status` from the worker). The worker parses the pair,
  checks that it covers the configured domains, stores it with
  `install_acme` (hot swap) and answers. The acme process never writes
  `cert_dir`.
- **Lifetime:** the monitor keeps its pid and reaps it at shutdown. It is not
  restarted if it dies; the worker logs the closed channel and keeps serving
  the last certificate.

## Consequences

Positive:
- The worker keeps no outbound network access.
- The provider secret and the ACME account key live in a process that has no
  listening socket and is not reachable from the network.

Negative:
- A fourth process and a second channel protocol to keep and test.
- The acme process and the worker share a uid: a taken worker can still
  signal (kill) the acme process. That stops renewals, which the expiry
  warnings report; it does not leak the secret.
- The seccomp table for `Acme` must be proven on each tier-1 architecture.

## Supersedes

The ADR-001 sentence that puts ACME in the worker.
