# Contributing to detent

See `AGENTS.md` for the full behavioral and coding contract. This file is the
short version for getting a change merged.

## Toolchain

- Rust: current stable; `rust-toolchain.toml` sets `channel = "stable"`
  (owner decision 2026-10-31, `docs/DECISIONS.md`). Run `rustup update stable`
  before you check a change. The minimum version is `rust-version` in
  `Cargo.toml`.
- Web: `bun` for package management and scripts; `biome` for lint/format.
- Do not add a dependency from an ecosystem outside `deny.toml`'s allow-list
  without discussing it first.

## Running checks locally

Rust:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check
```

Web:

```sh
cd web && bun run lint && bun run test
```

All of the above run in CI on every PR; a PR is not mergeable until they are
green.

## Commit rules (from `AGENTS.md`)

- Sign commits: `git commit -S -s`, SSH signing.
- One logical change per commit.
- Imperative, ASD-STE100-style commit messages: short sentences, only the
  necessary information, no mannered prose.

## Pull request expectations

Per `docs/PLAN.md` §6.5, a PR description includes:

- The phase/task id it addresses (if working from `docs/PLAN.md`).
- Acceptance evidence: the command you ran and its output, not a summary
  that a check passed.
- Coverage delta and size delta, where the change touches code covered by
  those gates.
- Any `docs/adr/` references the change relies on or affects.

## Supply-chain cooldown

New dependency versions (Cargo, Bun, GitHub Actions) are subject to a 7-day
cooldown before use. The Rust toolchain is not: it follows stable (owner
decision 2026-10-31) — see `docs/adr/ADR-011-supply-chain-cooldown.md`.
Security advisories bypass the cooldown; nothing else does.

## Adding a module or a translation

- Adding a config module: follow `docs/MODULE_GUIDE.md` and the checklist in
  `docs/PLAN.md` Appendix A.
- Adding or updating a translation: follow `docs/TRANSLATING.md`.

## Architecture decisions

Binding architectural decisions live in `docs/adr/`. Read the ones relevant
to what you're changing before you start. Changing a decision requires a new,
superseding ADR — see `docs/adr/README.md`.
