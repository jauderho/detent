# detent fuzz targets

`cargo-fuzz` workspace for detent. Excluded from the main workspace
(`fuzz` is in the root `Cargo.toml` `[workspace] exclude` list) so it can pin
its own toolchain (nightly) and dependency set without affecting the main
build.

## Prerequisites

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
```

## Running one target

```bash
cd fuzz
cargo +nightly fuzz run fuzz_hosts_parse
```

Time-box a run (used in CI: 60 s on PR, 20 min nightly):

```bash
cargo +nightly fuzz run fuzz_hosts_parse -- -max_total_time=60
```

List all targets:

```bash
cargo +nightly fuzz list
```

## Adding a target for a new module

Every module gets three targets, named `fuzz_<id>_<kind>` where `<id>` is the
module's `ConfigModule::ID` (e.g. `hosts`):

| Target | Exercises |
|---|---|
| `fuzz_<id>_parse` | `parse(bytes) -> LosslessDoc` on arbitrary bytes; must never panic. |
| `fuzz_<id>_roundtrip` | `render(parse(s)) == s` for arbitrary valid-ish input. |
| `fuzz_<id>_edit` | parse, apply an arbitrary sequence of model edits, re-render, re-parse; checks losslessness invariants hold under mutation. |

Steps:

1. Add the module crate as a path dependency in `fuzz/Cargo.toml` if it
   is not already present (mirror the `detent-module-hosts` entry).
2. Create `fuzz/fuzz_targets/fuzz_<id>_parse.rs` (and `_roundtrip.rs`,
   `_edit.rs`) using `libfuzzer_sys::fuzz_target!` and `arbitrary::Arbitrary`
   inputs. Register each with a `[[bin]]` entry in `fuzz/Cargo.toml` (`cargo
   fuzz add fuzz_<id>_parse` does this for you).
3. Seed the corpus: `fuzz/corpus/fuzz_<id>_parse/` (and the other two target
   dirs) with representative valid/invalid inputs, e.g. copied from
   `fixtures/<module>/`.
4. Confirm locally: `cargo +nightly fuzz run fuzz_<id>_parse -- -max_total_time=60`
   is clean.
Non-module surfaces (`fuzz_acme_json`, `fuzz_dns_response`) follow steps 2–4
with `detent-acme`'s `fuzzing` feature exposing the parser entry points.

## Corpus location

`fuzz/corpus/<target>/` — one directory per target, committed so CI and
local runs share a starting seed set. `cargo fuzz` grows these directories
during runs; commit only curated/minimized seeds, not every generated case.

## Crash-to-regression-test policy

When a fuzz target finds a crash:

1. `cargo +nightly fuzz run <target> <crash-file>` reproduces it locally.
2. Minimize: `cargo +nightly fuzz tmin <target> <crash-file>`.
3. Copy the minimized input into `fuzz/corpus/<target>/` so it stays covered
   by future runs.
4. Add a regression test in the owning crate (e.g.
   `crates/modules/hosts/tests/`) that feeds the exact minimized bytes
   through the same code path and asserts it no longer panics/fails the
   invariant. The fuzz corpus entry alone is not sufficient — the crate's
   own test suite must fail without the fix.
5. Fix the bug, confirm both the regression test and the fuzz target pass,
   then commit the fix, the regression test, and the corpus entry together.
