# Module guide

The authoritative walkthrough for adding a config module to `detent`, written
against the reference module `crates/modules/hosts/` and the copy-me skeleton
`crates/modules/_template/`. `docs/PLAN.md` §2.3 defines the trait and the six
invariants; Appendix A is the checklist this guide is written against.

## 1. What a module is

A module is one crate under `crates/modules/<id>/` exposing a single type that
implements `detent_core::module::ConfigModule`: a **lossless** parser and
renderer for one config file format, a typed model exported as JSON Schema, a
validator that returns Fluent message ids, secure per-host defaults, and static
metadata (the files it owns, the upstream project it tracks, the services it
affects, the external validator that checks a candidate file). One crate per
module is [ADR-004](adr/ADR-004-one-crate-per-module.md): it gives each module
its own feature flag, its own fuzz targets, and a compilation boundary a parser
bug cannot cross. Losslessness is [ADR-008](adr/ADR-008-lossless-document-model.md):
comments, whitespace, ordering and unrecognized directives all survive an edit,
because the admin hand-edited this file and the diff shown before Apply must be
the truth. Modules never do I/O, never spawn threads and contain no `unsafe`;
`detent-platform` owns every file operation.

## 2. Anatomy of the hosts module

```
crates/modules/hosts/
├── Cargo.toml            # deps, [lints] workspace = true, `fuzzing` feature
├── upstream.toml         # tracked upstream project + version + fixture dirs
├── src/lib.rs            # model, parser, descriptor, hints, validate, defaults, unit tests
└── tests/conformance.rs  # module_conformance! + fixture expectations
fixtures/hosts/…          # real upstream samples, one dir per version/platform
fuzz/fuzz_targets/fuzz_hosts_{parse,roundtrip,edit}.rs
locales/en-US/core.ftl    # every MessageId the crate constructs
```

**`Cargo.toml`** is boilerplate apart from the name and description. Two lines
matter: `[lints] workspace = true` (the pedantic/`unwrap_used`/`panic`/
`indexing_slicing` set is not optional per crate) and the `fuzzing` feature that
turns on `arbitrary::Arbitrary` for the model types and forwards to
`detent-core/fuzzing`.

**`src/lib.rs`** is ordered model → parsing/rendering → descriptor → schema hints
→ validation → defaults → `impl ConfigModule` → tests. The model is semantics
only:

```rust
pub struct Entry { pub ip: IpAddr, pub hostnames: Vec<String>, pub comment: Option<String> }
```

with `#[serde(deny_unknown_fields)]`, `JsonSchema`, and a doc comment per field.
The parser is two small total functions — `parse_entry` (line → `Option<Entry>`)
and `classify` (line → `LineKind`) — handed to `detent_core::doc::Document`,
which owns the line splitting, the terminators and the spans.
`render_line` is the inverse, and refuses anything that would not survive a
round trip.

**`tests/conformance.rs`** supplies the fixtures, a proptest strategy of valid
models, and the injection probes, then expands
`detent_core::module_conformance!` into the six invariant tests, and asserts the
exact model each fixture parses to.

**`upstream.toml`** is read by `.github/workflows/upstream-watch.yml`; it must
agree with the `Upstream` block in the descriptor.

## 3. Step by step

### 3.1 Copy the template

`crates/modules/_template/README.md` holds the exact recipe; it is one `cp`, one
`mv` loop for the fuzz stubs, one `sed` pass over the copied tree, an append of
`locale-snippet.ftl` to `locales/en-US/core.ftl`, and `cargo fmt`. The template
is excluded from the workspace (`[workspace] exclude` in the root `Cargo.toml`)
so its placeholders never break `cargo build --workspace`; your copy is a member
automatically through the `crates/modules/*` glob. Confirm the exclusion still
holds after any workspace change:

```bash
cargo metadata --format-version 1 | jq '.workspace_members'
```

An unmodified copy passes build, clippy, test and the coverage gate before you
write a line of format code — start from green and keep it green.

### 3.2 Classifier

Every line falls in exactly one of `Blank`, `Comment`, `Directive`, `Unknown`.
The classifier must be a **pure function of the line text**: `Document` re-runs
it after every edit, so context-dependent classification makes `apply`
non-deterministic. `Directive` must mean exactly "the entry parser succeeds",
because `to_model` and `apply` both walk `Directive` lines and invariant 2 fails
the moment they disagree. Anything the module does not model — in `hosts`, a bare
address, a malformed address, an IPv6 address with a zone id (`fe80::1%eth0`) —
is `Unknown` and is copied through untouched.

### 3.3 Model and schema hints

`deny_unknown_fields` everywhere: the JSON reaching `apply` comes from the web
API and the C ABI, and a typo must be a loud `ModelError::Shape`, not a silently
dropped setting. Attach an `x-detent` hint to **every** field with
`descriptor::apply_hints` and a JSON pointer into the generated schema
(`/properties/entries`, `/$defs/Entry/properties/ip`, …). `apply_hints` returns
`false` when the pointer resolves to nothing; the template's
`schema_with_hints_attaches_every_hint` test is what stops a hint from silently
applying to no field.

### 3.4 Descriptor, `upstream.toml`, fixtures

Targets are `&'static` path templates — a request can select a module, never the
file it writes. Give each init system its alternatives (`chronyd.service` **and**
`chrony.service`), and set `commit_confirm: true` only for a module that can lock
the admin out (ADR-012). Fixtures are real upstream files under
`fixtures/<id>/<version>/`, plus an `edge/` directory for the hand-made
adversarial cases: CRLF, no trailing newline, tabs and inline comments, unknown
directives. `hosts` carries seven.

### 3.5 `to_model` and `apply`

`apply` rewrites as little as possible. The template and `hosts` share one
shape, worth copying verbatim:

1. **Pass 1 is read-only.** Pair model entries with existing directive lines in
   order, render only the ones that differ, and collect the results. Rendering
   before mutating means a value rejected under invariant 5 leaves the document
   byte-identical — a half-applied config is worse than a refused one.
2. **A line whose parsed entry already equals the model's is never rendered.**
   That is what preserves hand-aligned columns, and what makes invariant 2 hold:
   `apply(doc, to_model(doc))` must change nothing *and* return
   `EditReport::default()`.
3. **Pass 2 touches only `Directive` lines**, so comments, blanks and unknown
   directives keep their positions, and new lines are inserted after the last
   directive rather than at end of file, so a trailing comment block stays
   trailing.

Two pitfalls the reference module already pays for:

- **Invariant 2 — the classifier round trip.** `Document::replace_raw` re-runs
  the classifier on the text you wrote. If `render_line` can produce a line that
  no longer classifies as `Directive` (a key beginning with `#`, a name
  containing whitespace), the edit vanishes from the next `to_model`. Both
  `hosts` and the template close this by re-parsing the rendered line and
  refusing it with `EditError::Unsupported` when it does not equal the entry it
  came from.
- **Invariant 5 and the `\r` case.** `Document` rejects `\n`, `\r` and NUL in any
  raw line (`check_raw`), and `Document::normalize` repairs the two states an
  edit can leave behind without changing a rendered byte: a line whose text ends
  in `\r` that has just been given an `Lf` terminator is converted to `CrLf`
  (otherwise its rendered text re-parses into a *different* document, breaking
  invariant 4), and a trailing empty line with no terminator is dropped because
  it renders as nothing. A module that writes its own CST instead of reusing
  `detent_core::doc::Document` must reproduce both behaviours — that is the main
  reason to reuse `Document` wherever the format is line-oriented.

### 3.6 `validate`

Findings are `(Severity, MessageId, Option<FieldPath>, Option<Span>, args)` —
never a rendered sentence, because this crate does not localize (ADR-003). Use
`Error` for "must not be applied", `Warning` for "valid but probably not what you
meant", `Recommendation` for "a better option exists". Attach the field path
(`entries/3/hostnames/0`) so the UI can point at the control, and pass every
interpolated value as a **named argument** (`.with_arg("name", …)`) so
translators can reorder them. `ValidationCtx` carries the `HostProfile`; prefer
host-aware findings over warnings that cannot apply to this host.

### 3.7 `defaults`

"Smart, secure defaults for this host" — not an empty model and not upstream's
shipped file. Match on `Os` exhaustively rather than with a `_` arm, so adding a
platform tier is a compile error here instead of a silently wrong file. Whatever
`defaults` returns must pass `validate` with no errors; the template ships that
assertion as a test.

### 3.8 Fluent strings

Every `MessageId` the crate constructs — display name, security notes, tooltips,
recommendations, diagnostics — needs a line in `locales/en-US/core.ftl`, id
prefixed with the module id. The template's `every_message_id_has_a_locale_entry`
test `include_str!`s `core.ftl` and fails on a missing entry; keep it and keep it
complete, it is the only thing standing between a missing string and a raw id in
the UI.

### 3.9 Tests

`detent_core::module_conformance!` generates the six invariants — four of them
also as proptests — from three parameters:

| Parameter | What it takes | Gets it wrong how |
|---|---|---|
| `fixtures` | `&'static str` slices, normally `include_str!` of `fixtures/<id>/…`. The macro does no I/O. They are added to `detent_core::conformance::adversarial_inputs()` (empty input, lone `\r`, NUL, non-ASCII, no trailing newline), so every invariant runs over both sets. | Hand-written "representative" text hides exactly the formatting quirks losslessness has to survive. |
| `model_strategy` | A proptest `Strategy` yielding **valid** models, used by invariants 3 (edit fidelity) and 4 (idempotence). | Those two checks *skip* a model `apply` rejects, so an over-broad strategy makes them silently vacuous. Constrain the generated strings to what the format really accepts. |
| `injection_probes` | Models whose values carry `\n`, `\r`, NUL or a format delimiter; at least one is required. Invariant 5 asserts `apply` refuses every one of them against every fixture. | One probe per *field* that reaches the rendered line, and one per delimiter — a probe only on the comment field proves nothing about the name field. |

Around the macro, add: one test per fixture asserting the exact model it parses
to (round-tripping proves losslessness, not comprehension), an adversarial block
(1 MiB line, 10 000 entries, NUL, CRLF, missing trailing newline), and at least
one test that an edit actually reaches the file — a module that refuses every
edit satisfies all six invariants.

### 3.10 Fuzz targets and corpus

Three targets per module, `fuzz_<id>_{parse,roundtrip,edit}`; the template ships
all three in `crates/modules/<id>/fuzz/`, ready to move into
`fuzz/fuzz_targets/`. Register each with a `[[bin]]` entry and add the module as
a path dependency with `features = ["fuzzing"]` in `fuzz/Cargo.toml`, then seed
`fuzz/corpus/fuzz_<id>_<kind>/` from `fixtures/<id>/`. `fuzz/README.md` has the
details, including the crash-to-regression-test policy (every crash becomes a
named test in the module crate before the fix merges).

```bash
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz build
cargo +nightly fuzz run fuzz_hosts_parse -- -max_total_time=60
```

`cargo fuzz` writes new inputs into `fuzz/corpus/<target>/` as it runs; commit
only curated, minimized seeds.

### 3.11 Registry and feature flag

Module enablement is explicit code, never link-time registration (PLAN §2.2).
In `crates/detent-modules/src/lib.rs` each module contributes one constructor in
two `cfg`-gated halves, and `modules()` flattens them:

```rust
#[cfg(feature = "module-hosts")]
fn hosts() -> Vec<Box<dyn DynModule>> {
    vec![Box::new(detent_core::module::Dyn::<detent_module_hosts::HostsModule>::new())]
}

#[cfg(not(feature = "module-hosts"))]
fn hosts() -> Vec<Box<dyn DynModule>> { Vec::new() }

pub fn modules() -> Vec<Box<dyn DynModule>> { [hosts()].into_iter().flatten().collect() }
```

The halves return a `Vec` rather than an `Option` on purpose: `Option` makes the
enabled half `clippy::unnecessary_wraps`, and pushing under `#[cfg]` into a local
makes that local `unused_mut` in a build with no modules at all — both are
`-D warnings` failures in the feature matrix. Then add the optional dependency
and `module-<id> = ["dep:detent-module-<id>"]` to
`crates/detent-modules/Cargo.toml`, and forward it from the binary in
`crates/detent/Cargo.toml` as `module-<id> = ["detent-modules/module-<id>"]`.
Check a minimal build, not just the full one:

```bash
cargo build -p detent --no-default-features --features "module-hosts,crypto-ring"
cargo test -p detent-modules --features module-hosts
```

### 3.12 Coverage to 100 %

`coverage-baseline.json` requires **100 % lines** for `crates/detent-core/` and
`crates/modules/`. Per module:

```bash
cargo llvm-cov -p detent-module-<id> -p detent-core --all-features \
  --lcov --output-path /tmp/<id>.lcov
scripts/coverage-merge.sh --output /tmp/<id>-merged.info /tmp/<id>.lcov
```

`detent-core` is in the invocation because a slice containing no core lines reads
as 0 % against its per-path minimum. The script prints one line per per-path
entry plus the global line, and exits non-zero on any miss:

```
[coverage-merge] per-path crates/detent-core/: lines 100.00% (min 100%, 922/922 lines)
[coverage-merge] per-path crates/modules/: lines 100.00% (min 100%, 442/442 lines)
[coverage-merge] PASS: all coverage thresholds met
```

To find what is missing, read the LCOV directly — `DA:<line>,<hits>`, so a `,0`
is an uncovered line, and the preceding `SF:` names the file:

```bash
awk '/^SF:/{f=$0} /^DA:.*,0$/{print f, $0}' /tmp/<id>.lcov
cargo llvm-cov -p detent-module-<id> --all-features --summary-only
```

Note that the per-target summary counts one test binary at a time while the merged
LCOV counts per line across the lib tests and the integration tests together — the
merged number is the one the gate uses. The whole workspace at once:

```bash
cargo llvm-cov --workspace --all-features --lcov --output-path /tmp/workspace.lcov
scripts/coverage-merge.sh --output /tmp/ws-merged.info /tmp/workspace.lcov
```

There is no exclusion mechanism: no `LCOV_EXCL`, no `cfg(not(coverage))`. An
uncovered line is either a missing test or dead code, and dead code is deleted —
the template's `parse_setting` carries a comment where an `is_empty` guard used
to be for exactly that reason.

## 4. Checklist (PLAN Appendix A)

- [ ] `crates/modules/<id>/` from `_template`; `Cargo.toml` with `[lints] workspace = true`
- [ ] `upstream.toml` (`tracked_version`, feed, docs) and `fixtures/<id>/<version>/`
- [ ] `Doc` CST: comments/blank/unknown preserved; spans; `render(parse(s)) == s`
- [ ] `Model` with serde + schemars, `deny_unknown_fields`, `x-detent` hints on every field (group, tooltip, recommendation, security_impact, since)
- [ ] `validate`: errors/warnings/recommendations as Fluent ids; injection checks (newline/NUL/delimiters)
- [ ] `defaults(profile)`: secure and smart; explained in `docs/modules/<id>.md`
- [ ] `ExternalCheck` and `ServiceBinding` with alternatives per init
- [ ] `module_conformance!` + adversarial unit tests + proptest strategy
- [ ] fuzz targets `fuzz_<id>_parse|roundtrip|edit` with seeds
- [ ] `locales/en-US/core.ftl` strings (`<id>-field-…`, `<id>-tip-…`, `<id>-rec-…`)
- [ ] feature flag in `detent/Cargo.toml`, registry entry in `detent-modules`
- [ ] 100 % lines; VM check recorded in `docs/spikes/m-<id>.md`

Before opening the PR:

```bash
cargo fmt --all -- --check
cargo build --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## 5. Common mistakes

1. **Reconstructing instead of editing.** Rendering the whole file from the model
   passes invariant 1 only by accident and destroys the admin's formatting. Edit
   the lines that changed and nothing else.
2. **Putting formatting in the model.** Alignment, comment position and blank
   lines belong to the `Doc`. A model field that echoes syntax breaks invariant 2
   the first time someone edits by hand.
3. **Escaping an injected value instead of refusing it.** Invariant 5 says
   reject or quote-per-format, never emit raw. When in doubt, refuse: an
   `EditError` is a visible failure, a smuggled directive is not.
4. **A model strategy that generates values `apply` rejects.** Invariants 3 and 4
   skip rejected models, so the strategy quietly stops testing anything.
5. **Fixtures that are not upstream's.** Hand-written samples encode the author's
   assumptions, which is precisely what the fixture is supposed to challenge.
6. **A validation rule upstream does not have.** A value this module rejects but
   the daemon accepts is a bug report; a value it accepts but the daemon rejects
   is caught only by the `ExternalCheck`, which may not be installed.
7. **A message id with no Fluent entry.** Keep the `include_str!` test.
8. **Reaching for `unwrap`, `expect`, `panic!` or indexing in tests.** The
   workspace lints apply to `--all-targets`; use `Result<(), String>` test
   signatures and `unwrap_or_default`, as `hosts` and the template do.
9. **Leaving `_template` in the workspace.** If `cargo metadata` ever lists it,
   the exclude entry was lost and CI will fail on the placeholders.
