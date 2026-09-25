# `_template` — copy-me module crate

The skeleton for a new `detent` config module (PLAN §2.3, ADR-004).
`docs/MODULE_GUIDE.md` is the walkthrough; this file is only the mechanical
instantiation recipe.

`_template` is a workspace member (package `detent-module-template`, matched
by the `crates/modules/*` glob), so workspace builds, lints and tests keep its
code compiling as the core traits change. Your copy is a member too, which is
why the recipe renames the package: two members may not share a name. CI runs
this recipe on a throwaway copy of the tree (`scripts/template-check.sh`) and
tests the result.

## Instantiate

Run from the repository root. `ID` is the module id (`ConfigModule::ID`,
lowercase, no underscores — cargo warns on `[[bin]]` names containing one when
the fuzz targets are registered — and also the `module-<id>` feature name and
the Fluent id prefix); `TYPE` is
the `UpperCamelCase` type name.

```bash
ID=chrony
TYPE=ChronyModule

cp -R crates/modules/_template "crates/modules/${ID}"

for kind in parse roundtrip edit; do
  mv "crates/modules/${ID}/fuzz/fuzz_TEMPLATE_${kind}.rs" \
     "crates/modules/${ID}/fuzz/fuzz_${ID}_${kind}.rs"
done

find "crates/modules/${ID}" -type f \
     \( -name '*.rs' -o -name '*.toml' -o -name '*.ftl' -o -name '*.md' \) -print0 |
  while IFS= read -r -d '' f; do
    sed -e "s/detent-module-template/detent-module-${ID}/g" \
        -e "s/detent_module_template/detent_module_${ID}/g" \
        -e "s/TemplateModule/${TYPE}/g" -e "s/TEMPLATE/${ID}/g" "$f" >"${f}.new"
    mv "${f}.new" "$f"
  done

cat "crates/modules/${ID}/locale-snippet.ftl" >>locales/en-US/core.ftl
rm "crates/modules/${ID}/locale-snippet.ftl" "crates/modules/${ID}/README.md"

mkdir -p "fixtures/${ID}/edge"

cargo fmt -p "detent-module-${ID}"
```

The final `cargo fmt` re-wraps the lines whose width changed with the name: the
template is formatted for the word `TEMPLATE`, your id is a different length.

`sed` applies its rules in order on purpose: the package and crate names
first, then `TemplateModule`, then the bare `TEMPLATE` id. Nothing else in the tree is touched — `locales/en-US/core.ftl`
is the only file outside `crates/modules/${ID}/` the recipe appends to.

## Verify the copy before writing any code

```bash
cargo fmt -p "detent-module-${ID}" -- --check
cargo build -p "detent-module-${ID}"
cargo clippy -p "detent-module-${ID}" --all-targets --all-features -- -D warnings
cargo test -p "detent-module-${ID}" --all-features
cargo llvm-cov -p "detent-module-${ID}" -p detent-core --all-features \
  --lcov --output-path "/tmp/${ID}.lcov"
scripts/coverage-merge.sh --output "/tmp/${ID}-merged.info" "/tmp/${ID}.lcov"
```

All six pass on an unmodified copy. If one fails, the template is broken — fix
the template, not just your copy.

`detent-core` is in the `llvm-cov` invocation because `coverage-baseline.json`
requires 100 % lines for `crates/detent-core/` as well as `crates/modules/`, and
a slice that contains no core lines at all reads as 0 %. `--output` keeps the
merged file out of the repository root, where the workspace-wide run writes its
own `merged.info`.

## Then

1. Work through the `TODO(<id>)` markers in `src/lib.rs`, in file order:
   `doc`, `model`, `parse`, `classify`, `render`, `descriptor`, `hints`,
   `id`, `to-model`, `apply`, `validate`, `defaults`, `fluent`, `upstream`,
   `tests`, `fuzzing`. Each explains *why* the code is shaped the way it is; delete the
   marker once the section is real.
2. Fill in `upstream.toml` and drop real upstream samples into
   `fixtures/<id>/<version>/`, then point `tests/conformance.rs` at them with
   `include_str!` and delete the inline fixture constants.
3. Move the fuzz targets into place and register them:

   ```bash
   mv "crates/modules/${ID}/fuzz/"*.rs fuzz/fuzz_targets/
   rmdir "crates/modules/${ID}/fuzz"
   mkdir -p "fuzz/corpus/fuzz_${ID}_parse" "fuzz/corpus/fuzz_${ID}_roundtrip" \
            "fuzz/corpus/fuzz_${ID}_edit"
   ```

   then add the path dependency and the three `[[bin]]` entries to
   `fuzz/Cargo.toml` (`fuzz/README.md` §"Adding a target for a new module").
4. Register the module: an entry in `crates/detent-modules/src/lib.rs` under
   `#[cfg(feature = "module-<id>")]`, the optional dependency and feature in
   `crates/detent-modules/Cargo.toml`, and `module-<id> =
   ["detent-modules/module-<id>"]` in `crates/detent/Cargo.toml`.
5. Walk Appendix A of `docs/PLAN.md` — it is the definition of done.
