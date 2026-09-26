//! `detent`: the command-line front end (PLAN §2.6, Phase 3 task 3).
//!
//! ```text
//! argv ──▶ cli (clap)  ──▶ run  ──▶ Operation ──▶ OpsEngine ──▶ monitor
//!                           │                         │
//!                           └──▶ output ◀─── OpOutcome ┘
//! ```
//!
//! * [`cli`] is the command tree and nothing else;
//! * [`run`] turns one parsed command into one [`detent_ops::Operation`], starts
//!   the privsep monitor it needs, and executes it;
//! * [`output`] renders the result, as pretty JSON under `--json` or as
//!   localized text otherwise;
//! * [`doctor`], [`serve`] and [`completions`] are the commands that do not
//!   go through the operations layer, each for a documented reason;
//! * [`webadmin`] (feature `web`) is `setup`, `user` and `token`: thin
//!   wrappers over `detent-web`'s own account and token stores, bypassing the
//!   operations layer entirely, since neither is a privileged target any
//!   module declares.
//!
//! # Every user-facing string is a Fluent id
//!
//! PLAN §4.3 admits no hardcoded English in an output path, and
//! `no_bare_english_in_output` (in this module) fails the build if one appears
//! in a `println!`/`eprintln!`/`write!` in this crate. The single documented
//! exception is clap's own `--help`/`--version` text, which is fixed at type
//! definition time, long before a locale exists; see [`cli`].
//!
//! # Exit codes
//!
//! `0` success, `1` the operation failed, `2` usage error, `3` permission or
//! privilege problem. Also in `detent --help` and in [`output::Exit`].
//!
//! # Out of scope for this task
//!
//! PLAN §2.6 also lists `install`, `cert` and `update`. `install` would
//! duplicate `packaging/install.sh`; the rest front operations (`CertStatus`,
//! `UpdateCheck`) that `detent-ops` deliberately does not define yet
//! (`detent_ops::op`).

// Both crypto features may be enabled (so `--all-features` builds); when both
// are present `crypto-aws-lc` takes precedence, mirroring rustls' own policy.
//
// Gated on `web`, because that is the only thing a rustls provider is for. A
// CLI build with the TLS stack switched off — PLAN §4.1's third size row —
// otherwise had to name a provider it would never link, which is a confusing
// demand to make of somebody trying to build the smallest binary.
#[cfg(all(
    feature = "web",
    not(any(feature = "crypto-aws-lc", feature = "crypto-ring"))
))]
compile_error!("the `web` feature needs one of crypto-aws-lc or crypto-ring");

mod cli;
mod completions;
mod doctor;
mod i18n;
#[cfg(feature = "mcp")]
mod mcp;
mod output;
mod run;
mod serve;
#[cfg(test)]
mod tests_support;
#[cfg(feature = "web")]
mod webadmin;

use std::io::Write as _;
use std::process::ExitCode;

use clap::Parser as _;

use crate::cli::Cli;
use crate::run::Streams;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // clap owns this text (see `cli`): `--help` and `--version` are a
            // successful run, anything else is a usage error.
            let _ = error.print();
            return ExitCode::from(if error.use_stderr() {
                output::Exit::Usage.code()
            } else {
                output::Exit::Ok.code()
            });
        }
    };
    let mut input = std::io::stdin();
    let mut out = std::io::stdout();
    let mut notes = std::io::stderr();

    let exit = run::run(
        &cli,
        &mut Streams {
            input: &mut input,
            out: &mut out,
            notes: &mut notes,
        },
    );
    let _ = out.flush();
    let _ = notes.flush();
    ExitCode::from(exit.code())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    type R = Result<(), Box<dyn std::error::Error>>;

    /// Every `.rs` file in this crate's `src/`.
    fn sources() -> Result<Vec<(PathBuf, String)>, std::io::Error> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(root)? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                let text = std::fs::read_to_string(&path)?;
                out.push((path, text));
            }
        }
        assert!(out.len() >= 8, "the source walk found almost nothing");
        Ok(out)
    }

    /// The part of a line before `//`, so a comment never trips the scanners.
    fn code_of(line: &str) -> &str {
        line.split("//").next().unwrap_or("")
    }

    /// The id prefix, assembled so this file's own scanner cannot match the
    /// literal that describes it.
    const PREFIX: &str = concat!("cli", "-");

    /// PLAN §4.3: no hardcoded user-facing English. A printing macro may only
    /// interpolate an already-localized value, never carry prose of its own, so
    /// its format string must contain no ASCII letters outside `{…}`.
    ///
    /// `completions.rs` is exempt and named here rather than silently skipped:
    /// it emits bash/zsh/fish syntax, which is a program for another program,
    /// not a sentence for a person.
    #[test]
    fn no_bare_english_in_output() -> R {
        for (path, text) in sources()? {
            if path.ends_with("completions.rs") {
                continue;
            }
            // Test modules build their own fixtures and assert on literals.
            // Skip only the test module, which closes the file by convention:
            // a `#[cfg(test)]` on one helper above production code must not
            // hide the rest of the file from the scan.
            let code = text.split("#[cfg(test)]\nmod ").next().unwrap_or("");
            for (number, line) in code.lines().enumerate() {
                let Some(rest) = [
                    "println!(",
                    "eprintln!(",
                    "print!(",
                    "eprint!(",
                    "write!(",
                    "writeln!(",
                ]
                .into_iter()
                .find_map(|name| code_of(line).split_once(name))
                .map(|(_, rest)| rest) else {
                    continue;
                };
                let Some(literal) = rest.split('"').nth(1) else {
                    continue;
                };
                let prose: String = literal
                    .split('{')
                    .filter_map(|chunk| chunk.split('}').next_back())
                    .collect();
                assert!(
                    !prose.chars().any(|c| c.is_ascii_alphabetic()),
                    "{}:{} prints hardcoded text: {literal:?}",
                    path.display(),
                    number.saturating_add(1),
                );
            }
        }
        Ok(())
    }

    /// Every CLI id the crate uses is defined in `locales/en-US/cli.ftl`, and
    /// every id defined there is used. A missing id renders as itself at a user;
    /// an unused one is a translation somebody wrote for nothing.
    #[test]
    fn cli_message_ids_and_the_catalogue_agree() -> R {
        let needle = format!("MessageId::new({}", '"');
        let mut used: BTreeSet<String> = BTreeSet::new();
        for (_, text) in sources()? {
            for (index, _) in text.match_indices(&needle) {
                let rest = text
                    .get(index.saturating_add(needle.len())..)
                    .unwrap_or_default();
                if let Some(id) = rest.split('"').next().filter(|id| id.starts_with(PREFIX)) {
                    used.insert(id.to_owned());
                }
            }
        }
        let defined: BTreeSet<String> = crate::i18n::CLI_FTL
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, _)| key.trim().to_owned())
            .filter(|key| key.starts_with(PREFIX))
            .collect();

        assert!(used.contains("cli-no-command"));
        assert!(defined.contains("cli-no-command"));
        let missing: Vec<&String> = used.difference(&defined).collect();
        let unused: Vec<&String> = defined.difference(&used).collect();
        assert!(missing.is_empty(), "undefined in cli.ftl: {missing:?}");
        assert!(unused.is_empty(), "defined but never used: {unused:?}");
        Ok(())
    }
}
