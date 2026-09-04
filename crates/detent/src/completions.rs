//! Shell completion scripts, generated from the clap command tree.
//!
//! `clap_complete` is the obvious way to do this and is not available: PLAN
//! §4.2's dependency policy is expressed through the workspace's
//! `[workspace.dependencies]`, which this crate may only draw from, and
//! `clap_complete` is not in it. The generator here walks the same
//! [`clap::Command`] tree clap already built and emits one word list per command
//! path, which is what a completion script actually needs; the scripts it writes
//! carry no English prose, only shell syntax and the command names themselves.

use std::fmt::Write as _;
use std::io::Write;

use clap::CommandFactory as _;

use crate::cli::{Cli, Shell};

/// Writes the completion script for `shell`.
///
/// # Errors
///
/// Whatever `out` reports.
pub fn write(out: &mut dyn Write, shell: Shell) -> std::io::Result<()> {
    let command = Cli::command();
    let table = table(&command);
    match shell {
        Shell::Bash => bash(out, &table),
        Shell::Zsh => zsh(out, &table),
        Shell::Fish => fish(out, &table),
    }
}

/// One command path and the words that may follow it.
type Table = Vec<(String, Vec<String>)>;

/// Every command path in the tree, with its subcommands and long options.
fn table(root: &clap::Command) -> Table {
    let mut out = Table::new();
    walk(root, "detent", &mut out);
    out
}

/// Depth-first walk, appending one entry per command.
fn walk(command: &clap::Command, path: &str, out: &mut Table) {
    let mut words: Vec<String> = command
        .get_subcommands()
        .map(|sub| sub.get_name().to_owned())
        .collect();
    words.extend(
        command
            .get_arguments()
            .filter_map(clap::Arg::get_long)
            .map(|long| format!("--{long}")),
    );
    words.sort_unstable();
    words.dedup();
    out.push((path.to_owned(), words));
    for sub in command.get_subcommands() {
        walk(sub, &format!("{path} {}", sub.get_name()), out);
    }
}

/// The top-level command names, used by the fish conditions.
fn top_level(table: &Table) -> Vec<String> {
    table
        .iter()
        .filter(|(path, _)| path.split(' ').count() == 2)
        .filter_map(|(path, _)| path.split(' ').nth(1).map(ToOwned::to_owned))
        .collect()
}

/// A `case` arm per command path, shared by the bash and zsh scripts.
fn case_arms(table: &Table) -> String {
    table.iter().fold(String::new(), |mut out, (path, words)| {
        // Writing to a `String` cannot fail.
        let _ = writeln!(
            out,
            "    '{path}') __detent_words=\"{}\" ;;",
            words.join(" ")
        );
        out
    })
}

/// Bash: rebuild the command path from the words typed so far, then complete
/// against that path's word list.
fn bash(out: &mut dyn Write, table: &Table) -> std::io::Result<()> {
    write!(
        out,
        "_detent() {{\n\
         \x20 local cur path i candidate __detent_words\n\
         \x20 cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n\
         \x20 path=\"detent\"\n\
         \x20 for ((i = 1; i < COMP_CWORD; i++)); do\n\
         \x20   case \"${{COMP_WORDS[i]}}\" in -*) continue ;; esac\n\
         \x20   candidate=\"$path ${{COMP_WORDS[i]}}\"\n\
         \x20   case \"$candidate\" in\n{}\
         \x20   *) continue ;;\n\
         \x20   esac\n\
         \x20   path=\"$candidate\"\n\
         \x20 done\n\
         \x20 __detent_words=\"\"\n\
         \x20 case \"$path\" in\n{}\
         \x20 esac\n\
         \x20 COMPREPLY=($(compgen -W \"$__detent_words\" -- \"$cur\"))\n\
         }}\n\
         complete -F _detent detent\n",
        known_paths(table),
        case_arms(table),
    )
}

/// A `case` arm per known path, used to decide whether a word advances the
/// path or is a positional value (a module id, a commit id).
fn known_paths(table: &Table) -> String {
    table
        .iter()
        .filter(|(path, _)| path != "detent")
        .fold(String::new(), |mut out, (path, _)| {
            let _ = writeln!(out, "    '{path}') ;;");
            out
        })
}

/// Zsh: the same table, driven by `compadd`.
fn zsh(out: &mut dyn Write, table: &Table) -> std::io::Result<()> {
    write!(
        out,
        "#compdef detent\n\
         _detent() {{\n\
         \x20 local path candidate word __detent_words\n\
         \x20 path=\"detent\"\n\
         \x20 for word in \"${{words[@]:1:$((CURRENT - 2))}}\"; do\n\
         \x20   case \"$word\" in -*) continue ;; esac\n\
         \x20   candidate=\"$path $word\"\n\
         \x20   case \"$candidate\" in\n{}\
         \x20   *) continue ;;\n\
         \x20   esac\n\
         \x20   path=\"$candidate\"\n\
         \x20 done\n\
         \x20 __detent_words=\"\"\n\
         \x20 case \"$path\" in\n{}\
         \x20 esac\n\
         \x20 compadd -- ${{=__detent_words}}\n\
         }}\n\
         compdef _detent detent\n",
        known_paths(table),
        case_arms(table),
    )
}

/// Fish: one `complete` line per command path.
fn fish(out: &mut dyn Write, table: &Table) -> std::io::Result<()> {
    let tops = top_level(table).join(" ");
    for (path, words) in table {
        if words.is_empty() {
            continue;
        }
        let parts: Vec<&str> = path.split(' ').skip(1).collect();
        let condition = if parts.is_empty() {
            format!("not __fish_seen_subcommand_from {tops}")
        } else {
            parts
                .iter()
                .map(|part| format!("__fish_seen_subcommand_from {part}"))
                .collect::<Vec<_>>()
                .join("; and ")
        };
        writeln!(
            out,
            "complete -c detent -f -n '{condition}' -a '{}'",
            words.join(" ")
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Shell, case_arms, table, top_level, write};
    use clap::CommandFactory as _;

    type R = Result<(), Box<dyn std::error::Error>>;

    fn script(shell: Shell) -> Result<String, Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        write(&mut out, shell)?;
        Ok(String::from_utf8(out)?)
    }

    #[test]
    fn the_table_covers_every_command_path() -> R {
        let command = crate::cli::Cli::command();
        let table = table(&command);
        let paths: Vec<&str> = table.iter().map(|(path, _)| path.as_str()).collect();
        for expected in [
            "detent",
            "detent config",
            "detent config apply",
            "detent commit confirm",
            "detent backup restore",
            "detent service status",
            "detent completions",
        ] {
            assert!(
                paths.contains(&expected),
                "{expected} is missing: {paths:?}"
            );
        }
        let root = table.first().ok_or("the root is first")?;
        assert!(root.1.contains(&"doctor".to_owned()));
        assert!(root.1.contains(&"--json".to_owned()));
        assert!(top_level(&table).contains(&"config".to_owned()));
        assert!(case_arms(&table).contains("'detent config'"));
        Ok(())
    }

    #[test]
    fn every_shell_script_mentions_every_top_level_command() -> R {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let text = script(shell)?;
            for command in ["serve", "config", "doctor", "completions"] {
                assert!(text.contains(command), "{shell:?} omits {command}");
            }
            assert!(text.contains("detent"));
        }
        Ok(())
    }

    #[test]
    fn the_bash_script_defines_and_registers_its_function() -> R {
        let text = script(Shell::Bash)?;
        assert!(text.starts_with("_detent() {"));
        assert!(text.trim_end().ends_with("complete -F _detent detent"));
        assert!(text.contains("COMPREPLY"));
        Ok(())
    }

    #[test]
    fn the_zsh_script_is_a_compdef() -> R {
        let text = script(Shell::Zsh)?;
        assert!(text.starts_with("#compdef detent"));
        assert!(text.contains("compadd"));
        Ok(())
    }

    #[test]
    fn the_fish_script_is_one_complete_line_per_path() -> R {
        let text = script(Shell::Fish)?;
        assert!(
            text.lines()
                .all(|line| line.starts_with("complete -c detent"))
        );
        assert!(text.contains("__fish_seen_subcommand_from config"));
        assert!(text.contains("not __fish_seen_subcommand_from"));
        Ok(())
    }

    #[test]
    fn a_write_failure_propagates() {
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            assert!(write(&mut Broken, shell).is_err(), "{shell:?}");
        }
    }
}
