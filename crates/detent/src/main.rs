//! detent binary: clap CLI, wiring, feature gates.

// Both crypto features may be enabled (so `--all-features` builds); when both
// are present `crypto-aws-lc` takes precedence, mirroring rustls' own policy.
#[cfg(not(any(feature = "crypto-aws-lc", feature = "crypto-ring")))]
compile_error!("one of crypto-aws-lc or crypto-ring must be enabled");

use clap::{Parser, Subcommand};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// detent: the busybox of config files.
#[derive(Parser)]
#[command(
    name = "detent",
    version,
    about = "detent: the busybox of config files"
)]
struct Cli {
    /// Print what would happen without making changes.
    #[arg(long, global = true)]
    dryrun: bool,

    /// Emit step-level progress and key variable state.
    #[arg(short = 'v', long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

/// Top-level subcommands.
#[derive(Subcommand)]
enum Command {
    /// Check the host environment for common misconfigurations.
    Doctor,
}

fn main() {
    let cli = Cli::parse();

    // --dryrun and --verbose are accepted but not yet wired to behavior.
    if cli.verbose {
        eprintln!("detent: verbose logging is not implemented yet");
    }
    if cli.dryrun {
        eprintln!("detent: --dryrun has no effect yet (no mutating operations exist)");
    }

    match cli.command {
        Command::Doctor => println!("detent doctor: not implemented"),
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;

    #[test]
    fn parses_doctor_subcommand() {
        let cli = Cli::parse_from(["detent", "doctor"]);
        assert!(matches!(cli.command, Command::Doctor));
    }
}
