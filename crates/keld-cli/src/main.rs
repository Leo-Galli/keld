//! `keld` binary: no args opens the TUI; subcommands arrive in later tasks.

use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use keld_core::{AUTHORIZED_USE, VERSION};
use keld_tui::{run, version_banner, TuiOptions};

#[derive(Debug, Parser)]
#[command(
    name = "keld",
    about = "Authorized recon, audit and report toolkit",
    after_help = AUTHORIZED_USE,
    disable_version_flag = true
)]
struct Cli {
    /// Print version (logo on TTY)
    #[arg(short = 'V', long = "version")]
    version: bool,

    /// Skip the splash screen
    #[arg(long)]
    no_splash: bool,

    /// Use plain ASCII art and symbols
    #[arg(long)]
    ascii: bool,

    /// Disable colors (also respects NO_COLOR)
    #[arg(long)]
    no_color: bool,
}

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    if cli.version {
        print_version(cli.ascii);
        return Ok(ExitCode::SUCCESS);
    }

    let opts = TuiOptions {
        show_splash: !cli.no_splash,
        ascii: cli.ascii,
        no_color: cli.no_color || std::env::var_os("NO_COLOR").is_some(),
    };

    run(opts).map_err(|e| anyhow::anyhow!(e))?;
    Ok(ExitCode::SUCCESS)
}

fn print_version(ascii: bool) {
    let mut out = io::stdout();
    if out.is_terminal() {
        let _ = write!(out, "{}", version_banner(ascii));
    } else {
        let _ = writeln!(out, "keld {VERSION}");
    }
}
