//! `keld` binary: no args opens the TUI; subcommands arrive in later tasks.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use keld_core::{
    default_audit_path, load, load_scope_optional, AuditLog, ConfigOverrides, ThemeName,
    AUTHORIZED_USE, VERSION,
};
use keld_tui::{run, version_banner, ThemeId, TuiOptions};

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

    /// Path to `keld.toml` (overrides discovery)
    #[arg(long = "config", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Path to `scope.toml` (default: ./scope.toml when present)
    #[arg(long = "scope", value_name = "PATH")]
    scope: Option<PathBuf>,

    /// Path to audit JSONL (default: ./audit.jsonl or user data dir)
    #[arg(long = "audit-log", value_name = "PATH")]
    audit_log: Option<PathBuf>,

    /// Skip the splash screen
    #[arg(long)]
    no_splash: bool,

    /// Use plain ASCII art and symbols
    #[arg(long)]
    ascii: bool,

    /// Disable colors (also respects NO_COLOR)
    #[arg(long)]
    no_color: bool,

    /// Theme: dark, light, or high-contrast
    #[arg(long, value_name = "NAME")]
    theme: Option<String>,
}

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    if cli.version {
        print_version(cli.ascii);
        return Ok(ExitCode::SUCCESS);
    }

    let theme = match cli.theme.as_deref() {
        None => None,
        Some(t) => match ThemeName::parse(t) {
            Some(name) => Some(name),
            None => {
                eprintln!("warning: unknown theme `{t}`; ignoring flag");
                None
            }
        },
    };

    let overrides = ConfigOverrides {
        config_path: cli.config.clone(),
        no_splash: cli.no_splash.then_some(true),
        ascii: cli.ascii.then_some(true),
        no_color: cli.no_color.then_some(true),
        theme,
    };

    let loaded = load(&overrides);
    for w in &loaded.warnings {
        eprintln!("warning: {w}");
    }

    let scope = load_scope_optional(cli.scope.as_deref()).map_err(|e| anyhow::anyhow!(e))?;
    if scope.is_empty() {
        eprintln!("warning: no scope loaded; active modules will refuse targets until scope.toml or --scope is set");
    }

    let audit_path = cli.audit_log.clone().unwrap_or_else(default_audit_path);
    let audit = AuditLog::load(&audit_path).map_err(|e| anyhow::anyhow!(e))?;

    let opts = TuiOptions {
        show_splash: loaded.config.splash,
        ascii: loaded.config.ascii,
        no_color: loaded.config.no_color,
        theme_id: ThemeId::from_theme_name(loaded.config.theme),
        needs_ack: !loaded.config.authorized_ack,
        config_path: loaded.persist_path,
        scope_summary: scope.summary(),
        audit_entries: audit.entries().to_vec(),
        audit_path,
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
