//! `keld` binary: no args opens the TUI; subcommands run the CLI.

mod color;
mod doctor;
mod output;
mod probe_cmd;
mod scan_cmd;
mod signal;

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use keld_core::{
    default_audit_path, load, load_scope_optional, AuditLog, ConfigOverrides, ThemeName,
    AUTHORIZED_USE, VERSION,
};
use keld_modules::{DEFAULT_PROBE_TIMEOUT_MS, DEFAULT_TIMEOUT_MS};
use keld_tui::{run, version_banner, ThemeId, TuiOptions};

use crate::color::ColorMode;
use crate::doctor::DoctorContext;
use crate::signal::PartialSaveHook;

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
    #[arg(long = "config", value_name = "PATH", global = true)]
    config: Option<PathBuf>,

    /// Path to `scope.toml` (default: ./scope.toml when present)
    #[arg(long = "scope", value_name = "PATH", global = true)]
    scope: Option<PathBuf>,

    /// Path to audit JSONL (default: ./audit.jsonl or user data dir)
    #[arg(long = "audit-log", value_name = "PATH", global = true)]
    audit_log: Option<PathBuf>,

    /// Skip the splash screen
    #[arg(long, global = true)]
    no_splash: bool,

    /// Use plain ASCII art and symbols
    #[arg(long, global = true)]
    ascii: bool,

    /// Disable colors (also respects NO_COLOR)
    #[arg(long, global = true)]
    no_color: bool,

    /// Theme: dark, light, or high-contrast
    #[arg(long, value_name = "NAME", global = true)]
    theme: Option<String>,

    /// Emit machine-readable JSON on commands that produce results
    #[arg(long, global = true)]
    json: bool,

    /// Show what would be sent without performing network actions
    #[arg(long, global = true)]
    dry_run: bool,

    /// Max requests per second (modules)
    #[arg(long, value_name = "N", global = true)]
    rate: Option<u32>,

    /// Max concurrent workers (modules)
    #[arg(long, value_name = "N", global = true)]
    concurrency: Option<u32>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Report terminal, privilege and network capability checks
    Doctor,
    /// Port scan (TCP connect, or SYN when a raw socket is allowed)
    Scan {
        /// Host or IP in scope
        target: String,
        /// Ports: `22`, `80,443`, `1-1024`, `top`, `top1000` (default: top)
        #[arg(short, long, default_value = "top")]
        ports: String,
        /// Connect timeout in milliseconds
        #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
        timeout: u64,
        /// Request SYN probes. Needs root or CAP_NET_RAW on Unix.
        /// Windows blocks raw TCP (Npcap is reported by `doctor`); falls back to TCP connect.
        #[arg(long)]
        syn: bool,
    },
    /// Banner / service detection from embedded signatures
    Probe {
        /// Host or IP in scope
        target: String,
        /// Ports: `22`, `80,443`, `1-1024`, `top`, `top1000` (default: top)
        #[arg(short, long, default_value = "top")]
        ports: String,
        /// Connect and read timeout in milliseconds
        #[arg(long, default_value_t = DEFAULT_PROBE_TIMEOUT_MS)]
        timeout: u64,
    },
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
    let scope_loaded = !scope.is_empty();
    if !scope_loaded {
        eprintln!("warning: no scope loaded; active modules will refuse targets until scope.toml or --scope is set");
    }

    let color = ColorMode::detect(loaded.config.no_color);
    let audit_path = cli.audit_log.clone().unwrap_or_else(default_audit_path);

    match cli.command {
        Some(Commands::Doctor) => {
            let hook = PartialSaveHook::new();
            hook.install(|| {});
            let report = DoctorContext {
                no_color: loaded.config.no_color,
                ascii: loaded.config.ascii,
                scope_loaded,
                scope_summary: scope.summary(),
            }
            .run();
            doctor::emit(&report, cli.json, color).map_err(anyhow::Error::msg)?;
            if hook.is_cancelled() {
                eprintln!("{}", color.yellow("interrupted; partial save hook ran"));
                return Ok(ExitCode::from(130));
            }
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Scan {
            target,
            ports,
            timeout,
            syn,
        }) => {
            let mut audit = AuditLog::load(&audit_path).map_err(|e| anyhow::anyhow!(e))?;
            let code = scan_cmd::run(
                scan_cmd::ScanArgs {
                    target,
                    ports,
                    timeout_ms: timeout,
                    concurrency: cli.concurrency.unwrap_or(0),
                    dry_run: cli.dry_run,
                    rate: cli.rate,
                    json: cli.json,
                    color,
                    syn,
                },
                &scope,
                &mut audit,
            )
            .map_err(|e| anyhow::anyhow!(e))?;
            Ok(ExitCode::from(code))
        }
        Some(Commands::Probe {
            target,
            ports,
            timeout,
        }) => {
            let mut audit = AuditLog::load(&audit_path).map_err(|e| anyhow::anyhow!(e))?;
            let code = probe_cmd::run(
                probe_cmd::ProbeArgs {
                    target,
                    ports,
                    timeout_ms: timeout,
                    concurrency: cli.concurrency.unwrap_or(0),
                    dry_run: cli.dry_run,
                    rate: cli.rate,
                    json: cli.json,
                    color,
                },
                &scope,
                &mut audit,
            )
            .map_err(|e| anyhow::anyhow!(e))?;
            Ok(ExitCode::from(code))
        }
        None => {
            let audit = AuditLog::load(&audit_path).map_err(|e| anyhow::anyhow!(e))?;

            let opts = TuiOptions {
                show_splash: loaded.config.splash,
                ascii: loaded.config.ascii,
                no_color: loaded.config.no_color,
                theme_id: ThemeId::from_theme_name(loaded.config.theme),
                needs_ack: !loaded.config.authorized_ack,
                config_path: loaded.persist_path,
                scope_summary: scope.summary(),
                scope,
                audit_entries: audit.entries().to_vec(),
                audit_path,
                key_preset: keld_tui::KeyPreset::Vim,
            };

            run(opts).map_err(|e| anyhow::anyhow!(e))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn print_version(ascii: bool) {
    let mut out = io::stdout();
    if out.is_terminal() {
        let _ = write!(out, "{}", version_banner(ascii));
    } else {
        let _ = writeln!(out, "keld {VERSION}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_help_mentions_scan_and_doctor() {
        let mut help = Vec::new();
        Cli::command().write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(help.contains("doctor") || help.contains("Doctor"));
        assert!(help.contains("scan") || help.contains("Scan"));
        assert!(help.contains("probe") || help.contains("Probe"));
        assert!(help.contains("--json"));
        assert!(help.contains("--dry-run"));
    }

    #[test]
    fn parses_probe_with_ports() {
        let cli = Cli::try_parse_from([
            "keld",
            "--dry-run",
            "probe",
            "127.0.0.1",
            "--ports",
            "22,80",
            "--timeout",
            "1500",
        ])
        .unwrap();
        assert!(cli.dry_run);
        match cli.command {
            Some(Commands::Probe {
                target,
                ports,
                timeout,
            }) => {
                assert_eq!(target, "127.0.0.1");
                assert_eq!(ports, "22,80");
                assert_eq!(timeout, 1500);
            }
            other => panic!("expected Probe, got {other:?}"),
        }
    }

    #[test]
    fn parses_scan_syn_flag() {
        let cli =
            Cli::try_parse_from(["keld", "scan", "127.0.0.1", "--syn", "--ports", "22"]).unwrap();
        match cli.command {
            Some(Commands::Scan { syn, ports, .. }) => {
                assert!(syn);
                assert_eq!(ports, "22");
            }
            other => panic!("expected Scan, got {other:?}"),
        }
    }

    #[test]
    fn parses_doctor_with_global_json() {
        let cli = Cli::try_parse_from(["keld", "doctor", "--json"]).unwrap();
        assert!(cli.json);
        assert!(matches!(cli.command, Some(Commands::Doctor)));
    }

    #[test]
    fn parses_scan_with_ports() {
        let cli = Cli::try_parse_from([
            "keld",
            "--dry-run",
            "scan",
            "127.0.0.1",
            "--ports",
            "22,80",
            "--timeout",
            "500",
        ])
        .unwrap();
        assert!(cli.dry_run);
        match cli.command {
            Some(Commands::Scan {
                target,
                ports,
                timeout,
                syn,
            }) => {
                assert_eq!(target, "127.0.0.1");
                assert_eq!(ports, "22,80");
                assert_eq!(timeout, 500);
                assert!(!syn);
            }
            other => panic!("expected Scan, got {other:?}"),
        }
    }

    #[test]
    fn no_subcommand_opens_tui_path() {
        let cli = Cli::try_parse_from(["keld", "--no-splash", "--ascii"]).unwrap();
        assert!(cli.command.is_none());
        assert!(cli.no_splash);
        assert!(cli.ascii);
    }
}
