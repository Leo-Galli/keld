//! `keld` binary: no args opens the TUI; subcommands run the CLI.

mod color;
mod dns_cmd;
mod doctor;
mod fuzz_cmd;
mod hash_cmd;
mod http_cmd;
mod net_cmd;
mod output;
mod probe_cmd;
mod report_cmd;
mod scan_cmd;
mod signal;
mod tls_cmd;

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use keld_core::{
    default_audit_path, load, load_scope_optional, AuditLog, ConfigOverrides, ThemeName,
    AUTHORIZED_USE, VERSION,
};
use keld_modules::{
    DEFAULT_DNS_TIMEOUT_MS, DEFAULT_FUZZ_TIMEOUT_MS, DEFAULT_HTTP_TIMEOUT_MS,
    DEFAULT_NET_TIMEOUT_MS, DEFAULT_PROBE_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, DEFAULT_TLS_TIMEOUT_MS,
};
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
    /// TLS certificate chain, expiry, protocols, ciphers, HSTS
    Tls {
        /// Host or IP in scope
        target: String,
        /// Ports: `443`, `443,8443` (default: 443)
        #[arg(short, long, default_value = "443")]
        ports: String,
        /// Connect / handshake / HTTP timeout in milliseconds
        #[arg(long, default_value_t = DEFAULT_TLS_TIMEOUT_MS)]
        timeout: u64,
    },
    /// HTTP security headers, cookies, CORS, fingerprint, robots/sitemap
    Http {
        /// URL or host in scope (scheme defaults to https)
        target: String,
        /// Request timeout in milliseconds
        #[arg(long, default_value_t = DEFAULT_HTTP_TIMEOUT_MS)]
        timeout: u64,
    },
    /// Directory and virtual-host discovery from a wordlist
    Fuzz {
        /// URL or host in scope (scheme defaults to http)
        target: String,
        /// Wordlist file (one entry per line; `#` comments skipped)
        #[arg(short, long, value_name = "PATH")]
        wordlist: PathBuf,
        /// Mode: `dir` (path) or `vhost` (Host header)
        #[arg(long, default_value = "dir")]
        mode: String,
        /// Status codes to hide when match-status is empty (default: 404; `none` clears)
        #[arg(long, default_value = "404", value_name = "CODES")]
        filter_status: String,
        /// Only keep these status codes (disables filter-status when set)
        #[arg(long, default_value = "", value_name = "CODES")]
        match_status: String,
        /// Hide responses with these body sizes
        #[arg(long, default_value = "", value_name = "SIZES")]
        filter_size: String,
        /// Request timeout in milliseconds
        #[arg(long, default_value_t = DEFAULT_FUZZ_TIMEOUT_MS)]
        timeout: u64,
    },
    /// DNS records, AXFR check, wordlist and CT subdomain discovery
    Dns {
        /// Domain in scope
        domain: String,
        /// Optional subdomain wordlist (`#` comments skipped)
        #[arg(short, long, value_name = "PATH")]
        wordlist: Option<PathBuf>,
        /// Query Certificate Transparency (crt.sh); default on
        #[arg(long, default_value_t = true)]
        ct: bool,
        /// Disable Certificate Transparency lookup
        #[arg(long = "no-ct")]
        no_ct: bool,
        /// Lookup / HTTP timeout in milliseconds
        #[arg(long, default_value_t = DEFAULT_DNS_TIMEOUT_MS)]
        timeout: u64,
    },
    /// Local interfaces and authorized subnet host discovery
    Net {
        /// CIDR or IP in scope (omit to list interfaces only)
        target: Option<String>,
        /// Discovery technique: `auto`, `arp`, `icmp`, or `tcp` (default: auto)
        #[arg(long, default_value = "auto")]
        technique: String,
        /// TCP probe ports when ARP/ICMP are unavailable (default: 80,443,22,445)
        #[arg(short, long, default_value = "80,443,22,445")]
        ports: String,
        /// Connect / ICMP timeout in milliseconds
        #[arg(long, default_value_t = DEFAULT_NET_TIMEOUT_MS)]
        timeout: u64,
    },
    /// Hash type identification and offline wordlist check
    Hash {
        /// Operator-supplied hash (hex digest or `$…` modular crypt)
        hash: String,
        /// Optional wordlist for offline check (`#` comments skipped)
        #[arg(short, long, value_name = "PATH")]
        wordlist: Option<PathBuf>,
        /// Force algo: `auto`, `md5`, `sha1`, `sha256`, `sha384`, `sha512` (default: auto)
        #[arg(long, default_value = "auto")]
        algo: String,
    },
    /// Merge findings into JSON, Markdown, HTML, CSV, or SARIF
    Report {
        /// Findings JSON file(s); full document, `{ "findings": [...] }`, or a bare array
        #[arg(short, long = "input", value_name = "PATH", required = true)]
        inputs: Vec<PathBuf>,
        /// Output format: `json`, `markdown`, `html`, `csv`, `sarif` (default: json)
        #[arg(short, long, default_value = "json")]
        format: String,
        /// Write to this path (default: stdout)
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Optional report title
        #[arg(long)]
        title: Option<String>,
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
        Some(Commands::Tls {
            target,
            ports,
            timeout,
        }) => {
            let mut audit = AuditLog::load(&audit_path).map_err(|e| anyhow::anyhow!(e))?;
            let code = tls_cmd::run(
                tls_cmd::TlsArgs {
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
        Some(Commands::Http { target, timeout }) => {
            let mut audit = AuditLog::load(&audit_path).map_err(|e| anyhow::anyhow!(e))?;
            let code = http_cmd::run(
                http_cmd::HttpArgs {
                    target,
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
        Some(Commands::Fuzz {
            target,
            wordlist,
            mode,
            filter_status,
            match_status,
            filter_size,
            timeout,
        }) => {
            let mut audit = AuditLog::load(&audit_path).map_err(|e| anyhow::anyhow!(e))?;
            let code = fuzz_cmd::run(
                fuzz_cmd::FuzzArgs {
                    target,
                    wordlist,
                    mode,
                    filter_status,
                    match_status,
                    filter_size,
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
        Some(Commands::Dns {
            domain,
            wordlist,
            ct,
            no_ct,
            timeout,
        }) => {
            let mut audit = AuditLog::load(&audit_path).map_err(|e| anyhow::anyhow!(e))?;
            let code = dns_cmd::run(
                dns_cmd::DnsArgs {
                    domain,
                    wordlist,
                    ct: ct && !no_ct,
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
        Some(Commands::Net {
            target,
            technique,
            ports,
            timeout,
        }) => {
            let mut audit = AuditLog::load(&audit_path).map_err(|e| anyhow::anyhow!(e))?;
            let code = net_cmd::run(
                net_cmd::NetArgs {
                    target,
                    technique,
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
        Some(Commands::Hash {
            hash,
            wordlist,
            algo,
        }) => {
            let mut audit = AuditLog::load(&audit_path).map_err(|e| anyhow::anyhow!(e))?;
            let code = hash_cmd::run(
                hash_cmd::HashArgs {
                    hash,
                    wordlist,
                    algo,
                    concurrency: cli.concurrency.unwrap_or(0),
                    dry_run: cli.dry_run,
                    rate: cli.rate,
                    json: cli.json,
                    color,
                },
                &mut audit,
            )
            .map_err(|e| anyhow::anyhow!(e))?;
            Ok(ExitCode::from(code))
        }
        Some(Commands::Report {
            inputs,
            format,
            output,
            title,
        }) => {
            let mut audit = AuditLog::load(&audit_path).map_err(|e| anyhow::anyhow!(e))?;
            let code = report_cmd::run(
                report_cmd::ReportArgs {
                    inputs,
                    format,
                    output,
                    title,
                    dry_run: cli.dry_run,
                    json: cli.json,
                    color,
                },
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
        assert!(help.contains("tls") || help.contains("Tls") || help.contains("TLS"));
        assert!(help.contains("http") || help.contains("Http") || help.contains("HTTP"));
        assert!(help.contains("fuzz") || help.contains("Fuzz"));
        assert!(help.contains("dns") || help.contains("Dns") || help.contains("DNS"));
        assert!(help.contains("net") || help.contains("Net"));
        assert!(help.contains("hash") || help.contains("Hash"));
        assert!(help.contains("report") || help.contains("Report"));
        assert!(help.contains("--json"));
        assert!(help.contains("--dry-run"));
    }

    #[test]
    fn parses_report_with_format() {
        let cli = Cli::try_parse_from([
            "keld",
            "--dry-run",
            "report",
            "-i",
            "a.json",
            "-i",
            "b.json",
            "-f",
            "html",
            "-o",
            "out.html",
            "--title",
            "demo",
        ])
        .unwrap();
        assert!(cli.dry_run);
        match cli.command {
            Some(Commands::Report {
                inputs,
                format,
                output,
                title,
            }) => {
                assert_eq!(inputs.len(), 2);
                assert_eq!(format, "html");
                assert_eq!(output.unwrap().as_os_str(), "out.html");
                assert_eq!(title.as_deref(), Some("demo"));
            }
            other => panic!("expected Report, got {other:?}"),
        }
    }

    #[test]
    fn parses_hash_with_wordlist() {
        let cli = Cli::try_parse_from([
            "keld",
            "--dry-run",
            "hash",
            "5eb63bbbe01eeed093cb22bb8f5acdc3",
            "-w",
            "words.txt",
            "--algo",
            "md5",
        ])
        .unwrap();
        assert!(cli.dry_run);
        match cli.command {
            Some(Commands::Hash {
                hash,
                wordlist,
                algo,
            }) => {
                assert_eq!(hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
                assert_eq!(wordlist.unwrap().as_os_str(), "words.txt");
                assert_eq!(algo, "md5");
            }
            other => panic!("expected Hash, got {other:?}"),
        }
    }

    #[test]
    fn parses_net_target() {
        let cli = Cli::try_parse_from([
            "keld",
            "--dry-run",
            "net",
            "10.0.0.0/30",
            "--technique",
            "tcp",
            "-p",
            "80,443",
            "--timeout",
            "500",
        ])
        .unwrap();
        assert!(cli.dry_run);
        match cli.command {
            Some(Commands::Net {
                target,
                technique,
                ports,
                timeout,
            }) => {
                assert_eq!(target.as_deref(), Some("10.0.0.0/30"));
                assert_eq!(technique, "tcp");
                assert_eq!(ports, "80,443");
                assert_eq!(timeout, 500);
            }
            other => panic!("expected Net, got {other:?}"),
        }
    }

    #[test]
    fn parses_net_ifaces_only() {
        let cli = Cli::try_parse_from(["keld", "net"]).unwrap();
        match cli.command {
            Some(Commands::Net { target, .. }) => assert!(target.is_none()),
            other => panic!("expected Net, got {other:?}"),
        }
    }

    #[test]
    fn parses_dns_domain() {
        let cli = Cli::try_parse_from([
            "keld",
            "--dry-run",
            "dns",
            "example.test",
            "-w",
            "subs.txt",
            "--no-ct",
            "--timeout",
            "2500",
        ])
        .unwrap();
        assert!(cli.dry_run);
        match cli.command {
            Some(Commands::Dns {
                domain,
                wordlist,
                ct,
                no_ct,
                timeout,
            }) => {
                assert_eq!(domain, "example.test");
                assert_eq!(wordlist, Some(PathBuf::from("subs.txt")));
                assert!(ct);
                assert!(no_ct);
                assert!(!(ct && !no_ct));
                assert_eq!(timeout, 2500);
            }
            other => panic!("expected Dns, got {other:?}"),
        }
    }

    #[test]
    fn parses_fuzz_target() {
        let cli = Cli::try_parse_from([
            "keld",
            "--dry-run",
            "fuzz",
            "http://127.0.0.1/",
            "-w",
            "words.txt",
            "--mode",
            "vhost",
            "--filter-status",
            "404,403",
            "--timeout",
            "2500",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Fuzz {
                target,
                wordlist,
                mode,
                filter_status,
                timeout,
                ..
            }) => {
                assert_eq!(target, "http://127.0.0.1/");
                assert_eq!(wordlist, PathBuf::from("words.txt"));
                assert_eq!(mode, "vhost");
                assert_eq!(filter_status, "404,403");
                assert_eq!(timeout, 2500);
            }
            other => panic!("expected Fuzz, got {other:?}"),
        }
        assert!(cli.dry_run);
    }

    #[test]
    fn parses_http_target() {
        let cli = Cli::try_parse_from([
            "keld",
            "--dry-run",
            "http",
            "https://127.0.0.1/",
            "--timeout",
            "2500",
        ])
        .unwrap();
        assert!(cli.dry_run);
        match cli.command {
            Some(Commands::Http { target, timeout }) => {
                assert_eq!(target, "https://127.0.0.1/");
                assert_eq!(timeout, 2500);
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn parses_tls_with_ports() {
        let cli = Cli::try_parse_from([
            "keld",
            "--dry-run",
            "tls",
            "127.0.0.1",
            "--ports",
            "443,8443",
            "--timeout",
            "3000",
        ])
        .unwrap();
        assert!(cli.dry_run);
        match cli.command {
            Some(Commands::Tls {
                target,
                ports,
                timeout,
            }) => {
                assert_eq!(target, "127.0.0.1");
                assert_eq!(ports, "443,8443");
                assert_eq!(timeout, 3000);
            }
            other => panic!("expected Tls, got {other:?}"),
        }
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
