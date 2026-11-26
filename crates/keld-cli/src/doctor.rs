//! `keld doctor` -- terminal, privilege, and SYN-path checks.

use std::io::{self, IsTerminal};
use std::net::UdpSocket;

use keld_modules::SynAvailability;
use serde::Serialize;

use crate::color::ColorMode;
use crate::output;

/// One capability check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorCheck {
    pub id: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// Full doctor report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub version: String,
    pub checks: Vec<DoctorCheck>,
}

/// Inputs that affect checks (flags / loaded state).
#[derive(Debug, Clone)]
pub struct DoctorContext {
    pub no_color: bool,
    pub ascii: bool,
    pub scope_loaded: bool,
    pub scope_summary: String,
}

impl DoctorContext {
    pub fn run(&self) -> DoctorReport {
        let syn = SynAvailability::probe();
        DoctorReport {
            version: keld_core::VERSION.to_string(),
            checks: vec![
                check_tty(),
                check_color(self.no_color),
                check_unicode(self.ascii),
                check_elevated(&syn),
                check_npcap(&syn),
                check_syn(&syn),
                check_network(),
                check_scope(self.scope_loaded, &self.scope_summary),
            ],
        }
    }
}

fn check_tty() -> DoctorCheck {
    let ok = io::stdout().is_terminal();
    DoctorCheck {
        id: "tty",
        ok,
        detail: if ok {
            "stdout is a TTY".into()
        } else {
            "stdout is not a TTY (piping / redirect)".into()
        },
    }
}

fn check_color(no_color_flag: bool) -> DoctorCheck {
    let mode = ColorMode::detect(no_color_flag);
    DoctorCheck {
        id: "color",
        ok: mode.enabled(),
        detail: if mode.enabled() {
            "ANSI colors enabled".into()
        } else if no_color_flag || std::env::var_os("NO_COLOR").is_some() {
            "colors disabled (--no-color or NO_COLOR)".into()
        } else {
            "colors unavailable (non-TTY or dumb TERM)".into()
        },
    }
}

fn check_unicode(ascii: bool) -> DoctorCheck {
    DoctorCheck {
        id: "unicode",
        ok: !ascii,
        detail: if ascii {
            "ASCII mode (--ascii); Unicode UI symbols disabled".into()
        } else {
            "Unicode symbols allowed (use --ascii if the terminal lacks support)".into()
        },
    }
}

fn check_elevated(syn: &SynAvailability) -> DoctorCheck {
    DoctorCheck {
        id: "elevated",
        ok: syn.elevated,
        detail: if syn.elevated {
            "process is elevated (root or administrator)".into()
        } else {
            "not elevated; raw SYN needs root on Unix or an elevated Windows session".into()
        },
    }
}

fn check_npcap(syn: &SynAvailability) -> DoctorCheck {
    #[cfg(windows)]
    {
        DoctorCheck {
            id: "npcap",
            ok: syn.npcap_present,
            detail: if syn.npcap_present {
                "Npcap Packet.dll found. Windows still blocks raw TCP, so SYN falls back to TCP connect".into()
            } else {
                "Npcap not detected. TCP connect scan remains available".into()
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = syn;
        DoctorCheck {
            id: "npcap",
            ok: true,
            detail: "Npcap is Windows-only; not required on this platform".into(),
        }
    }
}

fn check_syn(syn: &SynAvailability) -> DoctorCheck {
    DoctorCheck {
        id: "syn",
        ok: syn.usable,
        detail: if syn.usable {
            format!("SYN path available: {}", syn.detail)
        } else {
            format!("{}. TCP connect will be used", syn.detail)
        },
    }
}

fn check_network() -> DoctorCheck {
    match UdpSocket::bind(("127.0.0.1", 0)) {
        Ok(_) => DoctorCheck {
            id: "network",
            ok: true,
            detail: "local UDP bind succeeded".into(),
        },
        Err(e) => DoctorCheck {
            id: "network",
            ok: false,
            detail: format!("local UDP bind failed: {e}"),
        },
    }
}

fn check_scope(loaded: bool, summary: &str) -> DoctorCheck {
    DoctorCheck {
        id: "scope",
        ok: loaded,
        detail: if loaded {
            format!("scope loaded ({summary})")
        } else {
            "no scope loaded; set scope.toml or --scope before active modules".into()
        },
    }
}

/// Print doctor report as JSON or colored human text.
pub fn emit(report: &DoctorReport, json: bool, color: ColorMode) -> Result<(), String> {
    if json {
        return output::emit_json(report);
    }

    println!("{}", color.bold("keld doctor"));
    println!("{}", color.dim(&format!("version {}", report.version)));
    println!();
    for check in &report.checks {
        let mark = if check.ok {
            color.green("[ok]")
        } else if check.id == "network" {
            color.red("[!!]")
        } else {
            color.yellow("[!!]")
        };
        println!("  {mark} {:<10} {}", check.id, check.detail);
    }
    println!();
    println!(
        "{}",
        color.dim("SYN is optional. When it is unavailable, scan uses TCP connect.")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_includes_expected_ids() {
        let report = DoctorContext {
            no_color: true,
            ascii: true,
            scope_loaded: false,
            scope_summary: "none".into(),
        }
        .run();
        let ids: Vec<_> = report.checks.iter().map(|c| c.id).collect();
        assert_eq!(
            ids,
            ["tty", "color", "unicode", "elevated", "npcap", "syn", "network", "scope"]
        );
        assert!(!report.version.is_empty());
        let elevated = report.checks.iter().find(|c| c.id == "elevated").unwrap();
        assert!(!elevated.detail.contains("not probed"));
        assert!(!elevated.detail.contains("stub"));
        let syn = report.checks.iter().find(|c| c.id == "syn").unwrap();
        assert!(!syn.detail.is_empty());
        if !syn.ok {
            assert!(
                syn.detail.contains("TCP connect")
                    || syn.detail.contains("fallback")
                    || syn.detail.contains("root")
                    || syn.detail.contains("Npcap")
                    || syn.detail.contains("raw")
            );
        }
        let unicode = report.checks.iter().find(|c| c.id == "unicode").unwrap();
        assert!(!unicode.ok);
        let scope = report.checks.iter().find(|c| c.id == "scope").unwrap();
        assert!(!scope.ok);
    }

    #[test]
    fn json_serialize_roundtrip_shape() {
        let report = DoctorReport {
            version: "0.1.0".into(),
            checks: vec![DoctorCheck {
                id: "tty",
                ok: true,
                detail: "ok".into(),
            }],
        };
        let s = serde_json::to_string(&report).unwrap();
        assert!(s.contains("\"id\":\"tty\""));
        assert!(s.contains("\"ok\":true"));
    }
}
