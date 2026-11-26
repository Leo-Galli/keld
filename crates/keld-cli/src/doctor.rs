//! `keld doctor` -- basic capability checks (stub; deep probes arrive with modules).

use std::io::{self, IsTerminal};
use std::net::UdpSocket;

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
        DoctorReport {
            version: keld_core::VERSION.to_string(),
            checks: vec![
                check_tty(),
                check_color(self.no_color),
                check_unicode(self.ascii),
                check_elevated(),
                check_npcap(),
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

fn check_elevated() -> DoctorCheck {
    // shortcut: no OS privilege probe yet, upgrade in KL-012 with SYN/raw sockets
    DoctorCheck {
        id: "elevated",
        ok: false,
        detail: "elevation not probed yet (stub); SYN / raw-socket paths need privileges later"
            .into(),
    }
}

fn check_npcap() -> DoctorCheck {
    #[cfg(windows)]
    {
        use std::path::Path;
        let candidates = [
            Path::new(r"C:\Windows\System32\Npcap\Packet.dll"),
            Path::new(r"C:\Windows\System32\Packet.dll"),
        ];
        let found = candidates.iter().any(|p| p.exists());
        DoctorCheck {
            id: "npcap",
            ok: found,
            detail: if found {
                "Npcap Packet.dll found (SYN path may be available later)".into()
            } else {
                "Npcap not detected; connect-scan remains available".into()
            },
        }
    }
    #[cfg(not(windows))]
    {
        DoctorCheck {
            id: "npcap",
            ok: true,
            detail: "Npcap is Windows-only; not required on this platform".into(),
        }
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
        color.dim("Stub checks only; deeper probes land with scan/SYN and later modules.")
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
            ["tty", "color", "unicode", "elevated", "npcap", "network", "scope"]
        );
        assert!(!report.version.is_empty());
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
