//! Top-level navigation targets (sidebar).

/// Sidebar / route list for the empty shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Scan,
    Probe,
    Tls,
    Http,
    Fuzz,
    Dns,
    Net,
    Hash,
    Reports,
    Workspace,
    AuditLog,
    Settings,
}

impl Screen {
    pub const ALL: &'static [Screen] = &[
        Screen::Dashboard,
        Screen::Scan,
        Screen::Probe,
        Screen::Tls,
        Screen::Http,
        Screen::Fuzz,
        Screen::Dns,
        Screen::Net,
        Screen::Hash,
        Screen::Reports,
        Screen::Workspace,
        Screen::AuditLog,
        Screen::Settings,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Screen::Dashboard => "Dashboard",
            Screen::Scan => "Scan",
            Screen::Probe => "Probe",
            Screen::Tls => "TLS",
            Screen::Http => "HTTP",
            Screen::Fuzz => "Fuzz",
            Screen::Dns => "DNS",
            Screen::Net => "Net",
            Screen::Hash => "Hash",
            Screen::Reports => "Reports",
            Screen::Workspace => "Workspace",
            Screen::AuditLog => "Audit log",
            Screen::Settings => "Settings",
        }
    }

    pub fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|s| *s == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let idx = Self::ALL.iter().position(|s| *s == self).unwrap_or(0);
        let len = Self::ALL.len();
        Self::ALL[(idx + len - 1) % len]
    }
}
