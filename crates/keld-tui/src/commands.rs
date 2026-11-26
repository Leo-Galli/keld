//! Registered command-palette actions and fuzzy filter.

use crate::keys::KeyPreset;
use crate::screen::Screen;

/// Identifiers for palette (and future settings) actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandId {
    GoTo(Screen),
    ToggleSidebar,
    OpenHelp,
    SetPreset(KeyPreset),
    CyclePreset,
    Quit,
}

/// One selectable command in the palette.
#[derive(Debug, Clone, Copy)]
pub struct Command {
    pub id: CommandId,
    pub label: &'static str,
    /// Extra tokens matched by fuzzy filter (space-separated).
    pub keywords: &'static str,
}

const COMMANDS: &[Command] = &[
    Command {
        id: CommandId::GoTo(Screen::Dashboard),
        label: "Go to Dashboard",
        keywords: "home overview",
    },
    Command {
        id: CommandId::GoTo(Screen::Scan),
        label: "Go to Scan",
        keywords: "port tcp",
    },
    Command {
        id: CommandId::GoTo(Screen::Probe),
        label: "Go to Probe",
        keywords: "banner service",
    },
    Command {
        id: CommandId::GoTo(Screen::Tls),
        label: "Go to TLS",
        keywords: "cert certificate ssl",
    },
    Command {
        id: CommandId::GoTo(Screen::Http),
        label: "Go to HTTP",
        keywords: "headers cookies",
    },
    Command {
        id: CommandId::GoTo(Screen::Fuzz),
        label: "Go to Fuzz",
        keywords: "directory vhost wordlist",
    },
    Command {
        id: CommandId::GoTo(Screen::Dns),
        label: "Go to DNS",
        keywords: "subdomain zone",
    },
    Command {
        id: CommandId::GoTo(Screen::Net),
        label: "Go to Net",
        keywords: "network host discovery",
    },
    Command {
        id: CommandId::GoTo(Screen::Hash),
        label: "Go to Hash",
        keywords: "crack identify",
    },
    Command {
        id: CommandId::GoTo(Screen::Reports),
        label: "Go to Reports",
        keywords: "export sarif html",
    },
    Command {
        id: CommandId::GoTo(Screen::Workspace),
        label: "Go to Workspace",
        keywords: "project sqlite",
    },
    Command {
        id: CommandId::GoTo(Screen::Jobs),
        label: "Go to Jobs",
        keywords: "running progress tasks",
    },
    Command {
        id: CommandId::GoTo(Screen::AuditLog),
        label: "Go to Audit log",
        keywords: "audit history",
    },
    Command {
        id: CommandId::GoTo(Screen::Settings),
        label: "Go to Settings",
        keywords: "config theme",
    },
    Command {
        id: CommandId::ToggleSidebar,
        label: "Toggle sidebar",
        keywords: "nav modules overlay m",
    },
    Command {
        id: CommandId::OpenHelp,
        label: "Open help",
        keywords: "keybindings keys ?",
    },
    Command {
        id: CommandId::SetPreset(KeyPreset::Vim),
        label: "Keybindings: Vim",
        keywords: "preset vim hjkl",
    },
    Command {
        id: CommandId::SetPreset(KeyPreset::Arrows),
        label: "Keybindings: Arrows",
        keywords: "preset arrows keys",
    },
    Command {
        id: CommandId::CyclePreset,
        label: "Cycle keybinding preset",
        keywords: "preset toggle vim arrows",
    },
    Command {
        id: CommandId::Quit,
        label: "Quit",
        keywords: "exit close q",
    },
];

/// All registered commands (stable order).
pub fn all_commands() -> &'static [Command] {
    COMMANDS
}

/// Case-insensitive fuzzy filter: substring on label or keywords; empty query = all.
pub fn filter_commands(query: &str) -> Vec<&'static Command> {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return COMMANDS.iter().collect();
    }
    let mut scored: Vec<(i32, &Command)> = COMMANDS
        .iter()
        .filter_map(|cmd| score(cmd, &q).map(|s| (s, cmd)))
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.label.cmp(b.1.label)));
    scored.into_iter().map(|(_, c)| c).collect()
}

fn score(cmd: &Command, q: &str) -> Option<i32> {
    let label = cmd.label.to_ascii_lowercase();
    let keywords = cmd.keywords.to_ascii_lowercase();
    if label == q {
        return Some(300);
    }
    if label.starts_with(q) {
        return Some(200);
    }
    if label.contains(q) {
        return Some(100);
    }
    if keywords
        .split_whitespace()
        .any(|w| w.starts_with(q) || w == q)
    {
        return Some(80);
    }
    if keywords.contains(q) {
        return Some(40);
    }
    // Multi-word: every query token must appear in label or keywords.
    let hay = format!("{label} {keywords}");
    if q.split_whitespace().all(|t| hay.contains(t)) {
        return Some(20);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_query_lists_all() {
        assert_eq!(filter_commands("").len(), COMMANDS.len());
    }

    #[test]
    fn fuzzy_finds_scan() {
        let hits = filter_commands("scan");
        assert!(!hits.is_empty());
        assert!(hits
            .iter()
            .any(|c| matches!(c.id, CommandId::GoTo(Screen::Scan))));
    }

    #[test]
    fn fuzzy_keywords_vim() {
        let hits = filter_commands("hjkl");
        assert!(hits
            .iter()
            .any(|c| matches!(c.id, CommandId::SetPreset(KeyPreset::Vim))));
    }
}
