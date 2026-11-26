//! Keybinding presets (vim / arrows) and help tables.

/// Navigation / list keybinding preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyPreset {
    #[default]
    Vim,
    Arrows,
}

impl KeyPreset {
    pub fn label(self) -> &'static str {
        match self {
            Self::Vim => "Vim",
            Self::Arrows => "Arrows",
        }
    }

    pub fn cycle(self) -> Self {
        match self {
            Self::Vim => Self::Arrows,
            Self::Arrows => Self::Vim,
        }
    }

    /// Rows for the help overlay: (keys, action).
    pub fn help_rows(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Vim => HELP_VIM,
            Self::Arrows => HELP_ARROWS,
        }
    }
}

const HELP_VIM: &[(&str, &str)] = &[
    ("-- Global --", ""),
    ("Tab / Shift+Tab", "Next / prev focus"),
    ("/", "Filter (where available)"),
    (":", "Command palette"),
    ("?", "Help overlay"),
    ("m", "Toggle sidebar (narrow)"),
    ("q / Esc", "Back / close overlay / quit"),
    ("Ctrl+C", "Quit"),
    ("-- Vim preset --", ""),
    ("j / k", "Next / prev list or module"),
    ("h / l", "Reserved (module panes)"),
    ("g g", "Top of list"),
    ("G", "Bottom of list"),
    ("Ctrl+d / Ctrl+u", "Page down / up"),
    ("Enter", "Activate"),
    ("Space", "Toggle"),
];

const HELP_ARROWS: &[(&str, &str)] = &[
    ("-- Global --", ""),
    ("Tab / Shift+Tab", "Next / prev focus"),
    ("/", "Filter (where available)"),
    (":", "Command palette"),
    ("?", "Help overlay"),
    ("m", "Toggle sidebar (narrow)"),
    ("q / Esc", "Back / close overlay / quit"),
    ("Ctrl+C", "Quit"),
    ("-- Arrows preset --", ""),
    ("Up / Down", "Prev / next list or module"),
    ("Left / Right", "Reserved (module panes)"),
    ("Home / End", "Top / bottom of list"),
    ("PgUp / PgDn", "Page up / down"),
    ("Enter", "Activate"),
    ("Space", "Toggle"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycle_presets() {
        assert_eq!(KeyPreset::Vim.cycle(), KeyPreset::Arrows);
        assert_eq!(KeyPreset::Arrows.cycle(), KeyPreset::Vim);
    }

    #[test]
    fn help_mentions_palette() {
        assert!(KeyPreset::Vim.help_rows().iter().any(|(k, _)| *k == ":"));
        assert!(KeyPreset::Arrows
            .help_rows()
            .iter()
            .any(|(k, a)| *k == "?" || a.contains("Help")));
    }
}
