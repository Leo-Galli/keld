//! TUI design tokens (see DESIGN.md). Expanded in KL-002.

use ratatui::style::{Color, Style};

/// Theme identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeId {
    #[default]
    Dark,
    Light,
    HighContrast,
}

/// Resolved colors for the active theme.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub id: ThemeId,
    pub bg: Color,
    pub fg: Color,
    pub fg_muted: Color,
    pub accent: Color,
    pub accent_secondary: Color,
    pub border: Color,
    pub border_focus: Color,
}

impl Theme {
    pub fn dark() -> Self {
        Self {
            id: ThemeId::Dark,
            bg: Color::Rgb(11, 15, 20),
            fg: Color::Rgb(230, 237, 243),
            fg_muted: Color::Rgb(139, 155, 176),
            accent: Color::Rgb(46, 196, 182),
            accent_secondary: Color::Rgb(244, 162, 97),
            border: Color::Rgb(42, 53, 68),
            border_focus: Color::Rgb(46, 196, 182),
        }
    }

    pub fn light() -> Self {
        Self {
            id: ThemeId::Light,
            bg: Color::Rgb(247, 249, 252),
            fg: Color::Rgb(26, 35, 48),
            fg_muted: Color::Rgb(100, 116, 139),
            accent: Color::Rgb(13, 148, 136),
            accent_secondary: Color::Rgb(194, 65, 12),
            border: Color::Rgb(203, 213, 225),
            border_focus: Color::Rgb(13, 148, 136),
        }
    }

    pub fn high_contrast() -> Self {
        Self {
            id: ThemeId::HighContrast,
            bg: Color::Black,
            fg: Color::White,
            fg_muted: Color::Gray,
            accent: Color::Cyan,
            accent_secondary: Color::Yellow,
            border: Color::White,
            border_focus: Color::Cyan,
        }
    }

    pub fn from_id(id: ThemeId) -> Self {
        match id {
            ThemeId::Dark => Self::dark(),
            ThemeId::Light => Self::light(),
            ThemeId::HighContrast => Self::high_contrast(),
        }
    }

    /// Respect `NO_COLOR` by stripping to terminal defaults.
    pub fn apply_no_color(mut self, no_color: bool) -> Self {
        if !no_color {
            return self;
        }
        self.bg = Color::Reset;
        self.fg = Color::Reset;
        self.fg_muted = Color::Reset;
        self.accent = Color::Reset;
        self.accent_secondary = Color::Reset;
        self.border = Color::Reset;
        self.border_focus = Color::Reset;
        self
    }

    pub fn title_style(&self) -> Style {
        Style::default().fg(self.accent)
    }

    pub fn text_style(&self) -> Style {
        Style::default().fg(self.fg)
    }

    pub fn muted_style(&self) -> Style {
        Style::default().fg(self.fg_muted)
    }

    pub fn border_style(&self, focused: bool) -> Style {
        Style::default().fg(if focused {
            self.border_focus
        } else {
            self.border
        })
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_resets_accents() {
        let t = Theme::dark().apply_no_color(true);
        assert_eq!(t.accent, Color::Reset);
    }
}
