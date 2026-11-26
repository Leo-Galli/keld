//! Fixed Unicode symbol set with ASCII fallbacks (DESIGN.md).

/// Glyphs used by the shell; pick Unicode or ASCII via [`Symbols::for_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Symbols {
    pub bullet_on: &'static str,
    pub bullet_off: &'static str,
    pub caret: &'static str,
    pub caret_soft: &'static str,
    pub check: &'static str,
    pub cross: &'static str,
    pub vline: &'static str,
    pub hline: &'static str,
    pub corner_tl: &'static str,
    pub corner_tr: &'static str,
    pub corner_br: &'static str,
    pub corner_bl: &'static str,
    pub tee_l: &'static str,
    pub tee_r: &'static str,
    pub arrow_up: &'static str,
    pub arrow_down: &'static str,
    pub arrow_left: &'static str,
    pub arrow_right: &'static str,
    pub spinner: &'static [&'static str],
}

impl Symbols {
    pub const UNICODE: Self = Self {
        bullet_on: "●",
        bullet_off: "○",
        caret: "▸",
        caret_soft: "▹",
        check: "✓",
        cross: "✗",
        vline: "│",
        hline: "─",
        corner_tl: "╭",
        corner_tr: "╮",
        corner_br: "╯",
        corner_bl: "╰",
        tee_l: "├",
        tee_r: "┤",
        arrow_up: "▲",
        arrow_down: "▼",
        arrow_left: "◀",
        arrow_right: "▶",
        spinner: &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
    };

    pub const ASCII: Self = Self {
        bullet_on: "*",
        bullet_off: "o",
        caret: ">",
        caret_soft: "v",
        check: "[x]",
        cross: "[ ]",
        vline: "|",
        hline: "-",
        corner_tl: "+",
        corner_tr: "+",
        corner_br: "+",
        corner_bl: "+",
        tee_l: "+",
        tee_r: "+",
        arrow_up: "^",
        arrow_down: "v",
        arrow_left: "<",
        arrow_right: ">",
        spinner: &["|", "/", "-", "\\"],
    };

    pub const fn for_mode(ascii: bool) -> Self {
        if ascii {
            Self::ASCII
        } else {
            Self::UNICODE
        }
    }

    /// Sidebar / list selection marker including trailing space.
    pub fn selected_marker(self) -> String {
        format!("{} ", self.caret)
    }

    pub fn spinner_frame(self, tick: usize) -> &'static str {
        let frames = self.spinner;
        if frames.is_empty() {
            return " ";
        }
        frames[tick % frames.len()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_mode_uses_ascii_caret() {
        assert_eq!(Symbols::for_mode(true).caret, ">");
        assert_eq!(Symbols::for_mode(false).caret, "▸");
    }

    #[test]
    fn spinner_wraps() {
        let s = Symbols::ASCII;
        assert_eq!(s.spinner_frame(0), "|");
        assert_eq!(s.spinner_frame(4), "|");
    }

    #[test]
    fn unicode_set_matches_design() {
        let u = Symbols::UNICODE;
        assert_eq!(u.bullet_on, "●");
        assert_eq!(u.check, "✓");
        assert_eq!(u.corner_tl, "╭");
        assert_eq!(u.spinner.len(), 10);
    }
}
