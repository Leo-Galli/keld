//! KELD logos: splash block, compact wordmark, ASCII fallback.

use keld_core::{TAGLINE, VERSION};
use ratatui::text::{Line, Span};

use crate::theme::Theme;

/// Unicode splash logo (exact product art).
pub const SPLASH_UNICODE: &[&str] = &[
    " ██╗  ██╗███████╗██╗     ██████╗ ",
    " ██║ ██╔╝██╔════╝██║     ██╔══██╗",
    " █████╔╝ █████╗  ██║     ██║  ██║",
    " ██╔═██╗ ██╔══╝  ██║     ██║  ██║",
    " ██║  ██╗███████╗███████╗██████╔╝",
    " ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝ ",
];

/// Plain ASCII splash for `--ascii` or limited terminals (`# / \\ _ |` only).
pub const SPLASH_ASCII: &[&str] = &[
    " #  # ##### #    ###  ",
    " # #  #     #    #  # ",
    " ##   ####  #    #  # ",
    " # #  #     #    #  # ",
    " #  # ##### #### ###  ",
];

/// Compact header wordmark.
pub const WORDMARK: &str = "KELD";

/// Choose splash lines for the current mode.
pub const fn splash_lines(ascii: bool) -> &'static [&'static str] {
    if ascii {
        SPLASH_ASCII
    } else {
        SPLASH_UNICODE
    }
}

/// Styled splash lines plus tagline and version, using the active theme gradient.
pub fn splash_text(ascii: bool, theme: &Theme) -> Vec<Line<'static>> {
    let lines = splash_lines(ascii);
    let total = lines.len();
    let mut out: Vec<Line<'static>> = lines
        .iter()
        .enumerate()
        .map(|(i, row)| Line::from(Span::styled(*row, theme.gradient_style(i, total))))
        .collect();
    out.push(Line::from(""));
    out.push(Line::from(Span::styled(
        format!("     {TAGLINE}"),
        theme.muted_style(),
    )));
    out.push(Line::from(Span::styled(
        format!("          v{VERSION}"),
        theme.dim_style(),
    )));
    out
}

/// Multi-line version banner for TTY `--version`.
pub fn version_banner(ascii: bool) -> String {
    let mut s = String::new();
    for line in splash_lines(ascii) {
        s.push_str(line);
        s.push('\n');
    }
    s.push_str(&format!("     {TAGLINE}\n"));
    s.push_str(&format!("keld {VERSION}\n"));
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{ColorDepth, Theme, ThemeId};
    use ratatui::style::Style;

    #[test]
    fn unicode_splash_has_six_rows() {
        assert_eq!(SPLASH_UNICODE.len(), 6);
    }

    #[test]
    fn ascii_splash_uses_allowed_chars_only() {
        for line in SPLASH_ASCII {
            for ch in line.chars() {
                assert!(
                    matches!(ch, '#' | '/' | '\\' | '_' | '|' | ' '),
                    "unexpected char {ch:?} in {line:?}"
                );
            }
        }
    }

    #[test]
    fn version_banner_mentions_keld() {
        let b = version_banner(true);
        assert!(b.contains("keld"));
        assert!(b.contains(VERSION));
    }

    #[test]
    fn splash_text_respects_no_color() {
        let theme = Theme::resolve(ThemeId::Dark, ColorDepth::None);
        let lines = splash_text(true, &theme);
        assert!(!lines.is_empty());
        assert_eq!(lines[0].spans[0].style, Style::default());
    }
}
