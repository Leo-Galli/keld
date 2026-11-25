//! KELD logos: splash block, compact wordmark, ASCII fallback.

use keld_core::{TAGLINE, VERSION};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

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

/// Vertical gradient from primary teal to secondary amber across logo rows.
pub fn gradient_style(row: usize, total: usize, ascii: bool) -> Style {
    if ascii {
        return Style::default().fg(Color::Cyan);
    }
    let t = if total <= 1 {
        0.0
    } else {
        row as f32 / (total - 1) as f32
    };
    // primary #2EC4B6 -> secondary #F4A261
    let r = lerp(0x2E, 0xF4, t);
    let g = lerp(0xC4, 0xA2, t);
    let b = lerp(0xB6, 0x61, t);
    Style::default().fg(Color::Rgb(r, g, b))
}

fn lerp(a: u8, b: u8, t: f32) -> u8 {
    let v = a as f32 + (b as f32 - a as f32) * t;
    v as u8
}

/// Styled splash lines plus tagline and version.
pub fn splash_text(ascii: bool) -> Vec<Line<'static>> {
    let lines = splash_lines(ascii);
    let total = lines.len();
    let mut out: Vec<Line<'static>> = lines
        .iter()
        .enumerate()
        .map(|(i, row)| Line::from(Span::styled(*row, gradient_style(i, total, ascii))))
        .collect();
    out.push(Line::from(""));
    out.push(Line::from(Span::styled(
        format!("     {TAGLINE}"),
        Style::default().fg(Color::Gray),
    )));
    out.push(Line::from(Span::styled(
        format!("          v{VERSION}"),
        Style::default().fg(Color::DarkGray),
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
}
