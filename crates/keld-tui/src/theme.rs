//! TUI design tokens: themes, color depth, severity styles (DESIGN.md).

use ratatui::style::{Color, Modifier, Style};

/// Theme identifier (Settings wiring lands in KL-023).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeId {
    #[default]
    Dark,
    Light,
    HighContrast,
}

/// How aggressively colors are quantized for the terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorDepth {
    /// 24-bit `Color::Rgb`.
    #[default]
    TrueColor,
    /// 8-bit `Color::Indexed`.
    Ansi256,
    /// Named ANSI 16 colors.
    Ansi16,
    /// `NO_COLOR` / `--no-color`: strip to `Color::Reset`.
    None,
}

/// Raw RGB token before depth resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    pub fn to_color(self, depth: ColorDepth) -> Color {
        match depth {
            ColorDepth::None => Color::Reset,
            ColorDepth::TrueColor => Color::Rgb(self.r, self.g, self.b),
            ColorDepth::Ansi256 => Color::Indexed(rgb_to_ansi256(self.r, self.g, self.b)),
            ColorDepth::Ansi16 => nearest_ansi16(self.r, self.g, self.b),
        }
    }
}

/// Palette tokens as RGB (truecolor source of truth).
#[derive(Debug, Clone, Copy)]
struct Palette {
    bg: Rgb,
    bg_panel: Rgb,
    bg_elevated: Rgb,
    fg: Rgb,
    fg_muted: Rgb,
    fg_dim: Rgb,
    accent_primary: Rgb,
    accent_secondary: Rgb,
    border: Rgb,
    border_focus: Rgb,
    info: Rgb,
    low: Rgb,
    medium: Rgb,
    high: Rgb,
    critical: Rgb,
    success: Rgb,
    error: Rgb,
}

impl Palette {
    const DARK: Self = Self {
        bg: Rgb::new(0x0B, 0x0F, 0x14),
        bg_panel: Rgb::new(0x12, 0x18, 0x21),
        bg_elevated: Rgb::new(0x1A, 0x23, 0x30),
        fg: Rgb::new(0xE6, 0xED, 0xF3),
        fg_muted: Rgb::new(0x8B, 0x9B, 0xB0),
        fg_dim: Rgb::new(0x5A, 0x6A, 0x7E),
        accent_primary: Rgb::new(0x2E, 0xC4, 0xB6),
        accent_secondary: Rgb::new(0xF4, 0xA2, 0x61),
        border: Rgb::new(0x2A, 0x35, 0x44),
        border_focus: Rgb::new(0x2E, 0xC4, 0xB6),
        info: Rgb::new(0x5D, 0xAD, 0xE2),
        low: Rgb::new(0x82, 0xC9, 0x1E),
        medium: Rgb::new(0xF4, 0xA2, 0x61),
        high: Rgb::new(0xE7, 0x6F, 0x51),
        critical: Rgb::new(0xFF, 0x4D, 0x6D),
        success: Rgb::new(0x2E, 0xC4, 0xB6),
        error: Rgb::new(0xFF, 0x4D, 0x6D),
    };

    const LIGHT: Self = Self {
        bg: Rgb::new(0xF7, 0xF9, 0xFC),
        bg_panel: Rgb::new(0xEE, 0xF2, 0xF7),
        bg_elevated: Rgb::new(0xE2, 0xE8, 0xF0),
        fg: Rgb::new(0x1A, 0x23, 0x30),
        fg_muted: Rgb::new(0x64, 0x74, 0x8B),
        fg_dim: Rgb::new(0x94, 0xA3, 0xB8),
        accent_primary: Rgb::new(0x0D, 0x94, 0x88),
        accent_secondary: Rgb::new(0xC2, 0x41, 0x0C),
        border: Rgb::new(0xCB, 0xD5, 0xE1),
        border_focus: Rgb::new(0x0D, 0x94, 0x88),
        info: Rgb::new(0x02, 0x84, 0xC7),
        low: Rgb::new(0x4D, 0x7C, 0x0F),
        medium: Rgb::new(0xC2, 0x41, 0x0C),
        high: Rgb::new(0xC2, 0x41, 0x0C),
        critical: Rgb::new(0xBE, 0x12, 0x3C),
        success: Rgb::new(0x0D, 0x94, 0x88),
        error: Rgb::new(0xBE, 0x12, 0x3C),
    };

    /// Prefer named 16-color feel; RGB kept for truecolor/256 paths.
    const HIGH_CONTRAST: Self = Self {
        bg: Rgb::new(0x00, 0x00, 0x00),
        bg_panel: Rgb::new(0x00, 0x00, 0x00),
        bg_elevated: Rgb::new(0x1A, 0x1A, 0x1A),
        fg: Rgb::new(0xFF, 0xFF, 0xFF),
        fg_muted: Rgb::new(0xC0, 0xC0, 0xC0),
        fg_dim: Rgb::new(0x80, 0x80, 0x80),
        accent_primary: Rgb::new(0x00, 0xFF, 0xFF),
        accent_secondary: Rgb::new(0xFF, 0xFF, 0x00),
        border: Rgb::new(0xFF, 0xFF, 0xFF),
        border_focus: Rgb::new(0x00, 0xFF, 0xFF),
        info: Rgb::new(0x00, 0x7F, 0xFF),
        low: Rgb::new(0x00, 0xFF, 0x00),
        medium: Rgb::new(0xFF, 0xFF, 0x00),
        high: Rgb::new(0xFF, 0x7F, 0x00),
        critical: Rgb::new(0xFF, 0x00, 0x00),
        success: Rgb::new(0x00, 0xFF, 0x00),
        error: Rgb::new(0xFF, 0x00, 0x00),
    };

    fn for_id(id: ThemeId) -> Self {
        match id {
            ThemeId::Dark => Self::DARK,
            ThemeId::Light => Self::LIGHT,
            ThemeId::HighContrast => Self::HIGH_CONTRAST,
        }
    }
}

/// Finding / alert severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Resolved colors for the active theme and depth.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub id: ThemeId,
    pub depth: ColorDepth,
    pub bg: Color,
    pub bg_panel: Color,
    pub bg_elevated: Color,
    pub fg: Color,
    pub fg_muted: Color,
    pub fg_dim: Color,
    pub accent: Color,
    pub accent_secondary: Color,
    pub border: Color,
    pub border_focus: Color,
    pub info: Color,
    pub low: Color,
    pub medium: Color,
    pub high: Color,
    pub critical: Color,
    pub success: Color,
    pub error: Color,
    /// Source primary/secondary for splash gradient (truecolor RGB).
    pub gradient_primary: Rgb,
    pub gradient_secondary: Rgb,
}

impl Theme {
    pub fn resolve(id: ThemeId, depth: ColorDepth) -> Self {
        let p = Palette::for_id(id);
        // High-contrast prefers 16-color when truecolor is unavailable.
        let depth = match (id, depth) {
            (ThemeId::HighContrast, ColorDepth::Ansi256) => ColorDepth::Ansi16,
            (_, d) => d,
        };
        Self {
            id,
            depth,
            bg: p.bg.to_color(depth),
            bg_panel: p.bg_panel.to_color(depth),
            bg_elevated: p.bg_elevated.to_color(depth),
            fg: p.fg.to_color(depth),
            fg_muted: p.fg_muted.to_color(depth),
            fg_dim: p.fg_dim.to_color(depth),
            accent: p.accent_primary.to_color(depth),
            accent_secondary: p.accent_secondary.to_color(depth),
            border: p.border.to_color(depth),
            border_focus: p.border_focus.to_color(depth),
            info: p.info.to_color(depth),
            low: p.low.to_color(depth),
            medium: p.medium.to_color(depth),
            high: p.high.to_color(depth),
            critical: p.critical.to_color(depth),
            success: p.success.to_color(depth),
            error: p.error.to_color(depth),
            gradient_primary: p.accent_primary,
            gradient_secondary: p.accent_secondary,
        }
    }

    pub fn dark() -> Self {
        Self::resolve(ThemeId::Dark, ColorDepth::TrueColor)
    }

    pub fn light() -> Self {
        Self::resolve(ThemeId::Light, ColorDepth::TrueColor)
    }

    pub fn high_contrast() -> Self {
        Self::resolve(ThemeId::HighContrast, ColorDepth::TrueColor)
    }

    pub fn from_id(id: ThemeId) -> Self {
        Self::resolve(id, ColorDepth::TrueColor)
    }

    /// Build from id + detected depth, honoring `no_color`.
    pub fn for_runtime(id: ThemeId, no_color: bool) -> Self {
        let depth = if no_color {
            ColorDepth::None
        } else {
            detect_color_depth()
        };
        Self::resolve(id, depth)
    }

    /// Respect `NO_COLOR` by stripping to terminal defaults.
    pub fn apply_no_color(self, no_color: bool) -> Self {
        if !no_color {
            return self;
        }
        Self::resolve(self.id, ColorDepth::None)
    }

    pub fn with_depth(self, depth: ColorDepth) -> Self {
        Self::resolve(self.id, depth)
    }

    pub fn with_id(self, id: ThemeId) -> Self {
        Self::resolve(id, self.depth)
    }

    pub fn title_style(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn text_style(&self) -> Style {
        Style::default().fg(self.fg)
    }

    pub fn muted_style(&self) -> Style {
        Style::default().fg(self.fg_muted)
    }

    pub fn dim_style(&self) -> Style {
        Style::default().fg(self.fg_dim)
    }

    pub fn border_style(&self, focused: bool) -> Style {
        Style::default().fg(if focused {
            self.border_focus
        } else {
            self.border
        })
    }

    pub fn panel_style(&self) -> Style {
        Style::default().fg(self.fg).bg(self.bg_panel)
    }

    pub fn severity_color(&self, severity: Severity) -> Color {
        match severity {
            Severity::Info => self.info,
            Severity::Low => self.low,
            Severity::Medium => self.medium,
            Severity::High => self.high,
            Severity::Critical => self.critical,
        }
    }

    pub fn severity_style(&self, severity: Severity) -> Style {
        Style::default().fg(self.severity_color(severity))
    }

    /// Vertical gradient style for splash logo row `row` of `total`.
    pub fn gradient_style(&self, row: usize, total: usize) -> Style {
        if self.depth == ColorDepth::None {
            return Style::default();
        }
        let t = if total <= 1 {
            0.0
        } else {
            row as f32 / (total - 1) as f32
        };
        let a = self.gradient_primary;
        let b = self.gradient_secondary;
        let rgb = Rgb::new(lerp(a.r, b.r, t), lerp(a.g, b.g, t), lerp(a.b, b.b, t));
        Style::default().fg(rgb.to_color(self.depth))
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}

fn lerp(a: u8, b: u8, t: f32) -> u8 {
    (a as f32 + (b as f32 - a as f32) * t) as u8
}

/// Map RGB to xterm 256-color cube / grayscale.
pub fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
    // Prefer grayscale ramp when nearly gray.
    let avg = (u16::from(r) + u16::from(g) + u16::from(b)) / 3;
    let max_delta = r.abs_diff(g).max(g.abs_diff(b)).max(r.abs_diff(b));
    if max_delta < 8 {
        if avg < 8 {
            return 16;
        }
        if avg > 238 {
            return 231;
        }
        return (232 + ((avg - 8) / 10)) as u8;
    }
    let to_cube = |c: u8| -> u8 {
        if c < 48 {
            0
        } else if c < 115 {
            1
        } else {
            ((c - 35) / 40).min(5)
        }
    };
    16 + 36 * to_cube(r) + 6 * to_cube(g) + to_cube(b)
}

fn nearest_ansi16(r: u8, g: u8, b: u8) -> Color {
    const TABLE: [(Color, u8, u8, u8); 16] = [
        (Color::Black, 0, 0, 0),
        (Color::Red, 205, 0, 0),
        (Color::Green, 0, 205, 0),
        (Color::Yellow, 205, 205, 0),
        (Color::Blue, 0, 0, 238),
        (Color::Magenta, 205, 0, 205),
        (Color::Cyan, 0, 205, 205),
        (Color::Gray, 229, 229, 229),
        (Color::DarkGray, 127, 127, 127),
        (Color::LightRed, 255, 0, 0),
        (Color::LightGreen, 0, 255, 0),
        (Color::LightYellow, 255, 255, 0),
        (Color::LightBlue, 92, 92, 255),
        (Color::LightMagenta, 255, 0, 255),
        (Color::LightCyan, 0, 255, 255),
        (Color::White, 255, 255, 255),
    ];
    let mut best = TABLE[0].0;
    let mut best_dist = u32::MAX;
    for (color, tr, tg, tb) in TABLE {
        let dr = i32::from(r) - i32::from(tr);
        let dg = i32::from(g) - i32::from(tg);
        let db = i32::from(b) - i32::from(tb);
        let dist = (dr * dr + dg * dg + db * db) as u32;
        if dist < best_dist {
            best_dist = dist;
            best = color;
        }
    }
    best
}

/// Detect terminal color capability from environment (testable via [`color_depth_from_env`]).
pub fn detect_color_depth() -> ColorDepth {
    color_depth_from_env(
        std::env::var_os("NO_COLOR").is_some(),
        std::env::var("COLORTERM").ok().as_deref(),
        std::env::var("TERM").ok().as_deref(),
        std::env::var("TERM_PROGRAM").ok().as_deref(),
        std::env::var("TERM_PROGRAM_VERSION").ok().as_deref(),
        std::env::var("WT_SESSION").is_ok(),
    )
}

/// Pure color-depth resolution for unit tests.
pub fn color_depth_from_env(
    no_color: bool,
    colorterm: Option<&str>,
    term: Option<&str>,
    term_program: Option<&str>,
    term_program_version: Option<&str>,
    windows_terminal: bool,
) -> ColorDepth {
    if no_color {
        return ColorDepth::None;
    }

    // Apple Terminal.app before build 465 lacks reliable truecolor.
    if term_program == Some("Apple_Terminal") {
        let build = term_program_version
            .unwrap_or("0")
            .split(['.', '-'])
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        if build < 465 {
            let term = term.unwrap_or("");
            if term.contains("256color") || term.contains("256") {
                return ColorDepth::Ansi256;
            }
            return ColorDepth::Ansi16;
        }
    }

    if windows_terminal {
        return ColorDepth::TrueColor;
    }

    if let Some(ct) = colorterm {
        let ct = ct.to_ascii_lowercase();
        if ct.contains("truecolor") || ct.contains("24bit") {
            return ColorDepth::TrueColor;
        }
    }

    let term = term.unwrap_or("");
    if term.contains("truecolor") || term.ends_with("-direct") {
        return ColorDepth::TrueColor;
    }
    if term.contains("256color") || term.contains("256") {
        return ColorDepth::Ansi256;
    }
    if term.is_empty() || term == "dumb" {
        return ColorDepth::Ansi16;
    }

    // Modern defaults (Windows Terminal sets WT_SESSION; others often omit COLORTERM).
    ColorDepth::TrueColor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn themes_selectable_via_api() {
        assert_eq!(Theme::from_id(ThemeId::Dark).id, ThemeId::Dark);
        assert_eq!(Theme::light().id, ThemeId::Light);
        assert_eq!(Theme::high_contrast().accent, Color::Rgb(0, 255, 255));
        let switched = Theme::dark().with_id(ThemeId::Light);
        assert_eq!(switched.id, ThemeId::Light);
        assert_eq!(switched.accent, Color::Rgb(13, 148, 136));
    }

    #[test]
    fn no_color_resets_accents() {
        let t = Theme::dark().apply_no_color(true);
        assert_eq!(t.depth, ColorDepth::None);
        assert_eq!(t.accent, Color::Reset);
        assert_eq!(t.bg, Color::Reset);
        assert_eq!(t.critical, Color::Reset);
    }

    #[test]
    fn color_ladder_truecolor_256_16() {
        let rgb = Rgb::new(0x2E, 0xC4, 0xB6);
        assert_eq!(
            rgb.to_color(ColorDepth::TrueColor),
            Color::Rgb(46, 196, 182)
        );
        assert!(matches!(
            rgb.to_color(ColorDepth::Ansi256),
            Color::Indexed(_)
        ));
        assert!(!matches!(
            rgb.to_color(ColorDepth::Ansi16),
            Color::Rgb(_, _, _) | Color::Indexed(_)
        ));
        assert_eq!(rgb.to_color(ColorDepth::None), Color::Reset);
    }

    #[test]
    fn rgb_to_256_is_stable() {
        assert_eq!(rgb_to_ansi256(0, 0, 0), 16);
        assert_eq!(rgb_to_ansi256(255, 255, 255), 231);
        let teal = rgb_to_ansi256(46, 196, 182);
        assert!((16..=231).contains(&teal));
    }

    #[test]
    fn depth_detection_respects_no_color_and_colorterm() {
        assert_eq!(
            color_depth_from_env(
                true,
                Some("truecolor"),
                Some("xterm-256color"),
                None,
                None,
                false
            ),
            ColorDepth::None
        );
        assert_eq!(
            color_depth_from_env(false, Some("truecolor"), Some("xterm"), None, None, false),
            ColorDepth::TrueColor
        );
        assert_eq!(
            color_depth_from_env(false, None, Some("xterm-256color"), None, None, false),
            ColorDepth::Ansi256
        );
        assert_eq!(
            color_depth_from_env(false, None, Some("xterm"), None, None, true),
            ColorDepth::TrueColor
        );
        assert_eq!(
            color_depth_from_env(
                false,
                None,
                Some("xterm-256color"),
                Some("Apple_Terminal"),
                Some("455.1"),
                false
            ),
            ColorDepth::Ansi256
        );
        assert_eq!(
            color_depth_from_env(
                false,
                Some("truecolor"),
                Some("xterm-256color"),
                Some("Apple_Terminal"),
                Some("465"),
                false
            ),
            ColorDepth::TrueColor
        );
    }

    #[test]
    fn high_contrast_downgrades_256_to_16() {
        let t = Theme::resolve(ThemeId::HighContrast, ColorDepth::Ansi256);
        assert_eq!(t.depth, ColorDepth::Ansi16);
        assert_eq!(t.accent, Color::LightCyan);
    }

    #[test]
    fn severity_styles_differ() {
        let t = Theme::dark();
        assert_ne!(
            t.severity_color(Severity::Info),
            t.severity_color(Severity::Critical)
        );
    }

    #[test]
    fn gradient_uses_depth() {
        let t = Theme::resolve(ThemeId::Dark, ColorDepth::TrueColor);
        let s0 = t.gradient_style(0, 6);
        let s5 = t.gradient_style(5, 6);
        assert_ne!(s0.fg, s5.fg);
        let plain = Theme::resolve(ThemeId::Dark, ColorDepth::None).gradient_style(0, 6);
        assert_eq!(plain.fg, None);
    }
}
