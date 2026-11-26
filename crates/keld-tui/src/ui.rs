//! Rendering: splash + responsive shell layout.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, FocusPane, Phase};
use crate::logo::{self, WORDMARK};
use crate::screen::Screen;

const MIN_WIDTH: u16 = 60;
const MIN_HEIGHT: u16 = 16;
const SIDEBAR_BREAKPOINT: u16 = 100;
const SINGLE_PANE_BREAKPOINT: u16 = 70;
const SIDEBAR_FULL_WIDTH: u16 = 18;
const SIDEBAR_COMPACT_WIDTH: u16 = 8;

/// Responsive shell layout for the body area width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutMode {
    /// >= 100 cols: full sidebar + main.
    Full,
    /// 70..99 cols: abbreviated sidebar strip + main.
    Compact,
    /// < 70 cols: main only (unless overlay forced).
    Single,
}

impl LayoutMode {
    pub fn from_width(width: u16) -> Self {
        if width >= SIDEBAR_BREAKPOINT {
            Self::Full
        } else if width >= SINGLE_PANE_BREAKPOINT {
            Self::Compact
        } else {
            Self::Single
        }
    }
}

/// Effective body layout after applying the `m` overlay toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellBody {
    FullSidebar,
    CompactStrip,
    MainOnly,
}

impl ShellBody {
    pub fn resolve(mode: LayoutMode, overlay: bool) -> Self {
        match mode {
            LayoutMode::Full => Self::FullSidebar,
            LayoutMode::Compact if overlay => Self::FullSidebar,
            LayoutMode::Compact => Self::CompactStrip,
            LayoutMode::Single if overlay => Self::FullSidebar,
            LayoutMode::Single => Self::MainOnly,
        }
    }

    pub fn shows_sidebar(self) -> bool {
        !matches!(self, Self::MainOnly)
    }
}

pub fn draw(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    frame.render_widget(Clear, area);

    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        draw_too_small(frame, area, app);
        return;
    }

    match app.phase {
        Phase::Splash => draw_splash(frame, area, app),
        Phase::Acknowledge => draw_acknowledge(frame, area, app),
        Phase::Shell => draw_shell(frame, area, app),
    }
}

fn draw_acknowledge(frame: &mut Frame<'_>, area: Rect, app: &App) {
    use keld_core::{AUTHORIZED_ACK_PROMPT, AUTHORIZED_USE};

    let mark = if app.ack_checked { "[x]" } else { "[ ]" };
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(AUTHORIZED_USE, app.theme.text_style())),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!("{mark} "),
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(AUTHORIZED_ACK_PROMPT, app.theme.text_style()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Space toggle   Enter confirm   Esc quit",
            app.theme.muted_style(),
        )),
    ];
    if let Some(err) = &app.ack_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("Could not save acknowledgement: {err}"),
            Style::default().fg(app.theme.error),
        )));
    }

    let p = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true })
        .block(panel_block(app, "KELD  acknowledge authorized use", true));
    frame.render_widget(p, area);
}

fn draw_too_small(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let msg = format!(
        "Terminal too small\nNeed at least {MIN_WIDTH}x{MIN_HEIGHT}. Current {}x{}.",
        area.width, area.height
    );
    let p = Paragraph::new(msg)
        .style(app.theme.text_style())
        .alignment(Alignment::Center)
        .block(panel_block(app, "Keld", true));
    frame.render_widget(p, area);
}

fn draw_splash(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let lines = logo::splash_text(app.ascii, &app.theme);
    let height = lines.len() as u16 + 2;
    let width = lines
        .iter()
        .map(|l| l.width() as u16)
        .max()
        .unwrap_or(40)
        .saturating_add(4)
        .min(area.width);

    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height + 2) / 2;
    let logo_area = Rect {
        x,
        y,
        width,
        height,
    };

    let para = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .block(Block::default());
    frame.render_widget(para, logo_area);

    let hint = Paragraph::new(Line::from(Span::styled(
        "press any key to continue",
        app.theme.muted_style(),
    )))
    .alignment(Alignment::Center);
    let hint_y = (y + height + 1).min(area.y + area.height.saturating_sub(1));
    frame.render_widget(
        hint,
        Rect {
            x: area.x,
            y: hint_y,
            width: area.width,
            height: 1,
        },
    );
}

fn draw_shell(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(frame, chunks[0], app);
    draw_body(frame, chunks[1], app);
    draw_status(frame, chunks[2], app);
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mark = WORDMARK;
    let clock = app.clock_override.clone().unwrap_or_else(local_clock);
    let left = format!(
        "{mark}  ws:{}  scope: {}",
        app.workspace_name, app.scope_summary
    );
    let content_w = (left.chars().count() + 1 + clock.chars().count()) as u16;
    let pad = area.width.saturating_sub(content_w);
    let line = Line::from(vec![
        Span::styled(
            left,
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" ".repeat(pad as usize)),
        Span::styled(clock, app.theme.muted_style()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_body(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mode = LayoutMode::from_width(area.width);
    let body = ShellBody::resolve(mode, app.sidebar_overlay);

    match body {
        ShellBody::MainOnly => {
            draw_main(frame, area, app, true, true);
        }
        ShellBody::CompactStrip => {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(SIDEBAR_COMPACT_WIDTH),
                    Constraint::Min(20),
                ])
                .split(area);
            draw_sidebar(frame, cols[0], app, true);
            draw_main(frame, cols[1], app, false, app.focus == FocusPane::Main);
        }
        ShellBody::FullSidebar => {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(SIDEBAR_FULL_WIDTH), Constraint::Min(20)])
                .split(area);
            draw_sidebar(frame, cols[0], app, false);
            draw_main(frame, cols[1], app, false, app.focus == FocusPane::Main);
        }
    }
}

fn panel_block<'a>(app: &'a App, title: impl Into<String>, focused: bool) -> Block<'a> {
    let border_type = if app.ascii {
        BorderType::Plain
    } else {
        BorderType::Rounded
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(app.theme.border_style(focused))
        .title(title.into())
}

fn draw_sidebar(frame: &mut Frame<'_>, area: Rect, app: &App, compact: bool) {
    let marker = app.symbols.selected_marker();
    let focused = app.focus == FocusPane::Sidebar;
    let items: Vec<Line<'_>> = Screen::ALL
        .iter()
        .map(|s| {
            let selected = *s == app.screen;
            let label = if compact { s.abbrev() } else { s.title() };
            let prefix = if selected {
                if compact {
                    app.symbols.bullet_on
                } else {
                    marker.as_str()
                }
            } else if compact {
                " "
            } else {
                "  "
            };
            let style = if selected {
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                app.theme.text_style()
            };
            Line::from(Span::styled(format!("{prefix}{label}"), style))
        })
        .collect();

    let title = if compact { " Nav " } else { " Modules " };
    frame.render_widget(
        Paragraph::new(items).block(panel_block(app, title, focused)),
        area,
    );
}

fn draw_main(frame: &mut Frame<'_>, area: Rect, app: &App, single_pane: bool, focused: bool) {
    let title = format!(" {} ", app.screen.title());
    let text = match app.screen {
        Screen::Dashboard if single_pane => {
            "Dashboard (single-pane; Tab cycles modules, m toggles sidebar)\n\n\
             Modules and jobs arrive in later tasks."
        }
        Screen::Dashboard => {
            "Workspace overview placeholder.\n\n\
             Findings chart, jobs and sparklines arrive in KL-010.\n\
             Tab moves focus. Up/Down change modules when sidebar focused.\n\
             m toggles sidebar overlay below 100 cols. q quits."
        }
        _ => {
            "Module screen shell.\n\n\
             Target form, results table and job controls arrive with the module tasks."
        }
    };

    frame.render_widget(
        Paragraph::new(text)
            .style(app.theme.text_style())
            .block(panel_block(app, title, focused)),
        area,
    );
}

fn draw_status(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mode = LayoutMode::from_width(area.width);
    let focus_hint = match ShellBody::resolve(mode, app.sidebar_overlay) {
        ShellBody::MainOnly => "Tab modules",
        _ => "Tab focus",
    };
    let narrow_hint = if mode == LayoutMode::Full {
        ""
    } else {
        "  m sidebar"
    };
    let text = format!(
        " jobs:0  rate:0/s  err:0  |  {focus_hint}{narrow_hint}  ? help  q quit  |  {}",
        app.screen.title()
    );
    frame.render_widget(
        Paragraph::new(Span::styled(text, app.theme.muted_style())),
        area,
    );
}

fn local_clock() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // UTC hh:mm — good enough until chrono lands in a later task
    let mins_of_day = (secs / 60) % (24 * 60);
    format!("{:02}:{:02}Z", mins_of_day / 60, mins_of_day % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::TuiOptions;
    use insta::assert_snapshot;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn render(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        let buf = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..height {
            for x in 0..width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn test_opts(show_splash: bool) -> TuiOptions {
        TuiOptions {
            show_splash,
            ascii: true,
            no_color: true,
            theme_id: crate::theme::ThemeId::Dark,
            needs_ack: false,
            config_path: std::path::PathBuf::from("keld.toml"),
        }
    }

    fn shell_app() -> App {
        let mut app = App::new(test_opts(false));
        app.scope_summary = "10.0.0.0/24".into();
        app.clock_override = Some("12:00Z".into());
        app
    }

    #[test]
    fn layout_mode_breakpoints() {
        assert_eq!(LayoutMode::from_width(100), LayoutMode::Full);
        assert_eq!(LayoutMode::from_width(99), LayoutMode::Compact);
        assert_eq!(LayoutMode::from_width(70), LayoutMode::Compact);
        assert_eq!(LayoutMode::from_width(69), LayoutMode::Single);
        assert_eq!(LayoutMode::from_width(60), LayoutMode::Single);
    }

    #[test]
    fn shell_body_overlay_forces_full_sidebar() {
        assert_eq!(
            ShellBody::resolve(LayoutMode::Single, true),
            ShellBody::FullSidebar
        );
        assert_eq!(
            ShellBody::resolve(LayoutMode::Compact, true),
            ShellBody::FullSidebar
        );
        assert_eq!(
            ShellBody::resolve(LayoutMode::Single, false),
            ShellBody::MainOnly
        );
    }

    #[test]
    fn shell_snapshot_80x24() {
        let app = shell_app();
        let shot = render(&app, 80, 24);
        assert!(shot.contains("KELD"));
        assert!(shot.contains("Dash"));
        assert_snapshot!("shell_80x24", shot);
    }

    #[test]
    fn shell_snapshot_120x40() {
        let app = shell_app();
        let shot = render(&app, 120, 40);
        assert!(shot.contains("Modules"));
        assert!(shot.contains("Dashboard"));
        assert_snapshot!("shell_120x40", shot);
    }

    #[test]
    fn shell_snapshot_200x60() {
        let app = shell_app();
        let shot = render(&app, 200, 60);
        assert!(shot.contains("Modules"));
        assert_snapshot!("shell_200x60", shot);
    }

    #[test]
    fn splash_snapshot_80x24() {
        let app = App::new(test_opts(true));
        assert_snapshot!("splash_80x24", render(&app, 80, 24));
    }

    #[test]
    fn too_small_snapshot() {
        let app = App::new(test_opts(false));
        assert_snapshot!("too_small_40x10", render(&app, 40, 10));
    }

    #[test]
    fn single_pane_below_70() {
        let app = shell_app();
        let shot = render(&app, 65, 20);
        assert!(shot.contains("single-pane"));
        assert!(!shot.contains(" Modules "));
        assert!(!shot.contains(" Nav "));
        assert_snapshot!("shell_single_65x20", shot);
    }

    #[test]
    fn focus_ring_main_when_cycled() {
        let mut app = shell_app();
        app.focus = FocusPane::Main;
        let shot = render(&app, 120, 24);
        assert!(shot.contains("Modules"));
        assert!(shot.contains("Dashboard"));
    }

    #[test]
    fn unicode_sidebar_uses_design_caret() {
        let mut app = App::new(TuiOptions {
            show_splash: false,
            ascii: false,
            no_color: true,
            theme_id: crate::theme::ThemeId::Dark,
            needs_ack: false,
            config_path: std::path::PathBuf::from("keld.toml"),
        });
        app.clock_override = Some("12:00Z".into());
        let shot = render(&app, 120, 24);
        assert!(shot.contains("▸ Dashboard") || shot.contains('▸'));
    }

    #[test]
    fn ack_snapshot_80x24() {
        let mut app = App::new(TuiOptions {
            show_splash: false,
            ascii: true,
            no_color: true,
            theme_id: crate::theme::ThemeId::Dark,
            needs_ack: true,
            config_path: std::path::PathBuf::from("keld.toml"),
        });
        assert_eq!(app.phase, Phase::Acknowledge);
        let shot = render(&app, 80, 24);
        assert!(shot.contains("acknowledge"));
        assert!(shot.contains("[ ]"));
        assert_snapshot!("ack_80x24", shot);
        app.ack_checked = true;
        let shot = render(&app, 80, 24);
        assert!(shot.contains("[x]"));
    }
}
