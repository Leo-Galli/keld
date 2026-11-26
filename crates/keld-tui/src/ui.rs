//! Rendering: splash + empty shell layout.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::{App, Phase};
use crate::logo::{self, WORDMARK};
use crate::screen::Screen;

const MIN_WIDTH: u16 = 60;
const MIN_HEIGHT: u16 = 16;
const SIDEBAR_BREAKPOINT: u16 = 100;

pub fn draw(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    frame.render_widget(Clear, area);

    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        draw_too_small(frame, area, app);
        return;
    }

    match app.phase {
        Phase::Splash => draw_splash(frame, area, app),
        Phase::Shell => draw_shell(frame, area, app),
    }
}

fn draw_too_small(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let msg = format!(
        "Terminal too small\nNeed at least {MIN_WIDTH}x{MIN_HEIGHT}. Current {}x{}.",
        area.width, area.height
    );
    let p = Paragraph::new(msg)
        .style(app.theme.text_style())
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(app.theme.border_style(true))
                .title("Keld"),
        );
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
    if area.width < SIDEBAR_BREAKPOINT {
        draw_main(frame, area, app, true);
        return;
    }

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(18), Constraint::Min(20)])
        .split(area);
    draw_sidebar(frame, cols[0], app);
    draw_main(frame, cols[1], app, false);
}

fn draw_sidebar(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let marker = app.symbols.selected_marker();
    let items: Vec<Line<'_>> = Screen::ALL
        .iter()
        .map(|s| {
            let selected = *s == app.screen;
            let prefix = if selected { marker.as_str() } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                app.theme.text_style()
            };
            Line::from(Span::styled(format!("{prefix}{}", s.title()), style))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border_style(true))
        .title(" Modules ");
    frame.render_widget(Paragraph::new(items).block(block), area);
}

fn draw_main(frame: &mut Frame<'_>, area: Rect, app: &App, compact: bool) {
    let title = format!(" {} ", app.screen.title());
    let text = match app.screen {
        Screen::Dashboard if compact => {
            "Dashboard (sidebar collapsed; Tab cycles modules)\n\n\
             Modules and jobs arrive in later tasks."
        }
        Screen::Dashboard => {
            "Workspace overview placeholder.\n\n\
             Findings chart, jobs and sparklines arrive in KL-010.\n\
             Use Tab / Shift+Tab to change modules. q quits."
        }
        _ => {
            "Module screen shell.\n\n\
             Target form, results table and job controls arrive with the module tasks."
        }
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border_style(true))
        .title(title);
    frame.render_widget(
        Paragraph::new(text)
            .style(app.theme.text_style())
            .block(block),
        area,
    );
}

fn draw_status(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let text = format!(
        " jobs:0  rate:0/s  err:0  |  Tab modules  ? help  q quit  |  {}",
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
        // Snapshot character grid only (stable); ignore styles via Debug of cells' symbols
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
        }
    }

    #[test]
    fn shell_snapshot_80x24() {
        let mut app = App::new(test_opts(false));
        app.scope_summary = "10.0.0.0/24".into();
        app.clock_override = Some("12:00Z".into());
        let shot = render(&app, 80, 24);
        assert!(shot.contains("KELD"));
        assert!(shot.contains("Dashboard"));
        assert_snapshot!("shell_80x24", shot);
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
    fn unicode_sidebar_uses_design_caret() {
        let mut app = App::new(TuiOptions {
            show_splash: false,
            ascii: false,
            no_color: true,
            theme_id: crate::theme::ThemeId::Dark,
        });
        app.clock_override = Some("12:00Z".into());
        let shot = render(&app, 120, 24);
        assert!(shot.contains("▸ Dashboard") || shot.contains('▸'));
    }
}
