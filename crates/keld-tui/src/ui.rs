//! Rendering: splash + responsive shell layout.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, FocusPane, Overlay, Phase};
use crate::dashboard::{self, severity_label};
use crate::logo::{self, WORDMARK};
use crate::probe_view::ProbeField;
use crate::scan_view::ScanField;
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
        Phase::Shell => {
            draw_shell(frame, area, app);
            match app.overlay {
                Overlay::None => {}
                Overlay::Palette => draw_palette(frame, area, app),
                Overlay::Help => draw_help(frame, area, app),
            }
        }
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
    match app.screen {
        Screen::AuditLog => draw_audit(frame, area, app, focused),
        Screen::Dashboard => draw_dashboard(frame, area, app, single_pane, focused),
        Screen::Jobs => draw_jobs(frame, area, app, focused),
        Screen::Scan => draw_scan(frame, area, app, focused),
        Screen::Probe => draw_probe(frame, area, app, focused),
        _ => {
            let title = format!(" {} ", app.screen.title());
            frame.render_widget(
                Paragraph::new(
                    "Module screen shell.\n\n\
                     Target form, results table and job controls arrive with the module tasks.",
                )
                .style(app.theme.text_style())
                .block(panel_block(app, title, focused)),
                area,
            );
        }
    }
}

fn field_label(active: bool, name: &str, value: &str, editing: bool) -> String {
    let cursor = if active && editing { "_" } else { "" };
    let mark = if active { ">" } else { " " };
    format!("{mark}{name} [{value}{cursor}]")
}

fn draw_scan(frame: &mut Frame<'_>, area: Rect, app: &App, focused: bool) {
    let scan = &app.scan;
    let dry = if scan.dry_run { "x" } else { " " };
    let state = match scan.run_state {
        crate::scan_view::ScanRunState::Idle => "idle",
        crate::scan_view::ScanRunState::Running => "running",
        crate::scan_view::ScanRunState::Done => "done",
        crate::scan_view::ScanRunState::Failed => "failed",
    };
    let bar_w = (area.width.saturating_sub(28) as usize).clamp(8, 24);
    let frac = scan.progress_fraction().unwrap_or(0.0);
    let filled = ((frac * bar_w as f64).round() as usize).min(bar_w);
    let bar = if app.ascii {
        format!("{}{}", "#".repeat(filled), "-".repeat(bar_w - filled))
    } else {
        format!("{}{}", "█".repeat(filled), "░".repeat(bar_w - filled))
    };

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(Span::styled(
            format!(
                "{}  {}",
                field_label(
                    scan.field == ScanField::Target,
                    "Target",
                    &scan.target,
                    scan.editing
                ),
                field_label(
                    scan.field == ScanField::Ports,
                    "Ports",
                    &scan.ports,
                    scan.editing
                )
            ),
            app.theme.text_style(),
        )),
        Line::from(Span::styled(
            format!(
                "{}  {}  [{}] dry-run  state:{}",
                field_label(
                    scan.field == ScanField::Concurrency,
                    "Concurrency",
                    &scan.concurrency,
                    scan.editing
                ),
                field_label(
                    scan.field == ScanField::Timeout,
                    "Timeout",
                    &scan.timeout_ms,
                    scan.editing
                ),
                dry,
                state
            ),
            app.theme.text_style(),
        )),
        Line::from(Span::styled(
            format!(
                "Enter edit  Tab fields  s start  p dry-run  y syn[{}]",
                if scan.syn { "x" } else { " " }
            ),
            app.theme.muted_style(),
        )),
        Line::from(Span::styled(
            format!(
                "Progress {} {}  {}",
                bar,
                scan.progress_label(),
                scan.message
            ),
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!(" {:<16} {:>6} {:<10}", "Host", "Port", "State"),
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
    ];
    if !scan.notice.is_empty() {
        lines.insert(
            3,
            Line::from(Span::styled(
                scan.notice.as_str(),
                Style::default().fg(app.theme.accent_secondary),
            )),
        );
    }

    if scan.results.is_empty() {
        lines.push(Line::from(Span::styled(
            "(no results yet)",
            app.theme.muted_style(),
        )));
    } else {
        let header_rows = if scan.notice.is_empty() { 6u16 } else { 7u16 };
        let inner_h = area.height.saturating_sub(2);
        let visible = inner_h.saturating_sub(header_rows + 2) as usize;
        let selected = scan.selected.min(scan.results.len() - 1);
        let start = if visible == 0 || selected < visible {
            0
        } else {
            selected + 1 - visible
        };
        for (i, hit) in scan
            .results
            .iter()
            .enumerate()
            .skip(start)
            .take(visible.max(1))
        {
            let marker = if i == selected {
                app.symbols.selected_marker()
            } else {
                " ".into()
            };
            let row = format!("{marker}{:<16} {:>6} {:<10}", hit.host, hit.port, hit.state);
            let style = if i == selected {
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                app.theme.text_style()
            };
            lines.push(Line::from(Span::styled(row, style)));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("Detail: {}", scan.detail_line()),
        app.theme.muted_style(),
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .style(app.theme.text_style())
            .block(panel_block(app, " Scan ", focused)),
        area,
    );
}

fn draw_probe(frame: &mut Frame<'_>, area: Rect, app: &App, focused: bool) {
    let probe = &app.probe;
    let dry = if probe.dry_run { "x" } else { " " };
    let state = match probe.run_state {
        crate::probe_view::ProbeRunState::Idle => "idle",
        crate::probe_view::ProbeRunState::Running => "running",
        crate::probe_view::ProbeRunState::Done => "done",
        crate::probe_view::ProbeRunState::Failed => "failed",
    };
    let bar_w = (area.width.saturating_sub(28) as usize).clamp(8, 24);
    let frac = probe.progress_fraction().unwrap_or(0.0);
    let filled = ((frac * bar_w as f64).round() as usize).min(bar_w);
    let bar = if app.ascii {
        format!("{}{}", "#".repeat(filled), "-".repeat(bar_w - filled))
    } else {
        format!("{}{}", "█".repeat(filled), "░".repeat(bar_w - filled))
    };

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(Span::styled(
            format!(
                "{}  {}",
                field_label(
                    probe.field == ProbeField::Target,
                    "Target",
                    &probe.target,
                    probe.editing
                ),
                field_label(
                    probe.field == ProbeField::Ports,
                    "Ports",
                    &probe.ports,
                    probe.editing
                )
            ),
            app.theme.text_style(),
        )),
        Line::from(Span::styled(
            format!(
                "{}  {}  [{}] dry-run  state:{}",
                field_label(
                    probe.field == ProbeField::Concurrency,
                    "Concurrency",
                    &probe.concurrency,
                    probe.editing
                ),
                field_label(
                    probe.field == ProbeField::Timeout,
                    "Timeout",
                    &probe.timeout_ms,
                    probe.editing
                ),
                dry,
                state
            ),
            app.theme.text_style(),
        )),
        Line::from(Span::styled(
            "Enter edit  Tab fields  s start  p dry-run",
            app.theme.muted_style(),
        )),
        Line::from(Span::styled(
            format!(
                "Progress {} {}  {}",
                bar,
                probe.progress_label(),
                probe.message
            ),
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!(
                " {:<14} {:>5} {:<10} {:<10}",
                "Host", "Port", "Service", "Product"
            ),
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    if probe.results.is_empty() {
        lines.push(Line::from(Span::styled(
            "(no results yet)",
            app.theme.muted_style(),
        )));
    } else {
        let header_rows = 6u16;
        let inner_h = area.height.saturating_sub(2);
        let visible = inner_h.saturating_sub(header_rows + 2) as usize;
        let selected = probe.selected.min(probe.results.len() - 1);
        let start = if visible == 0 || selected < visible {
            0
        } else {
            selected + 1 - visible
        };
        for (i, hit) in probe
            .results
            .iter()
            .enumerate()
            .skip(start)
            .take(visible.max(1))
        {
            let marker = if i == selected {
                app.symbols.selected_marker()
            } else {
                " ".into()
            };
            let service = if hit.planned {
                "planned"
            } else {
                hit.service.as_str()
            };
            let product = if hit.planned {
                hit.probe_name.as_str()
            } else {
                hit.product.as_str()
            };
            let row = format!(
                "{marker}{:<14} {:>5} {:<10} {:<10}",
                hit.host, hit.port, service, product
            );
            let style = if i == selected {
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                app.theme.text_style()
            };
            lines.push(Line::from(Span::styled(row, style)));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("Detail: {}", probe.detail_line()),
        app.theme.muted_style(),
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .style(app.theme.text_style())
            .block(panel_block(app, " Probe ", focused)),
        area,
    );
}

fn draw_dashboard(frame: &mut Frame<'_>, area: Rect, app: &App, single_pane: bool, focused: bool) {
    let title = if single_pane {
        " Dashboard  (Tab modules  m sidebar) "
    } else {
        " Dashboard "
    };
    let dash = &app.dashboard;
    let max_findings = dash.findings.iter().map(|f| f.count).max().unwrap_or(1);
    let bar_w = if area.width < 50 { 6 } else { 10 };
    let spark_w = (area.width.saturating_sub(28) as usize).clamp(8, 20);

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(Span::styled(
            format!(
                "ws:{}  findings:{}  open ports:{}",
                app.workspace_name,
                dash.findings_total(),
                dash.open_ports.len()
            ),
            app.theme.muted_style(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Findings by severity",
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    for f in &dash.findings {
        let bar = dashboard::bar(f.count, max_findings, bar_w, app.ascii);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<8} ", severity_label(f.severity)),
                app.theme.severity_style(f.severity),
            ),
            Span::styled(bar, app.theme.severity_style(f.severity)),
            Span::styled(format!("  {}", f.count), app.theme.text_style()),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            "Requests/s  ",
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            dashboard::sparkline(&dash.rps_samples, spark_w, app.ascii),
            Style::default().fg(app.theme.accent_secondary),
        ),
        Span::styled(
            format!("  {}/s", dash.current_rate()),
            app.theme.muted_style(),
        ),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Recent jobs",
        Style::default()
            .fg(app.theme.accent)
            .add_modifier(Modifier::BOLD),
    )));
    for job in dash.jobs.iter().take(4) {
        let prog = job
            .progress_pct()
            .map(|p| format!("{p}%"))
            .unwrap_or_else(|| "--".into());
        lines.push(Line::from(Span::styled(
            format!(
                " {}  {:<6} {:<8} {:>4}  {}",
                job.id_label(),
                job.job.module.as_str(),
                job.state_label(),
                prog,
                job.results_label
            ),
            app.theme.text_style(),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Open ports (top)",
        Style::default()
            .fg(app.theme.accent)
            .add_modifier(Modifier::BOLD),
    )));
    if dash.open_ports.is_empty() {
        lines.push(Line::from(Span::styled(
            " (none yet)",
            app.theme.muted_style(),
        )));
    } else {
        let ports: String = dash
            .open_ports
            .iter()
            .map(|p| format!("{}/{}", p.port, p.proto))
            .collect::<Vec<_>>()
            .join("  ");
        lines.push(Line::from(Span::styled(ports, app.theme.text_style())));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .style(app.theme.text_style())
            .block(panel_block(app, title, focused)),
        area,
    );
}

fn draw_jobs(frame: &mut Frame<'_>, area: Rect, app: &App, focused: bool) {
    let title = " Jobs ";
    let mut lines: Vec<Line<'_>> = vec![Line::from(Span::styled(
        format!(
            " {:<6} {:<8} {:<9} {:>8} {:>8}  {}",
            "id", "module", "state", "progress", "duration", "results"
        ),
        Style::default()
            .fg(app.theme.accent)
            .add_modifier(Modifier::BOLD),
    ))];

    let jobs = &app.dashboard.jobs;
    if jobs.is_empty() {
        lines.push(Line::from(Span::styled(
            "(no jobs yet)",
            app.theme.muted_style(),
        )));
    } else {
        let header_rows = 1u16;
        let inner_h = area.height.saturating_sub(2);
        let visible = inner_h.saturating_sub(header_rows) as usize;
        let selected = app.job_selected.min(jobs.len() - 1);
        let start = if visible == 0 || selected < visible {
            0
        } else {
            selected + 1 - visible
        };
        for (i, job) in jobs.iter().enumerate().skip(start).take(visible.max(1)) {
            let marker = if i == selected {
                app.symbols.selected_marker()
            } else {
                " ".into()
            };
            let prog = job
                .progress_pct()
                .map(|p| format!("{p}%"))
                .unwrap_or_else(|| "--".into());
            let row = format!(
                "{marker}{:<6} {:<8} {:<9} {:>8} {:>8}  {}",
                job.id_label(),
                job.job.module.as_str(),
                job.state_label(),
                prog,
                job.duration_label(),
                job.results_label
            );
            let style = if i == selected {
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                app.theme.text_style()
            };
            lines.push(Line::from(Span::styled(row, style)));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .style(app.theme.text_style())
            .block(panel_block(app, title, focused)),
        area,
    );
}

fn draw_audit(frame: &mut Frame<'_>, area: Rect, app: &App, focused: bool) {
    let path = app.audit_path.display();
    let filter_label = if app.audit_filtering {
        format!("filter: {}_", app.audit_filter)
    } else if app.audit_filter.is_empty() {
        "filter: (none)  / to filter".into()
    } else {
        format!("filter: {}  / edit  Esc clear", app.audit_filter)
    };
    let title = format!(" Audit log  {path} ");

    let filtered = app.audit_filtered();
    let mut lines: Vec<Line<'_>> = vec![
        Line::from(Span::styled(filter_label, app.theme.muted_style())),
        Line::from(Span::styled(
            format!(
                " {:<20} {:<8} {:<16} {:<14} {}",
                "time", "module", "target", "params", "outcome"
            ),
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    if filtered.is_empty() {
        lines.push(Line::from(Span::styled(
            if app.audit_entries.is_empty() {
                "(no audit entries yet)"
            } else {
                "(no matches)"
            },
            app.theme.muted_style(),
        )));
    } else {
        let header_rows = 2u16;
        let inner_h = area.height.saturating_sub(2);
        let visible = inner_h.saturating_sub(header_rows) as usize;
        let selected = app.audit_selected.min(filtered.len() - 1);
        let start = if visible == 0 || selected < visible {
            0
        } else {
            selected + 1 - visible
        };
        for (i, entry) in filtered.iter().enumerate().skip(start).take(visible.max(1)) {
            let marker = if i == selected {
                app.symbols.selected_marker()
            } else {
                " ".into()
            };
            let row = format!(
                "{marker}{:<20} {:<8} {:<16} {:<14} {}",
                truncate(&entry.timestamp, 20, app.ascii),
                truncate(&entry.module, 8, app.ascii),
                truncate(&entry.target, 16, app.ascii),
                truncate(&entry.parameters, 14, app.ascii),
                entry.outcome
            );
            let style = if i == selected {
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                app.theme.text_style()
            };
            lines.push(Line::from(Span::styled(row, style)));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .style(app.theme.text_style())
            .block(panel_block(app, title, focused)),
        area,
    );
}

fn truncate(s: &str, max: usize, ascii: bool) -> String {
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    if max <= 1 {
        return s.chars().take(max).collect();
    }
    let mark = if ascii { "." } else { "…" };
    let take = max.saturating_sub(mark.chars().count());
    let mut out: String = s.chars().take(take).collect();
    out.push_str(mark);
    out
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
    let list_hint = match app.key_preset {
        crate::keys::KeyPreset::Vim => "j/k",
        crate::keys::KeyPreset::Arrows => "Up/Down",
    };
    let list_screen_hint = match app.screen {
        Screen::AuditLog if app.audit_filtering => "  Enter done  Esc clear".to_string(),
        Screen::AuditLog => format!("  / filter  {list_hint} select"),
        Screen::Jobs => format!("  {list_hint} select"),
        Screen::Scan if app.scan.editing => "  Enter done  Tab fields".to_string(),
        Screen::Scan => format!("  s start  p dry-run  y syn  {list_hint} select"),
        Screen::Probe if app.probe.editing => "  Enter done  Tab fields".to_string(),
        Screen::Probe => format!("  s start  p dry-run  {list_hint} select"),
        _ => String::new(),
    };
    let text = format!(
        " scope: {}  jobs:{}  rate:{}/s  err:{}  |  {focus_hint}{narrow_hint}{list_screen_hint}  : cmd  ? help  q quit  |  {} [{}]",
        app.scope_summary,
        app.dashboard.running_count(),
        app.dashboard.current_rate(),
        app.dashboard.error_count(),
        app.screen.title(),
        app.key_preset.label()
    );
    frame.render_widget(
        Paragraph::new(Span::styled(text, app.theme.muted_style())),
        area,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup[1])[1]
}

fn draw_palette(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let popup = centered_rect(70, 50, area);
    frame.render_widget(Clear, popup);

    let filtered = app.palette_filtered();
    let mut lines: Vec<Line<'_>> = vec![Line::from(Span::styled(
        format!(": {}_", app.palette_query),
        Style::default()
            .fg(app.theme.accent)
            .add_modifier(Modifier::BOLD),
    ))];

    if filtered.is_empty() {
        lines.push(Line::from(Span::styled(
            "(no matches)",
            app.theme.muted_style(),
        )));
    } else {
        let inner_h = popup.height.saturating_sub(2);
        let visible = inner_h.saturating_sub(1) as usize;
        let selected = app.palette_selected.min(filtered.len() - 1);
        let start = if visible == 0 || selected < visible {
            0
        } else {
            selected + 1 - visible
        };
        for (i, cmd) in filtered.iter().enumerate().skip(start).take(visible.max(1)) {
            let marker = if i == selected {
                app.symbols.selected_marker()
            } else {
                " ".into()
            };
            let style = if i == selected {
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                app.theme.text_style()
            };
            lines.push(Line::from(Span::styled(
                format!("{marker}{}", cmd.label),
                style,
            )));
        }
    }

    frame.render_widget(
        Paragraph::new(lines).block(panel_block(app, " Command palette ", true)),
        popup,
    );
}

fn draw_help(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let popup = centered_rect(72, 70, area);
    frame.render_widget(Clear, popup);

    let title = format!(" Help  ({}) ", app.key_preset.label());
    let mut lines: Vec<Line<'_>> = Vec::new();
    for (keys, action) in app.key_preset.help_rows() {
        if action.is_empty() {
            lines.push(Line::from(Span::styled(
                *keys,
                Style::default()
                    .fg(app.theme.accent_secondary)
                    .add_modifier(Modifier::BOLD),
            )));
        } else {
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {keys:<18} "),
                    Style::default()
                        .fg(app.theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(*action, app.theme.text_style()),
            ]));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Esc / ? / q  close",
        app.theme.muted_style(),
    )));

    frame.render_widget(
        Paragraph::new(lines).block(panel_block(app, title, true)),
        popup,
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
            scope_summary: "(no scope)".into(),
            scope: keld_core::Scope::empty(),
            audit_entries: Vec::new(),
            audit_path: std::path::PathBuf::from("audit.jsonl"),
            key_preset: crate::keys::KeyPreset::Vim,
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
        assert!(shot.contains("scope: 10.0.0.0/24"));
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
        assert!(shot.contains("Dashboard"));
        assert!(shot.contains("Findings"));
        assert!(!shot.contains(" Modules "));
        assert!(!shot.contains(" Nav "));
        assert_snapshot!("shell_single_65x20", shot);
    }

    #[test]
    fn dashboard_snapshot_80x24() {
        let app = shell_app();
        let shot = render(&app, 80, 24);
        assert!(shot.contains("Findings by severity"));
        assert!(shot.contains("Requests/s"));
        assert!(shot.contains("Recent jobs"));
        assert!(shot.contains("Open ports"));
        assert!(shot.contains("critical") || shot.contains("high"));
        assert_snapshot!("dashboard_80x24", shot);
    }

    #[test]
    fn jobs_snapshot_80x24() {
        let mut app = shell_app();
        app.screen = Screen::Jobs;
        app.focus = FocusPane::Main;
        let shot = render(&app, 80, 24);
        assert!(shot.contains("Jobs"));
        assert!(shot.contains("module"));
        assert!(shot.contains("running") || shot.contains("done"));
        assert!(shot.contains("j-00") || shot.contains("j-01"));
        assert_snapshot!("jobs_80x24", shot);
    }

    #[test]
    fn scan_snapshot_80x24() {
        use keld_modules::{PortHit, PortState};
        let mut app = shell_app();
        app.screen = Screen::Scan;
        app.focus = FocusPane::Main;
        app.scan.target = "10.0.0.5".into();
        app.scan.ports = "1-1024".into();
        app.scan.results = vec![
            PortHit {
                host: "10.0.0.5".into(),
                port: 22,
                state: PortState::Open,
            },
            PortHit {
                host: "10.0.0.5".into(),
                port: 80,
                state: PortState::Open,
            },
        ];
        app.scan.done = 42;
        app.scan.total = 100;
        app.scan.message = "scanning".into();
        let shot = render(&app, 80, 24);
        assert!(shot.contains("Scan"));
        assert!(shot.contains("10.0.0.5"));
        assert!(shot.contains("22"));
        assert!(shot.contains("open") || shot.contains("Open"));
        assert_snapshot!("scan_80x24", shot);
    }

    #[test]
    fn probe_snapshot_80x24() {
        use keld_modules::ProbeHit;
        let mut app = shell_app();
        app.screen = Screen::Probe;
        app.focus = FocusPane::Main;
        app.probe.target = "10.0.0.5".into();
        app.probe.ports = "22,80".into();
        app.probe.results = vec![
            ProbeHit {
                host: "10.0.0.5".into(),
                port: 22,
                service: "ssh".into(),
                product: "ssh".into(),
                banner: "SSH-2.0-OpenSSH_9.6".into(),
                probe_name: "null".into(),
                planned: false,
            },
            ProbeHit {
                host: "10.0.0.5".into(),
                port: 80,
                service: "http".into(),
                product: "http".into(),
                banner: "HTTP/1.0 200 OK".into(),
                probe_name: "httpget".into(),
                planned: false,
            },
        ];
        app.probe.done = 2;
        app.probe.total = 2;
        app.probe.message = "probing".into();
        let shot = render(&app, 80, 24);
        assert!(shot.contains("Probe"));
        assert!(shot.contains("10.0.0.5"));
        assert!(shot.contains("ssh"));
        assert!(shot.contains("http"));
        assert_snapshot!("probe_80x24", shot);
    }

    #[test]
    fn jobs_persist_when_switching_screens() {
        let mut app = shell_app();
        let before = app.dashboard.jobs[0].job.done;
        app.screen = Screen::Scan;
        for _ in 0..30 {
            app.on_tick();
        }
        assert_eq!(app.dashboard.jobs[0].job.done, before + 1);
        app.screen = Screen::Jobs;
        assert_eq!(app.dashboard.jobs[0].job.done, before + 1);
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
            ascii: false,
            ..test_opts(false)
        });
        app.clock_override = Some("12:00Z".into());
        let shot = render(&app, 120, 24);
        assert!(shot.contains("▸ Dashboard") || shot.contains('▸'));
    }

    #[test]
    fn ack_snapshot_80x24() {
        let mut app = App::new(TuiOptions {
            needs_ack: true,
            ..test_opts(false)
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

    #[test]
    fn audit_snapshot_80x24() {
        use keld_core::{AuditEntry, AuditOutcome};
        let mut app = shell_app();
        app.screen = Screen::AuditLog;
        app.focus = FocusPane::Main;
        app.audit_path = std::path::PathBuf::from("audit.jsonl");
        app.audit_entries = vec![
            AuditEntry {
                timestamp: "2026-11-26T10:00:00Z".into(),
                module: "scan".into(),
                target: "10.0.0.5".into(),
                parameters: "ports=1-1024".into(),
                outcome: AuditOutcome::Ok,
            },
            AuditEntry {
                timestamp: "2026-11-26T10:01:00Z".into(),
                module: "http".into(),
                target: "app.example.com".into(),
                parameters: "headers".into(),
                outcome: AuditOutcome::Denied,
            },
        ];
        let shot = render(&app, 80, 24);
        assert!(shot.contains("Audit log"));
        assert!(shot.contains("scan"));
        assert!(shot.contains("10.0.0.5"));
        assert!(shot.contains("denied") || shot.contains("Denied") || shot.contains("ok"));
        assert_snapshot!("audit_80x24", shot);
    }

    #[test]
    fn palette_snapshot_80x24() {
        let mut app = shell_app();
        app.open_palette();
        app.palette_query = "scan".into();
        let shot = render(&app, 80, 24);
        assert!(shot.contains("Command palette"));
        assert!(shot.contains(": scan"));
        assert!(shot.contains("Go to Scan"));
        assert_snapshot!("palette_80x24", shot);
    }

    #[test]
    fn help_snapshot_80x24() {
        let mut app = shell_app();
        app.open_help();
        let shot = render(&app, 80, 24);
        assert!(shot.contains("Help"));
        assert!(shot.contains("Vim"));
        assert!(shot.contains("Command palette"));
        assert_snapshot!("help_80x24", shot);
    }

    #[test]
    fn help_arrows_preset_label() {
        let mut app = shell_app();
        app.key_preset = crate::keys::KeyPreset::Arrows;
        app.open_help();
        let shot = render(&app, 80, 24);
        assert!(shot.contains("Arrows"));
        assert!(shot.contains("Up / Down"));
    }

    #[test]
    fn audit_filter_hides_rows() {
        use keld_core::{AuditEntry, AuditOutcome};
        let mut app = shell_app();
        app.screen = Screen::AuditLog;
        app.audit_entries = vec![
            AuditEntry {
                timestamp: "2026-11-26T10:00:00Z".into(),
                module: "scan".into(),
                target: "10.0.0.5".into(),
                parameters: "ports=22".into(),
                outcome: AuditOutcome::Ok,
            },
            AuditEntry {
                timestamp: "2026-11-26T11:00:00Z".into(),
                module: "tls".into(),
                target: "app.example.com".into(),
                parameters: "sni".into(),
                outcome: AuditOutcome::Error,
            },
        ];
        app.audit_filter = "tls".into();
        let shot = render(&app, 120, 24);
        assert!(shot.contains("tls"));
        assert!(!shot.contains("10.0.0.5"));
    }
}
