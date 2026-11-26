//! Terminal setup, event loop, panic restore.

use std::io::{self, stdout};
use std::panic;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use thiserror::Error;

use crate::app::{App, FocusPane, KeyAction, Overlay, Phase, TuiOptions};
use crate::keys::KeyPreset;
use crate::screen::Screen;
use crate::ui::{self, LayoutMode, ShellBody};

const SPLASH_DURATION: Duration = Duration::from_millis(1200);
const TICK: Duration = Duration::from_millis(33);

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Run the full-screen TUI until the user quits.
pub fn run(opts: TuiOptions) -> Result<(), TuiError> {
    install_panic_hook();

    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(opts);
    let splash_started = Instant::now();
    let result = event_loop(&mut terminal, &mut app, splash_started);

    // Always restore terminal
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    splash_started: Instant,
) -> Result<(), TuiError> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        if app.should_quit {
            break;
        }

        if app.phase == Phase::Splash && splash_started.elapsed() >= SPLASH_DURATION {
            app.skip_splash();
            continue;
        }

        let timeout = if app.phase == Phase::Splash {
            SPLASH_DURATION
                .checked_sub(splash_started.elapsed())
                .unwrap_or(Duration::ZERO)
                .min(TICK)
        } else {
            TICK
        };

        if !event::poll(timeout)? {
            app.on_tick();
            continue;
        }

        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                let size = terminal.size()?;
                if let Some(action) = map_key(key.code, key.modifiers, app, size.width) {
                    app.handle_key(action);
                } else if app.phase == Phase::Splash {
                    app.skip_splash();
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
    Ok(())
}

fn sidebar_visible(app: &App, width: u16) -> bool {
    ShellBody::resolve(LayoutMode::from_width(width), app.sidebar_overlay).shows_sidebar()
}

fn map_key(code: KeyCode, modifiers: KeyModifiers, app: &App, width: u16) -> Option<KeyAction> {
    if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
        return Some(KeyAction::Quit);
    }
    if app.phase == Phase::Splash {
        return match code {
            KeyCode::Char('q') | KeyCode::Esc => Some(KeyAction::Quit),
            _ => Some(KeyAction::SkipSplash),
        };
    }

    if app.phase == Phase::Acknowledge {
        return match code {
            KeyCode::Char('q') | KeyCode::Esc => Some(KeyAction::Quit),
            KeyCode::Char(' ') => Some(KeyAction::ToggleAck),
            KeyCode::Enter => Some(KeyAction::ConfirmAck),
            _ => None,
        };
    }

    if app.overlay == Overlay::Help {
        return match code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => Some(KeyAction::CloseOverlay),
            _ => None,
        };
    }

    if app.overlay == Overlay::Palette {
        return map_palette_key(code, modifiers, app.key_preset);
    }

    if app.audit_filtering {
        return match code {
            KeyCode::Esc => Some(KeyAction::CloseOverlay),
            KeyCode::Enter => Some(KeyAction::EndFilter),
            KeyCode::Backspace => Some(KeyAction::FilterBackspace),
            KeyCode::Char(c) => Some(KeyAction::FilterChar(c)),
            _ => None,
        };
    }

    let module_editing = matches!(
        (
            app.screen,
            app.scan.editing,
            app.probe.editing,
            app.tls.editing,
            app.http.editing
        ),
        (Screen::Scan, true, _, _, _)
            | (Screen::Probe, _, true, _, _)
            | (Screen::Tls, _, _, true, _)
            | (Screen::Http, _, _, _, true)
    );
    if module_editing {
        return match code {
            KeyCode::Esc => Some(KeyAction::CloseOverlay),
            KeyCode::Enter => Some(KeyAction::EndFilter),
            KeyCode::Backspace => Some(KeyAction::FilterBackspace),
            KeyCode::Tab => Some(KeyAction::NextFocus),
            KeyCode::BackTab => Some(KeyAction::PrevFocus),
            KeyCode::Char(c) => Some(KeyAction::FilterChar(c)),
            _ => None,
        };
    }

    // Global shell keys (both presets).
    match code {
        KeyCode::Char(':') => return Some(KeyAction::OpenPalette),
        KeyCode::Char('?') => return Some(KeyAction::OpenHelp),
        KeyCode::Char('m') => return Some(KeyAction::ToggleSidebar),
        KeyCode::Char('q') | KeyCode::Esc => return Some(KeyAction::Quit),
        KeyCode::Char('s')
            if matches!(
                app.screen,
                Screen::Scan | Screen::Probe | Screen::Tls | Screen::Http
            ) =>
        {
            return Some(KeyAction::ScanStart);
        }
        KeyCode::Char('p')
            if matches!(
                app.screen,
                Screen::Scan | Screen::Probe | Screen::Tls | Screen::Http
            ) =>
        {
            return Some(KeyAction::ScanToggleDryRun);
        }
        KeyCode::Char('y') if app.screen == Screen::Scan => {
            return Some(KeyAction::ScanToggleSyn);
        }
        KeyCode::Char('/') if app.screen == Screen::AuditLog => {
            return Some(KeyAction::BeginFilter);
        }
        KeyCode::Tab => {
            let dual = sidebar_visible(app, width);
            return Some(if dual {
                KeyAction::NextFocus
            } else {
                KeyAction::NextScreen
            });
        }
        KeyCode::BackTab => {
            let dual = sidebar_visible(app, width);
            return Some(if dual {
                KeyAction::PrevFocus
            } else {
                KeyAction::PrevScreen
            });
        }
        KeyCode::Enter => return Some(KeyAction::Activate),
        _ => {}
    }

    map_nav_key(code, modifiers, app, width)
}

fn map_palette_key(
    code: KeyCode,
    _modifiers: KeyModifiers,
    _preset: KeyPreset,
) -> Option<KeyAction> {
    // Palette query accepts every printable char; selection always uses arrows.
    match code {
        KeyCode::Esc => Some(KeyAction::CloseOverlay),
        KeyCode::Enter => Some(KeyAction::Activate),
        KeyCode::Backspace => Some(KeyAction::FilterBackspace),
        KeyCode::Down => Some(KeyAction::ListNext),
        KeyCode::Up => Some(KeyAction::ListPrev),
        KeyCode::Char(c) => Some(KeyAction::FilterChar(c)),
        _ => None,
    }
}

fn map_nav_key(code: KeyCode, modifiers: KeyModifiers, app: &App, width: u16) -> Option<KeyAction> {
    let dual = sidebar_visible(app, width);
    let main_list = matches!(
        app.screen,
        Screen::AuditLog | Screen::Jobs | Screen::Scan | Screen::Probe | Screen::Tls | Screen::Http
    ) && (!dual || app.focus == FocusPane::Main)
        && !(app.screen == Screen::Scan && app.scan.editing)
        && !(app.screen == Screen::Probe && app.probe.editing)
        && !(app.screen == Screen::Tls && app.tls.editing)
        && !(app.screen == Screen::Http && app.http.editing);
    let audit_list = app.screen == Screen::AuditLog && main_list;
    let sidebar_nav = !dual || app.focus == FocusPane::Sidebar;

    if modifiers.contains(KeyModifiers::CONTROL) {
        if !audit_list || app.key_preset != KeyPreset::Vim {
            return None;
        }
        return match code {
            KeyCode::Char('d') => Some(KeyAction::PageDown),
            KeyCode::Char('u') => Some(KeyAction::PageUp),
            _ => None,
        };
    }

    if let Some(action) = preset_list_dir(code, app.key_preset) {
        if main_list {
            return Some(action);
        }
        if sidebar_nav {
            return match action {
                KeyAction::ListNext => Some(KeyAction::NextScreen),
                KeyAction::ListPrev => Some(KeyAction::PrevScreen),
                other => Some(other),
            };
        }
        return None;
    }

    match (app.key_preset, code) {
        (KeyPreset::Vim, KeyCode::Char('g')) => Some(KeyAction::ChordG),
        (KeyPreset::Vim, KeyCode::Char('G')) => {
            if main_list {
                Some(KeyAction::ListBottom)
            } else {
                None
            }
        }
        (KeyPreset::Arrows, KeyCode::Home) if main_list => Some(KeyAction::ListTop),
        (KeyPreset::Arrows, KeyCode::End) if main_list => Some(KeyAction::ListBottom),
        (KeyPreset::Arrows, KeyCode::PageDown) if audit_list => Some(KeyAction::PageDown),
        (KeyPreset::Arrows, KeyCode::PageUp) if audit_list => Some(KeyAction::PageUp),
        _ => None,
    }
}

fn preset_list_dir(code: KeyCode, preset: KeyPreset) -> Option<KeyAction> {
    match (preset, code) {
        (KeyPreset::Vim, KeyCode::Char('j')) => Some(KeyAction::ListNext),
        (KeyPreset::Vim, KeyCode::Char('k')) => Some(KeyAction::ListPrev),
        (KeyPreset::Arrows, KeyCode::Down) => Some(KeyAction::ListNext),
        (KeyPreset::Arrows, KeyCode::Up) => Some(KeyAction::ListPrev),
        _ => None,
    }
}

fn install_panic_hook() {
    let original = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
        original(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::ThemeId;
    use std::path::PathBuf;

    fn shell_app(preset: KeyPreset) -> App {
        App::new(TuiOptions {
            show_splash: false,
            ascii: true,
            no_color: true,
            theme_id: ThemeId::Dark,
            needs_ack: false,
            config_path: PathBuf::from("keld.toml"),
            scope_summary: "(no scope)".into(),
            scope: keld_core::Scope::empty(),
            audit_entries: Vec::new(),
            audit_path: PathBuf::from("audit.jsonl"),
            key_preset: preset,
        })
    }

    #[test]
    fn colon_opens_palette() {
        let app = shell_app(KeyPreset::Vim);
        assert_eq!(
            map_key(KeyCode::Char(':'), KeyModifiers::NONE, &app, 120),
            Some(KeyAction::OpenPalette)
        );
    }

    #[test]
    fn question_opens_help() {
        let app = shell_app(KeyPreset::Arrows);
        assert_eq!(
            map_key(KeyCode::Char('?'), KeyModifiers::NONE, &app, 120),
            Some(KeyAction::OpenHelp)
        );
    }

    #[test]
    fn vim_j_not_arrows() {
        let vim = shell_app(KeyPreset::Vim);
        assert_eq!(
            map_key(KeyCode::Char('j'), KeyModifiers::NONE, &vim, 120),
            Some(KeyAction::NextScreen)
        );
        assert_eq!(map_key(KeyCode::Down, KeyModifiers::NONE, &vim, 120), None);

        let arrows = shell_app(KeyPreset::Arrows);
        assert_eq!(
            map_key(KeyCode::Down, KeyModifiers::NONE, &arrows, 120),
            Some(KeyAction::NextScreen)
        );
        assert_eq!(
            map_key(KeyCode::Char('j'), KeyModifiers::NONE, &arrows, 120),
            None
        );
    }

    #[test]
    fn scan_y_toggles_syn_unless_editing() {
        let mut app = shell_app(KeyPreset::Vim);
        app.screen = Screen::Scan;
        app.focus = FocusPane::Main;
        assert_eq!(
            map_key(KeyCode::Char('y'), KeyModifiers::NONE, &app, 120),
            Some(KeyAction::ScanToggleSyn)
        );
        app.scan.editing = true;
        assert_eq!(
            map_key(KeyCode::Char('y'), KeyModifiers::NONE, &app, 120),
            Some(KeyAction::FilterChar('y'))
        );
    }
}
