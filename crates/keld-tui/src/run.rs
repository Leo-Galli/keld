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

use crate::app::{App, FocusPane, KeyAction, Phase, TuiOptions};
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
    // Body width approximates terminal width (header/status are full-width).
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

    let dual = sidebar_visible(app, width);
    match code {
        KeyCode::Char('q') | KeyCode::Esc => Some(KeyAction::Quit),
        KeyCode::Char('m') => Some(KeyAction::ToggleSidebar),
        KeyCode::Tab => {
            if dual {
                Some(KeyAction::NextFocus)
            } else {
                Some(KeyAction::NextScreen)
            }
        }
        KeyCode::BackTab => {
            if dual {
                Some(KeyAction::PrevFocus)
            } else {
                Some(KeyAction::PrevScreen)
            }
        }
        KeyCode::Up | KeyCode::Char('k') if !dual || app.focus == FocusPane::Sidebar => {
            Some(KeyAction::PrevScreen)
        }
        KeyCode::Down | KeyCode::Char('j') if !dual || app.focus == FocusPane::Sidebar => {
            Some(KeyAction::NextScreen)
        }
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
