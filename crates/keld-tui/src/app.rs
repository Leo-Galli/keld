//! Application state for the TUI shell.

use crate::screen::Screen;
use crate::symbols::Symbols;
use crate::theme::{Theme, ThemeId};

/// Runtime options shared with the CLI.
#[derive(Debug, Clone)]
pub struct TuiOptions {
    pub show_splash: bool,
    pub ascii: bool,
    pub no_color: bool,
    pub theme_id: ThemeId,
}

impl Default for TuiOptions {
    fn default() -> Self {
        Self {
            show_splash: true,
            ascii: false,
            no_color: std::env::var_os("NO_COLOR").is_some(),
            theme_id: ThemeId::Dark,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Splash,
    Shell,
}

/// Root TUI state (empty shell for KL-001).
#[derive(Debug)]
pub struct App {
    pub phase: Phase,
    pub screen: Screen,
    pub theme: Theme,
    pub ascii: bool,
    pub symbols: Symbols,
    pub should_quit: bool,
    pub workspace_name: String,
    pub scope_summary: String,
    /// When set, header shows this instead of the live clock (tests).
    pub clock_override: Option<String>,
}

impl App {
    pub fn new(opts: TuiOptions) -> Self {
        let theme = Theme::for_runtime(opts.theme_id, opts.no_color);
        Self {
            phase: if opts.show_splash {
                Phase::Splash
            } else {
                Phase::Shell
            },
            screen: Screen::Dashboard,
            theme,
            ascii: opts.ascii,
            symbols: Symbols::for_mode(opts.ascii),
            should_quit: false,
            workspace_name: "default".into(),
            scope_summary: "(no scope)".into(),
            clock_override: None,
        }
    }

    /// Switch theme at runtime (Settings screen wires this in KL-023).
    pub fn set_theme(&mut self, id: ThemeId) {
        self.theme = self.theme.with_id(id);
    }

    pub fn set_ascii(&mut self, ascii: bool) {
        self.ascii = ascii;
        self.symbols = Symbols::for_mode(ascii);
    }

    pub fn skip_splash(&mut self) {
        if self.phase == Phase::Splash {
            self.phase = Phase::Shell;
        }
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    pub fn handle_key(&mut self, key: KeyAction) {
        match self.phase {
            Phase::Splash => {
                // Any key skips splash (including quit keys).
                if matches!(key, KeyAction::Quit) {
                    self.quit();
                } else {
                    self.skip_splash();
                }
            }
            Phase::Shell => match key {
                KeyAction::Quit => self.quit(),
                KeyAction::NextScreen => self.screen = self.screen.next(),
                KeyAction::PrevScreen => self.screen = self.screen.prev(),
                KeyAction::SkipSplash => {}
            },
        }
    }
}

/// Normalized keys the shell understands in KL-001.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Quit,
    NextScreen,
    PrevScreen,
    SkipSplash,
}
