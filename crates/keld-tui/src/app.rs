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

/// Which panel owns the accent focus ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPane {
    Sidebar,
    Main,
}

/// Root TUI state (empty shell for KL-001 / KL-003).
#[derive(Debug)]
pub struct App {
    pub phase: Phase,
    pub screen: Screen,
    pub focus: FocusPane,
    /// When true in Compact/Single layouts, show a full sidebar overlay (`m`).
    pub sidebar_overlay: bool,
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
            focus: FocusPane::Sidebar,
            sidebar_overlay: false,
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

    pub fn toggle_sidebar_overlay(&mut self) {
        self.sidebar_overlay = !self.sidebar_overlay;
        if self.sidebar_overlay {
            self.focus = FocusPane::Sidebar;
        } else {
            self.focus = FocusPane::Main;
        }
    }

    pub fn cycle_focus(&mut self, _forward: bool) {
        // Two panes: next and prev are the same toggle.
        self.focus = match self.focus {
            FocusPane::Sidebar => FocusPane::Main,
            FocusPane::Main => FocusPane::Sidebar,
        };
    }

    pub fn handle_key(&mut self, key: KeyAction) {
        match self.phase {
            Phase::Splash => {
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
                KeyAction::NextFocus => self.cycle_focus(true),
                KeyAction::PrevFocus => self.cycle_focus(false),
                KeyAction::ToggleSidebar => self.toggle_sidebar_overlay(),
                KeyAction::SkipSplash => {}
            },
        }
    }
}

/// Normalized keys the shell understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Quit,
    NextScreen,
    PrevScreen,
    NextFocus,
    PrevFocus,
    ToggleSidebar,
    SkipSplash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycle_focus_toggles_panes() {
        let mut app = App::new(TuiOptions {
            show_splash: false,
            ascii: true,
            no_color: true,
            theme_id: ThemeId::Dark,
        });
        assert_eq!(app.focus, FocusPane::Sidebar);
        app.cycle_focus(true);
        assert_eq!(app.focus, FocusPane::Main);
        app.cycle_focus(true);
        assert_eq!(app.focus, FocusPane::Sidebar);
        app.cycle_focus(false);
        assert_eq!(app.focus, FocusPane::Main);
    }

    #[test]
    fn toggle_sidebar_sets_focus() {
        let mut app = App::new(TuiOptions {
            show_splash: false,
            ascii: true,
            no_color: true,
            theme_id: ThemeId::Dark,
        });
        app.toggle_sidebar_overlay();
        assert!(app.sidebar_overlay);
        assert_eq!(app.focus, FocusPane::Sidebar);
        app.toggle_sidebar_overlay();
        assert!(!app.sidebar_overlay);
        assert_eq!(app.focus, FocusPane::Main);
    }
}
