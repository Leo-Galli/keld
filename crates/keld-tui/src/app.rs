//! Application state for the TUI shell.

use std::path::PathBuf;

use keld_core::{AuditEntry, ThemeName};

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
    /// Show the authorized-use acknowledgement before the shell.
    pub needs_ack: bool,
    /// Where to persist acknowledgement (and future settings).
    pub config_path: PathBuf,
    /// Active scope summary for header and status bar.
    pub scope_summary: String,
    /// Loaded audit entries (read-only viewer; append happens via core API).
    pub audit_entries: Vec<AuditEntry>,
    /// Path shown in the Audit log screen title.
    pub audit_path: PathBuf,
}

impl Default for TuiOptions {
    fn default() -> Self {
        Self {
            show_splash: true,
            ascii: false,
            no_color: std::env::var_os("NO_COLOR").is_some(),
            theme_id: ThemeId::Dark,
            needs_ack: true,
            config_path: PathBuf::from("keld.toml"),
            scope_summary: "(no scope)".into(),
            audit_entries: Vec::new(),
            audit_path: PathBuf::from("audit.jsonl"),
        }
    }
}

impl ThemeId {
    pub fn from_theme_name(name: ThemeName) -> Self {
        match name {
            ThemeName::Dark => Self::Dark,
            ThemeName::Light => Self::Light,
            ThemeName::HighContrast => Self::HighContrast,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Splash,
    Acknowledge,
    Shell,
}

/// Which panel owns the accent focus ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPane {
    Sidebar,
    Main,
}

/// Root TUI state.
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
    pub ack_checked: bool,
    pub needs_ack: bool,
    pub config_path: PathBuf,
    /// Last persistence error shown on the ack screen (if any).
    pub ack_error: Option<String>,
    pub audit_entries: Vec<AuditEntry>,
    pub audit_path: PathBuf,
    /// Substring filter for the Audit log screen (`/` to edit).
    pub audit_filter: String,
    /// Whether `/` filter input is active on the Audit log screen.
    pub audit_filtering: bool,
    /// Selected row in the filtered audit list.
    pub audit_selected: usize,
}

impl App {
    pub fn new(opts: TuiOptions) -> Self {
        let theme = Theme::for_runtime(opts.theme_id, opts.no_color);
        let phase = if opts.show_splash {
            Phase::Splash
        } else if opts.needs_ack {
            Phase::Acknowledge
        } else {
            Phase::Shell
        };
        Self {
            phase,
            screen: Screen::Dashboard,
            focus: FocusPane::Sidebar,
            sidebar_overlay: false,
            theme,
            ascii: opts.ascii,
            symbols: Symbols::for_mode(opts.ascii),
            should_quit: false,
            workspace_name: "default".into(),
            scope_summary: opts.scope_summary,
            clock_override: None,
            ack_checked: false,
            needs_ack: opts.needs_ack,
            config_path: opts.config_path,
            ack_error: None,
            audit_entries: opts.audit_entries,
            audit_path: opts.audit_path,
            audit_filter: String::new(),
            audit_filtering: false,
            audit_selected: 0,
        }
    }

    /// Filtered audit entries (oldest first), for the viewer.
    pub fn audit_filtered(&self) -> Vec<&AuditEntry> {
        self.audit_entries
            .iter()
            .filter(|e| e.matches_filter(&self.audit_filter))
            .collect()
    }

    fn clamp_audit_selection(&mut self) {
        let len = self.audit_filtered().len();
        if len == 0 {
            self.audit_selected = 0;
        } else if self.audit_selected >= len {
            self.audit_selected = len - 1;
        }
    }

    pub fn audit_select_next(&mut self) {
        let len = self.audit_filtered().len();
        if len == 0 {
            self.audit_selected = 0;
            return;
        }
        self.audit_selected = (self.audit_selected + 1).min(len - 1);
    }

    pub fn audit_select_prev(&mut self) {
        self.audit_selected = self.audit_selected.saturating_sub(1);
    }

    pub fn begin_audit_filter(&mut self) {
        self.audit_filtering = true;
        self.focus = FocusPane::Main;
    }

    pub fn end_audit_filter(&mut self) {
        self.audit_filtering = false;
    }

    pub fn clear_audit_filter(&mut self) {
        self.audit_filter.clear();
        self.audit_filtering = false;
        self.clamp_audit_selection();
    }

    pub fn audit_filter_push(&mut self, c: char) {
        if !c.is_control() {
            self.audit_filter.push(c);
            self.clamp_audit_selection();
        }
    }

    pub fn audit_filter_backspace(&mut self) {
        self.audit_filter.pop();
        self.clamp_audit_selection();
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
            self.phase = if self.needs_ack {
                Phase::Acknowledge
            } else {
                Phase::Shell
            };
        }
    }

    pub fn toggle_ack(&mut self) {
        if self.phase == Phase::Acknowledge {
            self.ack_checked = !self.ack_checked;
            self.ack_error = None;
        }
    }

    /// Confirm acknowledgement: persist then enter the shell.
    pub fn confirm_ack(&mut self) -> Result<(), String> {
        if self.phase != Phase::Acknowledge || !self.ack_checked {
            return Ok(());
        }
        keld_core::persist_authorized_ack(&self.config_path).map_err(|e| e.to_string())?;
        self.needs_ack = false;
        self.ack_error = None;
        self.phase = Phase::Shell;
        Ok(())
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
            Phase::Acknowledge => match key {
                KeyAction::Quit => self.quit(),
                KeyAction::ToggleAck => self.toggle_ack(),
                KeyAction::ConfirmAck => {
                    if let Err(e) = self.confirm_ack() {
                        self.ack_error = Some(e);
                    }
                }
                _ => {}
            },
            Phase::Shell => {
                if self.audit_filtering {
                    match key {
                        KeyAction::Quit => self.clear_audit_filter(),
                        KeyAction::ConfirmAck | KeyAction::EndFilter => self.end_audit_filter(),
                        KeyAction::FilterBackspace => self.audit_filter_backspace(),
                        KeyAction::FilterChar(c) => self.audit_filter_push(c),
                        _ => {}
                    }
                    return;
                }
                match key {
                    KeyAction::Quit => self.quit(),
                    KeyAction::NextScreen => {
                        self.screen = self.screen.next();
                        self.clamp_audit_selection();
                    }
                    KeyAction::PrevScreen => {
                        self.screen = self.screen.prev();
                        self.clamp_audit_selection();
                    }
                    KeyAction::NextFocus => self.cycle_focus(true),
                    KeyAction::PrevFocus => self.cycle_focus(false),
                    KeyAction::ToggleSidebar => self.toggle_sidebar_overlay(),
                    KeyAction::BeginFilter if self.screen == Screen::AuditLog => {
                        self.begin_audit_filter();
                    }
                    KeyAction::ListNext
                        if self.screen == Screen::AuditLog && self.focus == FocusPane::Main =>
                    {
                        self.audit_select_next();
                    }
                    KeyAction::ListPrev
                        if self.screen == Screen::AuditLog && self.focus == FocusPane::Main =>
                    {
                        self.audit_select_prev();
                    }
                    KeyAction::SkipSplash
                    | KeyAction::ToggleAck
                    | KeyAction::ConfirmAck
                    | KeyAction::BeginFilter
                    | KeyAction::EndFilter
                    | KeyAction::FilterBackspace
                    | KeyAction::FilterChar(_)
                    | KeyAction::ListNext
                    | KeyAction::ListPrev => {}
                }
            }
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
    ToggleAck,
    ConfirmAck,
    BeginFilter,
    EndFilter,
    FilterBackspace,
    FilterChar(char),
    ListNext,
    ListPrev,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(needs_ack: bool) -> TuiOptions {
        TuiOptions {
            show_splash: false,
            ascii: true,
            no_color: true,
            theme_id: ThemeId::Dark,
            needs_ack,
            config_path: PathBuf::from("keld.toml"),
            scope_summary: "(no scope)".into(),
            audit_entries: Vec::new(),
            audit_path: PathBuf::from("audit.jsonl"),
        }
    }

    #[test]
    fn audit_filter_and_selection() {
        use keld_core::{AuditEntry, AuditOutcome};
        let mut app = App::new(opts(false));
        app.screen = Screen::AuditLog;
        app.focus = FocusPane::Main;
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
        app.handle_key(KeyAction::BeginFilter);
        assert!(app.audit_filtering);
        app.handle_key(KeyAction::FilterChar('t'));
        app.handle_key(KeyAction::FilterChar('l'));
        app.handle_key(KeyAction::FilterChar('s'));
        assert_eq!(app.audit_filtered().len(), 1);
        app.handle_key(KeyAction::EndFilter);
        assert!(!app.audit_filtering);
        app.handle_key(KeyAction::ListNext);
        assert_eq!(app.audit_selected, 0);
        app.clear_audit_filter();
        app.handle_key(KeyAction::ListNext);
        assert_eq!(app.audit_selected, 1);
        app.handle_key(KeyAction::ListPrev);
        assert_eq!(app.audit_selected, 0);
    }

    #[test]
    fn cycle_focus_toggles_panes() {
        let mut app = App::new(opts(false));
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
        let mut app = App::new(opts(false));
        app.toggle_sidebar_overlay();
        assert!(app.sidebar_overlay);
        assert_eq!(app.focus, FocusPane::Sidebar);
        app.toggle_sidebar_overlay();
        assert!(!app.sidebar_overlay);
        assert_eq!(app.focus, FocusPane::Main);
    }

    #[test]
    fn starts_on_ack_when_needed() {
        let app = App::new(opts(true));
        assert_eq!(app.phase, Phase::Acknowledge);
    }

    #[test]
    fn splash_then_ack() {
        let mut app = App::new(TuiOptions {
            show_splash: true,
            needs_ack: true,
            ..opts(true)
        });
        assert_eq!(app.phase, Phase::Splash);
        app.skip_splash();
        assert_eq!(app.phase, Phase::Acknowledge);
    }

    #[test]
    fn confirm_ack_requires_checkbox() {
        let dir = std::env::temp_dir().join(format!(
            "keld-ack-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keld.toml");
        let mut app = App::new(TuiOptions {
            config_path: path.clone(),
            ..opts(true)
        });
        app.handle_key(KeyAction::ConfirmAck);
        assert_eq!(app.phase, Phase::Acknowledge);
        app.handle_key(KeyAction::ToggleAck);
        assert!(app.ack_checked);
        app.handle_key(KeyAction::ConfirmAck);
        assert_eq!(app.phase, Phase::Shell);
        assert!(!app.needs_ack);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("authorized_ack = true"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
