//! Application state for the TUI shell.

use std::path::PathBuf;

use keld_core::{AuditEntry, ThemeName};

use crate::commands::{self, CommandId};
use crate::dashboard::DashboardState;
use crate::keys::KeyPreset;
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
    /// Initial keybinding preset (Settings persists this in KL-023).
    pub key_preset: KeyPreset,
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
            key_preset: KeyPreset::Vim,
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

/// Modal overlay on top of the shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Overlay {
    #[default]
    None,
    Palette,
    Help,
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
    pub key_preset: KeyPreset,
    pub overlay: Overlay,
    pub palette_query: String,
    pub palette_selected: usize,
    /// Vim `g` chord: waiting for a second `g`.
    pub pending_g: bool,
    /// Dashboard / Jobs shared state (jobs keep running across screen switches).
    pub dashboard: DashboardState,
    /// Selected row on the Jobs screen.
    pub job_selected: usize,
    /// Tick accumulator so job elapsed advances ~1s even at 30 FPS.
    tick_accum: u32,
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
            key_preset: opts.key_preset,
            overlay: Overlay::None,
            palette_query: String::new(),
            palette_selected: 0,
            pending_g: false,
            dashboard: DashboardState::placeholder(),
            job_selected: 0,
            tick_accum: 0,
        }
    }

    /// Called from the event loop on idle ticks; advances running jobs regardless of screen.
    pub fn on_tick(&mut self) {
        if self.phase != Phase::Shell {
            return;
        }
        // ~30 FPS tick; advance job clocks once per ~30 ticks (~1s).
        self.tick_accum = self.tick_accum.saturating_add(1);
        if self.tick_accum < 30 {
            return;
        }
        self.tick_accum = 0;
        self.dashboard.tick();
    }

    pub fn job_select_next(&mut self) {
        let len = self.dashboard.jobs.len();
        if len == 0 {
            self.job_selected = 0;
            return;
        }
        self.job_selected = (self.job_selected + 1).min(len - 1);
    }

    pub fn job_select_prev(&mut self) {
        self.job_selected = self.job_selected.saturating_sub(1);
    }

    pub fn job_select_first(&mut self) {
        self.job_selected = 0;
    }

    pub fn job_select_last(&mut self) {
        self.job_selected = self.dashboard.jobs.len().saturating_sub(1);
    }

    fn clamp_job_selection(&mut self) {
        let len = self.dashboard.jobs.len();
        if len == 0 {
            self.job_selected = 0;
        } else if self.job_selected >= len {
            self.job_selected = len - 1;
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

    pub fn audit_select_first(&mut self) {
        self.audit_selected = 0;
    }

    pub fn audit_select_last(&mut self) {
        let len = self.audit_filtered().len();
        self.audit_selected = len.saturating_sub(1);
    }

    pub fn audit_page(&mut self, down: bool, page: usize) {
        let len = self.audit_filtered().len();
        if len == 0 {
            self.audit_selected = 0;
            return;
        }
        if down {
            self.audit_selected = (self.audit_selected + page).min(len - 1);
        } else {
            self.audit_selected = self.audit_selected.saturating_sub(page);
        }
    }

    pub fn begin_audit_filter(&mut self) {
        self.audit_filtering = true;
        self.focus = FocusPane::Main;
        self.pending_g = false;
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

    pub fn open_palette(&mut self) {
        self.overlay = Overlay::Palette;
        self.palette_query.clear();
        self.palette_selected = 0;
        self.pending_g = false;
        self.audit_filtering = false;
    }

    pub fn open_help(&mut self) {
        self.overlay = Overlay::Help;
        self.pending_g = false;
        self.audit_filtering = false;
    }

    pub fn close_overlay(&mut self) {
        self.overlay = Overlay::None;
        self.palette_query.clear();
        self.palette_selected = 0;
        self.pending_g = false;
    }

    pub fn palette_filtered(&self) -> Vec<&'static commands::Command> {
        commands::filter_commands(&self.palette_query)
    }

    fn clamp_palette_selection(&mut self) {
        let len = self.palette_filtered().len();
        if len == 0 {
            self.palette_selected = 0;
        } else if self.palette_selected >= len {
            self.palette_selected = len - 1;
        }
    }

    pub fn palette_select_next(&mut self) {
        let len = self.palette_filtered().len();
        if len == 0 {
            self.palette_selected = 0;
            return;
        }
        self.palette_selected = (self.palette_selected + 1).min(len - 1);
    }

    pub fn palette_select_prev(&mut self) {
        self.palette_selected = self.palette_selected.saturating_sub(1);
    }

    pub fn palette_query_push(&mut self, c: char) {
        if !c.is_control() {
            self.palette_query.push(c);
            self.clamp_palette_selection();
        }
    }

    pub fn palette_query_backspace(&mut self) {
        self.palette_query.pop();
        self.clamp_palette_selection();
    }

    pub fn execute_selected_command(&mut self) {
        let id = self
            .palette_filtered()
            .get(self.palette_selected)
            .map(|c| c.id);
        self.close_overlay();
        if let Some(id) = id {
            self.run_command(id);
        }
    }

    pub fn run_command(&mut self, id: CommandId) {
        match id {
            CommandId::GoTo(screen) => {
                self.screen = screen;
                self.clamp_audit_selection();
                self.clamp_job_selection();
            }
            CommandId::ToggleSidebar => self.toggle_sidebar_overlay(),
            CommandId::OpenHelp => self.open_help(),
            CommandId::SetPreset(preset) => self.key_preset = preset,
            CommandId::CyclePreset => self.key_preset = self.key_preset.cycle(),
            CommandId::Quit => self.quit(),
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
            Phase::Shell => self.handle_shell_key(key),
        }
    }

    fn handle_shell_key(&mut self, key: KeyAction) {
        if self.overlay == Overlay::Help {
            match key {
                KeyAction::CloseOverlay | KeyAction::OpenHelp | KeyAction::Quit => {
                    self.close_overlay();
                }
                _ => {}
            }
            return;
        }

        if self.overlay == Overlay::Palette {
            match key {
                KeyAction::CloseOverlay | KeyAction::Quit => self.close_overlay(),
                KeyAction::ConfirmAck | KeyAction::Activate => self.execute_selected_command(),
                KeyAction::FilterBackspace => self.palette_query_backspace(),
                KeyAction::FilterChar(c) => self.palette_query_push(c),
                KeyAction::ListNext => self.palette_select_next(),
                KeyAction::ListPrev => self.palette_select_prev(),
                _ => {}
            }
            return;
        }

        if self.audit_filtering {
            match key {
                KeyAction::Quit | KeyAction::CloseOverlay => self.clear_audit_filter(),
                KeyAction::ConfirmAck | KeyAction::EndFilter | KeyAction::Activate => {
                    self.end_audit_filter();
                }
                KeyAction::FilterBackspace => self.audit_filter_backspace(),
                KeyAction::FilterChar(c) => self.audit_filter_push(c),
                _ => {}
            }
            return;
        }

        if !matches!(key, KeyAction::ChordG) {
            self.pending_g = false;
        }

        match key {
            KeyAction::Quit => self.quit(),
            KeyAction::CloseOverlay => {}
            KeyAction::OpenPalette => self.open_palette(),
            KeyAction::OpenHelp => self.open_help(),
            KeyAction::NextScreen => {
                self.screen = self.screen.next();
                self.clamp_audit_selection();
                self.clamp_job_selection();
            }
            KeyAction::PrevScreen => {
                self.screen = self.screen.prev();
                self.clamp_audit_selection();
                self.clamp_job_selection();
            }
            KeyAction::NextFocus => self.cycle_focus(true),
            KeyAction::PrevFocus => self.cycle_focus(false),
            KeyAction::ToggleSidebar => self.toggle_sidebar_overlay(),
            KeyAction::BeginFilter if self.screen == Screen::AuditLog => {
                self.begin_audit_filter();
            }
            KeyAction::ListNext if self.audit_list_nav() => self.audit_select_next(),
            KeyAction::ListPrev if self.audit_list_nav() => self.audit_select_prev(),
            KeyAction::ListTop if self.audit_list_nav() => self.audit_select_first(),
            KeyAction::ListBottom if self.audit_list_nav() => self.audit_select_last(),
            KeyAction::PageDown if self.audit_list_nav() => self.audit_page(true, 10),
            KeyAction::PageUp if self.audit_list_nav() => self.audit_page(false, 10),
            KeyAction::ListNext if self.jobs_list_nav() => self.job_select_next(),
            KeyAction::ListPrev if self.jobs_list_nav() => self.job_select_prev(),
            KeyAction::ListTop if self.jobs_list_nav() => self.job_select_first(),
            KeyAction::ListBottom if self.jobs_list_nav() => self.job_select_last(),
            KeyAction::ChordG if self.key_preset == KeyPreset::Vim => {
                if self.pending_g {
                    if self.audit_list_nav() {
                        self.audit_select_first();
                    } else if self.jobs_list_nav() {
                        self.job_select_first();
                    }
                    self.pending_g = false;
                } else {
                    self.pending_g = true;
                }
            }
            KeyAction::SkipSplash
            | KeyAction::ToggleAck
            | KeyAction::ConfirmAck
            | KeyAction::Activate
            | KeyAction::BeginFilter
            | KeyAction::EndFilter
            | KeyAction::FilterBackspace
            | KeyAction::FilterChar(_)
            | KeyAction::ListNext
            | KeyAction::ListPrev
            | KeyAction::ListTop
            | KeyAction::ListBottom
            | KeyAction::PageDown
            | KeyAction::PageUp
            | KeyAction::ChordG => {}
        }
    }

    fn audit_list_nav(&self) -> bool {
        self.screen == Screen::AuditLog && self.focus == FocusPane::Main
    }

    fn jobs_list_nav(&self) -> bool {
        self.screen == Screen::Jobs && self.focus == FocusPane::Main
    }
}

/// Normalized keys the shell understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Quit,
    CloseOverlay,
    OpenPalette,
    OpenHelp,
    NextScreen,
    PrevScreen,
    NextFocus,
    PrevFocus,
    ToggleSidebar,
    SkipSplash,
    ToggleAck,
    ConfirmAck,
    Activate,
    BeginFilter,
    EndFilter,
    FilterBackspace,
    FilterChar(char),
    ListNext,
    ListPrev,
    ListTop,
    ListBottom,
    PageDown,
    PageUp,
    ChordG,
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
            key_preset: KeyPreset::Vim,
        }
    }

    #[test]
    fn palette_fuzzy_and_execute_goto() {
        let mut app = App::new(opts(false));
        app.handle_key(KeyAction::OpenPalette);
        assert_eq!(app.overlay, Overlay::Palette);
        app.handle_key(KeyAction::FilterChar('a'));
        app.handle_key(KeyAction::FilterChar('u'));
        app.handle_key(KeyAction::FilterChar('d'));
        assert!(app
            .palette_filtered()
            .iter()
            .any(|c| matches!(c.id, CommandId::GoTo(Screen::AuditLog))));
        // Select audit if not first.
        while app
            .palette_filtered()
            .get(app.palette_selected)
            .map(|c| c.id)
            != Some(CommandId::GoTo(Screen::AuditLog))
        {
            let before = app.palette_selected;
            app.palette_select_next();
            if app.palette_selected == before {
                break;
            }
        }
        app.handle_key(KeyAction::Activate);
        assert_eq!(app.overlay, Overlay::None);
        assert_eq!(app.screen, Screen::AuditLog);
    }

    #[test]
    fn help_overlay_opens_and_closes() {
        let mut app = App::new(opts(false));
        app.handle_key(KeyAction::OpenHelp);
        assert_eq!(app.overlay, Overlay::Help);
        app.handle_key(KeyAction::CloseOverlay);
        assert_eq!(app.overlay, Overlay::None);
    }

    #[test]
    fn cycle_preset_via_command() {
        let mut app = App::new(opts(false));
        assert_eq!(app.key_preset, KeyPreset::Vim);
        app.run_command(CommandId::SetPreset(KeyPreset::Arrows));
        assert_eq!(app.key_preset, KeyPreset::Arrows);
        app.run_command(CommandId::CyclePreset);
        assert_eq!(app.key_preset, KeyPreset::Vim);
    }

    #[test]
    fn esc_closes_palette_without_quit() {
        let mut app = App::new(opts(false));
        app.open_palette();
        app.handle_key(KeyAction::Quit);
        assert!(!app.should_quit);
        assert_eq!(app.overlay, Overlay::None);
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
