//! Keld terminal user interface.

pub mod app;
pub mod commands;
pub mod dashboard;
pub mod dns_view;
pub mod fuzz_view;
pub mod http_view;
pub mod keys;
pub mod logo;
pub mod probe_view;
pub mod run;
pub mod scan_view;
pub mod screen;
pub mod symbols;
pub mod theme;
pub mod tls_view;
pub mod ui;

pub use app::{App, FocusPane, Overlay, TuiOptions};
pub use commands::{filter_commands, Command, CommandId};
pub use keys::KeyPreset;
pub use logo::version_banner;
pub use run::{run, TuiError};
pub use symbols::Symbols;
pub use theme::{ColorDepth, Severity, Theme, ThemeId};
pub use ui::{LayoutMode, ShellBody};
