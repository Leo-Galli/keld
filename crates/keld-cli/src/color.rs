//! Minimal ANSI styling for CLI output. Respects `--no-color`, `NO_COLOR`, and TTY.

use std::io::{self, IsTerminal};

/// Whether human CLI output should use ANSI colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorMode {
    pub enabled: bool,
}

impl ColorMode {
    /// Enable colors only when writing to a TTY and color is not disabled.
    pub fn detect(no_color_flag: bool) -> Self {
        let env_no_color = std::env::var_os("NO_COLOR").is_some();
        let dumb = std::env::var_os("TERM").is_some_and(|t| t == "dumb");
        let tty = io::stdout().is_terminal();
        Self {
            enabled: tty && !no_color_flag && !env_no_color && !dumb,
        }
    }

    pub const fn enabled(self) -> bool {
        self.enabled
    }

    pub fn paint(self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn green(self, text: &str) -> String {
        self.paint("32", text)
    }

    pub fn yellow(self, text: &str) -> String {
        self.paint("33", text)
    }

    pub fn red(self, text: &str) -> String {
        self.paint("31", text)
    }

    pub fn dim(self, text: &str) -> String {
        self.paint("2", text)
    }

    pub fn bold(self, text: &str) -> String {
        self.paint("1", text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paint_disabled_is_plain() {
        let c = ColorMode { enabled: false };
        assert_eq!(c.green("ok"), "ok");
        assert_eq!(c.bold("x"), "x");
    }

    #[test]
    fn paint_enabled_wraps_ansi() {
        let c = ColorMode { enabled: true };
        assert_eq!(c.red("err"), "\x1b[31merr\x1b[0m");
    }
}
