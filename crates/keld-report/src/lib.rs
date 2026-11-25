//! Report renderers for Keld findings.
//!
//! Formats land in later tasks: JSON, Markdown, HTML, CSV, SARIF.

use keld_core::NAME;

/// Placeholder renderer identity for the skeleton.
pub fn renderer_name() -> &'static str {
    NAME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_name_is_keld() {
        assert_eq!(renderer_name(), "Keld");
    }
}
