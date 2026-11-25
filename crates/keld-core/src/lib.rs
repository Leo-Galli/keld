//! Core types and shared helpers for Keld.
//!
//! Modules, CLI and TUI build on this crate. Active scanning logic lives in
//! `keld-modules`; this crate stays free of network I/O for now.

/// Crate version string (workspace package version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Product name.
pub const NAME: &str = "Keld";

/// Short tagline shown under the splash logo.
pub const TAGLINE: &str = "recon . audit . report";

/// Authorized-use notice (CLI help, README, first-launch TUI).
pub const AUTHORIZED_USE: &str =
    "Keld is for systems you own or are explicitly authorized to test. \
Unauthorized scanning may be illegal.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_semver_like() {
        assert!(!VERSION.is_empty());
        assert!(VERSION.contains('.'));
    }
}
