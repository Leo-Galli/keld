# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Event bus (`EventBus` / `ModuleEvent`) and `Job` model in `keld-core`; stub module in `keld-modules` emits progress for TUI/CLI wiring
- Config load: `keld.toml` < env (`KELD_*`, `NO_COLOR`) < flags; `--config` / `--theme`; first-launch authorized-use acknowledgement persisted to config
- App shell polish: breakpoints (100 / 70 / 60x16), compact nav strip, single-pane, focus ring, `m` sidebar overlay
- Theme system: dark / light / high-contrast, truecolor / 256 / 16 / `NO_COLOR`, fixed Unicode symbols with ASCII fallbacks
- Initial workspace skeleton (`keld-core`, `keld-modules`, `keld-report`, `keld-tui`, `keld-cli`)
- Splash screen with KELD logo, empty TUI shell (header, sidebar, main, status)
- CLI entry: no args opens TUI; `--no-splash`, `--ascii`, `--version`
- CI workflow (fmt, clippy, test) on Windows, Linux, macOS
- Project docs: PLAN, DESIGN, PROGRESS, README, dual license, SECURITY, CONTRIBUTING
