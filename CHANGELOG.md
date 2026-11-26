# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `keld scan --syn`: optional IPv4 SYN probes when a raw TCP socket is allowed (root or `CAP_NET_RAW` on Unix). Otherwise the job falls back to TCP connect and prints the reason. `keld doctor` reports elevation, Npcap, and whether SYN is usable. The TUI Scan screen toggles the request with `y` and keeps the fallback line on screen.
- `keld scan`: TCP connect port scanner (ranges, lists, `top`/`top1000`, timeout, concurrency, `--dry-run`, `--rate`, `--json`); scope-gated; audit logged; TUI Scan screen with form, progress, results table
- Rate limiter helper in `keld-core`
- Dashboard screen: workspace overview, findings-by-severity bars, RPS sparkline, recent jobs, open-ports summary (placeholder data); Jobs list screen with progress/duration/results; jobs keep advancing across screen switches
- Command palette (`:`), help overlay (`?`), and Vim / Arrows keybinding presets (switch via palette; Settings persistence in KL-023)
- CLI framework: subcommands (`keld doctor`), global `--json` / `--dry-run` / `--rate` / `--concurrency`, colored human output (`NO_COLOR` / `--no-color`), Ctrl+C partial-save hook skeleton
- Audit log: append-only JSONL API (`AuditLog` / `AuditEntry`); `--audit-log` flag; read-only Audit log TUI screen with filter (`/`) and scroll
- Scope model: parse/validate `scope.toml` (includes, excludes, notes); `Scope::check` refuses out-of-scope/excluded targets; `--scope` flag; TUI status bar shows active scope summary
- Event bus (`EventBus` / `ModuleEvent`) and `Job` model in `keld-core`; stub module in `keld-modules` emits progress for TUI/CLI wiring
- Config load: `keld.toml` < env (`KELD_*`, `NO_COLOR`) < flags; `--config` / `--theme`; first-launch authorized-use acknowledgement persisted to config
- App shell polish: breakpoints (100 / 70 / 60x16), compact nav strip, single-pane, focus ring, `m` sidebar overlay
- Theme system: dark / light / high-contrast, truecolor / 256 / 16 / `NO_COLOR`, fixed Unicode symbols with ASCII fallbacks
- Initial workspace skeleton (`keld-core`, `keld-modules`, `keld-report`, `keld-tui`, `keld-cli`)
- Splash screen with KELD logo, empty TUI shell (header, sidebar, main, status)
- CLI entry: no args opens TUI; `--no-splash`, `--ascii`, `--version`
- CI workflow (fmt, clippy, test) on Windows, Linux, macOS
- Project docs: PLAN, DESIGN, PROGRESS, README, dual license, SECURITY, CONTRIBUTING
