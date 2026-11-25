# Keld Progress

## Current task

**KL-001** -- Workspace skeleton, splash screen, empty TUI shell, CI green, first PR merged

Acceptance:
- Cargo workspace: `keld-core`, `keld-modules`, `keld-report`, `keld-tui`, `keld-cli`
- `keld` with no args opens TUI; splash renders exact logo (skippable, `--no-splash`); empty shell (header/sidebar/main/status) renders
- Compact wordmark + ASCII fallback; `keld --version` shows logo on TTY
- Panic hook restores terminal
- Snapshot test(s) for shell at least at 80x24
- CI: fmt, clippy `-D warnings`, test on Windows/Linux/macOS
- Docs committed (PLAN, DESIGN, PROGRESS, README, licenses, SECURITY, CONTRIBUTING, CHANGELOG); `CLAUDE.md` not committed
- PR squash-merged to `main`

## Done

_(none yet)_

## Needs Leonardo

- crates.io publish token (optional later)
- Code-signing certificate (explicitly skipped; document SmartScreen)
- winget-pkgs fork + PAT / `WINGET_TOKEN` for auto-submit workflow (when releasing)
- Scoop / Homebrew taps if desired
- Manual TUI check matrix: Windows Terminal, PowerShell, conhost, Linux, macOS (after KL-001)

## Decisions log

- 2026-11-25: Stack pinned -- ratatui 0.30.2, crossterm 0.29, tokio 1.54, clap 4.6, cargo-dist 0.34, winget schema 1.28
- 2026-11-25: Dual license MIT OR Apache-2.0; PackageIdentifier `LeoGalli.Keld`
- 2026-11-25: `CLAUDE.md` never committed and never gitignored
- 2026-11-25: Pure Rust / rustls; no OpenSSL
- 2026-11-25: Modules emit events only; one engine, two front ends

## Backlog (ordered)

### Foundation

- **KL-002** -- Theme system (`theme.rs`): dark/light/high-contrast, truecolor/256/16/`NO_COLOR`, symbols + ASCII fallbacks; unit tests
- **KL-003** -- App shell polish: responsive breakpoints, sidebar collapse, terminal-too-small screen, focus ring; snapshots 80/120/200
- **KL-004** -- Config load (`keld.toml` + env + flags), first-launch acknowledgement persistence
- **KL-005** -- Event bus + Job model in `keld-core`; stub module that emits progress for TUI/CLI wiring
- **KL-006** -- Scope model + `scope.toml` parse/validate/exclude; refuse out-of-scope; status-bar scope summary
- **KL-007** -- Audit log (file + API); Audit log TUI viewer (read-only)
- **KL-008** -- CLI framework: global flags, `--json`, colored output, Ctrl+C partial-save hook skeleton, `keld doctor` stub
- **KL-009** -- Command palette + help overlay + keybinding presets (vim/arrows)
- **KL-010** -- Dashboard screen with placeholder charts/sparklines; Jobs list screen

### Modules

- **KL-011** -- `scan`: TCP connect scanner (ranges, top-ports, timeout, concurrency, dry-run); CLI + TUI + tests
- **KL-012** -- `scan`: optional SYN path (Npcap/root) with clear fallback messaging in doctor/TUI
- **KL-013** -- `probe`: banner/service detection + embedded signature file; CLI + TUI + tests
- **KL-014** -- `tls`: chain, expiry, protocols, weak ciphers, HSTS; CLI + TUI + tests
- **KL-015** -- `http`: headers, cookies, CORS, fingerprint, robots/sitemap; CLI + TUI + tests
- **KL-016** -- `fuzz`: dir + vhost wordlist discovery, filters; CLI + TUI + tests
- **KL-017** -- `dns`: records, AXFR check, wordlist + CT subdomains; CLI + TUI + tests
- **KL-018** -- `net`: interfaces + authorized subnet discovery (ARP/ICMP/TCP fallback); CLI + TUI + tests
- **KL-019** -- `hash`: type ID + offline wordlist check; CLI + TUI + tests

### Report, workspace, quality

- **KL-020** -- `report`: JSON/Markdown/HTML/CSV/SARIF; HTML logo; CLI + TUI
- **KL-021** -- `workspace`: SQLite projects (scope, results, audit); CLI + TUI
- **KL-022** -- Findings view (cross-module) + detail popup + export
- **KL-023** -- Settings screen wired to config; rate limits; splash/mouse/ascii/theme
- **KL-024** -- Completions + man page at build time
- **KL-025** -- `cargo deny` config + CI step; dependency policy
- **KL-026** -- Integration test harness (local listeners); expand module tests
- **KL-027** -- VHS demo tape + README GIF
- **KL-028** -- Manual terminal matrix recorded in Done notes

### Distribution

- **KL-029** -- cargo-dist / release workflow on tag; checksums
- **KL-030** -- First release `v0.1.0` artifacts on GitHub Releases
- **KL-031** -- winget manifests for `LeoGalli.Keld` + PR to winget-pkgs (or Needs Leonardo)
- **KL-032** -- Auto winget-releaser workflow if secrets exist; else document
- **KL-033** -- Optional crates.io / Scoop / Homebrew docs or publish (Needs Leonardo as required)
- **KL-034** -- README polish: badges, install, legal, keybindings; final consistency pass

When every task is Done, append `THE END` as the last line of this file.
