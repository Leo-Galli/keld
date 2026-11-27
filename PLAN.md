# Keld -- Plan

## Vision

Keld is an open-source, cross-platform toolkit for **authorized** penetration testing, reconnaissance and security auditing. It ships a scriptable CLI and a polished full-screen TUI of equal quality. Distribution: winget (primary), GitHub Releases, optionally crates.io, Scoop and Homebrew.

Tagline: `recon . audit . report`

## Scope

**In scope:** TCP/service recon, TLS and HTTP security checks, directory/vhost fuzzing, DNS enumeration, local network discovery on authorized subnets, offline hash identification/cracking of operator-supplied hashes, reporting, local workspaces, audit logging, scope enforcement.

**Out of scope:** malware, persistence, credential theft, exploitation payloads, AV/EDR evasion, unsolicited internet scanning, unpaid code-signing certificates, creating third-party accounts.

## Architecture

```
keld-cli ──┬── clap subcommands ──► CLI renderer (indicatif / JSON)
           └── no args ──────────► keld-tui (ratatui)
                    │
                    ▼
              event bus (tokio mpsc / broadcast)
                    │
         ┌──────────┼──────────┐
         ▼          ▼          ▼
    keld-modules  keld-core  keld-report
```

- **keld-core:** `Scope`, `RateLimiter`, `AuditLog`, target parsing (`IpAddr`, CIDR, hostname, URL), `Finding` / `Job` models, shared config load (`keld.toml` < env < flags).
- **keld-modules:** one module per feature behind `async trait Module` that emits `ModuleEvent::{Progress, Result, Log, Done, Error}`. Never prints.
- **keld-report:** merge findings into JSON, Markdown, self-contained HTML (logo as styled text), CSV, SARIF.
- **keld-tui:** immediate-mode ratatui app, ~30 FPS while busy, idle redraw on events. Work in tokio tasks only.
- **keld-cli:** binary `keld`. `keld` opens TUI; `keld <command>` runs CLI.

Errors: `thiserror` in libraries, `anyhow` in the binary. Logging: `tracing`. TLS/HTTP: `reqwest` + rustls. DNS: `hickory-resolver`. Storage: `rusqlite` (bundled). No OpenSSL. No `unsafe` unless documented and necessary.

## Modules

| ID | CLI / screen | Purpose |
|----|--------------|---------|
| scan | `keld scan` | TCP connect port scan; optional SYN (Npcap/root) with fallback |
| probe | `keld probe` | Service/banner detection from embedded signatures |
| tls | `keld tls` | Cert chain, expiry, protocols, weak ciphers, HSTS |
| http | `keld http` | Headers, cookies, CORS, tech fingerprint, robots/sitemap |
| fuzz | `keld fuzz` | Dir and vhost discovery from wordlists |
| dns | `keld dns` | Records, AXFR check, wordlist + CT subdomains |
| net | `keld net` | Interfaces, authorized subnet host discovery |
| hash | `keld hash` | Hash ID + offline wordlist check |
| report | `keld report` | Merge/export formats |
| workspace | `keld workspace` | SQLite projects: scope, results, audit |

Every active module requires a target scope (`scope.toml` or explicit targets). Exclusions supported. Out-of-scope targets refused. Defaults: sensible rate limits and concurrency. `--dry-run` shows what would be sent. Every action audited (timestamp, module, target, parameters).

## Data model (sketch)

- `Target`: host / IP / CIDR / URL + ports
- `Scope`: includes, excludes, notes; validated before jobs (`scope.toml`, `--scope`); IP/CIDR/hostname/URL-host; excludes win; `Scope::check` / TUI status summary
- `Finding`: id, severity, module, target, title, evidence, timestamps
- `Job`: id, module, state, progress, started/finished, counts
- `AuditEntry`: timestamp, module, target, params, outcome
- Workspace DB: SQLite file `{data_dir}/keld/workspaces/<name>/workspace.sqlite` (override `KELD_WORKSPACES_DIR`); stores scope TOML, findings, audit entries

## CLI design

- Quiet by default, colored readable output, `--json` on every command.
- Progress via `indicatif` (modules); Ctrl+C partial-save hook skeleton installed for CLI commands.
- `keld doctor`: TTY, color, Unicode, elevation, Npcap, SYN raw-socket capability (falls back to TCP connect), local network, scope.
- Shell completions + man page generated at build time.
- Global flags: `--config`, `--scope`, `--audit-log`, `--dry-run`, `--json`, `--ascii`, `--no-splash`, `--no-color`, `--theme`, `--rate`, `--concurrency`.

## TUI design

Full system in `DESIGN.md`. Flagship experience:

- Splash (~1.2s, skippable; disabled by `--no-splash` / config) with exact block logo + gradient + tagline + version.
- Compact wordmark in header; ASCII fallback when needed / `--ascii`.
- Layout: header | sidebar | main | status (scope always visible).
- Screens: Dashboard, each module, Jobs, Findings, Audit, Scope editor, Settings, first-launch acknowledgement + guided setup.
- Keys: vim and arrows presets, Tab focus, `/` filter, `:` command palette, `?` help, mouse optional.
- Panic hook restores terminal. Toast + confirm dialogs.

## Output formats

JSON (canonical), Markdown, self-contained HTML, CSV, SARIF 2.1.0. HTML report shows the KELD logo as styled text at the top.

## Testing

- Unit tests per module; integration tests spin local servers (no internet).
- TUI: `TestBackend` + `insta` snapshots at 80x24, 120x40, 200x60 for every screen; event-loop and keybinding tests.
- Manual matrix (recorded in PROGRESS): Windows Terminal, PowerShell, conhost, one Linux, one macOS terminal.
- CI: `fmt`, `clippy -D warnings`, `test`, `cargo deny check` on Windows, Linux, macOS.
- VHS tape for README demo GIF.

## Release and distribution

- Tags `vX.Y.Z` via cargo-dist 0.34+: Windows x64/ARM64 zip (+ MSI when ready), Linux x64/ARM64 tarballs, macOS universal, SHA-256.
- winget PackageIdentifier `LeoGalli.Keld`, schema 1.28, `wingetcreate`, PR to `microsoft/winget-pkgs`. Auto-submit workflow only if secrets exist.
- Document unsigned SmartScreen honestly; do not buy a certificate.
- Optional later: crates.io, Scoop, Homebrew (Needs Leonardo for tokens/taps as required).

## Security model

1. Authorized-use acknowledgement on first TUI launch (persisted in config).
2. Scope gate before every active module action.
3. Rate limits / concurrency defaults; dry-run.
4. Audit log for every action.
5. No exploit payloads, no credential theft, no persistence, no evasion.
6. Local-only workspace data; no telemetry.
7. Dependencies audited with `cargo deny`.

## Research snapshot (2026-11-25)

| Item | Version |
|------|---------|
| Rust (local) | 1.98.1 |
| ratatui | 0.30.2 |
| crossterm | 0.29.0 |
| tokio | 1.54.1 |
| clap | 4.6.10 |
| cargo-dist | 0.34.0 |
| winget schema | 1.28.0 |
