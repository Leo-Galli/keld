# Keld

```
 ██╗  ██╗███████╗██╗     ██████╗
 ██║ ██╔╝██╔════╝██║     ██╔══██╗
 █████╔╝ █████╗  ██║     ██║  ██║
 ██╔═██╗ ██╔══╝  ██║     ██║  ██║
 ██║  ██╗███████╗███████╗██████╔╝
 ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝
      recon . audit . report
```

Authorized penetration testing, reconnaissance and security auditing -- CLI and full-screen TUI.

[![CI](https://github.com/Leo-Galli/keld/actions/workflows/ci.yml/badge.svg)](https://github.com/Leo-Galli/keld/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

> Demo GIF will appear here after KL-027 (VHS recording).

## Install

```powershell
winget install LeoGalli.Keld
```

Also available from [GitHub Releases](https://github.com/Leo-Galli/keld/releases) (zip / tarball). Optional later: crates.io, Scoop, Homebrew.

**Note:** Windows builds may be unsigned. SmartScreen can warn on first run; that is expected until a certificate is available. Prefer installing via winget or verifying SHA-256 checksums from the release.

## Quick start

```powershell
# TUI (default)
keld
keld --no-splash
keld --ascii
keld --config path/to/keld.toml
keld --theme light

# CLI
keld --help
keld doctor
keld doctor --json
keld scan --help
```

Use only on systems you own or are explicitly authorized to test. Active modules require a scope (`scope.toml` or explicit targets). Out-of-scope targets are refused. Every action is written to an audit log.

## Modules

| Module | Purpose |
|--------|---------|
| `scan` | TCP connect port scan (optional SYN when privileged) |
| `probe` | Service and banner detection |
| `tls` | Certificate chain, protocols, weak ciphers, HSTS |
| `http` | Security headers, cookies, CORS, fingerprinting |
| `fuzz` | Directory and virtual-host discovery |
| `dns` | Records, zone-transfer check, subdomain discovery |
| `net` | Interfaces and authorized subnet host discovery |
| `hash` | Hash identification and offline wordlist checks |
| `report` | JSON, Markdown, HTML, CSV, SARIF |
| `workspace` | Local SQLite projects |

## Keybindings (TUI)

| Key | Action |
|-----|--------|
| Tab / Shift+Tab | Move focus (or cycle modules in single-pane) |
| Up / Down / j / k | Change module when sidebar focused |
| `m` | Toggle sidebar overlay (below 100 cols) |
| `/` | Filter |
| `:` | Command palette |
| `?` | Help |
| `q` / Esc | Back |
| Ctrl+C | Quit (confirm if jobs running) |

Vim-style and arrow-key presets are available in Settings. See [DESIGN.md](DESIGN.md).

## Legal notice

Keld is for **authorized** security testing only. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse. By using Keld you agree to comply with applicable laws and the terms of your engagement.

No malware, persistence, credential theft, exploitation payloads, or AV/EDR evasion features are included. Recon, enumeration, auditing and reporting only.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Architecture: [PLAN.md](PLAN.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Author

Leonardo Galli ([Leo-Galli](https://github.com/Leo-Galli))
