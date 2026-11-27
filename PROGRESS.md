# Keld Progress

## Current task

**KL-020** -- `report`: JSON/Markdown/HTML/CSV/SARIF; HTML logo; CLI + TUI

## Done

- **KL-019** -- `hash`: type ID + offline wordlist check; CLI + TUI + tests -- 2026-11-27 -- https://github.com/Leo-Galli/keld/pull/38
- **KL-018** -- `net`: interfaces + authorized subnet discovery (ARP/ICMP/TCP fallback); CLI + TUI + tests -- 2026-11-27 -- https://github.com/Leo-Galli/keld/pull/36
- **KL-017** -- `dns`: records, AXFR check, wordlist + CT subdomains; CLI + TUI + tests -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/34
- **KL-016** -- `fuzz`: dir + vhost wordlist discovery, filters; CLI + TUI + tests -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/31
- **KL-015** -- `http`: headers, cookies, CORS, fingerprint, robots/sitemap; CLI + TUI + tests -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/29
- **KL-014** -- `tls`: chain, expiry, protocols, weak ciphers, HSTS; CLI + TUI + tests -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/27
- **KL-013** -- `probe`: banner/service detection + embedded signature file; CLI + TUI + tests -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/25
- **KL-012** -- `scan`: optional SYN path (Npcap/root) with clear fallback messaging in doctor/TUI -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/23
- **KL-011** -- `scan`: TCP connect scanner (ranges, top-ports, timeout, concurrency, dry-run); CLI + TUI + tests -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/21
- **KL-010** -- Dashboard screen with placeholder charts/sparklines; Jobs list screen -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/19
- **KL-009** -- Command palette + help overlay + keybinding presets (vim/arrows) -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/17
- **KL-008** -- CLI framework: global flags, `--json`, colored output, Ctrl+C partial-save hook skeleton, `keld doctor` stub -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/15
- **KL-007** -- Audit log (file + API); Audit log TUI viewer (read-only) -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/13
- **KL-006** -- Scope model + `scope.toml` parse/validate/exclude; refuse out-of-scope; status-bar scope summary -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/11
- **KL-005** -- Event bus + Job model in `keld-core`; stub module that emits progress for TUI/CLI wiring -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/9
- **KL-004** -- Config load (`keld.toml` + env + flags), first-launch acknowledgement persistence -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/7
- **KL-003** -- App shell polish: responsive breakpoints, sidebar collapse, terminal-too-small screen, focus ring; snapshots 80/120/200 -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/5
- **KL-002** -- Theme system (`theme.rs`): dark/light/high-contrast, truecolor/256/16/`NO_COLOR`, symbols + ASCII fallbacks -- 2026-11-26 -- https://github.com/Leo-Galli/keld/pull/3
- **KL-001** -- Workspace skeleton, splash, empty TUI shell, CI -- 2026-11-25 -- https://github.com/Leo-Galli/keld/pull/1

## Needs Leonardo

- crates.io publish token (optional later)
- Code-signing certificate (explicitly skipped; document SmartScreen)
- winget-pkgs fork + PAT / `WINGET_TOKEN` for auto-submit workflow (when releasing)
- Scoop / Homebrew taps if desired
- Manual TUI check matrix: Windows Terminal, PowerShell, conhost, Linux, macOS (after KL-001 / with KL-028)

## Decisions log

- 2026-11-27: Hash is offline only (no network, no scope gate); identify by hex length (md5/sha1/sha256/sha384/sha512) or `$1$`/`$5$`/`$6$`/`$2a$`/`$2b$`/`$2y$` prefixes; wordlist checks only crackable hex digests via md-5/sha1/sha2 0.11; modular crypt is identify-only; `--algo auto` default; TUI Hash: `s`/`p`, `a` cycles algo
- 2026-11-27: Net lists interfaces via if-addrs 0.15; discovery expands CIDR (max 1024 hosts, IPv4 skips network/broadcast); Auto cascade prefers ARP then ICMP then TCP. ARP who-has is not injected (no link-layer stack; Npcap reported only), same honesty as SYN. ICMP uses raw ICMPv4 when the socket opens; otherwise TCP connect to default ports 80,443,22,445. Doctor reports icmp/arp. TUI Net: `s`/`p`, `t` cycles technique, `i` refreshes ifaces
- 2026-11-26: DNS uses hickory-resolver 0.26 (system or injected resolvers) for A/AAAA/MX/NS/TXT/CNAME/SOA; AXFR is a raw TCP length-prefixed probe (no hickory-client; still alpha) reporting OPEN as high / REFUSED as info; wordlist optional (`-w`); CT via crt.sh JSON (`--ct` default on, `--no-ct` off) with injectable `ct_base_url` for tests; TUI DNS reuses `s`/`p` and toggles CT with `c`
- 2026-11-26: Fuzz uses reqwest 0.13 with rustls; modes `dir` (path append) and `vhost` (`Host: {word}.{apex}`); default filter status 404; match-status overrides filter when set; filter-size hides body sizes; no redirects; wordlist skips blanks and `#` comments; dry-run plans each word; TUI Fuzz reuses `s`/`p`
- 2026-11-26: HTTP uses reqwest 0.13 with rustls (no OpenSSL). Target is URL or host (https default); scope check on host. Audit steps: GET primary (headers/cookies/CORS/fingerprint), OPTIONS CORS probe with synthetic Origin, GET /robots.txt and /sitemap.xml. Cookie flags Secure/HttpOnly/SameSite; missing security headers severity medium/low. TUI HTTP reuses `s`/`p`; field-edit routing fixed for Probe/TLS/HTTP
- 2026-11-26: TLS uses rustls + tokio-rustls + webpki-roots + x509-parser (no OpenSSL). Inspect handshake accepts any chain to collect metadata; separate webpki verify finding; protocol probe is TLS 1.2/1.3 only (client does not offer TLS 1.0/1.1); weak-cipher report classifies the negotiated suite (RC4/DES/NULL weak, CBC/RSA-kx medium); HSTS via HTTPS GET after handshake. Default port `443`. TUI TLS reuses `s`/`p`; also fixed Probe/TLS key wiring in `run.rs`
- 2026-11-26: Probe uses a curated embedded `signatures.keld` (not full nmap DB): null banner listen then port-hinted payloads; byte-regex matches; unmatched null banners reported as `unknown`; TUI reuses `s`/`p` like Scan
- 2026-11-26: SYN is opt-in (`--syn`, TUI `y`). It runs only when a raw IPv4 TCP socket opens (Unix root or CAP_NET_RAW). Windows blocks raw TCP; Npcap is reported and is not used to inject frames. Otherwise the job uses TCP connect and the reason is shown by doctor, the CLI, and the Scan screen. SYN probes are serial on one socket and IPv4-only
- 2026-11-26: TCP connect scan uses tokio `TcpStream` + semaphore concurrency; ports via `top`/`top1000`/ranges; dry-run emits planned probes only; TUI Scan runs worker thread + mpsc poll on tick (event loop stays sync); open ports only as Result events
- 2026-11-26: Dashboard/Jobs share `DashboardState` on `App` (placeholder findings/sparkline/ports); Jobs is its own sidebar screen; `on_tick` advances running jobs ~1s regardless of current screen until real engine wiring
- 2026-11-26: Command palette uses in-crate fuzzy substring scoring (no extra crate); palette selection always Up/Down so j/k remain typeable; Esc closes overlays without quitting; Vim vs Arrows are mutually exclusive for list/sidebar nav; preset switch via palette until KL-023 Settings
- 2026-11-26: CLI subcommands via clap `Option<Commands>` (no args still opens TUI); `--json`/`--dry-run`/`--rate`/`--concurrency` are global; colors are hand-rolled ANSI (no extra crate); Ctrl+C uses tokio signal on a helper thread + one-shot saver; doctor is stub checks only
- 2026-11-26: Audit log is append-only JSONL (`audit.jsonl`); default `./audit.jsonl` else user data dir; TUI viewer is read-only with `/` filter and j/k select
- 2026-11-26: Scope entries are IP, CIDR, or hostname (URL hosts stripped); no DNS in the gate; excludes win; empty includes invalid; summary `first (+n, ex:m)` for status/header
- 2026-11-26: Event bus uses tokio `broadcast` (fan-out to CLI/TUI/audit); modules get `EventSender`; lag is reported, not blocking
- 2026-11-26: Config precedence file < env < flags; persist ack to user config dir (or `--config` / loaded file); Space toggles ack checkbox, Enter confirms
- 2026-11-26: LayoutMode Full (>=100) / Compact (70-99 abbrev strip) / Single (<70); `m` forces full sidebar overlay; Tab toggles focus when dual-pane
- 2026-11-26: Color depth via env (`COLORTERM`, `TERM`, `WT_SESSION`, Apple Terminal build); high-contrast forces 16 when 256 requested
- 2026-11-25: Stack pinned -- ratatui 0.30.2, crossterm 0.29, tokio 1.54, clap 4.6, cargo-dist 0.34, winget schema 1.28
- 2026-11-25: Dual license MIT OR Apache-2.0; PackageIdentifier `LeoGalli.Keld`
- 2026-11-25: `CLAUDE.md` never committed and never gitignored
- 2026-11-25: Pure Rust / rustls; no OpenSSL
- 2026-11-25: Modules emit events only; one engine, two front ends
- 2026-11-25: First commit on `main` is empty; KL-001 landed via squash-merge of PR #1

## Backlog (ordered)

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
