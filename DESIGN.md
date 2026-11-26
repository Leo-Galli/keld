# Keld TUI Design System

Implement as a single `theme.rs` (plus logo helpers). No emoji. Unicode from a fixed set with ASCII fallbacks.

## Palette

### Dark (default)

| Token | Hex | Use |
|-------|-----|-----|
| bg | `#0B0F14` | Background |
| bg_panel | `#121821` | Panels |
| bg_elevated | `#1A2330` | Focused / elevated |
| fg | `#E6EDF3` | Primary text |
| fg_muted | `#8B9BB0` | Secondary text |
| fg_dim | `#5A6A7E` | Inactive |
| accent_primary | `#2EC4B6` | Teal: focus, brand, active |
| accent_secondary | `#F4A261` | Amber: highlights, warnings soft |
| border | `#2A3544` | Default borders |
| border_focus | `#2EC4B6` | Focused panel |
| info | `#5DADE2` | Severity info |
| low | `#82C91E` | Severity low |
| medium | `#F4A261` | Severity medium |
| high | `#E76F51` | Severity high |
| critical | `#FF4D6D` | Severity critical |
| success | `#2EC4B6` | Success / done |
| error | `#FF4D6D` | Errors |

### Light

bg `#F7F9FC`, fg `#1A2330`, accent primary `#0D9488`, secondary `#C2410C`, borders `#CBD5E1`. Same semantic severity hues, darkened for contrast.

### High contrast

bg `#000000`, fg `#FFFFFF`, accent `#00FFFF`, secondary `#FFFF00`, borders `#FFFFFF`. Severity: distinct pure colors. Prefer 16-color when truecolor unavailable.

### Color modes

1. Truecolor when terminal supports it.
2. Else 256-color approximations.
3. Else 16-color.
4. `NO_COLOR` or `--no-color`: no ANSI colors; structure via borders/symbols only.

## Typography and symbols

- Prefer terminal default monospace; do not assume custom fonts.
- Titles: bold. Muted labels: dim.
- Fixed Unicode set: `●` `○` `▸` `▹` `✓` `✗` `│` `─` `╭` `╮` `╯` `╰` `├` `┤` `▲` `▼` `◀` `▶` and braille spinners (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`).
- ASCII fallbacks: `*` `o` `>` `v` `[x]` `[ ]` `|` `-` `+` `/` `\` `_` `#`.
- Logo: exact splash block (below), compact `KELD` wordmark, and plain-ASCII big logo (`# / \ _ |` only).

### Splash logo (exact)

```
 ██╗  ██╗███████╗██╗     ██████╗
 ██║ ██╔╝██╔════╝██║     ██╔══██╗
 █████╔╝ █████╗  ██║     ██║  ██║
 ██╔═██╗ ██╔══╝  ██║     ██║  ██║
 ██║  ██╗███████╗███████╗██████╔╝
 ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝
      recon . audit . report
```

Vertical gradient primary -> secondary on the block. Tagline and version below, centered. ~1.2s, skippable any key. Disabled via `--no-splash` or config. Compact wordmark for header and width < 40. ASCII fallback when Unicode unsupported or `--ascii`. Also show big logo in `keld --version` (TTY only) and HTML report header.

## Layout grid

```
+--------------------------------------------------------------------+
| HEADER: wordmark | workspace | scope summary              clock    |
+----------+---------------------------------------------------------+
| SIDEBAR  | MAIN                                                    |
| Dashboard|                                                         |
| Scan     |                                                         |
| ...      |                                                         |
| Jobs     |                                                         |
| Audit    |                                                         |
| Settings |                                                         |
+----------+---------------------------------------------------------+
| STATUS: jobs | rate | errors | key hints                           |
+--------------------------------------------------------------------+
```

- Rounded borders (`╭╮╯╰`), thin separators, 1-cell padding, title in each panel border.
- Focused panel: `border_focus` (accent).
- Header height 1-3 rows. Sidebar ~18 cols. Status 1 row.
- Responsive:
  - < 100 cols: collapse sidebar to icon/abbrev strip or overlay (`m` to toggle).
  - < 70 cols: single-pane (main only); sidebar via command palette / `m`.
  - Below minimum (60x16): full-screen "terminal too small" message with required size.

## Keybindings

### Global (both presets)

| Key | Action |
|-----|--------|
| Tab / Shift+Tab | Next / prev focus |
| `/` | Filter |
| `:` | Command palette (fuzzy) |
| `?` | Help overlay |
| `q` / Esc | Back / close overlay |
| Ctrl+C | Quit (confirm if jobs running; save partial) |
| `m` | Toggle sidebar (narrow) |

### Vim preset

`h j k l` / `g g` / `G`, `Ctrl+d` / `Ctrl+u` for lists. `Enter` activate. `Space` toggle.

### Arrows preset

Arrows + PageUp/PageDown + Home/End. Enter / Space same.

### Module screens

`s` start, `p` dry-run toggle, `y` request SYN (falls back to TCP connect when a raw socket is unavailable; the reason stays on the Scan screen). `c` cancel, `e` export, `r` refresh options land with later module tasks. Pause/resume is not wired yet.

Mouse (optional, on by default): click focus/select, scroll lists. Disable in Settings.

## Motion

- Spinner + progress gauge animation only. No flashing.
- Busy: ~30 FPS tick. Idle: redraw on input/events only.
- Toasts: slide/fade restrained (or instant if reduced motion later).

## Accessibility

- Full keyboard path for every action.
- High-contrast theme.
- `NO_COLOR` / `--ascii`.
- Status bar always shows scope and job count.
- Confirm destructive actions.
- Screen reader: not a goal for v1; keep structure semantic and text-first.

## Screens (ASCII mockups)

### Splash

```
+--------------------------------------------------------------------+
|                                                                    |
|              ██╗  ██╗███████╗██╗     ██████╗                       |
|              ██║ ██╔╝██╔════╝██║     ██╔══██╗                      |
|              █████╔╝ █████╗  ██║     ██║  ██║                      |
|              ██╔═██╗ ██╔══╝  ██║     ██║  ██║                      |
|              ██║  ██╗███████╗███████╗██████╔╝                      |
|              ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝                       |
|                   recon . audit . report                           |
|                         v0.1.0                                     |
|              press any key to continue                             |
+--------------------------------------------------------------------+
```

### First launch (acknowledgement)

```
+--------------------------------------------------------------------+
| KELD  acknowledge authorized use                                   |
|--------------------------------------------------------------------|
|  Keld is for systems you own or are explicitly authorized to test. |
|  Unauthorized scanning may be illegal.                             |
|                                                                    |
|  [ ] I understand and will only use Keld on authorized targets.    |
|                                                                    |
|  Enter confirm   Esc quit                                          |
+--------------------------------------------------------------------+
```

### Dashboard

```
+--------------------------------------------------------------------+
| KELD  ws:default  scope: 10.0.0.0/24 (ex:2)              14:32:01 |
+----------+---------------------------------------------------------+
| Dashboard| Findings by severity          Requests/s                |
|▸ Scan    | critical ████░░░░  2          ▁▂▃▅▇▅▃▂▁▂▃               |
|  Probe   | high     ██████░░  5          Recent jobs               |
|  TLS     | medium   ███░░░░░  3          scan  done  12 open       |
|  HTTP    | low      ██░░░░░░  2          http  run   34%           |
|  Fuzz    | info     █░░░░░░░  1          Open ports (top)          |
|  DNS     |                               22/tcp  80/tcp  443/tcp   |
|  Net     |                                                         |
|  Hash    |                                                         |
|  Reports |                                                         |
|  Worksp. |                                                         |
|  Audit   |                                                         |
|  Settings|                                                         |
+----------+---------------------------------------------------------+
| jobs:1  rate:42/s  err:0  Tab focus  : cmd  ? help  q quit         |
+--------------------------------------------------------------------+
```

### Module screen (Scan example; others share the pattern)

```
+--------------------------------------------------------------------+
| KELD  ws:default  scope: 10.0.0.0/24                      14:32:11 |
+----------+---------------------------------------------------------+
| Dashboard| Scan                                                    |
|▸ Scan    | Target [10.0.0.5____________] Ports [1-1024___]        |
|  Probe   | Concurrency [100] Timeout [1000ms] [ ] dry-run          |
|  ...     | [Start s] [Pause p] [Cancel c] [Export e]               |
|          | Progress ████████░░░░░░░░ 42%  ETA 00:18                |
|          | +--------+------+--------+----------+                   |
|          | | Host   | Port | State  | Service  |                   |
|          | |10.0.0.5|   22 | open   | ssh?     |                   |
|          | |10.0.0.5|   80 | open   | http?    |                   |
|          | +--------+------+--------+----------+                   |
|          | Detail: 10.0.0.5:22 connect ok rtt=3ms                  |
+----------+---------------------------------------------------------+
| jobs:1  rate:120/s  / filter  s start  ? help                      |
+--------------------------------------------------------------------+
```

### Jobs

```
| Jobs                                                               |
| id     module  state   progress  duration  results                 |
| j-01   scan    running 42%       00:12     2 open                  |
| j-00   http    done    100%      00:45     8 findings              |
```

### Findings

```
| Findings                                                           |
| sev      target        module  title                               |
| HIGH     10.0.0.5:443  tls     cert expires in 12 days             |
| MEDIUM   https://...   http    missing HSTS                        |
| Detail popup: evidence, raw, copy, export                          |
```

### Audit log

```
| Audit                                                              |
| time                 module  target       params           outcome |
| 2026-11-25T14:32:01Z scan    10.0.0.5     ports=1-1024     ok      |
```

### Scope editor

```
| Scope                                                              |
| Includes:                                                          |
|   10.0.0.0/24                                                      |
|   app.example.com                                                  |
| Excludes:                                                          |
|   10.0.0.1                                                         |
| Validation: OK / errors listed                                     |
| [Save] [Reload]                                                    |
```

### Settings

```
| Settings                                                           |
| Theme: Dark | Light | High contrast                                |
| Keybindings: Vim | Arrows                                          |
| Rate limit default: [50]/s                                        |
| Splash: [x]  Mouse: [x]  ASCII: [ ]                                |
```

### Command palette

```
| : scan start________________________________                       |
|   Scan: Start job                                                  |
|   Scan: Export results                                             |
|   Go to Dashboard                                                  |
```

### Help overlay

Full keybinding table for active preset; Esc closes.

### Terminal too small

```
| Terminal too small                                                 |
| Need at least 60x16. Current WxH.                                  |
```

## Implementation notes

- Single `Theme` struct + `ThemeId::{Dark,Light,HighContrast}`.
- `symbols` module switches Unicode vs ASCII.
- `logo` module: splash lines, gradient styles, ascii variant, compact wordmark.
- Snapshot every screen at 80x24, 120x40, 200x60 with `insta` + `TestBackend`.
- Clean restore on exit and panic (panic hook).
