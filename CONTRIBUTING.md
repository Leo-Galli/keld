# Contributing to Keld

Thanks for helping. Keep changes focused and authorized-use ethics intact.

## Development

Requirements: recent stable Rust (1.88+; CI uses stable), Git.

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p keld-cli
```

## Process

1. Open an issue or pick a task from `PROGRESS.md`.
2. Branch from `main`: `feat/kl-xxx-short-name` or `fix/...`.
3. Conventional Commits (`feat:`, `fix:`, `chore:`, ...). Imperative subject, no trailing period.
4. Stage explicit paths only (never `git add .` / `-A`).
5. Open a PR; wait for green CI; squash-merge.

## Code rules

- English only. No emoji. No AI attribution lines.
- Modules emit typed events; they never print.
- `thiserror` in libraries; `anyhow` only in the binary.
- No `unsafe` unless necessary and documented.
- TUI changes need `TestBackend` snapshots where screens change.
- Do not weaken scope checks, audit logging, or the authorized-use acknowledgement.

## Docs

Update `README.md`, `PLAN.md`, `DESIGN.md`, and `CHANGELOG.md` when behavior changes. Do not commit `CLAUDE.md`.
