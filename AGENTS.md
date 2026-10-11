# AGENTS.md

Aur-Guard: AUR malware monitor + host auditor. Rust bin crate, no lib.rs.

## Layout
- `src/main.rs` — CLI entry (`mod` declarations live here)
- `src/daemon.rs` — ephemeral Unix socket daemon (Request/Response JSON, `run`, `handle_conn`)
- `src/config.rs` — `Config`/`FeedConfig`, paths (config/state/socket)
- `src/feeds.rs` — feed fetch/parse/cache + pure helpers (`parse_list`, `valid_name`, `normalize`, `feed_verdict`)
- `src/gate.rs` — IOC scan of PKGBUILD dirs (`IOC_PATTERNS`, `compiled_patterns`, `scan_dir`, `check`)
- `src/paru.rs` — paru.conf hook (`HOOK_LINE`, `insert_under_bin`, `ensure_hook`)
- `src/shell.rs` — shell rc hook (bash/zsh/fish)
- `src/audit.rs` — host audit (processes, persistence)
- `src/alerts.rs` — notify-send + log

## Conventions
- Keep functions private unless cross-module use requires `pub`.
- Regex patterns: precompile via `compiled_patterns()`/`OnceLock`, never compile per-iteration.

## Verify after every change
```sh
cargo build
cargo clippy --all-targets
cargo test
```
All three must pass.

On systems without a Rust toolchain (e.g. NixOS), run them via nix-shell.
`cargo`/`clippy` need `pkg-config` + `openssl` (reqwest native-tls):
```sh
nix-shell -p rustc cargo clippy pkg-config openssl --run "cargo build"
nix-shell -p rustc cargo clippy pkg-config openssl --run "cargo clippy --all-targets"
nix-shell -p rustc cargo clippy pkg-config openssl --run "cargo test"
```

## Tests
- Unit tests live as `#[cfg(test)] mod tests` inside each src file.
- Add tests for every new pure function (and any refactored pure logic).
- Use `std::env::temp_dir()` fixtures for filesystem-dependent tests; clean up after.
