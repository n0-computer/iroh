# Repository Guidelines

## Project Structure & Module Organization
- Workspace crates: `iroh`, `iroh-relay`, `iroh-base`, `iroh-dns-server`, and `iroh/bench`.
- Source lives in each crate’s `src/`; unit tests live alongside code, integration tests in `tests/`.
- Examples in `iroh/examples/` (see `echo.rs`).
- Tooling/config: `.cargo/`, `.config/nextest.toml`, `deny.toml`, `.typos.toml`, `cliff.toml`, `Makefile.toml`.

## Build, Test, and Development Commands
- Build workspace: `cargo build --workspace` (use `--release` for optimized builds).
- Run a binary: `cargo run -p iroh-relay -- --help` (replace package as needed).
- Format: `cargo make format` or `cargo fmt --all`.
- Lint: `cargo clippy --workspace --all-features -D warnings`.
- Tests (fast runner): `cargo nextest run` (uses `.config/nextest.toml`).
- Tests (std): `cargo test --workspace`.
- Security/audit: `cargo deny check` (per `deny.toml`).
- Typos: `typos` (uses `.typos.toml`).

## Coding Style & Naming Conventions
- Rust 2021+ idioms; keep modules small and cohesive.
- Formatting via `rustfmt`; imports grouped and reordered (see `Makefile.toml`).
- Names: types `PascalCase`, functions/vars `snake_case`, constants `SCREAMING_SNAKE_CASE`.
- Prefer explicit `pub(crate)` visibility; document public items with rustdoc.

## Testing Guidelines
- Use `cargo nextest run` by default; isolation for tests matching `::run_in_isolation::` is configured.
- Property tests: keep regressions under `proptest-regressions/` (e.g., in `iroh-relay/`); commit new seeds when stabilized.
- Name tests descriptively: `mod_name::feature_condition_expected`.
- Aim for meaningful coverage on public APIs and error paths.

## Commit & Pull Request Guidelines
- Commits: follow Conventional Commits when possible (`feat(scope): summary`, `fix: ...`, `chore: ...`).
- Write clear, scoped commits; keep CI green (fmt, clippy, tests).
- PRs: follow `.github/pull_request_template.md` — include description, note breaking changes, add tests/docs, and link issues.
- Changelog is generated via `cliff.toml`; conventional messages help grouping.

## Security & Configuration Tips
- Avoid introducing new `unsafe`; if necessary, justify and cover with tests.
- Keep features minimal; prefer `pub(crate)` re-exports in `iroh` for stable API surfaces.
- For WASM targets, mind `.cargo/config.toml` flags and avoid unsupported std features.
