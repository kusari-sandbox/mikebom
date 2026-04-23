# mikebom Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-04-23

## Active Technologies
- Rust stable (user-space only; no eBPF touched in this milestone) (002-python-npm-ecosystem)
- N/A — pure filesystem reads. All state lives in memory for the lifetime of a scan. (002-python-npm-ecosystem)
- Rust stable (same workspace compiler as milestones 001–002). No new nightly-only features required for user-space readers. `mikebom-ebpf` is untouched. (003-multi-ecosystem-expansion)
- N/A — all state is in-process for the duration of a single scan, same as milestone 002. (003-multi-ecosystem-expansion)
- Rust stable, same workspace compiler as milestones 001–003. No new nightly-only features. `mikebom-ebpf` is untouched. (004-rpm-binary-sboms)
- N/A — all state is in-process for the duration of a single scan. Mirrors milestones 002 / 003. (004-rpm-binary-sboms)
- Rust stable (same workspace toolchain as milestones 001–004) + No new crates. Existing: `tar = 0.4`, `object = 0.36`, `rpm = 0.22`, `cyclonedx-bom`, `serde/serde_json`, `flate2`, `tempfile`, `tracing`. (005-purl-and-scope-alignment)
- N/A — in-memory per scan; no persistence. (005-purl-and-scope-alignment)
- N/A — attestations are single JSON files (signed or (006-sbomit-suite)
- Rust stable, same workspace toolchain as milestones 001–006. No nightly features. `mikebom-ebpf` untouched. + Existing only — `quick-xml = "0.31"` for POM parsing (already used in `maven.rs`), `walkdir`, `serde`/`serde_json`, `tracing`. No new crates. (007-polyglot-fp-cleanup)
- Rust stable, same workspace as milestones 001–007. No nightly features. `mikebom-ebpf` untouched. + Existing only — `quick-xml`, `zip`, `walkdir`, `serde`/`serde_json`, `tracing`. No new crates. (008-polyglot-final-cleanup)
- Rust stable, same workspace as milestones 001–008. No nightly features. `mikebom-ebpf` untouched. + Existing only — `zip` (archive read), `spdx` (via `SpdxExpression::try_canonical`), `tracing`. No new crates. (009-maven-shade-deps)

- Rust stable (user-space) + nightly (eBPF target via `aya-ebpf`) + aya, aya-ebpf, aya-build, tokio, clap, reqwest, serde/serde_json, cyclonedx-bom, packageurl, sha2, chrono, thiserror, anyhow, tracing (001-build-trace-pipeline)

## Project Structure

```text
src/
tests/
```

## Commands

### Pre-PR verification (MANDATORY)

Before opening any PR, BOTH of these MUST pass locally — not one, not
a subset, BOTH:

1. `cargo +stable clippy --workspace --all-targets` — zero errors
2. `cargo +stable test --workspace` — every suite `ok. N passed; 0 failed`

These are the exact commands CI runs (`.github/workflows/ci.yml`).
`cargo test -p mikebom` alone is insufficient: it does not run clippy,
and clippy's `--all-targets` enforces `clippy::unwrap_used` inside
`#[cfg(test)]` modules too (the `mikebom-cli` crate root deny'ies it
per Constitution Principle IV). Test code that uses `.unwrap()` must
be guarded with:

```rust
#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
```

matching the existing convention throughout `mikebom-cli/src/trace/`.

If you open a PR without running these two commands clean, CI will
reject it. Do not cite a passing per-crate `cargo test` as evidence
of CI-readiness — they are not equivalent.

## Code Style

Rust stable (user-space) + nightly (eBPF target via `aya-ebpf`): Follow standard conventions

## Recent Changes
- 009-maven-shade-deps: Added Rust stable, same workspace as milestones 001–008. No nightly features. `mikebom-ebpf` untouched. + Existing only — `zip` (archive read), `spdx` (via `SpdxExpression::try_canonical`), `tracing`. No new crates.
- 008-polyglot-final-cleanup: Added Rust stable, same workspace as milestones 001–007. No nightly features. `mikebom-ebpf` untouched. + Existing only — `quick-xml`, `zip`, `walkdir`, `serde`/`serde_json`, `tracing`. No new crates.
- 007-polyglot-fp-cleanup: Added Rust stable, same workspace toolchain as milestones 001–006. No nightly features. `mikebom-ebpf` untouched. + Existing only — `quick-xml = "0.31"` for POM parsing (already used in `maven.rs`), `walkdir`, `serde`/`serde_json`, `tracing`. No new crates.


<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
