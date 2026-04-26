# mikebom Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-04-25

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
- Rust stable (same workspace toolchain as milestones 001–009). No nightly features. `mikebom-ebpf` is untouched — this milestone is user-space only. (010-spdx-output-support)
- N/A — all state is in-process for the duration of a single scan, mirroring milestones 002–009. (010-spdx-output-support)
- Rust stable (workspace toolchain inherited from milestones 001–010; no nightly required for user-space work) + existing only — `serde`/`serde_json` (JSON-LD encoding), `data-encoding` (BASE32 for deterministic SPDXIDs / IRIs), `sha2` (content-addressed IRIs, scan fingerprint), `chrono` (RFC 3339 timestamps), `spdx` (license-expression canonicalization, already used by SPDX 2.3 path), `tracing`, `anyhow`. Dev-dep: existing `jsonschema = "0.46"` (already validates SPDX 2.3) extended to SPDX 3.0.1. No new crates. (011-spdx-3-full-support)
- N/A — all state in-process per scan (mirrors milestones 002–010). (011-spdx-3-full-support)
- Rust stable (workspace toolchain inherited from milestones 001–011; no nightly required). + existing only — `spdx` (license-expression canonicalization), `data-encoding` (BASE32 for LicenseRef hash prefix), `sha2`, `serde`/`serde_json`, `tracing`, `anyhow`. Dev-dep: existing `jsonschema = "0.46"`. **No new crates.** (012-sbom-quality-fixes)
- N/A — in-process per scan. (012-sbom-quality-fixes)
- Rust stable (workspace toolchain inherited from milestones 001–012; no nightly). + existing only — `serde`/`serde_json` (format output parsing), `regex` (catalog-row parsing — already in the dependency closure), `tempfile`, `tracing`, `anyhow`. `clap` for the new `parity-check` subcommand (already used for `scan`). **No new crates.** (013-format-parity-enforcement)
- N/A — all state in-process per test invocation / per CLI invocation. (013-format-parity-enforcement)
- Rust stable (workspace toolchain inherited from milestones 001–015; no nightly required for this user-space-only work). + existing only — `cargo +stable clippy` (lint engine), `dtolnay/rust-toolchain@stable` (already used in CI), `Swatinem/rust-cache@v2` (already used). **No new crates.** (016-remaining-clippy-cleanup)
- N/A — purely source-tree edits. (016-remaining-clippy-cleanup)

- Rust stable (user-space) + nightly (eBPF target via `aya-ebpf`) + aya, aya-ebpf, aya-build, tokio, clap, reqwest, serde/serde_json, cyclonedx-bom, packageurl, sha2, chrono, thiserror, anyhow, tracing (001-build-trace-pipeline)

## Feature flags

- **`ebpf-tracing`** (off by default; milestone 020): gates the user-space
  eBPF integration that powers `mikebom trace`. When off (the default
  everywhere — local dev, default CI lanes), aya/aya-log/libc are dropped
  from the dep graph and nightly + bpf-linker are not required. When on
  (Linux + `--features ebpf-tracing`), build the kernel-side artifact
  first via `cargo run -p xtask -- ebpf`, then test with
  `cargo +stable test --workspace --features ebpf-tracing`. Local pre-PR
  opt-in: `MIKEBOM_PREPR_EBPF=1 ./scripts/pre-pr.sh`. CI runs the
  feature-on path in the dedicated `lint-and-test-ebpf` job. See
  `specs/020-ebpf-feature-gate/contracts/feature-flag.md` for the full
  contract.

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

`./scripts/pre-pr.sh` runs both in order and exits non-zero on the
first failure — preferred over invoking them by hand so the flag
set stays aligned with CI.

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
- 016-remaining-clippy-cleanup: Added Rust stable (workspace toolchain inherited from milestones 001–015; no nightly required for this user-space-only work). + existing only — `cargo +stable clippy` (lint engine), `dtolnay/rust-toolchain@stable` (already used in CI), `Swatinem/rust-cache@v2` (already used). **No new crates.**
- 013-format-parity-enforcement: Added Rust stable (workspace toolchain inherited from milestones 001–012; no nightly). + existing only — `serde`/`serde_json` (format output parsing), `regex` (catalog-row parsing — already in the dependency closure), `tempfile`, `tracing`, `anyhow`. `clap` for the new `parity-check` subcommand (already used for `scan`). **No new crates.**
- 012-sbom-quality-fixes: Added Rust stable (workspace toolchain inherited from milestones 001–011; no nightly required). + existing only — `spdx` (license-expression canonicalization), `data-encoding` (BASE32 for LicenseRef hash prefix), `sha2`, `serde`/`serde_json`, `tracing`, `anyhow`. Dev-dep: existing `jsonschema = "0.46"`. **No new crates.**


<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
