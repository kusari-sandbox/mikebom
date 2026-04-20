# mikebom Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-04-20

## Active Technologies
- Rust stable (user-space only; no eBPF touched in this milestone) (002-python-npm-ecosystem)
- N/A — pure filesystem reads. All state lives in memory for the lifetime of a scan. (002-python-npm-ecosystem)
- Rust stable (same workspace compiler as milestones 001–002). No new nightly-only features required for user-space readers. `mikebom-ebpf` is untouched. (003-multi-ecosystem-expansion)
- N/A — all state is in-process for the duration of a single scan, same as milestone 002. (003-multi-ecosystem-expansion)
- Rust stable, same workspace compiler as milestones 001–003. No new nightly-only features. `mikebom-ebpf` is untouched. (004-rpm-binary-sboms)
- N/A — all state is in-process for the duration of a single scan. Mirrors milestones 002 / 003. (004-rpm-binary-sboms)
- Rust stable (same workspace toolchain as milestones 001–004) + No new crates. Existing: `tar = 0.4`, `object = 0.36`, `rpm = 0.22`, `cyclonedx-bom`, `serde/serde_json`, `flate2`, `tempfile`, `tracing`. (005-purl-and-scope-alignment)
- N/A — in-memory per scan; no persistence. (005-purl-and-scope-alignment)

- Rust stable (user-space) + nightly (eBPF target via `aya-ebpf`) + aya, aya-ebpf, aya-build, tokio, clap, reqwest, serde/serde_json, cyclonedx-bom, packageurl, sha2, chrono, thiserror, anyhow, tracing (001-build-trace-pipeline)

## Project Structure

```text
src/
tests/
```

## Commands

cargo test [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] cargo clippy

## Code Style

Rust stable (user-space) + nightly (eBPF target via `aya-ebpf`): Follow standard conventions

## Recent Changes
- 005-purl-and-scope-alignment: Added Rust stable (same workspace toolchain as milestones 001–004) + No new crates. Existing: `tar = 0.4`, `object = 0.36`, `rpm = 0.22`, `cyclonedx-bom`, `serde/serde_json`, `flate2`, `tempfile`, `tracing`.
- 004-rpm-binary-sboms: Added Rust stable, same workspace compiler as milestones 001–003. No new nightly-only features. `mikebom-ebpf` is untouched.
- 003-multi-ecosystem-expansion: Added Rust stable (same workspace compiler as milestones 001–002). No new nightly-only features required for user-space readers. `mikebom-ebpf` is untouched.


<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
