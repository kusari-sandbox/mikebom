---
description: "Quickstart — implementing milestone 020 ebpf-tracing feature gate"
status: quickstart
milestone: 020
---

# Quickstart: ebpf-tracing Feature Gate

This is the implementer's checklist. The full spec lives in `spec.md`; the per-task ladder is in `tasks.md`. Read both before starting.

## Pre-flight

1. Confirm clean tree on `main` post-#44 merge.
2. Branch: `git checkout -b 020-ebpf-feature-gate` (already done if you're picking this up mid-stream).
3. Baseline: `./scripts/pre-pr.sh` clean, captures pre-020 timing as comparison reference.

## Implementation order (4 atomic commits)

### Commit 1: `020/feature-gate` (Cargo.toml + cfg gates)

Why combined? Per research R3, splitting them produces an intermediate state that doesn't compile.

1. Read `mikebom-common/Cargo.toml` to resolve research R2 (does `aya-user` require aya?). If yes, expand the umbrella.
2. Add `[features]` block to `mikebom-cli/Cargo.toml` per data-model.md "feature declaration".
3. Flip aya/aya-log/libc to `optional = true` per data-model.md "optional-dep transformation".
4. Mechanically expand 10 cfg gates per data-model.md inventory:
   - `mikebom-cli/src/trace/loader.rs` — 2 positive + 2 negative
   - `mikebom-cli/src/trace/processor.rs` — 1 positive
   - `mikebom-cli/src/trace/pid_tracker.rs` — 1 positive
   - `mikebom-cli/src/cli/scan.rs` — 6 positive
5. Verify: `cargo +stable check --workspace --tests` clean (no aya, default features).
6. Verify: `cargo +stable check --workspace --tests --features ebpf-tracing` clean (Linux only).
7. `./scripts/pre-pr.sh` clean.
8. Commit.

### Commit 2: `020/runtime-guard` (FR-003 error + integration test)

1. Add the `#[cfg(not(all(...)))] pub async fn execute` twin in `cli/scan.rs` per research R5 / data-model.md "runtime guard".
2. Create `mikebom-cli/tests/feature_gate.rs`:
   - One test: `trace_capture_returns_feature_off_error_in_default_build`.
   - Spawns `mikebom trace capture --target-pid 1`, asserts non-zero exit + exact FR-003 stderr substring.
   - Skipped via `#[cfg(feature = "ebpf-tracing")]` so it runs ONLY in default builds.
3. `./scripts/pre-pr.sh` clean.
4. Commit.

### Commit 3: `020/ci-split` (.github/workflows/ci.yml + scripts/pre-pr.sh)

1. In `.github/workflows/ci.yml`:
   - From `lint-and-test`: drop the "Install nightly Rust", "Install bpf-linker", "Build eBPF object" steps. Keep stable + clippy + tests + sbomqs.
   - Add new job `lint-and-test-ebpf` cloned from pre-020 `lint-and-test` (with all the eBPF prereqs), but pass `--features ebpf-tracing` on clippy + test commands.
   - Leave `lint-and-test-macos` alone.
2. In `scripts/pre-pr.sh`:
   - Default behavior unchanged (no eBPF).
   - Add `MIKEBOM_PREPR_EBPF=1` opt-in: when set, append `--features ebpf-tracing` to both clippy and test invocations.
3. `./scripts/pre-pr.sh` clean (default).
4. `MIKEBOM_PREPR_EBPF=1 ./scripts/pre-pr.sh` clean (only if you're on Linux + have nightly + bpf-linker).
5. Commit.

### Commit 4: `020/docs` (CLAUDE.md)

1. Add a short paragraph under "Active Technologies" or as a new "Feature flags" subsection:

```markdown
## Feature flags

- `ebpf-tracing` (off by default): enables `mikebom trace` (Linux + nightly + bpf-linker required).
  Build the kernel-side object with `cargo run -p xtask -- ebpf`, then test with
  `cargo +stable test --workspace --features ebpf-tracing`. Local-only verification:
  `MIKEBOM_PREPR_EBPF=1 ./scripts/pre-pr.sh`.
```

2. `./scripts/pre-pr.sh` clean.
3. Commit.

## Common pitfalls (from past milestones)

- **Don't drop the `target.'cfg(target_os = "linux")'` predicate** on the optional deps. Macs running `cargo build --features ebpf-tracing` should get a clean no-op, not a build error from an unbuildable Linux-only crate.
- **Don't gate `LoaderConfig`**. The struct is a plain-data DTO — its compilation is target/feature-independent. Only the `inner` module that uses aya needs the gate.
- **Don't gate `mod tests`**. Unit tests under `src/trace/*` that use aya types need the gate; tests that don't, don't. Inspect each module.
- **Don't put `bpf-linker` install in the default lane just because it's cached**. Cache-hit cost is non-zero (a few seconds), and the cache itself is environmentally costly. The point of the milestone is "default lane never thinks about eBPF".
- **Don't forget `tests/feature_gate.rs` is gated INVERSELY**: it runs in default builds and verifies the runtime guard. With the feature on, it should be skipped (the guard isn't reachable).

## Verification commands

```bash
# Default Linux/macOS build (the new normal)
cargo +stable check --workspace --tests
cargo +stable clippy --workspace --all-targets -- -D warnings
cargo +stable test --workspace
cargo tree -p mikebom -e normal | rg '^aya|^aya-log'  # should be empty

# Feature-on Linux build (CI ebpf lane)
cargo +stable check --workspace --tests --features ebpf-tracing
cargo +stable clippy --workspace --all-targets --features ebpf-tracing -- -D warnings
cargo +stable test --workspace --features ebpf-tracing
cargo tree -p mikebom -e normal --features ebpf-tracing | rg '^aya|^aya-log'  # should match

# Pre-PR convenience
./scripts/pre-pr.sh                    # default
MIKEBOM_PREPR_EBPF=1 ./scripts/pre-pr.sh  # opt-in (Linux only)
```

## What success looks like

- 4 commits on `020-ebpf-feature-gate`.
- All 3 CI jobs (lint-and-test, lint-and-test-macos, lint-and-test-ebpf) green on the PR.
- `lint-and-test` Linux runtime ≤ 2m (vs ~2m30s pre-020); macOS unchanged at ~1m20s; ebpf job ~2m30s.
- 27 byte-identity goldens regen with zero diff (no behavior drift in non-trace paths).
