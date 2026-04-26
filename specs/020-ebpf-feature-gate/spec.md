---
description: "eBPF code path behind a Cargo feature flag (Tier 6 — contributor-experience cleanup)"
status: spec
milestone: 020
---

# Spec: `ebpf-tracing` Feature Gate

## Background

`mikebom-ebpf` is a separate, nightly-only, `bpfel-unknown-none`-target crate that provides kernel-side trace probes for the experimental `mikebom trace` subcommand. It has been **dormant since bootstrap** (`git log --oneline mikebom-ebpf/` shows two commits ever: `b0f31c1` bootstrap, `17c29a3` Cargo.lock). Despite this, its build cost is paid by every Linux CI run on every PR:

- `cargo +nightly install bpf-linker --locked` — first-run install, ~30s
- `cargo +nightly build --target=bpfel-unknown-none -Z build-std=core --release` — ~30-60s
- nightly toolchain installation (always done; `dtolnay/rust-toolchain@nightly` step at `.github/workflows/ci.yml:51-54`)

The user-space deps `aya`, `aya-log`, and `libc` are unconditionally present in the Linux build via `[target.'cfg(target_os = "linux")'.dependencies]` (`mikebom-cli/Cargo.toml:103-106`). On macOS they're already absent — the macOS CI leg is eBPF-clean and runs in ~1m20s vs. Linux's ~2m30s.

This milestone makes eBPF support **opt-in via a Cargo feature flag**. Default builds (Linux + macOS, local + CI) drop nightly + bpf-linker + aya. A separate explicit CI lane (`lint-and-test-ebpf`, Linux only) opts into the feature and validates the trace path. Contributors who never touch `mikebom trace` no longer pay the toolchain tax.

## User Story (US1, P1)

**As a contributor working on non-trace code paths**, I want default workspace builds (`cargo build`, `cargo test --workspace`, `cargo clippy --workspace --all-targets`) to compile and pass without nightly Rust, without bpf-linker, and without aya/aya-log/libc in the dependency graph, so that my local dev loop and our CI default lane reflect only the surface area I'm actually touching.

**Why P1**: This is the only remaining Tier-6 item from the post-019 cleanup roadmap. It materially changes contributor experience (Linux dev no longer needs nightly+bpf-linker for non-trace work; macOS dev path remains the canonical reference experience). Other tier-4 module-split candidates (parity/extractors.rs, builder.rs) can land later without affecting this.

### Independent Test

After implementation:

- `rustup toolchain list` containing only `stable` is sufficient to compile + test the workspace.
- `cargo +stable clippy --workspace --all-targets -- -D warnings` succeeds without bpf-linker installed.
- `cargo +stable test --workspace` succeeds without `mikebom-ebpf/target/` existing.
- `cargo tree -p mikebom -e normal | grep -E '^aya|^aya-log|^libc'` returns empty (only `libc` indirect via other crates is OK).
- `cargo +stable clippy --workspace --all-targets --features ebpf-tracing -- -D warnings` succeeds when bpf-linker IS installed (CI ebpf lane).
- `mikebom trace capture --help` invoked from a default build returns a friendly "this build was compiled without eBPF support; rebuild with `--features ebpf-tracing` on a Linux host" message rather than crashing or compiling the subcommand out entirely (per FR-006 — discoverability).

## Acceptance Scenarios

**Scenario 1: Default Linux build, no bpf-linker, non-trace contributor**
```
Given: a clean Linux dev box with stable toolchain only, no bpf-linker
When:  contributor runs `./scripts/pre-pr.sh`
Then:  clippy + test both pass; xtask ebpf is never invoked; aya/aya-log not in build
```

**Scenario 2: Default macOS build, unchanged**
```
Given: macOS dev box with stable toolchain
When:  contributor runs `./scripts/pre-pr.sh`
Then:  identical to milestone-016 behavior — zero warnings, all user-space tests pass,
       dependency graph identical to pre-020 (macOS already excluded eBPF deps)
```

**Scenario 3: Opt-in feature build on Linux**
```
Given: Linux dev box with stable + nightly + bpf-linker installed,
       and `cargo run -p xtask -- ebpf` already executed
When:  contributor runs `cargo +stable test --workspace --features ebpf-tracing`
Then:  trace::loader::load_and_attach is compiled in; aya/aya-log/libc present in
       dependency graph; the `trace::loader::tests::*` (if any) execute against the
       kernel object
```

**Scenario 4: Default build, user invokes `mikebom trace`**
```
Given: a default-features mikebom binary
When:  user runs `mikebom trace capture --target-pid 123`
Then:  process exits with a clear error message naming the missing feature and
       the rebuild command — NOT a panic, NOT a missing-subcommand error
```

**Scenario 5: CI runtime savings**
```
Given: PR touching only mikebom-cli/src/scan_fs/* (no trace code)
When:  GitHub Actions CI runs
Then:  `lint-and-test` (linux + macos) jobs do NOT install nightly + bpf-linker;
       `lint-and-test-ebpf` runs in parallel and is the only job that pays the
       eBPF cost
```

## Edge Cases

- **`mikebom trace` discoverability**: Subcommand stays in `--help` output even when feature is off, so users can discover it exists. The runtime guard (FR-006) is what intercepts execution.
- **Cross-feature regressions**: Feature-on Linux build must be byte-identical to pre-020 Linux build for non-trace code paths (no behavior drift in `sbom scan`, `sbom verify`, `attestation generate`, etc.).
- **`xtask ebpf` invocation**: Stays exactly as it is. CI just stops calling it on the default lane. Local devs can still `cargo run -p xtask -- ebpf` whenever they want.
- **`mikebom-ebpf` crate itself**: Untouched. Already `exclude = ["mikebom-ebpf"]` in workspace `Cargo.toml`. The feature flag controls only the user-space loader, not the kernel-side crate's build trigger.
- **Test wiring**: No integration tests under `mikebom-cli/tests/` reference the trace pipeline today (per pre-spec inventory). Unit tests under `src/trace/*` that use `aya::*` are gated by `#[cfg(target_os = "linux")]` — these gates expand to `#[cfg(all(target_os = "linux", feature = "ebpf-tracing"))]`.

## Functional Requirements

- **FR-001**: `mikebom-cli/Cargo.toml` declares a `[features]` block with `default = []` and `ebpf-tracing = ["dep:aya", "dep:aya-log", "dep:libc"]`. The `aya`, `aya-log`, and `libc` entries in `[target.'cfg(target_os = "linux")'.dependencies]` become `optional = true`.
- **FR-002**: All `#[cfg(target_os = "linux")]` gates in `mikebom-cli/src/trace/*` and `mikebom-cli/src/cli/scan.rs` expand to `#[cfg(all(target_os = "linux", feature = "ebpf-tracing"))]`. The unrelated gates in `scan_fs/os_release.rs:134` and `attestation/builder.rs:109` (host-detection, kernel-version detection) are NOT changed — those stay platform-only.
- **FR-003**: `mikebom trace` (capture + run) subcommand parsing remains in clap unchanged. When the feature is off, the dispatcher in `mikebom-cli/src/main.rs` (or the trace sub-dispatcher) returns an `anyhow::Error` with the exact text: `"this build was compiled without eBPF support; rebuild with --features ebpf-tracing on a Linux host to enable trace capture"`. No panic, no clap-level "unknown subcommand".
- **FR-004**: `.github/workflows/ci.yml` is restructured into three jobs:
  1. `lint-and-test` (Linux): default features, no nightly, no bpf-linker, no `xtask ebpf` step.
  2. `lint-and-test-macos`: unchanged from pre-020.
  3. `lint-and-test-ebpf` (Linux, NEW): nightly + bpf-linker + xtask ebpf + clippy/test with `--features ebpf-tracing`.
- **FR-005**: `./scripts/pre-pr.sh` runs the same two commands as the default `lint-and-test` CI lane (no eBPF). A documented opt-in for contributors who want to verify the eBPF lane: `MIKEBOM_PREPR_EBPF=1 ./scripts/pre-pr.sh` adds `--features ebpf-tracing` to both commands.
- **FR-006**: The `trace` subcommand's `--help` output remains discoverable in default builds. A short note in `mikebom trace --help` (or `mikebom --help` adjacent to the trace subcommand) names the feature flag, so users can self-serve the rebuild.
- **FR-007**: `cargo tree -p mikebom -e normal` from a default build does NOT list `aya` or `aya-log` as direct deps. (`libc` is allowed indirect because other workspace deps may pull it in.)
- **FR-008**: Each commit in the milestone leaves the tree in a state where `./scripts/pre-pr.sh` passes — same per-commit-clean discipline as 018 + 019.
- **FR-009**: `CLAUDE.md` is updated with one-paragraph guidance on the feature flag in the "Active Technologies" or "Commands" section.
- **FR-010**: A new `tests/feature_gate.rs` integration test asserts that `mikebom trace` from a default build returns the FR-003 error string and exit code 1 (proves the runtime guard works).

## Key Entities

No new data — this is a build-system + module-gating refactor. The "entity" introduced is the `ebpf-tracing` Cargo feature itself, formally specified in `contracts/feature-flag.md`.

## Success Criteria

- **SC-001**: Default `cargo +stable test --workspace` completes on a stable-only Linux toolchain without bpf-linker installed. (Verification: `rustup toolchain uninstall nightly && which bpf-linker || true && ./scripts/pre-pr.sh`.)
- **SC-002**: `lint-and-test` Linux CI job runs faster than the pre-020 baseline by ≥ 30s (baseline ~2m30s; target ≤ 2m). Measured via `gh pr checks 44` style timing post-merge.
- **SC-003**: `lint-and-test-ebpf` Linux CI job is green on the milestone-020 PR — proves the feature-on path still works.
- **SC-004**: macOS CI job timing is unchanged from milestone 016 baseline (already eBPF-free; this is a regression check, not an improvement).
- **SC-005**: `cargo tree -p mikebom -e normal --no-default-features` (or `cargo tree -p mikebom -e normal` with default features) shows zero direct entries for `aya` or `aya-log`. Verified via `git diff` of `cargo tree` output before/after.
- **SC-006**: The 27 byte-identity goldens (CDX + SPDX 2.3 + SPDX 3) regen with zero diff — no behavior change in non-trace code paths.

## Clarifications

- **Default features**: `default = []`, NOT `default = ["ebpf-tracing"]`. Rationale: the whole point of the milestone is to make the default cheap. Linux CI's eBPF lane is the regression gate for the trace path; making it default would defeat the purpose.
- **Feature name**: `ebpf-tracing`, not `trace` or `ebpf`. Specific enough to communicate intent (kernel-side instrumentation), avoids collision with potential future `trace`-named features (e.g., logging).
- **Subcommand visibility**: Stays in `--help`. Discoverability matters; the runtime guard explains the rebuild.
- **xtask**: Untouched. The `cargo run -p xtask -- ebpf` command remains the canonical way to build the kernel-side artifact, just no longer invoked on the default CI lane.
- **`mikebom-ebpf` crate**: Untouched. Already workspace-excluded.

## Out of Scope

- Splitting `mikebom-ebpf` itself or the kernel-side probes.
- Adding new trace features.
- Rewriting `mikebom trace` UX.
- Replacing aya with another eBPF userland library.
- Changing the build artifact path or the loader's discovery logic (`mikebom-ebpf/target/...` and fallback).
- macOS DYLD interposition / EndpointSecurity (deferred to a future milestone, per memory `project_macos_tracing.md`).
- Any changes to non-eBPF Linux-only code (`os_release.rs:134`, `attestation/builder.rs:109`).
