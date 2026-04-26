---
description: "Implementation plan — milestone 020 ebpf-tracing feature gate"
status: plan
milestone: 020
---

# Plan: ebpf-tracing Feature Gate

## Architecture

A single Cargo feature, `ebpf-tracing`, gates the user-space eBPF integration in `mikebom-cli`. The feature pulls in three otherwise-optional dependencies (`aya`, `aya-log`, `libc`) and conditionally compiles the trace pipeline + the trace-capture CLI command.

The kernel-side crate (`mikebom-ebpf`) is unaffected — it remains `exclude`d from the workspace and built on demand via `cargo run -p xtask -- ebpf`. The xtask invocation moves from the default CI lane to a dedicated opt-in lane (`lint-and-test-ebpf`).

## Dependency change

| Dep | Before | After |
|---|---|---|
| `aya` | `[target.'cfg(target_os = "linux")'.dependencies]`, unconditional | same target gate, `optional = true`, activated by `ebpf-tracing` |
| `aya-log` | same as aya | same as aya |
| `libc` | same as aya | same as aya |

`mikebom-common`'s `aya-user` feature (`mikebom-cli/Cargo.toml:24`) — needs verification: does it transitively pull in aya itself? If yes, that feature also becomes part of the `ebpf-tracing` umbrella. If no (it's just a marker), no change needed. **Action item for research.md R2.**

## Code-gate transformation

Mechanical rewrite — no behavior change:

```rust
// Before:
#[cfg(target_os = "linux")]

// After (only in trace/* and cli/scan.rs):
#[cfg(all(target_os = "linux", feature = "ebpf-tracing"))]
```

Files touched:

| File | Lines (before) | Gates to expand |
|---|---|---|
| `mikebom-cli/src/trace/loader.rs` | 16, 179 | 2 |
| `mikebom-cli/src/trace/processor.rs` | 68 | 1 |
| `mikebom-cli/src/trace/pid_tracker.rs` | 92 | 1 |
| `mikebom-cli/src/cli/scan.rs` | 104, 158, 169, 544, 577, 612 | 6 |

Total: 10 cfg-gate expansions. The non-Linux fallback in `trace/loader.rs:184-190` becomes the unified "feature-off OR non-Linux" fallback (single `cfg(not(all(target_os = "linux", feature = "ebpf-tracing")))`).

## Runtime guard

The `mikebom trace` dispatcher (in `mikebom-cli/src/main.rs` or `mikebom-cli/src/cli/trace_cmd.rs` per the inventory) gets a feature-off arm that returns the FR-003 error message. This is a 5-10 LOC change.

## CI restructure

Three jobs in `.github/workflows/ci.yml`:

1. **`lint-and-test`** (Linux): default features, stable only.
   - Drops: nightly install, bpf-linker install, `xtask ebpf` step.
   - Keeps: clippy + test + sbomqs install.
2. **`lint-and-test-macos`**: unchanged.
3. **`lint-and-test-ebpf`** (Linux, NEW): clone of pre-020 `lint-and-test`.
   - Adds `--features ebpf-tracing` to clippy + test.
   - Keeps nightly + bpf-linker + xtask ebpf.

All three run in parallel (no `needs:` chain). PR is green when all three pass.

## Constitution alignment

- **Principle I (zero C)**: aya is pure Rust per the `data-encoding`-style audit; libc is `cfg(unix)` but only for FFI signatures. No new C deps. ✓
- **Principle IV (no .unwrap() in production)**: this milestone touches Cargo.toml + cfg gates + one runtime guard arm; no new `.unwrap()` introduced. ✓
- **Principle VI (three-crate architecture)**: untouched. mikebom-ebpf stays its own crate. ✓
- **Principle (atomic per-submodule commits, lessons from 018+019)**: this milestone is small enough for a single commit, but split per-concern (Cargo.toml + code gates, then runtime guard, then CI, then docs+pre-pr) keeps each commit independently verifiable.

## Phasing

Five commits in dependency order:

1. **020/cargo-feature**: Add `[features]` to `mikebom-cli/Cargo.toml`; flip aya/aya-log/libc to `optional = true`.
2. **020/cfg-gates**: Mechanical expansion of 10 cfg gates in `trace/*` + `cli/scan.rs`. After this commit, default `cargo +stable test --workspace` passes (proves feature-off is sound).
3. **020/runtime-guard**: Add the FR-003 error path in the trace dispatcher + the `tests/feature_gate.rs` integration test.
4. **020/ci-split**: Restructure `.github/workflows/ci.yml` into three jobs. Update `scripts/pre-pr.sh` for the FR-005 opt-in.
5. **020/docs**: Update `CLAUDE.md` with the feature-flag guidance.

Per FR-008, each commit's `./scripts/pre-pr.sh` must be clean. Commits 1+2 must land together if commit 1 alone breaks compilation (aya gone but cfg gates still unconditional). Decision in research R3.

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| 1 (Cargo feature) | 15 min | Mechanical |
| 2 (cfg gates) | 30 min | 10 sed-able expansions |
| 3 (runtime guard + test) | 45 min | New integration test scaffolding |
| 4 (CI split) | 30 min | YAML duplication + path adjustments |
| 5 (docs) | 15 min | One paragraph in CLAUDE.md |
| **Total** | **2-3 hr** | One focused half-day. |

## Risks

- **R1**: If `mikebom-common`'s `aya-user` feature transitively requires `aya`, the feature gate must include it. Verified in research.md R2.
- **R2**: If the `trace` subcommand's clap parsing references types from the gated module (e.g., `LoaderConfig`), parsing breaks even with feature off. The current code keeps `LoaderConfig` un-gated (`mikebom-cli/src/trace/loader.rs:6-14`), but the `ScanArgs` struct in `cli/scan.rs` may need a gate review. Verified in research.md R4.
- **R3**: Atomic commit ordering — if commit 1 (Cargo.toml) lands without commit 2 (cfg gates), `aya` becomes unavailable but `use aya::*` lines still try to import. Compilation breaks. Resolution: ship 1+2 as a single commit, OR verify pre-PR is clean after commit 1 alone (it won't be, so combine).
- **R4**: CI YAML duplication — the new `lint-and-test-ebpf` job is ~70% identical to the old `lint-and-test`. Reusable workflows are an option but add YAML complexity. Pragmatic call: duplicate the YAML for now, factor later if a third eBPF-needing job appears.
