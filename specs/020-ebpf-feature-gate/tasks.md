---
description: "Task list — milestone 020 ebpf-tracing feature gate"
---

# Tasks: ebpf-tracing Feature Gate — Design-First

**Input**: Design documents from `/specs/020-ebpf-feature-gate/`
**Prerequisites**: spec.md (✅), plan.md (✅), research.md (✅), data-model.md (✅), contracts/feature-flag.md (✅), quickstart.md (✅)

**Tests**: One new integration test (`tests/feature_gate.rs`, FR-010) plus the existing 27-golden byte-identity regression surface.

**Organization**: Single user story (US1). Four atomic commits.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: parallelizable — N/A here, commits are dependency-ordered.
- **[Story]**: All maps to US1.

## Path Conventions

- Touches `mikebom-cli/Cargo.toml`, `.github/workflows/ci.yml`, `scripts/pre-pr.sh`, `CLAUDE.md`.
- Touches `mikebom-cli/src/trace/{loader,processor,pid_tracker}.rs` and `mikebom-cli/src/cli/scan.rs` (cfg gates only).
- Adds `mikebom-cli/tests/feature_gate.rs`.
- Does NOT touch `mikebom-ebpf/`, `xtask/`, `mikebom-common/` (unless R2 reveals `aya-user` needs to move; documented in T001).

---

## Phase 1: Setup + Resolve R2

**Purpose**: Resolve the open research question on `mikebom-common/aya-user` before any code lands.

- [ ] T001 [US1] Read `mikebom-common/Cargo.toml`. Confirm whether the `aya-user` feature transitively requires `aya`. If yes, plan the umbrella expansion (likely: change `mikebom-cli/Cargo.toml:24` to `features = ["std"]`, add `aya-user` activation under `ebpf-tracing` in the new `[features]` block). If no, no change needed. Record finding in a 2-line comment in T002's commit message.
- [ ] T002 [US1] Snapshot baseline: `./scripts/pre-pr.sh 2>&1 | tee /tmp/baseline-020.txt | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/baseline-020-tests.txt`. Used at T013 for SC-002 test-name parity check.

---

## Phase 2: Commit 1 — `020/feature-gate`

**Goal**: Cargo.toml gets `[features]`; aya/aya-log/libc become optional; 12 cfg gates expand to feature-aware form.

**Independent test**: After T006, default `./scripts/pre-pr.sh` is clean and `cargo tree -p mikebom -e normal | rg '^aya'` is empty.

- [ ] T003 [US1] Edit `mikebom-cli/Cargo.toml`:
  - Add `[features]` block per data-model.md "feature declaration".
  - Flip aya/aya-log/libc to `optional = true` per data-model.md "optional-dep transformation".
  - Apply T001's R2 finding (umbrella may need `mikebom-common/aya-user`).
- [ ] T004 [US1] Mechanical cfg-gate expansion in `mikebom-cli/src/trace/{loader,processor,pid_tracker}.rs` per data-model.md inventory. Expected diff: ~6 lines.
- [ ] T005 [US1] Mechanical cfg-gate expansion in `mikebom-cli/src/cli/scan.rs` per data-model.md inventory (6 positive gates). Expected diff: ~6 lines.
- [ ] T006 [US1] Verify default build: `cargo +stable check --workspace --tests` clean. Verify feature-on build (Linux): `cargo +stable check --workspace --tests --features ebpf-tracing` clean. Pre-PR clean.
- [ ] T007 [US1] Commit: `refactor(020/feature-gate): introduce ebpf-tracing Cargo feature, drop aya from default deps`.

---

## Phase 3: Commit 2 — `020/runtime-guard`

**Goal**: `mikebom trace` returns the FR-003 error in default builds; integration test asserts on it.

**Independent test**: After T010, `cargo +stable test -p mikebom --test feature_gate` passes in default build; same test is skipped (compiled out) under `--features ebpf-tracing`.

- [ ] T008 [US1] Add the inverse-cfg `pub async fn execute` twin to `mikebom-cli/src/cli/scan.rs` per research R5. Exact body lifted from data-model.md "runtime guard".
- [ ] T009 [US1] Create `mikebom-cli/tests/feature_gate.rs`. Single test gated `#[cfg(not(feature = "ebpf-tracing"))]` that:
  1. Builds the binary path via `common::bin()` (already exists in `tests/common/mod.rs`).
  2. Runs `<binary> trace capture --target-pid 1`.
  3. Asserts: exit code != 0, stderr contains the substring `"compiled without eBPF support"`, AND contains `"--features ebpf-tracing"`.
- [ ] T010 [US1] Verify: `cargo +stable test --workspace` includes `feature_gate::trace_capture_returns_feature_off_error_in_default_build` and it passes. With `--features ebpf-tracing` it should be filtered out (or absent). Pre-PR clean.
- [ ] T011 [US1] Commit: `refactor(020/runtime-guard): add feature-off error path for mikebom trace + integration test`.

---

## Phase 4: Commit 3 — `020/ci-split`

**Goal**: CI runs three jobs; default Linux + macOS jobs drop nightly/bpf-linker entirely; new ebpf job validates the feature-on path.

**Independent test**: After push, GitHub Actions UI shows three checks; pre-existing `lint-and-test` shrinks; new `lint-and-test-ebpf` runs in parallel and is green.

- [ ] T012 [US1] Edit `.github/workflows/ci.yml`:
  - In `lint-and-test`: remove the "Install eBPF build deps" (still keep clang/llvm/libelf for sigstore? — verify; if only eBPF needs them, drop), "Install nightly Rust", "Install bpf-linker", "Build eBPF object" steps. Keep checkout, stable Rust, cache, sbomqs install, Add Go bin to PATH, Clippy, Tests.
  - Add new job `lint-and-test-ebpf` (Linux), copy of pre-020 `lint-and-test`, but:
    - Clippy command: `cargo +stable clippy --workspace --all-targets --features ebpf-tracing -- -D warnings`
    - Tests command: `cargo +stable test --workspace --features ebpf-tracing`
    - Otherwise identical (nightly install, bpf-linker, xtask ebpf, sbomqs).
  - `lint-and-test-macos` unchanged.
- [ ] T013 [US1] Edit `scripts/pre-pr.sh`:
  - Default behavior unchanged.
  - When env `MIKEBOM_PREPR_EBPF=1` is set, append `--features ebpf-tracing` to both clippy and test commands. Echo a clear "running ebpf lane" header line.
- [ ] T014 [US1] Verify locally: `./scripts/pre-pr.sh` clean (default). `MIKEBOM_PREPR_EBPF=1 ./scripts/pre-pr.sh` clean if your environment has nightly + bpf-linker. (Optional locally; CI will catch the feature-on path regardless.)
- [ ] T015 [US1] Commit: `ci(020/ci-split): three-lane CI — default lint-and-test (linux+macos) + opt-in lint-and-test-ebpf`.

---

## Phase 5: Commit 4 — `020/docs`

**Goal**: CLAUDE.md tells future contributors how the feature flag works.

- [ ] T016 [US1] Edit `CLAUDE.md` per quickstart.md "Commit 4" template. Place the `## Feature flags` section after `## Active Technologies` and before `## Project Structure`.
- [ ] T017 [US1] Pre-PR clean.
- [ ] T018 [US1] Commit: `docs(020/docs): document ebpf-tracing feature flag in CLAUDE.md`.

---

## Phase 6: Polish & Verification

**Purpose**: Final-state acceptance proof per spec SC-001 through SC-006.

- [ ] T019 SC-001 verification: From a Linux box (or container), `rustup toolchain uninstall nightly` (skip if can't), confirm `./scripts/pre-pr.sh` clean. (CI's `lint-and-test` job is the canonical proof — this is local belt-and-braces.)
- [ ] T020 SC-005 verification: `cargo tree -p mikebom -e normal | rg '^aya|^aya-log'` empty (default). `cargo tree -p mikebom -e normal --features ebpf-tracing | rg '^aya'` non-empty (Linux only).
- [ ] T021 SC-006 verification: `MIKEBOM_UPDATE_CDX_GOLDENS=1 MIKEBOM_UPDATE_SPDX_GOLDENS=1 MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test --workspace --tests -- --test-threads=1` produces zero diff in `mikebom-cli/tests/golden/`. (Pre-existing `spdx_determinism::cargo_scan_is_deterministic` flake under load is documented; re-run that single test in isolation to confirm.)
- [ ] T022 Push branch; observe all three CI jobs green. Capture timing.
- [ ] T023 SC-002 timing check: `lint-and-test` Linux ≤ 2m (vs ~2m30s baseline). Comment timing in PR description if tight against the budget.
- [ ] T024 Author the PR description. Per-commit summary (4 commits), feature-flag contract pointer, byte-identity attestation, CI timing comparison.

---

## Dependency Graph

```text
T001 (R2 confirm) ──→ T002 (baseline snapshot)
                         │
                         ↓
                     T003 → T004 → T005 → T006 → T007  ← Commit 1 (feature-gate)
                                                  │
                                                  ↓
                                              T008 → T009 → T010 → T011  ← Commit 2 (runtime-guard)
                                                                    │
                                                                    ↓
                                                                T012 → T013 → T014 → T015  ← Commit 3 (ci-split)
                                                                                       │
                                                                                       ↓
                                                                                    T016 → T017 → T018  ← Commit 4 (docs)
                                                                                                   │
                                                                                                   ↓
                                                                                              T019 → T020 → T021 → T022 → T023 → T024
                                                                                                                                  │
                                                                                                                                  ↓
                                                                                                                            Polish done
```

Each commit must leave `./scripts/pre-pr.sh` clean (FR-008). Commits 1-2 are landlocked by code+test pairs. Commits 3-4 are CI/docs only.

## Estimated effort

| Phase | Estimated effort | Notes |
|---|---|---|
| Phase 1 (setup + R2) | 15 min | Cargo.toml read + baseline snapshot |
| Phase 2 (feature-gate commit) | 30 min | Mechanical Cargo.toml + 12 cfg expansions |
| Phase 3 (runtime-guard commit) | 45 min | New integration test scaffolding is the new wrinkle |
| Phase 4 (ci-split commit) | 30 min | YAML duplication, careful step pruning |
| Phase 5 (docs commit) | 15 min | One paragraph |
| Phase 6 (polish) | 30 min | If CI green on first push |
| **Total** | **2-3 hr** | One focused half-day. |
