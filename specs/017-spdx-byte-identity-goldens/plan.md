# Implementation Plan: SPDX Byte-Identity Goldens + Cross-Host Determinism Parity

**Branch**: `017-spdx-byte-identity-goldens` | **Date**: 2026-04-25 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/017-spdx-byte-identity-goldens/spec.md`

## Summary

Bring SPDX 2.3 and SPDX 3 test coverage to parity with CycloneDX's milestone-010 FR-022 byte-identity guarantee. Three deliverables, in dependency order: (1) extract `mikebom-cli/tests/common/normalize.rs` exporting per-format normalizers + an `apply_fake_home_env` helper, migrate `cdx_regression.rs` to it without changing any committed CDX golden; (2) add `mikebom-cli/tests/spdx_regression.rs` and `mikebom-cli/tests/spdx3_regression.rs` plus 18 committed goldens under `tests/fixtures/golden/spdx-2.3/` and `tests/fixtures/golden/spdx-3/`; (3) migrate every test that today inlines `Command::env("HOME", ...)` etc. to the shared helper. End state: SPDX byte-identity coverage matches CDX, normalization discipline lives in one place, fake-HOME isolation is uniform across the test tree.

## Technical Context

**Language/Version**: Rust stable (workspace toolchain inherited from milestones 001-016; no nightly required for user-space test code).
**Primary Dependencies**: existing only — `serde_json` (parse + serialize for normalization), `tempfile` (fake-HOME tempdir), `std::process::Command`, `std::path::{Path, PathBuf}`. **No new crates.**
**Storage**: 18 new committed golden JSON files under `mikebom-cli/tests/fixtures/golden/spdx-2.3/` (~9 files) and `mikebom-cli/tests/fixtures/golden/spdx-3/` (~9 files). Estimated ~5-50 KB per file (npm and maven fixtures are largest); total committed bytes well under 1 MB.
**Testing**: `./scripts/pre-pr.sh` (`cargo +stable clippy --workspace --all-targets` + `cargo +stable test --workspace`) is the gate. Two new test targets (`spdx_regression`, `spdx3_regression`) each with 9 `#[test]` functions; one new shared helper module compiled into ~30 existing test targets via `mod common;` declarations.
**Target Platform**: macOS 14+ (maintainer dev) + Linux x86_64 (CI). Both must produce byte-identical SPDX output for every committed golden — that's the whole point. The macOS CI leg added in milestone 016 (PR #34) is the cross-host enforcement mechanism.
**Project Type**: Test-infrastructure milestone — adds shared helpers and golden files; no production-code changes (no `mikebom-cli/src/` or `mikebom-common/src/` modifications expected). If the goldens-regen pass surfaces an emitter bug (per spec assumption), that bug-fix is bundled into the same PR but stays in scope of "make the goldens correct."
**Performance Goals**: Each new test target completes in <5s on warm cache (similar to `cdx_regression.rs` today). Total test-suite runtime grows by <60s. Goldens regen is rare (per-PR maintainer task), not in the hot path.
**Constraints**:

- Zero behavioral changes to production code. The 1385-passing baseline (post-#38) plus the 18 new tests = expected new total. Existing test names MUST NOT disappear.
- `cdx_regression.rs` migration MUST produce byte-identical CDX goldens. Verified by running `MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo test -p mikebom --test cdx_regression` after the migration and observing zero `git diff` against `mikebom-cli/tests/fixtures/golden/cyclonedx/`.
- No new runtime crates per Constitution Principle VI (Three-Crate Architecture). `tests/common/normalize.rs` lives inside the existing `mikebom-cli/tests/common/` module.
- `#![deny(clippy::unwrap_used)]` on the cli crate root applies to test code via `--all-targets`. Test files keep their `#![allow(clippy::unwrap_used)]` header per the existing convention; the new helper module uses `.expect()` with descriptive messages where infallibility is by construction (e.g., `serde_json::from_str(committed_golden).expect("committed golden parses")`).
- Constitution Principle V (Specification Compliance) — the goldens encode current emitter behavior; regenerating them is allowed only after a deliberate emitter change, never to "fix" a flaky test.

**Scale/Scope**: ~30 test files touched for the FR-008 fake-HOME migration; 2 new test files added (`spdx_regression.rs`, `spdx3_regression.rs`); 1 new helper module (`tests/common/normalize.rs`); 1 existing helper module extended (`tests/common/mod.rs` may re-export new helpers). 18 new committed JSON files. Estimated total diff: +400 / -300 LOC across test code, plus ~500-800 LOC of pretty-printed JSON in goldens.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Bearing on this feature | Pass? |
|-----------|-------------------------|-------|
| I. Pure Rust, Zero C | No C deps; test-infrastructure-only Rust changes. | ✓ |
| II. eBPF-Only Observation | Untouched — no observation-semantics changes. | ✓ |
| III. Fail Closed | Untouched — no failure-mode changes in production. | ✓ |
| IV. Type-Driven Correctness | Test code uses `.expect()` with descriptive messages where infallibility holds; production code is untouched. The new helper module exports typed functions; no `.unwrap()` in production paths. | ✓ |
| V. Specification Compliance | This feature *enforces* spec compliance more strictly: byte-identity goldens detect any drift from documented SPDX 2.3 / SPDX 3 emitter behavior. Goldens encode the post-#38 emitter output as the canonical baseline. | ✓ |
| VI. Three-Crate Architecture | No new crates. `tests/common/normalize.rs` lives inside `mikebom-cli/tests/common/` per the existing pattern. | ✓ |
| VII. Test Isolation | This is the milestone's *core* contribution — tightening fake-HOME isolation across the test tree. Strengthens the principle. | ✓ |
| VIII. Completeness | The new tests catch a class of regressions (cross-host SPDX drift) the existing tests miss. Strengthens. | ✓ |
| IX. Accuracy | Goldens encode actual emitter output; nothing synthetic. Strengthens. | ✓ |
| X. Transparency | Normalization decisions documented in `tests/common/normalize.rs` module-doc with rationale per masked field. Strengthens. | ✓ |
| XI. Enrichment / XII. External Sources | Untouched. | ✓ |
| Strict Boundary 4 (`No .unwrap()` in production) | Untouched — production unchanged. | ✓ |
| Pre-PR Verification | This feature *uses* the existing pre-PR gate (`./scripts/pre-pr.sh` from #38) and adds 18 new test cases that the gate exercises. No new gate logic. | ✓ |

**Initial gate**: PASS. No principle violations; the feature strengthens VII / VIII / IX / X.

## Project Structure

### Documentation (this feature)

```text
specs/017-spdx-byte-identity-goldens/
├── spec.md                  # Feature spec (already written)
├── plan.md                  # This file
├── research.md              # Phase 0 — golden shape decisions, normalize-vs-strip choices, regen-env-var naming
├── data-model.md            # Phase 1 — golden file shape, TriageDecision-equivalent for masked-field rationale
├── quickstart.md            # Phase 1 — how a contributor regenerates one golden, verifies cross-host stability locally
├── contracts/
│   └── golden-regen.md      # The MIKEBOM_UPDATE_*_GOLDENS=1 contract + commit-discipline rules
├── checklists/
│   └── requirements.md      # Spec quality checklist
└── tasks.md                 # Phase 2 output (created with the milestone, mirrors the 016 layout)
```

### Source Code (repository root)

```text
mikebom-cli/tests/
├── common/
│   ├── mod.rs               # MAY EXTEND: re-export `normalize` if convenient (low priority)
│   └── normalize.rs         # NEW: shared per-format normalizers + apply_fake_home_env helper
├── cdx_regression.rs        # MODIFIED: replace inline normalize() (lines 143-183) with common::normalize::*; verify byte-identical CDX goldens
├── spdx_regression.rs       # NEW: 9 #[test] per ecosystem; assert byte-equality against committed SPDX 2.3 goldens
├── spdx3_regression.rs      # NEW: 9 #[test] per ecosystem; assert byte-equality against committed SPDX 3 goldens
├── spdx_us1_acceptance.rs   # MODIFIED: switch HOME/CARGO_HOME/etc. setup to common::apply_fake_home_env
├── spdx3_us3_acceptance.rs  # MODIFIED: same
├── spdx_determinism.rs      # MODIFIED: same (keeps the run-vs-run determinism check; uses helper for env)
├── spdx3_determinism.rs     # MODIFIED: same
├── ... (~25 other tests)    # MODIFIED per FR-008: every test that calls Command::env("HOME"|"M2_REPO"|"GOPATH"|"GOMODCACHE"|"CARGO_HOME"|"MAVEN_HOME") inline migrates to common::apply_fake_home_env
└── fixtures/
    └── golden/
        ├── cyclonedx/       # UNCHANGED: 9 existing files; verify byte-identical post-cdx_regression.rs migration
        ├── spdx-2.3/        # NEW: 9 committed golden files (apk.spdx.json, cargo.spdx.json, ..., rpm.spdx.json)
        └── spdx-3/          # NEW: 9 committed golden files (apk.spdx3.json, cargo.spdx3.json, ..., rpm.spdx3.json)
```

**Structure Decision**: Test-infrastructure milestone. The implementation concentrates in three areas: (a) one new helper module + migrating one existing test to it (`cdx_regression.rs` → byte-identical), (b) two new regression tests + 18 committed goldens, (c) a mechanical sweep of ~25 existing tests to migrate inline env-redirect to the helper. No `mikebom-cli/src/` or `mikebom-common/src/` changes expected; if the goldens-regen surfaces an emitter bug, the bug fix is bundled into the same PR but stays scoped to "make the goldens correct."

## Phase 0 — Research questions (resolved in research.md)

- **R1**: How to handle SPDX 2.3 normalization given the JSON document is shape-different from CDX? Pre-parse to `serde_json::Value`, mutate, re-serialize? Or string-replace on the raw output (CDX's strategy)?
- **R2**: Should the regen env-var be format-scoped (`MIKEBOM_UPDATE_SPDX_GOLDENS=1`) or test-scoped (`MIKEBOM_UPDATE_GOLDENS=spdx-2.3`)? Which composes better with future format additions?
- **R3**: Where exactly does the workspace path leak in SPDX 2.3 output today? In SPDX 3? Empirical sweep needed before pinning goldens; the answer determines how surgical the workspace-path replacement must be.
- **R4**: Should `spdx_regression.rs` and `spdx3_regression.rs` share infrastructure with `cdx_regression.rs` via a shared trait, or stay format-specific files? Trade-off between reuse and clarity.

## Phase 1 — Design artifacts (resolved in data-model.md, contracts/golden-regen.md, quickstart.md)

- **Golden file shape** — pretty-printed JSON, sorted keys at every level (per `serde_json` default) so a future maintainer's `git diff` is readable. Workspace placeholder is the literal string `<WORKSPACE>` (matching CDX). Timestamp / UUID placeholders are documented per format.
- **Regen contract** — env var is the single source of truth. Without it, tests assert byte-equality. With it, tests overwrite the golden with the *normalized* fresh output and pass. CI never sets the env var; only maintainers do, locally, when a deliberate emitter change requires it.
- **Quickstart workflow** — three commands per ecosystem regen: scan, normalize, write golden; the test code wraps all three.

## Complexity Tracking

> No constitution violations. Complexity is in (a) the *count* of fake-HOME-isolation migrations (~25 test files), (b) the *care* needed during the goldens-regen first pass to surface and fix any emitter drift before pinning, and (c) the cross-host verification step (regen on macOS, scan on Linux CI, confirm zero diff). Each is mechanical with judgment; none is architectural.

The single judgment-heavy moment is FR-007 — verifying that `cdx_regression.rs`'s migration to the shared helper produces byte-identical goldens. If they diverge, the new helper is wrong and must be reconciled with the inline behavior before the migration commits.
