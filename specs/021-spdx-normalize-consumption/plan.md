---
description: "Implementation plan — milestone 021 SPDX normalize-consumption"
status: plan
milestone: 021
---

# Plan: SPDX Test Normalize-Consumption

## Architecture

Test-files-only refactor. Each affected file imports the existing primitives from `common::normalize` and applies them at every `Command::new(bin())` site (or, for determinism tests, every output-normalization site).

No new modules, no new types, no production code changes. The `common::normalize` module already exposes everything needed.

## Touched files

| File | Change shape | Estimated diff |
|---|---|---|
| `mikebom-cli/tests/spdx_us1_acceptance.rs` | Import `apply_fake_home_env`; allocate `TempDir` + apply env at each scan-spawn site (~6 spawn sites) | ~30 lines |
| `mikebom-cli/tests/spdx_determinism.rs` | Update `scan_to_spdx_json()` to take or create a fake-home tempdir + apply env | ~10 lines |
| `mikebom-cli/tests/spdx3_us3_acceptance.rs` | Audit 5 scenarios; add `apply_fake_home_env` to scenarios that don't have it (specifically scenario 5 at line 277) | ~15 lines |
| `mikebom-cli/tests/spdx3_determinism.rs` | `normalize()` at line 56 gets workspace-path replacement against `WORKSPACE_PLACEHOLDER` | ~5 lines |

Total: ~60 lines of test-file changes across 4 files.

## Phasing

Three atomic commits, organized by failure-mode similarity:

### Commit 1: `021/acceptance-isolation`
- `spdx_us1_acceptance.rs` and `spdx3_us3_acceptance.rs` together — both are acceptance tests with shape assertions, both need pure HOME isolation.
- After commit: ALL acceptance-test spawns isolate HOME. SC-001 holds.

### Commit 2: `021/determinism-isolation`
- `spdx_determinism.rs` and `spdx3_determinism.rs` together — both are run-twice-and-compare, similar fix shape.
- `spdx_determinism.rs` gains `apply_fake_home_env`. `spdx3_determinism.rs::normalize()` gains workspace-path replacement.
- After commit: both runs of the same fixture see identical isolated env. SC-002 holds.

### Commit 3: `021/verify`
- Optional commit. If commits 1 and 2 are atomic and SC-003 holds at each of those, this commit is empty and not needed.
- If anything triggered a goldens diff, this commit captures the regen.

Per FR-008 each commit leaves `./scripts/pre-pr.sh` clean.

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Commit 1 (acceptance) | 45 min | Audit + insert isolation at each spawn site; ~6 sites in us1, ~3 missing sites in us3 |
| Commit 2 (determinism) | 30 min | More mechanical — only one site each |
| Verification + PR | 15 min | 50x loop per file + regen + push + PR description |
| **Total** | **1.5 hr** | One focused sitting. |

## Risks

- **R1: Acceptance tests' shape assertions break under isolation.** Possible if any assertion implicitly depended on a host-cache-derived value. Mitigation: read each scenario carefully before applying isolation; if a shape assertion relies on something that fake-HOME would invalidate, the assertion itself needs reframing. (Per recon, we don't expect this — assertions check PURLs/license fields/document-namespace stability, all fixture-derived.)
- **R2: `spdx3_determinism.rs` workspace-path edit invalidates the existing two-runs-compare contract.** Mitigation: the change is symmetric — both runs apply the same normalization, so the equality comparison still holds. Tight-loop verification (SC-002) is the regression gate.
- **R3: I create a temp `fake_home` per spawn but assertions later read paths from the produced output.** Possible with scenario-5-style tests. Mitigation: keep TempDir alive in the test scope; only normalize the JSON for assertions, not the underlying paths the test inspects.

## Constitution alignment

- **Principle IV (no `.unwrap()` in production):** test code is feature-gated via the existing `#[cfg_attr(test, allow(clippy::unwrap_used))]` on test modules; this milestone respects existing patterns.
- **Principle VI (three-crate architecture):** untouched. Test-only.
- **Per-commit verification (lessons from 018-019-020):** FR-008 enforced.

## What this milestone does NOT do

- Does not extract anything from `common/normalize.rs` (already extracted).
- Does not add goldens to acceptance/determinism tests (out of scope per spec).
- Does not touch `cdx_regression.rs` or `spdx_regression.rs` (already parity).
- Does not investigate the determinism flake (verified non-existent in T001).
