---
description: "Implementation plan — milestone 021 SPDX normalize-consumption"
status: plan
milestone: 021
---

# Plan: SPDX Test Normalize-Consumption

## Architecture

Test-files-only refactor. Each affected file imports the existing primitives from `common::normalize` and applies them at the single shared spawn helper.

No new modules, no new types, no production code changes. The `common::normalize` module already exposes everything needed.

## Touched files (corrected 2026-04-26)

| File | Change shape | Estimated diff |
|---|---|---|
| `mikebom-cli/tests/spdx_us1_acceptance.rs` | `scan()` helper at line 34 imports `apply_fake_home_env`; allocates one TempDir + applies env at line 37's `Command::new(bin())` site | ~6 lines |
| `mikebom-cli/tests/spdx_determinism.rs` | `scan_to_spdx_json()` at line 16 does the same | ~6 lines |

Total: ~12 lines across 2 files.

(Originally scoped at ~60 lines across 4 files; recon overstated the work — see spec.md "Note on spec amendment" for the verified file-by-file findings that reduced scope.)

## Phasing

**Single atomic commit** (`021/spdx-isolation`) — both files together since each is a one-helper, one-spawn-site change. Splitting into two commits would be ceremony for ~6 lines apiece. The originally planned "Commit 2" (determinism-isolation) collapses into the same commit; the originally planned "Commit 3" (verify) was already optional.

After commit: SC-001 + SC-002 + SC-003 + SC-005 hold simultaneously. Pre-PR clean.

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Single commit (both files) | 20 min | One helper edit per file, mechanical |
| Verification + PR | 20 min | 50x loops + regen + push + watch CI |
| **Total** | **~40 min** | One focused half-hour. |

## Risks

- **R1: Acceptance tests' shape assertions break under isolation.** Possible if any assertion implicitly depended on a host-cache-derived value (e.g., a Maven artifact resolved from local M2). Mitigation: spdx_us1_acceptance.rs scenarios check PURLs/license fields/document-namespace stability — all fixture-derived. If a shape assertion does break, the assertion itself was the bug (depending on host state to pass).
- **R2: `tempfile::TempDir` lifecycle.** The fake_home TempDir must outlive the spawn. Mitigation: bind it as a local in `scan()`/`scan_to_spdx_json()` so the implicit drop happens at end-of-scope, after `.output()` returns.

## Constitution alignment

- **Principle IV (no `.unwrap()` in production):** test code is feature-gated via the existing `#[cfg_attr(test, allow(clippy::unwrap_used))]` patterns; `.expect()` calls in tests follow existing convention.
- **Principle VI (three-crate architecture):** untouched. Test-only.
- **Per-commit verification (lessons from 018-019-020):** FR-008 enforced; only one commit, so trivially satisfied.

## What this milestone does NOT do

- Does not extract anything from `common/normalize.rs` (already extracted).
- Does not add goldens to acceptance/determinism tests (out of scope per spec).
- Does not touch `cdx_regression.rs`, `spdx_regression.rs`, `spdx3_us3_acceptance.rs`, or `spdx3_determinism.rs` (already at parity per re-verification).
- Does not investigate the determinism flake (verified non-existent in T001).
