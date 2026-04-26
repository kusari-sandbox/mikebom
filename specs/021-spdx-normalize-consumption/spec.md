---
description: "Bring SPDX 2.3/3.0.1 acceptance + determinism tests onto the existing normalize.rs hardening pattern (Tier 2)"
status: spec
milestone: 021
---

# Spec: SPDX Test Normalize-Consumption

## Background

Milestone 017 (PR #40) extracted `mikebom-cli/tests/common/normalize.rs` (281 LOC) with the canonical cross-host hardening primitives — `apply_fake_home_env()`, `WORKSPACE_PLACEHOLDER`, `normalize_cdx_for_golden()`, `normalize_spdx23_for_golden()`, `normalize_spdx3_for_golden()` — and applied them in `cdx_regression.rs` and `spdx_regression.rs`. Both regression suites now produce byte-identical output across macOS dev and Linux CI.

What didn't get done: the four sibling **acceptance** + **determinism** test files were left mid-conversion. The 2026-04-26 reconnaissance (logged in `tasks.md` T001) confirmed:

| Test file | `apply_fake_home_env`? | normalize helper? |
|---|---|---|
| `cdx_regression.rs` | ✓ | ✓ (gold standard) |
| `spdx_regression.rs` | ✓ | ✓ (already parity) |
| `spdx_us1_acceptance.rs` | ✗ | ✗ — bare `Command::new(bin())` |
| `spdx3_us3_acceptance.rs` | ⚠ partial — only one scenario | ✗ |
| `spdx_determinism.rs` | ✗ | ✗ |
| `spdx3_determinism.rs` | ✓ | ⚠ partial — missing workspace-path |

The risk is the same one PR #40 surfaced: a host-specific value (HOME-derived path, stale Maven repo cache, GOPATH module cache, workspace path) leaks into a test's assertion target, the test passes on the dev box but fails on a CI runner with different paths — or worse, passes on both but masks a real bug because the contaminated input happens to produce matching contaminated output.

The work is **consumption**, not extraction: the helpers exist; three files don't yet call them and one file calls them partially. No new infrastructure is needed.

## User Story (US1, P2)

**As a contributor opening any PR that touches the SPDX 2.3 or 3.0.1 generators**, I want every SPDX-related test file to use the same cross-host normalization discipline (`apply_fake_home_env` + the format-appropriate normalize helper) so that test results reflect generator correctness, not host-environment contamination.

**Why P2 (not P1):** none of the affected tests have observable failures today. The work is hygiene + risk reduction, not bug-fixing. Easy to slot in between higher-priority milestones; defer-able if a more urgent item appears.

### Independent Test

After implementation:

- `mikebom-cli/tests/spdx_us1_acceptance.rs` calls `apply_fake_home_env(&mut cmd, &fake_home)` on every spawned `Command::new(bin())` and stops setting host-leaked env vars unconditionally.
- `mikebom-cli/tests/spdx_determinism.rs` does the same — both `scan_to_spdx_json` invocations isolate HOME via the helper.
- `mikebom-cli/tests/spdx3_us3_acceptance.rs` applies isolation across **all** scenarios (not just scenario 4's npm test).
- `mikebom-cli/tests/spdx3_determinism.rs` adds workspace-path normalization to its `normalize()` helper (so two-runs comparison won't break the day a future field starts including the workspace path).
- All four files compile + pass under both:
  - `cargo +stable test --workspace` (default lane)
  - 50 iterations of `cargo +stable test -p mikebom --test spdx_us1_acceptance`, `--test spdx_determinism`, etc. in a tight loop on macOS
- 27 byte-identity goldens regen with zero diff (no behavior change in mikebom output).

## Acceptance Scenarios

**Scenario 1: Host-state isolation under unusual local Maven cache**
```
Given: a contributor with $M2_REPO populated with hundreds of artifacts
When:  they run `cargo +stable test --workspace`
Then:  spdx_us1_acceptance.rs and spdx_determinism.rs scan results are
       independent of the local Maven cache state — assertions reflect
       only the in-fixture content
```

**Scenario 2: Cross-host run-twice determinism**
```
Given: spdx_determinism::cargo_scan_is_deterministic
When:  the test runs on macOS dev box AND on Linux CI
Then:  both invocations produce mutually-byte-identical output (after
       masking only creationInfo.created), AND both runs use the same
       fake-HOME isolation so the comparison is honest
```

**Scenario 3: spdx3_us3_acceptance scenario consistency**
```
Given: spdx3_us3_acceptance.rs has 5 scenarios
When:  any one of them spawns `mikebom sbom scan`
Then:  all 5 use apply_fake_home_env identically — no scenario sees
       host state that another scenario doesn't
```

## Edge Cases

- **Acceptance tests have no goldens.** `spdx_us1_acceptance.rs` and `spdx3_us3_acceptance.rs` make in-memory shape assertions (PURLs, license fields, document-namespace stability). No golden files; no regen env var; the normalize helpers' golden-comparison contract doesn't apply. The scope is **isolation only** for these two files. The `normalize_spdx*_for_golden` helpers are NOT consumed; only `apply_fake_home_env`.
- **Determinism tests have no goldens.** Same reasoning. `spdx_determinism.rs` and `spdx3_determinism.rs` compare two in-memory scans against each other. They benefit from `apply_fake_home_env` (so both scans see the same isolated env) and from workspace-path normalization (so the contract doesn't accidentally start passing/failing based on whose dev box runs it).
- **`mask_volatile()` in spdx_us1_acceptance.rs scenario 5.** The local helper at lines 297-322 already does what `normalize_cdx_for_golden`/`normalize_spdx23_for_golden` would do for that one dual-format scenario. Scope-decision: leave the local helper, since extracting it back to `common/normalize.rs` would conflate "golden comparison" (the helpers' purpose) with "scenario-5 ad-hoc comparison" (a different need). FR-005 codifies this.
- **`spdx3_determinism.rs` partial state.** The file already calls `apply_fake_home_env` consistently in `run_scan()` (line 29). What it lacks is workspace-path replacement in its local `normalize()` helper (line 56). FR-004 makes this a one-line edit using `WORKSPACE_PLACEHOLDER`.
- **No new test files.** This milestone consumes existing helpers; it does not add tests.

## Functional Requirements

- **FR-001**: `mikebom-cli/tests/spdx_us1_acceptance.rs` imports `apply_fake_home_env` from `common::normalize` and applies it to every `Command::new(common::bin())` invocation. Each call site allocates a `tempfile::TempDir` for the fake HOME and holds it for the duration of the spawn.
- **FR-002**: `mikebom-cli/tests/spdx_determinism.rs` does the same — both `scan_to_spdx_json()` invocations (one in `scan_to_spdx_json` itself, applied to the helper) isolate HOME identically.
- **FR-003**: `mikebom-cli/tests/spdx3_us3_acceptance.rs` audits every scenario; any `Command::new(bin())` that doesn't currently call `apply_fake_home_env` gains the call. The existing scenario-4 npm test (line 206) is the reference pattern.
- **FR-004**: `mikebom-cli/tests/spdx3_determinism.rs::normalize()` (line 56) gains workspace-path replacement against `WORKSPACE_PLACEHOLDER`. The local `normalize()` continues to mask `CreationInfo.created` (already done); workspace-path becomes its second responsibility. (Or, equivalently, switch to calling `normalize_spdx3_for_golden()` from `common::normalize` if the contract matches — verified at implementation time.)
- **FR-005**: `mikebom-cli/tests/spdx_us1_acceptance.rs::mask_volatile()` (lines 297-322) is left in place. Out of scope to extract — different concern from golden comparison.
- **FR-006**: No mikebom production code changes. Test-files-only refactor (mirrors milestone 016's discipline).
- **FR-007**: 27 byte-identity goldens regen with zero diff. Verifies no scan-output behavior change.
- **FR-008**: Each commit leaves `./scripts/pre-pr.sh` clean — same per-commit-clean discipline as 018, 019, 020.

## Success Criteria

- **SC-001**: After implementation, `rg 'Command::new\(common::bin\(\)\)|Command::new\(bin\(\)\)' mikebom-cli/tests/spdx_us1_acceptance.rs mikebom-cli/tests/spdx_determinism.rs mikebom-cli/tests/spdx3_us3_acceptance.rs` shows zero call sites that aren't followed within 3 lines by an `apply_fake_home_env` invocation. (Heuristic — manual audit confirms.)
- **SC-002**: 50-iteration tight-loop test of each affected file in isolation passes 50/50.
- **SC-003**: 27-golden regen produces zero diff (`MIKEBOM_UPDATE_CDX_GOLDENS=1 MIKEBOM_UPDATE_SPDX_GOLDENS=1 MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test --workspace --tests -- --test-threads=1`).
- **SC-004**: Both Linux CI lanes + macOS lane green on the milestone PR.
- **SC-005**: `git diff main..021-spdx-normalize-consumption -- mikebom-cli/src/` is empty (test-only refactor).

## Clarifications

- **Scope is consumption only**, not extraction. The normalize.rs module exists and is mature.
- **Acceptance tests don't get goldens or regen mechanisms.** Their assertion model (in-memory shape checks) is fine as-is; they only need isolation.
- **Determinism tests don't get goldens.** Their assertion model (two-runs comparison) doesn't fit the goldens pattern.
- **`mask_volatile()` stays put.** Different concern from golden comparison; not worth conflating.
- **No spec-to-implementation contracts file.** No public API surface changes; no new types or modules introduced.

## Out of Scope

- Adding goldens to acceptance or determinism tests (different milestone).
- Investigating the (now-debunked) `cargo_scan_is_deterministic` flake — verified non-existent in milestone-021 task T001.
- Module splits (Tier 4).
- Any change to `mikebom-cli/src/`.
- Touching `cdx_regression.rs` or `spdx_regression.rs` — they're already at parity.
