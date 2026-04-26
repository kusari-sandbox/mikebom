---
description: "Task list — milestone 021 SPDX normalize-consumption"
---

# Tasks: SPDX Normalize-Consumption — Tighter Spec

**Input**: Design documents from `/specs/021-spdx-normalize-consumption/`
**Prerequisites**: spec.md (✅), plan.md (✅), checklists/requirements.md (✅)

**Tests**: No new tests. The 27 byte-identity goldens (from milestones 017 + 020) plus the existing 50-iteration tight-loop discipline are the regression surface.

**Organization**: Single user story (US1, P2). Two atomic commits + polish.

## Format: `[ID] [Story] Description`

- All tasks map to US1.

## Path Conventions

- Touches `mikebom-cli/tests/spdx_us1_acceptance.rs`, `mikebom-cli/tests/spdx3_us3_acceptance.rs`, `mikebom-cli/tests/spdx_determinism.rs`, `mikebom-cli/tests/spdx3_determinism.rs`.
- Does NOT touch `mikebom-cli/src/` (FR-006 / SC-005).
- Does NOT touch `cdx_regression.rs`, `spdx_regression.rs` (already at parity), or `common/normalize.rs` itself (already mature).

---

## Phase 1: Reconnaissance & Baseline

- [X] T001 Reconnaissance done in pre-spec investigation (2026-04-26). Findings logged in `spec.md` Background table. The "documented flake" verified non-existent (50 isolated + 5 default-parallel + 12 4-way concurrent + 3 regen-mode runs all green).
- [ ] T002 Snapshot baseline: `./scripts/pre-pr.sh 2>&1 | tee /tmp/baseline-021.txt | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/baseline-021-tests.txt`. Compare post-021 to confirm zero test renames/removals.

---

## Phase 2: Commit 1 — `021/acceptance-isolation`

**Goal**: `spdx_us1_acceptance.rs` and `spdx3_us3_acceptance.rs` apply `apply_fake_home_env` at every `Command::new(bin())` spawn site.

- [ ] T003 Audit `spdx_us1_acceptance.rs` for `Command::new(bin())` and `Command::new(common::bin())` sites. List each line number. Expected: 5-7 sites based on file LOC.
- [ ] T004 At each site: import `common::normalize::apply_fake_home_env`; allocate `let fake_home = tempfile::tempdir().expect("tempdir");`; call `apply_fake_home_env(&mut cmd, fake_home.path())` before `.output()`/`.spawn()`. Hold `fake_home` in scope until after the spawn completes.
- [ ] T005 Audit `spdx3_us3_acceptance.rs` for spawn sites that don't already use `apply_fake_home_env`. The existing scenario-4 npm test (line 206) is the pattern.
- [ ] T006 Apply isolation to the missing scenarios (specifically scenario 5 at ~line 277 per recon).
- [ ] T007 Verify: `cargo +stable test -p mikebom --test spdx_us1_acceptance --test spdx3_us3_acceptance` passes. Pre-PR clean.
- [ ] T008 Commit: `refactor(021/acceptance-isolation): apply_fake_home_env across SPDX 2.3 + 3.0.1 acceptance tests`.

---

## Phase 3: Commit 2 — `021/determinism-isolation`

**Goal**: `spdx_determinism.rs` gains `apply_fake_home_env`; `spdx3_determinism.rs::normalize()` gains workspace-path replacement.

- [ ] T009 Edit `spdx_determinism.rs::scan_to_spdx_json` (line 16): allocate `fake_home: TempDir` (caller-provided or function-internal; pick whichever keeps the helper simple), apply `apply_fake_home_env` to the `Command` before `.output()`. Hold the tempdir in scope until output is read.
- [ ] T010 Edit `spdx3_determinism.rs::normalize()` (line 56): add workspace-path replacement against `WORKSPACE_PLACEHOLDER` before parsing JSON. Decision per FR-004: either inline the `raw.replace(workspace, WORKSPACE_PLACEHOLDER)` step OR delegate to `normalize_spdx3_for_golden()` if the contract matches. Verify by running the test before and after.
- [ ] T011 Verify: `cargo +stable test -p mikebom --test spdx_determinism --test spdx3_determinism` passes. Pre-PR clean.
- [ ] T012 Commit: `refactor(021/determinism-isolation): apply_fake_home_env + workspace-path normalization across SPDX determinism tests`.

---

## Phase 4: Verification

- [ ] T013 50-iteration tight loops, one per affected file:
  ```
  for i in $(seq 1 50); do cargo +stable test -p mikebom --test spdx_us1_acceptance -- --test-threads=1 2>&1 | grep -qE 'test result: ok' || echo FAIL $i; done
  ```
  Repeat for `spdx_determinism`, `spdx3_us3_acceptance`, `spdx3_determinism`. SC-002 holds when each is 50/50.
- [ ] T014 SC-003 verification: regen all 27 goldens via `MIKEBOM_UPDATE_CDX_GOLDENS=1 MIKEBOM_UPDATE_SPDX_GOLDENS=1 MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test --workspace --tests -- --test-threads=1`. Verify `git diff -- mikebom-cli/tests/golden` is empty.
- [ ] T015 SC-005 verification: `git diff main..HEAD -- mikebom-cli/src/` is empty.
- [ ] T016 Push branch; observe both Linux CI lanes + macOS lane green.
- [ ] T017 Author PR description: 2-commit summary, contract pointer (`tests/common/normalize.rs` is what's being consumed), byte-identity attestation.

---

## Dependency Graph

```text
T001 (recon, done) ──→ T002 (baseline)
                          │
                          ↓
                     T003 → T004 → T005 → T006 → T007 → T008  ← Commit 1
                                                          │
                                                          ↓
                                                     T009 → T010 → T011 → T012  ← Commit 2
                                                                            │
                                                                            ↓
                                                                       T013 → T014 → T015 → T016 → T017
```

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Phase 1 (baseline) | 5 min | T001 already done; just T002 snapshot |
| Phase 2 (acceptance) | 45 min | Audit + insert; us1 has more sites than us3 |
| Phase 3 (determinism) | 30 min | Smaller diff; mostly mechanical |
| Phase 4 (verify + PR) | 20 min | 50x loops + regen + push |
| **Total** | **~1.5 hr** | One focused sitting. |
