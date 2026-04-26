---
description: "Task list — milestone 021 SPDX normalize-consumption"
---

# Tasks: SPDX Normalize-Consumption — Tighter Spec

**Input**: Design documents from `/specs/021-spdx-normalize-consumption/`
**Prerequisites**: spec.md (✅), plan.md (✅), checklists/requirements.md (✅)

**Tests**: No new tests. The 27 byte-identity goldens (from milestones 017 + 020) plus the 50-iteration tight-loop discipline are the regression surface.

**Organization**: Single user story (US1, P2). One atomic commit + verification.

## Path Conventions

- Touches `mikebom-cli/tests/spdx_us1_acceptance.rs` and `mikebom-cli/tests/spdx_determinism.rs`.
- Does NOT touch `mikebom-cli/src/` (FR-006 / SC-005).
- Does NOT touch `cdx_regression.rs`, `spdx_regression.rs`, `spdx3_us3_acceptance.rs`, `spdx3_determinism.rs`, or `common/normalize.rs` (all already at parity per direct re-verification).

---

## Phase 1: Reconnaissance & Baseline

- [X] T001 Reconnaissance done in pre-spec investigation (2026-04-26). Initial recon overstated scope; direct re-verification corrected: `spdx3_us3_acceptance.rs` and `spdx3_determinism.rs` are already at parity. The "documented spdx_determinism flake" verified non-existent across 70 local + 30 CI runs.
- [ ] T002 Snapshot baseline: `./scripts/pre-pr.sh 2>&1 | tee /tmp/baseline-021.txt | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/baseline-021-tests.txt`. Confirm post-021 list is identical (zero rename or removal).

---

## Phase 2: Single Commit — `021/spdx-isolation`

**Goal**: Both files apply `apply_fake_home_env` at their single shared spawn helper.

- [ ] T003 Edit `mikebom-cli/tests/spdx_us1_acceptance.rs::scan()` (line 34):
  1. Add `use common::normalize::apply_fake_home_env;` to the imports near `use common::{bin, workspace_root};`.
  2. Inside the `scan()` body, after `let tmp = tempfile::tempdir()...`, allocate `let fake_home = tempfile::tempdir().expect("fake-home tempdir");`.
  3. After `let mut cmd = Command::new(bin());`, add `apply_fake_home_env(&mut cmd, fake_home.path());`.
  4. Verify `fake_home` lives until after `let out = cmd.output()...;` returns (it does — both bindings are in the same `fn` body and Rust drops at end-of-scope).
- [ ] T004 Edit `mikebom-cli/tests/spdx_determinism.rs::scan_to_spdx_json()` (line 16):
  1. Add `use common::normalize::apply_fake_home_env;` to imports.
  2. Inside `scan_to_spdx_json()`, after `let tmp = tempfile::tempdir()...`, allocate `let fake_home = tempfile::tempdir().expect("fake-home tempdir");`.
  3. After `let bin = env!(...); let status = Command::new(bin)`, restructure to bind `let mut cmd = Command::new(bin); apply_fake_home_env(&mut cmd, fake_home.path()); let status = cmd.arg(...)...`.
- [ ] T005 Verify: `cargo +stable test -p mikebom --test spdx_us1_acceptance --test spdx_determinism` passes.
- [ ] T006 Pre-PR clean (`./scripts/pre-pr.sh`).
- [ ] T007 Commit: `refactor(021/spdx-isolation): apply_fake_home_env in spdx_us1_acceptance + spdx_determinism shared helpers`.

---

## Phase 3: Verification

- [ ] T008 50-iteration tight loops:
  ```
  for i in $(seq 1 50); do
    cargo +stable test -p mikebom --test spdx_us1_acceptance -- --test-threads=1 \
      2>&1 | grep -qE 'test result: ok' || echo "FAIL iter $i"
  done
  ```
  Repeat for `spdx_determinism`. SC-002 holds when each is 50/50.
- [ ] T009 SC-003 verification: regen all 27 goldens via `MIKEBOM_UPDATE_CDX_GOLDENS=1 MIKEBOM_UPDATE_SPDX_GOLDENS=1 MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test --workspace --tests -- --test-threads=1`. Verify `git diff -- mikebom-cli/tests/golden` is empty.
- [ ] T010 SC-005 verification: `git diff main..HEAD -- mikebom-cli/src/` is empty. Also: `git diff main..HEAD -- mikebom-cli/tests/spdx3_us3_acceptance.rs mikebom-cli/tests/spdx3_determinism.rs` is empty (corrected-scope regression check from spec Scenario 3).
- [ ] T011 Push branch; observe both Linux CI lanes + macOS lane green.
- [ ] T012 Author PR description: 1-commit summary, recon-correction note, byte-identity attestation, what was NOT touched and why.

---

## Dependency Graph

```text
T001 (recon, done) → T002 (baseline)
                       │
                       ↓
                  T003 → T004 → T005 → T006 → T007  ← Single commit
                                                │
                                                ↓
                                           T008 → T009 → T010 → T011 → T012
```

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Phase 1 (baseline) | 5 min | T001 already done; just T002 snapshot |
| Phase 2 (single commit) | 20 min | Two helper edits, ~6 lines each |
| Phase 3 (verify + PR) | 20 min | 50x loops + regen + push |
| **Total** | **~45 min** | One focused half-hour-plus. |
