---
description: "Task list — SPDX byte-identity goldens + cross-host determinism parity (milestone 017)"
---

# Tasks: SPDX Byte-Identity Goldens + Cross-Host Determinism Parity

**Input**: Design documents from `/specs/017-spdx-byte-identity-goldens/`
**Prerequisites**: spec.md (✅), plan.md (✅), research.md (✅), data-model.md (✅), contracts/golden-regen.md (✅), quickstart.md (✅)

**Tests**: Two new test targets (`spdx_regression`, `spdx3_regression`) with 9 `#[test]` each = 18 new test cases. The byte-identity check IS the new behavioral guarantee per FRs 003/004; verification is via the existing `./scripts/pre-pr.sh` gate plus the FR-008 grep + the SC-003 deliberate-byte-flip probe.

**Organization**: Tasks are grouped by user story for independent implementation:

- **US1 (P1, MVP)**: SPDX byte-identity goldens for all 9 ecosystems — 18 new committed goldens + 2 new test files. Largest single contributor; closes the post-#38 SPDX gap.
- **US2 (P2)**: Shared normalization helper — `tests/common/normalize.rs` with the four FR-006 functions; CDX migration to it is byte-identical proof-of-correctness.
- **US3 (P3)**: Uniform fake-HOME isolation across the test tree — mechanical sweep.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Maps task to spec.md user story (US1, US2, US3); omitted on Setup / Polish

## Path Conventions

Single Rust workspace; this milestone touches `mikebom-cli/tests/common/`, `mikebom-cli/tests/*.rs` (new + modified), and `mikebom-cli/tests/fixtures/golden/{spdx-2.3,spdx-3}/` (new). No production-code changes expected — see plan.md "Project type" caveat about emitter-bug fixes if surfaced during regen.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Snapshot the post-#38 baseline so regressions during the migration are obvious. Confirm the helper-module skeleton compiles.

- [ ] T001 Snapshot baseline: `./scripts/pre-pr.sh 2>&1 | tee /tmp/baseline-017.txt` — capture the test count + clippy state on the milestone-branch tip. Used later for FR-009 cross-check (no test names disappear; new ones appear). Output is local-only — not committed.
- [ ] T002 Create the helper module skeleton at `mikebom-cli/tests/common/normalize.rs`. Write the module-doc per `data-model.md` "Module-doc shape" (currently empty bullets — will be filled in T003-T006 as each function lands). Add empty function signatures matching FR-006 with `unimplemented!()` bodies. Run `cargo +stable check --workspace` — confirm the workspace compiles with the skeleton.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Build the helper's CDX-compatible core and prove the migration is byte-identical. This phase is the foundation for US1; both SPDX targets depend on it.

**Checkpoint**: After Phase 2 completes, the helper module has working CDX functions and `cdx_regression.rs` uses them. `MIKEBOM_UPDATE_CDX_GOLDENS=1 git diff` is empty.

- [ ] T003 [US2] Implement `apply_fake_home_env(cmd: &mut Command, fake_home: &Path)` in `tests/common/normalize.rs`. Six env vars per `data-model.md` "Helper module": HOME, M2_REPO, MAVEN_HOME, GOPATH, GOMODCACHE, CARGO_HOME. Each redirected to a sub-path under `fake_home` (sub-paths don't need to exist — they just point cache lookups at empty dirs). Add the corresponding module-doc bullet enumerating the env vars + what cache each one points at.
- [ ] T004 [US2] Implement `normalize_cdx_for_golden(raw: &str, workspace: &Path) -> String` by porting `cdx_regression.rs:143-183` verbatim into the helper. The string-replace + JSON-walk + hash-strip logic moves wholesale; only function name + module location change. Add the module-doc bullets covering CDX masked fields (per `data-model.md` "Placeholder catalog" CDX rows).
- [ ] T005 [US2] Migrate `cdx_regression.rs` to call `common::normalize::normalize_cdx_for_golden` and `common::normalize::apply_fake_home_env`. Delete the now-unused inline `fn normalize` (lines 143-183) and the inline env block (lines 88-93). Constants `SERIAL_PLACEHOLDER`, `TIMESTAMP_PLACEHOLDER`, `WORKSPACE_PLACEHOLDER` move into `tests/common/normalize.rs` as `pub const` (or stay inlined; either works — pick the one that keeps `cdx_regression.rs` thinnest). Run `cargo +stable test -p mikebom --test cdx_regression`; expect all 9 to pass.
- [ ] T006 [US2] Verify CDX byte-identity post-migration. Run `MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo +stable test -p mikebom --test cdx_regression` then `git diff mikebom-cli/tests/fixtures/golden/cyclonedx/`. Expected output: empty. If diff is non-empty, the helper diverged from the inline behavior — diff the helper line-for-line against the pre-migration `cdx_regression.rs:143-183` and reconcile before proceeding to Phase 3.

---

## Phase 3: User Story 1 — SPDX byte-identity goldens for all 9 ecosystems (Priority: P1) 🎯 MVP

**Goal**: Ship `spdx_regression.rs` + `spdx3_regression.rs` with 18 committed goldens and full normalize coverage.

**Independent Test**: After T015, `cargo +stable test -p mikebom --test spdx_regression` and `--test spdx3_regression` each report `ok. 9 passed; 0 failed` from a clean working tree (no env vars set). Both CI legs (Linux + macOS, via `./scripts/pre-pr.sh`) pass on the open PR.

**Implementation note**: T007–T009 (SPDX 2.3) and T011–T013 (SPDX 3) are file-disjoint after T010 lands. T007 + T011 can run in parallel since they touch separate helper functions; T008 + T012 are independent test files; T009 + T013 are independent goldens directories.

- [ ] T007 [US1] Implement `normalize_spdx23_for_golden(doc: serde_json::Value, workspace: &Path) -> serde_json::Value` in `tests/common/normalize.rs`. Per `data-model.md` "Placeholder catalog" SPDX 2.3 rows: mask `creationInfo.created` to `1970-01-01T00:00:00Z`; strip `packages[].checksums[]`. Workspace-path string-replace runs on the raw output before parsing — caller's responsibility (mirrored from CDX). Add the module-doc bullets covering SPDX 2.3 masked fields with rationale.
- [ ] T008 [P] [US1] Create `mikebom-cli/tests/spdx_regression.rs` by copying `cdx_regression.rs`'s post-T005 shape. Adjust: `--format spdx-2.3-json`, golden path `tests/fixtures/golden/spdx-2.3/{label}.spdx.json`, env var `MIKEBOM_UPDATE_SPDX_GOLDENS`, normalize call to `normalize_spdx23_for_golden`. 9 `#[test]` named `<ecosystem>_byte_identity` per `research.md` R7. The test body uses `common::apply_fake_home_env` from T003.
- [ ] T009 [US1] Generate the 9 SPDX 2.3 goldens. Create the directory: `mkdir -p mikebom-cli/tests/fixtures/golden/spdx-2.3`. Run `MIKEBOM_UPDATE_SPDX_GOLDENS=1 cargo +stable test -p mikebom --test spdx_regression`. Verify the 9 files exist with non-trivial content. Empirical leak-vector sweep per `research.md` R3: `rg '/Users/[^"]*' mikebom-cli/tests/fixtures/golden/spdx-2.3/` MUST return empty. If non-empty, augment `normalize_spdx23_for_golden`'s string-replace pass with the discovered prefix, regen, re-sweep until empty.
- [ ] T010 [US1] Run `cargo +stable test -p mikebom --test spdx_regression` (no env vars) — expect 9/9 pass. The goldens are now load-bearing.
- [ ] T011 [US1] Implement `normalize_spdx3_for_golden(doc: serde_json::Value, workspace: &Path) -> serde_json::Value` in `tests/common/normalize.rs`. Per `data-model.md`: walk `@graph[]`, mask `created` on every element with `type == "CreationInfo"`; on every element with `type == "Package"`, strip `verifiedUsing[]`. Document IRI is content-derived (host-stable per `spdx3_determinism.rs:11-13`) so left alone. Add the module-doc bullets.
- [ ] T012 [P] [US1] Create `mikebom-cli/tests/spdx3_regression.rs` by copying `spdx_regression.rs`'s shape. Adjust: `--format spdx-3-json`, golden path `tests/fixtures/golden/spdx-3/{label}.spdx3.json`, env var `MIKEBOM_UPDATE_SPDX3_GOLDENS`, normalize call to `normalize_spdx3_for_golden`. 9 `#[test]` named `<ecosystem>_byte_identity`.
- [ ] T013 [US1] Generate the 9 SPDX 3 goldens. `mkdir -p mikebom-cli/tests/fixtures/golden/spdx-3`. Run `MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test -p mikebom --test spdx3_regression`. Empirical leak-vector sweep: `rg '/Users/[^"]*' mikebom-cli/tests/fixtures/golden/spdx-3/` MUST return empty. Iterate normalize + regen until clean.
- [ ] T014 [US1] Run `cargo +stable test -p mikebom --test spdx3_regression` — expect 9/9 pass.
- [ ] T015 [US1] Verify zero-warnings for the new test code. Run `cargo +stable clippy --workspace --all-targets`. Expected: zero warnings (post-016 baseline holds). If warnings appear, fix in-place. **Depends on T002–T014.**

**Checkpoint**: After T015, the byte-identity goldens are committed and load-bearing. The test suite has 18 new green tests. `cdx_regression.rs` has been migrated to the shared helper byte-identically. The remaining work in Phase 4 is the durability sweep.

---

## Phase 4: User Story 3 — Uniform fake-HOME isolation across all acceptance tests (Priority: P3)

**Goal**: Every test that shells the binary uses `common::apply_fake_home_env`. Inline `Command::env("HOME"|"M2_REPO"|...)` calls are zero outside `tests/common/`.

**Independent Test**: After T020, `rg 'env\("HOME"' mikebom-cli/tests/ -g '!common/'` and the equivalent grep for the other 5 env vars all return empty.

**Implementation note**: T016-T019 are file-disjoint and parallel-safe within their respective test-file clusters. T020 is the verification sweep.

- [ ] T016 [P] [US3] Migrate the SPDX-determinism test cluster to `apply_fake_home_env`. Files: `mikebom-cli/tests/spdx_determinism.rs`, `mikebom-cli/tests/spdx3_determinism.rs`. Each currently inlines a 6-line env block per scan. Replace with one call to the helper. Re-run the affected targets; expect green.
- [ ] T017 [P] [US3] Migrate the SPDX-acceptance test cluster. Files: `mikebom-cli/tests/spdx_us1_acceptance.rs`, `mikebom-cli/tests/spdx3_us3_acceptance.rs`, `mikebom-cli/tests/spdx_annotation_fidelity.rs`, `mikebom-cli/tests/spdx3_annotation_fidelity.rs`, `mikebom-cli/tests/spdx_license_ref_extracted.rs`, `mikebom-cli/tests/spdx_schema_validation.rs`, `mikebom-cli/tests/spdx3_schema_validation.rs`, `mikebom-cli/tests/spdx_cdx_parity.rs`, `mikebom-cli/tests/spdx3_cdx_parity.rs`. Same pattern. Re-run affected targets.
- [ ] T018 [P] [US3] Migrate the parity / mapping / format-dispatch cluster. Files: `mikebom-cli/tests/holistic_parity.rs`, `mikebom-cli/tests/component_count_parity.rs`, `mikebom-cli/tests/cpe_v3_acceptance.rs`, `mikebom-cli/tests/format_dispatch.rs`, `mikebom-cli/tests/mapping_doc_bidirectional.rs`, `mikebom-cli/tests/openvex_sidecar.rs`, `mikebom-cli/tests/parity_cmd.rs`, `mikebom-cli/tests/sbom_format_mapping_coverage.rs`, `mikebom-cli/tests/sbomqs_parity.rs`, `mikebom-cli/tests/dual_format_perf.rs`. Same pattern.
- [ ] T019 [P] [US3] Migrate any remaining test files that shell the binary. Use `rg -l 'env\("HOME"' mikebom-cli/tests/ -g '!common/'` to enumerate stragglers; expect ~0-3 files left after T016-T018. Migrate each.
- [ ] T020 [US3] Verify FR-008 grep is clean. Run all six greps:
  ```bash
  for v in HOME M2_REPO MAVEN_HOME GOPATH GOMODCACHE CARGO_HOME; do
      rg "env\\(\"$v\"" mikebom-cli/tests/ -g '!common/'
  done
  ```
  Expected: every grep returns empty. If any returns hits, migrate them. **Depends on T016-T019.**

**Checkpoint**: After T020, fake-HOME isolation is uniformly applied. Future ecosystem-reader env-var additions get test-side isolation by editing one helper.

---

## Phase 5: Polish & Verification

**Purpose**: Final-state acceptance proof per spec SC-001 through SC-005.

- [ ] T021 Run `./scripts/pre-pr.sh` from a clean tree. Expect both clippy and tests pass with no warnings, no failures. Capture the test-name list (`grep "^test " /tmp/test-output.txt | sort > /tmp/post-017-tests.txt`) and diff against the T001 baseline. Expected: 18 added test names (`spdx_regression::*::*_byte_identity` ×9 + `spdx3_regression::*::*_byte_identity` ×9); zero removed.
- [ ] T022 SC-003 deliberate-flip probe. Pick one committed SPDX golden (e.g., `spdx-2.3/npm.spdx.json`); modify a single byte (e.g., change one character in a `name` field); run `cargo test -p mikebom --test spdx_regression npm_byte_identity`; observe failure with diff naming both files; revert the change; rerun; observe pass. Document in the PR description that this probe was performed.
- [ ] T023 Cross-host CI verification. Push the branch; observe both Linux (`lint-and-test`) and macOS (`lint-and-test-macos`) jobs pass on `gh run watch`. If macOS-pinned goldens fail on Linux (or vice versa), iterate Phase 3 leak-vector sweeps.
- [ ] T024 Author the PR description per `data-model.md` "Regen-decision record" + `quickstart.md` "Recommended commit chunking." Include: total counts (18 new test cases, 18 new goldens, ~25 files migrated to `apply_fake_home_env`), the SC-003 probe attestation, and the per-format goldens-regen rationale ("first time pinning" for SPDX 2.3 and SPDX 3).

---

## Dependency Graph

```text
T001 (snapshot)
└─ T002 (helper skeleton)
   └─ T003 (apply_fake_home_env)
      └─ T004 (normalize_cdx)
         └─ T005 (cdx_regression migration)
            └─ T006 (CDX byte-identity gate) ← Phase 2 done
               ├─ T007 (normalize_spdx23) → T008 (spdx_regression test) → T009 (regen + leak sweep) → T010 (assert path)
               └─ T011 (normalize_spdx3)  → T012 (spdx3_regression test) → T013 (regen + leak sweep) → T014 (assert path)
                  └─ T015 (clippy gate) ← Phase 3 done
                     ├─ T016 / T017 / T018 / T019 (parallel migrations)
                     │  └─ T020 (FR-008 grep gate) ← Phase 4 done
                     │     ├─ T021 (pre-PR run + diff baseline)
                     │     ├─ T022 (deliberate-flip probe)
                     │     ├─ T023 (cross-host CI)
                     │     └─ T024 (PR description) ← Phase 5 done
```

T007/T008/T009/T010 vs. T011/T012/T013/T014 are independent (parallel-safe per Phase 3 implementation note). T016-T019 are independent.

## Estimated effort

| Phase | Estimated effort | Notes |
|---|---|---|
| Phase 1 (Setup) | 15 min | Mechanical scaffolding. |
| Phase 2 (CDX migration) | 1-2 hr | The byte-identity verification (T006) is the slow gate; if it diverges, debugging adds time. |
| Phase 3 (SPDX targets + goldens) | 3-5 hr | Empirical leak-vector sweep (T009, T013) is the wildcard; if SPDX has many more leak points than CDX, expect more iteration. |
| Phase 4 (fake-HOME sweep) | 2 hr | ~25 mechanical edits + verify. |
| Phase 5 (polish + PR) | 30 min | If CI is green on first push. |
| **Total** | **6-10 hr** | One focused day or two half-days. |
