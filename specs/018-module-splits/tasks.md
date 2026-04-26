---
description: "Task list — Module splits for pip.rs, npm.rs, binary/mod.rs (milestone 018)"
---

# Tasks: Module Splits — pip.rs, npm.rs, binary/mod.rs

**Input**: Design documents from `/specs/018-module-splits/`
**Prerequisites**: spec.md (✅), plan.md (✅), research.md (✅), data-model.md (✅), contracts/module-boundaries.md (✅), quickstart.md (✅)

**Tests**: No new automated tests added — milestone 018 is a source-tree refactor with zero behavioral changes. The 27 byte-identity goldens (#38 + #40) are the load-bearing regression test; existing per-test-target counts and inline `#[cfg(test)]` test names must remain stable per FR-006 + SC-004.

**Organization**: One user story per directory split.

- **US1 (P1, MVP)**: `pip.rs` → `pip/` (largest single split; validates the milestone's general approach).
- **US2 (P2)**: `npm.rs` → `npm/` (smaller and simpler; no shared-state-merge dance).
- **US3 (P3)**: `binary/mod.rs` shrinks; new siblings `discover.rs`, `scan.rs`, `entry.rs`. Slightly more entangled than pip/npm.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel — independent of other in-flight tasks.
- **[Story]**: Maps to spec.md user story.

## Path Conventions

Source-tree refactor only. Touches `mikebom-cli/src/scan_fs/package_db/{pip,npm}.rs` (deleted) → directories, and `mikebom-cli/src/scan_fs/binary/mod.rs` (shrunk) + new siblings. No `Cargo.toml`, no test files, no `mikebom-common/`, no `mikebom-ebpf/` changes.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Snapshot the post-#41 baseline so FR-006 / SC-004 can verify zero test-name regression.

- [ ] T001 Snapshot baseline: `./scripts/pre-pr.sh 2>&1 | tee /tmp/baseline-018.txt | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/baseline-018-tests.txt`. Capture the post-#41 test-name list. Output is local-only — not committed. Used at T015 for SC-004 diff.
- [ ] T002 Verify baseline LOCs: `for f in mikebom-cli/src/scan_fs/package_db/pip.rs mikebom-cli/src/scan_fs/package_db/npm.rs mikebom-cli/src/scan_fs/binary/mod.rs; do wc -l "$f"; done`. Expected: 1965, 1616, 1858. If any has drifted from the spec's stated values, update FR-010's targets accordingly OR re-baseline (but expected to match — confirmed during 2026-04-25 reconnaissance).

---

## Phase 2: User Story 1 — pip.rs split (Priority: P1) 🎯 MVP

**Goal**: `pip.rs` (1965 LOC) replaced by `pip/` directory containing `mod.rs`, `dist_info.rs`, `poetry.rs`, `pipfile.rs`, `requirements_txt.rs`. Public surface unchanged. Byte-identity goldens unchanged.

**Independent Test**: After T006, `mikebom-cli/src/scan_fs/package_db/pip.rs` does not exist; `mikebom-cli/src/scan_fs/package_db/pip/{mod,dist_info,poetry,pipfile,requirements_txt}.rs` all exist with non-trivial content. `./scripts/pre-pr.sh` passes clean. `MIKEBOM_UPDATE_*_GOLDENS=1` regen produces zero `git diff`.

**Implementation note**: Per quickstart.md, execute T003-T005 as one atomic edit, not piecemeal. Rust's module system requires `pip.rs` OR `pip/` — not both — so intermediate states are broken.

- [ ] T003 [US1] Plan the move on paper using `data-model.md` "Visibility ladder — pip.rs split" as the canonical reference. Map every existing top-level item in `pip.rs` (per the structural-seams output captured during reconnaissance) to its target submodule + visibility level. Sanity-check by counting LOC: pre-split (1965) ≈ post-split (`mod.rs` ~600 + `dist_info.rs` ~370 + `poetry.rs` ~140 + `pipfile.rs` ~95 + `requirements_txt.rs` ~1040 = ~2245; net +280 LOC for the new `mod foo;` declarations + `pub use` re-exports + per-submodule `use` lines + per-submodule `#[cfg(test)] mod tests` boilerplate — acceptable).
- [ ] T004 [US1] Execute the move. Create `mikebom-cli/src/scan_fs/package_db/pip/` directory. Move code blocks from `pip.rs` into the appropriate submodule files per T003's plan. Adjust `pub`/`pub(super)`/private visibility per data-model.md table. `pip/mod.rs` must declare `mod dist_info; mod poetry; mod pipfile; mod requirements_txt;` and `use` the submodules' `pub(super)` items. Re-export pre-existing `pub` items via `pub use submodule::Item;` so external callers don't break. Delete `pip.rs`.
- [ ] T005 [US1] Compile + visibility-iterate. Run `cargo +stable check --workspace --tests`. Expect compile errors about "private function" / "function is private" / "cannot find function in module" — adjust visibility per the data-model.md table OR move the item to `pip/mod.rs` if it's used by ≥ 2 siblings. Iterate until `cargo check` passes.
- [ ] T006 [US1] Verify byte-identity. Run all three regen commands: `MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo +stable test -p mikebom --test cdx_regression`, `MIKEBOM_UPDATE_SPDX_GOLDENS=1 cargo +stable test -p mikebom --test spdx_regression`, `MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test -p mikebom --test spdx3_regression`. Then `git diff --stat mikebom-cli/tests/fixtures/golden/`. **Expected: empty.** If non-empty, the split changed scan output — diff the moved code against pre-split byte-for-byte to find the unintended reorder/edit. Reconcile before proceeding.
- [ ] T007 [US1] Run full pre-PR. `./scripts/pre-pr.sh` exits 0; capture per-target test result lines. SC-004 spot-check: pip-related test names (`parse_requirements_line_*`, `parse_hash_*`, `egg_fragment_*`, etc.) appear in the post-T007 output identically to baseline-018-tests.txt.
- [ ] T008 [US1] Commit per FR-009: `git add mikebom-cli/src/scan_fs/package_db/pip/ mikebom-cli/src/scan_fs/package_db/pip.rs && git commit -m "refactor(018/US1): split pip.rs into pip/ submodule"`. Commit message includes a per-submodule LOC table for reviewer context.

**Checkpoint**: After T008, `pip.rs` is gone; the pip module is a directory with 5 submodules. Phase 3 can start.

---

## Phase 3: User Story 2 — npm.rs split (Priority: P2)

**Goal**: `npm.rs` (1616 LOC) replaced by `npm/` directory containing `mod.rs`, `package_lock.rs`, `pnpm_lock.rs`, `walk.rs`, `enrich.rs`. Public surface unchanged. Byte-identity goldens unchanged.

**Independent Test**: Same shape as US1, applied to npm.

- [ ] T009 [US2] Plan the move per `data-model.md` "Visibility ladder — npm.rs split". Same atomicity discipline as T003.
- [ ] T010 [US2] Execute the move. Same atomic-edit approach as T004. Delete `npm.rs`; create `npm/{mod,package_lock,pnpm_lock,walk,enrich}.rs` with the appropriate code blocks.
- [ ] T011 [US2] Compile + visibility-iterate (same as T005).
- [ ] T012 [US2] Verify byte-identity (same as T006). The npm-relevant goldens (`golden/cyclonedx/npm.cdx.json`, `golden/spdx-2.3/npm.spdx.json`, `golden/spdx-3/npm.spdx3.json`) are the most direct check; the other 24 goldens should also remain unchanged because the split doesn't touch any non-npm code path.
- [ ] T013 [US2] Run full pre-PR + SC-004 spot-check on npm-related test names (`derive_name_from_path_key_*`, `parse_pnpm_key_*`, `classify_npm_source_*`, integrity tests).
- [ ] T014 [US2] Commit: `refactor(018/US2): split npm.rs into npm/ submodule`.

**Checkpoint**: After T014, both pip and npm are directory modules.

---

## Phase 4: User Story 3 — binary/mod.rs split (Priority: P3)

**Goal**: `binary/mod.rs` shrunk from 1858 → ≤ 800 LOC. New siblings `discover.rs`, `scan.rs`, `entry.rs`. Existing siblings (`linkage.rs`, `elf.rs`, `go_binary.rs`, `python_collapse.rs`) unchanged.

**Independent Test**: Same shape; the `tests/scan_binary.rs` integration test (1337 LOC, 30+ scenarios) is the most stringent check.

- [ ] T015 [US3] Plan the move per `data-model.md` "Visibility ladder — binary/mod.rs split". Note: `binary/` already has siblings — the new `discover.rs`/`scan.rs`/`entry.rs` join them, not replace them. `binary/mod.rs` continues to declare existing `mod linkage; mod elf; mod go_binary; mod python_collapse;` PLUS new `mod discover; mod scan; mod entry;`.
- [ ] T016 [US3] Execute the move. Cut `discover_binaries` + `walk_dir` + `is_supported_binary` from `mod.rs` → `discover.rs`. Cut `scan_binary` + `scan_fat_macho` + `collect_string_region` + `is_go_binary` → `scan.rs`. Cut `version_match_to_entry` + `make_file_level_component` + `note_package_to_entry` + the `impl PackageDbEntry` block → `entry.rs`. Keep `read()`, `RootfsKind`, `detect_rootfs_kind`, `is_host_system_path`, `has_rpmdb_at`, `is_os_managed_directory` in `mod.rs`.
- [ ] T017 [US3] Compile + visibility-iterate (same as T005, T011).
- [ ] T018 [US3] Verify byte-identity. The binary-relevant goldens are different per ecosystem — many ecosystems include scan-from-binary results. All 27 goldens must remain unchanged.
- [ ] T019 [US3] Run full pre-PR. `tests/scan_binary.rs`'s 30+ scenarios are the most direct binary-coverage check; all must pass identically to baseline.
- [ ] T020 [US3] Verify FR-010 LOC ceiling. `wc -l mikebom-cli/src/scan_fs/binary/mod.rs` ≤ 800. If `mod.rs` is still > 800, examine which functions remain and consider whether another extraction is needed (e.g., the OS-managed-directory predicates → `binary/predicates.rs`).
- [ ] T021 [US3] Commit: `refactor(018/US3): split binary/mod.rs into discover.rs / scan.rs / entry.rs`.

**Checkpoint**: After T021, all three splits are done. Phase 5 wraps up.

---

## Phase 5: Polish & Verification

**Purpose**: Final-state acceptance proof per spec SC-001 through SC-006.

- [ ] T022 Run `./scripts/pre-pr.sh` from clean tree. Expect both clippy and tests pass with zero warnings, zero failures. Capture the post-018 test-name list (`grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/post-018-tests.txt`).
- [ ] T023 SC-004 verification: `comm -23 /tmp/baseline-018-tests.txt /tmp/post-018-tests.txt` → expect empty (no removed names). `comm -13 /tmp/baseline-018-tests.txt /tmp/post-018-tests.txt` → expect empty OR a few added names if a test was renamed during the move (PR description must list each renamed name + reason).
- [ ] T024 SC-001 LOC ceilings: per the quickstart.md "Final-state verification" block (a). All checks must pass — no FAIL output.
- [ ] T025 SC-003 zero-diff goldens: regen all three formats, `git diff --stat mikebom-cli/tests/fixtures/golden/` empty.
- [ ] T026 Cross-host CI verification. Push the branch; observe both Linux (`lint-and-test`) and macOS (`lint-and-test-macos`) jobs pass on `gh run watch`. The 27 byte-identity goldens are the cross-host canary, same as 017.
- [ ] T027 Author the PR description. Per-commit summary table (3 commits, one per user story). Per-submodule LOC inventory. SC-003 attestation (regen → empty). SC-004 attestation (test-name parity). PR title: `refactor(018): module splits — pip / npm / binary`.

---

## Dependency Graph

```text
T001 (snapshot baseline)
└─ T002 (verify pre-split LOCs) ← Phase 1 done
   ├─ T003 (US1 plan) → T004 (US1 execute) → T005 (US1 compile) → T006 (US1 byte-identity) → T007 (US1 pre-PR) → T008 (US1 commit) ← Phase 2 done
   │
   ├─ T009 (US2 plan) → T010 → T011 → T012 → T013 → T014 ← Phase 3 done
   │
   └─ T015 (US3 plan) → T016 → T017 → T018 → T019 → T020 → T021 ← Phase 4 done
      └─ T022 (post-018 pre-PR)
         ├─ T023 (SC-004 verify)
         ├─ T024 (SC-001 LOC verify)
         ├─ T025 (SC-003 byte-identity verify)
         ├─ T026 (cross-host CI)
         └─ T027 (PR description) ← Phase 5 done
```

US1 / US2 / US3 are sequentially executed because each requires a clean compile state before moving on, but they are *independent* in scope — failure of one doesn't invalidate the others. The order (pip → npm → binary) is recommended for risk-management (pip's split validates the general pattern before binary's slightly-more-entangled split).

## Estimated effort

| Phase | Estimated effort | Notes |
|---|---|---|
| Phase 1 (setup) | 15 min | Mechanical baseline snapshot. |
| Phase 2 (US1 pip) | 2-3 hr | Largest split; planning + atomic move + visibility iterations + byte-identity verify. |
| Phase 3 (US2 npm) | 1-2 hr | Smaller; no shared-state-merge dance. Pattern is now familiar from US1. |
| Phase 4 (US3 binary) | 2-3 hr | Slightly more entangled; LOC ceiling check is the wildcard. |
| Phase 5 (polish + PR) | 30 min | If CI is green on first push. |
| **Total** | **6-9 hr** | One focused day or two half-days. |

If byte-identity goldens trip during T006 / T012 / T018, add 1-2 hr per ecosystem to diff the moved code against pre-split byte-for-byte and find the unintended reorder/edit.
