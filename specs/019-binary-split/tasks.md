---
description: "Task list — binary/mod.rs split (milestone 019)"
---

# Tasks: binary/mod.rs Split — Design-First

**Input**: Design documents from `/specs/019-binary-split/`
**Prerequisites**: spec.md (✅), plan.md (✅), research.md (✅), data-model.md (✅), contracts/module-boundaries.md (✅), quickstart.md (✅)

**Tests**: No new automated tests. The 27 byte-identity goldens (#38 + #40) and the 1337-LOC `tests/scan_binary.rs` integration test are the regression surface.

**Organization**: Single user story (US1). Five extraction commits in dependency order.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel — N/A here, extractions are dependency-ordered.
- **[Story]**: All maps to US1.

## Path Conventions

Source-tree refactor only. Touches `mikebom-cli/src/scan_fs/binary/{mod,discover,entry,predicates,scan}.rs`. No `Cargo.toml`, no test files, no other modules.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Snapshot the post-#43 baseline so SC-002 can verify zero test-name regression.

- [ ] T001 Snapshot baseline: `./scripts/pre-pr.sh 2>&1 | tee /tmp/baseline-019.txt | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/baseline-019-tests.txt`. Confirm the post-#43 test-name list. Output is local-only — not committed.
- [ ] T002 Verify baseline LOC: `wc -l mikebom-cli/src/scan_fs/binary/mod.rs`. Expected: 1858. If drifted, update FR-001 budget accordingly.

---

## Phase 2: Extract `predicates.rs` (Priority: P1) 🎯 First extraction

**Goal**: Move `RootfsKind`, `detect_rootfs_kind`, `is_host_system_path`, `has_rpmdb_at`, `is_os_managed_directory` and their 14 inline tests from `binary/mod.rs` into a new sibling `binary/predicates.rs`.

**Independent Test**: After T006, `mikebom-cli/src/scan_fs/binary/predicates.rs` exists with the 5 production fns + 14 tests; `mod.rs` shrinks by ~350 LOC; `./scripts/pre-pr.sh` passes; goldens unchanged.

- [ ] T003 [US1] Plan the move using `data-model.md` "Items landing in binary/predicates.rs" table.
- [ ] T004 [US1] Construct `binary/predicates.rs`. Header: `//!` doc + `use std::path::Path;`. Body: 5 functions with `pub(super)` visibility (per visibility ladder); enum `RootfsKind` becomes `pub(super)`. Tests block follows same `#[cfg(test)] #[cfg_attr(test, allow(clippy::unwrap_used))] mod tests { use super::*; ... }` pattern as milestone-018 splits.
- [ ] T005 [US1] Update `binary/mod.rs`: remove the moved code; add `mod predicates;` declaration; qualify all call sites in `read()` (e.g., `detect_rootfs_kind(...)` → `predicates::detect_rootfs_kind(...)`). Same atomic-edit discipline as milestone 018 — one commit, no piecemeal moves.
- [ ] T006 [US1] Verify byte-identity. `cargo +stable check --workspace --tests` passes; the three goldens regen (`MIKEBOM_UPDATE_*_GOLDENS=1`) produces empty `git diff`. Run `./scripts/pre-pr.sh` — clean.
- [ ] T007 [US1] Commit: `refactor(019/extract-predicates): move RootfsKind + OS predicates from binary/mod.rs to predicates.rs`.

---

## Phase 3: Extract `discover.rs`

**Goal**: Move `discover_binaries`, `walk_dir`, `is_supported_binary`, `detect_format` from `binary/mod.rs` into `binary/discover.rs`.

**Independent Test**: After T011, `mikebom-cli/src/scan_fs/binary/discover.rs` exists; `mod.rs` shrinks by ~85 LOC; pre-PR clean; goldens unchanged.

- [ ] T008 [US1] Plan the move using `data-model.md` "Items landing in binary/discover.rs" table.
- [ ] T009 [US1] Construct `binary/discover.rs`. Header: `//!` doc + `use std::path::{Path, PathBuf};`. Body: 4 functions; `discover_binaries` is `pub(super) fn`; `walk_dir` and `is_supported_binary` stay private; `detect_format` keeps `pub(crate)` (per FR-006 strict reading).
- [ ] T010 [US1] Update `binary/mod.rs`: remove moved code; add `mod discover;` declaration; qualify call sites in `read()` (`discover_binaries(...)` → `discover::discover_binaries(...)`).
- [ ] T011 [US1] Verify byte-identity (same pattern as T006). Run `./scripts/pre-pr.sh`.
- [ ] T012 [US1] Commit: `refactor(019/extract-discover): move filesystem walker from binary/mod.rs to discover.rs`.

---

## Phase 4: Extract `entry.rs`

**Goal**: Move `BinaryScan` struct + `version_match_to_entry`, `make_file_level_component`, `note_package_to_entry`, `impl PackageDbEntry` + 12 tests from `binary/mod.rs` into `binary/entry.rs`. **Critical**: must come before scan.rs extraction because scan.rs depends on `BinaryScan` from entry.rs.

**Independent Test**: After T016, `mikebom-cli/src/scan_fs/binary/entry.rs` exists; `mod.rs` shrinks by ~490 LOC; pre-PR clean; goldens unchanged.

- [ ] T013 [US1] Plan the move using `data-model.md` "Items landing in binary/entry.rs" table.
- [ ] T014 [US1] Construct `binary/entry.rs`. Header: `//!` doc + imports per `data-model.md` "Cross-submodule import inventory" entry.rs section. Body: `pub(crate) struct BinaryScan` + 3 conversion fns (`pub(super)`) + `impl PackageDbEntry` + 12 tests + `fake_binary_scan` helper.
- [ ] T015 [US1] Update `binary/mod.rs`: remove moved code; add `mod entry;` declaration; qualify call sites in `read()` (`version_match_to_entry(...)` → `entry::version_match_to_entry(...)`, etc.). `mod.rs` may still need `use entry::BinaryScan;` if any test in mod.rs references it (verify during this step).
- [ ] T016 [US1] Verify byte-identity. Pre-PR clean.
- [ ] T017 [US1] Commit: `refactor(019/extract-entry): move BinaryScan + entry conversion from binary/mod.rs to entry.rs`.

---

## Phase 5: Extract `scan.rs`

**Goal**: Move `scan_binary`, `scan_fat_macho`, `collect_string_region`, `is_go_binary` + 4 tests from `binary/mod.rs` into `binary/scan.rs`. **Depends on entry.rs already existing** so scan.rs can `use super::entry::BinaryScan`.

**Independent Test**: After T021, `mikebom-cli/src/scan_fs/binary/scan.rs` exists; `mod.rs` ≤ 800 LOC (FR-001 met); pre-PR clean; goldens unchanged.

- [ ] T018 [US1] Plan the move using `data-model.md` "Items landing in binary/scan.rs" table.
- [ ] T019 [US1] Construct `binary/scan.rs`. Header: `//!` doc + imports per `data-model.md` scan.rs section, including `use super::entry::BinaryScan;` and the existing-sibling refs `use super::{elf, packer, version_strings};`. Body: 4 functions; `scan_binary` is `pub(super) fn`; others stay private; 4 tests + helper.
- [ ] T020 [US1] Update `binary/mod.rs`: remove moved code; add `mod scan;` declaration; qualify call sites in `read()` (`scan_binary(...)` → `scan::scan_binary(...)`).
- [ ] T021 [US1] Verify byte-identity + LOC ceiling: `wc -l mikebom-cli/src/scan_fs/binary/mod.rs` ≤ 800. Pre-PR clean.
- [ ] T022 [US1] Commit: `refactor(019/extract-scan): move single-file binary scanner from binary/mod.rs to scan.rs — completes the split`.

---

## Phase 6: Polish & Verification

**Purpose**: Final-state acceptance proof per spec SC-001 through SC-006.

- [ ] T023 Run `./scripts/pre-pr.sh` from a clean tree. Capture post-019 test-name list. Diff against /tmp/baseline-019-tests.txt — expected: zero removed-without-rename. Renamed entries (e.g., `binary::tests::is_go_binary_*` → `binary::scan::tests::is_go_binary_*`) are normal.
- [ ] T024 SC-005 verification: `git diff main..019-binary-split -- mikebom-cli/src/scan_fs/mod.rs mikebom-cli/src/scan_fs/package_db/maven.rs mikebom-cli/src/scan_fs/package_db/go_binary.rs mikebom-cli/src/scan_fs/binary/linkage.rs` — expected: empty.
- [ ] T025 Cross-host CI verification. Push the branch; observe both Linux and macOS CI legs pass. The 27 byte-identity goldens are the cross-host canary, same as milestones 017 and 018.
- [ ] T026 Author the PR description. Per-commit summary table (5 extraction commits), per-submodule LOC inventory, byte-identity attestation, test-name diff attestation. PR title: `refactor(019): binary/mod.rs split — design-first, 5 files`.

---

## Dependency Graph

```text
T001 (snapshot baseline)
└─ T002 (verify pre-split LOC) ← Phase 1 done
   ├─ T003 (predicates plan) → T004 (predicates construct) → T005 (mod.rs update) → T006 (verify) → T007 (commit) ← Phase 2 done
   │
   ├─ T008 (discover plan) → T009 → T010 → T011 → T012 ← Phase 3 done
   │
   ├─ T013 (entry plan) → T014 → T015 → T016 → T017 ← Phase 4 done    ← MUST come before Phase 5
   │
   └─ T018 (scan plan) → T019 → T020 → T021 → T022 ← Phase 5 done     ← scan.rs imports BinaryScan from entry.rs
      └─ T023 (post-019 pre-PR + diff)
         ├─ T024 (SC-005 external-callers verify)
         ├─ T025 (cross-host CI)
         └─ T026 (PR description) ← Phase 6 done
```

Phases 2 and 3 are independent of each other (predicates ⊥ discover). Phase 4 must precede Phase 5 (entry must exist before scan imports BinaryScan from it). Recommended order: 2 → 3 → 4 → 5 (but 2 and 3 could swap without consequence).

## Estimated effort

| Phase | Estimated effort | Notes |
|---|---|---|
| Phase 1 (setup) | 10 min | Mechanical baseline snapshot. |
| Phase 2 (predicates) | 1-2 hr | First extraction; the visibility-ladder pattern is established here. |
| Phase 3 (discover) | 30-45 min | Smaller and self-contained. |
| Phase 4 (entry) | 2-3 hr | Largest extraction; the BinaryScan-relocation is the careful step. |
| Phase 5 (scan) | 2 hr | Cross-sibling import to entry.rs is the new wrinkle. |
| Phase 6 (polish + PR) | 30 min | If CI is green on first push. |
| **Total** | **6-8 hr** | One focused day. |

If goldens trip at any T006 / T011 / T016 / T021 verification, add 1-2 hr per ecosystem to diff the moved code against pre-split byte-for-byte and find the unintended reorder/edit.
