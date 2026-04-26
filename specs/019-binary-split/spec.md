# Feature Specification: binary/mod.rs Split — Design-First

**Feature Branch**: `019-binary-split`
**Created**: 2026-04-25
**Status**: Draft
**Input**: User audit follow-on to milestone 018; addresses the **deferred US3** from milestone 018 ("018/US3 — binary/mod.rs split"). Tier 4.5 of the post-016 cleanup roadmap.

## Background

Milestone 018 (#42) split `pip.rs` (1965 LOC) and `npm.rs` (1616 LOC) into directory submodules but **deferred** the third planned split: `binary/mod.rs` (1858 LOC). The PR description recorded the entanglement that defeated the mechanical-split approach used for pip and npm:

- `BinaryScan` and `is_path_claimed` are referenced by external callers (`linkage.rs`, `go_binary.rs`, `maven.rs`) via `crate::scan_fs::binary::*` paths — splitting requires explicit re-export design at the new `binary/mod.rs`.
- The production code is non-contiguous (file-discovery + scan-one + entry-conversion interleave with the orchestrator's `read()` loop).
- Shared imports (`super::elf`, `super::packer`, `super::version_strings`) need re-routing through every new submodule.

Milestone 018's commentary explicitly recommended a follow-up "design-first" milestone where the re-export surface and cross-submodule visibility are designed before any code moves. This is that milestone.

A new finding from reconnaissance after #43 merged: the inline `#[cfg(test)]` block in `binary/mod.rs` is ~700 LOC carrying 38 test functions. About 14 of those exercise OS-aware predicates (`RootfsKind`, `detect_rootfs_kind`, `is_host_system_path`, `has_rpmdb_at`, `is_os_managed_directory`) — a cohesive group of ~150 LOC of production code. Treating this group as a fifth submodule (`binary/predicates.rs`) is the only way to land `binary/mod.rs` under the FR-010 800-LOC ceiling without test-pruning.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — binary/mod.rs ≤ 800 LOC via 5-file split (Priority: P1) 🎯 MVP

As a maintainer adding support for a new binary format (PE, fat-Mach-O variant, future container-runtime ELF) or fixing a Mach-O fat-binary edge case, I want the file-discovery, single-file scan, and entry-conversion logic separated from the orchestrator's `read()` loop so I don't have to scroll through 1858 lines to locate the 200-line section relevant to my change.

**Why this priority**: Direct continuation of milestone 018's deferred US3. The split unblocks future `binary/*` work (PE+macho stub completion, additional binary-format readers) by making each concern independently editable.

**Independent Test**: After this story ships:

- `mikebom-cli/src/scan_fs/binary/` gains four new sibling files: `discover.rs`, `entry.rs`, `predicates.rs`, `scan.rs`. The existing siblings (`elf.rs`, `jdk_collapse.rs`, `linkage.rs`, `macho.rs`, `packer.rs`, `pe.rs`, `python_collapse.rs`, `version_strings.rs`) are unchanged.
- `mikebom-cli/src/scan_fs/binary/mod.rs` shrinks to ≤ 800 LOC (currently 1858).
- The 27 byte-identity goldens are unchanged: `MIKEBOM_UPDATE_*_GOLDENS=1` regen for CDX + SPDX 2.3 + SPDX 3 produces zero `git diff`.
- `tests/scan_binary.rs` (the integration test, 1337 LOC) passes identically — every assertion that exercises a binary code path keeps working.

**Acceptance Scenarios**:

1. **Given** the post-#43 main, **When** the binary split lands, **Then** `./scripts/pre-pr.sh` passes clean (modulo the pre-existing `dual_format_perf` / `spdx_us1_acceptance` / `spdx_determinism` flakiness pattern documented in #42 and #43).
2. **Given** the split lands, **When** a maintainer regenerates the byte-identity goldens, **Then** `git diff mikebom-cli/tests/fixtures/golden/` is empty.
3. **Given** the existing external callers (`maven.rs:2274`, `go_binary.rs:517`, `linkage.rs:45`) reference `crate::scan_fs::binary::is_path_claimed`, **When** the split lands, **Then** none of those call sites change — `is_path_claimed` remains reachable at the same path.
4. **Given** `tests/scan_binary.rs` (the integration test for binary scanning across ELF / Mach-O / fat-Mach-O / PE / Go-built-binary / RPM-note / DEB / APK / RHEL/Alpine), **When** it runs, **Then** every test passes identically — the split is purely organizational.

---

### Edge Cases

- **`is_path_claimed` stays in `binary/mod.rs`**, not in `scan.rs` (despite milestone-018's plan suggesting otherwise). Rationale: it's used by `read()` (which stays in mod.rs) AND by external callers via `crate::scan_fs::binary::is_path_claimed`. Keeping it in mod.rs avoids a re-export and keeps the canonical location matching the external-caller path. The submodule can call `super::is_path_claimed` if it ever needs to (currently it doesn't).
- **`BinaryScan` lives in `entry.rs`** because that's where the entry-conversion code that owns the type's transformation lives. `scan.rs` constructs it via `use super::entry::BinaryScan;`. The struct stays `pub(crate)` (unchanged from current visibility); no re-export needed because no external crate references it.
- **`detect_format` (line 908)** is used only by `is_supported_binary` (line 901). Both move to `discover.rs` together; neither needs `pub(super)` because their only call site is internal to `discover.rs`.
- **Sibling-module references** (`super::elf`, `super::linkage`, `super::packer`, `super::version_strings`) keep working because the new submodules are direct siblings of `elf.rs`/`linkage.rs`/etc. — `super::elf::ElfNotePackage` from `entry.rs` resolves to `binary/elf.rs`.
- **Inline test distribution**: the 38-test `#[cfg(test)] mod tests` block in mod.rs distributes by which production code each test exercises. Tests that exercise functions in mod.rs (read, is_path_claimed, claim_skip_*, inode_match_*) stay there; tests for moved code move with it.
- **`fake_binary_scan` test helper**: moves to `entry.rs::tests` because it constructs `BinaryScan` and is used by `make_file_level_component_*` tests (which also move to entry.rs).
- **`tests/scan_binary.rs`** (1337 LOC integration test) is **not touched**. It uses only the public API (`binary::read`); the split doesn't change that.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: After this milestone ships, `mikebom-cli/src/scan_fs/binary/mod.rs` MUST be ≤ 800 LOC. Verified by `wc -l`.
- **FR-002**: After this milestone ships, the `binary/` directory MUST contain at least these files: `mod.rs`, `discover.rs`, `entry.rs`, `predicates.rs`, `scan.rs`. The existing siblings (`elf.rs`, `jdk_collapse.rs`, `linkage.rs`, `macho.rs`, `packer.rs`, `pe.rs`, `python_collapse.rs`, `version_strings.rs`) MUST be unchanged.
- **FR-003**: External callers MUST NOT change. Specifically: `crate::scan_fs::binary::read(...)` and `crate::scan_fs::binary::is_path_claimed(...)` MUST resolve to the same items at the same paths. The 4 call sites in `scan_fs/mod.rs:218`, `package_db/maven.rs:2274`, `package_db/go_binary.rs:517`, `binary/linkage.rs:45` are not edited.
- **FR-004**: Zero behavioral changes. The 27 byte-identity goldens (`mikebom-cli/tests/fixtures/golden/`) MUST be byte-identical after the split. Verified by `MIKEBOM_UPDATE_*_GOLDENS=1` regen producing zero `git diff`.
- **FR-005**: All inline `#[cfg(test)]` test names from `binary/mod.rs::tests` (38 functions including the 1 helper) MUST be preserved verbatim. Tests that move into a new submodule's `#[cfg(test)] mod tests` block keep their function names. SC-002 verifies this with a sorted-name diff.
- **FR-006**: Visibility ladder per `data-model.md` "Visibility ladder" table. Pre-existing `pub` and `pub(crate)` items keep their level; cross-submodule `fn` items expand to `pub(super) fn` at minimum. **Visibility contraction is out of scope.**
- **FR-007**: `binary/mod.rs` declares `mod discover; mod entry; mod predicates; mod scan;` for the new submodules. Existing `pub mod elf;` etc. declarations are unchanged.
- **FR-008**: Each user-story commit on the milestone branch passes `./scripts/pre-pr.sh` cleanly. Reviewers can `git diff <commit>~..<commit>` and see one logical chunk at a time. Per the milestone-018 lesson, the split is one atomic commit per submodule extraction (not piecemeal moves that risk broken intermediate state).
- **FR-009**: No new runtime crates. No `Cargo.toml` changes for `mikebom-cli`. Per Constitution Principle VI.
- **FR-010**: `tests/scan_binary.rs` (1337 LOC integration test) is unchanged. The integration test exercises `binary::read` and the public binary-format coverage; it passes the split as a black-box gate.

### Key Entities *(include if feature involves data)*

This milestone has no new data — same as milestone 018, it's source-tree organization. The single relevant pre-existing type is `BinaryScan` (a struct used internally to pass scan results from `scan_binary` to `make_file_level_component`); it relocates to `entry.rs` but keeps its current `pub(crate)` visibility.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `wc -l mikebom-cli/src/scan_fs/binary/mod.rs` ≤ 800. Each new submodule (`discover.rs`, `entry.rs`, `predicates.rs`, `scan.rs`) ≤ 800 LOC. Verified by `wc -l`.
- **SC-002**: Test-name parity. After the split, sorted test-name diff against the post-#43 baseline shows: zero removed names from before-baseline; added names are renamed-only (e.g., `binary::tests::is_go_binary_*` → `binary::scan::tests::is_go_binary_*`). Same FR-007-style verification used in milestone 018.
- **SC-003**: 27 byte-identity goldens unchanged. Verified by regen + `git diff --stat mikebom-cli/tests/fixtures/golden/` returning empty.
- **SC-004**: `./scripts/pre-pr.sh` exits 0 from a clean tree on macOS and Linux (pre-existing flaky tests aside; see "Known flakiness" in the assumptions). Verified by both CI legs.
- **SC-005**: External call sites unchanged. `git diff` against `scan_fs/mod.rs`, `package_db/maven.rs`, `package_db/go_binary.rs`, `binary/linkage.rs` shows zero edits to those files (the binary split touches `binary/` only).
- **SC-006**: A maintainer chasing a Mach-O fat-binary or PE-format bug post-merge finds the relevant code in `binary/scan.rs` (single-file scanner) within **under 30 seconds** via `find` or fuzzy-search on the new file structure. Same qualitative criterion as milestone 018's SC-005.

## Clarifications

### Session 2026-04-25

- Q: Why 5 files instead of milestone-018's planned 4? → A: Reconnaissance after #43 merged showed the inline tests in `binary/mod.rs::tests` are ~700 LOC; ~14 of 38 tests test OS-aware predicates (`RootfsKind`, `has_rpmdb_at`, `is_os_managed_directory`, `is_host_system_path`) which are themselves ~150 LOC of production code. Without extracting those into `predicates.rs`, `mod.rs` lands ~1100 LOC post-split — well over the 800-LOC ceiling. The 5th submodule is necessary to meet FR-001.
- Q: Why does `is_path_claimed` stay in `mod.rs` instead of moving to `scan.rs` per milestone-018's plan? → A: It's called by `read()` (which stays in mod.rs) AND by external callers via `crate::scan_fs::binary::is_path_claimed`. Keeping it in mod.rs avoids a `pub(crate) use ...` re-export and keeps the canonical location matching where external callers already point.
- Q: Should `tests/scan_binary.rs` (1337 LOC integration test) also be split? → A: No (same answer as milestone 018 for `tests/scan_*.rs`). Integration tests are organized by feature/scenario, not by parser shape. Out of scope.

## Assumptions

- The byte-identity goldens (#38 + #40) are the load-bearing regression test for "no behavior change." If goldens trip during the split, the split is wrong and must be reconciled before commit. Same gate that caught milestone 017's T013b emitter bug.
- Milestone 018's pip + npm splits set the convention for inline `#[cfg(test)]` test distribution: tests move with the production code they exercise. We follow the same pattern; SC-002 enforces preservation.
- `tests/scan_binary.rs` (1337 LOC) exercises every binary code path through the public API. If `tests/scan_binary.rs` passes, the split's external behavior is unchanged regardless of where the moved code physically lives.
- Pre-existing flakiness in `dual_format_perf`, `spdx_us1_acceptance`, and `spdx_determinism` (documented in #42 and #43) may surface intermittently in `./scripts/pre-pr.sh` on busy dev boxes. These are concurrent-test-load issues, not regressions from this milestone — verified by running each test in isolation.
- No `Cargo.toml` changes needed. Each new submodule declares `use super::*;` patterns where helpful and explicit `use super::entry::BinaryScan;` etc. for cross-sibling types.

## Out of Scope

- `tests/scan_binary.rs` split. Per the clarification above.
- Sub-splitting any individual new submodule below the FR-001 ceiling. (Future polish if it surfaces a real readability win.)
- Refactoring the binary-scan logic itself. The split is purely "move code into siblings"; behavior unchanged.
- Renaming `pub fn read` or `pub(crate) fn is_path_claimed` or `pub(crate) struct BinaryScan`. Their existing visibility levels and names stay.
- Touching `cdx_regression.rs`, `spdx_regression.rs`, or `spdx3_regression.rs` test files. They run as-is; the goldens drive the verification.
- Completing the existing stub modules (`macho.rs`, `pe.rs`, `packer.rs`, `version_strings.rs`). They stay stubs.
- Splitting `maven.rs` (5702 LOC). Same rationale as in milestone 018: maven's sub-concerns are coupled by Maven's build model, not by accidental file growth. Separate consideration.
