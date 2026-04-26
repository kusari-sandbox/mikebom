# Implementation Plan: binary/mod.rs Split — Design-First

**Branch**: `019-binary-split` | **Date**: 2026-04-25 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/019-binary-split/spec.md`

## Summary

Address milestone 018's deferred US3 with a design-first approach. Split `mikebom-cli/src/scan_fs/binary/mod.rs` (1858 LOC) into a 5-file directory module by extracting four cohesive concerns into siblings of the existing `elf.rs`/`linkage.rs`/etc. files: `discover.rs` (filesystem walker), `scan.rs` (single-file binary scanner), `entry.rs` (`BinaryScan` + entry conversion), `predicates.rs` (OS-aware rootfs predicates). The orchestrator `read()` and the cross-cutting `is_path_claimed` stay in `mod.rs`. Visibility ladder + cross-submodule import design happens before any code moves; commits land one submodule at a time, each leaving the tree green and the byte-identity goldens unchanged.

## Technical Context

**Language/Version**: Rust stable (workspace toolchain inherited from milestones 001-018; no nightly required for user-space scan-pipeline code).
**Primary Dependencies**: existing only — `object` (ELF/Mach-O/PE parsing), `sha2` (SHA-256 hashing), `mikebom_common::types::{hash::ContentHash, purl::Purl}`. No `Cargo.toml` changes. Per Constitution Principle VI.
**Storage**: source-tree restructure only. ~1858 LOC moves from one file into 5 files with mechanical visibility adjustments. ~150 LOC of new submodule headers (per-file doc, imports, `mod` declarations); net production-LOC change is ~+150.
**Testing**: `./scripts/pre-pr.sh` (clippy + workspace test). The 27 byte-identity goldens are the load-bearing regression test. The 1337-LOC integration test `tests/scan_binary.rs` is the second gate — every binary-format scenario it covers (ELF / Mach-O / fat-Mach-O / PE / Go / RPM-note / DEB / APK) passes through the public API unchanged.
**Target Platform**: macOS 14+ + Linux x86_64. The split is platform-neutral — no `cfg(target_os = "linux")` gates in the moved code (binary scanning is cross-platform).
**Project Type**: Source-tree refactor — no new public APIs, no new tests, no new crates, no behavioral changes.
**Performance Goals**: Compile time should not regress materially. Per-module compilation in Rust may improve parallelism within `mikebom-cli` (5 small files compile in parallel within the bin's dep graph) but this is incidental — not a stated goal.
**Constraints**:

- Zero behavioral changes to scan output. The 27 byte-identity goldens are the gate. If `MIKEBOM_UPDATE_*_GOLDENS=1` regen produces a non-empty diff at any commit, the commit is wrong.
- Zero new public APIs, zero pre-existing `pub`/`pub(crate)` items un-`pub`'d. Visibility may *expand* mechanically (a `fn` becomes `pub(super) fn` to be reachable from a sibling submodule); contraction is out of scope.
- `is_path_claimed` MUST stay reachable as `crate::scan_fs::binary::is_path_claimed` for external callers in `maven.rs`, `go_binary.rs`, `linkage.rs` — accomplished by keeping it in `mod.rs` (no re-export needed).
- `BinaryScan` (`pub(crate)` struct) keeps its visibility level. It moves to `entry.rs`; `scan.rs` accesses it via `use super::entry::BinaryScan;`. No external crate references the type today (verified by `rg`).
- Constitution Principle V (Specification Compliance) — the byte-identity goldens encode current SBOM-emission contract; splitting the production code MUST NOT change scan output.
- The milestone-018 lesson: each user-story commit is one atomic move. Don't try to incrementally extract one submodule at a time — Rust's module system breaks under partial moves (file exists in two places, name resolution conflicts).

**Scale/Scope**: 1 source file (`binary/mod.rs`) becomes 5 files (`mod.rs` + 4 siblings). 38 inline tests redistributed across the 5 files. ~1858 LOC moved; net production-code LOC unchanged. No test files renamed or added. Estimated PR diff: +1858 / -1858 with ~+150 of import/header churn.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Bearing on this feature | Pass? |
|-----------|-------------------------|-------|
| I. Pure Rust, Zero C | No deps changes; no C surface. | ✓ |
| II. eBPF-Only Observation | Untouched — no observation-semantics changes. | ✓ |
| III. Fail Closed | Untouched — no failure-mode changes in production. | ✓ |
| IV. Type-Driven Correctness | No new `.unwrap()` introduced. `.expect()` relocates verbatim with descriptive messages preserved. | ✓ |
| V. Specification Compliance | Byte-identity goldens (#38 + #40) are the regression gate. Zero scan-output drift required. | ✓ |
| VI. Three-Crate Architecture | No new crates. Workspace stays at `mikebom-cli` (lib + bin), `mikebom-common`, `mikebom-ebpf`. | ✓ |
| VII. Test Isolation | Inline `#[cfg(test)]` modules move with their owning code. `tests/scan_binary.rs` integration test unchanged. | ✓ |
| VIII–XII | Untouched. | ✓ |
| Strict Boundary 4 (`No .unwrap()` in production) | Same as IV. | ✓ |
| Pre-PR Verification | Each commit on the milestone branch passes `./scripts/pre-pr.sh` cleanly. The split is meaningless if any commit ships broken state. | ✓ |

**Initial gate**: PASS. No principle violations.

## Project Structure

### Documentation (this feature)

```text
specs/019-binary-split/
├── spec.md                  # Feature spec
├── plan.md                  # This file
├── research.md              # Phase 0 — re-export surface design, why 5 files (not 4), is_path_claimed staying in mod.rs
├── data-model.md            # Phase 1 — visibility ladder + per-item file destination + test distribution
├── quickstart.md            # Phase 1 — atomic-move recipe + per-commit verification
├── contracts/
│   └── module-boundaries.md # Per-submodule entry points + visibility contract (analogous to milestone 018's)
├── checklists/
│   └── requirements.md      # Spec quality checklist
└── tasks.md                 # Phase 2 — numbered task list
```

### Source Code (repository root)

```text
mikebom-cli/src/scan_fs/binary/
├── mod.rs                   # MODIFIED: shrunk from 1858 → ~575 LOC. Keeps: pub fn read, pub(crate) fn is_path_claimed, mod declarations, doc + imports.
├── discover.rs              # NEW: discover_binaries + walk_dir + is_supported_binary + detect_format (~85 LOC)
├── entry.rs                 # NEW: pub(crate) struct BinaryScan + version_match_to_entry + make_file_level_component + note_package_to_entry + impl PackageDbEntry (~290 LOC)
├── predicates.rs            # NEW: enum RootfsKind + detect_rootfs_kind + is_host_system_path + has_rpmdb_at + is_os_managed_directory (~150 LOC)
├── scan.rs                  # NEW: scan_binary + scan_fat_macho + collect_string_region + is_go_binary (~290 LOC)
├── elf.rs                   # UNCHANGED (existing sibling)
├── jdk_collapse.rs          # UNCHANGED
├── linkage.rs               # UNCHANGED — `crate::scan_fs::binary::is_path_claimed` reference at line 45 keeps working
├── macho.rs                 # UNCHANGED (stub)
├── packer.rs                # UNCHANGED (stub)
├── pe.rs                    # UNCHANGED (stub)
├── python_collapse.rs       # UNCHANGED
└── version_strings.rs       # UNCHANGED (stub)
```

**Structure Decision**: 5-file split (4 new siblings + 1 shrunk `mod.rs`). The new submodules join the existing siblings (which were already split per format/concern in earlier milestones); they don't replace them. `mod.rs` becomes an orchestrator + cross-cutting helpers + 8 inline tests for those helpers.

## Phase 0 — Research questions (resolved in research.md)

- **R1**: Why 5 files instead of milestone-018's planned 4? (Test-LOC budget — the OS-predicate tests are ~200 LOC and need their own submodule to land mod.rs under 800.)
- **R2**: Why `is_path_claimed` stays in `mod.rs` (not `scan.rs` per milestone-018 plan)? (External-caller path stability + read() proximity.)
- **R3**: Where does `BinaryScan` live? (entry.rs — that's where its consumers live; scan.rs imports via `super::entry::BinaryScan`.)
- **R4**: Visibility ladder for cross-sibling access. (Same rule as milestone 018: `pub(super) fn` for sibling-only callers; `pub(crate)` only for items already at that level.)
- **R5**: Atomic vs incremental commits per submodule. (Atomic per-submodule extraction — milestone 018's lesson.)
- **R6**: How to verify "no scan output drift" — same as milestone 018 (regen byte-identity goldens, expect zero diff).

## Phase 1 — Design artifacts (resolved in data-model.md, contracts/module-boundaries.md, quickstart.md)

- **Visibility ladder** — every item in `binary/mod.rs` mapped to its target submodule + post-split visibility level.
- **Cross-submodule imports** — explicit list of `use super::entry::BinaryScan;` etc. that each new submodule needs.
- **Test distribution table** — each of the 38 inline tests assigned to its owning submodule.
- **Atomic-move recipe** — quickstart.md cookbook for executing one submodule extraction without breaking compilation mid-step.

## Complexity Tracking

> No constitution violations. Complexity is in (a) the *care* needed to design the re-export surface (only 2 items: `read` and `is_path_claimed`), (b) the *count* of cross-submodule type/function references that need explicit imports (~15 sites), (c) the *iteration* per-submodule extraction needs to avoid breaking compilation mid-split. Each is mechanical-with-judgment; none is architectural.

The single judgment-heavy moment is FR-004 — verifying that scan output is byte-identical post-split. This is the same gate that caught 017's T013b emitter bug + that protected the milestone-018 splits from drift; if a split changes behavior, the goldens trip. Verification is `MIKEBOM_UPDATE_*_GOLDENS=1` regen → `git diff` empty. Per milestone-018's experience this catches misorderings, accidentally-changed iteration patterns, and any non-determinism leaking through.

## Post-implementation verification

After all 5 commits land, before opening PR:

```bash
# (a) FR-001 LOC ceiling.
test "$(wc -l < mikebom-cli/src/scan_fs/binary/mod.rs)" -le 800

# (b) FR-004 byte-identity goldens still match.
MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo +stable test -p mikebom --test cdx_regression > /dev/null
MIKEBOM_UPDATE_SPDX_GOLDENS=1 cargo +stable test -p mikebom --test spdx_regression > /dev/null
MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test -p mikebom --test spdx3_regression > /dev/null
git diff --stat mikebom-cli/tests/fixtures/golden/   # expected: empty

# (c) FR-008 / SC-004 full pre-PR.
./scripts/pre-pr.sh   # expected: clean (modulo pre-existing flakiness)

# (d) FR-005 / SC-002 test-name parity.
./scripts/pre-pr.sh 2>&1 | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/post-019-tests.txt
# expect: removed entries are renames (e.g., binary::tests::is_go_binary_* → binary::scan::tests::is_go_binary_*)
# zero entries removed without a corresponding rename
```
