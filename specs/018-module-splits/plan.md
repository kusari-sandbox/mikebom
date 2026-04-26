# Implementation Plan: Module Splits — pip.rs, npm.rs, binary/mod.rs

**Branch**: `018-module-splits` | **Date**: 2026-04-25 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/018-module-splits/spec.md`

## Summary

Split three oversized scan-pipeline files into per-concern submodules without changing any production behavior. Three deliverables, ordered by independence + risk: (1) `pip.rs` (1965 LOC) → `pip/{mod,dist_info,poetry,pipfile,requirements_txt}.rs`; (2) `npm.rs` (1616 LOC) → `npm/{mod,package_lock,pnpm_lock,walk,enrich}.rs`; (3) `binary/mod.rs` (1858 LOC) → `binary/{mod,discover,scan,entry}.rs` (joining the existing siblings `linkage.rs`, `elf.rs`, `go_binary.rs`, `python_collapse.rs`). Each split is mechanical code-relocation with cross-submodule visibility adjustments (`fn` → `pub(super) fn`); zero parser-logic changes. The 27 byte-identity goldens shipped in #38 + #40 are the regression test — any change in committed scan output trips them.

## Technical Context

**Language/Version**: Rust stable (workspace toolchain inherited from milestones 001-017; no nightly required for user-space scan-pipeline code).
**Primary Dependencies**: existing only. No `Cargo.toml` changes for `mikebom-cli`. No new crates. Per Constitution Principle VI.
**Storage**: source-tree restructure only. ~5400 LOC moves from three single-file modules into directory-based modules; no net LOC change (other than minor whitespace adjustments around the new `mod foo;` declarations).
**Testing**: `./scripts/pre-pr.sh` (clippy + workspace test). The 27 byte-identity goldens (`tests/fixtures/golden/{cyclonedx,spdx-2.3,spdx-3}/`) are the load-bearing regression test — any drift in committed scan output trips them.
**Target Platform**: macOS 14+ + Linux x86_64. Both legs of CI verify the split. `binary/mod.rs` has minor `cfg(target_os = "linux")` content for the rootfs-kind detection that descends into `/proc`-shaped paths; cfg gates move with the code.
**Project Type**: Source-tree refactor — no new public APIs, no new tests, no new crates, no behavioral changes.
**Performance Goals**: Compilation time should not regress materially. Rust compiles per-crate, so per-module restructuring within `mikebom-cli` produces the same net codegen. Some parallelism may improve (smaller files compile in parallel within the crate's dep graph), but this is incidental — not a stated goal.
**Constraints**:

- Zero behavioral changes to scan output. The 27 byte-identity goldens are the gate. If `MIKEBOM_UPDATE_*_GOLDENS=1` regen produces a non-empty diff at any commit, the commit is wrong.
- Zero new public APIs, zero pre-existing `pub` items un-`pub`'d. Visibility may *expand* mechanically (a `fn` becomes `pub(super) fn` to be reachable from a sibling submodule); contraction is out of scope.
- Constitution Principle IV (no `.unwrap()` in production) — the split MUST NOT introduce new `.unwrap()` calls. `.expect()` calls relocate verbatim with their owning code.
- Constitution Principle V (Specification Compliance) — the byte-identity goldens encode current SBOM-emission contract; splitting the scan-pipeline production code MUST NOT change what gets emitted. Bug discovery during the split is highly unlikely (we're moving code, not changing it) but if it surfaces, the fix follows the same in-PR-bundling pattern as 017's T013b.
- `#[cfg(test)]` modules: tests that test a submodule's private items move with that submodule; tests that test cross-cutting orchestrator behavior stay at `mod.rs`. Test names preserved verbatim.

**Scale/Scope**: 3 source files become 3 directories (~13-15 source files post-split). No test files renamed or added. ~5400 LOC moved; no net diff in production-code LOC. Estimated PR size: +5400 / -5400 (almost entirely code moves), readable per-commit because each commit is one directory split.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Bearing on this feature | Pass? |
|-----------|-------------------------|-------|
| I. Pure Rust, Zero C | No deps changes; no C surface. | ✓ |
| II. eBPF-Only Observation | Untouched — no observation-semantics changes. | ✓ |
| III. Fail Closed | Untouched — no failure-mode changes in production. | ✓ |
| IV. Type-Driven Correctness | No new `.unwrap()` introduced. `.expect()` relocates verbatim with descriptive messages preserved. | ✓ |
| V. Specification Compliance | Byte-identity goldens (#38 + #40) are the regression gate. Zero scan-output drift is required and verified. | ✓ |
| VI. Three-Crate Architecture | No new crates. Workspace stays at `mikebom-cli` (lib + bin), `mikebom-common`, `mikebom-ebpf`. | ✓ |
| VII. Test Isolation | Inline `#[cfg(test)]` modules move with their owning code. Integration tests under `tests/` unchanged. | ✓ |
| VIII–XII (Completeness, Accuracy, Transparency, Enrichment, External Sources) | Untouched. | ✓ |
| Strict Boundary 4 (`No .unwrap()` in production) | Same as IV. | ✓ |
| Pre-PR Verification | Each commit on the milestone branch passes `./scripts/pre-pr.sh` cleanly. The split is meaningless if any commit ships broken state. | ✓ |

**Initial gate**: PASS. No principle violations; the milestone strengthens VII (smaller modules → easier per-submodule `#[cfg(test)]` test placement).

## Project Structure

### Documentation (this feature)

```text
specs/018-module-splits/
├── spec.md                  # Feature spec (already written)
├── plan.md                  # This file
├── research.md              # Phase 0 — submodule split shapes, name conventions, cross-submodule visibility strategy, maven exclusion rationale
├── data-model.md            # Phase 1 — minimal: which items are pub vs pub(super) vs private
├── quickstart.md            # Phase 1 — how a contributor verifies a split locally + on CI; commit-by-commit checklist
├── contracts/
│   └── module-boundaries.md # Per-submodule entry points + visibility contract
├── checklists/
│   └── requirements.md      # Spec quality checklist
└── tasks.md                 # Phase 2 — numbered task list
```

### Source Code (repository root)

```text
mikebom-cli/src/scan_fs/package_db/
├── pip/                     # NEW: directory replacing pip.rs (1965 LOC → ~5 files)
│   ├── mod.rs               # NEW: pub fn read + pub fn collect_claimed_paths + PURL helpers + project-root walker (~600 LOC)
│   ├── dist_info.rs         # NEW: PEP 376 venv walker + PipDistInfoEntry (~370 LOC, was lines 325-694)
│   ├── poetry.rs            # NEW: poetry.lock parser + helpers (~140 LOC, was 697-833)
│   ├── pipfile.rs           # NEW: Pipfile.lock parser (~95 LOC, was 834-925)
│   └── requirements_txt.rs  # NEW: requirements.txt parser + RequirementsTxtEntry (~1040 LOC, was 927-end)
│
├── npm/                     # NEW: directory replacing npm.rs (1616 LOC → ~5 files)
│   ├── mod.rs               # NEW: pub fn read + NpmError + integrity + base64 helper + dispatch (~400 LOC)
│   ├── package_lock.rs      # NEW: package-lock.json v2/v3 parser (~140 LOC, was 311-447)
│   ├── pnpm_lock.rs         # NEW: pnpm-lock.yaml parser (~140 LOC, was 491-628)
│   ├── walk.rs              # NEW: node_modules flat walker + classifier (~250 LOC, was 630-787 + 939-end)
│   └── enrich.rs            # NEW: author backfill (~80 LOC, was 789-863)
│
└── maven.rs                 # UNCHANGED (5702 LOC) — explicitly out of scope per spec clarification

mikebom-cli/src/scan_fs/binary/
├── mod.rs                   # MODIFIED: pub fn read + RootfsKind + cross-cutting predicates only (~700 LOC, was 1858)
├── discover.rs              # NEW: discover_binaries + walk_dir + is_supported_binary (~80 LOC, was 861-939)
├── scan.rs                  # NEW: scan_binary + scan_fat_macho + collect_string_region (~220 LOC, was 641-859)
├── entry.rs                 # NEW: version_match_to_entry + make_file_level_component + note_package_to_entry (~200 LOC, was 583-639 + 940-end)
├── linkage.rs               # UNCHANGED (existing sibling)
├── elf.rs                   # UNCHANGED (existing sibling)
├── go_binary.rs             # UNCHANGED (existing sibling)
└── python_collapse.rs       # UNCHANGED (existing sibling)
```

**Structure Decision**: Three independent directory-modules. Each user story produces one new directory. The split is purely organizational; no helpers or types relocate cross-module (e.g., a `pip/` helper doesn't move into `npm/`). Per-submodule visibility uses `pub(super)` for cross-sibling access within the directory module; types/functions previously `pub` (visible outside the file) become re-exported from `mod.rs`.

## Phase 0 — Research questions (resolved in research.md)

- **R1**: How to handle inline `#[cfg(test)]` test modules during the split? Move with the production code? Keep at orchestrator?
- **R2**: Naming convention for new submodules. `poetry.rs` vs `poetry_lock.rs`? `requirements_txt.rs` vs `requirements.rs`? Match parser-format vs file-format?
- **R3**: Visibility ladder. When a previously-private `fn` needs to be reachable from a sibling submodule, is `pub(super)` the right choice or should it stay `pub(crate)`?
- **R4**: Cross-submodule helpers. Where do `should_skip_*_descent`, `merge_without_override`, etc. land? In `mod.rs` (orchestrator-side)? In a `walker.rs` submodule?
- **R5**: Per-commit chunking strategy. One commit per user story? Sub-commits per submodule extraction? Trade-off between reviewability and atomicity.
- **R6**: Why is maven.rs excluded? Document the rationale empirically (point at maven's specific seam-tangling features) so a future contributor doesn't pick it up without thinking.

## Phase 1 — Design artifacts (resolved in data-model.md, contracts/module-boundaries.md, quickstart.md)

- **Module boundary contract** — for each new submodule, what items are `pub` (re-exported from `mod.rs`), what are `pub(super)` (visible to siblings within the directory), what stay `fn`/`struct` (private to the submodule).
- **Quickstart workflow** — per-split: cut the production code, drop in a thin `mod.rs`, declare `mod foo;` lines, fix visibility, run `cargo +stable check`, run the byte-identity regen, verify zero diff.
- **Visibility decisions table** — every item that needs visibility expansion gets a row in data-model.md so a code reviewer can verify "this `fn` became `pub(super)` because it's called from sibling X."

## Complexity Tracking

> No constitution violations to justify. Complexity is in (a) the *count* of items that need visibility-ladder adjustment (~30 items across the three splits), (b) the *care* needed to preserve byte-identity goldens (verified by regen producing zero diff), and (c) the *iteration* per-submodule extraction needs to avoid breaking compilation mid-split. Each is mechanical with judgment; none is architectural.

The single judgment-heavy moment per split is FR-005 — verifying that scan output is byte-identical post-split. This is the same gate that caught 017's T013b emitter bug; if a split changes behavior, the goldens trip. The verification is `MIKEBOM_UPDATE_*_GOLDENS=1` regen → `git diff` empty.

For maven.rs, the explicit-out-of-scope decision (per spec clarification) is documented in research.md R6 with the underlying rationale: maven's parsers share state through tightly-coupled mutable orchestrators (the property-interpolation engine threads through every parser call site), unlike pip/npm where each parser is a pure function from input → entries.
