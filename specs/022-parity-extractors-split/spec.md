---
description: "Split 1654-LOC parity/extractors.rs into per-format submodules (Tier 4)"
status: spec
milestone: 022
---

# Spec: parity/extractors.rs Split

## Background

`mikebom-cli/src/parity/extractors.rs` is 1654 LOC, the second-largest single file after `maven.rs` (5702) and `pip.rs` pre-018 (1965). The 2026-04-26 reconnaissance confirmed the file is **almost perfectly columnar**: 92 catalog rows × 3 format-specific extractor functions per row (CDX, SPDX 2.3, SPDX 3.0.1), wired together by a single `pub static EXTRACTORS: &[ParityExtractor]` table. Every datum (PURL, hashes, licenses, supplier, dependency edges, annotations) has three implementations side by side.

This shape is the textbook seam for a per-format split, identical to how milestone 018 split `pip.rs` along Poetry / Pipfile / venv-walker boundaries and milestone 019 split `binary/mod.rs` along discover / scan / entry / predicates cohorts.

External exposure is narrow: only 2 callers consume `parity::extractors::*`:
- `mikebom-cli/src/cli/parity_cmd.rs` (the `mikebom parity check` subcommand)
- `mikebom-cli/tests/holistic_parity.rs` (integration test)

The public surface is preserved exactly (`pub struct ParityExtractor`, `pub enum Directionality`, `pub static EXTRACTORS`, plus 4 `pub fn` walk helpers + `extract_mikebom_annotation_values`).

## User Story (US1, P2)

**As a contributor fixing a CDX-only or SPDX-only parity bug**, I want to navigate to one ~400-LOC format-specific submodule rather than scrolling a 1654-LOC file with three interleaved format implementations per datum, so that diffs and PRs reflect the actual scope of the change.

**Why P2 (not P1):** maintenance ergonomics, no behavior change, no observable user impact. Defer-able if a higher-priority item appears.

### Independent Test

After implementation:

- `mikebom-cli/src/parity/` contains `mod.rs`, `catalog.rs` (unchanged), and **four new submodules**: `extractors/cdx.rs`, `extractors/spdx2.rs`, `extractors/spdx3.rs`, `extractors/common.rs`.
- The original `extractors.rs` is replaced by `extractors/mod.rs`, holding only the `EXTRACTORS` table + module declarations + the 2 structural tests (`extractors_table_is_sorted_by_row_id`, `every_catalog_row_has_an_extractor`).
- `mod.rs` LOC ≤ 250 (sized to fit just the table + tests).
- Each per-format submodule LOC ≤ 600 (per the recon's ~400 estimate, with 50% headroom).
- `common.rs` LOC ≤ 350 (cross-sibling helpers — types, macros, annotation envelope decoder, `spdx_relationship_edges`).
- All 4 external callers untouched (`parity_cmd.rs` line 28, `holistic_parity.rs` line 22, plus any indirect uses through the public surface).
- 27 byte-identity goldens regen with zero diff.
- `cargo +stable test --workspace` passes.
- Per-commit `./scripts/pre-pr.sh` clean.

## Acceptance Scenarios

**Scenario 1: Future CDX-only parity fix**
```
Given: a contributor is fixing a CDX hash-extraction bug
When:  they grep for `cdx_hashes` to find the implementation
Then:  the only match is `mikebom-cli/src/parity/extractors/cdx.rs`,
       and the diff is bounded to one ~400-LOC file
```

**Scenario 2: Public-surface stability**
```
Given: the public re-exports from parity::extractors
When:  parity_cmd.rs and holistic_parity.rs are built post-split
Then:  no import line changes; the path
       `mikebom::parity::extractors::{ParityExtractor, Directionality, EXTRACTORS, ...}`
       still resolves identically
```

**Scenario 3: Cross-format helper does not leak**
```
Given: spdx_relationship_edges() is shared between SPDX 2.3 + SPDX 3 paths
When:  it lands in extractors/common.rs as pub(super)
Then:  spdx2.rs and spdx3.rs both `use super::common::spdx_relationship_edges;`,
       and no external caller can reach it
```

## Edge Cases

- **`spdx_relationship_edges()` placement**: 169-LOC function used by both SPDX 2.3 and SPDX 3 graph extractors. Not CDX. Three placement options considered (duplicate / put in spdx2.rs and import / new spdx_common.rs). Decision: put in `extractors/common.rs` alongside other cross-sibling helpers (`extract_spdx23_annotation_values`, `extract_spdx3_annotation_values`, `decode_envelope`, `canonicalize_atomic_values`, the two macros). The "common" module collects everything used by ≥ 2 sibling submodules — including the SPDX-specific cross-format ones. Avoids a 5-file split.
- **Macros**: `component_anno_extractors!` and `document_anno_extractors!` (lines 1187-1211) generate C-section extractors. They're format-agnostic by construction (they take a per-format function as input). Land in `common.rs`. Each per-format submodule invokes the macro to declare its C1-C20 extractors.
- **`walk_cdx_components` / `walk_spdx23_packages` / `walk_spdx3_packages`**: each is single-format. Land in their respective format submodule. Re-exported through `mod.rs::pub use` chain to preserve the existing `parity::extractors::walk_*` paths used by `holistic_parity.rs`.
- **`pub static EXTRACTORS`**: stays in `mod.rs`. The table holds 92 entries each pointing at three function pointers (one per format); rebuilding it from per-format sub-tables would be net-more-complicated. Single source of truth in mod.rs.
- **Tests**: the 2 inline tests (`extractors_table_is_sorted_by_row_id`, `every_catalog_row_has_an_extractor`) are EXTRACTORS-table-validation tests. Stay in mod.rs since the table lives there.
- **No new behavior, no new tests.**

## Functional Requirements

- **FR-001**: `mikebom-cli/src/parity/extractors.rs` (single 1654-LOC file) is replaced by `mikebom-cli/src/parity/extractors/mod.rs` (≤ 250 LOC) plus 4 sibling submodules: `cdx.rs` (≤ 600), `spdx2.rs` (≤ 600), `spdx3.rs` (≤ 600), `common.rs` (≤ 350).
- **FR-002**: Public surface is preserved exactly. From outside the `extractors` module, `mikebom::parity::extractors::{ParityExtractor, Directionality, EXTRACTORS, walk_cdx_components, walk_spdx23_packages, walk_spdx3_packages, extract_mikebom_annotation_values}` resolves identically. Verified via `git diff main..HEAD -- mikebom-cli/src/cli/parity_cmd.rs mikebom-cli/tests/holistic_parity.rs` returning empty (SC-005).
- **FR-003**: Visibility ladder applies. Items used only across siblings get `pub(super)`. Items previously `pub` (because they were re-exported through `parity::extractors::`) keep `pub` and are re-exported through `extractors/mod.rs`. No expansions or contractions of public visibility (matches research R4 from milestone 019).
- **FR-004**: Per-submodule extraction commits land in dependency order. The recon shows no inter-format dependencies (CDX functions don't call SPDX functions or vice versa), so the commits can extract in any order. Recommended: common.rs first (others import it), then cdx, spdx2, spdx3.
- **FR-005**: Each commit leaves `./scripts/pre-pr.sh` clean — same per-commit-clean discipline as 018, 019, 020, 021.
- **FR-006**: 27 byte-identity goldens regen with zero diff. Production code is split, not changed.
- **FR-007**: No mikebom production behavior change. The split is structural; no edits to extractor logic, no edits to the EXTRACTORS table contents.
- **FR-008**: External-caller files (`cli/parity_cmd.rs`, `tests/holistic_parity.rs`) are not modified. SC-005 verifies.

## Success Criteria

- **SC-001**: Per FR-001, `wc -l mikebom-cli/src/parity/extractors/{mod,cdx,spdx2,spdx3,common}.rs` shows mod.rs ≤ 250, each format submodule ≤ 600, common.rs ≤ 350.
- **SC-002**: Test-name parity. Sorted-name diff between pre-split and post-split test-output lists shows only renames (e.g., `parity::extractors::tests::*` → `parity::extractors::cdx::tests::*` if any tests move) — no removed-without-rename names.
- **SC-003**: 27-golden regen produces zero diff.
- **SC-004**: All 3 CI lanes green on the milestone PR.
- **SC-005**: `git diff main..HEAD -- mikebom-cli/src/cli/parity_cmd.rs mikebom-cli/tests/holistic_parity.rs` is empty.
- **SC-006**: Per-commit pre-PR clean.

## Clarifications

- **`extractors.rs` becomes `extractors/`**: replacing the single file with a directory module is the cleanest option (matches how 018+019 handled their splits). The directory contains `mod.rs` plus the 4 sibling submodules.
- **`common.rs` placement of SPDX cross-sibling helpers**: chosen over a separate `spdx_common.rs` to avoid a 5-file split. The `common` module is "everything used by ≥ 2 sibling submodules" — including the SPDX-only cross-format helpers like `spdx_relationship_edges`.
- **Macros stay in `common.rs`**: they're format-agnostic by construction.
- **`EXTRACTORS` table stays in `extractors/mod.rs`**: single source of truth; partitioning by format would force a runtime concatenation that's more complex than the gain.
- **No new tests, no test moves**: the 2 inline tests are table-validation (live with the table).
- **Visibility ladder**: same as 018+019. `pub` for items in the documented public surface, `pub(super)` for sibling-only items, private otherwise. No expansion or contraction.

## Out of Scope

- Splitting `mikebom-cli/src/parity/catalog.rs` (independent, not currently flagged).
- Refactoring extractor logic.
- Changing the EXTRACTORS table contents.
- Adding new extractors or formats.
- Touching `cli/parity_cmd.rs` or `holistic_parity.rs`.
- Splitting any other Tier 4 candidate (`generate/cyclonedx/builder.rs`, `resolve/deduplicator.rs`, etc. — separate milestones).
