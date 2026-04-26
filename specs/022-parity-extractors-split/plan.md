---
description: "Implementation plan — milestone 022 parity/extractors.rs split"
status: plan
milestone: 022
---

# Plan: parity/extractors.rs Split

## Architecture

The 1654-LOC `extractors.rs` becomes a directory module `extractors/` with 5 files:

```
mikebom-cli/src/parity/
├── catalog.rs            (unchanged, 18K)
├── extractors/
│   ├── mod.rs            (≤ 250 LOC — module decls, re-exports, EXTRACTORS table, 2 structural tests)
│   ├── common.rs         (≤ 350 LOC — cross-sibling types, helpers, macros)
│   ├── cdx.rs            (≤ 600 LOC — CDX-specific extractors + walk_cdx_components)
│   ├── spdx2.rs          (≤ 600 LOC — SPDX 2.3 extractors + walk_spdx23_packages)
│   └── spdx3.rs          (≤ 600 LOC — SPDX 3.0.1 extractors + walk_spdx3_packages)
└── mod.rs                (unchanged — `pub mod extractors; pub mod catalog;`)
```

Public surface is preserved by `extractors/mod.rs` re-exporting from siblings:

```rust
mod cdx;
mod common;
mod spdx2;
mod spdx3;

pub use common::{
    extract_mikebom_annotation_values, Directionality, ParityExtractor,
};
pub use cdx::walk_cdx_components;
pub use spdx2::walk_spdx23_packages;
pub use spdx3::walk_spdx3_packages;

pub static EXTRACTORS: &[ParityExtractor] = &[ /* 92 entries */ ];

#[cfg(test)]
mod tests { /* 2 structural tests */ }
```

External callers (`parity_cmd.rs`, `holistic_parity.rs`) see the same paths and the same items — no import changes.

## Cohort assignments

Per the recon's section-by-section analysis:

### `common.rs` (cross-sibling)
- `pub struct ParityExtractor` (lines 25-32)
- `pub enum Directionality` (lines 35-52)
- `pub fn extract_mikebom_annotation_values` (lines 71-86) — used by all 3 formats via macros
- `extract_spdx23_annotation_values` (lines 88-120) — used by SPDX 2.3 + SPDX 3 sides
- `extract_spdx3_annotation_values` (lines 122-166) — same
- `decode_envelope` (lines 168-187)
- `canonicalize_atomic_values` (lines 188-214)
- `empty()` sentinel (lines 262-264)
- `spdx_relationship_edges` (lines 831-923) — 169-LOC SPDX 2/3 shared graph traversal
- `component_anno_extractors!` macro (lines 1187-1198)
- `document_anno_extractors!` macro (lines 1200-1211)
- `normalize_alg` (lines 415-417) — used by all 3 formats' hash extractors

### `cdx.rs` (CDX-specific)
- `walk_cdx_components` (lines 215-230)
- All CDX-prefixed extractor fns: `cdx_purl`, `cdx_name`, `cdx_version`, `cdx_hashes`, `cdx_external_ref_by_type` (and homepage/vcs/distribution helpers it spawns), `cdx_cpe`, `cdx_licenses_typed/declared/concluded`, `cdx_supplier`, `cdx_dependency_edges`, `cdx_runtime_deps`, `cdx_dev_deps`, `cdx_containment`, `cdx_root`, `cdx_property_values`
- CDX C/D/E/F/G section custom extractors (CDX side only)
- Macro invocations producing CDX C1-C20

### `spdx2.rs` (SPDX 2.3-specific)
- `walk_spdx23_packages` (lines 231-245)
- All SPDX23-prefixed extractor fns
- SPDX 2.3 C/D/E/F/G section custom extractors
- Macro invocations producing SPDX 2.3 C1-C20
- `use super::common::spdx_relationship_edges;`

### `spdx3.rs` (SPDX 3.0.1-specific)
- `walk_spdx3_packages` (lines 246-261)
- All SPDX3-prefixed extractor fns
- SPDX 3 C/D/E/F/G section custom extractors
- Macro invocations producing SPDX 3 C1-C20
- `use super::common::spdx_relationship_edges;`

### `mod.rs`
- Module declarations
- `pub use` chain
- `pub static EXTRACTORS` (92 entries)
- 2 inline tests: `extractors_table_is_sorted_by_row_id`, `every_catalog_row_has_an_extractor`

## Phasing

Five atomic commits in dependency order:

1. **022/extract-common**: create `extractors/` dir, move types + cross-sibling helpers + macros to `common.rs`, replace `extractors.rs` with `extractors/mod.rs` that re-exports from common. Other format extractor fns stay in mod.rs temporarily. Pre-PR clean.

2. **022/extract-cdx**: move CDX-specific extractors + `walk_cdx_components` to `cdx.rs`. mod.rs imports back via `use cdx::*` only what it needs for the EXTRACTORS table. Pre-PR clean.

3. **022/extract-spdx2**: same for SPDX 2.3 → `spdx2.rs`. Pre-PR clean.

4. **022/extract-spdx3**: same for SPDX 3 → `spdx3.rs`. Pre-PR clean.

5. **022/finalize-modrs**: trim `extractors/mod.rs` to its final shape — module decls, `pub use` chain, EXTRACTORS table, 2 tests. Verify SC-001 LOC budgets.

Per FR-005 each commit's `./scripts/pre-pr.sh` is clean. The dependency order (common before others) avoids the 019 R3 trap (Cargo.toml + cfg-gates split): each commit leaves the tree compilable.

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| 1 (extract-common) | 45 min | Move types + macros + ~200 LOC helpers; care needed re macro export |
| 2 (extract-cdx) | 45 min | Mechanical; CDX has more custom code than the others |
| 3 (extract-spdx2) | 30 min | Mechanical |
| 4 (extract-spdx3) | 30 min | Mechanical |
| 5 (finalize) | 15 min | Trim + verify LOC ceilings |
| Verify + PR | 30 min | Goldens regen + push + watch CI |
| **Total** | **~3 hr** | One focused half-day. |

## Risks

- **R1: Macros export from `common.rs`.** Rust macros need `#[macro_use]` or `pub use` to be visible across modules. Per the recon, the macros are `macro_rules!`. Mitigation: declare with `#[macro_export]` if needed, or use `pub(super) use common::component_anno_extractors;` in each format submodule. Verified at commit 1.
- **R2: `EXTRACTORS` table references function pointers from all four submodules.** The table lives in `mod.rs` and points at items from cdx/spdx2/spdx3 (and macros from common). Mitigation: `mod.rs` does `use cdx::{cdx_purl, cdx_name, ...}` etc. The recon found 92 entries × 3 fns = ~276 fn references; this is the bulk of mod.rs.
- **R3: `pub(super) fn` items used by `mod.rs::EXTRACTORS` are visible.** `pub(super)` from a sibling module IS visible to mod.rs (mod.rs is the parent). Verified — no visibility expansion needed.
- **R4: Test names change**. The 2 structural tests stay in mod.rs and keep their paths. SC-002 holds trivially.

## Constitution alignment

- **Principle IV (no `.unwrap()` in production):** untouched. Pure structural refactor.
- **Principle VI (three-crate architecture):** untouched.
- **Per-commit verification (lessons from 018-021):** FR-005 enforced.
- **Atomic-per-cohort (lesson from 019 R3):** the 5-commit chain respects sub-module dependency order — common before format-specific submodules.

## What this milestone does NOT do

- Does not change extractor logic.
- Does not modify the EXTRACTORS table contents.
- Does not touch external callers (`parity_cmd.rs`, `holistic_parity.rs`).
- Does not split `catalog.rs`.
- Does not add new tests.
