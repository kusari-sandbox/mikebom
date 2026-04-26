---
description: "Task list — milestone 022 parity/extractors.rs split"
---

# Tasks: parity/extractors.rs Split — Tighter Spec

**Input**: Design documents from `/specs/022-parity-extractors-split/`
**Prerequisites**: spec.md (✅), plan.md (✅), checklists/requirements.md (✅)

**Tests**: No new tests. The 27 byte-identity goldens + 2 inline structural tests + `tests/holistic_parity.rs` integration test are the regression surface.

**Organization**: Single user story (US1, P2). Five atomic commits.

## Path Conventions

- Touches `mikebom-cli/src/parity/extractors.rs` → replaced by `mikebom-cli/src/parity/extractors/{mod,common,cdx,spdx2,spdx3}.rs`.
- Does NOT touch `mikebom-cli/src/cli/parity_cmd.rs`, `mikebom-cli/tests/holistic_parity.rs`, `mikebom-cli/src/parity/catalog.rs`, or `mikebom-cli/src/parity/mod.rs`.

---

## Phase 1: Setup

- [X] T001 Reconnaissance done in pre-spec investigation (2026-04-26). Findings logged in `spec.md` Background + `plan.md` Cohort assignments.
- [ ] T002 Snapshot baseline: `./scripts/pre-pr.sh 2>&1 | tee /tmp/baseline-022.txt | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/baseline-022-tests.txt`. Confirm post-022 list shows only renames, no removed-without-rename names.
- [ ] T003 Verify baseline LOC: `wc -l mikebom-cli/src/parity/extractors.rs`. Expected: 1654.

---

## Phase 2: Commit 1 — `022/extract-common`

**Goal**: Create `extractors/` directory with `mod.rs` + `common.rs`. Move cross-sibling items.

- [ ] T004 [US1] `git mv mikebom-cli/src/parity/extractors.rs mikebom-cli/src/parity/extractors/mod.rs` (or equivalent move that preserves history).
- [ ] T005 [US1] Create `extractors/common.rs`. Move:
  - `pub struct ParityExtractor` (lines 25-32)
  - `pub enum Directionality` (lines 35-52)
  - `pub fn extract_mikebom_annotation_values` (lines 71-86)
  - `extract_spdx23_annotation_values` (lines 88-120)
  - `extract_spdx3_annotation_values` (lines 122-166)
  - `decode_envelope` (lines 168-187)
  - `canonicalize_atomic_values` (lines 188-214)
  - `empty()` (lines 262-264)
  - `spdx_relationship_edges` (lines 831-923)
  - `normalize_alg` (lines 415-417)
  - `component_anno_extractors!` macro (lines 1187-1198) — declare with appropriate scope marker
  - `document_anno_extractors!` macro (lines 1200-1211)
- [ ] T006 [US1] In `extractors/mod.rs`: declare `mod common;`. Re-export public types via `pub use common::{ParityExtractor, Directionality, extract_mikebom_annotation_values};`. Qualify call sites that previously called these functions directly (e.g., `extract_spdx23_annotation_values(...)` → `common::extract_spdx23_annotation_values(...)`).
- [ ] T007 [US1] Verify: `cargo +stable check --workspace --tests` clean. `./scripts/pre-pr.sh` clean.
- [ ] T008 [US1] Commit: `refactor(022/extract-common): create extractors/ dir, move types + cross-sibling helpers to common.rs`.

---

## Phase 3: Commit 2 — `022/extract-cdx`

**Goal**: Move CDX-specific extractors to `cdx.rs`.

- [ ] T009 [US1] Create `extractors/cdx.rs`. Move every CDX-prefixed extractor function (cdx_purl, cdx_name, cdx_version, cdx_hashes, cdx_external_ref_by_type, cdx_homepage/vcs/distribution helpers, cdx_cpe, cdx_licenses_*, cdx_supplier, cdx_dependency_edges, cdx_runtime_deps, cdx_dev_deps, cdx_containment, cdx_root, cdx_property_values) plus `walk_cdx_components`. Add macro invocations for CDX C1-C20 if they live in CDX scope.
- [ ] T010 [US1] In `extractors/mod.rs`: declare `mod cdx;`. Re-export `pub use cdx::walk_cdx_components;`. Update `EXTRACTORS` table entries' CDX function pointers to `cdx::cdx_purl`, `cdx::cdx_name`, etc. (or `use cdx::*;` if visibility allows).
- [ ] T011 [US1] Apply `pub(super)` visibility to moved functions per FR-003.
- [ ] T012 [US1] Verify: `cargo +stable check --workspace --tests` clean. `./scripts/pre-pr.sh` clean.
- [ ] T013 [US1] Commit: `refactor(022/extract-cdx): move CDX-specific extractors to extractors/cdx.rs`.

---

## Phase 4: Commit 3 — `022/extract-spdx2`

**Goal**: Move SPDX 2.3-specific extractors to `spdx2.rs`.

- [ ] T014 [US1] Create `extractors/spdx2.rs`. Move every spdx23-prefixed extractor + `walk_spdx23_packages`. Add `use super::common::spdx_relationship_edges;` at top.
- [ ] T015 [US1] In `extractors/mod.rs`: declare `mod spdx2;`. Re-export `pub use spdx2::walk_spdx23_packages;`. Update EXTRACTORS table SPDX 2.3 fn pointers.
- [ ] T016 [US1] Apply `pub(super)` visibility per FR-003.
- [ ] T017 [US1] Verify: `./scripts/pre-pr.sh` clean.
- [ ] T018 [US1] Commit: `refactor(022/extract-spdx2): move SPDX 2.3 extractors to extractors/spdx2.rs`.

---

## Phase 5: Commit 4 — `022/extract-spdx3`

**Goal**: Move SPDX 3.0.1-specific extractors to `spdx3.rs`.

- [ ] T019 [US1] Create `extractors/spdx3.rs`. Move every spdx3-prefixed extractor + `walk_spdx3_packages`. `use super::common::spdx_relationship_edges;`.
- [ ] T020 [US1] In `extractors/mod.rs`: declare `mod spdx3;`. Re-export `pub use spdx3::walk_spdx3_packages;`. Update EXTRACTORS table SPDX 3 fn pointers.
- [ ] T021 [US1] Apply `pub(super)` visibility per FR-003.
- [ ] T022 [US1] Verify: `./scripts/pre-pr.sh` clean.
- [ ] T023 [US1] Commit: `refactor(022/extract-spdx3): move SPDX 3.0.1 extractors to extractors/spdx3.rs`.

---

## Phase 6: Commit 5 — `022/finalize-modrs`

**Goal**: Trim `extractors/mod.rs` to its final shape per the spec's LOC ceilings.

- [ ] T024 [US1] Inspect `extractors/mod.rs`. Should contain only:
  - Module declarations: `mod cdx; mod common; mod spdx2; mod spdx3;`
  - Public re-exports: `pub use common::{ParityExtractor, Directionality, extract_mikebom_annotation_values}; pub use cdx::walk_cdx_components; pub use spdx2::walk_spdx23_packages; pub use spdx3::walk_spdx3_packages;`
  - `pub static EXTRACTORS: &[ParityExtractor] = &[ ... 92 entries ... ];`
  - `#[cfg(test)] mod tests { /* 2 structural tests */ }`
- [ ] T025 [US1] If anything else lingers (forgotten helper, stray test), move it to the right submodule.
- [ ] T026 [US1] Verify SC-001: `wc -l mikebom-cli/src/parity/extractors/{mod,common,cdx,spdx2,spdx3}.rs` shows mod.rs ≤ 250, each format submodule ≤ 600, common.rs ≤ 350.
- [ ] T027 [US1] `./scripts/pre-pr.sh` clean.
- [ ] T028 [US1] Commit: `refactor(022/finalize-modrs): trim extractors/mod.rs to its final shape — completes the split`.

---

## Phase 7: Verification

- [ ] T029 SC-002 verification: post-022 test-name list — diff against `/tmp/baseline-022-tests.txt`. Expected: zero removed-without-rename. Renames OK (e.g., the 2 structural tests stay at `parity::extractors::tests::*` but their path may shift to `parity::extractors::mod::tests::*` depending on how cargo formats). The 2 structural tests should still be present.
- [ ] T030 SC-003 verification: `MIKEBOM_UPDATE_CDX_GOLDENS=1 MIKEBOM_UPDATE_SPDX_GOLDENS=1 MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test --workspace --tests -- --test-threads=1` produces zero diff in `mikebom-cli/tests/golden`.
- [ ] T031 SC-005 verification: `git diff main..022-parity-extractors-split -- mikebom-cli/src/cli/parity_cmd.rs mikebom-cli/tests/holistic_parity.rs mikebom-cli/src/parity/catalog.rs mikebom-cli/src/parity/mod.rs` is empty.
- [ ] T032 Push branch; observe all 3 CI lanes green.
- [ ] T033 Author PR description: 5-commit summary, per-submodule LOC inventory, byte-identity attestation, external-callers-untouched attestation.

---

## Dependency Graph

```text
T001 (recon, done) → T002 (baseline) → T003 (LOC verify)
                                             │
                                             ↓
                                        T004-T008  ← Commit 1 (common)
                                             │
                                             ↓
                                        T009-T013  ← Commit 2 (cdx)
                                             │
                                             ↓
                                        T014-T018  ← Commit 3 (spdx2)
                                             │
                                             ↓
                                        T019-T023  ← Commit 4 (spdx3)
                                             │
                                             ↓
                                        T024-T028  ← Commit 5 (finalize)
                                             │
                                             ↓
                                        T029-T033 (verify + PR)
```

Commit 1 (common) MUST come first — others import from it. Commits 2-4 (cdx/spdx2/spdx3) are independent and could be reordered if needed, but the recommended order keeps each commit's mod.rs intermediate state clean.

## Estimated effort

| Phase | Effort | Notes |
|---|---|---|
| Phase 1 (baseline) | 5 min | T001 done; just snapshot + LOC |
| Phase 2 (common) | 45 min | Macro export is the careful step |
| Phase 3 (cdx) | 45 min | Largest format submodule |
| Phase 4 (spdx2) | 30 min | Mechanical |
| Phase 5 (spdx3) | 30 min | Mechanical |
| Phase 6 (finalize) | 15 min | Trim + LOC verify |
| Phase 7 (verify + PR) | 30 min | Goldens + push + CI watch |
| **Total** | **~3.5 hr** | One focused half-day. |
