---
description: "Task list — Cross-format SBOM-Quality Fixes (milestone 012)"
---

# Tasks: Cross-format SBOM-Quality Fixes

**Input**: Design documents from `/specs/012-sbom-quality-fixes/`
**Prerequisites**: plan.md (✅), spec.md (✅), research.md (✅), data-model.md (✅), quickstart.md (✅)

**Tests**: Test tasks are included. Spec success criteria SC-001 through SC-009 each name an enforceable CI gate; the project's pre-PR gate (constitution Pre-PR Verification clause) requires `cargo +stable test --workspace` clean. Tests are load-bearing.

**Organization**: Tasks are grouped by user story for independent implementation:
- **US1 (P1, MVP)**: SPDX 3 CPE coverage parity vs. CycloneDX (1-line bug fix in `is_fully_resolved_cpe23`).
- **US2 (P2)**: CDX↔SPDX 2.3 component-count parity. Phase-0 R2 finding determined this is **not a code bug** — fix is tighter bidirectional parity tests + a structural-difference doc note. **No emitter code change.**
- **US3 (P3)**: SPDX 2.3 LicenseRef-`<hash>` + `hasExtractedLicensingInfos[]` backport so non-canonicalizable license expressions are preserved instead of dropping to `NOASSERTION`.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Maps task to spec.md user story (US1, US2, US3); omitted on Setup/Foundational/Polish

## Path Conventions

Single Rust workspace; mikebom is a CLI binary. Source under `mikebom-cli/src/`, tests under `mikebom-cli/tests/`. Mapping doc at `docs/reference/sbom-format-mapping.md`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: One-time helper extraction needed by US3. The other two stories don't need anything from setup.

- [X] T001 [P] Extracted `hash_prefix` helper in `spdx/ids.rs` + added `SpdxId::for_license_ref`. 6 new unit tests (determinism, prefix shape, 27-char total length, charset compliance, different-inputs-different-ids, 10k-synthetic-input collision-resistance sanity). All pass.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: None. The three user stories are mutually independent at the source-file level (US1 = `v3_external_ids.rs`; US2 = parity test files only; US3 = `packages.rs` + `document.rs` + `ids.rs`). Phase 1's T001 covers the only shared helper. Skip directly to user-story phases.

---

## Phase 3: User Story 1 — SPDX 3 CPE coverage parity (Priority: P1) 🎯 MVP

**Goal**: SPDX 3 emits one `ExternalIdentifier[cpe23]` entry per CPE that CycloneDX emits for the same scan. Today the SPDX 3 path drops nearly all CPEs because `is_fully_resolved_cpe23` rejects vectors with `update=*` (which mikebom-synthesized CPEs always have).

**Independent Test**: Run `cargo +stable test -p mikebom --test cpe_v3_acceptance` and `--test spdx3_cdx_parity` — both pass for every ecosystem fixture. Polyglot fixture's SPDX 3 CPE count rises from 1 to ≥ 727.

### Tests for User Story 1 (TDD-style — write first, expect to fail until T004)

- [X] T002 [P] [US1] Authored `mikebom-cli/tests/cpe_v3_acceptance.rs`. 9 per-ecosystem tests. Directional check (every CDX CPE → SPDX 3 `cpe23` ExternalIdentifier) + SPDX 3 count ≥ CDX count lower bound. All 9 pass.
- [X] T003 [P] [US1] Extended `mikebom-cli/tests/spdx3_cdx_parity.rs::assert_parity` with per-Package CPE-presence check: for each CDX component carrying `component.cpe`, an equal-string `cpe23` ExternalIdentifier appears on the matching Package. All 9 ecosystem tests pass.

### Implementation for User Story 1

- [X] T004 [US1] Fixed `is_fully_resolved_cpe23` in `v3_external_ids.rs:75`. Changed `parts[2..7]` to `parts[2..6]` + rewrote both the doc comment (lines 68-80) and the inline comment (line 83) so they match the implementation. Added 6 unit tests covering the wildcard-update passes, version=`*` fails, update=`-` passes, too-short fails, non-cpe-prefix fails, wildcard-vendor fails. All 6 pass.

**Checkpoint**: T002 + T003 pass after T004 lands. The SPDX 3 emitter now emits one `cpe23` entry per fully-resolved CPE candidate (FR-001/FR-002/FR-003).

---

## Phase 4: User Story 2 — CDX↔SPDX 2.3 component-count parity (Priority: P2)

**Goal**: Lock in the CDX-flattened ↔ SPDX 2.3-packages component-set equality as a CI invariant, plus document the structural difference (CDX nests, SPDX 2.3 flattens) so future readers don't re-investigate. Per Phase-0 R2: not a code bug — a tighter parity test + doc note.

**Independent Test**: Run `cargo +stable test -p mikebom --test component_count_parity` and `--test spdx_cdx_parity` and `--test spdx3_cdx_parity` — all pass for every ecosystem fixture.

### Tests for User Story 2

- [X] T005 [P] [US2] Authored `mikebom-cli/tests/component_count_parity.rs`. 9 per-ecosystem tests. Three assertions per ecosystem: CDX flattened count == SPDX 2.3 packages minus synthetic root; CDX flattened count == SPDX 3 software_Package minus synthetic root; SPDX 2.3 and SPDX 3 agree on non-synthetic count. All 9 pass.
- [X] T006 [P] [US2] Discovered the existing `spdx_cdx_parity.rs::assert_parity` already has the SPDX→CDX reverse walk from milestone 010 (lines 232-262). No code change needed. Confirmed all 9 tests still pass.
- [X] T007 [P] [US2] Same as T006 — the existing `spdx3_cdx_parity.rs::assert_parity` already has the reverse walk from milestone 011 (line 278). Confirmed all 9 tests still pass.

### Implementation for User Story 2

- [X] T008 [US2] Added new Section H ("Structural differences between formats") to `docs/reference/sbom-format-mapping.md` with row H1 documenting the CDX-nests-vs-SPDX-flattens difference + reference to the locked CI invariant (`component_count_parity.rs`). Explains why the user-reported "22-component drift" was not a bug.

**Checkpoint**: T005 + T006 + T007 pass; T008 documents the locked invariant. **No emitter code touched.**

---

## Phase 5: User Story 3 — SPDX 2.3 LicenseRef preservation (Priority: P3)

**Goal**: When a CycloneDX `licenses[]` entry contains a non-canonicalizable expression (e.g. `"GNU General Public"`), SPDX 2.3 emits the expression verbatim via `LicenseRef-<hash>` + `hasExtractedLicensingInfos[]` instead of dropping to `NOASSERTION`. Per clarification Q1: all-or-nothing — any non-canonicalizable term in a multi-term expression triggers the LicenseRef path for the whole expression.

**Independent Test**: Run `cargo +stable test -p mikebom --test spdx_license_ref_extracted` — passes for every ecosystem fixture; native-linkage SPDX 2.3 license-count rises from 38 to ≥ 107.

### Tests for User Story 3

- [X] T009 [P] [US3] Authored `mikebom-cli/tests/spdx_license_ref_extracted.rs`. 9 per-ecosystem tests. Asserts: count of CDX components-with-license == count of SPDX 2.3 Packages-with-non-NOASSERTION; every `LicenseRef-` in `licenseDeclared` has a matching entry in `hasExtractedLicensingInfos[]`; dedup (every licenseId appears once); non-empty `extractedText` + `name` on every entry. All 9 pass.

### Implementation for User Story 3

- [X] T010 [P] [US3] Added `SpdxLicenseField::LicenseRef(String)` variant with a bare-string Serialize arm. Covered by the existing `license_expression_serializes_as_bare_string` test pattern + the new `unparseable_license_emits_license_ref_and_extracted_info` unit test.
- [X] T011 [P] [US3] Added `SpdxExtractedLicensingInfo` struct + `has_extracted_licensing_infos` field on `SpdxDocument` with `#[serde(rename = "hasExtractedLicensingInfos", skip_serializing_if = "Vec::is_empty")]`.
- [X] T012 [US3] Rewrote `reduce_license_vec` returning `(SpdxLicenseField, Option<SpdxExtractedLicensingInfo>)` per all-or-nothing rule. Empty input → `(NoAssertion, None)`. Joined canonical-parse success → `(Expression, None)`. Joined canonical-parse failure → `(LicenseRef, Some(info))`. Unit tests cover all three paths including the dedup case.
- [X] T013 [US3] Wired `build_packages` to return `(Vec<SpdxPackage>, Vec<SpdxExtractedLicensingInfo>)` — dedups by `license_id` via `BTreeMap` (also provides deterministic ordering by licenseId). `build_document` destructures and passes `has_extracted_licensing_infos` into the `SpdxDocument` constructor. Determinism gate (spdx_determinism.rs) passes clean.
- [X] T014 [US3] Updated mapping doc A7/A8 rows with the full set of `licenseDeclared` shapes: canonical expression / `LicenseRef-<hash>` / `NOASSERTION` / `NONE`. Documents the cross-reference to `hasExtractedLicensingInfos[]` for the LicenseRef shape.

**Checkpoint**: T009 passes (per-ecosystem license-coverage parity holds; LicenseRef shape + dedup confirmed). Native-linkage SPDX 2.3 license count rises from 38 to ≥ 107 (verifiable via the smoke-test commands in `quickstart.md`).

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Cross-cutting validation that all three fixes land cleanly together.

- [X] T015 [P] `sbom_format_mapping_coverage` `ok. 3 passed; 0 failed` — mapping-doc edits (T008, T014) preserved row coverage.
- [X] T016 [P] `spdx_determinism` `ok. 9 passed` + `spdx3_determinism` `ok. 3 passed` — LicenseRef-`<hash>` derivation deterministic; BTreeMap-ordered extracted-info collection byte-stable.
- [X] T017 [P] `spdx_annotation_fidelity` `ok. 9 passed` + `spdx3_annotation_fidelity` `ok. 3 passed` — LicenseRef change didn't leak into the annotation path.
- [X] T018 [P] Milestone-010 / 011 regression guards: `cdx_regression` `ok. 9 passed`, `spdx_us1_acceptance` `ok. 5 passed`, `format_dispatch` `ok. 9 passed`.
- [X] T019 Smoke-test confirmed: release-build against npm fixture, emits all three formats; SPDX 3 cpe23 count = 3 (up from 1 pre-fix — 2 npm components + synthetic root); SPDX 2.3 `hasExtractedLicensingInfos` absent for npm fixture (all licenses canonicalize — FR-008 behavior preserved).
- [X] T020 Pre-PR gate clean: `cargo +stable clippy --workspace --all-targets` reports **0 errors**; `cargo +stable test --workspace` reports **1353 passed, 0 failed** across 40 test binaries.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: T001 has no dependencies. Can land first as a small standalone PR or as the first commit of the milestone PR.
- **Foundational (Phase 2)**: empty — skipped.
- **US1 (Phase 3)**: depends on Phase 1 (none of US1's tasks need T001, but T001 lands cleanly enough that US1 can start immediately after). Tests T002/T003 [P] before implementation T004.
- **US2 (Phase 4)**: depends on Phase 1 (none of US2's tasks need T001). Tests T005/T006/T007 [P]; T008 (doc) [P] with the tests.
- **US3 (Phase 5)**: depends on T001 (uses `SpdxId::for_license_ref`) AND on T010 + T011 (T012 needs both the new variant + the new struct). T009 [P] with T010/T011; T013 depends on T012; T014 (doc) [P] with the implementation work.
- **Polish (Phase 6)**: depends on all three user stories complete. T015/T016/T017/T018 [P]; T019/T020 sequential at the end.

### User Story Dependencies (in spec.md priority order)

- **US1 (P1)**: independent. Smallest fix in the milestone (one literal change + one assertion line). Could ship as a standalone PR for fastest user-visible improvement.
- **US2 (P2)**: independent. No emitter code change; tests + doc only. Could ship in parallel with US1.
- **US3 (P3)**: depends on T001 (foundational helper). Largest fix in the milestone. Can ship after US1+US2 as an independent increment, or all together.

### Parallel Opportunities

- **Setup**: only T001 — no parallel batch.
- **US1 tests**: T002 + T003 [P] (different files).
- **US2**: T005 + T006 + T007 + T008 all [P] (each touches a different file).
- **US3**: T009 + T010 + T011 + T014 all [P] (test, packages.rs enum-variant addition, document.rs struct addition, mapping doc — all different files). T012 sequential (rewrites a function in packages.rs that touches the new variant). T013 sequential (wires the build_document plumbing).
- **Polish**: T015 + T016 + T017 + T018 all [P] (independent verification runs).

---

## Parallel Example: User Story 3

```bash
# Four independent file edits in parallel:
Task: "Author tests/spdx_license_ref_extracted.rs (per-ecosystem coverage + shape + dedup checks)"
Task: "Add SpdxLicenseField::LicenseRef variant + Serialize arm in spdx/packages.rs"
Task: "Add SpdxExtractedLicensingInfo struct + has_extracted_licensing_infos field in spdx/document.rs"
Task: "Update docs/reference/sbom-format-mapping.md A7/A8 LicenseRef shape mention"

# Then sequential:
Task: "Rewrite reduce_license_vec in spdx/packages.rs (depends on T010 + T011 + T001)"
Task: "Wire extracted-info collection in build_packages → build_document"
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Complete T001 (foundational helper).
2. Complete US1 (T002–T004) — three tasks, ~20 minutes of work.
3. Run `cargo +stable test -p mikebom --test cpe_v3_acceptance --test spdx3_cdx_parity` — both pass.
4. Could merge as a fast first PR — biggest user-visible quality improvement (CPE coverage in SPDX 3).

### Incremental Delivery

1. T001 (foundational).
2. US1 → ship — SPDX 3 CPE coverage restored.
3. US2 → ship — bidirectional parity tests + structural-difference doc note (no emitter code).
4. US3 → ship — SPDX 2.3 LicenseRef preservation.
5. Polish → ship — final cross-cutting verification + pre-PR gate.

Each story is independently shippable. Recommended: ship all three in one PR (~20 tasks total, mostly small) since they share the milestone-012 spec narrative; OR ship US1 first as a quick fast-track.

### Parallel Team Strategy (if staffed)

After T001 lands, US1 / US2 / US3 can split across three developers:
- Developer A: US1 (T002–T004) — ~30 minutes
- Developer B: US2 (T005–T008) — ~1 hour
- Developer C: US3 (T009–T014) — ~3 hours

All three converge on Phase 6 polish.

---

## Notes

- File paths are absolute relative to repo root; cargo commands run from repo root.
- Per `feedback_prepr_gate_full_output.md`, the PR description MUST cite the per-target `ok. N passed; 0 failed` lines from `cargo test --workspace`, not a grep summary.
- All `v3_*` modules and `spdx/*` modules use `#[cfg_attr(test, allow(clippy::unwrap_used))]` on any `mod tests` block per Constitution Principle IV + the `mikebom-cli` crate-root deny.
- The 16-char BASE32-NOPAD prefix from SHA-256 gives 80 bits of collision resistance — for the polyglot fixture's ~700 distinct expressions, collision probability is ≈ 2 × 10⁻¹⁹. Effectively zero. (See research.md §R3.)
- US2's "fix" is intentionally non-code: per Phase-0 R2, the 22-component drift is a structural difference between CDX and SPDX 2.3, not a bug. Tightening the parity test is the right resolution; the spec's FR-004/FR-005/FR-006 are all satisfied by the test + doc work.
