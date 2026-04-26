# Spec Quality Checklist: parity/extractors.rs Split

**Checklist for** `/specs/022-parity-extractors-split/spec.md`

## Coverage

- [X] Background section explains why the split is needed (1654 LOC → second-largest single file post-018+019; columnar format-shaped structure).
- [X] User story has a P-priority (P2) and a "why this priority" justification (maintenance ergonomics, no behavior change).
- [X] Independent Test is concrete (specific file paths + LOC ceilings + golden-regen check).
- [X] Acceptance scenarios use Given/When/Then framing (3 scenarios).
- [X] Edge Cases section names the corner cases (spdx_relationship_edges placement, macros, walk_*, EXTRACTORS table location, tests).
- [X] Functional Requirements are numbered (FR-001 through FR-008), each independently verifiable.
- [X] Key Entities NOT applicable — pure structural refactor (consistent with 019 spec, which made the same call).
- [X] Success Criteria are measurable (SC-001 through SC-006), each with a verification mechanism.
- [X] Clarifications section captures the 5 scope decisions (dir vs file, common.rs scope, macros, EXTRACTORS table, no test moves, visibility ladder).
- [X] Out of Scope section names every adjacent concern (catalog.rs, logic refactor, table content changes, new extractors, external callers, other Tier 4 candidates).

## Tighter spec set rationale (4 files vs 8)

- [X] No `research.md` — the recon answered every architectural question. Only one open issue (spdx_relationship_edges placement) and the spec resolves it directly in Edge Cases + Clarifications.
- [X] No `data-model.md` — no new types or modules introduced from a data-model perspective; the visibility ladder is fully specified inline in spec.md FR-003 + plan.md Cohort assignments.
- [X] No `contracts/` — no public surface change; FR-002 + SC-005 enforce identity. A standalone contracts file would just restate this.
- [X] No `quickstart.md` — 4 short files (spec, plan, tasks, checklists) are self-explanatory. The implementer reads in order.

This is the second use of the 4-file template (after 021), now stable as the format for genuinely contained milestones with well-understood seams.

## Independence

- [X] The single user story is self-contained.
- [X] Each per-commit deliverable (5 commits) is independently verifiable (per FR-005 each commit's `./scripts/pre-pr.sh` passes).

## Concreteness

- [X] FRs cite specific file paths (`mikebom-cli/src/parity/extractors/{mod,common,cdx,spdx2,spdx3}.rs`).
- [X] FR-001 quantifies LOC budgets (mod.rs ≤ 250; each format ≤ 600; common.rs ≤ 350).
- [X] SC-001 names the verification command (`wc -l ...`).
- [X] SC-005 names the verification command exactly.
- [X] FR-002 names the 4 specific external symbols whose paths must not change.

## Internal consistency

- [X] FR-001 LOC budgets align with plan.md cohort estimates.
- [X] FR-003 (visibility ladder) aligns with plan.md R3 (no expansion needed, sibling pub(super) visible to mod.rs).
- [X] FR-005 (per-commit pre-PR clean) aligns with tasks.md commit chunking.
- [X] Edge Case "spdx_relationship_edges placement" aligns with Clarifications "common.rs scope" + plan.md cohort table.

## Lessons from milestones 016, 018, 019, 020, 021

- [X] FR-005 carries the per-commit-clean discipline.
- [X] Plan.md R1 (macro export) flagged as the careful step — analogous to 019 R3 (Cargo.toml + cfg gates atomic).
- [X] Plan.md R3 verifies `pub(super) fn` from sibling visible to parent mod.rs — same observation that drove 019's visibility ladder.
- [X] Recon-first discipline reinforced: every assumption in the spec is grounded in a file:line reference from the recon report.

## Pre-implementation

- [X] [PHASE-1] T001 reconnaissance done (2026-04-26). Findings logged in spec + plan.
- [ ] [PHASE-1] T002 baseline snapshot captured.
- [ ] [PHASE-1] T003 baseline LOC verified (1654).
- [ ] [PHASE-2] Commit 1 (common) landed.
- [ ] [PHASE-3] Commit 2 (cdx) landed.
- [ ] [PHASE-4] Commit 3 (spdx2) landed.
- [ ] [PHASE-5] Commit 4 (spdx3) landed.
- [ ] [PHASE-6] Commit 5 (finalize) landed; SC-001 LOC ceilings met.
- [ ] [POLISH] SC-002 test-name parity check returns no removed-without-rename names.
- [ ] [POLISH] SC-003 27-golden regen produces zero diff.
- [ ] [POLISH] SC-004 all 3 CI lanes green.
- [ ] [POLISH] SC-005 external-callers diff empty.

## Post-merge

- [ ] [QUALITATIVE] Next time someone fixes a CDX-only or SPDX-only parity bug, observe whether navigation feels faster vs. pre-split. If yes, milestone delivered.
