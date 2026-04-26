# Spec Quality Checklist: SPDX Normalize-Consumption

**Checklist for** `/specs/021-spdx-normalize-consumption/spec.md`

## Coverage

- [X] Background section explains *why* the milestone is needed (carries the milestone-017 deferred-uplift context + the 2026-04-26 reconnaissance table).
- [X] User story has a P-priority and a "why this priority" justification (P2 because no observable failures today; hygiene + risk reduction).
- [X] Independent Test is concrete (specific files + specific helpers + tight-loop count).
- [X] Acceptance scenarios use Given/When/Then framing (3 scenarios).
- [X] Edge Cases section names the corner cases concretely (acceptance tests have no goldens; determinism tests have no goldens; mask_volatile stays put; spdx3_determinism partial state).
- [X] Functional Requirements are numbered (FR-001 through FR-008), each independently verifiable.
- [X] Key Entities NOT applicable — no new types/modules introduced (consumption-only).
- [X] Success Criteria are measurable (SC-001 through SC-005), each with a verification mechanism.
- [X] Clarifications section captures the scope-vs-extraction distinction explicitly.
- [X] Out of Scope section names every adjacent concern (goldens for acceptance/determinism, flake investigation, module splits, src/ changes, parity-already-good files).

## Tighter spec set rationale

- [X] No `research.md` — there are no open questions. The recon (T001) confirmed the helpers exist and which files don't consume them. No "should we do X or Y" decisions remain.
- [X] No `data-model.md` — no new types, structs, or modules introduced. The data model is the existing `common::normalize` surface.
- [X] No `contracts/` — no new public surface. Tests-only.
- [X] No `quickstart.md` — the 4 spec files are short enough that a quickstart would just paraphrase them. The implementer reads spec.md → plan.md → tasks.md in order.

This is the template for tighter milestones (when scope is genuinely contained). The full 8-file pattern stays default for milestones with open questions, new types, or new public surfaces.

## Independence

- [X] The single user story is self-contained — no dependencies on other in-flight work.
- [X] Each per-commit deliverable (1 commit, post-correction) is independently verifiable (per FR-008 each commit's `./scripts/pre-pr.sh` passes). Original 2-commit plan collapsed to 1 after re-verification reduced scope.

## Concreteness

- [X] FRs cite specific file paths (`mikebom-cli/tests/spdx_us1_acceptance.rs`, etc.) and specific line numbers from the recon (line 277, line 56, line 206).
- [X] FR-003 names the reference pattern (scenario-4 npm test at line 206).
- [X] Success Criteria reference the existing pre-PR gate + 27-golden regression surface.

## Internal consistency

- [X] FR-001/FR-002/FR-003 (apply_fake_home_env consumption) align with the spec table's "✗" entries from the recon.
- [X] FR-004 (workspace-path in spdx3_determinism.rs) aligns with the recon's "⚠ partial — missing workspace-path" finding.
- [X] FR-005 (mask_volatile stays put) aligns with the Edge Cases entry on the same topic.
- [X] FR-006 (no production code changes) aligns with the milestone-016 + Tier-2 framing.

## Lessons from milestones 016, 018, 019, 020

- [X] FR-008 (per-commit pre-PR clean) carries the 018+019+020 atomic-commit discipline.
- [X] The "no observable flake" framing in spec.md Background avoids the trap I just fell into during the milestone-020 wrap-up (treating speculation as documented fact). The flake reference is now an explicit "verified non-existent" rather than a vague "documented".
- [X] T001 explicitly logs the recon as "done in pre-spec investigation" with the date — future maintainers see what was checked.

## Pre-implementation

- [X] [PHASE-1] T001 reconnaissance done + corrected (2026-04-26). Initial recon overstated scope; direct re-verification reduced scope to 2 files / ~12 lines.
- [ ] [PHASE-1] T002 baseline snapshot captured.
- [ ] [PHASE-2] Single commit landed (combined acceptance + determinism); SC-001 + SC-002 hold simultaneously.
- [ ] [POLISH] SC-002 50x tight-loop passes for each affected file.
- [ ] [POLISH] SC-003 27-golden regen produces zero diff.
- [ ] [POLISH] SC-004 all CI lanes green.
- [ ] [POLISH] SC-005 `mikebom-cli/src/` diff empty + corrected-scope files (spdx3_us3, spdx3_determinism) untouched.

## Post-merge

- [ ] [QUALITATIVE] Next time someone touches an SPDX generator, observe whether the test suite is more trustworthy (no need to wonder "did this fail because of host state?"). If yes, milestone delivered.
