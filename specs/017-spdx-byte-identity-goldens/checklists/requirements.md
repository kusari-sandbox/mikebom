# Spec Quality Checklist: SPDX Byte-Identity Goldens

**Checklist for** `/specs/017-spdx-byte-identity-goldens/spec.md`

This is the standard spec-quality checklist applied to milestone 017. Items marked `[X]` are verified; `[ ]` are pending implementation-time verification.

## Coverage

- [X] Background section explains *why* the gap exists (CDX has goldens since 010; SPDX shipped without them in 010 + 011).
- [X] Each user story has a P-priority and a "why this priority" justification.
- [X] Each user story has an Independent Test that's *concrete* (specific command + expected output) — not vague ("tests pass").
- [X] Acceptance scenarios use Given/When/Then framing throughout.
- [X] Edge Cases section names at least 5 corner cases (synthetic image, document IRI evolution, hash strip per format, annotation-envelope path leak, future-feature emitter changes).
- [X] Functional Requirements are numbered (FR-001 through FR-011) and each is independently verifiable.
- [X] Key Entities cover the persisted artifacts (golden file, normalize helper, fake-HOME helper).
- [X] Success Criteria are measurable (SC-001 through SC-006), with verification mechanism stated for each.
- [X] Clarifications section captures the two scope decisions (synthetic image excluded; SPDX 3 IRI not masked today).
- [X] Assumptions are explicit (post-#38 emitter is the correct baseline; cross-host discipline that worked for CDX translates to SPDX).
- [X] Out of Scope section names every other tier from the post-016 audit (Tiers 3–6) plus the synthetic-image goldens.

## Independence

- [X] User Story 1 (the byte-identity goldens) can ship without User Story 3 (uniform fake-HOME migration); the migration is durability work, not a prerequisite.
- [X] User Story 2 (the helper module) is an internal prerequisite for User Story 1 — but that's intentional, and the helper is a means to the end, not a parallel deliverable.
- [X] The 9 ecosystem fixtures are independent of each other; a PR could in principle pin only some of them, though the FRs require all 9 for completeness.

## Concreteness

- [X] FRs cite specific file paths (`mikebom-cli/tests/fixtures/golden/spdx-2.3/`, `mikebom-cli/tests/common/normalize.rs`) — not "the test directory."
- [X] FR-006 names every helper function the milestone introduces, with parameter types.
- [X] Placeholders are spelled out (`<WORKSPACE>`, `urn:uuid:00000000-0000-0000-0000-000000000000`, `1970-01-01T00:00:00Z`) so a reviewer can verify the goldens match.
- [X] Success Criteria reference the existing pre-PR gate (`./scripts/pre-pr.sh`) so verification is concrete.

## Internal consistency

- [X] FR-007 (CDX goldens unchanged) aligns with research.md R5 (bundle the migration in this PR; verify byte-identical).
- [X] FR-010 (mask exactly the run-scoped fields) aligns with data-model.md "Placeholder catalog."
- [X] FR-008 (zero inline `env\("HOME"`) aligns with the User Story 3 acceptance scenarios.
- [X] FR-005 (env-var regen) aligns with contracts/golden-regen.md.
- [X] Constitution-check entries (plan.md) all derive from documented principles in `.specify/memory/constitution.md`.

## Pre-implementation

- [ ] [PHASE-1] Helper module skeleton compiles with empty function bodies (`unimplemented!()`) — proves the FR-006 signatures are sound.
- [ ] [PHASE-A] CDX migration is byte-identical (verified via `git diff` after `MIKEBOM_UPDATE_CDX_GOLDENS=1`).
- [ ] [PHASE-B] SPDX 2.3 leak-vector sweep returns empty for `rg '/Users/[^"]*'` and `rg '/home/runner/[^"]*'`.
- [ ] [PHASE-C] SPDX 3 leak-vector sweep returns empty for the same patterns.
- [ ] [PHASE-D] Inline-env grep returns empty (FR-008 enforcement).
- [ ] [PHASE-E] Both CI legs (Linux + macOS) pass on the open PR.

## Post-merge (per spec SC-006)

- [ ] [DAY-30] Spot-check merged-PR descriptions; every regen has an explanation.
- [ ] [DAY-60] Same.
- [ ] [DAY-90] Same. If patterns of "always-regenerated together" emerge, document in `docs/architecture/generation.md`.
