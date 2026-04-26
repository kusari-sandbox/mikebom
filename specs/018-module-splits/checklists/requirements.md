# Spec Quality Checklist: Module Splits

**Checklist for** `/specs/018-module-splits/spec.md`

Standard spec-quality checklist applied to milestone 018.

## Coverage

- [X] Background section explains *why* the splits are needed (three concrete pain points: read-cost, review-burden, onboarding).
- [X] Each user story has a P-priority and a "why this priority" justification.
- [X] Each user story has an Independent Test that's *concrete* (specific files + LOC bound + golden-regen check).
- [X] Acceptance scenarios use Given/When/Then framing throughout.
- [X] Edge Cases section names ≥ 5 corner cases (inline `#[cfg(test)]`, cross-submodule helpers, type re-exports, parsers sharing state, clippy allows, maven exclusion, scan_fs/mod.rs path resolution).
- [X] Functional Requirements are numbered (FR-001 through FR-010) and each is independently verifiable.
- [X] Key Entities section explicitly notes there are no new data — this is a structural refactor.
- [X] Success Criteria are measurable (SC-001 through SC-006), each with a verification mechanism.
- [X] Clarifications section captures three scope decisions (maven excluded; integration-test files not split; pip's `requirements_txt` not sub-split).
- [X] Assumptions are explicit (goldens are the regression test; `scan_fs/mod.rs` paths resolve identically; inline tests can move; clippy allows portable; no Cargo.toml changes).
- [X] Out of Scope section names every adjacent concern that someone might confuse with the milestone's actual scope.

## Independence

- [X] User Stories US1, US2, US3 are independent — each can ship without the others (per FR-009 commit chunking).
- [X] No story depends on another's intermediate state. The order (pip → npm → binary) is recommended for risk-management, not required.
- [X] Each story is independently verifiable: the byte-identity goldens, pre-PR script, and LOC ceiling all apply per-story.

## Concreteness

- [X] FRs cite specific file paths (`mikebom-cli/src/scan_fs/package_db/pip/`, etc.) — not abstract "the pip module."
- [X] FR-010 quantifies the LOC targets (≤ 800 default; ≤ 1100 for `requirements_txt.rs` only).
- [X] FR-005 names the verification command verbatim (`MIKEBOM_UPDATE_*_GOLDENS=1` regen → `git diff` empty).
- [X] Success Criteria reference the existing pre-PR gate (`./scripts/pre-pr.sh`) so verification is reproducible.

## Internal consistency

- [X] FR-005 (zero behavioral changes) is the strict reading of FR-010 (LOC ceilings can be met without changing behavior).
- [X] FR-007 (test names preserved) aligns with SC-004 (sorted-name diff).
- [X] FR-009 (per-user-story commits) aligns with quickstart.md commit chunking.
- [X] The visibility-ladder tables in `data-model.md` align with the cross-sibling-surface contract in `contracts/module-boundaries.md`.
- [X] Constitution-check entries (plan.md) all derive from `.specify/memory/constitution.md` principles.

## Pre-implementation

- [ ] [PHASE-1] Snapshot baseline: `./scripts/pre-pr.sh` test-name list captured (post-#41 baseline).
- [ ] [PHASE-1] LOC pre-split confirmed: 1965 / 1616 / 1858 / 5702 (pip / npm / binary / maven). (Verified during reconnaissance — current as of 2026-04-25.)
- [ ] [US1] Post-split: pip/ directory exists with 5 submodules; pip.rs absent.
- [ ] [US1] Goldens regen produces zero `git diff`.
- [ ] [US2] Same for npm.
- [ ] [US3] Same for binary; LOC of `binary/mod.rs` ≤ 800.
- [ ] [POLISH] FR-010 LOC ceilings all met (verified via `wc -l` per the quickstart).
- [ ] [POLISH] SC-004 test-name parity check returns no removed names.
- [ ] [POLISH] Both CI legs (Linux + macOS) green on the open PR.

## Post-merge (per spec SC-005 + SC-006)

- [ ] [DAY-30] Spot-check merged-PR diffs; confirm no PR re-bundles the splits.
- [ ] [QUALITATIVE] Next time a Poetry / pnpm / Mach-O bug is fixed, observe whether navigation feels faster vs. pre-split. If yes, milestone delivered. If no, capture the contributor's friction into a follow-up issue.
