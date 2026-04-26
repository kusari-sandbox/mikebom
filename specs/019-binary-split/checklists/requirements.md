# Spec Quality Checklist: binary/mod.rs Split

**Checklist for** `/specs/019-binary-split/spec.md`

## Coverage

- [X] Background section explains *why* the split is needed (carries milestone-018's deferred US3 context + new finding about test-LOC budget driving the 5-file split).
- [X] User story has a P-priority and a "why this priority" justification.
- [X] Independent Test is concrete (specific file paths + LOC ceiling + golden-regen check).
- [X] Acceptance scenarios use Given/When/Then framing.
- [X] Edge Cases section names ≥ 5 corner cases (`is_path_claimed` location, `BinaryScan` location, `detect_format` retention, sibling-module references, test-distribution rules, `tests/scan_binary.rs` exemption).
- [X] Functional Requirements are numbered (FR-001 through FR-010), each independently verifiable.
- [X] Key Entities section explicitly notes there's no new data — structural refactor only.
- [X] Success Criteria are measurable (SC-001 through SC-006), each with a verification mechanism.
- [X] Clarifications section captures three scope decisions (5 files vs 4; `is_path_claimed` location; `tests/scan_binary.rs` not split).
- [X] Assumptions are explicit (byte-identity goldens are the regression gate; `tests/scan_binary.rs` covers the public API; pre-existing flakiness in `dual_format_perf` etc.).
- [X] Out of Scope section names every adjacent concern (test file split, sub-splits, behavior changes, renames, stub completion, maven).

## Independence

- [X] The single user story is self-contained — no dependencies on other in-flight work.
- [X] Each per-submodule extraction commit is independently verifiable (per FR-008 each commit's `./scripts/pre-pr.sh` passes).

## Concreteness

- [X] FRs cite specific file paths (`mikebom-cli/src/scan_fs/binary/{discover,entry,predicates,scan}.rs`).
- [X] FR-001 quantifies the LOC target (≤ 800).
- [X] FR-004 names the verification command verbatim.
- [X] FR-003 names the 4 specific external call sites that must not change.
- [X] Success Criteria reference the existing pre-PR gate.

## Internal consistency

- [X] FR-006 (visibility expansion only) aligns with research.md R4 (visibility ladder).
- [X] FR-005 (test names preserved) aligns with SC-002 (sorted-name diff).
- [X] FR-008 (per-commit pre-PR clean) aligns with quickstart.md commit chunking.
- [X] The visibility-ladder tables in `data-model.md` align with the cross-sibling-surface contract in `contracts/module-boundaries.md`.
- [X] research.md's R5 (atomic per-submodule commits) aligns with quickstart.md's commit chunking.

## Lessons from milestone 018

- [X] research.md R2 captures why `is_path_claimed` stays in mod.rs — the failure mode that defeated 018/US3 was trying to move it to scan.rs and re-route external callers.
- [X] research.md R3 captures where `BinaryScan` lives + why scan.rs imports it from entry.rs (not mod.rs).
- [X] research.md R5 captures the atomic-per-submodule-commit lesson.
- [X] quickstart.md "Common pitfalls" enumerates the failure modes.
- [X] FR-008 enforces the per-commit verification convention that protected milestone 018's pip + npm splits.

## Pre-implementation

- [ ] [PHASE-1] Snapshot baseline: `./scripts/pre-pr.sh` test-name list captured (post-#43 baseline).
- [ ] [PHASE-1] LOC pre-split confirmed: 1858 (verified during reconnaissance — current as of 2026-04-25, post-#43).
- [ ] [PHASE-2] predicates.rs landed; mod.rs ~1500 LOC.
- [ ] [PHASE-3] discover.rs landed; mod.rs ~1415 LOC.
- [ ] [PHASE-4] entry.rs landed; mod.rs ~925 LOC.
- [ ] [PHASE-5] scan.rs landed; mod.rs ≤ 800 LOC.
- [ ] [POLISH] FR-001 LOC ceiling met (verified via `wc -l` per the quickstart).
- [ ] [POLISH] SC-002 test-name parity check returns no removed-without-rename names.
- [ ] [POLISH] Goldens regen produces zero diff.
- [ ] [POLISH] Both CI legs (Linux + macOS) green on the open PR.

## Post-merge (per spec SC-006)

- [ ] [QUALITATIVE] Next time a Mach-O fat-binary or PE-format bug is fixed, observe whether navigation feels faster vs. pre-split. If yes, milestone delivered.
