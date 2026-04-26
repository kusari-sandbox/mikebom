# Spec Quality Checklist: Mach-O Binary Identity

**Checklist for** `/specs/024-macho-binary-identity/spec.md`

## Coverage

- [X] Background section explains why three specific Mach-O identity
      signals are missing today + cites file:line evidence (`macho.rs`
      = 7-line stub; `scan_fat_macho` lines 219-303 do linkage but not
      identity).
- [X] User story has a P-priority (P1 — correctness, not polish) and
      a "why this priority" justification.
- [X] Independent Test is concrete (specific binary, observable
      annotations, holistic_parity row IDs).
- [X] Acceptance scenarios use Given/When/Then framing (4 scenarios).
- [X] Edge Cases section names the corner cases (fat-slice UUID
      divergence, multiple LC_RPATH, @rpath / @executable_path,
      LC_BUILD_VERSION vs LC_VERSION_MIN_*, codesign deferred,
      CPU type deferred).
- [X] Functional Requirements numbered (FR-001 through FR-010).
- [X] Key Entities — 3 new BinaryScan fields specified inline in
      FR-002.
- [X] Success Criteria measurable (SC-001 through SC-007), each with
      a verification mechanism.
- [X] Clarifications section captures the 5 scope decisions
      (annotations-not-typed-fields; first-slice-only UUID; min-OS
      format; no codesign; no dSYM resolution).
- [X] Out of Scope names every adjacent concern.

## Tighter spec set rationale (4 files vs 8)

- [X] No `research.md` — recon answered every architectural question
      (5th use of the 4-file template is now well-validated).
- [X] No `data-model.md` — only struct extensions, no new types.
- [X] No `contracts/` — no public surface change beyond catalog rows.
- [X] No `quickstart.md` — 4 short files self-explanatory.

This is the **5th use** of the 4-file template (after 021, 022, 023,
025). Pattern stable for genuinely contained binary-metadata milestones.

## Independence

- [X] Single user story self-contained.
- [X] Each per-commit deliverable (3 commits) is independently
      verifiable (per FR-010 each commit's pre-PR passes).

## Concreteness

- [X] FRs cite specific file paths and line numbers
      (`macho.rs`, `scan_fat_macho` line range, `make_file_level_component`).
- [X] FR-005 names exact bag keys (`mikebom:macho-uuid`,
      `mikebom:macho-rpath`, `mikebom:macho-min-os`).
- [X] FR-001 names exact load-command constants (LC_UUID,
      LC_RPATH, LC_BUILD_VERSION + fallbacks).
- [X] SC-002 names the verification command (`otool -l /bin/ls`).
- [X] SC-004 quantifies the LOC ceiling (350 for macho.rs).
- [X] SC-007 (bag amortization) names the verification command
      (`git diff` against `package_db/`).

## Internal consistency

- [X] FR-001-005 (parsers + BinaryScan + scan.rs + entry.rs bag
      population) flow end-to-end.
- [X] FR-006 + FR-007 (catalog + parity) align with the
      holistic_parity regression gate.
- [X] Edge Case "first-slice-only UUID for fat" aligns with
      Scenario 2 + FR-004.
- [X] SC-002 leans on the existing `class == "macho"` branch in
      scan_binary.rs (which milestone 023 already gated).

## Lessons from milestones 016-025

- [X] FR-010 carries the per-commit-clean discipline.
- [X] Bag-first design (milestone 023) means SC-005 is automatic.
- [X] SC-007 is the second amortization-proof check (after milestone
      025's). Two consecutive milestones consuming the bag without
      churn is the design's payoff.
- [X] Recon-first: every claim in the spec backed by a file:line
      reference from the pre-spec investigation.

## Pre-implementation

- [X] [PHASE-1] T001 reconnaissance done (2026-04-26).
- [ ] [PHASE-1] T002 baseline snapshot captured.
- [ ] [PHASE-2] Commit 1 (parsers) landed.
- [ ] [PHASE-3] Commit 2 (wire-up-bag + scan_binary assertion) landed.
- [ ] [PHASE-4] Commit 3 (parity-rows) landed.
- [ ] [POLISH] SC-001-SC-007 verified.
- [ ] [POLISH] All 3 CI lanes green (macOS lane is SC-002 anchor).

## Post-merge

- [ ] [QUALITATIVE] Next time someone asks "is this the macOS binary
      that crash report references?" the LC_UUID annotation answers
      it directly. If yes, milestone delivered.
