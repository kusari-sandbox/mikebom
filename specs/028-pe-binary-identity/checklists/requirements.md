# Spec Quality Checklist: PE Binary Identity

**Checklist for** `/specs/028-pe-binary-identity/spec.md`

## Coverage

- [X] Background section explains why three specific PE identity
      signals are missing today + cites file:line evidence (`pe.rs`
      = 6-line stub; `scan.rs:117` for has_debug_symbols PE arm,
      `scan.rs:213` for `.rdata` PE arm). Confirms `object` 0.36
      provides `pdb_info()` (file.rs:348) + IMAGE_* constants.
- [X] User story has a P-priority (P1 — correctness, not polish) and
      a "why this priority" justification grounded in the same
      data-quality argument that 023 + 024 made.
- [X] Independent Test is concrete (specific test paths,
      observable annotations, holistic_parity row IDs).
- [X] Acceptance scenarios use Given/When/Then framing (4 scenarios).
- [X] Edge Cases section names corner cases (CodeView record types,
      stripped binaries, forwarder DLLs, unknown machine type,
      unknown subsystem, PDB filename in CodeView, endianness,
      PE32 vs PE32+).
- [X] Functional Requirements numbered (FR-001 through FR-010).
- [X] Key Entities — 3 new BinaryScan fields specified inline in
      FR-002.
- [X] Success Criteria measurable (SC-001 through SC-007), each with
      a verification mechanism.
- [X] Clarifications section captures the 5 scope decisions
      (PDB-id format `<guid>:<age>` not concatenated; machine +
      subsystem as strings; no PDB filename; no Authenticode;
      no Rich header; no DllCharacteristics).
- [X] Out of Scope names every adjacent concern.

## Tighter spec set rationale (4 files vs 8)

- [X] No `research.md` — recon answered every architectural question
      (6th use of the 4-file template — pattern fully validated).
- [X] No `data-model.md` — only struct extensions, no new types.
- [X] No `contracts/` — no public surface change beyond catalog rows.
- [X] No `quickstart.md` — 4 short files self-explanatory.

This is the **6th use** of the 4-file template (after 021, 022, 023,
024, 025). Pattern stable for genuinely contained binary-metadata
milestones.

## Independence

- [X] Single user story self-contained.
- [X] Each per-commit deliverable (3 commits) is independently
      verifiable (per FR-010 each commit's pre-PR passes).

## Concreteness

- [X] FRs cite specific file paths and line numbers
      (`pe.rs`, `scan.rs:117 + 213`, `entry.rs::BinaryScan`,
      `entry.rs:597` for fake_binary_scan).
- [X] FR-004 names exact bag keys (`mikebom:pe-pdb-id`,
      `mikebom:pe-machine`, `mikebom:pe-subsystem`).
- [X] FR-001 names exact `object` API entry points
      (`PeFile::pdb_info`, `nt_headers().file_header().machine`,
      `optional_header().subsystem()`).
- [X] SC-004 quantifies the LOC ceiling (250 for pe.rs — tighter than
      023's 420 / 024's 350 because `object` provides typed accessors).
- [X] SC-007 (bag amortization) names the verification command (27-
      golden regen).

## Internal consistency

- [X] FR-001-004 (parsers + BinaryScan + scan.rs + entry.rs bag
      population) flow end-to-end.
- [X] FR-005 + FR-006 (catalog + parity) align with the
      holistic_parity regression gate.
- [X] Edge Case "PE32 vs PE32+" aligns with FR-001's `ImageNtHeaders`
      generic + FR-003's PeFile32/PeFile64 dispatch.
- [X] Edge Case "absent CodeView" aligns with Scenario 4 + FR-004's
      "skip emission" clause.

## Lessons from milestones 016-027

- [X] FR-010 carries the per-commit-clean discipline.
- [X] Bag-first design (milestone 023) means SC-005 is automatic.
- [X] SC-007 is the third amortization-proof check (after milestones
      024 + 025). Three consecutive milestones consuming the bag
      without churn is the design's payoff.
- [X] Recon-first: every claim in the spec backed by a file:line
      reference from the pre-spec investigation.
- [X] R1 in plan.md (CodeView accessor visibility) anticipates the
      same kind of "object-crate API surface gotcha" pattern that
      could derail a milestone if discovered mid-implementation.

## Pre-implementation

- [X] [PHASE-1] T001 reconnaissance done (2026-04-26).
- [ ] [PHASE-1] T002 baseline snapshot captured.
- [ ] [PHASE-2] Commit 1 (parsers) landed.
- [ ] [PHASE-3] Commit 2 (wire-up-bag) landed.
- [ ] [PHASE-4] Commit 3 (parity-rows) landed.
- [ ] [POLISH] SC-001-SC-007 verified.
- [ ] [POLISH] All 3 CI lanes green.

## Post-merge

- [ ] [QUALITATIVE] Next time someone asks "is this the same Windows
      binary across two MSI installers?" or "what's the symbol-server
      key for this .exe?", the pe-pdb-id annotation answers it
      directly. If yes, milestone delivered.
