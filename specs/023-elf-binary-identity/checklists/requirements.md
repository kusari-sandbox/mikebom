# Spec Quality Checklist: ELF Binary Identity

**Checklist for** `/specs/023-elf-binary-identity/spec.md`

## Coverage

- [X] Background section explains why three specific ELF identity signals are
      missing today + cites file:line evidence (`elf.rs:43-79` for the existing
      pattern; absence verified in pre-spec recon).
- [X] User story has a P-priority (P1 — correctness, not polish) and a
      "why this priority" justification.
- [X] Independent Test is concrete (specific fixtures + observable annotations
      + holistic_parity row IDs).
- [X] Acceptance scenarios use Given/When/Then framing (4 scenarios).
- [X] Edge Cases section names the corner cases (build-id formats, dual
      RPATH/RUNPATH, $ORIGIN, CRC32, fat ELF non-existence, corrupt notes).
- [X] Functional Requirements numbered (FR-001 through FR-010).
- [X] Key Entities — DebuglinkEntry struct introduced (small; lives in
      binary/entry.rs).
- [X] Success Criteria measurable (SC-001 through SC-006), each with a
      verification mechanism.
- [X] Clarifications section captures the 4 scope decisions (annotations vs
      fields; no $ORIGIN expansion; no CRC32 verify; no debuginfod lookup).
- [X] Out of Scope names every adjacent concern (Mach-O, PE, Go VCS, Rust
      auditable, container layers, dedup-at-scan-time).

## Tighter spec set rationale (4 files vs 8)

- [X] No `research.md` — recon answered every architectural question; the
      bag-first design discovery happened mid-implementation and was
      captured as a spec amendment rather than a separate research file.
- [~] `data-model.md` would be appropriate for the bag's contract.
      Inlined in spec.md FR-001-FR-007 instead. Acceptable for this scope.
- [~] `contracts/` would be appropriate for the bag's emission contract
      across CDX/SPDX 2.3/SPDX 3. Inlined as FR-005, FR-006, FR-007.
- [X] No `quickstart.md` — 4 short files self-explanatory.

This is the third use of the 4-file template (after 021, 022). Spec was
amended mid-implementation when scope discovery showed PackageDbEntry has
35 init sites and emission flows through generate/. Amendment landed in a
follow-up commit before any non-extractor code touched main.

## Independence

- [X] Single user story self-contained.
- [X] Each per-commit deliverable independently verifiable (per FR-008 each
      commit's `./scripts/pre-pr.sh` passes).

## Concreteness

- [X] FRs cite specific file paths and line numbers.
- [X] FR-001 names the exact extractor signatures.
- [X] FR-002 names the exact field types.
- [X] SC-004 quantifies the LOC ceiling (420 for elf.rs).
- [X] SC-001 names the verification commands verbatim.

## Internal consistency

- [X] FR-001 (extractors) align with FR-002 (BinaryScan fields) align with
      FR-003 (scan_binary call sites) align with FR-004 (mod.rs annotation
      emission).
- [X] FR-005 + FR-006 (catalog + parity) align with the holistic_parity
      regression gate in FR-009.
- [X] Edge Case "absent fields don't produce empty annotations" aligns with
      FR-004's "skip emission" clause.

## Lessons from milestones 016-022

- [X] FR-008 carries the per-commit-clean discipline.
- [X] R3 in plan.md (deterministic fixtures) anticipates the same kind of
      "fixtures break under non-determinism" pitfall we hit on 022.
- [X] The annotation-emission path uses the exact same envelope decoder
      (`extract_mikebom_annotation_values`) and CDX-property writer
      (`cdx_property_values`) that 022 just unified — no new infrastructure.
- [X] Recon-first: every claim in the spec backed by a file:line reference
      from the pre-spec investigation.

## Pre-implementation (revised — bag-first phasing)

- [X] [PHASE-1] T001 reconnaissance done (2026-04-26) + bag-first amendment
      after mid-implementation scope discovery.
- [X] [PHASE-1] T002 baseline snapshot captured (1217 tests).
- [X] [PHASE-2] Commit 1 (`023/extractors`, `e0d658e`) landed — ELF parsers
      with 13 inline tests, dead_code allowed.
- [ ] [PHASE-3] Commit 2 (`023/extra-annotations-bag`) landed — bag end-to-end.
- [ ] [PHASE-4] Commit 3 (`023/wire-up-elf-identity`) landed — first consumer.
- [ ] [PHASE-5] Commit 4 (`023/parity-rows`) landed.
- [ ] [POLISH] SC-001-SC-008 verified.
- [ ] [POLISH] All 3 CI lanes green.

## Post-merge

- [ ] [QUALITATIVE] Next time someone asks "is this the same binary across
      these two layers?" the build-id annotation answers it directly. If yes,
      milestone delivered.
