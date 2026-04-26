# Spec Quality Checklist: Go VCS Metadata

**Checklist for** `/specs/025-go-vcs-metadata/spec.md`

## Coverage

- [X] Background section explains why the data is missing today + cites
      file:line evidence (`go_binary.rs:346` `parse_go_version_from_build_info`
      reads only first line; subsequent lines have VCS keys but discarded).
- [X] User story has a P-priority (P2 — data already recoverable via
      `go version -m`, this surfaces in SBOM) and a "why this priority"
      justification.
- [X] Independent Test is concrete (specific BuildInfo build helper,
      observable annotations, holistic_parity row IDs).
- [X] Acceptance scenarios use Given/When/Then framing (4 scenarios:
      clean build, dirty build, VCS-disabled build, dep entries
      unaffected).
- [X] Edge Cases section names corner cases (mixed VCS, truncated, TAB
      vs space, non-ASCII, trailing whitespace, multiple lines for same
      key).
- [X] Functional Requirements numbered (FR-001 through FR-010).
- [X] Key Entities — `GoVcsInfo` struct introduced (3 fields).
- [X] Success Criteria measurable (SC-001 through SC-007), each with a
      verification mechanism.
- [X] Clarifications section captures the 4 scope decisions
      (annotations vs typed fields; "true"/"false" string format;
      vcs.system deferred; main-module-only).
- [X] Out of Scope names every adjacent concern.

## Tighter spec set rationale (4 files vs 8)

- [X] No `research.md` — recon answered every architectural question;
      the bag-design lessons from milestone 023 carry forward directly.
- [X] No `data-model.md` — only one new struct (GoVcsInfo, 3 fields).
      Specified inline in FR-001.
- [X] No `contracts/` — no public surface change beyond the added
      catalog rows; FR-007 / FR-008 enforce.
- [X] No `quickstart.md` — 4 short files self-explanatory.

This is the fourth use of the 4-file template (after 021, 022, 023).
Pattern stable for genuinely contained milestones.

## Independence

- [X] Single user story self-contained.
- [X] Each per-commit deliverable (3 commits) is independently
      verifiable (per FR-010 each commit's `./scripts/pre-pr.sh`
      passes).

## Concreteness

- [X] FRs cite specific file paths and line numbers
      (`go_binary.rs:346`, `:179`, `:587`, `:623`).
- [X] FR-005 names exact bag keys (`mikebom:go-vcs-revision`,
      `mikebom:go-vcs-time`, `mikebom:go-vcs-modified`).
- [X] SC-004 quantifies the LOC ceiling (1600 for go_binary.rs).
- [X] SC-007 names the verification command (file paths to grep
      against).

## Internal consistency

- [X] FR-001-004 (GoVcsInfo + GoBinaryInfo + parser + decode) flow
      end-to-end into FR-005 (bag population).
- [X] FR-006 (dep entries unaffected) aligns with Scenario 4.
- [X] FR-007 + FR-008 (catalog + parity) align with the
      holistic_parity regression gate.
- [X] Edge Case "VCS-disabled build" aligns with FR-005's "skip
      insertion when None" + Scenario 3.

## Lessons from milestones 016-023

- [X] FR-010 carries the per-commit-clean discipline (021, 022, 023).
- [X] Bag-first design (milestone 023) means SC-005 is automatic — no
      `generate/` plumbing because the bag already does it.
- [X] SC-007 is the "amortization proof" — explicitly verifies the
      milestone-023 bag pattern paid its dividend.
- [X] Recon-first: every claim in the spec backed by a file:line
      reference from the pre-spec investigation.

## Pre-implementation

- [X] [PHASE-1] T001 reconnaissance done (2026-04-26).
- [ ] [PHASE-1] T002 baseline snapshot captured.
- [ ] [PHASE-2] Commit 1 (parser) landed.
- [ ] [PHASE-3] Commit 2 (wire-up-bag) landed.
- [ ] [PHASE-4] Commit 3 (parity-rows) landed.
- [ ] [POLISH] SC-001-SC-007 verified.
- [ ] [POLISH] All 3 CI lanes green.

## Post-merge

- [ ] [QUALITATIVE] Next time someone asks "what commit was this Go
      service built from?" the SBOM answers it directly. If yes,
      milestone delivered.
