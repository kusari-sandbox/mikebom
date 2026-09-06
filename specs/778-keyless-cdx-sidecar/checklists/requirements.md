# Specification Quality Checklist: Keyless CycloneDX Signing via Detached Sidecar

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-09-06
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No implementation details (languages, frameworks, APIs)
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
- [x] All mandatory sections completed

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Success criteria are technology-agnostic (no implementation details)
- [x] All acceptance scenarios are defined
- [x] Edge cases are identified
- [x] Scope is clearly bounded
- [x] Dependencies and assumptions identified

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria
- [x] User scenarios cover primary flows
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification

## Notes

- All items pass. The single [NEEDS CLARIFICATION] marker on FR-012
  (the form the signature-location record should take) was resolved to
  a relative name with no directory component. FR-012 was rewritten,
  FR-012a and SC-009 were added, and two User Story 2 acceptance
  scenarios now pin the chosen form.
- Content Quality: the spec deliberately avoids naming the signing
  ecosystem's products, file extensions, function names, and CLI flags,
  describing them by role instead ("companion signature artifact",
  "standard verification tooling"). The technical specifics live in
  issue #804 and belong in the plan, not the spec.
- The spec's Context restates why the embedded option was rejected.
  That reasoning was established and verified during milestone 777;
  it is repeated here because a reader of this spec alone would
  otherwise have no way to judge whether the sidecar choice is sound.
- An assumption records that the signature reference aids discovery and
  does NOT improve quality-scorer results, so a later reader does not
  mistake it for a fix to the score that motivated milestone 777.

## Clarify pass — 2026-09-06

Ran `/speckit.clarify`. **Zero questions asked**: the ambiguity scan
found four gaps, and each was either already forced by an existing
requirement or had a single answer verifiable from the code, so none
warranted a decision from the user. All four were recorded instead:

- **FR-004a** — the signed payload is the document's bytes exactly as
  written, not a canonicalization. Forced by FR-004 (no
  waybill-specific verifier tooling) and confirmed against the SPDX
  keyless path, which signs raw bytes. Stated explicitly because the
  same source file also contains milestone 777's canonicalize-then-sign
  pattern, which a planner could reasonably reach for by analogy and
  which would break FR-004.
- **FR-016 / SC-010** — an operator-visible summary of what was signed
  and where. Missing from the Non-Functional/Observability category;
  matches the summary-log convention every comparable milestone follows,
  so defaulted rather than asked.
- **Edge case: no checksum on the signature reference.** Circular by
  construction — the artifact signs the document, so the document
  cannot contain the artifact's hash. Recorded because the idea is
  attractive and the circularity is only obvious once attempted.
- **Edge case: split output cannot co-occur with signing.** Signing
  requires a single output path; split requires an output directory and
  forbids a single path. Verified in `scan_cmd.rs`. Recorded so nobody
  builds multi-document companion-artifact machinery for a case that
  cannot arise.
