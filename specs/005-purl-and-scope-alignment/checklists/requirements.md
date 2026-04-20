# Specification Quality Checklist: PURL & Scope Alignment

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-04-20
**Feature**: [spec.md](../spec.md)

## Content Quality

- [X] No implementation details (languages, frameworks, APIs)
- [X] Focused on user value and business needs
- [X] Written for non-technical stakeholders
- [X] All mandatory sections completed

## Requirement Completeness

- [X] No [NEEDS CLARIFICATION] markers remain
- [X] Requirements are testable and unambiguous
- [X] Success criteria are measurable
- [X] Success criteria are technology-agnostic (no implementation details)
- [X] All acceptance scenarios are defined
- [X] Edge cases are identified
- [X] Scope is clearly bounded
- [X] Dependencies and assumptions identified

## Feature Readiness

- [X] All functional requirements have clear acceptance criteria
- [X] User scenarios cover primary flows
- [X] Feature meets measurable outcomes defined in Success Criteria
- [X] No implementation details leak into specification

## Notes

- This spec covers four correctness fixes. Each is testable independently; US1 (npm scoping) and US4 (RPM version alignment) are the narrowest since they don't depend on the os-release-driven plumbing that US2+US3 share.
- US2 and US3 together imply `/etc/os-release` parsing is already plumbed through the deb reader (it is — for `VERSION_CODENAME`). The change is switching which fields are used, not adding new I/O.
- US4's requirement to produce a root-cause analysis BEFORE the fix (FR-014) is deliberate — earlier rounds of this project showed that PURL shape changes made without diagnosis create long debugging cycles.
- Spec is silent on whether mikebom's older Alpine/RPM fixtures need their ground-truth PURLs regenerated. That's a conformance-suite concern, not a mikebom concern. Conformance baselines may need updating to match the new deb PURL shape (US2, US3) — this is called out in SC-007 as a regression guard but not as an FR.

## Clarifications Resolved (Session 2026-04-20)

- **npm-internals path pattern**: Canonical glob `**/node_modules/npm/node_modules/**` (FR-001, FR-002).
- **npm-internals tagging property**: `mikebom:npm-role=internal` as a normative CycloneDX property (FR-004). Future-generalisation tracked as follow-up todo.
- **os-release diagnostic surfacing**: CycloneDX `metadata.properties` entry `mikebom:os-release-missing-fields` with comma-joined value (FR-006, FR-009, SC-009). Standard-spec-field migration tracked as follow-up todo.
