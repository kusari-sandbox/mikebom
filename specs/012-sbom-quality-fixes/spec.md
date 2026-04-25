# Feature Specification: Cross-format SBOM-Quality Fixes

**Feature Branch**: `012-sbom-quality-fixes`
**Created**: 2026-04-25
**Status**: Draft
**Input**: User description: Three issues from a 3-format comparison run (`runs/3format-2026-04-25T00-51-57Z/`): (1) SPDX 3 emits 1/752 CPEs on polyglot fixture vs. 727+/749 in CDX and SPDX 2.3 — the data exists internally, the SPDX 3 emitter drops it; (2) SPDX 2.3 has 22 more components than CDX on polyglot — different dedupe paths suspected; (3) SPDX 2.3 license modeling drops non-canonicalizable expressions to `NOASSERTION` (38/107 licenses on native-linkage), where SPDX 3 preserves them via `simplelicensing_LicenseExpression` — backport an equivalent `LicenseRef-<hash>` + `hasExtractedLicensingInfos` shape to SPDX 2.3.

## Clarifications

### Session 2026-04-25

- Q: When a CycloneDX `licenses[]` array contains a mix of canonicalizable AND non-canonicalizable expressions, what shape does the SPDX 2.3 emitter produce? → A: **All-or-nothing**. If any term in the array fails canonicalization, the whole expression becomes a single `LicenseRef-<hash>` whose `extractedText` is the original entries joined by ` AND `; the Package's `licenseDeclared` is the `LicenseRef-<hash>` string only. Rationale: round-trip-faithful (the consumer sees the exact original input verbatim) and simpler emitter than per-term splitting, with no demonstrated downstream consumer benefit to the more complex shape.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - SPDX 3 carries every CPE that CycloneDX carries (Priority: P1)

A user comparing mikebom's three SBOM outputs side-by-side for the same scan finds that the SPDX 3 output carries the same set of CPE identifiers — by string-equality value — that the CycloneDX output carries. Today, the SPDX 3 output drops nearly all CPE candidates (1/752 on a polyglot container-image fixture, 12/114 on a native-linkage fixture, 1/8 on a small directory fixture) — which makes downstream vulnerability tooling that reads CPEs from SPDX 3 silently miss most components.

**Why this priority**: This is the highest-impact regression because it directly degrades a vulnerability-discovery signal that downstream consumers depend on. Every CPE emitted in CDX and SPDX 2.3 represents a synthesized candidate that mikebom's resolution layer already produced; the SPDX 3 emitter has the data and is dropping it. Fixing this is a single-emitter change that removes the regression without any other format-version impact.

**Independent Test**: For each of mikebom's nine fixture ecosystems, run `mikebom sbom scan --format cyclonedx-json,spdx-3-json --output cyclonedx-json=cdx --output spdx-3-json=spdx3` and assert that for every CycloneDX `component.cpe` value, an equal-string `software_Package.externalIdentifier[].identifier` value (with `externalIdentifierType: "cpe23"`) appears in SPDX 3 on the matching Package.

**Acceptance Scenarios**:

1. **Given** a scan that produces N CycloneDX components carrying CPE identifiers, **When** the same scan emits SPDX 3, **Then** the count of `cpe23`-typed `ExternalIdentifier` entries across all SPDX 3 `software_Package` elements is ≥ N (allowing for the synthetic-root Package's own CPE to add 1).
2. **Given** the polyglot-builder-image fixture, **When** mikebom emits all three formats in a single scan, **Then** the SPDX 3 CPE count is within 1 of the CycloneDX CPE count (synthetic root accounts for the off-by-one).
3. **Given** the same component identified by the same PURL appears in both the CycloneDX and SPDX 3 output, **When** that component carried one or more CPE strings in CDX, **Then** every one of those CPE strings appears as the `identifier` of a `cpe23` `ExternalIdentifier` entry on the matching SPDX 3 `software_Package`.

---

### User Story 2 - SPDX 2.3 component count matches CycloneDX component count (Priority: P2)

A user comparing component counts across the three formats for the same scan finds that the CycloneDX and SPDX 2.3 outputs agree on the set of components — same count, same PURLs. Today the polyglot-builder-image scan emits 729 components in CDX but 751 in SPDX 2.3, a 22-component drift attributable to a divergent dedupe or filtering path between the two emitters.

**Why this priority**: This is a correctness gap, not a regression — the formats have always disagreed on this fixture. But it's load-bearing for the milestone-010 SC-003 / FR-017 native-field parity guarantee (`every CycloneDX component appears as exactly one SPDX 2.3 Package, with matching PURL and checksum values`). The current parity test passes because it walks CDX → SPDX one-way; the reverse drift hides under that one-directional assertion. Fixing this restores end-to-end count parity and reveals (or rules out) any latent dedupe bugs.

**Independent Test**: For each of mikebom's nine fixture ecosystems plus the polyglot-builder-image fixture, run `mikebom sbom scan --format cyclonedx-json,spdx-2.3-json` once and assert the count of CycloneDX `components[]` entries (including nested `components[].components[]`) equals the count of SPDX 2.3 `packages[]` entries minus the synthetic root Package.

**Acceptance Scenarios**:

1. **Given** the polyglot-builder-image fixture, **When** mikebom emits both CycloneDX and SPDX 2.3 in a single scan, **Then** the component count in CDX equals the package count in SPDX 2.3 minus 1 (the synthetic root).
2. **Given** any of the nine ecosystem fixtures, **When** mikebom emits both formats, **Then** the component count in CDX equals the package count in SPDX 2.3 minus 1.
3. **Given** a fixture that exposes the dedupe-path divergence (the polyglot-builder-image case), **When** the underlying root cause is identified and fixed, **Then** the fix is documented in the milestone's research record so future contributors see the divergence and the resolution.

---

### User Story 3 - SPDX 2.3 preserves every license expression CycloneDX carries (Priority: P3)

A user reading the SPDX 2.3 output for a scan that includes components with non-SPDX-valid license expressions (e.g., `"GNU General Public"`, `"Apache 2"`, free-text human-readable license strings that the SPDX expression grammar doesn't accept) finds those expressions preserved in the SPDX 2.3 document instead of silently collapsed to `NOASSERTION`. Today the native-linkage fixture's SPDX 2.3 output carries 38 licenses where CDX and SPDX 3 carry 107 — a 64% loss of license-detection signal for that fixture.

**Why this priority**: Closing a documented data-loss gap. SPDX 2.3 has a native mechanism (`hasExtractedLicensingInfos[]` carrying `licenseId: LicenseRef-<hash>` + `extractedText: <raw expression>`, with the Package's `licenseDeclared` set to the `LicenseRef-<hash>`) for exactly this case — the milestone-010 SPDX 2.3 emitter just doesn't use it. The SPDX 3 emitter (milestone 011) preserves all expressions via `simplelicensing_LicenseExpression`'s text-passthrough mode; backporting the equivalent shape to SPDX 2.3 closes the format-version inconsistency.

**Independent Test**: For each of mikebom's nine fixture ecosystems, run `mikebom sbom scan --format cyclonedx-json,spdx-2.3-json` and assert that the count of components carrying any `licenses[]` entry in CDX equals the count of SPDX 2.3 packages whose `licenseDeclared` is NOT the literal `NOASSERTION` (modulo legitimately-empty-license components, which are also `NOASSERTION` in CDX).

**Acceptance Scenarios**:

1. **Given** a scan whose components include a component carrying a license expression that the SPDX expression grammar cannot canonicalize (e.g., the literal string `"GNU General Public"`), **When** mikebom emits SPDX 2.3, **Then** the corresponding `Package` has `licenseDeclared: "LicenseRef-<deterministic-hash>"` and the document's `hasExtractedLicensingInfos[]` array carries an entry with `licenseId: "LicenseRef-<same-hash>"`, `extractedText: "GNU General Public"`, and `name` populated.
2. **Given** the native-linkage fixture, **When** mikebom emits SPDX 2.3, **Then** the count of Packages with non-`NOASSERTION` `licenseDeclared` equals the count of Packages with non-empty CDX `licenses[]` (107 on native-linkage, vs. 38 today).
3. **Given** a component with an SPDX-valid license expression (e.g., `"MIT"`), **When** mikebom emits SPDX 2.3, **Then** `licenseDeclared` is the canonical SPDX expression string verbatim (no `LicenseRef-` wrapping); the `LicenseRef-<hash>` shape only applies to non-canonicalizable expressions.

---

### Edge Cases

- A component carries a license expression whose canonicalization succeeds in one format and fails in another (mikebom uses one canonicalizer for both formats, so this should not happen — but the test suite should fail loudly if it does, e.g., via a parity assertion that treats the canonicalized form and the raw form as functionally equal for downstream consumers).
- A component carries multiple license expressions in CycloneDX `licenses[]` where some canonicalize and some don't — SPDX 2.3 emits **one** `LicenseRef-<hash>` covering the whole expression (all-or-nothing rule per clarification Q1). `extractedText` is the original entries joined by ` AND `; `licenseDeclared` is just the `LicenseRef-<hash>` string. The canonical terms are preserved inside `extractedText` verbatim and recoverable by a consumer that re-parses the joined string.
- A scan produces zero components — the SPDX 2.3 `hasExtractedLicensingInfos[]` is absent (not an empty array), matching the SPDX schema's optional-field convention.
- The CycloneDX output carries a CPE string that is itself non-canonical (e.g., a malformed CPE 2.3 vector) — both formats emit it verbatim or both formats reject it; consistency wins. The behavior on malformed CPEs is the same in CycloneDX, SPDX 2.3, and SPDX 3.
- A component appears under one PURL in CDX and under a different PURL in SPDX 2.3 because the dedupe path filtered differently — this is the kind of case the User Story 2 fix is designed to surface and resolve (or document with a stable cross-format identifier).
- A user pinning per-component byte-for-byte goldens (e.g., for reproducible-build attestation) against an existing milestone-010 or milestone-011 release sees byte changes after the fixes ship — the goldens regenerate cleanly. The fix increases SBOM-quality scores; consumers regenerating goldens is part of the upgrade path.

## Requirements *(mandatory)*

### Functional Requirements

#### SPDX 3 CPE coverage

- **FR-001**: For every component the resolution layer emits with a CPE 2.3 candidate, the SPDX 3 output MUST emit one `software_Package.externalIdentifier[]` entry with `externalIdentifierType: "cpe23"` and `identifier: <CPE string>` for every CPE string the CycloneDX output emits for that component.
- **FR-002**: The SPDX 3 emitter's CPE-acceptance rule MUST treat as emittable any CPE 2.3 vector whose `part`, `vendor`, `product`, and `version` slots are non-wildcard. Wildcards in the remaining slots (`update`, `edition`, `language`, `sw_edition`, `target_sw`, `target_hw`, `other`) MUST NOT cause the CPE to be dropped — those slots commonly carry legitimate `*` "any" markers in real-world CPEs.
- **FR-003**: For components with multiple CPE candidates, every candidate that satisfies FR-002 MUST be emitted as a separate `cpe23` entry; the order MUST be deterministic.

#### CDX ↔ SPDX 2.3 component-count parity

- **FR-004**: For any scan, the count of components in the CycloneDX output (including those nested under `components[].components[]`) MUST equal the count of `software_Package` / `Package` elements in the SPDX 2.3 output minus the synthetic root Package.
- **FR-005**: Component-set parity MUST be enforced as a CI gate in addition to the existing one-directional native-field parity check (milestone-010 `spdx_cdx_parity.rs`); the new check fires when SPDX 2.3 carries a Package whose PURL has no matching CycloneDX component.
- **FR-006**: When the dedupe-path divergence is identified, its root cause MUST be documented in the milestone's research record so the resolution rationale is reviewable; both emitters MUST converge on a single shared dedupe path.

#### SPDX 2.3 LicenseRef preservation

- **FR-007**: When a component carries one or more license expressions in CycloneDX, but those expressions cannot be reduced to a canonical SPDX expression by the existing canonicalizer, the SPDX 2.3 output MUST emit the raw expression(s) verbatim instead of collapsing to `NOASSERTION`. The mechanism MUST be the SPDX 2.3 native `hasExtractedLicensingInfos[]` array carrying `licenseId: "LicenseRef-<deterministic-hash>"`, `extractedText: <raw expression>`, and a populated `name` field; the Package's `licenseDeclared` MUST be set to the same `LicenseRef-<hash>` string.
- **FR-008**: For components whose license expressions DO canonicalize, the existing emission shape MUST be preserved verbatim — `licenseDeclared` is the canonical SPDX expression string, no `LicenseRef-` wrapping, no `hasExtractedLicensingInfos[]` entry generated.
- **FR-009**: The `LicenseRef-<hash>` derivation MUST be deterministic: the same raw expression yields the same `LicenseRef-<hash>` across runs, across machines, and across mikebom versions.
- **FR-010**: License expressions involving multiple terms — whether all of them fail canonicalization OR any subset of them fails — MUST be reduced to a single `LicenseRef-<hash>` whose `extractedText` is the original entries joined by ` AND ` (all-or-nothing rule per clarification Q1). The Package's `licenseDeclared` is the `LicenseRef-<hash>` string only — there is NO mixed `licenseDeclared` of the form `"MIT AND LicenseRef-<x>"`. This keeps the emitter shape simple and the downstream-consumer parse path uniform: any non-canonicalizable component in a multi-term expression triggers the LicenseRef path for the whole expression.

#### Cross-format consistency

- **FR-011**: All three fixes MUST preserve the existing milestone-010 and milestone-011 byte-determinism guarantees: two runs of the same scan produce byte-identical output after timestamp and document-identifier normalization.
- **FR-012**: All three fixes MUST preserve the existing format-mapping doc (`docs/reference/sbom-format-mapping.md`) — every row's three-column entries remain present; the SPDX 2.3 LicenseRef row gets a concrete description (was implicit before; now explicit).
- **FR-013**: All three fixes MUST be opt-off-safe: a user who does not request the affected format experiences no behavior change.

### Key Entities *(include if feature involves data)*

- **CPE 2.3 vector**: A 13-segment colon-delimited identifier of the form `cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>`. Mikebom's resolution layer synthesizes one or more candidates per discovered component; the emitter chooses which to surface in each format.
- **Synthetic root Package**: The mikebom-emitted Package whose PURL is `pkg:generic/<scan-target>@0.0.0` and SPDXID is `SPDXRef-DocumentRoot-<...>` (SPDX 2.3) or `<doc IRI>/pkg-root-<...>` (SPDX 3). It exists for sbomqs scoring parity and has no CycloneDX component analogue. Component-count comparisons subtract 1 to account for it.
- **`LicenseRef-<hash>`**: The SPDX 2.3 `hasExtractedLicensingInfos[]` shape. `<hash>` is a deterministic content-addressed prefix of the raw expression; the same expression yields the same hash everywhere.
- **`hasExtractedLicensingInfos[]`**: A document-level SPDX 2.3 array holding `{licenseId, extractedText, name}` entries — the SPDX-spec native mechanism for carrying license expressions that don't fit the SPDX expression grammar.
- **mikebom-shared canonicalizer**: The existing `spdx::Expression::try_canonical(&str)` call site shared between the SPDX 2.3 and SPDX 3 emitters. The boundary between "canonical" and "extracted-text" is determined by this function's success/failure.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For every fixture in mikebom's test matrix, the count of distinct CPE strings in the SPDX 3 output equals the count of distinct CPE strings in the CycloneDX output for the same scan, plus or minus 1 (the synthetic root's own CPE). Enforced on the 9-ecosystem fixture matrix in CI; verifiable manually on external fixtures per the Assumptions section.
- **SC-002**: Reviewer-verifiable on external fixtures: for the `polyglot-builder-image` container-image fixture cited in the milestone's input report, the SPDX 3 CPE count rises from the current 1 to match the CycloneDX CPE count ±1 (currently 727 in CDX). The CI proxy for this invariant is SC-001, which enforces the same ratio on the 9-ecosystem matrix.
- **SC-003**: For every fixture in mikebom's test matrix, the count of components in the CycloneDX output (recursively flattened across `components[].components[]`) equals the count of `Package` elements in the SPDX 2.3 output minus the synthetic root (0 or 1).
- **SC-004**: Reviewer-verifiable on external fixtures: for the `polyglot-builder-image` fixture, the SPDX 2.3 package-count vs. **flattened** CycloneDX component-count drift drops from the currently-reported +22 to 0. The CI proxy for this invariant is SC-003's bidirectional test on the 9-ecosystem matrix. (Note: the +22 drift in the input report was measured against *top-level* CDX component count, not flattened — see `research.md` §R2 for the structural explanation.)
- **SC-005**: For every fixture in mikebom's test matrix, the count of SPDX 2.3 `Package` elements with non-`NOASSERTION` `licenseDeclared` equals the count of CycloneDX components with non-empty `licenses[]`.
- **SC-006**: Reviewer-verifiable on external fixtures: for the `native-linkage` container-image fixture cited in the milestone's input report, the SPDX 2.3 license count rises from the current 38 to match the CycloneDX baseline (currently 107). The CI proxy for this invariant is SC-005 on the 9-ecosystem matrix.
- **SC-007**: Two runs of the same scan produce byte-identical output across all three formats after timestamp + document-identifier normalization (FR-011 — milestone-010 / milestone-011 determinism guarantee preserved).
- **SC-008**: A user who does not request the affected format experiences no measurable change in their existing pipeline (FR-013 — opt-off invariant preserved).
- **SC-009**: sbomqs's `comp_with_cpe` feature score for SPDX 3 outputs rises to within 0.5 of the score for the CycloneDX output across all 9 ecosystem fixtures — **enforcement auto-activates** when upstream sbomqs adds SPDX 3 parsing support. sbomqs v2.0.6 (the CI-pinned version) does not yet parse SPDX 3 and the milestone-011 `sbomqs_parity.rs::SbomqsScoreResult::Unsupported` path graceful-skips SPDX 3 scoring; when sbomqs publishes a version with a SPDX 3 reader, the existing CI wiring picks it up automatically without a code change and SC-009 becomes enforceable.

## Assumptions

- The CPE-coverage bug is in mikebom's `is_fully_resolved_cpe23` helper in `mikebom-cli/src/generate/spdx/v3_external_ids.rs`. The function currently checks parts[2..7] (part, vendor, product, version, **update**) for non-wildcard; including `update` rejects nearly all real-world CPEs since the synthesizer leaves `update` as `*`. The fix is to check parts[2..6] (drop the update slot from the check).
- The 22-component drift between CDX and SPDX 2.3 on the polyglot fixture is a single shared root cause — likely a different dedupe path between the two emitters, or a different filter applied to nested vs. top-level components. The investigation is part of US2's scope; the fix may be a single-helper refactor (one shared dedupe function) or a clearer documentation of why the divergence is intentional.
- The SPDX 2.3 LicenseRef backport reuses the same content-addressed-hash pattern that other mikebom IRIs use. The hash input is the raw expression string; the prefix length matches the existing `SpdxId::for_purl` prefix length (16 chars BASE32 = 80 bits — far below collision threshold for a typical scan's distinct license-expression set).
- All three fixes are independent of each other and can ship as separate increments. The scope of this milestone is bug-fixes-only — no new emitter formats, no new mikebom-namespaced fields, no new external dependencies. Existing tests (CDX↔SPDX 2.3 parity, SPDX 3 schema validation, format-mapping coverage) gain new assertions but no test files are deleted.
- The fixes increase SBOM-quality (sbomqs) scores for SPDX 2.3 and SPDX 3 across multiple fixtures. Specifically: the native-linkage SPDX 2.3 score is expected to rise from 8.00 (B) toward parity with the CycloneDX 8.70 (B); the SPDX 3 score gap (currently un-measured because sbomqs v2.0.6 doesn't parse SPDX 3) is closed for the CPE feature when sbomqs adds SPDX 3 support.
- All three fixes preserve backwards compatibility with the milestone-011 contract `contracts/spdx-3-emitter.contract.md` and the milestone-010 contract analogues. No contract revisions are required.
- The container-image fixtures named in SC-002 / SC-004 / SC-006 (`polyglot-builder-image`, `native-linkage`) are external to the repo's `tests/fixtures/` tree — they were used in the milestone's originating comparison run (`runs/3format-2026-04-25T00-51-57Z/`) but aren't checked in. The CI test matrix enforces the same invariants on the 9-ecosystem fixture set via the per-fixture forms (SC-001 / SC-003 / SC-005); the external-fixture SCs document the reviewer-verifiable end-state and don't require fixture additions to this milestone. Adding the external fixtures to `tests/fixtures/` is a separate repo-tooling concern outside this milestone's scope.
