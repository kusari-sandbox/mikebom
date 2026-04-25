# Feature Specification: Holistic Cross-Format Output Parity

**Feature Branch**: `013-format-parity-enforcement`
**Created**: 2026-04-25
**Status**: Draft
**Input**: User description: "Can we ensure that the various output formats have parity? They should all have equivalent outputs. So the data should be very similar, just formatting and structure should be different."

## Clarifications

### Session 2026-04-25

- Q: How does the parity test distinguish "universal parity" from "format-restricted" catalog rows? → A: **Implicit text match**. Parse the existing three-column mapping doc; any row whose CycloneDX / SPDX-2.3 / SPDX-3 column contains `omitted — <reason>` or `defer — <reason>` is classified "format-restricted" (with the reason following the em-dash); every other row is "universal parity." No new doc structure (no 5th column, no sidecar file); zero structural change to the existing mapping doc; test parser is a simple line-by-line regex over markdown table rows.
- Q: Does the parity test enforce bidirectional catalog-to-emitter correspondence, or one-directional only? → A: **Both directions**. The test asserts (1) every emitted CycloneDX property name has a catalog row (auto-discovery direction — FR-005/006), AND (2) every catalog row marked "universal parity" has its CycloneDX property actually present in at least one of the 9 ecosystem fixtures' outputs (catalog-to-emitter direction — catches orphan catalog rows left over from deleted / never-implemented properties). Symmetric coverage makes the catalog a true spec of emitter behavior rather than a "likely-current" reference.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - One unified parity guarantee across all formats (Priority: P1)

A platform-security engineer running `mikebom sbom scan` and emitting all three output formats in a single invocation — CycloneDX 1.6, SPDX 2.3, and SPDX 3.0.1 — can rely on a single, documented guarantee: every piece of data mikebom discovers about a scan surfaces in all three formats. The formats differ in *structure* (where the datum lives in the JSON tree) and *encoding* (e.g., CPE-2.3 enum values differ between SPDX 2.3 `SECURITY/cpe23Type` and SPDX 3's `ExternalIdentifier[cpe23]`), but the *set of facts* about the scan is the same. A consumer who picks any one of the three formats gets the complete mikebom signal for their scan, not a strict subset.

**Why this priority**: Today the parity story is told across ~7 narrow per-slice tests (CDX↔SPDX 2.3, CDX↔SPDX 3, SPDX 2.3↔SPDX 3 annotation fidelity, CPE coverage, component count, license count, mapping-doc completeness). Each test catches its own slice, but when a new signal is added to one format without being added to the others, none of the existing tests necessarily fire — the regression would only be caught after someone wrote a new per-slice test for the new signal. This story moves parity from a loose collection of slice-tests to a single canonical guarantee that's documented, testable, and hard to regress.

**Independent Test**: For each of mikebom's 9 ecosystem fixtures, run `mikebom sbom scan --format cyclonedx-json,spdx-2.3-json,spdx-3-json` in one invocation. Build a catalog of every distinct datum type mikebom could emit (PURL, name, version, each hash algorithm, declared license, concluded license, supplier, author, each `mikebom:*` field, each external-reference type, CPE candidates, dependency edges, containment edges, OpenVEX cross-reference, etc.). For each datum type present in any format's output for that scan, assert its corresponding representation is present in the other two formats. One test per ecosystem — a failure names both the ecosystem and the specific datum that broke parity.

**Acceptance Scenarios**:

1. **Given** a scan produces a component with a declared license in CycloneDX, **When** the same scan emits SPDX 2.3 and SPDX 3, **Then** the license value is reachable in SPDX 2.3 (via `licenseDeclared` or `hasExtractedLicensingInfos[]`) and in SPDX 3 (via `simplelicensing_LicenseExpression` + `hasDeclaredLicense` Relationship) — same license value by string, different structural location per format.
2. **Given** a scan produces a component with N `mikebom:*` annotations in CycloneDX properties, **When** the same scan emits SPDX 2.3 and SPDX 3, **Then** every one of the N signals appears in each of the two SPDX outputs (native field where available, Annotation envelope otherwise).
3. **Given** a new mikebom signal is introduced in a future milestone and wired into the CycloneDX emitter but not yet into SPDX 2.3 or SPDX 3, **When** the parity test runs, **Then** it fails with a clear message naming the un-mapped datum and the format(s) where it's missing.
4. **Given** a scan produces an OpenVEX sidecar, **When** all three formats are emitted, **Then** both SPDX outputs carry a cross-reference to the sidecar (SPDX 2.3 `externalDocumentRefs[]`, SPDX 3 `externalRef[]` on SpdxDocument) — same sidecar file, different cross-reference mechanism per format.

---

### User Story 2 - Auto-discovery catches un-cataloged datums (Priority: P2)

A mikebom contributor adds a new `mikebom:foo-bar` property to the CycloneDX emitter to surface a newly-discovered signal. Without manually updating the per-format SPDX emitters or the format-mapping doc, they run the pre-PR gate. An auto-discovery test fails, pointing at the new `mikebom:foo-bar` name and naming the two formats where it's missing. The contributor can't ship the change without adding corresponding SPDX 2.3 + SPDX 3 emission paths OR explicitly documenting the new datum as format-restricted with a reason in the format-mapping doc.

**Why this priority**: This is the regression-prevention layer. US1 enforces parity on the **currently-cataloged** datum set; US2 ensures that set stays up-to-date as mikebom evolves. Without US2, every new milestone's contributor has to remember to update the parity catalog manually — easy to miss, especially for quick fixes.

**Independent Test**: For each of the 9 ecosystem fixtures, emit all three formats. Extract from the CycloneDX output: every distinct `components[].properties[].name` value, every distinct `components[].evidence[]` field name, every distinct top-level document key. For each extracted name, assert the format-mapping doc (`docs/reference/sbom-format-mapping.md`) has a row that mentions this name in its CycloneDX column. Any name without a row fails the test until the mapping doc is updated.

**Acceptance Scenarios**:

1. **Given** the CycloneDX emitter produces a component with a property whose name isn't documented in any row of `docs/reference/sbom-format-mapping.md`, **When** the auto-discovery test runs, **Then** it fails with the property name and a pointer at the mapping doc.
2. **Given** the CycloneDX emitter produces a document-level key not listed in the mapping doc's Section G (document envelope) or elsewhere, **When** the auto-discovery test runs, **Then** it fails with the key name.
3. **Given** a property is added to the CycloneDX emitter AND documented in the mapping doc with an explicit "format-restricted — <reason>" note, **When** the test runs, **Then** it passes (the documented restriction is an acceptable answer).

---

### User Story 3 - User-facing parity diagnostic (Priority: P3)

A user who ran `mikebom sbom scan --format cyclonedx-json,spdx-2.3-json,spdx-3-json` and noticed their SPDX 3 output has fewer CPE entries than their CDX output runs a diagnostic command that produces a human-readable table showing which datum types are present in each format for that specific scan. The table makes the equivalence (or non-equivalence) inspectable without the user having to write their own parity test.

**Why this priority**: Closes the "is my SBOM output really equivalent across formats?" investigation loop for end users. Today, answering that question requires writing ad-hoc shell / `jq` pipelines against each format. A built-in diagnostic makes the cross-format view a first-class observability surface — and surfaces bugs the test harness might miss on un-standard fixtures.

**Independent Test**: Run the diagnostic on one ecosystem fixture; inspect that the output is a human-readable per-datum coverage table showing which formats carry which data; the table's rows for universally-emitted datums (PURL, name, version, hashes) show check marks in all three format columns; rows for format-restricted datums show "omitted in <format>: <reason>" text from the format-mapping doc.

**Acceptance Scenarios**:

1. **Given** a user runs the parity-diagnostic command against a scan output directory containing all three format outputs, **When** the command completes, **Then** the user sees a per-datum table (one row per datum type, one column per format) with clear coverage markers.
2. **Given** the diagnostic identifies a datum present in one format but missing in another without a documented restriction, **When** the diagnostic output is rendered, **Then** that row is visually flagged (e.g., a leading `⚠️` or `FAIL`) so the user sees the gap immediately.

---

### Edge Cases

- A datum is genuinely format-restricted (e.g., SPDX 3's profile-conformance claim has no CycloneDX analogue; OpenVEX sidecar metadata has no CDX analogue beyond the `/vulnerabilities[]` field). The format-mapping doc MUST carry an explicit `omitted — <reason>` or `defer — <reason>` entry for these cases; the parity test treats these entries as acceptable answers and does not fire on them.
- A scan produces zero components (empty fixture). The parity test skips per-component assertions gracefully but still verifies document-envelope parity (CreationInfo / Tool / generation-context annotations in all three formats).
- A scan produces the same signal twice via different CycloneDX mechanisms (e.g., both `component.licenses[]` with an `id` entry AND an `expression` entry for the same license). The parity test de-duplicates at the (component, field) key level before comparing across formats.
- A signal is ONLY emitted in SPDX 3 because of a 3.x-specific profile element (e.g., a future `ai_AIPackage` typed Package). The format-mapping doc's SPDX 3 column carries the 3.x-native entry; the CDX and SPDX 2.3 columns carry an `omitted — SPDX 3 typed profile, no 1.6/2.3 equivalent` entry. Parity test accepts this explicit mapping.
- A signal is emitted in the CycloneDX output as a custom namespaced property (`mikebom:new-thing`) but the contributor forgot to add a mapping-doc row. Auto-discovery test (US2) catches this and fails with the property name.
- A signal's CycloneDX representation is format-dependent (e.g., `component.cpe` is single-valued in CDX but SPDX 3 emits every fully-resolved candidate via `ExternalIdentifier[cpe23]`). The parity test treats this as "directional containment" — every CDX value MUST appear in the other formats; the other formats MAY carry additional values. Milestone 012's `cpe_v3_acceptance.rs` already established this pattern; US1 generalizes it.
- The format-mapping doc gets updated, but a new emitter code path that reads the doc isn't. The parity test still reads the doc as the source of truth; the emitter's output is the observable. If the doc says "this field lives at path X" but the emitter writes path Y, the parity test fires.

## Requirements *(mandatory)*

### Functional Requirements

#### Datum catalog + holistic parity

- **FR-001**: A canonical datum catalog MUST exist naming every distinct signal mikebom can emit (component identity, hashes, licenses, supplier, author, each `mikebom:*` field, each external-reference type, CPE candidates, dependency edges, containment edges, OpenVEX cross-reference, document-level signals). The catalog's canonical home is `docs/reference/sbom-format-mapping.md` — each catalog entry is a row naming the CycloneDX, SPDX 2.3, and SPDX 3 representations.
- **FR-002**: For each catalog entry whose three-format mapping is marked "universal parity," the three format outputs of any scan MUST carry equivalent data — the set of facts (field name + value) is the same across formats, only the structural location differs.
- **FR-003**: For each catalog entry whose mapping is marked "format-restricted" (classification per clarification Q1 — any row whose CycloneDX, SPDX 2.3, or SPDX 3 column contains `omitted — <reason>` or `defer — <reason>`), the parity check MUST accept the restriction for the format(s) whose column carries the restriction marker, and MUST NOT fire on that row's restricted format(s). Rows with no restriction marker in any column are treated as "universal parity" — every format must carry the datum.
- **FR-004**: The parity check MUST be directional-containment-aware: when a format natively represents a single-valued slot (CycloneDX `component.cpe`), emitters that support multi-valued slots (SPDX 3 `ExternalIdentifier[cpe23]`) MAY emit additional values beyond the CycloneDX one without breaking parity.

#### Auto-discovery regression guard

- **FR-005**: An auto-discovery check MUST scan every emitted CycloneDX output for distinct property names (at both component and document level) and assert each appears in at least one catalog row's CycloneDX column. (Direction: emitter → catalog.)
- **FR-006**: When a new CycloneDX property name is introduced without a corresponding catalog row, the auto-discovery check MUST fail the pre-PR gate with a clear message naming the un-mapped property.
- **FR-007**: The auto-discovery check MUST accept two kinds of entries as valid catalog rows: (a) rows mapping the property to concrete locations in all three formats ("universal parity"); (b) rows with an explicit `omitted — <reason>` or `defer — <reason>` entry in one or two format columns ("format-restricted").
- **FR-007a**: A reverse check (catalog → emitter, per clarification Q2) MUST assert that every catalog row classified "universal parity" has its CycloneDX-column property actually produced by at least one of the 9 ecosystem fixtures' emitted CycloneDX output. Catalog rows listing properties that no emitter produces MUST fail the pre-PR gate with a clear message naming the orphan row, so the catalog stays in sync with what the emitter actually emits (no "spec lists it but code doesn't do it" drift).

#### User-facing diagnostic

- **FR-008**: A user-invoked diagnostic MUST produce a human-readable per-datum coverage table for a specific scan, showing which formats carry which signals.
- **FR-009**: The diagnostic MUST visually flag rows where a universally-cataloged datum is missing from one of the three format outputs — a gap the contributor's CI should have caught but didn't (e.g., stale test matrix, local-dev-only scan).
- **FR-010**: The diagnostic MUST work against a directory of already-emitted format outputs — it does NOT need to re-run the scan.

#### Cross-format invariants

- **FR-011**: The parity test MUST run against all 9 ecosystem fixtures in mikebom's standard test matrix + 1 container-image fixture (apk, cargo, deb, gem, go, maven, npm, pip, rpm, plus the synthetic perf-test image). One test per fixture.
- **FR-012**: The parity test MUST preserve the existing milestone-010 through milestone-012 byte-determinism guarantees: two runs of the same scan produce byte-identical output after timestamp and document-identifier normalization.
- **FR-013**: The parity test MUST NOT require any scan-pipeline changes. Discovery, deep-hash, enrichment, and resolution layers are untouched.

### Key Entities *(include if feature involves data)*

- **Datum catalog** — the single-source-of-truth table (rows with `(signal_name, CycloneDX location, SPDX 2.3 location, SPDX 3 location, classification)` columns). Classification is either `universal` (parity must hold) or `format-restricted — <reason>` (at least one column is `omitted — <reason>`). Lives at `docs/reference/sbom-format-mapping.md`.
- **Parity slice** — one signal type's full row in the catalog. A slice is either `universal-parity`, in which case all three format outputs must carry the datum, or `format-restricted`, in which case the omission is documented and accepted.
- **Auto-discovery scan** — the list of distinct property names, field names, and top-level keys extracted from a single CycloneDX output. Each discovered name is checked against the catalog.
- **Coverage table** — the per-datum-type × per-format matrix the user-facing diagnostic produces. One row per datum type, one column per format, cell content is either "present," "absent," or "format-restricted: <reason>."

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For every ecosystem in mikebom's test matrix, every catalog entry marked "universal parity" has its datum present in all three format outputs of every scan. A failure on any entry flags both the ecosystem and the specific datum that broke parity.
- **SC-002**: For every ecosystem, zero distinct CycloneDX property names, evidence fields, or document-level keys appear in the emitted output without a matching catalog row (emitter → catalog direction), AND zero catalog rows classified "universal parity" go without their CycloneDX property appearing in at least one ecosystem's emitted output (catalog → emitter direction — per clarification Q2).
- **SC-003**: The parity test completes in ≤ 5 seconds per ecosystem on CI (ubuntu-latest) — the test is an output-parsing-plus-table-lookup check, no re-scan required; scan time is amortized via a single triple-format invocation per ecosystem.
- **SC-004**: An end user running the diagnostic command against a scan output directory sees a coverage table in ≤ 1 second for a 9-ecosystem-sized SBOM.
- **SC-005**: The diagnostic flags every parity gap it detects with a visually-obvious marker (leading `⚠️`, `FAIL`, or equivalent), so the user doesn't have to scan the whole table for gaps.
- **SC-006**: When a contributor adds a new CycloneDX property without updating the catalog, the auto-discovery test fails within the pre-PR gate with a message that names the property AND points at the mapping doc's expected update location.
- **SC-007**: The parity test preserves byte-determinism: two runs of the same scan produce byte-identical output across all three formats after timestamp + document-IRI normalization.

## Assumptions

- The format-mapping doc's existing row structure (CycloneDX / SPDX 2.3 / SPDX 3 columns per row) IS the canonical datum catalog — no new columns, no sidecar file. Per clarification Q1, the `universal` vs `format-restricted` classification is inferred from the presence of `omitted — <reason>` or `defer — <reason>` text in one or more format columns. The parity test parses the markdown directly via a simple line-by-line regex over table rows.
- The auto-discovery check's scope is limited to the CycloneDX output's distinct property names + top-level keys (covers the typical new-signal entry path: a new mikebom field lands in CDX first, then the emitter authors port it to SPDX 2.3 + SPDX 3). Signals added directly to SPDX 2.3 or SPDX 3 without going through CDX first are rare enough that the catalog-update step catches them via review.
- The user-facing diagnostic is a best-effort view, not a formal assertion surface. The parity test is the authoritative gate; the diagnostic is an inspection tool for end users and reviewers.
- Existing per-slice parity tests (`spdx_cdx_parity.rs`, `spdx3_cdx_parity.rs`, `spdx_annotation_fidelity.rs`, `spdx3_annotation_fidelity.rs`, `cpe_v3_acceptance.rs`, `component_count_parity.rs`, `spdx_license_ref_extracted.rs`) remain in place as narrow-slice regression guards. The new holistic test is a superset; it doesn't obsolete them. A future milestone may consolidate them if the overlap becomes a maintenance burden, but that's out of scope here.
- No new external dependencies are introduced. The parity test, auto-discovery check, and diagnostic all reuse existing crates (`serde_json`, `tempfile`, standard library).
- Container-image fixtures are best-effort: the standard 9-ecosystem matrix is the primary enforcement surface; a synthetic container-image fixture (the one `dual_format_perf.rs` / `triple_format_perf.rs` already build from 500 deb + 1500 npm packages) is exercised for scale-realism coverage.
- The user-facing diagnostic is a CLI flag or subcommand; the exact surface (`mikebom sbom parity-report` vs. `--parity-report`) is a small user-experience decision the plan will finalize. The spec only requires that a command with the described behavior exists.
- **Validator-of-the-validator confidence (formerly SC-008)**: by construction, the parity test would have fired on the milestone-012 SPDX 3 CPE bug (extractor for catalog row A12 covers the `cpe23` ExternalIdentifier slot) and on the SPDX 2.3 LicenseRef drop (extractor for A7 covers `licenseDeclared` + `hasExtractedLicensingInfos[]`). This is a design-level confidence statement, not a CI-asserted gate — automating it as a regression-detection sanity check would require a mutation-testing harness (out of scope). Reviewers verify the property by inspecting the extractor table's coverage of the catalog rows the milestone-012 bugs touched.
