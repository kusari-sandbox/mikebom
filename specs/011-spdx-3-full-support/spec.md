# Feature Specification: Full SPDX 3.x Output Support

**Feature Branch**: `011-spdx-3-full-support`
**Created**: 2026-04-24
**Status**: Draft
**Input**: User description: "can we now look at fully implementing spdx 3.X support?"

## Clarifications

### Session 2026-04-24

- Q: How does the SPDX 3 document cross-reference the OpenVEX sidecar? → A: `ExternalRef` on the SPDX 3 document element, with a SPDX-3-vocabulary-canonical "security advisory"–type ExternalRef and a relative-path URI to the OpenVEX sidecar.
- Q: What's the decision rule for placing each `mikebom:*` signal in SPDX 3 — native field vs. Annotation? → A: Native SPDX 3 field only when typed semantics match exactly (same meaning, same cardinality); every other signal goes to an SPDX 3 Annotation. Borderline rows (e.g., shade-relocation lineage, deep-hash address) are explicitly enumerated and decided per-row in `docs/reference/sbom-format-mapping.md`, not left to emitter discretion.
- Q: What CI gate threshold enforces the triple-format wall-clock amortization? → A: Spec target stays at ≥30% reduction (SC-007); CI gate enforces ≥25% with the same documented noise-budget rationale milestone 010 used for `SC009_CI_MIN_REDUCTION`. The 5-point gap absorbs fixed per-invocation CLI overhead on shared CI runners.
- Q: Does Constitution Principle V's experimental-labeling clause apply to the `spdx-3-json-experimental` alias once it routes through the stable emitter? → A: No. After this milestone, the alias is a **deprecation track** to a stable emitter, not an experimental emitter. The clause governs emitters whose output is preview-quality (which is what milestone 010's stub was). The alias produces byte-identical output to the stable identifier — same filename `mikebom.spdx3.json`, same document bytes, no experimental marker in CreationInfo or SpdxDocument comments. The deprecation signal is carried by the stderr notice (FR-002) and the CLI help-text "(deprecated)" annotation, not by the constitution's experimental-labeling mechanism.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Production-grade SPDX 3 output across every supported ecosystem (Priority: P1)

A platform-security engineer who has standardized their SBOM pipeline on SPDX 3.x (the format version that SPDX has designated the long-term direction) runs `mikebom sbom scan` against any of the nine ecosystems mikebom supports today (apk, cargo, deb, gem, go, maven, npm, pip, rpm) and receives a schema-valid, byte-deterministic SPDX 3 document that carries every component mikebom discovered, each with its PURL, name, version, license, and integrity checksums expressed in SPDX 3 native fields — the same discovery signal mikebom already puts in its CycloneDX and SPDX 2.3 outputs.

**Why this priority**: Without this story, mikebom's SPDX 3 output is the current experimental stub (npm-only, no licenses, no broader ecosystem coverage). The stub is labeled experimental in the CLI help to signal "not production-ready," and downstream SBOM consumers that have moved to SPDX 3 must either fall back to SPDX 2.3 or use a different SBOM producer. Closing this gap is the whole point of the milestone — it turns SPDX 3 from a demo surface into a peer of SPDX 2.3. The MVP for this milestone is the point at which a user can choose SPDX 3 as their primary mikebom output format and not lose information relative to what mikebom puts in CycloneDX today.

**Independent Test**: Run `mikebom sbom scan --path <fixture> --format spdx-3-json --output spdx-3-json=out.spdx3.json` against each of the nine ecosystem fixtures that `tests/fixtures/` already exercises for CDX and SPDX 2.3. For each output: (a) it validates against the published SPDX 3.0.1 JSON-LD schema, (b) it contains one SPDX 3 Package element per component that CycloneDX emits for the same scan, and (c) every Package carries PURL, name, version, license, and checksum data populated in the SPDX 3 native fields those concepts map to.

**Acceptance Scenarios**:

1. **Given** a user has the mikebom CLI installed and an ecosystem fixture on disk, **When** they run `mikebom sbom scan --path <fixture> --format spdx-3-json --output spdx-3-json=out.spdx3.json`, **Then** the resulting file validates against the official SPDX 3.0.1 JSON-LD schema, exits zero, and surfaces no experimental-warning label in the CLI output.
2. **Given** a single scan of any supported ecosystem, **When** the user requests CycloneDX and SPDX 3 in a single invocation via `--format cyclonedx-json,spdx-3-json`, **Then** for every component present in the CycloneDX output, the SPDX 3 output contains exactly one Package whose PURL matches the CycloneDX component's PURL and whose version and checksum values match byte-for-byte.
3. **Given** two runs of the same scan on the same input, **When** the two SPDX 3 files are compared after stripping the run-scoped document identifier and creation timestamp, **Then** the remaining bytes are identical.
4. **Given** the user has not passed `--format`, **When** they run `mikebom sbom scan --path <fixture>`, **Then** the CLI behavior for default-format selection is unchanged from today (CycloneDX remains the default).

---

### User Story 2 - Mikebom-specific discovery signal preserved in SPDX 3 (Priority: P2)

A user who already relies on mikebom's distinctive discovery signal — build-provenance hints, deep-hash content addresses, shade-relocation lineage, dependency-scope annotations, Maven POM provenance, apk/deb package-manager metadata — inspects the SPDX 3 output and finds that same signal carried through, either in SPDX 3 native fields where the SPDX 3 vocabulary has a home for the concept, or in the same annotation-envelope shape that mikebom already uses for SPDX 2.3 where SPDX 3 does not.

**Why this priority**: Story 1 alone matches mikebom's CycloneDX surface on core identity (PURL, version, license, checksum), which is the load-bearing interop contract. Story 2 matches mikebom's CycloneDX surface on the *distinctive-signal* columns (C1–C20 in the existing format mapping) that differentiate mikebom's output from a generic scanner. Without Story 2, SPDX 3 consumers of mikebom's output lose information that SPDX 2.3 consumers of mikebom's output already have — which is a regression between two SPDX format versions, a worse user experience than the format-version choice should imply.

**Independent Test**: For the same nine ecosystem fixtures as Story 1, assert that every `mikebom:*` annotation mikebom emits in its SPDX 2.3 output is present in the SPDX 3 output for the same scan (either as an SPDX 3 native field binding or as an SPDX 3 `Annotation` element carrying the same JSON envelope shape as today's SPDX 2.3 annotations).

**Acceptance Scenarios**:

1. **Given** a scan that produces N `mikebom:*` annotations on a given component in SPDX 2.3, **When** the same scan runs against SPDX 3, **Then** the SPDX 3 document surfaces all N signals (each either in a native SPDX 3 field or in an SPDX 3 Annotation element), with no signal dropped.
2. **Given** a scan that emits Maven shade-relocation lineage or dependency-scope metadata in CycloneDX evidence, **When** the same scan runs against SPDX 3, **Then** those signals appear in the SPDX 3 output with the same semantic content as the CycloneDX evidence entries.
3. **Given** a scan that produces an OpenVEX sidecar file today alongside SPDX 2.3, **When** SPDX 3 is selected as an output format, **Then** OpenVEX is emitted in the same sidecar shape and cross-referenced from the SPDX 3 document.

---

### User Story 3 - Experimental label retired once parity is proven (Priority: P3)

A user who has been tracking mikebom's SPDX 3 progress and has seen the `spdx-3-json-experimental` format identifier in CLI help output sees that identifier retire in favor of a stable `spdx-3-json` format name once Stories 1 and 2 ship — giving them a signal that SPDX 3 has crossed from "preview" into "supported on par with SPDX 2.3."

**Why this priority**: This is the documentation and UX piece that closes the loop on the experimental status. Stories 1 and 2 deliver the functional parity; Story 3 tells users via the CLI surface itself that they can now rely on SPDX 3. Without Story 3 the output is there but downstream users can't tell it's ready.

**Independent Test**: Run `mikebom sbom scan --help` and assert the stable `spdx-3-json` identifier is listed and is not annotated with an experimental warning. Run with the older `spdx-3-json-experimental` identifier and assert the CLI still accepts it (so existing user scripts don't break), but emits a deprecation notice pointing at the stable name.

**Acceptance Scenarios**:

1. **Given** Stories 1 and 2 have shipped and their acceptance tests pass, **When** the user runs `mikebom sbom scan --help`, **Then** `spdx-3-json` appears in the format list with no experimental annotation, and release notes record the status change.
2. **Given** an existing user pipeline that passes `--format spdx-3-json-experimental`, **When** that pipeline runs against the new release, **Then** the scan completes successfully and a deprecation notice is printed to stderr pointing at `spdx-3-json`.

---

### Edge Cases

- A component has a license expression that mikebom cannot canonicalize (an unknown SPDX license identifier or a malformed expression). The SPDX 3 output MUST still emit the component with the raw license string preserved somewhere readable, matching today's CycloneDX and SPDX 2.3 fallback behavior (no silent drop).
- A scan discovers a component that has no PURL (e.g., a source-tree discovery where ecosystem inference fails). SPDX 3 identifiers MUST still be generated deterministically and the component MUST still appear, using the same synthetic-identifier fallback as SPDX 2.3.
- A scan target produces zero components (an empty fixture). The SPDX 3 output MUST still validate against the schema and carry the scan-subject Package as the document root, matching the SPDX 2.3 synthesized-root behavior for sbomqs parity.
- A scan produces a very large SPDX 3 document (thousands of components, as in a real container image). Emission MUST not spike memory disproportionately to the SPDX 2.3 path, and CLI wall-clock MUST remain within the same order of magnitude as SPDX 2.3 for the same scan.
- A user requests all three formats in a single invocation: `--format cyclonedx-json,spdx-2.3-json,spdx-3-json`. The dual-format amortization that exists for any pair today MUST extend to the triple case — the single invocation MUST still be meaningfully faster than three sequential single-format invocations.
- A user's pipeline relies on the current experimental-stub shape (npm-only, no licenses). After the full implementation ships, that stub shape is no longer what gets emitted for `spdx-3-json-experimental`; the deprecation notice MUST make the shape-change impact visible.
- A component has multiple PURLs or multiple CPEs (the rpm and deb cases). SPDX 3's ExternalIdentifier model MUST carry them all, not just the first.
- A scan targets a container image whose layer walk produces containment nesting (an image contains a shaded JAR which contains relocated classes). The SPDX 3 Relationship graph MUST express the same containment structure that the CycloneDX and SPDX 2.3 outputs do today, preserving the parent-child chain.

## Requirements *(mandatory)*

### Functional Requirements

#### Format identifier and CLI surface

- **FR-001**: The CLI MUST accept `spdx-3-json` as a first-class format identifier wherever `cyclonedx-json` and `spdx-2.3-json` are accepted today (the `--format` flag and `--output <format>=<path>` bindings).
- **FR-002**: The CLI MUST continue to accept the existing `spdx-3-json-experimental` identifier for at least one release after `spdx-3-json` ships, treating it as an alias that emits the same output while printing a deprecation notice directing the user to the stable identifier.
- **FR-003**: The CLI help surface MUST remove the experimental annotation on the SPDX 3 format entry once the acceptance criteria for Stories 1 and 2 are satisfied.
- **FR-004**: When a single invocation requests SPDX 3 alongside one or more of the other supported formats, the scan + discovery + deep-hash work MUST run exactly once and feed all requested format serializers — extending the existing dual-format single-pass guarantee to the SPDX 3 format.

#### Ecosystem coverage

- **FR-005**: SPDX 3 output MUST include one SPDX 3 Package element for every component that the CycloneDX output contains for the same scan, for all nine ecosystems that mikebom currently supports (apk, cargo, deb, gem, go, maven, npm, pip, rpm).
- **FR-006**: For each Package, SPDX 3 output MUST populate the SPDX 3 native fields that express: the package URL (via ExternalIdentifier of the `purl` type), the package name, the package version, the declared license (and concluded license when mikebom distinguishes them), and the content checksums mikebom computed.
- **FR-007**: For components that carry multiple PURLs or multiple CPEs, every PURL and every CPE MUST appear as a separate ExternalIdentifier entry.
- **FR-008**: For components where the raw license string cannot be canonicalized to a valid SPDX license expression, the raw string MUST be preserved in the SPDX 3 output without blocking emission of the rest of the component — the same non-fatal-fallback behavior that exists for CycloneDX and SPDX 2.3 today.

#### Graph structure

- **FR-009**: The SPDX 3 output MUST express dependency relationships (A depends on B) and containment relationships (image contains layer contains file/package) using SPDX 3 Relationship elements, preserving the same graph shape that the CycloneDX and SPDX 2.3 outputs carry for the same scan.
- **FR-010**: The SPDX 3 document root MUST identify the scan subject (path, image, or source tree) as the top-level package the document is about, mirroring the synthesized-root pattern the SPDX 2.3 emitter uses today.

#### Mikebom-specific signal fidelity

- **FR-011**: Every `mikebom:*` annotation that mikebom emits on a component or on the document in its SPDX 2.3 output MUST be present in the SPDX 3 output for the same scan, with placement governed by a strict-match rule: a signal binds to a native SPDX 3 field only when the SPDX 3 vocabulary exposes a typed property whose semantics match the mikebom signal exactly (same meaning, same cardinality); every other signal MUST be emitted as an SPDX 3 Annotation element using the same JSON envelope schema (`schema: mikebom-annotation/v1`, `field`, `value`) that SPDX 2.3 annotations use today. Borderline rows where multiple SPDX 3 placements are plausible (e.g., shade-relocation lineage, deep-hash content addresses) MUST be enumerated and resolved per-row in `docs/reference/sbom-format-mapping.md` rather than decided at emit time.
- **FR-012**: The mapping of each CycloneDX field to its SPDX 3 target MUST be recorded in the canonical format-mapping document (`docs/reference/sbom-format-mapping.md`), with no row left at "?", "TODO", "TBD", or an empty cell — the same standard the SPDX 2.3 column met in milestone 010.

#### OpenVEX

- **FR-013**: When SPDX 3 is selected as an output format, mikebom MUST emit the OpenVEX sidecar file using the same shape, schema, and default filename that the SPDX 2.3 path uses today.
- **FR-014**: The SPDX 3 document MUST cross-reference the OpenVEX sidecar via an SPDX 3 `ExternalRef` on the document element, using the SPDX-3-vocabulary-canonical "security advisory" ExternalRef type and a relative-path URI to the sidecar file. The pattern matches the ExternalRef-based cross-reference convention SPDX 2.3 already uses, so downstream consumers stay on a familiar parse path across format versions.

#### Determinism, validation, and parity

- **FR-015**: Two runs of the same scan against the same input MUST produce byte-identical SPDX 3 output after the run-scoped document identifier and creation timestamp are normalized — matching the determinism guarantee that CycloneDX and SPDX 2.3 outputs meet today.
- **FR-016**: Every SPDX 3 output mikebom produces MUST validate against the published SPDX 3.0.1 JSON-LD schema without warnings or errors.
- **FR-017**: For each of the nine ecosystem fixtures, every CycloneDX component's PURL, version, and checksum set MUST appear on exactly one SPDX 3 Package in the SPDX 3 output for the same scan — mirroring the native-field parity guard that exists between CycloneDX and SPDX 2.3 today.
- **FR-018**: Every `mikebom:*` field that the SPDX 2.3 output carries for a given fixture MUST be reachable (by field name and value) in the SPDX 3 output for that fixture — whether via a native SPDX 3 field or an Annotation element.

#### Opt-off and backward compatibility

- **FR-019**: A user who does not request SPDX 3 MUST see no change in CLI behavior, output file shapes, sidecar presence, or scan performance.
- **FR-020**: The existing `spdx-3-json-experimental` identifier MUST continue to accept arguments that today's implementation accepts for at least one release cycle after the stable identifier ships.

### Key Entities *(include if feature involves data)*

- **SPDX 3 Document**: The top-level JSON-LD structure mikebom emits. Carries a creation context (tool identity, timestamp, document identifier), a root Package identifying the scan subject, the full set of discovered Package elements, the relationship graph connecting them, and any mikebom-specific Annotation elements.
- **SPDX 3 Package**: One element per component. Carries identity fields (name, version), identifier fields (PURLs and CPEs as ExternalIdentifier entries), integrity fields (content checksums), license fields (declared and concluded), and any mikebom-specific signal either bound to a native SPDX 3 property or attached as an Annotation.
- **SPDX 3 Relationship**: An element expressing a typed edge between Packages. Expresses dependency edges, containment edges, license edges (declared/concluded), and any other graph structure the SPDX 3 vocabulary models as a Relationship rather than a direct property.
- **SPDX 3 Annotation**: An element attached to a Package (or the Document) carrying a mikebom-specific signal that has no SPDX 3 native home, using the same JSON envelope schema (`schema: mikebom-annotation/v1`, `field`, `value`) that mikebom's SPDX 2.3 annotations use today.
- **Mikebom annotation envelope**: The existing JSON shape mikebom uses to carry its distinctive signal in formats that lack native fields for it. Already defined and exercised in the SPDX 2.3 path; reused verbatim in the SPDX 3 path.
- **OpenVEX sidecar**: A separate JSON file mikebom already emits alongside SPDX 2.3 to carry vulnerability-status data. In SPDX 3 mode it MUST be emitted with the same shape and cross-referenced from the SPDX 3 document.
- **Format-mapping document**: The canonical `docs/reference/sbom-format-mapping.md` table already used in milestone 010. Gains a fully-populated SPDX 3 column.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For every one of the nine ecosystems, an external SBOM-quality scorer rates the SPDX 3 output at least as highly as the CycloneDX output on every NTIA-minimum feature both formats express natively — matching the gate that already exists for SPDX 2.3.
- **SC-002**: Every SPDX 3 output mikebom emits across the full fixture matrix validates against the published SPDX 3.0.1 JSON-LD schema with zero warnings and zero errors.
- **SC-003**: For every ecosystem, every component appearing in the CycloneDX output for a given scan appears as exactly one SPDX 3 Package in the SPDX 3 output for the same scan, with matching PURL, version, and checksum values.
- **SC-004**: Every row in `docs/reference/sbom-format-mapping.md` has a non-placeholder entry in the SPDX 3 column — the same completeness standard the SPDX 2.3 column meets today.
- **SC-005**: Every `mikebom:*` signal present in the SPDX 2.3 output for a given fixture is retrievable by field name and value in the SPDX 3 output for that fixture.
- **SC-006**: Two runs of the same scan produce byte-identical SPDX 3 output after the document identifier and timestamp are normalized.
- **SC-007**: A single invocation requesting CycloneDX, SPDX 2.3, and SPDX 3 together completes in at least 30% less wall-clock time than three sequential single-format invocations against the same production-scale target. The CI regression gate enforces ≥25% reduction (a 5-point noise budget below the spec target), matching the `SC009_CI_MIN_REDUCTION` pattern milestone 010 established for dual-format amortization.
- **SC-008**: CLI help output shows the stable `spdx-3-json` format identifier without an experimental annotation, and the older `spdx-3-json-experimental` identifier remains accepted for at least one release cycle while printing a deprecation notice.
- **SC-009**: A user who does not request SPDX 3 observes no measurable change in their existing pipeline — same scan wall-clock, same output files, same sidecar presence.
- **SC-010**: An independent SBOM-format-mapping coverage check finds zero CycloneDX fields present in the 9 ecosystem goldens that lack a populated SPDX 3 column entry.

## Assumptions

- Target SPDX 3 version is **SPDX 3.0.1** — the published, schema-validated revision mikebom's experimental stub already targets. If SPDX 3 publishes a revision (3.0.2, 3.1.0) before this milestone ships, the target is the highest published revision at implementation time whose JSON-LD schema is publicly retrievable.
- The `spdx-3-json-experimental` identifier is treated as a **deprecation-track alias** rather than a parallel emitter after this milestone ships. It emits the same bytes as `spdx-3-json` and prints a stderr deprecation notice; it does not preserve the old npm-only stub shape. Users who want the old stub shape must stay on a pre-011 release.
- The default output filename when the user passes `--format spdx-3-json` without an explicit `--output` binding is `mikebom.spdx3.json`, mirroring the `mikebom.spdx.json` pattern used by SPDX 2.3.
- No change to scan pipeline, discovery, deep-hash, or enrichment code is in scope — this milestone is purely about adding an output serializer that consumes the existing `ScanArtifacts` shape, the same architectural boundary milestone 010 used for SPDX 2.3.
- The OpenVEX sidecar is cross-referenced from the SPDX 3 document via `ExternalRef` on the document element (security-advisory type, relative-path URI), per FR-014. ExternalRef was chosen over Relationship-to-File-element, ExternalMap, or Annotation because it is the de-facto pattern downstream consumers already parse for SPDX 2.3 sidecar references, keeping the cross-version parse path uniform.
- Rows in the format-mapping document that are intentionally not emitted in SPDX 3 (e.g., because SPDX 3 has no native home for them and mikebom chooses not to annotate them either) are marked `omitted — <reason>` or `defer — <reason>`, following the same convention the SPDX 2.3 column uses. These count as populated, not empty.
- Coverage across ecosystems uses the same nine-fixture matrix that every other format parity test uses today (`apk`, `cargo`, `deb`, `gem`, `go`, `maven`, `npm`, `pip`, `rpm`). Adding a new ecosystem to mikebom in the future is a separate milestone and automatically picks up SPDX 3 coverage via the existing shared test harness.
- The schema-validation CI gate that exists for SPDX 2.3 is extended to also run against every SPDX 3 output from the fixture matrix, using the same `jsonschema` dev-dep that already powers the SPDX 2.3 gate.
