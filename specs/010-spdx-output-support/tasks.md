---
description: "Task list for milestone 010-spdx-output-support — SPDX 2.3 output (with SPDX 3.0.1 opt-in stub) + OpenVEX sidecar + dual-format data-placement map"
---

# Tasks: SPDX Output Support (2.3 with groundwork for 3+)

**Input**: Design documents from `/Users/mlieberman/Projects/mikebom/specs/010-spdx-output-support/`
**Prerequisites**: `plan.md` ✅, `spec.md` ✅, `research.md` ✅, `data-model.md` ✅, `contracts/` ✅, `quickstart.md` ✅

**Tests**: REQUIRED — the spec explicitly mandates automated tests (FR-021, FR-022, SC-002/003/004/006/007/008/009). Test tasks are integrated into each user story phase.

**Organization**: Tasks are grouped by user story (US1 = P1 / MVP, US2 = P2, US3 = P3) so each story can be implemented, tested, and demoed independently. The MVP cut is Phase 1 → Phase 2 → Phase 3 (US1).

## Format: `[TaskID] [P?] [Story?] Description with file path`

- **[P]**: Can run in parallel — different files, no dependency on incomplete tasks.
- **[Story]**: User story label (US1, US2, US3) for tasks within a story phase.
- All file paths are absolute or repo-rooted from `/Users/mlieberman/Projects/mikebom/`.

## Path Conventions

Single Cargo workspace. New code lives entirely in `mikebom-cli/`. Documentation lives under `docs/`. No new crates added (Constitution Principle VI). See `plan.md` → Project Structure for the full file tree.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Vendor external schemas, add the test-only validator dependency, scaffold module trees.

- [X] T001 [P] Vendor SPDX 2.3 JSON schema (download from `https://github.com/spdx/spdx-spec/blob/development/v2.3/schemas/spdx-schema.json`) into `mikebom-cli/tests/fixtures/schemas/spdx-2.3.json`
- [X] T002 [P] Vendor SPDX 3.0.1 JSON schema (download from `https://spdx.org/schema/3.0.1/spdx-json-schema.json`) into `mikebom-cli/tests/fixtures/schemas/spdx-3.0.1.json`
- [X] T003 [P] Vendor OpenVEX 0.2.0 JSON schema (download from `https://github.com/openvex/spec/blob/main/openvex.schema.json`) into `mikebom-cli/tests/fixtures/schemas/openvex-0.2.0.json`
- [X] T004 [P] Add `jsonschema = "0.46"` under `[dev-dependencies]` in `mikebom-cli/Cargo.toml` (test-only; verify pure-Rust transitive closure with `cargo tree -p jsonschema | grep -i 'sys\|cc\|bindgen'` returning empty)
- [X] T005 [P] Create empty SPDX module skeleton at `mikebom-cli/src/generate/spdx/` containing `mod.rs`, `document.rs`, `packages.rs`, `relationships.rs`, `annotations.rs`, `ids.rs`, `v3_stub.rs` (each file: just module declarations / `pub use` placeholders so the crate compiles after `pub mod spdx;` is added in `generate/mod.rs`)
- [X] T006 [P] Create empty OpenVEX module skeleton at `mikebom-cli/src/generate/openvex/` containing `mod.rs`, `statements.rs` (placeholder declarations)
- [X] T056 [P] Vendor SPDX 2.3 reference example `SPDXJSONExample-v2.3.spdx.json` (download from `https://github.com/spdx/spdx-spec/tree/development/v2.3/examples/SPDXJSONExample-v2.3.spdx.json`) into `mikebom-cli/tests/fixtures/reference/SPDXJSONExample-v2.3.spdx.json`. This is the warning-baseline reference that T015 compares produced output against per SC-002 — without it, the warning-baseline half of SC-002 is non-executable. (Numerically appended to preserve existing T-IDs; logically belongs in Phase 1 Setup and MUST complete before T014.)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Stand up the format-dispatch architecture (FR-019), refactor the existing CycloneDX serializer behind it without behavior change, and pin the byte-identity baseline that protects FR-022 / SC-006 throughout the rest of the milestone.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T007 Define the `SbomSerializer` trait, `EmittedArtifact` struct, and `OutputConfig` struct in `mikebom-cli/src/generate/mod.rs` per `data-model.md` §2 (id / default_filename / experimental / serialize)
- [X] T008 Define `SerializerRegistry` (`with_defaults()`, `ids()`, `get(id)`) in `mikebom-cli/src/generate/mod.rs`; initially `with_defaults()` only registers the existing CycloneDX serializer (depends on T007)
- [X] T009 Refactor existing CycloneDX serializer (`mikebom-cli/src/generate/cyclonedx/mod.rs` and the helpers it calls into) to implement `SbomSerializer` with `id() == "cyclonedx-json"` and `default_filename() == "mikebom.cdx.json"`; touch nothing inside the helper modules' build logic so output bytes are unchanged (depends on T008)
- [X] T010 [P] Generate and pin pre-milestone CycloneDX golden fixtures at `mikebom-cli/tests/fixtures/golden/cyclonedx/{apk,cargo,deb,gem,golang,maven,npm,pip,rpm}.cdx.json` by running the current `mikebom sbom scan` against each existing per-ecosystem integration-test fixture (one fixture file per ecosystem). Synthetic `apk/` and `deb/` fixture roots were added under `tests/fixtures/{apk,deb}/synthetic/` (minimal `/etc/os-release` + package db entries) since no static ones existed.
- [X] T011 Write CycloneDX byte-identity regression test in `mikebom-cli/tests/cdx_regression.rs` that, for each of the 9 ecosystems, runs the current scan and asserts byte-equal output against the corresponding pinned fixture from T010 (depends on T009 and T010; this is the standing guarantee for FR-022 / SC-006). The test normalizes two CDX-volatile fields (`serialNumber` v4 UUID and `metadata.timestamp`) before byte compare — rest of the document is protected. `MIKEBOM_UPDATE_CDX_GOLDENS=1` toggles regeneration.
- [X] T012 Modify `mikebom-cli/src/cli/scan_cmd.rs` (not `sbom/scan_cmd.rs` — corrected path) so `--format` parses a comma-separated list (`value_delimiter(',')`) and is also `repeatable`, accepts `--output <fmt>=<path>` repeated overrides (also still accepts a bare `--output <path>` for single-format invocations for backwards compat), deduplicates format identifiers silently, and dispatches each requested format through `SerializerRegistry::get(id).serialize(&scan, &cfg)` writing each `EmittedArtifact` to the override path or `default_filename()` (FR-001, FR-004, FR-004a, FR-004b; depends on T008)
- [X] T013 Write CLI-dispatch integration tests in `mikebom-cli/tests/format_dispatch.rs` covering: (a) no `--format` produces a single `mikebom.cdx.json` byte-identical to T010 fixtures; (b) `--format cyclonedx-json,cyclonedx-json` deduplicates to one file; (c) unknown format identifier exits non-zero with a clear error listing registered ids; (d) `--output <fmt>=<path>` for an unrequested format is a hard error; (e) override-path collisions abort before scan work runs (depends on T012)

**Checkpoint**: Foundation ready. CycloneDX byte-identity is now under continuous protection. New format serializers can be registered with confidence that the pre-milestone surface stays exactly as it was.

---

## Phase 3: User Story 1 - Produce a valid SPDX 2.3 SBOM from a scan (Priority: P1) 🎯 MVP

**Goal**: A user running `mikebom sbom scan --format spdx-2.3-json` (or `--format cyclonedx-json,spdx-2.3-json` for both) gets a schema-valid, deterministic SPDX 2.3 JSON SBOM covering all 9 ecosystems, with PURL / version / checksums / declared+concluded licenses / dependency relationships matching the CycloneDX output for the same scan on every native field. Mikebom-specific annotation fidelity (US2) is not in scope here — this story ships "core SPDX."

**Independent Test**: Run `mikebom sbom scan --path <fixture>` for any of the 9 ecosystems requesting SPDX output; the produced `mikebom.spdx.json` validates clean against the vendored SPDX 2.3 JSON schema and contains one SPDX Package per CycloneDX component, matched by PURL.

### Tests for User Story 1 (write FIRST; FAIL until implementation lands) ⚠️

- [X] T014 [P] [US1] Build the schema-validation harness (compile-once with `jsonschema::validator_for(&schema)`, expose a `validate_spdx_2_3(doc: &serde_json::Value)` helper) in `mikebom-cli/tests/spdx_schema_validation.rs`
- [X] T015 [US1] In `mikebom-cli/tests/spdx_schema_validation.rs` add 9 per-ecosystem tests (`spdx_apk_validates`, `spdx_cargo_validates`, …, `spdx_rpm_validates`) — each runs the scan against the existing per-ecosystem fixture, requests SPDX 2.3, and asserts (a) the produced document has zero validator errors AND (b) the set of validator warning categories on the produced document is a subset of the warning categories produced by validating the vendored reference example `mikebom-cli/tests/fixtures/reference/SPDXJSONExample-v2.3.spdx.json` (vendored by T056) under the same validator — i.e., mikebom's output does not introduce new warning categories beyond what the SPDX project's own reference produces. Compute the reference baseline once per test-binary run via a `LazyLock` to avoid re-validating the reference for each ecosystem (FR-005, FR-021, SC-002; same file as T014 → not parallel; depends on T056 + T014). Confirmed: the SPDX reference example produces zero categories (empty baseline), and all 9 mikebom outputs also produce zero categories — the strong form of clean-validate.
- [X] T016 [P] [US1] Determinism test in `mikebom-cli/tests/spdx_determinism.rs` — run the same scan twice in-process with the same `OutputConfig.created`, assert byte-identical SPDX output (FR-020, SC-007)
- [X] T017 [P] [US1] US1 acceptance integration tests in `mikebom-cli/tests/spdx_us1_acceptance.rs` — implement spec.md US1 acceptance scenarios 1 (npm + node_modules), 2 (deb container image), 3 (declared+concluded license preservation), 4 (determinism re-run), 5 (single invocation emits both CDX and SPDX with one scan; bit-identical to two separate invocations)

### Implementation for User Story 1

- [X] T018 [P] [US1] `SpdxId` newtype in `mikebom-cli/src/generate/spdx/ids.rs` per `data-model.md` §3.1: `for_purl(&Purl) -> SpdxId` (R7 derivation: `SPDXRef-Package-<base32(SHA-256(canonical_purl))[..16]>`), `document() -> SpdxId` const for `SPDXRef-DOCUMENT`, transparent serde, no public string constructor; include `#[cfg(test)] #[cfg_attr(test, allow(clippy::unwrap_used))] mod tests` covering deterministic PURL→ID, character-set conformance, and uniqueness across a 10k-PURL fixture. A `synthetic_root(hash_prefix)` constructor was also added (shape `SPDXRef-DocumentRoot-<prefix>`) for the multi-root / no-root edge case in T025.
- [X] T019 [P] [US1] `SpdxDocumentNamespace` newtype in `mikebom-cli/src/generate/spdx/document.rs` per `data-model.md` §3.2: `derive(&ScanArtifacts, mikebom_version) -> SpdxDocumentNamespace` (R8 derivation: `https://mikebom.kusari.dev/spdx/<base32(SHA-256(canonical_scan_inputs))[..32]>` where canonical_scan_inputs = scan target + mikebom version + sorted set of resolved component PURLs), transparent serde, with unit tests asserting determinism for identical inputs and divergence for different ones
- [X] T020 [P] [US1] SPDX 2.3 envelope structs in `mikebom-cli/src/generate/spdx/document.rs`: `SpdxDocument`, `CreationInfo`, `SpdxAnnotation`, `SpdxAnnotationType` enum, `SpdxExternalDocumentRef` per `data-model.md` §3.3 with `serde::Serialize` derive and field-rename attributes
- [X] T021 [P] [US1] SPDX 2.3 Package + license + checksum + externalRef structs in `mikebom-cli/src/generate/spdx/packages.rs`: `SpdxPackage`, `SpdxChecksum`, `SpdxChecksumAlgorithm` enum, `SpdxLicenseField` enum (with custom Serialize that emits literal `"NOASSERTION"`/`"NONE"` for sentinels), `SpdxExternalRef`, `SpdxExternalRefCategory` enum
- [X] T022 [P] [US1] SPDX 2.3 Relationship struct + mapping in `mikebom-cli/src/generate/spdx/relationships.rs`: `SpdxRelationship`, `SpdxRelationshipType` enum (`DESCRIBES`, `DEPENDS_ON`, `DEV_DEPENDENCY_OF`, `BUILD_DEPENDENCY_OF`, `CONTAINS`, `CONTAINED_BY`), and the `RelationshipType → SpdxRelationshipType` mapping table. Note: the internal `RelationshipType` enum is `{DependsOn, DevDependsOn, BuildDependsOn}` — for dev/build edges SPDX's `*_DEPENDENCY_OF` verb is reversed-direction, so internal `A DevDependsOn B` emits SPDX `B DEV_DEPENDENCY_OF A` to preserve semantics.
- [X] T023 [US1] `pub fn build_packages(scan: &ScanArtifacts) -> Vec<SpdxPackage>` in `mikebom-cli/src/generate/spdx/packages.rs`: one `SpdxPackage` per `ResolvedComponent` with SPDXID from `for_purl`, name/version, `externalRefs[PACKAGE-MANAGER/purl]`, every hash → `checksums[]`, declared and concluded licenses canonicalized via `spdx::Expression::try_canonical` (NOASSERTION on parse failure), `supplier` as `"Organization: <name>"` or `NOASSERTION`, `downloadLocation = NOASSERTION`, `filesAnalyzed = false`
- [X] T024 [US1] `pub fn build_relationships(scan: &ScanArtifacts, root: &SpdxId) -> Vec<SpdxRelationship>` in `mikebom-cli/src/generate/spdx/relationships.rs`: emit `DESCRIBES` from `SPDXRef-DOCUMENT` to root, map every dependency edge per the table in T022, and expand CycloneDX nested-component containment into explicit `CONTAINS` edges between flat Packages (FR-010, FR-011). Orphan containment and unresolvable dependency PURLs are dropped with debug logs rather than producing dangling edges.
- [X] T025 [US1] `pub fn build_document(scan: &ScanArtifacts, cfg: &OutputConfig) -> SpdxDocument` in `mikebom-cli/src/generate/spdx/document.rs`: assembles the full SPDX 2.3 envelope; synthesizes a deterministic `SPDXRef-DocumentRoot-<hash>` root Package when the scan has no natural single root or multiple top-level components (Edge Case "Multiple roots / no root").
- [X] T026 [US1] `Spdx2_3JsonSerializer` impl `SbomSerializer` in `mikebom-cli/src/generate/spdx/mod.rs`: `id() == "spdx-2.3-json"`, `default_filename() == "mikebom.spdx.json"`, `experimental() == false`, `serialize()` calls `build_document` then `serde_json::to_string_pretty`; registered in `SerializerRegistry::with_defaults()` in `mikebom-cli/src/generate/mod.rs`.
- [X] T027 [US1] Update `--help` text in `mikebom-cli/src/cli/scan_cmd.rs` (corrected path; see T012 note) to list `spdx-2.3-json` as an accepted format. The unknown-id error message was already programmatic (built from `registry.ids()`) in Phase 2, so it picks up the new registration automatically.

**Checkpoint**: US1 complete. SPDX 2.3 emission is fully functional, schema-valid for all 9 ecosystems, deterministic, and works in single-format or alongside CycloneDX in one scan invocation. **MVP is shippable here.**

---

## Phase 4: User Story 2 - Dual-format data-placement guarantee + OpenVEX sidecar (Priority: P2)

**Goal**: Every mikebom-specific data element that lives in CycloneDX has a documented and exercised target location in SPDX 2.3 — either a native field, an SPDX `annotations[]` entry with the `MikebomAnnotationCommentV1` envelope, or (for VEX) an OpenVEX 0.2.0 JSON sidecar referenced from the SPDX document. Ships the canonical `docs/reference/sbom-format-mapping.md` and a CI doc-completeness check that prevents map drift.

**Independent Test**: For any scan that produces `mikebom:*` properties, evidence, compositions, or VEX in CycloneDX, the corresponding SPDX 2.3 output preserves every value via the location named in `docs/reference/sbom-format-mapping.md` — verified by the cross-format parity, annotation-fidelity, OpenVEX sidecar, and doc-completeness tests below. Open the map document and walk any row; the expected location is populated in the SPDX output for an exercising fixture.

### Tests for User Story 2 (write FIRST; FAIL until implementation lands) ⚠️

- [X] T028 [P] [US2] Cross-format parity test in `mikebom-cli/tests/spdx_cdx_parity.rs`: for each of the 9 ecosystem fixtures, request both `cyclonedx-json` and `spdx-2.3-json` from one scan, then assert that for every CDX component a matching SPDX Package exists with bit-identical PURL, version string, and the same `{algorithm, value}` checksum set (SC-003). Shipped ahead of the rest of Phase 4 on PR #20 as a Phase-3-adjacent regression guard; currently green on the US1 surface.
- [ ] T029 [P] [US2] Annotation-fidelity test in `mikebom-cli/tests/spdx_annotation_fidelity.rs`: for each ecosystem fixture, collect every `mikebom:*` property and every CDX `evidence.identity` / `evidence.occurrences` from the CDX output, then assert the SPDX output has a matching `SpdxAnnotation` whose `comment` parses as `MikebomAnnotationCommentV1` with the same `field` and the same `value` (FR-015, FR-016, walks `data-placement-map` Sections C / D / E)
- [ ] T030 [P] [US2] OpenVEX sidecar presence test in `mikebom-cli/tests/openvex_sidecar.rs`: for a fixture that produces VEX, assert (a) `mikebom.openvex.json` is written next to `mikebom.spdx.json`, (b) the SPDX document contains an `externalDocumentRefs` entry with `externalDocumentId == "DocumentRef-OpenVEX"`, the relative sidecar path, and a SHA-256 checksum that matches the sidecar bytes; for a fixture that produces no VEX, assert no sidecar file is created (FR-016a)
- [ ] T031 [US2] OpenVEX schema-validation test in `mikebom-cli/tests/openvex_sidecar.rs` using a `validate_openvex_0_2_0` helper added to the same harness module from T014 (alongside the existing `validate_spdx_2_3` helper, and the `validate_spdx_3_0_1` helper that T040 will add) against the vendored OpenVEX 0.2.0 schema (same file as T030 → not parallel)
- [X] T032 [P] [US2] Doc-completeness CI check in `mikebom-cli/tests/sbom_format_mapping_coverage.rs`: walks the pinned CDX golden fixtures from T010, extracts every distinct `properties[].name` value and every distinct field path emitted, then asserts that `specs/010-spdx-output-support/contracts/sbom-format-mapping.md` (pre-T039; will swap to `docs/reference/...` when T039 moves the file) (a) contains a row whose CycloneDX-location column matches each one AND (b) every row has a non-empty value in all three format columns (CycloneDX, SPDX 2.3, SPDX 3) — entries like `omitted — <reason>` or `defer — <reason>` count as non-empty; literal whitespace, `TODO`, `TBD`, or `?` markers fail the check (SC-004). Shipped on PR #20. Caught one real gap: added row A12 for native `component.cpe` → `externalRefs[SECURITY/cpe23Type]`.

### Implementation for User Story 2

- [ ] T033 [P] [US2] `MikebomAnnotationCommentV1` envelope struct + serializer in `mikebom-cli/src/generate/spdx/annotations.rs` per `data-model.md` §4 and `contracts/mikebom-annotation.schema.json`: `schema: &'static str = "mikebom-annotation/v1"`, `field: String`, `value: serde_json::Value`; helper `pub fn build_annotation(annotator: &str, date: &str, field: &str, value: serde_json::Value) -> SpdxAnnotation` returning a fully-formed `SpdxAnnotation` whose `comment` is the JSON-encoded envelope and `annotationType: OTHER`
- [ ] T034 [US2] Wire annotation emission in `mikebom-cli/src/generate/spdx/{packages.rs,document.rs}` per `contracts/sbom-format-mapping.md` Sections C/D/E: in `build_packages`, for each `ResolvedComponent` walk `properties` + `evidence` and append matching `SpdxAnnotation`s to the `Package.annotations` field (Section C rows + D1/D2); in `build_document`, for each metadata-level mikebom field (compositions, generation-context, os-release-missing-fields, trace-integrity-*) append to document-level `SpdxDocument.annotations` (Section C21–C23 + Section E1) (depends on T033)
- [ ] T035 [P] [US2] OpenVEX 0.2.0 structs in `mikebom-cli/src/generate/openvex/statements.rs` per `data-model.md` §6: `OpenVexDocument`, `OpenVexStatement`, `OpenVexVulnerability`, `OpenVexProduct`, `OpenVexStatus` enum, `OpenVexJustification` enum
- [ ] T036 [US2] `pub fn serialize_openvex(scan: &ScanResult, cfg: &OutputConfig) -> Option<EmittedArtifact>` in `mikebom-cli/src/generate/openvex/mod.rs`: returns `None` when `scan.vulnerabilities` is empty; otherwise builds an `OpenVexDocument` with `@context = "https://openvex.dev/ns/v0.2.0"`, deterministic `@id` (same fingerprint scheme as `SpdxDocumentNamespace`), `author = "mikebom-<version>"`, `timestamp = cfg.created`, `version = 1`, and one `OpenVexStatement` per CDX vulnerability mapping `Vulnerability.{id, affected, status, justification}` to the corresponding OpenVEX fields; serialize via `serde_json::to_vec_pretty` (depends on T035)
- [ ] T037 [US2] Co-emit OpenVEX sidecar from `Spdx2_3JsonSerializer::serialize()` in `mikebom-cli/src/generate/spdx/mod.rs`: after building the SPDX document, call `serialize_openvex`; if `Some(artifact)`, append it to the returned `Vec<EmittedArtifact>` and add an `externalDocumentRefs` entry to the SPDX document with `externalDocumentId: "DocumentRef-OpenVEX"`, `spdxDocument: <artifact.relative_path>`, `checksum: { algorithm: SHA256, checksumValue: hex(sha256(artifact.bytes)) }` (depends on T036; FR-016a)
- [ ] T038 [US2] Add `--output openvex=<path>` override handling in `mikebom-cli/src/sbom/scan_cmd.rs` (treats `openvex` as a pseudo-format for override purposes only — cannot be requested via `--format`; only honored when an SPDX format is requested AND the scan produces VEX); reject `--output openvex=...` without an SPDX format with a clear error (depends on T012)
- [ ] T039 [US2] Copy and refine the data-placement map from `specs/010-spdx-output-support/contracts/sbom-format-mapping.md` to its canonical home at `docs/reference/sbom-format-mapping.md`; ensure all internal cross-references (to spec.md, plan.md, mikebom-annotation.schema.json) resolve relative to the new location; add a top-of-file note that this is the canonical version and the `contracts/` copy is an audit mirror

**Checkpoint**: US2 complete. The SPDX output now carries full mikebom fidelity (annotations + OpenVEX sidecar) per the published map, parity tests pass, and the doc-completeness CI check guards against future drift. US1 still works exactly as before — annotations are additive.

---

## Phase 5: User Story 3 - SPDX 3.0.1 stub emitter + experimental opt-in (Priority: P3)

**Goal**: A maintainer or willing early adopter can opt in to a minimal-but-valid SPDX 3.0.1 JSON-LD document for npm components, gated behind the explicit `spdx-3-json-experimental` format identifier. The serializer-dispatch surface is exercised by real code (not paper) so that adding full SPDX 3 emission in a future milestone is incremental, not a rewrite. The stub is visibly labeled experimental everywhere it surfaces (CLI `--help`, output filename, document creator field).

**Independent Test**: Run `mikebom sbom scan --path <npm fixture> --format spdx-3-json-experimental`; the produced `mikebom.spdx3-experimental.json` validates clean against the vendored SPDX 3.0.1 schema and contains one SPDX 3 `Package` element per npm component matched by PURL. With the opt-in NOT selected, scan output is byte-identical to a build without the stub.

### Tests for User Story 3 (write FIRST; FAIL until implementation lands) ⚠️

- [ ] T040 [P] [US3] SPDX 3.0.1 schema-validation test in `mikebom-cli/tests/spdx3_stub.rs`: extends the harness from T014 with an `validate_spdx_3_0_1` helper bound to the vendored 3.0.1 schema, runs the npm fixture with `--format spdx-3-json-experimental`, asserts validation passes (FR-019a, SC-008 first half)
- [ ] T041 [US3] Opt-off byte-identity test in `mikebom-cli/tests/spdx3_stub.rs`: with `--format cyclonedx-json` (no SPDX 3 requested), assert no `mikebom.spdx3-experimental.json` is produced and the CDX output is byte-identical to the T010 fixtures (SC-008 second half + FR-019a "off by default = byte-identical to a build without the stub"; same file as T040 → not parallel)
- [ ] T042 [P] [US3] CLI experimental-labeling tests in `mikebom-cli/tests/spdx3_cli_labeling.rs`: assert (a) `mikebom sbom scan --help` output contains the literal token `[EXPERIMENTAL]` next to the `spdx-3-json-experimental` line; (b) `--format spdx-3-json` (without the suffix) exits non-zero with a "did you mean `spdx-3-json-experimental`?" message; (c) the produced SPDX 3 document's `creationInfo.createdUsing` / tool comment contains the substring `experimental` (FR-019b)
- [ ] T043 [P] [US3] US3 acceptance integration tests in `mikebom-cli/tests/spdx3_us3_acceptance.rs` covering spec.md US3 acceptance scenarios 1 (format-neutral internal types — no SPDX-3-specific struct visible from scan/resolution), 2 (data-placement map carries populated SPDX 3 column), 3 (CLI dispatch: registering the stub touched only `generate/spdx/v3_stub.rs`, `generate/spdx/mod.rs`, and `generate/mod.rs`), 4 (npm fixture → valid SPDX 3 + PURL parity), 5 (opt-in not selected → behavior identical to no-stub build)

### Implementation for User Story 3

- [ ] T044 [US3] `pub fn serialize_v3_stub(scan: &ScanResult, cfg: &OutputConfig) -> anyhow::Result<serde_json::Value>` in `mikebom-cli/src/generate/spdx/v3_stub.rs`: hand-written `serde_json::json!` macros emitting a JSON-LD document with `@context: "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"`, an `@graph` array containing a `CreationInfo` element, an `SpdxDocument` element (referencing the CreationInfo and naming the npm-root element as `rootElement`), one `Package` element per npm `ResolvedComponent` (PURL → `purl` field; checksums → nested `verifiedUsing` `Hash` elements with `algorithm` + `hashValue`; declared license → `declaredLicense` LicenseExpression element; canonicalized via `spdx::Expression::canonicalize` with NOASSERTION fallback), and `Relationship` elements for npm dependency edges. Emit a tool comment containing the literal `experimental` so T042 can assert it (FR-019a, FR-019b)
- [ ] T045 [US3] `Spdx3JsonExperimentalSerializer` impl `SbomSerializer` in `mikebom-cli/src/generate/spdx/mod.rs`: `id() == "spdx-3-json-experimental"`, `default_filename() == "mikebom.spdx3-experimental.json"`, `experimental() == true`, `serialize()` calls `serialize_v3_stub` then `serde_json::to_vec_pretty`; for non-npm scans return `Ok(vec![])` (stub coverage limitation per R3 — documented in the data-placement map and in `--help`); register in `SerializerRegistry::with_defaults()` in `mikebom-cli/src/generate/mod.rs` (depends on T044)
- [ ] T046 [US3] CLI experimental labeling in `mikebom-cli/src/sbom/scan_cmd.rs`: when constructing `--format` help text, append ` [EXPERIMENTAL]` to any registered serializer where `experimental() == true`; when parsing `--format` values, intercept the literal `spdx-3-json` (no suffix) and exit non-zero with `error: unknown format identifier 'spdx-3-json' (did you mean 'spdx-3-json-experimental'?)` (depends on T045; FR-019b)
- [ ] T047 [US3] Update `docs/reference/sbom-format-mapping.md` SPDX 3.0.1 column entries: for fields the npm stub honors (Sections A1–A8 for npm Packages, B1 for npm DEPENDS_ON edges, G1/G2/G3/G4) write the concrete SPDX 3.0.1 location instead of the previous `defer …` placeholder; leave non-npm rows and SPDX 3 evidence/compositions/VEX rows as `defer until SPDX 3 profile X stabilizes` with reasons (depends on T039)
- [ ] T048 [P] [US3] Update `quickstart.md` and `docs/user-guide/cli-reference.md` to document `spdx-3-json-experimental` (single-ecosystem coverage, opt-in, schema target = SPDX 3.0.1, deferred fields)

**Checkpoint**: US3 complete. The SPDX 3 stub validates against the vendored 3.0.1 schema, the experimental label is visible everywhere, opt-off output is regression-clean, and the path to extending the stub (additional ecosystems, SPDX 3.1) is documented as a future milestone.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Performance proof points (SC-009 dual-format wall-clock, SC-001 sbomqs cross-format quality), user-facing docs sweep, changelog, and the mandatory pre-PR verification.

- [ ] T049 [P] Performance benchmark in `mikebom-cli/tests/dual_format_perf.rs`: against the fixture `mikebom-cli/tests/fixtures/images/debian-12-slim.tar` (selected because it exercises BOTH deep-hash deb work AND embedded npm — the two paths the dual-format optimization is designed to amortize). If that fixture does not yet exist, add a precursor sub-task that produces it via `docker pull debian:12-slim && docker save debian:12-slim -o mikebom-cli/tests/fixtures/images/debian-12-slim.tar` (with a CI-friendly fallback path documented in `mikebom-cli/tests/fixtures/images/README.md`). Warm-cache the scan tree before timing; measure wall-clock time of `mikebom sbom scan --format cyclonedx-json,spdx-2.3-json --path <fixture>` vs two sequential single-format invocations against the same target; assert dual-format wall-clock is ≥ 30% lower than the sum of the two single-format runs (SC-009).
- [ ] T050 [P] Update `docs/design-notes.md` with a short paragraph noting milestone 010 status: SPDX 2.3 is now a peer of CycloneDX; an opt-in SPDX 3.0.1 stub exists for npm; the dual-format data-placement map at `docs/reference/sbom-format-mapping.md` is the canonical contract
- [ ] T051 [P] Update `docs/user-guide/cli-reference.md` to document the multi-value `--format` flag, all three format identifiers (one stable, one new-stable, one experimental), the `--output <fmt>=<path>` per-format override syntax, and the OpenVEX sidecar emission rules
- [ ] T052 Add a milestone 010 entry to `CHANGELOG.md` summarizing user-visible changes (SPDX 2.3 output, dual-format emission, OpenVEX sidecar, experimental SPDX 3 stub) — sequential since the file is append-only and shared with any concurrent milestone work
- [ ] T053 Manual quickstart validation: against a multi-ecosystem fixture (e.g., a Debian image with embedded npm + maven), execute every command block in `specs/010-spdx-output-support/quickstart.md`, verify produced files exist at the documented default paths and validate clean against the vendored schemas; update `quickstart.md` with any corrections discovered
- [ ] T055 [P] sbomqs cross-format scoring test in `mikebom-cli/tests/sbomqs_parity.rs`: provision the `sbomqs` binary in CI (vendor as a release artifact under `mikebom-cli/tests/fixtures/bin/sbomqs` with the version pinned in `mikebom-cli/tests/fixtures/bin/SBOMQS_VERSION`, or install via the project's CI provisioning step). For each of the 9 ecosystem fixtures, invoke `sbomqs score` against both the CDX and the SPDX outputs from a single dual-format scan; assert the SPDX score is greater than or equal to the CDX score on the categories both formats express natively (NTIA-minimum: name, version, supplier, checksums, license, dependencies, externalRefs). Sequenced AFTER T053 (quickstart validation) and BEFORE T054 (pre-PR gate). (SC-001)
- [ ] T054 Pre-PR verification (per Constitution + `CLAUDE.md`): run `cargo +stable clippy --workspace --all-targets` (zero errors required) AND `cargo +stable test --workspace` (every suite reports `ok. N passed; 0 failed`). Both must be clean before opening the PR; fix any clippy or test failure as a blocking task — do not ship until both are green

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No dependencies. Start immediately. All 7 tasks (T001–T006 + T056) can run in parallel.
- **Phase 2 (Foundational)**: Depends on Phase 1 completion. **Blocks all user stories.**
- **Phase 3 (US1 — MVP)**: Depends on Phase 2 completion. **Shippable on its own.**
- **Phase 4 (US2)**: Depends on Phase 2 completion (registry + dispatch). Phase 4 implementation tasks (T034, T037, T038) modify files first written in Phase 3 (T023, T025, T026, T012), so US2 implementation must follow US1 implementation. US2 *tests* (T028–T032) can be written in parallel with US1 implementation if a developer is available.
- **Phase 5 (US3)**: Depends on Phase 2 completion. Independent of US2 implementation (no shared files except `generate/{spdx,}/mod.rs` registry registration, which is append-only). Can run in parallel with US2.
- **Phase 6 (Polish)**: Depends on US1 + US2 + US3 being complete (T049–T053, T055). T054 is the final gate before PR.

### User Story Dependencies

- **US1 (P1)**: Independent — only depends on the foundational dispatch layer.
- **US2 (P2)**: Builds on US1 (the SPDX serializer it extends with annotations and the OpenVEX cross-reference is registered in US1). US2 tests depend on US1 implementation existing.
- **US3 (P3)**: Independent of US2. Touches only `generate/spdx/v3_stub.rs`, `generate/spdx/mod.rs` registry registration, `generate/mod.rs` registry, `sbom/scan_cmd.rs` help text, and the SPDX 3 column of the data-placement map. US3 acceptance scenario 3 explicitly verifies this isolation.

### Within Each User Story

- Tests (T014–T017, T028–T032, T040–T043) MUST be written before their corresponding implementation lands and MUST initially fail.
- Per data-model.md §8, all serializer implementations honor the determinism contract (sorted iteration, single shared `OutputConfig.created`, no `HashMap` in the serialization path).
- Constitution Principle IV: no `.unwrap()` in production code. Test modules must use `#[cfg_attr(test, allow(clippy::unwrap_used))]` per the `mikebom-cli/src/trace/` convention.

### Parallel Opportunities

- **All 7 Setup tasks (T001–T006 + T056)** can run in parallel.
- **T010 (CDX golden fixtures)** can run in parallel with **T009 (CDX serializer refactor)** since T009 must produce byte-identical output and T010 captures that exact output either before or after T009.
- **US1 model layer (T018–T022)** — five files, all independent — can run in parallel.
- **US1 tests (T014, T016, T017)** are independent files; T015 shares a file with T014, so T015 follows T014.
- **US2 tests (T028–T032)** are independent files (T030+T031 share `openvex_sidecar.rs` so they're sequential between themselves, but parallel with T028, T029, T032).
- **US3 tests (T040+T041 share a file)**, T042 and T043 are independent files.
- **US2 and US3 implementations** can run in parallel after US1 lands (different files, with US3 only adding to the registry's `with_defaults()` after US1 has done so).
- **Polish tasks T049–T051** can run in parallel; T052/T053/T054 are sequential.

---

## Parallel Example: User Story 1

```bash
# Step 1: write the failing tests in parallel (after T014 harness lands)
Task: "T016 [US1] Determinism test in mikebom-cli/tests/spdx_determinism.rs"
Task: "T017 [US1] US1 acceptance integration tests in mikebom-cli/tests/spdx_us1_acceptance.rs"
# (T015 follows T014 sequentially — same file)

# Step 2: write the model layer in parallel (after tests are red)
Task: "T018 [US1] SpdxId newtype in mikebom-cli/src/generate/spdx/ids.rs"
Task: "T019 [US1] SpdxDocumentNamespace newtype in mikebom-cli/src/generate/spdx/document.rs"
Task: "T020 [US1] SPDX 2.3 envelope structs in mikebom-cli/src/generate/spdx/document.rs"
Task: "T021 [US1] SPDX 2.3 Package + license + checksum + externalRef structs in mikebom-cli/src/generate/spdx/packages.rs"
Task: "T022 [US1] SPDX 2.3 Relationship struct + mapping in mikebom-cli/src/generate/spdx/relationships.rs"
# Note: T019 and T020 both live in document.rs — coordinate the merge; the rest are independent files.

# Step 3: assemble (sequential — depends on the parallel layer above)
T023 → T024 → T025 → T026 → T027
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. **Phase 1: Setup** — vendor schemas, add `jsonschema 0.46` dev-dep, scaffold modules. ~6 small tasks; can land in one PR.
2. **Phase 2: Foundational** — registry trait, CDX refactor behind it, pinned golden fixtures, regression test, multi-value `--format` flag. The CDX byte-identity test from T011 is the load-bearing safety net for everything that follows.
3. **Phase 3: User Story 1** — write failing tests (T014–T017), build the SPDX 2.3 serializer (T018–T026), wire it into the CLI (T027).
4. **STOP and VALIDATE**: 9 ecosystem fixtures produce schema-valid SPDX 2.3 documents; CDX output is unchanged; both formats can be emitted from one scan. This is the minimum a user can adopt.
5. **Ship**: SPDX 2.3 output is now usable in production for users who only need parity on native fields.

### Incremental Delivery

1. Setup + Foundational (~13 tasks) → safety net in place.
2. US1 (~14 tasks) → schema-valid SPDX 2.3 output ready for any consumer that tolerates "thin" annotations. **Demo-able / shippable.**
3. US2 (~12 tasks) → adds full mikebom fidelity (annotations + OpenVEX sidecar) and the canonical map document. **Demo-able / shippable on top of US1.**
4. US3 (~9 tasks) → opt-in SPDX 3.0.1 stub for early adopters. **Demo-able / shippable on top of US1.**
5. Polish (~6 tasks) → performance proof, docs, changelog, pre-PR verification.

### Parallel Team Strategy

After Phase 2 completes:

- **Developer A** drives US1 to completion (the MVP critical path).
- **Developer B** writes US2 tests (T028–T032) in parallel with A's US1 implementation; once US1 lands, B starts US2 implementation.
- **Developer C** drives US3 from start to finish — minimal interaction with US2 work (the only shared touchpoint is `SerializerRegistry::with_defaults()`, an append-only registration site).
- All three converge in Phase 6; T054 (pre-PR clippy + test) is the final gate.

---

## Notes

- **Tests are required, not optional.** The spec explicitly mandates them (FR-021, plus seven SC-NNN criteria each describe an automated test). All test tasks land inside their owning user story's phase.
- **Determinism is a global invariant.** Every implementation task must honor the `data-model.md §8` contract (single `OutputConfig.created`; `BTreeMap`/sorted iteration; no `HashMap` on the serialization path; no direct `Utc::now()` calls). The determinism test (T016) catches regressions immediately.
- **CDX byte-identity is a global safety net.** T011 protects FR-022 / SC-006. If any task accidentally changes CDX output, T011 fires before any of the SPDX work can be merged.
- **No `.unwrap()` in production.** Test modules must use `#[cfg_attr(test, allow(clippy::unwrap_used))]` matching the `mikebom-cli/src/trace/` convention. This is a Constitution Principle IV gate enforced by `cargo +stable clippy --workspace --all-targets`.
- **No new runtime crates.** `jsonschema 0.46` is `[dev-dependencies]` only. All serializers are hand-written `serde` structs per `research.md` R1, R2, R4.
- **Constitution deviation tracker**: Principle V names "SPDX 3.1." This milestone ships SPDX 2.3 + a SPDX 3.0.1 stub with documented justification in `plan.md` → Complexity Tracking. A follow-up PR amending Principle V is recommended but not blocking for this milestone.
- Commit after each task or logical group; use the existing project commit-message style (see `git log --oneline -20`).
- Stop at any checkpoint to validate the just-completed user story independently.
