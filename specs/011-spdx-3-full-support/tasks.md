---
description: "Task list — Full SPDX 3.x Output Support (milestone 011)"
---

# Tasks: Full SPDX 3.x Output Support

**Input**: Design documents from `/specs/011-spdx-3-full-support/`
**Prerequisites**: plan.md (✅), spec.md (✅), research.md (✅), data-model.md (✅), contracts/spdx-3-emitter.contract.md (✅), quickstart.md (✅)

**Tests**: Test tasks are included. Spec success criteria SC-001 through SC-010 each name an enforcing CI gate, the contract enumerates G1–G10 with named test files, and the project's pre-PR gate (constitution Development Workflow §Pre-PR Verification) requires `cargo test --workspace` clean. Tests are load-bearing, not optional.

**Organization**: Tasks are grouped by user story. Stories from spec.md:
- US1 (P1, MVP): Production-grade SPDX 3 output across all 9 ecosystems with native-field parity vs. CycloneDX.
- US2 (P2): Every `mikebom:*` signal in SPDX 2.3 reaches SPDX 3 — native field if Q2-strict-match, Annotation otherwise.
- US3 (P3): Retire the experimental label; alias `spdx-3-json-experimental` accepted with deprecation notice.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Maps task to spec.md user story (US1, US2, US3); omitted on Setup/Foundational/Polish

## Path Conventions

Single Rust workspace; mikebom is a CLI binary. Source under `mikebom-cli/src/`, tests under `mikebom-cli/tests/`, bundled fixtures under `mikebom-cli/tests/fixtures/`. Mapping doc at `docs/reference/sbom-format-mapping.md`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Bundle the schema fixture and scaffold the per-element file layout. Makes US1 implementation work directly without bookkeeping detours.

- [X] T001 Download the published SPDX 3.0.1 JSON-LD schema and place it at `mikebom-cli/tests/fixtures/schemas/spdx-3.0.1.json` (path adjusted to match the existing milestone-010 `tests/fixtures/schemas/` convention; SHA-256 `582c64e809d5b3ef9bd0c4de13a32391b47b0284a3e8d199569fb96f649234b1`, fetched 2026-04-24).
- [X] T002 [P] Scaffolded `mikebom-cli/src/generate/spdx/v3_document.rs`, `v3_packages.rs`, `v3_relationships.rs`, `v3_licenses.rs`, `v3_agents.rs`, `v3_external_ids.rs`, `v3_annotations.rs`. Each `build_*` returns empty data per analysis I2 fix (avoids `unimplemented!()` panics if accidentally invoked).
- [X] T003 [P] Registered the new modules in `mikebom-cli/src/generate/spdx/mod.rs` (`pub mod v3_*;`).

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Establish the new stable format identifier `spdx-3-json` and route it through a placeholder `v3_document::build_document` that delegates to the existing `v3_stub::serialize_v3_stub` for now. This unblocks tests in subsequent phases (the format identifier exists; tests can call it). The placeholder is replaced incrementally during US1.

**⚠️ CRITICAL**: No US1/US2/US3 work begins until this phase is complete.

- [X] T004 Added `Spdx3JsonSerializer` struct in `mikebom-cli/src/generate/spdx/mod.rs` with `id="spdx-3-json"`, `default_filename="mikebom.spdx3.json"`, `experimental()=true`. Refactored `Spdx3JsonExperimentalSerializer` to delegate verbatim to `Spdx3JsonSerializer::serialize` per research.md §R6 — alias produces byte-identical output, default filename `mikebom.spdx3.json` (same as stable, NOT the milestone-010 `mikebom.spdx3-experimental.json`).
- [X] T005 Implemented `v3_document::build_document` in `mikebom-cli/src/generate/spdx/v3_document.rs` as a Phase-2 placeholder that delegates to `super::v3_stub::serialize_v3_stub`. Phase 3 progressively replaces the body with native composition.
- [X] T006 Registered both `Spdx3JsonSerializer` and `Spdx3JsonExperimentalSerializer` in `SerializerRegistry::with_defaults()`. Removed the milestone-010 typo-guard for `spdx-3-json` in `cli/scan_cmd.rs::resolve_dispatch` — that identifier is now first-class. Updated the `--format` doc comment to describe both identifiers.
- [X] T007 Added SPDX 3.0.1 schema-loader helper in `mikebom-cli/tests/spdx3_schema_validation.rs` using `OnceLock<jsonschema::Validator>` to amortize compilation. Smoke test `schema_loader_compiles` passes — schema parses + compiles cleanly. Per-fixture coverage tests added in Phase 3 T008.

**Checkpoint**: `cargo +stable test --workspace` passes; `--format spdx-3-json` is accepted by the CLI and emits the placeholder stub bytes; schema-validation harness wired but with zero per-fixture assertions.

---

## Phase 3: User Story 1 — Production-grade SPDX 3 across all 9 ecosystems (Priority: P1) 🎯 MVP

**Goal**: For every fixture in `mikebom-cli/tests/fixtures/{apk,cargo,deb,gem,go,maven,npm,pip,rpm}`, `mikebom sbom scan --format spdx-3-json` produces a schema-valid SPDX 3 document containing one `software_Package` per CycloneDX component with PURL, name, version, license, hash data populated in native SPDX 3 fields.

**Independent Test**: Run `cargo +stable test -p mikebom --test spdx3_schema_validation` and `--test spdx3_cdx_parity` and `--test spdx3_determinism` — all three pass for every ecosystem.

### Tests for User Story 1

- [X] T008 [P] [US1] Authored `mikebom-cli/tests/spdx3_schema_validation.rs`. 10 tests (9 ecosystems + 1 loader smoke). **All 10 pass.**
- [X] T009 [P] [US1] Authored `mikebom-cli/tests/spdx3_cdx_parity.rs`. 9 per-ecosystem tests confirming PURL set, version, and checksum-set parity between CDX and SPDX 3 outputs. **All 9 pass.**
- [X] T010 [P] [US1] Authored `mikebom-cli/tests/spdx3_determinism.rs`. 3 tests against npm, cargo, deb fixtures. **All 3 pass.**

### Implementation for User Story 1

- [X] T011 [P] [US1] Implemented `v3_packages.rs`. Emits Packages with name, version, packageUrl (typed), verifiedUsing Hash objects, software_homePage/sourceInfo/downloadLocation from external_references, externalIdentifier list (via v3_external_ids), suppliedBy/originatedBy (via v3_agents attachment map). Two entry points: `build_iri_lookup` (first pass — PURL→IRI) and `build_packages` (second pass — full Package elements).
- [X] T012 [P] [US1] Implemented `v3_external_ids.rs`. Emits one `packageUrl` ExternalIdentifier per component + one `cpe23` entry per fully-resolved CPE. SPDX 3 vocabulary's externalIdentifierType value is `"packageUrl"`, NOT `"purl"` (bundled-schema enum).
- [X] T013 [P] [US1] Implemented `v3_relationships.rs`. Emits `dependsOn` for all three CDX relationship kinds (DependsOn/DevDependsOn/BuildDependsOn) — SPDX 3.0.1's `prop_Relationship_relationshipType` enum has no `devDependencyOf`/`buildDependencyOf` entries; the dev/build subtype signal will be preserved via the C6 `mikebom:dev-dependency` annotation in US2. Containment edges emit as `contains`. Documented the rationale in v3_relationships.rs module docs + mapping doc row B2.
- [X] T014 [P] [US1] Implemented `v3_licenses.rs`. Emits `simplelicensing_LicenseExpression` elements (deduped across packages by canonical-expression string) + `hasDeclaredLicense` / `hasConcludedLicense` Relationships. Canonicalization via `spdx::Expression::try_canonical(&str)`; canonicalization failure preserves raw string verbatim per FR-008.
- [X] T015 [P] [US1] Implemented `v3_agents.rs`. Emits `Organization` elements + returns `AgentBuild { elements, attachments }` where `attachments` maps each Package IRI to its `suppliedBy`/`originatedBy` values. In SPDX 3, supplier/originator are properties on the Package (inherited from Artifact_props), NOT Relationship edges — the schema's relationshipType enum has no `suppliedBy` entry. Package builder inlines the attachments onto each Package.
- [X] T016 [US1] Rewrote `v3_document::build_document` from a `v3_stub` delegation into a full two-pass compositor: (a) PURL→IRI lookup, (b) agent attachments, (c) full Package emission, (d) agent + license element emission, (e) combined Relationship list (dependency + containment + license + describes edges, sorted by spdxId). Deterministic ordering per data-model.md §"Deterministic ordering rules". `v3_stub.rs` marked `#![allow(dead_code)]` (T032 will delete it).
- [X] T017 [US1] Updated `docs/reference/sbom-format-mapping.md` Section A defer rows: A1 (added SPDX 3 ExternalIdentifier in addition to typed property), A4 (suppliedBy via Artifact_props property, not Relationship), A5 (explicit "omitted — resolution layer doesn't surface originator"), A6 (algorithm enum lowercase), A7/A8 (hasDeclaredLicense/hasConcludedLicense Relationship edges), A12 (ExternalIdentifier[cpe23]), plus B2 (no devDependencyOf in SPDX 3.0.1 enum).

**Checkpoint**: T008/T009/T010 pass for all 9 ecosystems. `cargo +stable clippy --workspace --all-targets` clean. SPDX 3 emitter is functionally on par with SPDX 2.3 on Section A native fields. US1 is complete and demonstrable as the milestone MVP.

---

## Phase 4: User Story 2 — Mikebom-specific signal fidelity in SPDX 3 (Priority: P2)

**Goal**: Every `mikebom:*` field reachable in SPDX 2.3 (Sections C, D, E of the mapping doc) reaches SPDX 3 — native field if Q2-strict-match permits, Annotation otherwise. OpenVEX sidecar cross-referenced via `ExternalRef` on the SpdxDocument element.

**Independent Test**: `cargo +stable test -p mikebom --test spdx3_annotation_fidelity` passes for all 9 ecosystems; `cargo +stable test -p mikebom --test openvex_sidecar` passes (covers both 2.3 and 3 cross-ref paths).

### Tests for User Story 2 (write before implementation)

- [ ] T018 [P] [US2] Author `mikebom-cli/tests/spdx3_annotation_fidelity.rs`. For each of 9 ecosystems, run dual-scan `--format spdx-2.3-json,spdx-3-json`. Build the set of `(field_name, value)` pairs reachable in the SPDX 2.3 output (from `annotations[].comment` decoded as `MikebomAnnotationCommentV1` plus native fields per the mapping doc). Build the same set from the SPDX 3 output (from `Annotation.statement` decoded the same way plus the corresponding native fields). Assert set equality. One test per ecosystem so a failure names the offender.
- [ ] T019 [P] [US2] Extend `mikebom-cli/tests/openvex_sidecar.rs` with two new `#[test]`s: (a) `spdx3_with_vex_emits_external_ref_on_document` — synthetic ScanArtifacts with one advisory; assert `SpdxDocument.externalRef[]` carries exactly one `securityAdvisory` entry whose `locator` matches the sidecar's emitted path. (b) `spdx3_no_vex_emits_no_external_ref` — empty advisories; assert `externalRef` is absent or empty.

### Implementation for User Story 2

- [ ] T020 [P] [US2] Implement `mikebom-cli/src/generate/spdx/v3_annotations.rs` per `data-model.md` `Annotation`. Function `pub fn build_annotations(...) -> Vec<Value>` emitting one Annotation per `(subject, field, value)` tuple drawn from per-component mikebom fields and document-level fields. `statement` is the JSON-encoded `MikebomAnnotationCommentV1` envelope reused verbatim from milestone 010 (`mikebom-cli/src/generate/spdx/annotations.rs::MikebomAnnotationCommentV1`).
- [ ] T021 [US2] Wire component-level annotations into `v3_document::build_document`. Cover the 20 fields enumerated in `data-model.md` §"Mapping from `ResolvedComponent` fields" Annotation rows (C1–C20 per the mapping doc) — `is_dev`, `evidence_kind`, `binary_class`, `binary_stripped`, `linkage_kind`, `detected_go`, `confidence`, `binary_packed`, `npm_role`, `raw_version`, `parent_purl`, `co_owned_by`, `shade_relocation`, `requirement_range`, `source_type`, `sbom_tier`, `buildinfo_status`, `evidence.technique`, `evidence.confidence`, `occurrences`. Skip fields that are already bound to native SPDX 3 properties (per the mapping doc) to avoid double-emission.
- [ ] T022 [US2] Wire document-level annotations into `v3_document::build_document`: `mikebom:generation-context` (C21), `mikebom:os-release-missing-fields` (C22), `mikebom:trace-integrity-*` subkeys (C23), `compositions` (E1).
- [ ] T023 [US2] Implement OpenVEX `ExternalRef` cross-reference on the SpdxDocument element in `v3_document::build_document`. Build the OpenVEX sidecar artifact via the existing `crate::generate::openvex::serialize_openvex(scan, cfg)` (same call the SPDX 2.3 path makes), then on non-`None` result, push `{type: "ExternalRef", externalRefType: "securityAdvisory", locator: <relative-path>, comment: "OpenVEX 0.2.0 sidecar produced by mikebom"}` into the SpdxDocument's `externalRef[]` list. Path-resolution copies the SPDX 2.3 path's logic (`OutputConfig.overrides["openvex"]` if set, else artifact's relative_path).
- [ ] T024 [US2] Implement the C19 split in `v3_document::build_document` (or a helper in `v3_external_ids.rs` + `v3_annotations.rs` collaboration): for each component's `cpes`, emit ExternalIdentifier[cpe23] entries for fully-resolved candidates AND emit one Annotation `mikebom:cpe-candidates` carrying the residual unresolved set. Per research.md §R3 + §R5.
- [ ] T025 [US2] Update remaining "defer" cells in `docs/reference/sbom-format-mapping.md` — Sections C and E. Per research.md §R5: C8 stays Annotation, C16 stays Annotation, C18 stays Annotation, C19 documented as split (native + Annotation), C21–C23 documented as document-level Annotation, E1 documented as document-level Annotation. Replace any remaining `defer until SPDX 3 …` text with the actual SPDX 3 binding.
- [ ] T026 [US2] Wire the OpenVEX sidecar artifact into `Spdx3JsonSerializer::serialize` return value (not just the cross-reference): when the OpenVEX serializer returns `Some(artifact)`, append it to the `Vec<EmittedArtifact>` so the file lands on disk alongside the SPDX 3 document. Mirrors the SPDX 2.3 path in `mikebom-cli/src/generate/spdx/mod.rs::Spdx2_3JsonSerializer::serialize`.

**Checkpoint**: T018 + T019 pass. Every mikebom signal reachable in SPDX 2.3 is reachable in SPDX 3 by field name and value. OpenVEX sidecar emits and is cross-referenced.

---

## Phase 5: User Story 3 — Retire experimental label, install deprecation alias (Priority: P3)

**Goal**: `--format spdx-3-json` is no longer flagged experimental in CLI help; produced documents carry no experimental marker. `--format spdx-3-json-experimental` continues to work — emits the same bytes (modulo the experimental marker on `CreationInfo.comment` and `SpdxDocument.comment`) and prints a one-line stderr deprecation notice.

**Independent Test**: `cargo +stable test -p mikebom --test spdx3_cli_labeling` and `--test spdx3_us3_acceptance` pass.

### Tests for User Story 3 (write before implementation)

- [ ] T027 [P] [US3] Rewrite `mikebom-cli/tests/spdx3_cli_labeling.rs` to assert: `mikebom sbom scan --help` text contains the literal `spdx-3-json` with no `(experimental)` annotation; AND `spdx-3-json-experimental` is still listed but explicitly marked as deprecated/aliased.
- [ ] T028 [P] [US3] Rewrite `mikebom-cli/tests/spdx3_us3_acceptance.rs` to assert: (a) running `--format spdx-3-json-experimental` exits zero and emits the deprecation notice exactly once on stderr (notice text per `research.md` §R2 — two lines covering deprecation directive + shape-change advisory); (b) the bytes emitted by the alias are **byte-identical** to the bytes emitted by `--format spdx-3-json` for the same scan (per research.md §R6 / contract §4); (c) `MIKEBOM_NO_DEPRECATION_NOTICE=1` suppresses the stderr warning while leaving the document bytes unchanged.

### Implementation for User Story 3

- [ ] T029 [US3] Flip `Spdx3JsonSerializer::experimental()` from `true` to `false` in `mikebom-cli/src/generate/spdx/mod.rs`. Verify `v3_document::build_document` does NOT add the experimental-marker `comment` properties on `CreationInfo` or `SpdxDocument` for the stable path.
- [ ] T030 [US3] Refactor `Spdx3JsonExperimentalSerializer::serialize` to **delegate verbatim** to `Spdx3JsonSerializer::serialize`. Per research.md §R6 / contract §4, the alias produces byte-identical bytes to the stable identifier — no comment-marker injection, no JSON post-processing. Set `Spdx3JsonExperimentalSerializer::experimental()` to return `false` (deprecation lifecycle is signaled separately, not via the trait flag). Default filename is `mikebom.spdx3.json` (same as stable). Drop the milestone-010 `EXPERIMENTAL_MARKER` constant from `mikebom-cli/src/generate/spdx/v3_stub.rs` if T032's deletion hasn't already removed it; if the marker is referenced elsewhere, remove those references too.
- [ ] T031 [US3] Wire deprecation-notice emission in `mikebom-cli/src/cli/scan_cmd.rs`: when the user passes `--format spdx-3-json-experimental` (any of the comma-separated formats), print the two-line FR-002 deprecation notice to stderr exactly once per invocation (deprecation directive + shape-change advisory). Honor `MIKEBOM_NO_DEPRECATION_NOTICE=1` env override. Notice text verbatim per research.md §R2. Also wire help-text annotation: when the CLI's format-list rendering encounters `spdx-3-json-experimental`, append `(deprecated, use spdx-3-json)` to the line so `--help` output communicates the lifecycle status (separate from the trait's `experimental()` flag, which is now `false`).
- [ ] T032 [US3] Delete `mikebom-cli/src/generate/spdx/v3_stub.rs`. Remove the `pub mod v3_stub;` line from `mikebom-cli/src/generate/spdx/mod.rs`. The function previously lived here is no longer reachable.
- [ ] T033 [US3] Delete `mikebom-cli/tests/spdx3_stub.rs` (npm-only stub coverage no longer applies — full coverage tested by `spdx3_schema_validation.rs` + `spdx3_cdx_parity.rs`).

**Checkpoint**: All three user stories complete. Stable identifier is `spdx-3-json`; alias is `spdx-3-json-experimental` with deprecation notice; emitter has full-ecosystem coverage and full mikebom-signal fidelity.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: SC-001 (sbomqs cross-format scoring), SC-007 (triple-format perf gate), SC-004/SC-010 (mapping coverage), final cleanup. These tests validate properties that span all three user stories rather than belonging to one.

- [ ] T034 [P] Extend `mikebom-cli/tests/sbomqs_parity.rs` to also produce + score the SPDX 3 output for each ecosystem and assert `spdx3_score ≥ cdx_score` on every entry of `NATIVE_FEATURES`. Use the same skip-on-no-binary pattern. Update the file's module doc to describe SC-001 enforcement across CDX/2.3/3.
- [ ] T035 [P] Add `mikebom-cli/tests/triple_format_perf.rs`. Mirror the structure of `dual_format_perf.rs`: same synthetic fixture (500 deb + 1500 npm), median-of-3 wall-clock measurement, three sequential single-format invocations vs. one triple-format invocation. CI gate at ≥25% reduction (per research.md §R3 / spec SC-007 CI threshold). Constant `SC007_CI_MIN_REDUCTION = 0.25` with a doc comment matching the milestone-010 noise-budget rationale verbatim. `MIKEBOM_PERF_IMAGE` env override accepted.
- [ ] T036 [P] Verify `mikebom-cli/tests/sbom_format_mapping_coverage.rs` enforcement: every row in `docs/reference/sbom-format-mapping.md` has a non-placeholder SPDX 3 column entry after T017 + T025. Test currently checks all three columns; confirm SPDX 3 column passes after this milestone's mapping-doc updates (no test code change expected; if the test fails, the failure output names the offending rows and the fix is doc-only).
- [ ] T036b [P] Confirm milestone-010 byte-equality regression-guards still pass (FR-019 / SC-009 opt-off invariant): run `cargo +stable test -p mikebom --test cdx_regression --test spdx_us1_acceptance --test spdx_determinism --test spdx_annotation_fidelity` and assert all four report `ok. N passed; 0 failed`. Cite the per-test counts in the PR description per `feedback_prepr_gate_full_output.md`. Closes the analysis-G1 gap by making the implicit pre-PR-gate coverage of FR-019/SC-009 an explicit task with cited evidence.
- [ ] T037 [P] Update `mikebom-cli/tests/format_dispatch.rs` to register-test both `spdx-3-json` and `spdx-3-json-experimental`: both identifiers dispatch with `experimental()=false` (per research.md §R6 / contract §4 — alias is a deprecation track, not an experimental emitter); both emit a `mikebom.spdx3.json` artifact when no override is set; alias-vs-stable byte equality assertion confirms the two outputs are byte-identical for the same scan.
- [ ] T038 [P] Update `mikebom-cli/src/generate/spdx/mod.rs` module documentation: replace the milestone-010 stub-coverage paragraph with a one-sentence note that SPDX 3 covers all 9 ecosystems with full mikebom-signal fidelity per `docs/reference/sbom-format-mapping.md` and `specs/011-spdx-3-full-support/`.
- [ ] T039 Run quickstart.md smoke-test commands manually — release-build the binary, run against `tests/fixtures/npm/node-modules-walk` and one container-image fixture, inspect the emitted SPDX 3 document with `jq` for sane shape.
- [ ] T040 Run pre-PR gate: `cargo +stable clippy --workspace --all-targets` (zero errors) AND `cargo +stable test --workspace` (every suite reports `ok. N passed; 0 failed`). Capture the per-target `passed; 0 failed` lines from the test output and include them in the PR description, per `feedback_prepr_gate_full_output.md`.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies. T001/T002/T003 can run as soon as the branch is checked out. T002/T003 are [P].
- **Foundational (Phase 2)**: Depends on Setup. Blocks all user stories. T004/T005/T006/T007 sequential — each depends on the prior. Once Phase 2 is at the checkpoint, all three user stories can be picked up in parallel by separate developers if staffed.
- **US1 (Phase 3)**: Depends on Foundational. Inside US1: T008/T009/T010 (tests) run first and are mutually [P]; T011/T012/T013/T014/T015 (per-element implementations) are mutually [P] and run in parallel; T016 (composition) depends on T011–T015; T017 (mapping doc) is [P] with implementation work — doc edit is in a separate file.
- **US2 (Phase 4)**: Depends on US1 (specifically T016 — the composition function must exist before annotation rows can be plugged in). Inside US2: T018/T019 (tests) [P]; T020 [P] with the tests; T021/T022/T023/T024/T026 sequential against `v3_document.rs` (same file); T025 (mapping doc) [P].
- **US3 (Phase 5)**: Depends on US1 + US2 (the spec's gating rule — the alias is a deprecation track, not a parallel feature; experimental label only retires when the implementation is at parity with SPDX 2.3). Inside US3: T027/T028 (tests) [P]; T029/T030 sequential (same file); T031 independent file; T032/T033 deletions.
- **Polish (Phase 6)**: Depends on all three user stories complete. T034/T035/T036/T037/T038 mutually [P] (different files); T039/T040 sequential at the end.

### User Story Dependencies (in spec.md priority order)

- **US1 (P1)**: Independent within Foundational gate. Can ship as MVP standalone — produces a stable, schema-valid SPDX 3 document on the new `spdx-3-json` identifier (still flagged experimental in help; flag removal is US3).
- **US2 (P2)**: Depends on US1's compose function (T016). Adds annotations + OpenVEX cross-ref. Can ship after US1 as an independent increment — tests pass, no US3 work required.
- **US3 (P3)**: Depends on US1+US2 acceptance. Smallest piece — flips a flag, adds an alias delegate, deletes the stub. Could ship same release as US1+US2 or held back as a follow-up.

### Within Each User Story

- Tests (T008/T009/T010 for US1; T018/T019 for US2; T027/T028 for US3) are written first and expected to fail until the implementation tasks land. This is the project's standard workflow per the constitution's Test Isolation principle (VII) and the milestone-010 cadence.
- Models/elements (per-element `v3_*.rs` files) before composition (`v3_document.rs`).
- Composition before mapping-doc edits in the same story (mapping doc references the implementation, not vice versa — but the doc edit is a free-standing parallelizable file edit).

### Parallel Opportunities

- **Setup**: T002 + T003 in parallel.
- **US1 implementation**: T011 + T012 + T013 + T014 + T015 all in parallel (five separate files).
- **US1 tests**: T008 + T009 + T010 in parallel.
- **US2 implementation**: T020 in parallel with the test pair (T018/T019). T025 (mapping doc) [P] with everything else in US2.
- **US3**: T027 + T028 in parallel; T031 in parallel with T029/T030.
- **Polish**: T034 + T035 + T036 + T037 + T038 all in parallel.

---

## Parallel Example: User Story 1 implementation

```bash
# Five element-builder implementations run in parallel (different files):
Task: "Implement v3_packages.rs per data-model.md §software_Package"
Task: "Implement v3_external_ids.rs per data-model.md §ExternalIdentifier"
Task: "Implement v3_relationships.rs per data-model.md §Relationship"
Task: "Implement v3_licenses.rs per data-model.md §simplelicensing_LicenseExpression"
Task: "Implement v3_agents.rs per data-model.md §Organization/Person"

# Three test files in parallel (different files):
Task: "Author tests/spdx3_schema_validation.rs (9 ecosystems)"
Task: "Author tests/spdx3_cdx_parity.rs (9 ecosystems)"
Task: "Author tests/spdx3_determinism.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001–T003).
2. Complete Phase 2: Foundational (T004–T007). New format identifier accepted by CLI; emits placeholder bytes.
3. Complete Phase 3: User Story 1 (T008–T017). Schema-valid full-coverage SPDX 3 across 9 ecosystems with native-field parity.
4. **STOP and VALIDATE**: Run `cargo +stable test -p mikebom --test spdx3_schema_validation`, `--test spdx3_cdx_parity`, `--test spdx3_determinism` — all pass. Run pre-PR gate.
5. Could merge as MVP — stable identifier, full ecosystem coverage, still flagged experimental in help.

### Incremental Delivery

1. Setup + Foundational ready.
2. Add US1 → MVP (full-coverage SPDX 3, experimental flag still on).
3. Add US2 → Annotation fidelity + OpenVEX cross-ref.
4. Add US3 → Retire experimental label, install deprecation alias.
5. Polish → SC-001 sbomqs gate + SC-007 triple-format perf gate + final cleanup.

### Parallel Team Strategy (if staffed)

- Single developer typical for this milestone — work proceeds sequentially through phases.
- With multiple developers: after Foundational, US1 tests + US1 element implementations split across developers (10 parallel-able files); US2 + US3 can also run in parallel with each other after US1's `T016` lands, since US3 work is mostly CLI-surface flips that don't touch `v3_*.rs` element files.

---

## Notes

- File paths above are absolute relative to repo root; cargo commands run from repo root.
- Tests are not optional in this milestone — SC-001 through SC-010 each name an enforcing CI gate, and the constitution's Pre-PR Verification clause rejects PRs whose `cargo +stable test --workspace` is not clean.
- Pre-PR gate (T040) is the final required step before opening any PR carrying these tasks — both `cargo +stable clippy --workspace --all-targets` AND `cargo +stable test --workspace` must pass clean. Citing a passing per-crate test as evidence is explicitly prohibited per `feedback_prepr_gate_full_output.md`.
- Cross-host byte-identity for any new goldens (none introduced in this milestone, but if Phase 6 grows them) follows the four-layer normalization pattern from `feedback_cross_host_goldens.md`: serialNumber UUID + metadata.timestamp + workspace path + per-component hashes — and HOME / M2_REPO / MAVEN_HOME / GOPATH / GOMODCACHE / CARGO_HOME isolation.
- All `v3_*.rs` files use `#[cfg_attr(test, allow(clippy::unwrap_used))]` on any `mod tests` block per the project convention (constitution Principle IV + `mikebom-cli` crate-root deny).
