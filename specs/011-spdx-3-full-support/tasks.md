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

### Tests for User Story 2

- [X] T018 [P] [US2] Authored `mikebom-cli/tests/spdx3_annotation_fidelity.rs`. 9 per-ecosystem fidelity tests comparing the `(subject, field, value)` set reachable in SPDX 2.3 vs. SPDX 3 outputs (both formats carry the same `MikebomAnnotationCommentV1` envelope bytes, so decoding is one serde_json call per place). **All 9 pass.**
- [X] T019 [P] [US2] Added three SPDX-3 VEX tests in `src/generate/spdx/mod.rs::tests` (matching the existing milestone-010 unit-test shape): `spdx3_no_vex_emits_no_external_ref_on_document`, `spdx3_with_vex_emits_sidecar_and_external_ref_on_document`, `spdx3_openvex_override_path_threads_into_external_ref`. Also added `spdx3_alias_bytes_are_byte_identical_to_stable` locking in the research.md §R6 / contract §4 delegation contract. **All 4 new unit tests pass.**

### Implementation for User Story 2

- [X] T020 [P] [US2] Implemented `v3_annotations.rs`. Functions `build_component_annotations` (C1–C20 + D1/D2, per-Package) and `build_document_annotations` (C21–C23 + E1, document-level). Reuses `super::annotations::MikebomAnnotationCommentV1` envelope verbatim — same JSON bytes in SPDX 2.3 `annotations[].comment` and SPDX 3 `Annotation.statement`.
- [X] T021 [US2] Wired component-level annotations into `v3_document::build_document` — they compose into the `@graph` as the last section, sorted by `spdxId` for determinism.
- [X] T022 [US2] Wired document-level annotations via the same function. Four `trace-integrity-*` subkey annotations emit unconditionally; `generation-context` always; others gated on non-empty data (same gates as SPDX 2.3 path).
- [X] T023 [US2] Implemented OpenVEX `ExternalRef` cross-reference on the SpdxDocument element. `build_document` now takes an `openvex_locator: Option<&str>` argument; when non-`None` it inlines the ExternalRef as `{type: "ExternalRef", externalRefType: "vulnerabilityExploitabilityAssessment", contentType: "application/openvex+json", locator: [<path>], comment: "OpenVEX 0.2.0 sidecar produced by mikebom"}`. Used the VEX-precise enum value (not just `securityAdvisory`) as it's the most specific match in SPDX 3.0.1's `prop_ExternalRef_externalRefType` enum.
- [X] T024 [US2] C19 split is in place: `v3_external_ids.rs` emits `ExternalIdentifier[cpe23]` entries for fully-resolved CPEs (is_fully_resolved_cpe23 check); `v3_annotations.rs` emits `mikebom:cpe-candidates` Annotation when more than one candidate exists (same gate as SPDX 2.3 path).
- [X] T025 [US2] Updated `docs/reference/sbom-format-mapping.md` — Section C rows (C1–C23) and Section D/E/F rows rewritten for the SPDX 3 column with concrete shapes (annotation names where applicable, ExternalRef shape for F1/OpenVEX). All `defer`/`pending`/`TODO`/`TBD` text removed from data rows.
- [X] T026 [US2] `Spdx3JsonSerializer::serialize` now co-emits the OpenVEX sidecar artifact in the returned `Vec<EmittedArtifact>` alongside the SPDX 3 document. Mirrors the SPDX 2.3 path — same call to `crate::generate::openvex::serialize_openvex`, same `OutputConfig.overrides["openvex"]` path override plumbing, same sidecar-present-iff-advisories invariant.

**Checkpoint**: T018 + T019 pass. Every mikebom signal reachable in SPDX 2.3 is reachable in SPDX 3 by field name and value. OpenVEX sidecar emits and is cross-referenced.

---

## Phase 5: User Story 3 — Retire experimental label, install deprecation alias (Priority: P3)

**Goal**: `--format spdx-3-json` is no longer flagged experimental in CLI help; produced documents carry no experimental marker. `--format spdx-3-json-experimental` continues to work — emits the same bytes (modulo the experimental marker on `CreationInfo.comment` and `SpdxDocument.comment`) and prints a one-line stderr deprecation notice.

**Independent Test**: `cargo +stable test -p mikebom --test spdx3_cli_labeling` and `--test spdx3_us3_acceptance` pass.

### Tests for User Story 3

- [X] T027 [P] [US3] Rewrote `mikebom-cli/tests/spdx3_cli_labeling.rs` — asserts no `[EXPERIMENTAL]` in `--help` after flip; alias carries `[DEPRECATED]` label in unknown-format error known-id list; bare `spdx-3-json` is a first-class format with no stderr deprecation notice.
- [X] T028 [P] [US3] Added scenarios 6/7/8 to `mikebom-cli/tests/spdx3_us3_acceptance.rs`: (6) alias exits zero + two-line stderr deprecation notice exactly once; (7) alias bytes byte-identical to stable; (8) `MIKEBOM_NO_DEPRECATION_NOTICE=1` suppresses the warning without altering document bytes. Kept scenarios 1–5 for continued regression coverage.

### Implementation for User Story 3

- [X] T029 [US3] Flipped `Spdx3JsonSerializer::experimental()` to `false`. `v3_document::build_document` already doesn't emit experimental-marker `comment` properties (verified).
- [X] T030 [US3] Set `Spdx3JsonExperimentalSerializer::experimental()` to `false` per research.md §R6 / contract §4 — delegation already returns byte-identical bytes. Updated the struct's doc comment to clarify that deprecation lifecycle is signaled outside the trait flag (help-text + stderr notice).
- [X] T031 [US3] Wired the two-line deprecation-notice emission in `scan_cmd.rs::execute` with `MIKEBOM_NO_DEPRECATION_NOTICE` env-var opt-out. Added `[DEPRECATED]` branch in `format_help_list` for the alias (separate from the trait's `experimental()` flag). Updated `--format` clap doc-comment to reflect the US3 surface.
- [X] T032 [US3] Deleted `mikebom-cli/src/generate/spdx/v3_stub.rs` and removed `pub mod v3_stub;` from `spdx/mod.rs`. Updated the `spdx/mod.rs` top-level module docs to describe the three user-facing formats (2.3 stable, 3 stable, 3-experimental deprecation alias).
- [X] T033 [US3] Deleted `mikebom-cli/tests/spdx3_stub.rs` — npm-only stub coverage superseded by full-coverage tests in `spdx3_schema_validation.rs` + `spdx3_cdx_parity.rs`.

**Checkpoint**: All three user stories complete. Stable identifier is `spdx-3-json`; alias is `spdx-3-json-experimental` with deprecation notice; emitter has full-ecosystem coverage and full mikebom-signal fidelity.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: SC-001 (sbomqs cross-format scoring), SC-007 (triple-format perf gate), SC-004/SC-010 (mapping coverage), final cleanup. These tests validate properties that span all three user stories rather than belonging to one.

- [X] T034 [P] Extended `mikebom-cli/tests/sbomqs_parity.rs` — now scores all three outputs (CDX + SPDX 2.3 + SPDX 3) per ecosystem and enforces `spdx_score ≥ cdx_score` on each NATIVE_FEATURES entry for both SPDX versions. Added `SbomqsScoreResult::{Scored, Unsupported}` enum to handle sbomqs v2.0.6's lack of SPDX 3 support — the Unsupported branch prints a visible skip diagnostic per ecosystem; SC-001 enforcement for SPDX 3 activates automatically when upstream sbomqs adds a reader. SPDX 2.3 enforcement is hard-fail throughout.
- [X] T035 [P] Added `mikebom-cli/tests/triple_format_perf.rs`. Mirrors `dual_format_perf.rs` fixture + helpers; triple-invocation times 3 single-format scans + 1 triple-format scan (median of 3 each, post-warmup). `SC007_CI_MIN_REDUCTION = 0.25` matches the milestone-010 noise-budget rationale. **Measured reduction 58.8 %** on the local synthetic fixture — well above both the 25 % CI gate and the 30 % spec target. `MIKEBOM_PERF_IMAGE` env override honored.
- [X] T036 [P] Verified `mikebom-cli/tests/sbom_format_mapping_coverage.rs` — all 3 tests pass after the US1 + US2 mapping-doc updates. No test code change required; the doc updates in T017 + T025 landed cleanly.
- [X] T036b [P] Confirmed milestone-010 regression guards still pass clean post-US1/US2/US3: `cdx_regression` `ok. 9 passed`, `spdx_us1_acceptance` `ok. 9 passed`, `spdx_determinism` `ok. 5 passed`, `spdx_annotation_fidelity` `ok. 5 passed`. FR-019 / SC-009 opt-off invariant preserved throughout milestone 011.
- [X] T037 [P] Extended `mikebom-cli/tests/format_dispatch.rs` with two new tests: (a) both SPDX 3 identifiers dispatch through the registry, both emit `mikebom.spdx3.json` as default filename, only the alias prints a stderr deprecation notice; (b) alias↔stable byte-identity end-to-end (strongest defense against the alias drifting from the stable emitter). **All 9 format_dispatch tests pass.**
- [X] T038 [P] `spdx/mod.rs` module docs were already updated during US3 (T032) — describes the three formats (2.3 stable, 3 stable, 3-deprecated-alias) with per-format purpose notes and a pointer to the mapping doc. No additional change needed in Phase 6.
- [X] T039 Ran quickstart smoke-test. Released binary, scanned `tests/fixtures/npm/node-modules-walk` with `--format cyclonedx-json,spdx-2.3-json,spdx-3-json --no-deep-hash`; all three artifacts written; SPDX 3 `@graph` contains `{CreationInfo:1, Tool:1, SpdxDocument:1, software_Package:3, simplelicensing_LicenseExpression:1, Relationship:3, Annotation:13}`. Shape matches the US2 `data-model.md` element catalog.
- [X] T040 Pre-PR gate clean: `cargo +stable clippy --workspace --all-targets` reports **0 errors**; `cargo +stable test --workspace` reports **1312 passed, 0 failed** across the full workspace (38 test binaries).

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
