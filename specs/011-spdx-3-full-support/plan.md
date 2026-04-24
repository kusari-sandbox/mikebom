# Implementation Plan: Full SPDX 3.x Output Support

**Branch**: `011-spdx-3-full-support` | **Date**: 2026-04-24 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/011-spdx-3-full-support/spec.md`

## Summary

Replace the milestone-010 SPDX 3.0.1 npm-only experimental stub (`spdx-3-json-experimental`, `mikebom-cli/src/generate/spdx/v3_stub.rs`) with a production-grade SPDX 3.0.1 JSON-LD emitter (`spdx-3-json`) that achieves byte-deterministic, schema-valid output across all nine ecosystems mikebom supports today (apk, cargo, deb, gem, go, maven, npm, pip, rpm). The emitter consumes the same `ScanArtifacts` neutral input the SPDX 2.3 emitter consumes — no scan-pipeline changes — and produces a `software_Package` per CycloneDX component, a `Relationship` per dependency / containment edge, an `ExternalIdentifier` per PURL/CPE, a `simplelicensing_LicenseExpression` plus `hasDeclaredLicense` / `hasConcludedLicense` `Relationship` for licensing, an `Agent`/`Organization`/`Person` per supplier/originator, and an `Annotation` per `mikebom:*` field that has no exact-semantics native SPDX 3 home. Every `mikebom:*` signal carried in SPDX 2.3 reaches SPDX 3 (Q2 = strict-match native, Annotation otherwise). OpenVEX sidecar emission stays exactly as the SPDX 2.3 path emits it; the SPDX 3 document cross-references the sidecar via an `ExternalRef` (Q1) on the document element. The `spdx-3-json-experimental` identifier becomes a deprecation-track alias that emits the same bytes as `spdx-3-json` and prints a stderr deprecation notice. Every milestone-010 parity test (CDX↔SPDX 2.3 native fields, annotation fidelity, schema validation, sbomqs scoring, determinism, dual-format perf) gains an SPDX 3 sibling; a triple-format perf test gates SC-007.

## Technical Context

**Language/Version**: Rust stable (workspace toolchain inherited from milestones 001–010; no nightly required for user-space work)
**Primary Dependencies**: existing only — `serde`/`serde_json` (JSON-LD encoding), `data-encoding` (BASE32 for deterministic SPDXIDs / IRIs), `sha2` (content-addressed IRIs, scan fingerprint), `chrono` (RFC 3339 timestamps), `spdx` (license-expression canonicalization, already used by SPDX 2.3 path), `tracing`, `anyhow`. Dev-dep: existing `jsonschema = "0.46"` (already validates SPDX 2.3) extended to SPDX 3.0.1. No new crates.
**Storage**: N/A — all state in-process per scan (mirrors milestones 002–010).
**Testing**: `cargo +stable test --workspace`, `cargo +stable clippy --workspace --all-targets`, plus the milestone-010-style integration suites under `mikebom-cli/tests/` (extended for SPDX 3); CI sbomqs binary in `$PATH` for SC-001 enforcement.
**Target Platform**: Linux x86_64 (CI: ubuntu-latest); macOS dev (no platform-specific behavior — pure JSON-LD synthesis from neutral inputs).
**Project Type**: cli (Rust workspace; the existing three-crate split — `mikebom-ebpf`, `mikebom-common`, `mikebom-cli` — is unchanged).
**Performance Goals**: SC-007 — single-invocation triple-format scan (CycloneDX + SPDX 2.3 + SPDX 3) ≥30% faster wall-clock than three sequential single-format invocations (spec target); CI gate ≥25% reduction (clarification Q3, mirroring `SC009_CI_MIN_REDUCTION` from milestone 010).
**Constraints**: every emitted document validates against the published SPDX 3.0.1 JSON-LD schema with zero warnings and zero errors (FR-016, SC-002); byte-deterministic after timestamp + document-IRI normalization (FR-015, SC-006); no scan-pipeline / discovery / deep-hash code touched (Assumption "no scan pipeline changes"); strict-match-only native-field placement, Annotation otherwise (FR-011, clarification Q2); OpenVEX cross-ref is `ExternalRef` on the document element (FR-014, clarification Q1).
**Scale/Scope**: 9 ecosystem fixtures × tens-to-hundreds of components per fixture for the parity test matrix; the dual-format perf fixture (`build_benchmark_fixture` in `tests/dual_format_perf.rs`: 500 deb stanzas + 1500 npm packages) is reused for the triple-format perf gate.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Justification |
|-----------|--------|---------------|
| I. Pure Rust, Zero C | ✅ | No new dependencies; no C toolchain changes. |
| II. eBPF-Only Observation | ✅ | Output serializer only; no discovery work. The SPDX 3 emitter consumes pre-resolved `ScanArtifacts` produced by the existing trace + enrichment pipeline. |
| III. Fail Closed | ✅ | Schema-validation failures fail the build (CI gate). Emitter errors return `anyhow::Result::Err` and propagate; no silent fallback to a partial document. |
| IV. Type-Driven Correctness | ✅ | Reuses `SpdxId` newtype from `spdx/ids.rs` for IRI synthesis. New types added in `spdx/v3_*` for SPDX-3-specific shapes (e.g., `SpdxV3Element` enum, `SpdxV3Relationship`, `SpdxV3ExternalIdentifier`). No `.unwrap()` in production paths; tests use the existing `#[cfg_attr(test, allow(clippy::unwrap_used))]` pattern. |
| V. Specification Compliance | ✅ | Schema-validates against SPDX 3.0.1; CISA 2025 minimum elements covered (Tool, generation context, supplier, version, license, hash, dependency); PURL spec preserved (PURLs round-trip from `Purl(String)` through `software_packageUrl` and `ExternalIdentifier[purl]`). Constitution V's experimental-labeling clause is retired for both `spdx-3-json` (no longer experimental — full ecosystem coverage, schema-valid) and `spdx-3-json-experimental` (no longer experimental — alias routes through the stable emitter and emits byte-identical output; see clarification Q4 in spec.md). The alias signals its lifecycle via stderr deprecation notice + CLI help-text "(deprecated)" annotation, not via constitution V's experimental-labeling mechanism — the clause governs emitters whose output is preview-quality, which the alias is not after this milestone. |
| VI. Three-Crate Architecture | ✅ | All work inside `mikebom-cli`; no new crate. |
| VII. Test Isolation | ✅ | All milestone-011 tests are user-space JSON synthesis + parsing; no eBPF privilege required. |
| VIII. Completeness | ✅ | SC-003 enforces SPDX 3 component-set parity with CycloneDX. No silent component drops. |
| IX. Accuracy | ✅ | No new components introduced — SPDX 3 emits the same set CDX/SPDX 2.3 emit for the same scan. |
| X. Transparency | ✅ | `mikebom:trace-integrity-*` document-level signals reach SPDX 3 via Annotation (Section C row C23). Confidence/evidence preserved per FR-011. |
| XI. Enrichment | ✅ | License + supplier + hash data already in `ResolvedComponent` flow through to SPDX 3 native fields. No new enrichment pulls. |
| XII. External Data Source Enrichment | ✅ | No new external sources. Annotation-envelope provenance markers remain in place for fields originating from lockfiles vs. trace. |

**No violations. Complexity Tracking section omitted.**

## Project Structure

### Documentation (this feature)

```text
specs/011-spdx-3-full-support/
├── plan.md              # This file
├── spec.md              # Feature spec (already populated)
├── research.md          # Phase 0 output — resolves the two deferred clarify items + sketches SPDX-3 → SPDX-2.3 element mapping
├── data-model.md        # Phase 1 output — entities & their JSON-LD shapes
├── quickstart.md        # Phase 1 output — devloop + verification commands
├── contracts/
│   └── spdx-3-emitter.contract.md   # Public contract: input shape, output guarantees, schema validation
├── checklists/
│   └── requirements.md  # Spec quality checklist (already populated)
└── tasks.md             # Phase 2 output — produced by /speckit.tasks (NOT this command)
```

### Source Code (repository root)

```text
mikebom-cli/src/generate/
├── mod.rs                       # SbomSerializer trait + SerializerRegistry — register the renamed Spdx3JsonSerializer + alias for spdx-3-json-experimental
├── cyclonedx/
│   └── mod.rs                   # untouched
├── openvex/                     # untouched (sidecar shape is reused by SPDX 3)
│   ├── mod.rs
│   └── statements.rs
└── spdx/
    ├── mod.rs                   # SPDX 2.3 emitter unchanged; v3_stub.rs deleted; new v3 module surface registered
    ├── annotations.rs           # SPDX 2.3 only; reused indirectly via Q2-strict-match table
    ├── document.rs              # SPDX 2.3 only
    ├── ids.rs                   # shared — extended with `SpdxId::v3_iri()` if needed for IRI synthesis
    ├── packages.rs              # SPDX 2.3 only
    ├── relationships.rs         # SPDX 2.3 only
    ├── v3_document.rs           # NEW — top-level @graph builder, ExternalRef→OpenVEX wiring
    ├── v3_packages.rs           # NEW — software_Package elements (name, version, purl, hashes, homepage, vcs, downloadLocation)
    ├── v3_relationships.rs      # NEW — dependsOn, devDependencyOf, buildDependencyOf, contains, hasDeclaredLicense, hasConcludedLicense
    ├── v3_licenses.rs           # NEW — simplelicensing_LicenseExpression element synthesis
    ├── v3_agents.rs             # NEW — Agent / Organization / Person element synthesis
    ├── v3_external_ids.rs       # NEW — ExternalIdentifier[purl,cpe23Type] element synthesis
    └── v3_annotations.rs        # NEW — SPDX 3 Annotation element wrapper around the existing MikebomAnnotationCommentV1 envelope

mikebom-cli/tests/
├── spdx3_schema_validation.rs   # ENLARGED — was stub-only; now covers all 9 ecosystems against the bundled SPDX 3.0.1 JSON-LD schema
├── spdx3_cdx_parity.rs          # NEW — SPDX 3 mirror of spdx_cdx_parity.rs (PURL/version/checksum parity per ecosystem)
├── spdx3_annotation_fidelity.rs # NEW — every mikebom:* field reachable in SPDX 2.3 reachable in SPDX 3
├── spdx3_determinism.rs         # NEW — byte-equality across two runs, after IRI + timestamp normalization
├── spdx3_us3_acceptance.rs      # MODIFIED — alias deprecation notice + stable identifier surface
├── spdx3_cli_labeling.rs        # MODIFIED — stable identifier no longer experimental
├── spdx3_stub.rs                # DELETED — npm-only stub coverage retired
├── sbom_format_mapping_coverage.rs  # MODIFIED — already enforces three columns; updated to flag any "defer" entry as a populated row only when paired with a follow-up milestone reference
├── sbomqs_parity.rs             # MODIFIED — extends NATIVE_FEATURES check to also score the SPDX 3 output
├── triple_format_perf.rs        # NEW — SC-007 CI gate, ≥25% reduction with documented noise budget
├── format_dispatch.rs           # MODIFIED — register stable + alias identifiers
└── tests/fixtures/spdx3-3.0.1.schema.json  # NEW — bundled JSON-LD schema for offline validation

docs/reference/
└── sbom-format-mapping.md       # MODIFIED — every "defer until SPDX 3 …" cell replaced with the concrete SPDX 3 native binding (Section A: A4, A5, A7, A8, A12) or the explicit Annotation shape (Section C/D rows already populated, double-checked for SPDX 3 alignment)
```

**Structure Decision**: Mirror milestone 010's flat-sibling pattern under `mikebom-cli/src/generate/spdx/`. Rationale: SPDX 2.3 used a flat `document.rs` / `packages.rs` / `relationships.rs` / `annotations.rs` / `ids.rs` layout rather than a `v2_3/` subdirectory. SPDX 3 follows the same convention with a `v3_*` prefix on each sibling. Reasoning behind not introducing a `v3/` subdirectory: would require a public `pub mod v3` rename and a re-export layer for the shared `ids.rs` types — pure plumbing churn for no architectural payoff. The shared `ids.rs` and the milestone-010 `MikebomAnnotationCommentV1` envelope are reused verbatim across both versions; only the per-version JSON-LD shape lives in a per-version file.

The `v3_stub.rs` file is **deleted** rather than retained. The milestone-010 stub's npm-only coverage was an explicit experimental scope contract; replacing it with the full emitter is the entire point of this milestone, and keeping the stub around would violate FR-002's "alias emits the same bytes as `spdx-3-json`" guarantee. The `Spdx3JsonExperimentalSerializer` struct remains as an alias type (same `serialize` body as the stable serializer) so existing format-dispatch tests keep finding it.

## Phase 0: Outline & Research

The two clarify-deferred items are resolved in `research.md`, plus the SPDX-3-element-shape lookup work that drives the Phase 1 data model.

**R1 — SPDX 3.0.1 schema source: bundle vs. fetch.** Decision: bundle the schema as a static file under `mikebom-cli/tests/fixtures/spdx3-3.0.1.schema.json`. Rationale: milestone-010 SPDX 2.3 schema validation already bundles its schema; offline CI runs (and any future air-gapped CI mirror) cannot rely on schema-fetch URLs being live; bundling produces a reproducible test artifact tied to a known schema revision. Alternatives considered: fetch via `reqwest` at test time (rejected — flaky CI, runtime dependency on schema-host availability), fetch via `build.rs` (rejected — adds a build-time network dependency, breaks `cargo build --offline`).

**R2 — `spdx-3-json-experimental` deprecation window.** Decision: alias persists through the next milestone (012) and is removed in milestone 013 unless usage signals (issue tracker, CI logs of downstream pipelines we have visibility into) suggest the alias is still in use. The deprecation notice format is `warning: --format spdx-3-json-experimental is deprecated; use --format spdx-3-json (same bytes, no -experimental in filename, no experimental marker in document)`. Rationale: existing user pipelines that name the experimental identifier need a friction-low migration path; one-milestone overlap is the standard period mikebom's prior format renames have used. Alternatives considered: remove immediately (rejected — breaks user scripts the moment they pull the new release), keep indefinitely (rejected — accumulates legacy aliases).

**R3 — SPDX 3.0.1 element shape lookup for the Section A defer rows.** Decision: enumerated per row in `research.md` Section R3 with citations to the SPDX 3.0.1 JSON-LD context file, covering A4 (supplier as Agent + suppliedBy Relationship), A5 (originator as Person + originatedBy Relationship), A7 (declared license via simplelicensing_LicenseExpression element + hasDeclaredLicense Relationship), A8 (concluded license, parallel shape), A12 (CPE via ExternalIdentifier with `externalIdentifierType: cpe23`). Each row's exact JSON-LD shape lands in `data-model.md`.

**R4 — Triple-format dispatcher caching.** Decision: extend the existing single-pass invariant in `cli/scan_cmd.rs`. The scan + discovery + enrichment + deep-hash work already runs once per invocation regardless of how many `--format` outputs are requested; the SPDX 3 serializer plugs into the same `SerializerRegistry::serialize_all` loop the SPDX 2.3 serializer does. No new caching layer is needed. Rationale: amortization is already structural — milestone 010's dual-format perf test confirmed the cost is the per-serializer work, which is small relative to scan work. Adding SPDX 3 as a third serializer adds a third small cost, and the savings vs. three sequential invocations comes from reusing the scan output, not from inter-serializer caching.

**R5 — Q2 borderline rows.** Decision: enumerated in research.md and in the updated mapping doc — `mikebom:source-files` (C18) provisionally lands in `software_Package/contentBy` only when SPDX 3.0.1's build profile defines `contentBy`; for 3.0.1 it stays Annotation. `mikebom:cpe-candidates` (C19) splits: every fully-resolved candidate becomes an `ExternalIdentifier[cpe23]` (native); the remaining unresolved candidate set stays in an Annotation. `mikebom:shade-relocation` (C8) stays Annotation (no SPDX 3 typed property captures "this artifact contains relocated symbols from another artifact"). `mikebom:confidence` (C16) stays Annotation pending SPDX 3 evidence-profile stabilization. Rationale: strict-match per Q2 — anywhere semantics don't align exactly, Annotation wins.

**Output**: `research.md` consolidates R1–R5 with Decision / Rationale / Alternatives entries.

## Phase 1: Design & Contracts

**Prerequisites**: `research.md` complete (this plan + the research file are produced together; the `/speckit.tasks` step downstream consumes both).

1. **Data model** (`data-model.md`): enumerates each SPDX 3.0.1 JSON-LD element type mikebom emits, with: type identifier, required properties, optional properties mikebom populates, IRI-synthesis rule, source field in `ResolvedComponent` / `ScanArtifacts`. Covered: `CreationInfo`, `Tool`, `SpdxDocument`, `software_Package`, `Relationship` (4 typed sub-shapes), `simplelicensing_LicenseExpression`, `Agent`/`Organization`/`Person`, `ExternalIdentifier` (purl, cpe23), `ExternalRef` (security-advisory → OpenVEX sidecar), `Hash`, `Annotation`. Also documents the IRI-synthesis function (deterministic SHA-256 → BASE32 prefix, identical to milestone 010 stub) and the `creationInfo` blank-node convention (the only place the schema permits a `_:` ID).

2. **Contracts** (`contracts/spdx-3-emitter.contract.md`): the public guarantees the SPDX 3 serializer makes to its callers. Includes: input neutrality (`ScanArtifacts` shape unchanged from SPDX 2.3 path), output schema-validity guarantee (FR-016), byte-determinism guarantee (FR-015), Annotation-envelope JSON shape (`schema: "mikebom-annotation/v1"`, `field`, `value` — reused verbatim from milestone 010, no envelope-version bump because the envelope JSON is unchanged), OpenVEX cross-reference shape (FR-014, ExternalRef on document element), default filename (`mikebom.spdx3.json`), alias-identifier deprecation notice format (R2).

3. **Quickstart** (`quickstart.md`): the dev-loop a contributor uses to add or change an SPDX 3 row. Step-by-step: (a) edit the relevant `v3_*.rs` file; (b) update the corresponding row in `docs/reference/sbom-format-mapping.md`; (c) run `cargo +stable test -p mikebom --test spdx3_schema_validation` to confirm the schema gate; (d) run `cargo +stable test -p mikebom --test spdx3_cdx_parity` to confirm component parity; (e) run the full pre-PR gate (`cargo +stable clippy --workspace --all-targets`, `cargo +stable test --workspace`).

4. **Agent context update**: run `.specify/scripts/bash/update-agent-context.sh claude` to refresh `CLAUDE.md` with the milestone-011 active-technology entry.

**Output**: `data-model.md`, `contracts/spdx-3-emitter.contract.md`, `quickstart.md`, refreshed `CLAUDE.md`.

## Re-evaluated Constitution Check (post-design)

All twelve principles still pass. The data-model and contract artifacts make the strict-match-or-Annotation rule (Q2) explicit and reviewable; the schema-bundling decision (R1) keeps the build offline-clean (Principle I corollary — no surprise network dependencies); the deprecation-window decision (R2) keeps the alias on a defined exit ramp (Principle V — no indefinite parallel emitters that could be mistaken for production-grade peers).

**Specific note on Principle V's experimental-labeling clause** (per clarification Q4 in spec.md): the clause requires labeling in `--help` text, output filename, AND document creator/tool metadata for emitters whose output is *experimental quality*. Both `spdx-3-json` (full coverage, schema-valid, sbomqs-parity-passing) and the deprecation alias `spdx-3-json-experimental` (byte-identical output to the stable emitter via delegation) produce *production-quality* output after this milestone — the clause therefore does not apply to either. The alias's lifecycle is signaled by a stderr deprecation notice (FR-002) and a help-text "(deprecated)" annotation; the alias output bytes, default filename, and document comments are byte-identical to the stable emitter. Users who want the milestone-010 npm-only stub bytes must stay on a pre-011 release (already documented in spec Assumptions).

**Verification regression-guard for FR-019 / SC-009** (per analysis G1): existing milestone-010 byte-equality tests (`tests/cdx_regression.rs`, `tests/spdx_us1_acceptance.rs`) gate the opt-off invariant. The pre-PR gate runs them via `cargo +stable test --workspace`. Phase 6 task T036b (added during analysis remediation) makes the regression check an explicit step rather than an implicit byproduct of the broader test sweep.

## Complexity Tracking

> No constitutional violations. Section intentionally empty.
