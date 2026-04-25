# Implementation Plan: Cross-format SBOM-Quality Fixes

**Branch**: `012-sbom-quality-fixes` | **Date**: 2026-04-25 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/012-sbom-quality-fixes/spec.md`

## Summary

Three independent emitter-side fixes:

1. **US1 (P1) — SPDX 3 CPE coverage**: One-line fix in `mikebom-cli/src/generate/spdx/v3_external_ids.rs::is_fully_resolved_cpe23`. The current implementation checks `parts[2..7]` for non-wildcard, which includes the `update` slot. Synthesized CPEs almost always have `update=*`, so the check rejects them. The function's own doc comment claims it checks only `part/vendor/product/version` — implementation should match the doc. Fix: change to `parts[2..6]`. Adds a unit test for the synthesized `cpe:2.3:a:mikebom:foo:1.0:*:*:*:*:*:*:*` shape.

2. **US2 (P2) — CDX↔SPDX 2.3 component-count parity (research-only resolution)**: Phase-0 investigation determined this is **not a code bug** — it's a comparison-script framing issue. CDX nests components via `component.components[]` (Maven shade-plugin pattern); SPDX 2.3 flattens everything to top-level `packages[]` and expresses parent-child via `CONTAINS` Relationships. The user's comparison report counted CDX *top-level* (729) vs. SPDX 2.3 *flattened* (751) — apples to oranges. The 22-component drift is exactly the count of nested children, which is the structural design difference. Resolution: add a bidirectional CI parity test that asserts `cdx.flattened_count == spdx23.packages.length - synthetic_root_count` (the existing `spdx_cdx_parity.rs` walks flattened CDX one-way; this PR adds the SPDX→CDX reverse walk to lock the invariant), and document the structural difference in the format-mapping doc.

3. **US3 (P3) — SPDX 2.3 LicenseRef backport**: New emitter logic in `spdx/packages.rs` + `spdx/document.rs`. When a component's `licenses[]` array contains any term that fails `spdx::Expression::try_canonical`, the entire expression flows through a `LicenseRef-<base32(SHA256(joined-with-AND))[..16]>` path. Document gains a `hasExtractedLicensingInfos[]` array carrying one entry per distinct LicenseRef referenced by any Package's `licenseDeclared`/`licenseConcluded`. Per clarification Q1: all-or-nothing — any non-canonicalizable term in a multi-term expression triggers the LicenseRef path for the whole expression.

All three fixes are bug-fixes-only. No new dependencies, no new format identifiers, no scan-pipeline changes.

## Technical Context

**Language/Version**: Rust stable (workspace toolchain inherited from milestones 001–011; no nightly required).
**Primary Dependencies**: existing only — `spdx` (license-expression canonicalization), `data-encoding` (BASE32 for LicenseRef hash prefix), `sha2`, `serde`/`serde_json`, `tracing`, `anyhow`. Dev-dep: existing `jsonschema = "0.46"`. **No new crates.**
**Storage**: N/A — in-process per scan.
**Testing**: `cargo +stable test --workspace`, `cargo +stable clippy --workspace --all-targets`. Existing milestone-010/011 fixture matrix covers all three fix surfaces.
**Target Platform**: Linux x86_64 (CI: ubuntu-latest); macOS dev.
**Project Type**: cli (Rust workspace; three-crate split unchanged).
**Performance Goals**: No change. Fixes are O(emit-cost-per-component) additions; total emission time is dominated by JSON serialization, not the new license-expression hash or the CPE check.
**Constraints**: byte-determinism preserved (FR-011); opt-off invariant preserved (FR-013); existing format-mapping doc rows preserved (FR-012); `MikebomAnnotationCommentV1` envelope shape preserved (no consumer-parser changes).
**Scale/Scope**: 9 ecosystem fixtures + the synthetic perf fixture (500 deb + 1500 npm). LicenseRef hash space stays well below the 80-bit collision threshold even on the polyglot fixture's ~700 distinct license expressions (collision probability ≈ 10⁻¹⁹).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Justification |
|-----------|--------|---------------|
| I. Pure Rust, Zero C | ✅ | No new dependencies. |
| II. eBPF-Only Observation | ✅ | Output serializer-side fixes only; discovery/resolution layer untouched. |
| III. Fail Closed | ✅ | LicenseRef fallback IS the fail-closed path — non-canonicalizable expressions previously dropped to `NOASSERTION` (silent data loss); after this milestone they land in `hasExtractedLicensingInfos[]` (explicit preserved). |
| IV. Type-Driven Correctness | ✅ | New types: `SpdxLicenseField` gains a `LicenseRef(String)` variant; new struct `SpdxExtractedLicensingInfo`. No `.unwrap()` in production paths; tests use the existing `#[cfg_attr(test, allow(clippy::unwrap_used))]` pattern. |
| V. Specification Compliance | ✅ | SPDX 2.3 §10.1 (`hasExtractedLicensingInfos`) is the spec-native mechanism for non-SPDX-list license identifiers. SPDX 3.0.1 emission is unchanged (already preserved expressions verbatim). CycloneDX 1.6 emission is unchanged. PURL spec preserved. |
| VI. Three-Crate Architecture | ✅ | All work inside `mikebom-cli`; no new crate. |
| VII. Test Isolation | ✅ | All tests user-space JSON synthesis + parsing; no eBPF privilege required. |
| VIII. Completeness | ✅ | Three fixes each *increase* completeness vs. today: more CPEs in SPDX 3, more licenses in SPDX 2.3, explicit component-count parity check. |
| IX. Accuracy | ✅ | No new components. CPE/license data flowing into emitters originates in resolution; emitters preserve more of it. |
| X. Transparency | ✅ | LicenseRef path makes the previously-implicit data loss explicit + recoverable by consumers. The `extractedText` field carries the original verbatim string. |
| XI. Enrichment | ✅ | License + CPE enrichment data already in `ResolvedComponent` reaches the SPDX 2.3 / SPDX 3 outputs more faithfully. |
| XII. External Data Source Enrichment | ✅ | No new external sources. |

**No violations. Complexity Tracking section omitted.**

## Project Structure

### Documentation (this feature)

```text
specs/012-sbom-quality-fixes/
├── plan.md              # This file
├── spec.md              # Feature spec (clarification Q1 integrated)
├── research.md          # Phase 0 — investigation results for the three fix areas
├── data-model.md        # Phase 1 — entity table for LicenseRef + extracted-licensing-infos
├── quickstart.md        # Phase 1 — dev-loop + verification commands
├── checklists/
│   └── requirements.md  # Spec quality checklist (16/16 pass)
└── tasks.md             # Phase 2 output — produced by /speckit.tasks
```

### Source Code (repository root)

```text
mikebom-cli/src/generate/
├── cyclonedx/builder.rs              # untouched
├── openvex/                          # untouched
└── spdx/
    ├── mod.rs                        # untouched (registry already exposes both SPDX 3 identifiers)
    ├── document.rs                   # MODIFIED — `SpdxDocument` gains `has_extracted_licensing_infos: Vec<SpdxExtractedLicensingInfo>` (skip-serializing-if empty); document-level collection wiring
    ├── ids.rs                        # MODIFIED — adds `for_license_ref()` constructor + reusable `hash_prefix` helper for license-ref derivation
    ├── packages.rs                   # MODIFIED — `SpdxLicenseField` gains `LicenseRef(String)` variant; `reduce_license_vec` rewritten per FR-007–FR-010 all-or-nothing rule; returns `(SpdxLicenseField, Option<SpdxExtractedLicensingInfo>)` so document.rs can collect the extracted-info entries
    ├── annotations.rs                # untouched
    ├── relationships.rs              # untouched
    ├── v3_document.rs                # untouched
    ├── v3_packages.rs                # untouched
    ├── v3_relationships.rs           # untouched
    ├── v3_licenses.rs                # untouched
    ├── v3_agents.rs                  # untouched
    ├── v3_external_ids.rs            # MODIFIED — one-line fix: `is_fully_resolved_cpe23` checks `parts[2..6]` (drop `update` slot); doc comment + unit tests refreshed
    └── v3_annotations.rs             # untouched

mikebom-cli/tests/
├── spdx_cdx_parity.rs                # MODIFIED — adds bidirectional component-set parity assertion (US2). Reverse walk: every SPDX 2.3 Package PURL (excluding synthetic root) must match a flattened CycloneDX component PURL
├── spdx3_cdx_parity.rs               # MODIFIED — same bidirectional + an explicit CPE-set count assertion: `count(spdx3.cpe23) ≈ count(cdx.cpe) + synthetic_root_cpe_count` (US1 closure)
├── (3 new tests below)
└── … all other tests untouched

mikebom-cli/tests/cpe_v3_acceptance.rs            # NEW — US1: per-ecosystem assertion that SPDX 3 CPE count matches CDX CPE count ± synthetic-root delta; named test per ecosystem so a failure points at the offending one
mikebom-cli/tests/component_count_parity.rs       # NEW — US2: per-ecosystem bidirectional component-count parity (CDX flattened == SPDX 2.3 packages - synthetic root; SPDX 3 software_Package count == SPDX 2.3 packages count)
mikebom-cli/tests/spdx_license_ref_extracted.rs   # NEW — US3: per-ecosystem assertion that SPDX 2.3 license-coverage count matches CDX, plus shape-correctness checks (LicenseRef-<hash> in licenseDeclared, matching entry in hasExtractedLicensingInfos[], extractedText is the joined raw)

docs/reference/
└── sbom-format-mapping.md            # MODIFIED — Section A row A7 (declared license) and A8 (concluded license) get an explicit mention of the LicenseRef-<hash> + hasExtractedLicensingInfos shape for non-canonicalizable expressions; new Section H row documenting the CDX-nesting vs. SPDX-flattening structural difference (US2 research record)
```

**Structure Decision**: Three new test files (one per user story) for clean per-story attribution; modifications to existing files are surgical and confined to the listed lines. No new modules; no architectural changes. Mirrors the milestone-011 pattern of "scope-minimal source changes + per-story acceptance test files."

## Phase 0: Outline & Research

The Phase-0 investigation results are recorded in [research.md](research.md), covering:

- **R1 — SPDX 3 CPE bug confirmation**: Inspected `is_fully_resolved_cpe23` at `v3_external_ids.rs:75-85`. Confirmed: function checks `parts[2..7]` (5 slots: part/vendor/product/version/**update**); the doc comment one line above CLAIMS to only check 4 slots (part/vendor/product/version). Synthesized CPEs from mikebom's resolution layer set `update=*`. The fix is a one-character edit (`parts[2..7]` → `parts[2..6]`).
- **R2 — 22-component drift root cause**: NOT a code bug. CDX nests components via `component.components[]` (Maven shade-plugin pattern; the CDX builder filters `parent_purl.is_none()` for top-level emission); SPDX 2.3 flattens everything to top-level `packages[]` and expresses parent-child via `CONTAINS` Relationships (this is the SPDX 2.3 standard pattern). The user's comparison report compared CDX top-level count to SPDX 2.3 flattened count — apples to oranges. The 22-component drift on polyglot is exactly the count of nested children. Resolution: tighten the existing parity test to assert `cdx.flattened_count == spdx23.packages.length - synthetic_root_count` and document the structural difference. **No code change to the emitters needed for US2.**
- **R3 — LicenseRef hash + entry shape**: 16-char BASE32-NOPAD prefix of SHA-256(joined-AND-expression-string) — same parameters as `SpdxId::for_purl`. Hash collision resistance is 80 bits; far above the ~700-distinct-expression scale of the polyglot fixture. The `name` field gets a fixed string (`"mikebom-extracted-license"`) per LicenseRef entry — SPDX schema requires it non-empty and the value is not consumer-significant.
- **R4 — SPDX 3 LicenseRef parity**: SPDX 3 already preserves non-canonicalizable expressions verbatim via `simplelicensing_LicenseExpression`'s text-passthrough mode (milestone 011 implementation in `v3_licenses.rs::canonicalize_or_raw`). After US3 lands SPDX 2.3 fix, both formats preserve the same data through different mechanisms. Spec FR-007 only requires SPDX 2.3 changes; SPDX 3 stays untouched.

## Phase 1: Design & Contracts

1. **Data model** (`data-model.md`): documents the new `SpdxLicenseField::LicenseRef(String)` variant, the new `SpdxExtractedLicensingInfo` struct (fields: `licenseId`, `extractedText`, `name`), and the LicenseRef ID-derivation rule. Clarifies the all-or-nothing rule's interaction with `SpdxLicenseField::Expression` / `NoAssertion`.

2. **Contracts**: no public-API changes. The CLI surface (`--format` flag, output filenames, exit codes) is unchanged. The format-mapping doc gains the explicit LicenseRef row text + a structural-nesting note. No `contracts/` artifact for this milestone — these fixes don't introduce new public guarantees, they tighten existing ones.

3. **Quickstart** (`quickstart.md`): dev-loop for verifying the three fixes locally — release-build, scan against the npm fixture and one container-image fixture, inspect with `jq` for the new shapes (CPE entries in SPDX 3 ExternalIdentifier list, LicenseRef-prefixed `licenseDeclared` for non-canonical expressions, document-level `hasExtractedLicensingInfos[]` array).

4. **Agent context update**: run `.specify/scripts/bash/update-agent-context.sh claude` after research.md/data-model.md land.

**Output**: `research.md`, `data-model.md`, `quickstart.md`, refreshed `CLAUDE.md`.

## Re-evaluated Constitution Check (post-design)

All twelve principles still pass after the Phase 1 design. The Phase-0 R2 finding (US2 is not a code bug) reduces the milestone's surface area — the original spec assumed a dedupe-path bug and the fix would be code; the research showed it's a tooling/documentation issue and the fix is a tighter parity test + a structural-difference note. This is a clean tightening; the spec's FR-004/FR-005/FR-006 are still satisfied (just via test+docs rather than code change).

## Complexity Tracking

> No constitutional violations. Section intentionally empty.
