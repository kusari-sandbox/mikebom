# Implementation Plan: Holistic Cross-Format Output Parity

**Branch**: `013-format-parity-enforcement` | **Date**: 2026-04-25 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/013-format-parity-enforcement/spec.md`

## Summary

Three test/diagnostic increments that turn the existing per-slice parity story into a single canonical, testable, hard-to-regress guarantee:

1. **US1 (P1, MVP) — Holistic parity test**: new `mikebom-cli/tests/holistic_parity.rs`. Parses `docs/reference/sbom-format-mapping.md` as the canonical datum catalog (per clarification Q1: any row with `omitted — <reason>` or `defer — <reason>` in a format column is "format-restricted"; every other row is "universal parity"). For each of the 9 ecosystem fixtures + one synthetic container-image fixture, emits all three formats in one invocation, then asserts every universal-parity row's datum is present in all three format outputs via a Rust-side extractor table keyed by catalog row id. Per-ecosystem `#[test]` functions so failures name the offender.

2. **US2 (P2) — Auto-discovery + reverse catalog check**: new `mikebom-cli/tests/mapping_doc_bidirectional.rs`. Implements clarification Q2's both-direction rule: (a) forward — extract every distinct `components[].properties[].name` + `metadata.properties[].name` + top-level-document-key from each fixture's emitted CycloneDX output, assert each has a matching catalog row's CDX column; (b) reverse — for every catalog row classified "universal parity," extract the referenced CycloneDX property/field name via regex over the CDX column's location text, assert the name appears in at least one ecosystem fixture's emitted CDX output. Orphan catalog rows (listed but never emitted) fail loudly.

3. **US3 (P3) — User-facing parity diagnostic**: new `mikebom sbom parity-check --scan-dir <dir>` subcommand. Reads the three emitted format files from the specified directory, runs the same catalog-keyed extractor table as US1's test, renders a per-datum × per-format coverage table with visual markers (`✓` present, `·` format-restricted, `⚠️` universal-parity-but-missing). No re-scan required.

All three increments are test/CLI-layer additions. Zero source changes to `generate/`, `resolve/`, `scan_fs/`, `enrich/`, or `trace/`. The existing per-slice parity tests (`spdx_cdx_parity.rs`, `spdx3_cdx_parity.rs`, `spdx_annotation_fidelity.rs`, `spdx3_annotation_fidelity.rs`, `cpe_v3_acceptance.rs`, `component_count_parity.rs`, `spdx_license_ref_extracted.rs`) remain in place as narrow-slice regression guards — the holistic test is a superset that also validates the catalog-level documentation, not a replacement.

## Technical Context

**Language/Version**: Rust stable (workspace toolchain inherited from milestones 001–012; no nightly).
**Primary Dependencies**: existing only — `serde`/`serde_json` (format output parsing), `regex` (catalog-row parsing — already in the dependency closure), `tempfile`, `tracing`, `anyhow`. `clap` for the new `parity-check` subcommand (already used for `scan`). **No new crates.**
**Storage**: N/A — all state in-process per test invocation / per CLI invocation.
**Testing**: `cargo +stable test --workspace` + `cargo +stable clippy --workspace --all-targets`.
**Target Platform**: Linux x86_64 (CI) + macOS dev.
**Project Type**: cli (unchanged three-crate split).
**Performance Goals**: SC-003: holistic parity test ≤5s per ecosystem on ubuntu-latest. SC-004: diagnostic ≤1s on a 9-ecosystem-sized SBOM. The parity test's dominant cost is the triple-format scan (~1–2s per fixture — reused from milestone-011 `triple_format_perf.rs` timing); catalog parsing + extractor-table lookup is microseconds-level.
**Constraints**: no byte-level output change (FR-012); opt-off preserved (no scan-pipeline changes); existing per-slice tests remain green throughout the milestone; `MikebomAnnotationCommentV1` envelope shape unchanged.
**Scale/Scope**: catalog has ~45 rows today across Sections A–H; parity test covers all 9 ecosystem fixtures; reverse-check iterates all universal-parity rows. Rust-side extractor table has ~45 entries, one per catalog row, each a 3-tuple of closures `(cdx_extract, spdx23_extract, spdx3_extract)`.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Justification |
|-----------|--------|---------------|
| I. Pure Rust, Zero C | ✅ | No new dependencies. |
| II. eBPF-Only Observation | ✅ | Test + CLI-layer addition only; discovery/resolution layers untouched. |
| III. Fail Closed | ✅ | Parity test fails loudly when catalog/emitter drift; the diagnostic surfaces gaps rather than silently hiding them. |
| IV. Type-Driven Correctness | ✅ | New types: `CatalogRow`, `Classification`, `DatumExtractor<F>` (one trait, one implementation table). No `.unwrap()` in production paths; CLI subcommand returns `anyhow::Result` cleanly. |
| V. Specification Compliance | ✅ | No output-format changes. Parity test asserts conformance; doesn't alter output bytes. |
| VI. Three-Crate Architecture | ✅ | All work inside `mikebom-cli` (tests + `cli/` subcommand). No new crate. |
| VII. Test Isolation | ✅ | All tests user-space; no eBPF privilege required. |
| VIII. Completeness | ✅ | Positive impact: catches "datum added to one format only" regressions before merge. |
| IX. Accuracy | ✅ | No impact on component identity or resolution. |
| X. Transparency | ✅ | Diagnostic IS a new transparency surface — exposes cross-format coverage to end users. |
| XI. Enrichment | ✅ | No impact on enrichment flow. |
| XII. External Data Source Enrichment | ✅ | No impact. |

**No violations. Complexity Tracking section omitted.**

## Project Structure

### Documentation (this feature)

```text
specs/013-format-parity-enforcement/
├── plan.md              # This file
├── spec.md              # Feature spec (Q1 + Q2 integrated)
├── research.md          # Phase 0 — diagnostic CLI surface, container-image fixture choice, extractor-table pattern
├── data-model.md        # Phase 1 — CatalogRow / Classification / DatumExtractor types
├── quickstart.md        # Phase 1 — dev-loop + test-run + diagnostic invocation
├── checklists/
│   └── requirements.md  # Spec quality checklist (16/16 pass)
└── tasks.md             # Phase 2 output — produced by /speckit.tasks
```

### Source Code (repository root)

```text
mikebom-cli/
├── Cargo.toml                            # MODIFIED — add explicit `[lib] path = "src/lib.rs"` entry alongside the existing `[[bin]]`
└── src/
    ├── lib.rs                            # NEW — minimal library-crate root: `pub mod parity;`. Enables both the binary
    │                                     #         (cli/parity_cmd.rs) AND integration tests (`tests/`) to import the
    │                                     #         catalog parser + extractor table via `use mikebom::parity::*;`.
    ├── main.rs                           # untouched (binary crate root; main()'s `mod cli;` etc. unchanged)
    ├── parity/                           # NEW MODULE — promoted from `tests/common/` so both binary AND tests can use it
    │   ├── mod.rs                        # NEW — `pub mod catalog; pub mod extractors;` re-exports
    │   ├── catalog.rs                    # NEW — CatalogRow / FormatCoverage / Classification / parse_mapping_doc
    │   └── extractors.rs                 # NEW — ParityExtractor / Directionality / EXTRACTORS table
    ├── cli/
    │   ├── mod.rs                        # MODIFIED — register the new `parity-check` subcommand
    │   ├── scan_cmd.rs                   # untouched
    │   └── parity_cmd.rs                 # NEW — `mikebom sbom parity-check` implementation; consumes `crate::parity` (binary view of the lib's pub mod)
    ├── generate/                         # untouched
    ├── resolve/                          # untouched
    ├── scan_fs/                          # untouched
    ├── enrich/                           # untouched
    └── trace/                            # untouched

mikebom-cli/tests/
├── holistic_parity.rs                    # NEW — US1 parity test; uses `mikebom::parity::*;`
├── mapping_doc_bidirectional.rs          # NEW — US2 auto-discovery + reverse check; uses `mikebom::parity::*;`
├── parity_cmd.rs                         # NEW — US3 end-to-end test for the new CLI subcommand
├── spdx_cdx_parity.rs                    # untouched
├── spdx3_cdx_parity.rs                   # untouched
├── spdx_annotation_fidelity.rs           # untouched
├── spdx3_annotation_fidelity.rs          # untouched
├── cpe_v3_acceptance.rs                  # untouched
├── component_count_parity.rs             # untouched
├── spdx_license_ref_extracted.rs         # untouched
└── … (everything else unchanged)

# Existing doc (untouched by this milestone):
docs/reference/sbom-format-mapping.md     # untouched — this IS the canonical catalog; milestone-013 code reads it, doesn't mutate it
```

**Structure Decision**: Catalog parser + extractor table land at `mikebom-cli/src/parity/` (production code path), accessible to BOTH the binary (`src/cli/parity_cmd.rs` for US3's diagnostic) AND the integration tests (`tests/holistic_parity.rs` etc. for US1+US2). To make this work, mikebom-cli is promoted from binary-only to **lib + bin** crate via a minimal `src/lib.rs` exposing `pub mod parity;`. The library and binary coexist in the same package per the standard Cargo convention (Cargo auto-detects both when src/main.rs and src/lib.rs are present; no Cargo.toml change strictly required, though we add an explicit `[lib]` entry for clarity).

The earlier candidate of placing these under `tests/common/` was rejected: Rust integration tests under `tests/` cannot import test-only modules from `src/`, AND the binary cannot import test-only modules at all. The lib + bin layout is the standard solution for shared module visibility.

Three new test files (one per user story) + one new CLI module (`parity_cmd.rs`) + the new shared `parity/` module under `src/`. Zero changes to `generate/`, `resolve/`, etc. — the only `src/` additions are `lib.rs`, `parity/`, and `cli/parity_cmd.rs`.

## Phase 0: Outline & Research

Recorded in [research.md](research.md):

- **R1 — Diagnostic CLI surface**: `mikebom sbom parity-check --scan-dir <dir>` (subcommand, not a flag on `scan`). Subcommand keeps `sbom scan`'s output clean and gives the diagnostic its own help text, flags, and exit codes. Alternative `sbom scan --parity-report` rejected — conflates "run a scan" with "inspect already-emitted outputs."
- **R2 — Container-image fixture choice**: reuse the synthetic docker-save tarball built by `dual_format_perf.rs::build_benchmark_fixture` (500 deb + 1500 npm packages). No new fixture code; expose the helper as `pub(crate)` so the holistic-parity test can call it. The synthetic image gives scale-realism (~2000 components) without checking a 60-MB image into git.
- **R3 — How to extract CycloneDX property/field names from mapping-doc rows**: regex over the CDX column's text. Three patterns cover every existing row shape — `name="([^"]+)"` for property rows (`/components/{i}/properties[name="mikebom:source-type"]`), trailing-path-segment for direct paths (`/components/{i}/purl` → `purl`), and whole-string for relationship rows (`/dependencies[]/dependsOn[]` treated as a pseudo-identifier). Format-restricted rows whose CDX column contains `omitted —` / `defer —` are skipped in the reverse direction (the omission is explicit and accepted).
- **R4 — Extractor-table pattern**: one Rust-side table in `tests/common/parity_extractors.rs` keyed by catalog row id (`"A1"`, `"A2"`, …, `"H1"`). Each value is a struct holding three extractor closures — `Fn(&Value) -> Vec<String>` for (cdx, spdx23, spdx3). The closures return the normalized set of "observable values" for that datum in the format's output (e.g., for A1 PURL: CDX extractor returns `cdx.components[].purl`; SPDX 2.3 extractor returns `spdx23.packages[].externalRefs[].referenceLocator where referenceType=purl`; SPDX 3 extractor returns `spdx3.@graph[software_Package].externalIdentifier[].identifier where externalIdentifierType=packageUrl`). The holistic parity test iterates every universal-parity catalog row, invokes all three extractors on the emitted outputs, and asserts the three sets have the same contents (up to the directional-containment relaxation from FR-004 / milestone-012 CPE-style case).
- **R5 — Handling the directional-containment case in the extractor**: rows where CDX natively single-valued + SPDX 3 natively multi-valued (like A12 CPE) use an explicit directionality marker in the extractor — `cdx_extract` returns the single primary value; assertion is `spdx3.contains(cdx.first())`, not `spdx3 == cdx`. The table entry carries a `directional_only: bool` flag. Only 2-3 rows today need this flag (A12 CPE, possibly A9/A10/A11 external references); most rows are symmetric-equal.
- **R6 — What about `omitted —` rows where a datum exists in SPDX 3 only (e.g., SPDX-3-profile-native signals)?** When a row has `omitted —` in the CDX column AND concrete text in SPDX 3, the reverse auto-discovery (catalog → emitter) for CDX is skipped for that row (nothing to check — omission is explicit). The forward auto-discovery (emitter → catalog) only runs on CDX-emitted properties, so SPDX-3-only rows don't trigger either direction. Symmetric handling.

## Phase 1: Design & Contracts

1. **Data model** (`data-model.md`): documents the `CatalogRow`, `Classification`, `DatumExtractor`, and `ExtractorTable` types. Clarifies the directional-containment flag's semantics and which catalog rows use it today.

2. **Contracts** (no `contracts/` artifact for this milestone — all additions are test/CLI; no public-API changes). The `parity-check` subcommand's CLI contract (flags, exit codes, output format) is documented inline in `quickstart.md` and in `parity_cmd.rs`'s rustdoc.

3. **Quickstart** (`quickstart.md`): dev-loop + test-run commands + example `parity-check` invocation + sample output.

4. **Agent context update**: `.specify/scripts/bash/update-agent-context.sh claude` after research.md/data-model.md land.

**Output**: `research.md`, `data-model.md`, `quickstart.md`, refreshed `CLAUDE.md`.

## Re-evaluated Constitution Check (post-design)

All twelve principles still pass. The Phase-0 R4 extractor-table design is the core technical decision; it keeps the catalog doc human-readable (plain markdown) while giving the test executable semantics. The extractor table is the one place where "how to check this datum" lives in Rust code; adding a new catalog row means adding one table entry + one markdown row. Missing an extractor for a universal-parity row fails the test loudly (test-setup error, not a silent skip).

The `parity-check` subcommand (US3) is the only production-code addition in the milestone, and it's a pure-read diagnostic — no output emission, no scan. Its CLI contract is narrow enough that no formal `contracts/` artifact is warranted; inline rustdoc + the test in `tests/parity_cmd.rs` are sufficient.

## Complexity Tracking

> No constitutional violations. Section intentionally empty.
