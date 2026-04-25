---
description: "Task list — Holistic Cross-Format Output Parity (milestone 013)"
---

# Tasks: Holistic Cross-Format Output Parity

**Input**: Design documents from `/specs/013-format-parity-enforcement/`
**Prerequisites**: plan.md (✅), spec.md (✅), research.md (✅), data-model.md (✅), quickstart.md (✅)

**Tests**: Test tasks are included. Milestone 013's entire output IS tests + one diagnostic CLI — the spec's success criteria (SC-001 through SC-008) each name an enforceable CI gate, and the project's pre-PR gate (constitution Pre-PR Verification clause) requires `cargo +stable test --workspace` clean.

**Organization**: Tasks are grouped by user story for independent implementation:
- **US1 (P1, MVP)**: Holistic parity test — one canonical test that enumerates every universal-parity catalog row and asserts all 3 formats carry the datum. Per clarification Q1's implicit-text-match rule.
- **US2 (P2)**: Bidirectional catalog↔emitter auto-discovery. Per clarification Q2 both directions are checked — forward (new CDX property without catalog row fails) + reverse (catalog row without emitter fails).
- **US3 (P3)**: User-facing `mikebom sbom parity-check --scan-dir <dir>` subcommand producing a per-datum × per-format coverage table.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Maps task to spec.md user story (US1, US2, US3); omitted on Setup / Foundational / Polish

## Path Conventions

Single Rust workspace; mikebom is a CLI binary. Source under `mikebom-cli/src/`, tests under `mikebom-cli/tests/`. Test-shared helpers live under `mikebom-cli/tests/common/`. The canonical datum catalog IS `docs/reference/sbom-format-mapping.md` (read-only for this milestone).

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Promote mikebom-cli to a lib + bin crate (so the new `parity/` module is reachable from both the binary AND integration tests), scaffold the new module skeleton, and promote the perf-fixture builder so US1 can reuse it for the container-image fixture case.

- [X] T001 Add `mikebom-cli/src/lib.rs` containing only `pub mod parity;`. Update `mikebom-cli/Cargo.toml` to add an explicit `[lib]\npath = "src/lib.rs"` entry alongside the existing `[[bin]]` block. Run `cargo build -p mikebom` to confirm both targets compile. Create skeleton files `mikebom-cli/src/parity/mod.rs` (declaring `pub mod catalog; pub mod extractors;`), `mikebom-cli/src/parity/catalog.rs` (module-level doc comment only), and `mikebom-cli/src/parity/extractors.rs` (module-level doc comment only); contents land in Phase 2 + Phase 3.
- [X] T002 [P] Promote `build_benchmark_fixture`, `build_synthetic_image`, and `ImageFile` from private to `pub(crate)` in `mikebom-cli/tests/dual_format_perf.rs`. Add a one-line header comment noting the cross-test reuse (milestone-013 `holistic_parity.rs` calls `build_benchmark_fixture` for its container-image fixture case per research.md §R2). No behavior change — private → crate-visible only.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Implement the catalog parser. Every user story depends on this.

**⚠️ CRITICAL**: No US1/US2/US3 work begins until this phase is complete.

- [X] T003 Implement `mikebom-cli/src/parity/catalog.rs` per `data-model.md` §"`CatalogRow`" + §"`Classification`": `CatalogRow` struct (id/label/cdx_location/spdx23_location/spdx3_location/section), `FormatCoverage` enum (Present/Omitted{reason}/Deferred{reason}), `Classification` struct holding three FormatCoverage fields with `is_universal_parity()` / `is_checked(Format)` methods, `Format` enum, `parse_mapping_doc(&Path) -> Vec<CatalogRow>` function. Parser uses regex `^\| ([A-H][0-9]+[a-z]?) \|` to identify rows (first-cell row-id match), splits the remaining pipes, trims each cell. FormatCoverage inference: column text contains `omitted —` → `Omitted { reason: text_after_em_dash }`, contains `defer —` → `Deferred { ... }`, else `Present`. All public types/functions land under `pub mod catalog` so they're reachable as `mikebom::parity::catalog::*`. Add unit tests asserting (a) every row in `docs/reference/sbom-format-mapping.md` parses cleanly; (b) classification correctly identifies existing `omitted` / `defer` rows (A5, plus any future); (c) universal-parity rows have all three formats Present.

**Checkpoint**: `cargo +stable test -p mikebom --test common` (or equivalent) confirms parser works.

---

## Phase 3: User Story 1 — Holistic parity test (Priority: P1) 🎯 MVP

**Goal**: A single canonical test that iterates the catalog + extractor table, asserts every universal-parity row's datum is present in all three format outputs, for every ecosystem fixture + one container-image fixture. Per clarification Q1 (implicit text-match classification) + Q2 directional cases.

**Independent Test**: `cargo +stable test -p mikebom --test holistic_parity` passes — one test per ecosystem (9) + 1 for the container-image fixture = 10 total; every universal-parity catalog row has its datum present in all three format outputs per each fixture's scan.

- [X] T004 [US1] Add `ParityExtractor` struct + `Directionality` enum in `mikebom-cli/src/parity/extractors.rs` per `data-model.md` §"`ParityExtractor`". Define empty `pub static EXTRACTORS: &[ParityExtractor] = &[];` constant. Add shared helper `extract_mikebom_annotation_values(doc: &Value, field_name: &str, subject_is_document: bool) -> BTreeSet<String>` that decodes the `MikebomAnnotationCommentV1` envelope from SPDX 2.3 `annotations[].comment` / SPDX 3 `Annotation.statement` entries keyed by field-name — used by ~23 Section C rows to keep extractor definitions terse.
- [X] T005 [P] [US1] Fill `EXTRACTORS` table entries for Section A rows (A1–A12 — core identity) in `src/parity/extractors.rs`: PURL, name, version, supplier, author, hashes, declared license, concluded license, homepage, VCS, distribution, CPE. Per research.md §R5, A12 uses `Directionality::CdxSubsetOfSpdx` (CDX single-valued `component.cpe` ⊆ SPDX 3 multi-valued `ExternalIdentifier[cpe23]`); every other A-row uses `Directionality::SymmetricEqual`. Rows classified format-restricted (A4 supplier — see post-milestone-011 classification; A5 author — marked `omitted — mikebom resolution doesn't surface originator`) are noted with `FormatCoverage::Omitted` and the extractor for that format returns `BTreeSet::new()` (the parity test skips the format-restricted extractor anyway, but empty-returns are cleaner than `unreachable!()`).
- [X] T006 [P] [US1] Fill `EXTRACTORS` table entries for Section B rows (B1–B4 — graph structure) in `src/parity/extractors.rs`: dependency edge (runtime), dependency edge (dev), nested containment, image/filesystem root. B3 uses `Directionality::CdxSubsetOfSpdx` (CDX nests, SPDX flattens — the set of (parent, child) pairs is equal when CDX is flattened, which the extractor does). B2 notes: SPDX 3 has no `devDependencyOf` relationshipType per milestone-011 B2 mapping; dev/build subtypes collapse to plain `dependsOn` in SPDX 3, signal preserved via C6 annotation. Extractor returns the PURL-pair set for dependency edges; for dev-dependency, the extractor only counts edges whose C6 annotation (`mikebom:dev-dependency`) is `"true"` on the source Package.
- [X] T007 [P] [US1] Fill `EXTRACTORS` table entries for Section C rows (C1–C23 — mikebom-specific annotations) in `src/parity/extractors.rs` using the `extract_mikebom_annotation_values` helper from T004. Each row's extractor is one line in the CDX direction (`cdx.components[].properties[name=="mikebom:<foo>"].value`) and a one-line helper call for SPDX 2.3 and SPDX 3 (`extract_mikebom_annotation_values(doc, "mikebom:<foo>", false)`). C19 `mikebom:cpe-candidates` uses `Directionality::CdxSubsetOfSpdx` (per research.md §R5 — the candidate-set split across native + annotation). C21–C23 are document-level (subject is document, not a Package) — the helper's `subject_is_document` flag handles that.
- [X] T008 [P] [US1] Fill `EXTRACTORS` table entries for Section D-H rows in `src/parity/extractors.rs`: D1 evidence.identity, D2 evidence.occurrences (both annotation-based via T004's helper), E1 compositions (document-level annotation), F1 VEX (OpenVEX sidecar cross-reference — presence check: SPDX 2.3 `externalDocumentRefs[DocumentRef-OpenVEX]`, SPDX 3 `SpdxDocument.externalRef[vulnerabilityExploitabilityAssessment]`, CDX `/vulnerabilities[]` non-empty OR documented `omitted — no-advisory-fixture` per mapping doc), G1–G4 envelope fields (tool + timestamp + dataLicense + document-identifier — G4 is format-native-only so uses `SymmetricEqual` on tool/timestamp/dataLicense but omits document-identifier as format-specific), H1 structural-difference (meta-row: skipped by the parity test via format-restricted markers in all three columns since it's documentation-only).
- [X] T009 [US1] Add unit test in `src/parity/extractors.rs::tests` module: `every_catalog_row_has_an_extractor` — load the catalog via `super::catalog::parse_mapping_doc`, assert every parsed row's id has a matching entry in `EXTRACTORS`. Orphan catalog rows OR rows without extractors fail this test loudly. Depends on T005–T008.
- [X] T010 [US1] Author `mikebom-cli/tests/holistic_parity.rs` (top of file: `use mikebom::parity::{catalog, extractors};`). One `#[test]` per ecosystem (9) named `parity_<ecosystem>` + 1 for the container-image fixture named `parity_synthetic_container_image` (using `dual_format_perf::build_benchmark_fixture` — see T002's promotion). Each test: run a single triple-format scan (`--format cyclonedx-json,spdx-2.3-json,spdx-3-json`), load the three output files, iterate `extractors::EXTRACTORS`, for each universal-parity row invoke the three extractors, assert the extracted sets satisfy the `Directionality` rule (SymmetricEqual = three-way equality; CdxSubsetOfSpdx = `cdx ⊆ spdx23 && cdx ⊆ spdx3`). HOME / M2_REPO / MAVEN_HOME / GOPATH / GOMODCACHE / CARGO_HOME isolation per the project standard. Failure messages name the row id + label + the set-difference so the offending datum is instantly visible.

**Checkpoint**: `cargo +stable test -p mikebom --test holistic_parity` passes all 10 tests.

---

## Phase 4: User Story 2 — Bidirectional catalog ↔ emitter auto-discovery (Priority: P2)

**Goal**: A new test file that walks both directions — forward (emitter → catalog: every distinct CDX property name in any fixture output has a matching catalog row) + reverse (catalog → emitter: every universal-parity catalog row's CDX property name appears in at least one ecosystem's output). Per clarification Q2.

**Independent Test**: `cargo +stable test -p mikebom --test mapping_doc_bidirectional` passes; no new tests needed in other files.

- [X] T011 [P] [US2] Add helper `extract_cdx_property_name_from_catalog_row(row: &CatalogRow) -> Option<String>` in `mikebom-cli/src/parity/catalog.rs`. Implements the three-pattern regex from research.md §R3: (1) property-row pattern — `name="([^"]+)"` over CDX column, returns the `mikebom:<foo>` name; (2) direct-JSON-path pattern — trailing path segment after final `/`; (3) whole-string fallback for rows where neither regex matches. Rows whose CDX column contains `omitted —` or `defer —` return `None` — the caller skips them for the reverse direction. Add unit tests covering all three patterns against existing catalog rows.
- [X] T012 [US2] Author `mikebom-cli/tests/mapping_doc_bidirectional.rs` (top of file: `use mikebom::parity::catalog::{parse_mapping_doc, extract_cdx_property_name_from_catalog_row, ...};`). Emits CDX for all 9 ecosystem fixtures (cached in `OnceLock<Vec<(label, cdx_json)>>` so the triple-format scan runs once per ecosystem, not twice — shared tempdir via `lazy_static!`-style initialization if needed). Two test functions: (a) `forward_every_emitted_property_has_a_catalog_row` — walk all 9 CDX outputs, collect distinct `components[].properties[].name` + `metadata.properties[].name` + top-level document keys into a `BTreeSet`, assert each is covered by a catalog row's CDX-column extracted name per the T011 helper; (b) `reverse_every_universal_parity_row_has_at_least_one_emitted_value` — iterate catalog rows classified `universal-parity`, extract each row's CDX property name, assert the name is present in at least one of the 9 cached CDX outputs.

**Checkpoint**: Both tests pass. A future regression that adds a CDX property without updating the catalog fails (a). A future catalog edit that references a deleted property fails (b).

---

## Phase 5: User Story 3 — User-facing parity diagnostic (Priority: P3)

**Goal**: A new `mikebom sbom parity-check --scan-dir <dir>` subcommand that reads already-emitted three-format outputs, runs the same extractor table as US1's test, renders a per-datum × per-format coverage table. Per research.md §R1 (subcommand, not flag; exit codes 0/1/2).

**Independent Test**: `cargo +stable test -p mikebom --test parity_cmd` passes + `mikebom sbom parity-check --help` exits cleanly with usage text.

- [X] T013 [P] [US3] Add `mikebom-cli/src/cli/parity_cmd.rs` with `ParityCheckArgs` (clap Args derive: `scan_dir: PathBuf`, `format: OutputFormat` with default `Table`), `OutputFormat` enum (`Table`, `Json`), `CoverageReport` struct, `CoverageRowReport` struct, `CoverageStatus` enum (`Present { value_count }`, `Restricted { reason }`, `Missing`) per data-model.md §"`CoverageReport`". Imports the catalog parser + extractor table via `use crate::parity::{catalog, extractors};` (the binary crate sees `crate::parity::*` because `src/lib.rs` exposes `pub mod parity` — see T001). Stub out the `execute(args: ParityCheckArgs) -> anyhow::Result<ExitCode>` function as a no-op for this task — filling follows in T014.
- [X] T014 [US3] Implement `parity_cmd::execute`: (1) locate the three expected files `<scan_dir>/mikebom.cdx.json`, `<scan_dir>/mikebom.spdx.json`, `<scan_dir>/mikebom.spdx3.json`, exit code 2 on any missing or unparseable; (2) load the catalog via `crate::parity::catalog::parse_mapping_doc`; (3) iterate every catalog row, invoking the matching `crate::parity::extractors::EXTRACTORS` entry's three extractors (or `BTreeSet::new()` for format-restricted columns); (4) compute per-row `CoverageRowReport` with the correct `CoverageStatus` per format; (5) build the `CoverageReport`; (6) render per `OutputFormat` flag; (7) exit code 1 if any universal-parity row has `CoverageStatus::Missing` in any format, else 0. The catalog parser + extractor table are in `src/parity/` (per the C1 resolution from analysis); both binary AND tests import via `mikebom::parity::*`. No duplication.
- [X] T015 [P] [US3] Implement `CoverageReport::render_table` per the quickstart.md example output: one section per catalog-row section letter (A / B / C / …), one row per catalog row, `[CDX ✓ (N)]` / `[CDX · (0)]` / `[CDX ⚠️ MISSING]` marker per format. Summary footer: "Universal-parity rows: N / M  ✓", "Format-restricted rows: K", "Parity gaps: 0". Unit tests for rendering.
- [X] T016 [P] [US3] Implement `CoverageReport::render_json` — same data, JSON shape. Unit tests covering the serialized structure.
- [X] T017 [US3] Register the `parity-check` subcommand in `mikebom-cli/src/cli/mod.rs` (and `main.rs` if `SbomCommand` is enumerated there) under the existing `sbom` noun: `SbomCommand::ParityCheck(ParityCheckArgs)` variant, dispatched in the command's match arm to `parity_cmd::execute`. Depends on T014.
- [X] T018 [US3] Author `mikebom-cli/tests/parity_cmd.rs` with end-to-end tests: (a) produce all three format outputs via `cargo +stable run -- sbom scan …` into a tempdir, invoke `cargo +stable run -- sbom parity-check --scan-dir <tmp>`, assert exit code 0 + stdout table contains expected row IDs; (b) delete one of the three files post-scan, assert exit code 2 with a clear error message; (c) `--format json` produces parseable JSON whose `rows[]` shape matches CoverageReport.

**Checkpoint**: `mikebom sbom parity-check --scan-dir <valid-dir>` produces a coverage table; exit codes 0/1/2 all reachable; help text shows new subcommand.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Verify no existing test suite regressed + final pre-PR gate.

- [X] T019 [P] Verify milestone-010 / 011 / 012 per-slice parity tests still pass: `cargo +stable test -p mikebom --test spdx_cdx_parity --test spdx3_cdx_parity --test spdx_annotation_fidelity --test spdx3_annotation_fidelity --test cpe_v3_acceptance --test component_count_parity --test spdx_license_ref_extracted` — all expected green.
- [X] T020 [P] Verify milestone-010 / 011 / 012 byte-equality regression guards still pass: `cdx_regression`, `spdx_us1_acceptance`, `spdx_determinism`, `spdx3_determinism`, `format_dispatch`. Cite per-test counts in the PR description per `feedback_prepr_gate_full_output.md`.
- [X] T021 [P] Verify `sbom_format_mapping_coverage.rs` still passes — no changes expected since the mapping doc is untouched by this milestone, but the existing coverage test guards the doc structure.
- [X] T022 Run the quickstart.md smoke-test: release-build the binary, scan the npm fixture in triple-format mode into a tempdir, run `mikebom sbom parity-check --scan-dir <tmp>`, confirm the output table renders with per-section grouping and exit code 0.
- [X] T023 Run pre-PR gate: `cargo +stable clippy --workspace --all-targets` (zero errors) AND `cargo +stable test --workspace` (every suite reports `ok. N passed; 0 failed`). Capture per-target pass counts for the PR description.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: T001 + T002 both [P]. No dependencies.
- **Foundational (Phase 2)**: T003 depends on T001. Blocks every user story.
- **US1 (Phase 3)**: depends on Phase 2 (uses `parity_catalog`). Within US1: T004 (types) before T005–T008 (table fills) before T009 (setup-guard test) + T010 (the holistic test itself).
- **US2 (Phase 4)**: depends on Phase 2. T011 adds a helper to `parity_catalog.rs`; T012 consumes it. Can run in parallel with US1 work after T003 lands.
- **US3 (Phase 5)**: depends on Phase 2 + US1 (needs the EXTRACTORS table filled). T013 is stub; T014 is the main implementation (depends on T013 + US1's T005–T008); T015 + T016 [P] (different rendering paths); T017 wires up the subcommand (depends on T014); T018 is the e2e test (depends on T017).
- **Polish (Phase 6)**: depends on all three user stories complete. T019 + T020 + T021 [P] (independent test-suite verifications); T022 + T023 sequential at the end.

### User Story Dependencies

- **US1 (P1, MVP)**: independent within Phase 2 gate. Ships a standalone holistic parity test even without US2 or US3.
- **US2 (P2)**: independent within Phase 2 gate. Can ship as a separate PR after US1 or in parallel with it.
- **US3 (P3)**: depends on US1's EXTRACTORS table. Can ship after US1 (own PR) or combined with US1 + US2.

### Parallel Opportunities

- **Setup**: T001 + T002 [P].
- **US1 table fills**: T005 + T006 + T007 + T008 [P] — four independent EXTRACTORS table sections; each contributes ~10–23 entries. Biggest parallelizable batch in the milestone.
- **US3 rendering**: T015 + T016 [P] — table vs JSON rendering paths.
- **Polish**: T019 + T020 + T021 [P] — three independent verification runs.

---

## Parallel Example: US1 extractor table fill

```bash
# Four independent table fills in parallel:
Task: "Fill EXTRACTORS entries for Section A (A1–A12 core identity) in parity_extractors.rs"
Task: "Fill EXTRACTORS entries for Section B (B1–B4 graph structure) in parity_extractors.rs"
Task: "Fill EXTRACTORS entries for Section C (C1–C23 mikebom annotations) using extract_mikebom_annotation_values helper in parity_extractors.rs"
Task: "Fill EXTRACTORS entries for Section D-H (D1/D2/E1/F1/G1-G4/H1 miscellaneous) in parity_extractors.rs"

# Then sequential:
Task: "Add every_catalog_row_has_an_extractor unit test to parity_extractors.rs::tests"
Task: "Author holistic_parity.rs (10 #[test] functions iterating EXTRACTORS)"
```

---

## Implementation Strategy

### MVP First (US1 only)

1. Complete Phase 1: Setup (T001–T002). ~10 minutes.
2. Complete Phase 2: Foundational (T003). ~30 minutes — parser + unit tests.
3. Complete Phase 3: US1 (T004–T010). ~3 hours — the table is the biggest time sink; can parallelize by section.
4. Run `cargo +stable test -p mikebom --test holistic_parity` — all 10 tests pass.
5. Ship as a standalone PR — the holistic guarantee is the main user ask from this milestone's spec.

### Incremental Delivery

1. Setup + Foundational → ready.
2. US1 → MVP ships. Holistic parity enforced.
3. US2 → ships. Bidirectional regression-prevention layer.
4. US3 → ships. User-facing diagnostic.
5. Polish → final pre-PR gate.

### Parallel Team Strategy

After Phase 2, three developers can split:
- Developer A: US1 T005–T008 in parallel (table fills by section)
- Developer B: US2 T011–T012 (auto-discovery + reverse)
- Developer C: US3 T013–T016 (CLI + rendering)

All three converge on T017–T018 (wire US3) + Phase 6 polish.

---

## Notes

- File paths absolute relative to repo root; cargo commands run from repo root.
- `docs/reference/sbom-format-mapping.md` is **read-only** for this milestone. The catalog doc is the source of truth; milestone-013 code parses it; no milestone-013 edit modifies it.
- Per `feedback_prepr_gate_full_output.md`, the PR description MUST cite per-target `ok. N passed; 0 failed` lines, not grep summaries.
- `#[cfg_attr(test, allow(clippy::unwrap_used))]` guards on test modules (Constitution Principle IV + `mikebom-cli` crate-root deny).
- The extractor table is the one place where "how to check this datum in each format" is executable. When a new catalog row lands in a future milestone, adding a table entry is mandatory (T009 fires if missing). When a table entry exists without a corresponding catalog row, the reverse-check in US2's T012 fires.
- The extractor table + catalog parser live at `mikebom-cli/src/parity/` (production code path) per the C1 resolution from analysis. Tests under `tests/` import via `use mikebom::parity::{catalog, extractors};`. The binary's `cli/parity_cmd.rs` imports via `use crate::parity::{catalog, extractors};`. mikebom-cli is promoted from binary-only to lib + bin via a minimal `src/lib.rs` (per T001).
