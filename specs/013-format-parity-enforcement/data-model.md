# Phase 1 Data Model: Holistic Cross-Format Output Parity

**Branch**: `013-format-parity-enforcement` | **Date**: 2026-04-25 | **Plan**: [plan.md](plan.md) | **Research**: [research.md](research.md)

## Scope

Test-layer + CLI-layer types only. No changes to `mikebom-common`, `generate/`, `resolve/`, or any scan-pipeline types. Three new test-shared modules and one new CLI subcommand module.

## Module layout

```text
mikebom-cli/src/
├── lib.rs                    # NEW — minimal library-crate root: `pub mod parity;`
├── main.rs                   # untouched
├── parity/
│   ├── mod.rs                # `pub mod catalog; pub mod extractors;`
│   ├── catalog.rs            # defines CatalogRow, FormatCoverage, Classification, Format, parse_mapping_doc
│   └── extractors.rs         # defines ParityExtractor, Directionality, EXTRACTORS table
└── cli/
    └── parity_cmd.rs         # declares pub fn execute(args: ParityCheckArgs) -> anyhow::Result<()>
                              # + ParityCheckArgs struct with --scan-dir, --format flags
```

**Visibility note**: `parity/` lives under `src/` (production path) so that both the binary's `cli/parity_cmd.rs` AND integration tests under `tests/` can `use mikebom::parity::{parse_mapping_doc, EXTRACTORS, ...}`. The lib + bin crate layout is the standard Rust pattern for sharing modules between a binary and its integration tests; mikebom-cli previously had only `src/main.rs` (binary-only), so this milestone introduces a minimal `src/lib.rs` whose only purpose is `pub mod parity;`.

## Types

### `CatalogRow` (in `tests/common/parity_catalog.rs`)

One row from `docs/reference/sbom-format-mapping.md`.

```rust
#[derive(Debug, Clone)]
pub struct CatalogRow {
    /// Row identifier — A1, A2, …, B1, B2, …, H1 (first cell of
    /// each markdown table row).
    pub id: String,
    /// Human-readable short name — second cell ("PURL", "name",
    /// "mikebom:source-type", etc.).
    pub label: String,
    /// Full text of the CycloneDX 1.6 location column.
    pub cdx_location: String,
    /// Full text of the SPDX 2.3 location column.
    pub spdx23_location: String,
    /// Full text of the SPDX 3.0.1 location column.
    pub spdx3_location: String,
    /// Section letter (A, B, C, D, E, F, G, H) — derived from
    /// row id's first character. Used for grouping in the US3
    /// diagnostic output.
    pub section: char,
}
```

Parser function:

```rust
pub fn parse_mapping_doc(markdown_path: &std::path::Path) -> Vec<CatalogRow>;
```

Contract: finds every markdown table row whose first cell matches `/^[A-H][0-9]+[a-z]?$/` (covers A1–H99 + lettered-suffix rows like T036b), extracts the 2nd–5th cells as `label / cdx_location / spdx23_location / spdx3_location`, ignores all other rows (header dividers, narrative text, maintenance-contract section). Returns rows in document order.

### `Classification` (in `tests/common/parity_catalog.rs`)

Per-row, per-format coverage classification, inferred from the location text (clarification Q1):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatCoverage {
    /// Native field binding or Annotation path; this format
    /// carries the datum.
    Present,
    /// Row explicitly says `omitted — <reason>` in this format's
    /// column. The format intentionally does not carry the datum.
    Omitted { reason: String },
    /// Row says `defer — <reason>`. Same semantics as Omitted for
    /// parity-check purposes; kept as a distinct variant so the
    /// diagnostic can surface "deferred to a future milestone"
    /// vs "structurally omitted."
    Deferred { reason: String },
}

#[derive(Debug, Clone)]
pub struct Classification {
    pub cdx: FormatCoverage,
    pub spdx23: FormatCoverage,
    pub spdx3: FormatCoverage,
}

impl Classification {
    /// True when every format is Present. The parity test enforces
    /// equality (or directional containment) on these rows.
    pub fn is_universal_parity(&self) -> bool;

    /// For each format, whether the row should be checked.
    /// Omitted / Deferred skip the corresponding extractor.
    pub fn is_checked(&self, format: Format) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format { Cdx, Spdx23, Spdx3 }
```

Inference rule (per clarification Q1): `FormatCoverage` is `Omitted { reason }` if the column text contains `omitted —`, `Deferred { reason }` if it contains `defer —`, else `Present`.

### `ParityExtractor` (in `tests/common/parity_extractors.rs`)

Per-row extractor table entry. One entry per catalog row whose Classification has at least one `Present` format.

```rust
pub struct ParityExtractor {
    pub row_id: &'static str,     // "A1", "A2", …
    pub label: &'static str,      // "PURL", "mikebom:source-type", …
    pub cdx: fn(&serde_json::Value) -> std::collections::BTreeSet<String>,
    pub spdx23: fn(&serde_json::Value) -> std::collections::BTreeSet<String>,
    pub spdx3: fn(&serde_json::Value) -> std::collections::BTreeSet<String>,
    pub directional: Directionality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Directionality {
    /// CDX, SPDX 2.3, SPDX 3 sets must be equal.
    SymmetricEqual,
    /// CDX ⊆ SPDX 2.3 AND CDX ⊆ SPDX 3. The SPDX sides MAY carry
    /// additional values not in CDX (e.g., A12 CPE: CDX primary
    /// only; SPDX 3 all fully-resolved candidates).
    CdxSubsetOfSpdx,
}
```

Static table:

```rust
pub static EXTRACTORS: &[ParityExtractor] = &[
    ParityExtractor {
        row_id: "A1",
        label: "PURL",
        cdx: extract_cdx_purls,
        spdx23: extract_spdx23_purls,
        spdx3: extract_spdx3_purls,
        directional: Directionality::SymmetricEqual,
    },
    // … one entry per catalog row that has at least one Present format
];
```

Three helper functions per row (one per format). Total: ~45 rows × 3 = ~135 small closures. Each closure is 5–10 lines of `serde_json::Value` navigation.

### `CoverageReport` (in `cli/parity_cmd.rs`, for US3)

User-facing output shape:

```rust
pub struct CoverageReport {
    pub rows: Vec<CoverageRowReport>,
}

pub struct CoverageRowReport {
    pub row_id: String,
    pub label: String,
    pub section: char,
    pub cdx: CoverageStatus,
    pub spdx23: CoverageStatus,
    pub spdx3: CoverageStatus,
}

pub enum CoverageStatus {
    /// Datum present in this format.
    Present { value_count: usize },
    /// Row intentionally omits this format (with reason).
    Restricted { reason: String },
    /// Row is universal-parity but this format's extractor returned
    /// an empty set — a parity gap worth flagging.
    Missing,
}

impl CoverageReport {
    /// Render as an ASCII table with per-format columns and
    /// ✓ / · / ⚠️ markers.
    pub fn render_table(&self) -> String;

    /// Render as JSON (for `--format json`).
    pub fn render_json(&self) -> serde_json::Value;
}
```

### `ParityCheckArgs` (CLI flags for US3)

```rust
#[derive(Debug, clap::Args)]
pub struct ParityCheckArgs {
    /// Directory containing the emitted format outputs. Expected
    /// filenames:
    ///   - `mikebom.cdx.json`  (CycloneDX)
    ///   - `mikebom.spdx.json` (SPDX 2.3)
    ///   - `mikebom.spdx3.json` (SPDX 3)
    /// Missing files → exit code 2.
    #[arg(long)]
    pub scan_dir: std::path::PathBuf,

    /// Output shape: `table` (human-readable, default) or `json`
    /// (machine-readable).
    #[arg(long, default_value = "table")]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat { Table, Json }
```

Exit codes:
- `0` — all universal-parity rows accounted for in all three formats.
- `1` — at least one universal-parity row missing from at least one format (gap detected).
- `2` — input error (missing file, unparseable JSON, unreadable directory).

## Parser contract (invariants)

1. `parse_mapping_doc` MUST return every table row whose first cell matches the row-id regex. Ordering is document order. Stable across runs (file contents are the only input).
2. `Classification::from_row` MUST be deterministic — same three location strings always produce the same classification. No external state, no time-dependent behavior.
3. The EXTRACTORS table MUST be in catalog-row order (sorted by row_id). A unit test in `tests/common/parity_catalog.rs::tests` enforces this.
4. Every CatalogRow returned by the parser MUST have a corresponding entry in EXTRACTORS (by `row_id`). A unit test in `tests/common/parity_extractors.rs::tests` enforces this — missing extractor = test-setup error, surfaced before any parity assertion runs.

## Interaction with existing code

- **No changes** to any `src/generate/` module. The holistic parity test + reverse check + diagnostic are pure readers of emitted format outputs.
- **No changes** to `scan_cmd.rs`. The new `parity_cmd.rs` is registered as a sibling in `cli/mod.rs`.
- **`tests/dual_format_perf.rs::build_benchmark_fixture`** is promoted from private `fn` to `pub(crate) fn` so `holistic_parity.rs` can call it for the container-image fixture (research.md §R2).

No public-API surface changes. The new CLI subcommand is additive.
