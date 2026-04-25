//! `mikebom sbom parity-check` subcommand (milestone 013 US3 /
//! T013–T017).
//!
//! Reads three already-emitted format outputs from a directory
//! (`<dir>/mikebom.cdx.json`, `<dir>/mikebom.spdx.json`,
//! `<dir>/mikebom.spdx3.json`) and renders a per-datum × per-
//! format coverage table using the same catalog + extractor
//! table as the holistic_parity test (US1). Exit codes:
//!
//! - 0: every universal-parity catalog row has its datum
//!   present in all three formats per its [`Directionality`].
//! - 1: at least one universal-parity row's datum is absent in
//!   at least one format that's *expected* to carry it.
//! - 2: input files missing or unparseable.
//!
//! See `specs/013-format-parity-enforcement/quickstart.md` for
//! the canonical end-to-end usage.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use serde::Serialize;
use serde_json::Value;

use mikebom::parity::catalog::{parse_mapping_doc, CatalogRow, Format, FormatCoverage};
use mikebom::parity::extractors::{Directionality, ParityExtractor, EXTRACTORS};

/// Args for `mikebom sbom parity-check`.
#[derive(Args, Debug)]
pub struct ParityCheckArgs {
    /// Directory containing the three previously-emitted format
    /// files: `mikebom.cdx.json`, `mikebom.spdx.json`,
    /// `mikebom.spdx3.json`. All three must be present.
    #[arg(long)]
    pub scan_dir: PathBuf,

    /// Output format. `table` is the default human-readable
    /// per-row × per-format grid; `json` produces the machine
    /// readable [`CoverageReport`] structure for CI consumption.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
}

/// Per-format coverage status of a single catalog row, computed
/// from running its extractor against the corresponding format
/// output.
#[derive(Serialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CoverageStatus {
    /// Extractor returned at least one value.
    Present { value_count: usize },
    /// The catalog classifies this format-row as Omitted /
    /// Deferred. The extractor is skipped; the diagnostic
    /// preserves the reason verbatim.
    Restricted { reason: String },
    /// Extractor returned empty AND the row's classification
    /// expects the datum to be present in this format. This
    /// flags a parity gap when paired with a Present sibling
    /// in another format (i.e., the datum is in some formats
    /// but not all). When EVERY format's status is `Absent`,
    /// the scan simply doesn't carry the datum (not a gap).
    Absent,
}

#[derive(Serialize, Debug, Clone)]
pub struct CoverageRowReport {
    pub row_id: String,
    pub label: String,
    pub section: char,
    pub directional: String,
    pub cdx: CoverageStatus,
    pub spdx23: CoverageStatus,
    pub spdx3: CoverageStatus,
    pub universal_parity: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct CoverageSummary {
    pub universal_parity_rows_total: usize,
    pub universal_parity_rows_passing: usize,
    pub format_restricted_rows: usize,
    pub parity_gaps: usize,
}

#[derive(Serialize, Debug, Clone)]
pub struct CoverageReport {
    pub summary: CoverageSummary,
    pub rows: Vec<CoverageRowReport>,
}

impl CoverageReport {
    /// Render the per-section grouped table to stdout per the
    /// quickstart.md example. Section headers are alphabetic
    /// (A / B / C / …); each row shows three `[<format> <icon>
    /// (N)]` markers.
    pub fn render_table(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut current_section: Option<char> = None;
        for row in &self.rows {
            if Some(row.section) != current_section {
                writeln!(out, "\n=== Section {} ===", row.section)?;
                current_section = Some(row.section);
            }
            writeln!(
                out,
                "  {:<5} {:<48} [CDX {}] [SPDX2.3 {}] [SPDX3 {}]",
                row.row_id,
                row.label,
                fmt_status(&row.cdx),
                fmt_status(&row.spdx23),
                fmt_status(&row.spdx3),
            )?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "Universal-parity rows: {} / {}  {}",
            self.summary.universal_parity_rows_passing,
            self.summary.universal_parity_rows_total,
            if self.summary.parity_gaps == 0 {
                "✓"
            } else {
                "✗"
            }
        )?;
        writeln!(
            out,
            "Format-restricted rows: {}",
            self.summary.format_restricted_rows
        )?;
        writeln!(out, "Parity gaps: {}", self.summary.parity_gaps)?;
        Ok(())
    }

    pub fn render_json(&self, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
        serde_json::to_writer_pretty(&mut *out, self)?;
        writeln!(out)?;
        Ok(())
    }
}

fn fmt_status(s: &CoverageStatus) -> String {
    match s {
        CoverageStatus::Present { value_count } => format!("✓ ({value_count})"),
        CoverageStatus::Restricted { .. } => "· (n/a)".into(),
        CoverageStatus::Absent => "· (0)".into(),
    }
}

fn coverage_to_status(coverage: &FormatCoverage, value_count: usize) -> CoverageStatus {
    match coverage {
        FormatCoverage::Present => {
            if value_count > 0 {
                CoverageStatus::Present { value_count }
            } else {
                CoverageStatus::Absent
            }
        }
        FormatCoverage::Omitted { reason } | FormatCoverage::Deferred { reason } => {
            CoverageStatus::Restricted {
                reason: reason.clone(),
            }
        }
    }
}

fn workspace_root_for_mapping_doc() -> PathBuf {
    // The catalog is the *canonical* doc — `docs/reference/sbom-
    // format-mapping.md`. The binary needs to find it relative to
    // CARGO_MANIFEST_DIR at compile time when running from the
    // workspace; otherwise, callers must `cd` to the repo root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn read_format_file(label: &str, path: &PathBuf) -> anyhow::Result<Value> {
    let s = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!("failed to read {label} at {}: {e}", path.display())
    })?;
    serde_json::from_str(&s).map_err(|e| {
        anyhow::anyhow!("failed to parse {label} at {} as JSON: {e}", path.display())
    })
}

pub async fn execute(args: ParityCheckArgs) -> anyhow::Result<ExitCode> {
    let cdx_path = args.scan_dir.join("mikebom.cdx.json");
    let spdx23_path = args.scan_dir.join("mikebom.spdx.json");
    let spdx3_path = args.scan_dir.join("mikebom.spdx3.json");
    for (label, p) in [
        ("CycloneDX output", &cdx_path),
        ("SPDX 2.3 output", &spdx23_path),
        ("SPDX 3 output", &spdx3_path),
    ] {
        if !p.exists() {
            eprintln!(
                "Error: {label} not found at {} — run `mikebom sbom scan ... --format cyclonedx-json,spdx-2.3-json,spdx-3-json` into this directory first.",
                p.display()
            );
            return Ok(ExitCode::from(2));
        }
    }
    let cdx = match read_format_file("CycloneDX output", &cdx_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return Ok(ExitCode::from(2));
        }
    };
    let spdx23 = match read_format_file("SPDX 2.3 output", &spdx23_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return Ok(ExitCode::from(2));
        }
    };
    let spdx3 = match read_format_file("SPDX 3 output", &spdx3_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return Ok(ExitCode::from(2));
        }
    };

    let mapping_doc = workspace_root_for_mapping_doc().join("docs/reference/sbom-format-mapping.md");
    if !mapping_doc.exists() {
        eprintln!(
            "Error: catalog doc not found at {} — `mikebom sbom parity-check` must run from the mikebom workspace root (or with the doc bundled into the runtime).",
            mapping_doc.display()
        );
        return Ok(ExitCode::from(2));
    }
    let rows = parse_mapping_doc(&mapping_doc);

    let report = build_report(&rows, &cdx, &spdx23, &spdx3);

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    match args.format {
        OutputFormat::Table => report.render_table(&mut handle)?,
        OutputFormat::Json => report.render_json(&mut handle)?,
    }

    if report.summary.parity_gaps == 0 {
        Ok(ExitCode::from(0))
    } else {
        Ok(ExitCode::from(1))
    }
}

fn build_report(
    rows: &[CatalogRow],
    cdx: &Value,
    spdx23: &Value,
    spdx3: &Value,
) -> CoverageReport {
    let mut row_reports: Vec<CoverageRowReport> = Vec::new();
    let mut universal_total = 0usize;
    let mut universal_pass = 0usize;
    let mut restricted = 0usize;
    let mut gaps = 0usize;

    for row in rows {
        let classification = row.classification();
        let extractor: Option<&ParityExtractor> =
            EXTRACTORS.iter().find(|e| e.row_id == row.id);
        let (cdx_count, spdx23_count, spdx3_count) = match extractor {
            Some(e) => (
                if classification.is_checked(Format::Cdx) {
                    (e.cdx)(cdx).len()
                } else {
                    0
                },
                if classification.is_checked(Format::Spdx23) {
                    (e.spdx23)(spdx23).len()
                } else {
                    0
                },
                if classification.is_checked(Format::Spdx3) {
                    (e.spdx3)(spdx3).len()
                } else {
                    0
                },
            ),
            None => (0, 0, 0),
        };

        let cdx_status = coverage_to_status(&classification.cdx, cdx_count);
        let spdx23_status = coverage_to_status(&classification.spdx23, spdx23_count);
        let spdx3_status = coverage_to_status(&classification.spdx3, spdx3_count);

        let universal_parity = classification.is_universal_parity();
        if universal_parity {
            universal_total += 1;
            let any_present = matches!(cdx_status, CoverageStatus::Present { .. })
                || matches!(spdx23_status, CoverageStatus::Present { .. })
                || matches!(spdx3_status, CoverageStatus::Present { .. });
            let all_present = matches!(cdx_status, CoverageStatus::Present { .. })
                && matches!(spdx23_status, CoverageStatus::Present { .. })
                && matches!(spdx3_status, CoverageStatus::Present { .. });
            if all_present {
                universal_pass += 1;
            } else if any_present {
                // Present in some, absent in others — a real
                // parity gap that drives exit code 1.
                gaps += 1;
            }
            // else: the scan simply doesn't carry this datum;
            // not a gap, just an unexercised row.
        } else {
            restricted += 1;
        }

        row_reports.push(CoverageRowReport {
            row_id: row.id.clone(),
            label: row.label.clone(),
            section: row.section,
            directional: extractor
                .map(|e| match e.directional {
                    Directionality::SymmetricEqual => "symmetric_equal",
                    Directionality::CdxSubsetOfSpdx => "cdx_subset_of_spdx",
                    Directionality::PresenceOnly => "presence_only",
                })
                .unwrap_or("unknown")
                .to_string(),
            cdx: cdx_status,
            spdx23: spdx23_status,
            spdx3: spdx3_status,
            universal_parity,
        });
    }

    // Suppress unused warning while keeping `BTreeSet` import in
    // sync with future expansions of this module (the helper-set
    // approach is referenced by render_table's spec).
    let _: Option<BTreeSet<String>> = None;

    CoverageReport {
        summary: CoverageSummary {
            universal_parity_rows_total: universal_total,
            universal_parity_rows_passing: universal_pass,
            format_restricted_rows: restricted,
            parity_gaps: gaps,
        },
        rows: row_reports,
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn render_table_includes_section_headers_and_summary() {
        let report = CoverageReport {
            summary: CoverageSummary {
                universal_parity_rows_total: 1,
                universal_parity_rows_passing: 1,
                format_restricted_rows: 0,
                parity_gaps: 0,
            },
            rows: vec![CoverageRowReport {
                row_id: "A1".into(),
                label: "PURL".into(),
                section: 'A',
                directional: "symmetric_equal".into(),
                cdx: CoverageStatus::Present { value_count: 3 },
                spdx23: CoverageStatus::Present { value_count: 3 },
                spdx3: CoverageStatus::Present { value_count: 3 },
                universal_parity: true,
            }],
        };
        let mut buf: Vec<u8> = Vec::new();
        report.render_table(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Section A"));
        assert!(s.contains("A1"));
        assert!(s.contains("Universal-parity rows: 1 / 1"));
        assert!(s.contains("Parity gaps: 0"));
    }

    #[test]
    fn render_json_emits_summary_and_rows() {
        let report = CoverageReport {
            summary: CoverageSummary {
                universal_parity_rows_total: 1,
                universal_parity_rows_passing: 0,
                format_restricted_rows: 0,
                parity_gaps: 1,
            },
            rows: vec![CoverageRowReport {
                row_id: "A1".into(),
                label: "PURL".into(),
                section: 'A',
                directional: "symmetric_equal".into(),
                cdx: CoverageStatus::Absent,
                spdx23: CoverageStatus::Present { value_count: 1 },
                spdx3: CoverageStatus::Present { value_count: 1 },
                universal_parity: true,
            }],
        };
        let mut buf: Vec<u8> = Vec::new();
        report.render_json(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["summary"]["parity_gaps"], json!(1));
        assert_eq!(v["rows"][0]["row_id"], json!("A1"));
        assert_eq!(v["rows"][0]["cdx"]["kind"], json!("absent"));
    }
}
