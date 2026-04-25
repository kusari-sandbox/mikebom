//! Cross-format datum-catalog parser (milestone 013 T003 + T011).
//!
//! Parses `docs/reference/sbom-format-mapping.md` — the canonical
//! datum catalog — into a `Vec<CatalogRow>`. Per spec
//! clarification Q1, classification is inferred from the
//! presence of `omitted — <reason>` or `defer — <reason>` text in
//! one or more format columns.
//!
//! See `specs/013-format-parity-enforcement/research.md` §R3 for
//! the regex-based extraction rules and `specs/013-format-parity-enforcement/data-model.md`
//! §"`CatalogRow`" + §"`Classification`" for the type catalog.

use std::path::Path;

/// One row of the datum-catalog table — extracted from
/// `docs/reference/sbom-format-mapping.md` via the
/// `parse_mapping_doc` function.
#[derive(Debug, Clone)]
pub struct CatalogRow {
    /// Row identifier — "A1", "A2", …, "B1", …, "H1". First cell
    /// of the markdown table row.
    pub id: String,
    /// Human-readable short name. Second cell.
    pub label: String,
    /// Third cell — full text of the CycloneDX 1.6 location.
    pub cdx_location: String,
    /// Fourth cell — full text of the SPDX 2.3 location.
    pub spdx23_location: String,
    /// Fifth cell — full text of the SPDX 3.0.1 location.
    pub spdx3_location: String,
    /// Section letter, derived from id's first character (A, B,
    /// …, H). Used for grouping in the US3 diagnostic output.
    pub section: char,
}

impl CatalogRow {
    /// Per-format classification of this row. See [`Classification`].
    pub fn classification(&self) -> Classification {
        Classification {
            cdx: classify_column(&self.cdx_location),
            spdx23: classify_column(&self.spdx23_location),
            spdx3: classify_column(&self.spdx3_location),
        }
    }
}

/// Per-format coverage classification, inferred from the
/// location text per spec clarification Q1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatCoverage {
    /// Native field binding or Annotation path; this format
    /// carries the datum.
    Present,
    /// Row explicitly says `omitted — <reason>` in this format's
    /// column.
    Omitted { reason: String },
    /// Row says `defer — <reason>`. Same semantics as Omitted for
    /// parity-check purposes; kept distinct so the diagnostic can
    /// surface "deferred to a future milestone" vs "structurally
    /// omitted."
    Deferred { reason: String },
}

impl FormatCoverage {
    /// True when the format intentionally does NOT carry the
    /// datum (Omitted or Deferred). The parity check skips the
    /// extractor for such formats.
    pub fn is_restricted(&self) -> bool {
        matches!(self, Self::Omitted { .. } | Self::Deferred { .. })
    }
}

/// Per-row, per-format classification holder.
#[derive(Debug, Clone)]
pub struct Classification {
    pub cdx: FormatCoverage,
    pub spdx23: FormatCoverage,
    pub spdx3: FormatCoverage,
}

impl Classification {
    /// True when every format is `Present` — the parity test
    /// enforces equality (or directional containment) on these
    /// rows.
    pub fn is_universal_parity(&self) -> bool {
        matches!(self.cdx, FormatCoverage::Present)
            && matches!(self.spdx23, FormatCoverage::Present)
            && matches!(self.spdx3, FormatCoverage::Present)
    }

    /// Whether the parity check should run for the given format.
    /// Restricted (Omitted/Deferred) formats skip their extractor.
    pub fn is_checked(&self, format: Format) -> bool {
        let coverage = match format {
            Format::Cdx => &self.cdx,
            Format::Spdx23 => &self.spdx23,
            Format::Spdx3 => &self.spdx3,
        };
        !coverage.is_restricted()
    }
}

/// Three-way enum naming the format being checked. Used by
/// `Classification::is_checked` and the per-row extractor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Cdx,
    Spdx23,
    Spdx3,
}

/// Classify one column's text per the implicit-text-match rule
/// (spec clarification Q1).
fn classify_column(text: &str) -> FormatCoverage {
    // Em-dash (`—`, U+2014) is the canonical separator the
    // mapping doc uses. ASCII hyphens are not accepted — the
    // doc convention is consistent.
    if let Some(rest) = text.split_once("omitted — ") {
        return FormatCoverage::Omitted {
            reason: rest.1.trim().to_string(),
        };
    }
    if let Some(rest) = text.split_once("defer — ") {
        return FormatCoverage::Deferred {
            reason: rest.1.trim().to_string(),
        };
    }
    // Some doc rows use `defer until …` shorthand without an
    // explicit reason in em-dash form. Treat as Deferred for
    // classification purposes; reason is the trailing text.
    if let Some(rest) = text.split_once("defer until ") {
        return FormatCoverage::Deferred {
            reason: format!("until {}", rest.1.trim()),
        };
    }
    FormatCoverage::Present
}

/// Parse `docs/reference/sbom-format-mapping.md` into a
/// `Vec<CatalogRow>`. Returns rows in document order.
///
/// Recognizes any markdown table row whose first cell matches
/// the row-id pattern `^[A-H][0-9]+[a-z]?$`. Other rows
/// (header dividers, narrative text) are silently skipped.
pub fn parse_mapping_doc(markdown_path: &Path) -> Vec<CatalogRow> {
    let raw = std::fs::read_to_string(markdown_path)
        .unwrap_or_else(|e| panic!("read {}: {}", markdown_path.display(), e));
    parse_mapping_doc_str(&raw)
}

/// Same as [`parse_mapping_doc`] but consumes a string directly.
/// Useful for unit tests.
pub fn parse_mapping_doc_str(raw: &str) -> Vec<CatalogRow> {
    let row_id_re = regex::Regex::new(r"^[A-H][0-9]+[a-z]?$").expect("compile row-id regex");

    let mut rows = Vec::new();
    for line in raw.lines() {
        if !line.starts_with('|') {
            continue;
        }
        // Split into cells. A markdown table row of N cells has
        // N+2 split parts: leading "" + N cells + trailing "".
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 7 {
            // Need at least 5 content cells (id, label, cdx,
            // spdx23, spdx3) → 7 split parts.
            continue;
        }
        let id_cell = parts[1].trim();
        if !row_id_re.is_match(id_cell) {
            continue;
        }
        let section = id_cell
            .chars()
            .next()
            .expect("non-empty id matched the regex");
        rows.push(CatalogRow {
            id: id_cell.to_string(),
            label: parts[2].trim().to_string(),
            cdx_location: parts[3].trim().to_string(),
            spdx23_location: parts[4].trim().to_string(),
            spdx3_location: parts[5].trim().to_string(),
            section,
        });
    }
    rows
}

/// Extract the CycloneDX property/field name a catalog row
/// references, if extractable. Used by the US2 reverse check
/// (`mapping_doc_bidirectional.rs::reverse_every_universal_parity_row...`)
/// to assert every cataloged property name actually appears in
/// the emitted CDX output.
///
/// Returns `None` when:
/// * The CDX column carries `omitted —` or `defer —` (format-
///   restricted on CDX — there's nothing to verify).
/// * No name can be extracted (e.g., a relationship-row
///   pseudo-identifier like `/dependencies[]/dependsOn[]` — the
///   caller falls back to a different check for such rows).
///
/// Per research.md §R3, three patterns are tried in order:
/// 1. `name="([^"]+)"` over the column text — captures
///    `mikebom:source-type`, etc. for property rows.
/// 2. Trailing path segment after the final `/` — captures
///    `purl`, `version`, etc. for direct-JSON-path rows.
/// 3. None — caller falls back / skips.
pub fn extract_cdx_property_name_from_catalog_row(row: &CatalogRow) -> Option<String> {
    // Returns the trailing-most segment per the spec ("trailing
    // path segment after the final `/`"). The plural variant
    // [`extract_cdx_property_names_from_catalog_row`] returns
    // every recognized identifier and is what the bidirectional
    // auto-discovery test (US2 / T012) iterates over.
    extract_cdx_property_names_from_catalog_row(row)
        .into_iter()
        .last()
}

/// Same as [`extract_cdx_property_name_from_catalog_row`] but
/// returns *every* candidate identifier the row references in
/// the CDX format. Useful for the bidirectional auto-discovery
/// test (US2 / T012), which needs to honor "row covers any of
/// these emitted names" — e.g., E1's CDX cell
/// `` `/compositions[]` with `aggregate` + `assemblies/dependencies` ``
/// covers both `compositions` (the leaf path segment) and
/// `dependencies` (a sub-path segment). The forward direction
/// passes if ANY segment matches; the reverse direction passes
/// if ANY segment is emitted by some fixture.
pub fn extract_cdx_property_names_from_catalog_row(row: &CatalogRow) -> Vec<String> {
    if row.classification().cdx.is_restricted() {
        return Vec::new();
    }

    // Pattern 1 — explicit property name: `name="..."`. When
    // this fires, it IS the canonical row name; path-segment
    // matches under it (`components`, `properties`) are CDX
    // scaffolding emitted everywhere and are excluded.
    let property_re =
        regex::Regex::new(r#"name="([^"]+)""#).expect("compile property-name regex");
    let prop_matches: Vec<String> = property_re
        .captures_iter(&row.cdx_location)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect();
    if !prop_matches.is_empty() {
        let mut out: Vec<String> = Vec::new();
        for m in prop_matches {
            push_unique(&mut out, m);
        }
        return out;
    }

    // Pattern 2 — direct JSON paths: every path segment after
    // a `/`. The plural helper returns *all* segments so the
    // bidirectional auto-discovery test honors "row covers any
    // of these emitted names" (e.g., E1 covers both
    // `compositions` and `dependencies`); the singular helper
    // returns the trailing-most segment per the spec.
    let cdx_clean: String = row.cdx_location.replace('`', "");
    let path_re =
        regex::Regex::new(r"/([A-Za-z][A-Za-z0-9_]*)").expect("compile path-segment regex");
    let mut out: Vec<String> = Vec::new();
    for cap in path_re.captures_iter(&cdx_clean) {
        if let Some(m) = cap.get(1) {
            push_unique(&mut out, m.as_str().to_string());
        }
    }
    if !out.is_empty() {
        return out;
    }

    // Pattern 3 — fallback when the CDX cell is a generic
    // "property" / "metadata property" pointer (C19 / C22 / C23):
    // pull every backtick-wrapped identifier from the LABEL
    // column. Strip a trailing `-*` glob marker so e.g.
    // `` `mikebom:trace-integrity-*` `` returns the prefix
    // `mikebom:trace-integrity-` (caller's responsibility to
    // `starts_with`-match for the C23 multi-subkey case).
    let label_re =
        regex::Regex::new(r"`([^`]+)`").expect("compile label-backtick regex");
    for cap in label_re.captures_iter(&row.label) {
        if let Some(m) = cap.get(1) {
            push_unique(&mut out, m.as_str().trim_end_matches('*').to_string());
        }
    }

    out
}

fn push_unique(out: &mut Vec<String>, item: String) {
    if !out.contains(&item) {
        out.push(item);
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn classify_present_row() {
        let cov = classify_column("`/components/{i}/purl`");
        assert!(matches!(cov, FormatCoverage::Present));
    }

    #[test]
    fn classify_omitted_row() {
        let cov = classify_column("omitted — mikebom resolution layer doesn't surface originator");
        match cov {
            FormatCoverage::Omitted { reason } => {
                assert!(reason.starts_with("mikebom resolution layer"));
            }
            other => panic!("expected Omitted, got {other:?}"),
        }
    }

    #[test]
    fn classify_deferred_row() {
        let cov = classify_column("defer — pending SPDX 3 evidence profile");
        match cov {
            FormatCoverage::Deferred { reason } => {
                assert_eq!(reason, "pending SPDX 3 evidence profile");
            }
            other => panic!("expected Deferred, got {other:?}"),
        }
    }

    #[test]
    fn classify_defer_until_shorthand() {
        let cov = classify_column("defer until SPDX 3.x evidence profile stabilizes");
        assert!(matches!(cov, FormatCoverage::Deferred { .. }));
    }

    #[test]
    fn parse_real_mapping_doc_finds_rows() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("docs/reference/sbom-format-mapping.md");
        let rows = parse_mapping_doc(&path);
        // We expect ~45 rows across sections A–H. Loose lower
        // bound check guards against parser regressions without
        // pinning an exact count (the doc evolves milestone-to-
        // milestone).
        assert!(
            rows.len() >= 30,
            "expected ≥30 catalog rows, got {}: {:?}",
            rows.len(),
            rows.iter().map(|r| &r.id).collect::<Vec<_>>(),
        );
        // Section coverage sanity: A and B exist (core identity
        // + graph structure are always present).
        assert!(rows.iter().any(|r| r.id == "A1"));
        assert!(rows.iter().any(|r| r.id == "B1"));
    }

    #[test]
    fn classification_is_universal_parity_only_when_all_three_present() {
        let row = CatalogRow {
            id: "T001".into(),
            label: "test".into(),
            cdx_location: "/components/{i}/foo".into(),
            spdx23_location: "/packages/{i}/bar".into(),
            spdx3_location: "software_Package/baz".into(),
            section: 'A',
        };
        assert!(row.classification().is_universal_parity());

        let row_restricted = CatalogRow {
            id: "T002".into(),
            label: "test".into(),
            cdx_location: "/components/{i}/foo".into(),
            spdx23_location: "omitted — no analogue".into(),
            spdx3_location: "software_Package/baz".into(),
            section: 'A',
        };
        assert!(!row_restricted.classification().is_universal_parity());
        assert!(row_restricted.classification().is_checked(Format::Cdx));
        assert!(!row_restricted.classification().is_checked(Format::Spdx23));
        assert!(row_restricted.classification().is_checked(Format::Spdx3));
    }

    #[test]
    fn extract_cdx_property_name_property_pattern() {
        let row = CatalogRow {
            id: "C1".into(),
            label: "mikebom:source-type".into(),
            cdx_location: r#"`/components/{i}/properties[name="mikebom:source-type"]`"#.into(),
            spdx23_location: "Annotation `mikebom:source-type`".into(),
            spdx3_location: "Annotation `mikebom:source-type`".into(),
            section: 'C',
        };
        assert_eq!(
            extract_cdx_property_name_from_catalog_row(&row).as_deref(),
            Some("mikebom:source-type"),
        );
    }

    #[test]
    fn extract_cdx_property_name_direct_path() {
        let row = CatalogRow {
            id: "A1".into(),
            label: "PURL".into(),
            cdx_location: "`/components/{i}/purl`".into(),
            spdx23_location: "...".into(),
            spdx3_location: "...".into(),
            section: 'A',
        };
        assert_eq!(
            extract_cdx_property_name_from_catalog_row(&row).as_deref(),
            Some("purl"),
        );
    }

    #[test]
    fn real_doc_e1_candidates_include_compositions() {
        // E1 cdx_location is
        // `` `/compositions[]` with `aggregate` + `assemblies/dependencies` ``
        // — pattern 2 picks up *every* path segment, so the
        // candidate list contains both `compositions` and
        // `dependencies`. The bidirectional reverse check (US2)
        // matches against ANY candidate, so this row passes as
        // long as at least one candidate is emitted by the
        // fixture set.
        let p = std::path::PathBuf::from(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/reference/sbom-format-mapping.md"),
        );
        let rows = parse_mapping_doc(&p);
        let e1 = rows.iter().find(|r| r.id == "E1").expect("E1 parses");
        let candidates = extract_cdx_property_names_from_catalog_row(e1);
        assert!(
            candidates.iter().any(|c| c == "compositions"),
            "expected `compositions` in candidates {candidates:?}"
        );
    }

    #[test]
    fn real_doc_c19_is_extracted_as_mikebom_cpe_candidates() {
        let p = std::path::PathBuf::from(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/reference/sbom-format-mapping.md"),
        );
        let rows = parse_mapping_doc(&p);
        let c19 = rows.iter().find(|r| r.id == "C19").expect("C19 parses");
        let name = extract_cdx_property_name_from_catalog_row(c19);
        assert_eq!(
            name.as_deref(),
            Some("mikebom:cpe-candidates"),
            "C19 cdx_location={:?} label={:?}",
            c19.cdx_location,
            c19.label,
        );
    }

    #[test]
    fn extract_cdx_property_name_label_fallback() {
        // C19 / C22 / C23 in the real mapping doc have CDX cell
        // text "property" / "metadata property" without an inline
        // `name="..."` form — the canonical name lives only in
        // the LABEL column. Pattern 3 must extract it.
        let row = CatalogRow {
            id: "C19".into(),
            label: "`mikebom:cpe-candidates`".into(),
            cdx_location: "property".into(),
            spdx23_location: "Annotation `mikebom:cpe-candidates`".into(),
            spdx3_location: "Annotation `mikebom:cpe-candidates`".into(),
            section: 'C',
        };
        assert_eq!(
            extract_cdx_property_name_from_catalog_row(&row).as_deref(),
            Some("mikebom:cpe-candidates"),
        );
    }

    #[test]
    fn extract_cdx_property_name_omitted_returns_none() {
        let row = CatalogRow {
            id: "X1".into(),
            label: "test".into(),
            cdx_location: "omitted — no CDX analogue".into(),
            spdx23_location: "...".into(),
            spdx3_location: "...".into(),
            section: 'A',
        };
        assert_eq!(extract_cdx_property_name_from_catalog_row(&row), None);
    }
}
