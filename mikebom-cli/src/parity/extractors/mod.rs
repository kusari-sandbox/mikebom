//! Per-catalog-row extractor table (milestone 013 T004–T009).
//!
//! One entry per `CatalogRow` whose Classification has at least
//! one Present format. Each entry carries three extractor
//! closures (CDX, SPDX 2.3, SPDX 3) returning the normalized set
//! of "observable values" for that datum in the format's output,
//! plus a `Directionality` flag (SymmetricEqual vs.
//! CdxSubsetOfSpdx).
//!
//! When a new catalog row lands in `docs/reference/sbom-format-mapping.md`,
//! a corresponding entry MUST be added to [`EXTRACTORS`] —
//! `every_catalog_row_has_an_extractor` (in tests) fires
//! otherwise. Per spec FR-005a / clarification Q2: the catalog
//! is the source of truth; the extractor table is the executable
//! interpretation; mismatches surface at the pre-PR gate.

mod cdx;
mod common;
mod spdx2;
mod spdx3;

pub use common::{
    extract_mikebom_annotation_values, walk_cdx_components, walk_spdx23_packages,
    walk_spdx3_packages, Directionality, ParityExtractor,
};

use cdx::{
    c10_cdx, c11_cdx, c12_cdx, c13_cdx, c14_cdx, c15_cdx, c16_cdx, c17_cdx, c18_cdx, c19_cdx,
    c1_cdx, c20_cdx, c21_cdx, c22_cdx, c23_cdx, c24_cdx, c25_cdx, c26_cdx, c27_cdx, c28_cdx,
    c29_cdx, c2_cdx, c30_cdx, c31_cdx, c32_cdx, c3_cdx, c4_cdx, c5_cdx, c6_cdx, c7_cdx, c8_cdx,
    c9_cdx, cdx_containment, cdx_cpe, cdx_dev_deps, cdx_distribution, cdx_hashes, cdx_homepage,
    cdx_licenses_concluded, cdx_licenses_declared, cdx_name, cdx_purl, cdx_root, cdx_runtime_deps,
    cdx_supplier, cdx_vcs, cdx_version, d1_cdx, d2_cdx, e1_cdx, f1_cdx, g1_cdx,
};
use common::empty;
use spdx2::{
    c10_spdx23, c11_spdx23, c12_spdx23, c13_spdx23, c14_spdx23, c15_spdx23, c16_spdx23,
    c17_spdx23, c18_spdx23, c19_spdx23, c1_spdx23, c20_spdx23, c21_spdx23, c22_spdx23,
    c23_spdx23, c24_spdx23, c25_spdx23, c26_spdx23, c27_spdx23, c28_spdx23, c29_spdx23, c2_spdx23,
    c30_spdx23, c31_spdx23, c32_spdx23, c3_spdx23, c4_spdx23, c5_spdx23, c6_spdx23, c7_spdx23,
    c8_spdx23, c9_spdx23, d1_spdx23, d2_spdx23, e1_spdx23, f1_spdx23, g1_spdx23,
    spdx23_containment, spdx23_cpe, spdx23_dev_deps, spdx23_distribution, spdx23_hashes,
    spdx23_homepage, spdx23_licenses_concluded, spdx23_licenses_declared, spdx23_name,
    spdx23_purl, spdx23_root, spdx23_runtime_deps, spdx23_supplier, spdx23_vcs, spdx23_version,
};
use spdx3::{
    c10_spdx3, c11_spdx3, c12_spdx3, c13_spdx3, c14_spdx3, c15_spdx3, c16_spdx3, c17_spdx3,
    c18_spdx3, c19_spdx3, c1_spdx3, c20_spdx3, c21_spdx3, c22_spdx3, c23_spdx3, c24_spdx3,
    c25_spdx3, c26_spdx3, c27_spdx3, c28_spdx3, c29_spdx3, c2_spdx3, c30_spdx3, c31_spdx3,
    c32_spdx3, c3_spdx3, c4_spdx3, c5_spdx3, c6_spdx3, c7_spdx3, c8_spdx3, c9_spdx3, d1_spdx3,
    d2_spdx3, e1_spdx3, f1_spdx3, g1_spdx3, spdx3_containment, spdx3_cpe, spdx3_dev_deps,
    spdx3_distribution, spdx3_hashes, spdx3_homepage, spdx3_licenses_concluded,
    spdx3_licenses_declared, spdx3_name, spdx3_purl, spdx3_root, spdx3_runtime_deps,
    spdx3_supplier, spdx3_vcs, spdx3_version,
};

// All extractor functions live in the per-format submodules
// (cdx.rs / spdx2.rs / spdx3.rs) as of milestone 022. mod.rs
// owns only the `EXTRACTORS` table that wires them together,
// the public re-exports (above), and the structural tests
// (below). The G/H rows that don't have format-specific business
// logic route through `common::empty` (was `g_empty` pre-022;
// collapsed since the two sentinels did the same thing).

// ============================================================
// EXTRACTORS table — keyed by row id, sorted alphabetically.
// ============================================================

pub static EXTRACTORS: &[ParityExtractor] = &[
    // Section A — Core identity
    ParityExtractor { row_id: "A1",  label: "PURL",                    cdx: cdx_purl,        spdx23: spdx23_purl,        spdx3: spdx3_purl,        directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "A2",  label: "name",                    cdx: cdx_name,        spdx23: spdx23_name,        spdx3: spdx3_name,        directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "A3",  label: "version",                 cdx: cdx_version,     spdx23: spdx23_version,     spdx3: spdx3_version,     directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "A4",  label: "supplier",                cdx: cdx_supplier,    spdx23: spdx23_supplier,    spdx3: spdx3_supplier,    directional: Directionality::SymmetricEqual },
    // A5 author — format-restricted on all three (mikebom doesn't
    // surface originator yet); empty extractors.
    ParityExtractor { row_id: "A5",  label: "author",                  cdx: empty,           spdx23: empty,              spdx3: empty,             directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "A6",  label: "hashes",                  cdx: cdx_hashes,      spdx23: spdx23_hashes,      spdx3: spdx3_hashes,      directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "A7",  label: "license — declared",      cdx: cdx_licenses_declared,  spdx23: spdx23_licenses_declared,  spdx3: spdx3_licenses_declared,  directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "A8",  label: "license — concluded",     cdx: cdx_licenses_concluded, spdx23: spdx23_licenses_concluded, spdx3: spdx3_licenses_concluded, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "A9",  label: "external ref — homepage", cdx: cdx_homepage,    spdx23: spdx23_homepage,    spdx3: spdx3_homepage,    directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "A10", label: "external ref — VCS",      cdx: cdx_vcs,         spdx23: spdx23_vcs,         spdx3: spdx3_vcs,         directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "A11", label: "external ref — distribution", cdx: cdx_distribution, spdx23: spdx23_distribution, spdx3: spdx3_distribution, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "A12", label: "CPE",                     cdx: cdx_cpe,         spdx23: spdx23_cpe,         spdx3: spdx3_cpe,         directional: Directionality::CdxSubsetOfSpdx },
    // Section B — Graph structure
    ParityExtractor { row_id: "B1",  label: "dependency edge (runtime)", cdx: cdx_runtime_deps, spdx23: spdx23_runtime_deps, spdx3: spdx3_runtime_deps, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "B2",  label: "dependency edge (dev)",   cdx: cdx_dev_deps,    spdx23: spdx23_dev_deps,    spdx3: spdx3_dev_deps,    directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "B3",  label: "nested containment",      cdx: cdx_containment, spdx23: spdx23_containment, spdx3: spdx3_containment, directional: Directionality::SymmetricEqual },
    // B4 image/filesystem root: each format encodes the root
    // PURL with format-specific name-sanitization (CDX preserves
    // the raw image tag `mikebom-perf:latest@0.0.0`; SPDX 2.3
    // substitutes `:` → `_` per SPDXID rules; SPDX 3 substitutes
    // `:` → `-` per the stricter Element-name rules). The root
    // concept is the same datum across formats — presence-only
    // enforcement.
    ParityExtractor { row_id: "B4",  label: "image / filesystem root", cdx: cdx_root,        spdx23: spdx23_root,        spdx3: spdx3_root,        directional: Directionality::PresenceOnly },
    // Section C — mikebom-specific annotations
    ParityExtractor { row_id: "C1",  label: "mikebom:source-type",     cdx: c1_cdx,  spdx23: c1_spdx23,  spdx3: c1_spdx3,  directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C2",  label: "mikebom:source-connection-ids", cdx: c2_cdx,  spdx23: c2_spdx23,  spdx3: c2_spdx3,  directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C3",  label: "mikebom:deps-dev-match",  cdx: c3_cdx,  spdx23: c3_spdx23,  spdx3: c3_spdx3,  directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C4",  label: "mikebom:evidence-kind",   cdx: c4_cdx,  spdx23: c4_spdx23,  spdx3: c4_spdx3,  directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C5",  label: "mikebom:sbom-tier",       cdx: c5_cdx,  spdx23: c5_spdx23,  spdx3: c5_spdx3,  directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C6",  label: "mikebom:dev-dependency",  cdx: c6_cdx,  spdx23: c6_spdx23,  spdx3: c6_spdx3,  directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C7",  label: "mikebom:co-owned-by",     cdx: c7_cdx,  spdx23: c7_spdx23,  spdx3: c7_spdx3,  directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C8",  label: "mikebom:shade-relocation", cdx: c8_cdx, spdx23: c8_spdx23, spdx3: c8_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C9",  label: "mikebom:npm-role",        cdx: c9_cdx,  spdx23: c9_spdx23,  spdx3: c9_spdx3,  directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C10", label: "mikebom:binary-class",    cdx: c10_cdx, spdx23: c10_spdx23, spdx3: c10_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C11", label: "mikebom:binary-stripped", cdx: c11_cdx, spdx23: c11_spdx23, spdx3: c11_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C12", label: "mikebom:linkage-kind",    cdx: c12_cdx, spdx23: c12_spdx23, spdx3: c12_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C13", label: "mikebom:buildinfo-status", cdx: c13_cdx, spdx23: c13_spdx23, spdx3: c13_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C14", label: "mikebom:detected-go",     cdx: c14_cdx, spdx23: c14_spdx23, spdx3: c14_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C15", label: "mikebom:binary-packed",   cdx: c15_cdx, spdx23: c15_spdx23, spdx3: c15_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C16", label: "mikebom:confidence",      cdx: c16_cdx, spdx23: c16_spdx23, spdx3: c16_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C17", label: "mikebom:raw-version",     cdx: c17_cdx, spdx23: c17_spdx23, spdx3: c17_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C18", label: "mikebom:source-files",    cdx: c18_cdx, spdx23: c18_spdx23, spdx3: c18_spdx3, directional: Directionality::SymmetricEqual },
    // C19 cpe-candidates: CDX serializes the candidates as a
    // pipe-separated single-property string with single-backslash
    // PURL-escapes (`github.com\/foo`); SPDX serializes as an
    // array-valued envelope with double-backslash escapes
    // (`github.com\\\\/foo` in the wire form). The atomic CPEs
    // are the same datum but the per-format escape conventions
    // differ; presence-only enforcement keeps the parity check
    // honest about the shared emission across formats without
    // tripping on the cosmetic escaping difference.
    ParityExtractor { row_id: "C19", label: "mikebom:cpe-candidates",  cdx: c19_cdx, spdx23: c19_spdx23, spdx3: c19_spdx3, directional: Directionality::PresenceOnly },
    ParityExtractor { row_id: "C20", label: "mikebom:requirement-range", cdx: c20_cdx, spdx23: c20_spdx23, spdx3: c20_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C21", label: "mikebom:generation-context", cdx: c21_cdx, spdx23: c21_spdx23, spdx3: c21_spdx3, directional: Directionality::SymmetricEqual },
    // C22: CDX serializes the missing-field set as a comma-joined
    // string property; SPDX serializes as an annotation with a
    // real JSON-array-valued envelope. The atomic atoms differ —
    // CDX cannot losslessly emit a JSON array via a property's
    // `value` (CDX 1.6 properties are stringly-typed). Both carry
    // the same datum; presence-only enforcement reflects the
    // shape gap.
    ParityExtractor { row_id: "C22", label: "mikebom:os-release-missing-fields", cdx: c22_cdx, spdx23: c22_spdx23, spdx3: c22_spdx3, directional: Directionality::PresenceOnly },
    ParityExtractor { row_id: "C23", label: "mikebom:trace-integrity-*", cdx: c23_cdx, spdx23: c23_spdx23, spdx3: c23_spdx3, directional: Directionality::SymmetricEqual },
    // Section C continued — milestone 023 ELF identity (CDX/SPDX
    // emitted via the extra_annotations bag in entry.rs::make_file_level_component;
    // catalog rows defined in docs/reference/sbom-format-mapping.md C24-C26).
    ParityExtractor { row_id: "C24", label: "mikebom:elf-build-id",      cdx: c24_cdx, spdx23: c24_spdx23, spdx3: c24_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C25", label: "mikebom:elf-runpath",       cdx: c25_cdx, spdx23: c25_spdx23, spdx3: c25_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C26", label: "mikebom:elf-debuglink",     cdx: c26_cdx, spdx23: c26_spdx23, spdx3: c26_spdx3, directional: Directionality::SymmetricEqual },
    // Section C continued — milestone 025 Go VCS metadata (CDX/SPDX
    // emitted via the extra_annotations bag in
    // go_binary.rs::build_vcs_annotations on the main-module entry
    // only; catalog rows in docs/reference/sbom-format-mapping.md C27-C29).
    ParityExtractor { row_id: "C27", label: "mikebom:go-vcs-revision",   cdx: c27_cdx, spdx23: c27_spdx23, spdx3: c27_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C28", label: "mikebom:go-vcs-time",       cdx: c28_cdx, spdx23: c28_spdx23, spdx3: c28_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C29", label: "mikebom:go-vcs-modified",   cdx: c29_cdx, spdx23: c29_spdx23, spdx3: c29_spdx3, directional: Directionality::SymmetricEqual },
    // C30-C32 — Mach-O binary identity (milestone 024). Emitted via
    // the extra_annotations bag in
    // binary/entry.rs::build_macho_identity_annotations on the
    // file-level Mach-O component; catalog rows in
    // docs/reference/sbom-format-mapping.md C30-C32).
    ParityExtractor { row_id: "C30", label: "mikebom:macho-uuid",        cdx: c30_cdx, spdx23: c30_spdx23, spdx3: c30_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C31", label: "mikebom:macho-rpath",       cdx: c31_cdx, spdx23: c31_spdx23, spdx3: c31_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "C32", label: "mikebom:macho-min-os",      cdx: c32_cdx, spdx23: c32_spdx23, spdx3: c32_spdx3, directional: Directionality::SymmetricEqual },
    // Section D — Evidence
    // D1 evidence shape diverges — CDX `evidence.identity[].{field,
    // confidence, methods[]}` is the full CDX evidence model;
    // SPDX condenses to flat `{technique, confidence}`. The
    // `technique` strings can even differ (CDX names the concrete
    // method; SPDX uses the higher-level evidence type).
    // Presence-only.
    ParityExtractor { row_id: "D1",  label: "evidence — identity",     cdx: d1_cdx, spdx23: d1_spdx23, spdx3: d1_spdx3, directional: Directionality::PresenceOnly },
    ParityExtractor { row_id: "D2",  label: "evidence — occurrences",  cdx: d2_cdx, spdx23: d2_spdx23, spdx3: d2_spdx3, directional: Directionality::SymmetricEqual },
    // Section E — Compositions
    // E1 compositions: CDX preserves the full CDX-native
    // compositions[] array verbatim; SPDX uses a condensed
    // `{complete_ecosystems: [...]}` annotation per the catalog
    // doc. The shapes irreconcilably diverge; presence-only.
    ParityExtractor { row_id: "E1",  label: "ecosystem completeness",  cdx: e1_cdx, spdx23: e1_spdx23, spdx3: e1_spdx3, directional: Directionality::PresenceOnly },
    // Section F — VEX
    ParityExtractor { row_id: "F1",  label: "vulnerabilities (VEX)",   cdx: f1_cdx, spdx23: f1_spdx23, spdx3: f1_spdx3, directional: Directionality::SymmetricEqual },
    // Section G — Document envelope (mostly format-shape)
    ParityExtractor { row_id: "G1",  label: "tool name + version",     cdx: g1_cdx, spdx23: g1_spdx23, spdx3: g1_spdx3, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "G2",  label: "created timestamp",       cdx: empty, spdx23: empty, spdx3: empty, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "G3",  label: "data license",            cdx: empty, spdx23: empty, spdx3: empty, directional: Directionality::SymmetricEqual },
    ParityExtractor { row_id: "G4",  label: "document namespace",      cdx: empty, spdx23: empty, spdx3: empty, directional: Directionality::SymmetricEqual },
    // Section H — Structural-difference meta-rows
    ParityExtractor { row_id: "H1",  label: "nested vs. flat",         cdx: empty, spdx23: empty, spdx3: empty, directional: Directionality::SymmetricEqual },
];

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn extractors_table_is_sorted_by_row_id() {
        let mut last: Option<&str> = None;
        for e in EXTRACTORS {
            if let Some(prev) = last {
                assert!(
                    natural_compare(prev, e.row_id),
                    "EXTRACTORS not sorted: {prev} >= {}",
                    e.row_id
                );
            }
            last = Some(e.row_id);
        }
    }

    /// Compare row IDs naturally — A1 < A2 < ... < A12 < B1.
    fn natural_compare(a: &str, b: &str) -> bool {
        let (a_section, a_num) = split_id(a);
        let (b_section, b_num) = split_id(b);
        match a_section.cmp(&b_section) {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => a_num < b_num,
        }
    }
    fn split_id(id: &str) -> (char, u32) {
        let section = id.chars().next().unwrap();
        let num: u32 = id[1..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .unwrap_or(0);
        (section, num)
    }

    #[test]
    fn every_catalog_row_has_an_extractor() {
        let mapping_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("docs/reference/sbom-format-mapping.md");
        let rows = super::super::catalog::parse_mapping_doc(&mapping_path);
        let extractor_ids: std::collections::BTreeSet<&str> =
            EXTRACTORS.iter().map(|e| e.row_id).collect();
        let missing: Vec<&str> = rows
            .iter()
            .map(|r| r.id.as_str())
            .filter(|id| !extractor_ids.contains(id))
            .collect();
        assert!(
            missing.is_empty(),
            "catalog rows without extractors: {missing:?}"
        );
        let row_ids: std::collections::BTreeSet<&str> =
            rows.iter().map(|r| r.id.as_str()).collect();
        let orphans: Vec<&str> = EXTRACTORS
            .iter()
            .map(|e| e.row_id)
            .filter(|id| !row_ids.contains(id))
            .collect();
        assert!(
            orphans.is_empty(),
            "EXTRACTORS entries without catalog rows: {orphans:?}"
        );
    }
}
