//! SPDX 3.0.1-side parity extractors (milestone 022 commit 4).
//!
//! Mirrors `extractors/cdx.rs` and `extractors/spdx2.rs` but for
//! SPDX 3.0.1 graph shape (`@graph[]` of typed elements, IRI-keyed
//! relationships). Owns every `spdx3_*` and `c*_spdx3` /
//! `d*_spdx3` / `e*_spdx3` / `f*_spdx3` / `g*_spdx3` extractor
//! function referenced by `EXTRACTORS` in `super::mod`.

use std::collections::BTreeSet;

use serde_json::Value;

use super::common::{
    decode_envelope, extract_mikebom_annotation_values, normalize_alg, spdx_relationship_edges,
    walk_spdx3_packages,
};

/// Single-format SPDX 3 C-section stub generator.
macro_rules! spdx3_anno {
    ($name:ident, $field:literal, component) => {
        pub(super) fn $name(doc: &Value) -> BTreeSet<String> {
            extract_mikebom_annotation_values(doc, $field, false)
        }
    };
    ($name:ident, $field:literal, document) => {
        pub(super) fn $name(doc: &Value) -> BTreeSet<String> {
            extract_mikebom_annotation_values(doc, $field, true)
        }
    };
}

// ============================================================
// Section A — Core identity (A1-A12)
// ============================================================

pub(super) fn spdx3_purl(doc: &Value) -> BTreeSet<String> {
    walk_spdx3_packages(doc)
        .iter()
        .filter_map(|p| {
            p.get("software_packageUrl")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect()
}

pub(super) fn spdx3_name(doc: &Value) -> BTreeSet<String> {
    walk_spdx3_packages(doc)
        .iter()
        .filter_map(|p| p.get("name").and_then(|v| v.as_str()).map(String::from))
        .collect()
}

pub(super) fn spdx3_version(doc: &Value) -> BTreeSet<String> {
    walk_spdx3_packages(doc)
        .iter()
        .filter_map(|p| {
            p.get("software_packageVersion")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect()
}

pub(super) fn spdx3_hashes(doc: &Value) -> BTreeSet<String> {
    walk_spdx3_packages(doc)
        .iter()
        .flat_map(|p| {
            p.get("verifiedUsing")
                .and_then(|v| v.as_array())
                .map(|arr| arr.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter_map(|h| {
                    let alg = h.get("algorithm").and_then(|v| v.as_str())?;
                    let val = h.get("hashValue").and_then(|v| v.as_str())?;
                    Some(format!("{}:{}", normalize_alg(alg), val))
                })
        })
        .collect()
}

pub(super) fn spdx3_homepage(doc: &Value) -> BTreeSet<String> {
    walk_spdx3_packages(doc)
        .iter()
        .filter_map(|p| {
            p.get("software_homePage")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect()
}
pub(super) fn spdx3_vcs(doc: &Value) -> BTreeSet<String> {
    walk_spdx3_packages(doc)
        .iter()
        .filter_map(|p| {
            p.get("software_sourceInfo")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect()
}
pub(super) fn spdx3_distribution(doc: &Value) -> BTreeSet<String> {
    walk_spdx3_packages(doc)
        .iter()
        .filter_map(|p| {
            p.get("software_downloadLocation")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect()
}

pub(super) fn spdx3_cpe(doc: &Value) -> BTreeSet<String> {
    walk_spdx3_packages(doc)
        .iter()
        .flat_map(|p| {
            p.get("externalIdentifier")
                .and_then(|v| v.as_array())
                .map(|arr| arr.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|e| {
                    e.get("externalIdentifierType").and_then(|v| v.as_str()) == Some("cpe23")
                })
                .filter_map(|e| {
                    e.get("identifier")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
        })
        .collect()
}

// SPDX 3 walks simplelicensing_LicenseExpression elements + their
// hasDeclared/hasConcludedLicense Relationships.
fn spdx3_license_expressions_by_relationship(
    doc: &Value,
    rel_type: &str,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return out;
    };
    let mut expr_by_iri = std::collections::BTreeMap::new();
    for el in graph {
        if el.get("type").and_then(|v| v.as_str())
            == Some("simplelicensing_LicenseExpression")
        {
            if let (Some(id), Some(expr)) = (
                el.get("spdxId").and_then(|v| v.as_str()),
                el.get("simplelicensing_licenseExpression")
                    .and_then(|v| v.as_str()),
            ) {
                expr_by_iri.insert(id.to_string(), expr.to_string());
            }
        }
    }
    for el in graph {
        if el.get("type").and_then(|v| v.as_str()) != Some("Relationship") {
            continue;
        }
        if el.get("relationshipType").and_then(|v| v.as_str()) != Some(rel_type) {
            continue;
        }
        let Some(targets) = el.get("to").and_then(|v| v.as_array()) else {
            continue;
        };
        for t in targets {
            if let Some(iri) = t.as_str() {
                if let Some(expr) = expr_by_iri.get(iri) {
                    out.insert(expr.clone());
                }
            }
        }
    }
    out
}
pub(super) fn spdx3_licenses_declared(doc: &Value) -> BTreeSet<String> {
    spdx3_license_expressions_by_relationship(doc, "hasDeclaredLicense")
}
pub(super) fn spdx3_licenses_concluded(doc: &Value) -> BTreeSet<String> {
    spdx3_license_expressions_by_relationship(doc, "hasConcludedLicense")
}

pub(super) fn spdx3_supplier(doc: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return out;
    };
    let mut name_by_iri = std::collections::BTreeMap::new();
    for el in graph {
        if matches!(
            el.get("type").and_then(|v| v.as_str()),
            Some("Organization") | Some("Person")
        ) {
            if let (Some(id), Some(name)) = (
                el.get("spdxId").and_then(|v| v.as_str()),
                el.get("name").and_then(|v| v.as_str()),
            ) {
                name_by_iri.insert(id.to_string(), name.to_string());
            }
        }
    }
    for p in walk_spdx3_packages(doc) {
        if let Some(iri) = p.get("suppliedBy").and_then(|v| v.as_str()) {
            if let Some(name) = name_by_iri.get(iri) {
                out.insert(name.clone());
            }
        }
    }
    out
}

// ============================================================
// Section B — Graph structure (B1-B4)
// ============================================================

pub(super) fn spdx3_runtime_deps(doc: &Value) -> BTreeSet<String> {
    spdx_relationship_edges(doc, "", "dependsOn")
}

// SPDX 3 lacks `devDependencyOf`; the C6 annotation carries the
// dev-vs-runtime distinction (mapping doc B2). The extractor walks
// `dependsOn` edges and filters by C6 annotation on the source
// Package.
pub(super) fn spdx3_dev_deps(doc: &Value) -> BTreeSet<String> {
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return BTreeSet::new();
    };
    let mut purl_by_iri: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for el in graph {
        if el.get("type").and_then(|v| v.as_str()) == Some("software_Package") {
            if let (Some(iri), Some(purl)) = (
                el.get("spdxId").and_then(|v| v.as_str()),
                el.get("software_packageUrl").and_then(|v| v.as_str()),
            ) {
                purl_by_iri.insert(iri.to_string(), purl.to_string());
            }
        }
    }
    // Set of IRIs whose C6 annotation marks them dev.
    let mut dev_iris: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for el in graph {
        if el.get("type").and_then(|v| v.as_str()) != Some("Annotation") {
            continue;
        }
        let Some(subject) = el.get("subject").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(stmt) = el.get("statement").and_then(|v| v.as_str()) else {
            continue;
        };
        if let Some(values) = decode_envelope(stmt, "mikebom:dev-dependency") {
            if values.iter().any(|v| v == "true" || v == "\"true\"") {
                dev_iris.insert(subject.to_string());
            }
        }
    }
    let mut out = BTreeSet::new();
    for el in graph {
        if el.get("type").and_then(|v| v.as_str()) != Some("Relationship") {
            continue;
        }
        if el.get("relationshipType").and_then(|v| v.as_str()) != Some("dependsOn") {
            continue;
        }
        let Some(from) = el.get("from").and_then(|v| v.as_str()) else {
            continue;
        };
        if !dev_iris.contains(from) {
            continue;
        }
        let Some(to_arr) = el.get("to").and_then(|v| v.as_array()) else {
            continue;
        };
        let Some(from_purl) = purl_by_iri.get(from) else {
            continue;
        };
        for t in to_arr {
            if let Some(t_iri) = t.as_str() {
                if let Some(to_purl) = purl_by_iri.get(t_iri) {
                    out.insert(format!("{from_purl}->{to_purl}"));
                }
            }
        }
    }
    out
}

pub(super) fn spdx3_containment(doc: &Value) -> BTreeSet<String> {
    spdx_relationship_edges(doc, "", "contains")
}

pub(super) fn spdx3_root(doc: &Value) -> BTreeSet<String> {
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return BTreeSet::new();
    };
    let mut purl_by_iri: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for el in graph {
        if el.get("type").and_then(|v| v.as_str()) == Some("software_Package") {
            if let (Some(iri), Some(purl)) = (
                el.get("spdxId").and_then(|v| v.as_str()),
                el.get("software_packageUrl").and_then(|v| v.as_str()),
            ) {
                purl_by_iri.insert(iri.to_string(), purl.to_string());
            }
        }
    }
    let mut out = BTreeSet::new();
    for el in graph {
        if el.get("type").and_then(|v| v.as_str()) != Some("SpdxDocument") {
            continue;
        }
        let Some(roots) = el.get("rootElement").and_then(|v| v.as_array()) else {
            continue;
        };
        for r in roots {
            if let Some(iri) = r.as_str() {
                if let Some(purl) = purl_by_iri.get(iri) {
                    out.insert(purl.clone());
                }
            }
        }
    }
    out
}

// ============================================================
// Section C — annotation stubs (C1-C23 SPDX 3 side)
// ============================================================

spdx3_anno!(c1_spdx3, "mikebom:source-type", component);
spdx3_anno!(c2_spdx3, "mikebom:source-connection-ids", component);
spdx3_anno!(c3_spdx3, "mikebom:deps-dev-match", component);
spdx3_anno!(c4_spdx3, "mikebom:evidence-kind", component);
spdx3_anno!(c5_spdx3, "mikebom:sbom-tier", component);
spdx3_anno!(c6_spdx3, "mikebom:dev-dependency", component);
spdx3_anno!(c7_spdx3, "mikebom:co-owned-by", component);
spdx3_anno!(c8_spdx3, "mikebom:shade-relocation", component);
spdx3_anno!(c9_spdx3, "mikebom:npm-role", component);
spdx3_anno!(c10_spdx3, "mikebom:binary-class", component);
spdx3_anno!(c11_spdx3, "mikebom:binary-stripped", component);
spdx3_anno!(c12_spdx3, "mikebom:linkage-kind", component);
spdx3_anno!(c13_spdx3, "mikebom:buildinfo-status", component);
spdx3_anno!(c14_spdx3, "mikebom:detected-go", component);
spdx3_anno!(c15_spdx3, "mikebom:binary-packed", component);
spdx3_anno!(c16_spdx3, "mikebom:confidence", component);
spdx3_anno!(c17_spdx3, "mikebom:raw-version", component);
spdx3_anno!(c18_spdx3, "mikebom:source-files", component);
spdx3_anno!(c19_spdx3, "mikebom:cpe-candidates", component);
spdx3_anno!(c20_spdx3, "mikebom:requirement-range", component);
spdx3_anno!(c21_spdx3, "mikebom:generation-context", document);
spdx3_anno!(c22_spdx3, "mikebom:os-release-missing-fields", document);
spdx3_anno!(c23_spdx3, "mikebom:trace-integrity-ring-buffer-overflows", document);

// C24-C26 (milestone 023 — ELF identity, surfaced via the
// extra_annotations bag in entry.rs::make_file_level_component).
spdx3_anno!(c24_spdx3, "mikebom:elf-build-id", component);
spdx3_anno!(c25_spdx3, "mikebom:elf-runpath", component);
spdx3_anno!(c26_spdx3, "mikebom:elf-debuglink", component);

// C27-C29 (milestone 025 — Go VCS metadata).
spdx3_anno!(c27_spdx3, "mikebom:go-vcs-revision", component);
spdx3_anno!(c28_spdx3, "mikebom:go-vcs-time", component);
spdx3_anno!(c29_spdx3, "mikebom:go-vcs-modified", component);

// C30-C32 (milestone 024 — Mach-O binary identity).
spdx3_anno!(c30_spdx3, "mikebom:macho-uuid", component);
spdx3_anno!(c31_spdx3, "mikebom:macho-rpath", component);
spdx3_anno!(c32_spdx3, "mikebom:macho-min-os", component);

// ============================================================
// Sections D-G — custom SPDX 3 extractors
// ============================================================

pub(super) fn d1_spdx3(doc: &Value) -> BTreeSet<String> {
    extract_mikebom_annotation_values(doc, "evidence.identity", false)
}
pub(super) fn d2_spdx3(doc: &Value) -> BTreeSet<String> {
    extract_mikebom_annotation_values(doc, "evidence.occurrences", false)
}

pub(super) fn e1_spdx3(doc: &Value) -> BTreeSet<String> {
    extract_mikebom_annotation_values(doc, "compositions", true)
}

// F1 VEX: SPDX 3 emits an externalRef on SpdxDocument with type
// `vulnerabilityExploitabilityAssessment`.
pub(super) fn f1_spdx3(doc: &Value) -> BTreeSet<String> {
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return BTreeSet::new();
    };
    let has_ref = graph
        .iter()
        .filter(|el| el.get("type").and_then(|v| v.as_str()) == Some("SpdxDocument"))
        .any(|el| {
            el.get("externalRef")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter().any(|r| {
                        r.get("externalRefType").and_then(|v| v.as_str())
                            == Some("vulnerabilityExploitabilityAssessment")
                    })
                })
                .unwrap_or(false)
        });
    if has_ref {
        BTreeSet::from(["__openvex_sidecar_present__".to_string()])
    } else {
        BTreeSet::new()
    }
}

pub(super) fn g1_spdx3(doc: &Value) -> BTreeSet<String> {
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return BTreeSet::new();
    };
    graph
        .iter()
        .filter(|el| el.get("type").and_then(|v| v.as_str()) == Some("Tool"))
        .filter_map(|el| el.get("name").and_then(|v| v.as_str()))
        .map(|s| s.split('-').next().unwrap_or("").to_string())
        .collect()
}
