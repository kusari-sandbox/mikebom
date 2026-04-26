//! SPDX 2.3-side parity extractors (milestone 022 commit 3).
//!
//! Mirrors `extractors/cdx.rs` but for SPDX 2.3 output shape. Owns
//! every `spdx23_*` and `c*_spdx23` / `d*_spdx23` / `e*_spdx23` /
//! `f*_spdx23` / `g*_spdx23` extractor function referenced by
//! `EXTRACTORS` in `super::mod`. Visibility: pub(super) for table
//! consumers; private for internal helpers.

use std::collections::BTreeSet;

use serde_json::Value;

use super::common::{
    extract_mikebom_annotation_values, normalize_alg, spdx_relationship_edges,
    walk_spdx23_packages,
};

/// Single-format SPDX 2.3 C-section stub generator. Component-scope:
/// `spdx23_anno!(c1_spdx23, "mikebom:source-type", component);`
/// Document-scope:
/// `spdx23_anno!(c21_spdx23, "mikebom:generation-context", document);`
macro_rules! spdx23_anno {
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

pub(super) fn spdx23_purl(doc: &Value) -> BTreeSet<String> {
    walk_spdx23_packages(doc)
        .iter()
        .flat_map(|p| {
            p.get("externalRefs")
                .and_then(|v| v.as_array())
                .map(|arr| arr.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|r| r.get("referenceType").and_then(|v| v.as_str()) == Some("purl"))
                .filter_map(|r| {
                    r.get("referenceLocator")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
        })
        .collect()
}

pub(super) fn spdx23_name(doc: &Value) -> BTreeSet<String> {
    walk_spdx23_packages(doc)
        .iter()
        .filter_map(|p| p.get("name").and_then(|v| v.as_str()).map(String::from))
        .collect()
}

pub(super) fn spdx23_version(doc: &Value) -> BTreeSet<String> {
    walk_spdx23_packages(doc)
        .iter()
        .filter_map(|p| {
            p.get("versionInfo")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect()
}

pub(super) fn spdx23_hashes(doc: &Value) -> BTreeSet<String> {
    walk_spdx23_packages(doc)
        .iter()
        .flat_map(|p| {
            p.get("checksums")
                .and_then(|v| v.as_array())
                .map(|arr| arr.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter_map(|c| {
                    let alg = c.get("algorithm").and_then(|v| v.as_str())?;
                    let val = c.get("checksumValue").and_then(|v| v.as_str())?;
                    Some(format!("{}:{}", normalize_alg(alg), val))
                })
        })
        .collect()
}

fn spdx23_external_ref_by_type(doc: &Value, ref_type: &str) -> BTreeSet<String> {
    walk_spdx23_packages(doc)
        .iter()
        .flat_map(|p| {
            p.get("externalRefs")
                .and_then(|v| v.as_array())
                .map(|arr| arr.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|r| r.get("referenceType").and_then(|v| v.as_str()) == Some(ref_type))
                .filter_map(|r| {
                    r.get("referenceLocator")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
        })
        .collect()
}

pub(super) fn spdx23_homepage(doc: &Value) -> BTreeSet<String> {
    let mut out = spdx23_external_ref_by_type(doc, "website");
    out.extend(spdx23_external_ref_by_type(doc, "homepage"));
    out
}
pub(super) fn spdx23_vcs(doc: &Value) -> BTreeSet<String> {
    spdx23_external_ref_by_type(doc, "vcs")
}
pub(super) fn spdx23_distribution(doc: &Value) -> BTreeSet<String> {
    let mut out = spdx23_external_ref_by_type(doc, "distribution");
    // Some downloads land in `downloadLocation` not externalRefs.
    out.extend(walk_spdx23_packages(doc).iter().filter_map(|p| {
        let dl = p.get("downloadLocation").and_then(|v| v.as_str())?;
        if dl == "NOASSERTION" || dl == "NONE" {
            None
        } else {
            Some(dl.to_string())
        }
    }));
    out
}

pub(super) fn spdx23_cpe(doc: &Value) -> BTreeSet<String> {
    walk_spdx23_packages(doc)
        .iter()
        .flat_map(|p| {
            p.get("externalRefs")
                .and_then(|v| v.as_array())
                .map(|arr| arr.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|r| {
                    matches!(
                        r.get("referenceType").and_then(|v| v.as_str()),
                        Some("cpe23Type") | Some("cpe22Type")
                    )
                })
                .filter_map(|r| {
                    r.get("referenceLocator")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
        })
        .collect()
}

// Licenses (A7 declared, A8 concluded). For LicenseRef-<hash>,
// return the underlying extractedText so cross-format comparison
// sees the same raw expression in CDX (which also surfaces it as a
// free-text expression). Lookup is global via the document's
// hasExtractedLicensingInfos[].
fn spdx23_licenses_field(doc: &Value, field: &str) -> BTreeSet<String> {
    walk_spdx23_packages(doc)
        .iter()
        .filter_map(|p| {
            let v = p.get(field).and_then(|v| v.as_str())?;
            if v == "NOASSERTION" || v == "NONE" {
                return None;
            }
            if v.starts_with("LicenseRef-") {
                if let Some(extracted) = doc
                    .get("hasExtractedLicensingInfos")
                    .and_then(|x| x.as_array())
                    .and_then(|arr| {
                        arr.iter().find(|e| {
                            e.get("licenseId").and_then(|x| x.as_str()) == Some(v)
                        })
                    })
                    .and_then(|e| e.get("extractedText"))
                    .and_then(|x| x.as_str())
                {
                    return Some(extracted.to_string());
                }
            }
            Some(v.to_string())
        })
        .collect()
}
pub(super) fn spdx23_licenses_declared(doc: &Value) -> BTreeSet<String> {
    spdx23_licenses_field(doc, "licenseDeclared")
}
pub(super) fn spdx23_licenses_concluded(doc: &Value) -> BTreeSet<String> {
    spdx23_licenses_field(doc, "licenseConcluded")
}

pub(super) fn spdx23_supplier(doc: &Value) -> BTreeSet<String> {
    walk_spdx23_packages(doc)
        .iter()
        .filter_map(|p| {
            let v = p.get("supplier").and_then(|v| v.as_str())?;
            if v == "NOASSERTION" {
                return None;
            }
            v.strip_prefix("Organization: ")
                .or_else(|| v.strip_prefix("Person: "))
                .map(String::from)
        })
        .collect()
}

// ============================================================
// Section B — Graph structure (B1-B4)
// ============================================================

pub(super) fn spdx23_runtime_deps(doc: &Value) -> BTreeSet<String> {
    spdx_relationship_edges(doc, "DEPENDS_ON", "")
}
pub(super) fn spdx23_dev_deps(doc: &Value) -> BTreeSet<String> {
    // Per milestone-011 B2 + milestone-012 mapping, SPDX 2.3 emits
    // DEV_DEPENDENCY_OF (target-source swap). Reverse the pair to
    // align with CDX direction.
    let raw = spdx_relationship_edges(doc, "DEV_DEPENDENCY_OF", "");
    raw.into_iter()
        .filter_map(|s| {
            let parts: Vec<&str> = s.splitn(2, "->").collect();
            if parts.len() == 2 {
                Some(format!("{}->{}", parts[1], parts[0]))
            } else {
                None
            }
        })
        .collect()
}

pub(super) fn spdx23_containment(doc: &Value) -> BTreeSet<String> {
    spdx_relationship_edges(doc, "CONTAINS", "")
}

pub(super) fn spdx23_root(doc: &Value) -> BTreeSet<String> {
    let Some(describes) = doc.get("documentDescribes").and_then(|v| v.as_array()) else {
        return BTreeSet::new();
    };
    let mut purl_by_spdxid: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for p in doc
        .get("packages")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let id = match p.get("SPDXID").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let purl = p
            .get("externalRefs")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|r| {
                    if r.get("referenceType").and_then(|v| v.as_str()) == Some("purl") {
                        r.get("referenceLocator")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                    } else {
                        None
                    }
                })
            });
        if let Some(purl) = purl {
            purl_by_spdxid.insert(id.to_string(), purl);
        }
    }
    describes
        .iter()
        .filter_map(|v| v.as_str())
        .filter_map(|id| purl_by_spdxid.get(id).cloned())
        .collect()
}

// ============================================================
// Section C — annotation stubs (C1-C23 SPDX 2.3 side)
// ============================================================

spdx23_anno!(c1_spdx23, "mikebom:source-type", component);
spdx23_anno!(c2_spdx23, "mikebom:source-connection-ids", component);
spdx23_anno!(c3_spdx23, "mikebom:deps-dev-match", component);
spdx23_anno!(c4_spdx23, "mikebom:evidence-kind", component);
spdx23_anno!(c5_spdx23, "mikebom:sbom-tier", component);
spdx23_anno!(c6_spdx23, "mikebom:dev-dependency", component);
spdx23_anno!(c7_spdx23, "mikebom:co-owned-by", component);
spdx23_anno!(c8_spdx23, "mikebom:shade-relocation", component);
spdx23_anno!(c9_spdx23, "mikebom:npm-role", component);
spdx23_anno!(c10_spdx23, "mikebom:binary-class", component);
spdx23_anno!(c11_spdx23, "mikebom:binary-stripped", component);
spdx23_anno!(c12_spdx23, "mikebom:linkage-kind", component);
spdx23_anno!(c13_spdx23, "mikebom:buildinfo-status", component);
spdx23_anno!(c14_spdx23, "mikebom:detected-go", component);
spdx23_anno!(c15_spdx23, "mikebom:binary-packed", component);
spdx23_anno!(c16_spdx23, "mikebom:confidence", component);
spdx23_anno!(c17_spdx23, "mikebom:raw-version", component);
spdx23_anno!(c18_spdx23, "mikebom:source-files", component);
spdx23_anno!(c19_spdx23, "mikebom:cpe-candidates", component);
spdx23_anno!(c20_spdx23, "mikebom:requirement-range", component);
spdx23_anno!(c21_spdx23, "mikebom:generation-context", document);
spdx23_anno!(c22_spdx23, "mikebom:os-release-missing-fields", document);
// C23 actually expands into 4 sub-fields; canary is ring-buffer-overflows.
spdx23_anno!(c23_spdx23, "mikebom:trace-integrity-ring-buffer-overflows", document);

// C24-C26 (milestone 023 — ELF identity, surfaced via the
// extra_annotations bag in entry.rs::make_file_level_component).
spdx23_anno!(c24_spdx23, "mikebom:elf-build-id", component);
spdx23_anno!(c25_spdx23, "mikebom:elf-runpath", component);
spdx23_anno!(c26_spdx23, "mikebom:elf-debuglink", component);

// C27-C29 (milestone 025 — Go VCS metadata).
spdx23_anno!(c27_spdx23, "mikebom:go-vcs-revision", component);
spdx23_anno!(c28_spdx23, "mikebom:go-vcs-time", component);
spdx23_anno!(c29_spdx23, "mikebom:go-vcs-modified", component);

// ============================================================
// Sections D-G — custom SPDX 2.3 extractors
// ============================================================

pub(super) fn d1_spdx23(doc: &Value) -> BTreeSet<String> {
    extract_mikebom_annotation_values(doc, "evidence.identity", false)
}
pub(super) fn d2_spdx23(doc: &Value) -> BTreeSet<String> {
    extract_mikebom_annotation_values(doc, "evidence.occurrences", false)
}

pub(super) fn e1_spdx23(doc: &Value) -> BTreeSet<String> {
    extract_mikebom_annotation_values(doc, "compositions", true)
}

// F1 VEX: SPDX 2.3 emits the cross-ref when advisories exist; the
// "present"/"absent" boolean is checkable via DocumentRef-OpenVEX
// in externalDocumentRefs.
pub(super) fn f1_spdx23(doc: &Value) -> BTreeSet<String> {
    let has_ref = doc
        .get("externalDocumentRefs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|r| {
                r.get("externalDocumentId").and_then(|v| v.as_str())
                    == Some("DocumentRef-OpenVEX")
            })
        })
        .unwrap_or(false);
    if has_ref {
        BTreeSet::from(["__openvex_sidecar_present__".to_string()])
    } else {
        BTreeSet::new()
    }
}

pub(super) fn g1_spdx23(doc: &Value) -> BTreeSet<String> {
    doc.get("creationInfo")
        .and_then(|c| c.get("creators"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| s.starts_with("Tool: "))
                .map(|s| s.trim_start_matches("Tool: ").split('-').next().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}
