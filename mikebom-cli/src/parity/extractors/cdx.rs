//! CycloneDX-side parity extractors (milestone 022 commit 2).
//!
//! Owns every `cdx_*` and `c*_cdx` / `d*_cdx` / `e*_cdx` / `f*_cdx` /
//! `g*_cdx` extractor function referenced by `EXTRACTORS` in
//! `super::mod`. The `cdx_property_values` helper + the `cdx_anno!`
//! macro are CDX-internal (single-format equivalent of the
//! pre-022 cross-format `component_anno_extractors!` /
//! `document_anno_extractors!` macros).
//!
//! Visibility: every fn referenced from `super::EXTRACTORS` is
//! `pub(super)`; helpers used only inside this module stay private.

use std::collections::BTreeSet;

use serde_json::Value;

use super::common::{canonicalize_atomic_values, walk_cdx_components};

// ============================================================
// CDX-side property-name extractor — reused by the C-section
// annotation stub generator below.
// ============================================================

/// Yield the set of property values whose `name` matches `field_name`.
/// For component-level properties (`subject_is_document = false`)
/// walks each component's `properties[]`; for document-level (`true`)
/// walks `metadata.properties[]`.
fn cdx_property_values(
    doc: &Value,
    field_name: &str,
    subject_is_document: bool,
) -> BTreeSet<String> {
    let pools: Vec<&Value> = if subject_is_document {
        doc.get("metadata")
            .and_then(|m| m.get("properties"))
            .into_iter()
            .collect()
    } else {
        walk_cdx_components(doc)
            .into_iter()
            .filter_map(|c| c.get("properties"))
            .collect()
    };
    let mut out = BTreeSet::new();
    for pool in pools {
        let Some(arr) = pool.as_array() else { continue };
        for p in arr {
            if p.get("name").and_then(|v| v.as_str()) != Some(field_name) {
                continue;
            }
            let Some(value) = p.get("value") else { continue };
            // Canonicalize via the same flatten-and-decode helper as
            // the SPDX side so byte-equivalent atomic values collapse
            // identically across formats — handles JSON-encoded
            // scalars (`"true"` → `true`) and array values both
            // inline (`[a,b]`) and split-per-property.
            for v in canonicalize_atomic_values(value) {
                out.insert(v);
            }
        }
    }
    out
}

/// Single-format C-section stub generator. Component-scope:
/// `cdx_anno!(c1_cdx, "mikebom:source-type", component);`
/// Document-scope:
/// `cdx_anno!(c21_cdx, "mikebom:generation-context", document);`
macro_rules! cdx_anno {
    ($name:ident, $field:literal, component) => {
        pub(super) fn $name(doc: &Value) -> BTreeSet<String> {
            cdx_property_values(doc, $field, false)
        }
    };
    ($name:ident, $field:literal, document) => {
        pub(super) fn $name(doc: &Value) -> BTreeSet<String> {
            cdx_property_values(doc, $field, true)
        }
    };
}

// ============================================================
// Section A — Core identity (A1-A12)
// ============================================================

pub(super) fn cdx_purl(doc: &Value) -> BTreeSet<String> {
    walk_cdx_components(doc)
        .iter()
        .filter_map(|c| c.get("purl").and_then(|v| v.as_str()).map(String::from))
        .collect()
}

pub(super) fn cdx_name(doc: &Value) -> BTreeSet<String> {
    walk_cdx_components(doc)
        .iter()
        .filter_map(|c| c.get("name").and_then(|v| v.as_str()).map(String::from))
        .collect()
}

pub(super) fn cdx_version(doc: &Value) -> BTreeSet<String> {
    walk_cdx_components(doc)
        .iter()
        .filter_map(|c| c.get("version").and_then(|v| v.as_str()).map(String::from))
        .collect()
}

pub(super) fn cdx_hashes(doc: &Value) -> BTreeSet<String> {
    walk_cdx_components(doc)
        .iter()
        .flat_map(|c| {
            c.get("hashes")
                .and_then(|v| v.as_array())
                .map(|arr| arr.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter_map(|h| {
                    let alg = h.get("alg").and_then(|v| v.as_str())?;
                    let content = h.get("content").and_then(|v| v.as_str())?;
                    Some(format!("{}:{}", super::common::normalize_alg(alg), content))
                })
        })
        .collect()
}

fn cdx_external_ref_by_type(doc: &Value, ref_type: &str) -> BTreeSet<String> {
    walk_cdx_components(doc)
        .iter()
        .flat_map(|c| {
            c.get("externalReferences")
                .and_then(|v| v.as_array())
                .map(|arr| arr.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|r| r.get("type").and_then(|v| v.as_str()) == Some(ref_type))
                .filter_map(|r| r.get("url").and_then(|v| v.as_str()).map(String::from))
        })
        .collect()
}

pub(super) fn cdx_homepage(doc: &Value) -> BTreeSet<String> {
    let mut out = cdx_external_ref_by_type(doc, "website");
    out.extend(cdx_external_ref_by_type(doc, "homepage"));
    out
}
pub(super) fn cdx_vcs(doc: &Value) -> BTreeSet<String> {
    cdx_external_ref_by_type(doc, "vcs")
}
pub(super) fn cdx_distribution(doc: &Value) -> BTreeSet<String> {
    cdx_external_ref_by_type(doc, "distribution")
}

pub(super) fn cdx_cpe(doc: &Value) -> BTreeSet<String> {
    walk_cdx_components(doc)
        .iter()
        .filter_map(|c| c.get("cpe").and_then(|v| v.as_str()).map(String::from))
        .collect()
}

fn cdx_licenses_typed(doc: &Value, ack: &str) -> BTreeSet<String> {
    walk_cdx_components(doc)
        .iter()
        .flat_map(|c| {
            c.get("licenses")
                .and_then(|v| v.as_array())
                .map(|arr| arr.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|l| {
                    // CDX 1.6 nests acknowledgement inside the
                    // `license` object for {license: {id, name,
                    // acknowledgement}}, and at the top of the
                    // entry for {expression, acknowledgement}.
                    let nested = l
                        .get("license")
                        .and_then(|li| li.get("acknowledgement"))
                        .and_then(|v| v.as_str());
                    let top = l.get("acknowledgement").and_then(|v| v.as_str());
                    nested == Some(ack) || top == Some(ack)
                })
                .filter_map(|l| {
                    if let Some(id) = l.get("license")
                        .and_then(|li| li.get("id"))
                        .and_then(|v| v.as_str())
                    {
                        return Some(id.to_string());
                    }
                    if let Some(name) = l
                        .get("license")
                        .and_then(|li| li.get("name"))
                        .and_then(|v| v.as_str())
                    {
                        return Some(name.to_string());
                    }
                    if let Some(expr) = l.get("expression").and_then(|v| v.as_str()) {
                        return Some(expr.to_string());
                    }
                    None
                })
        })
        .collect()
}
pub(super) fn cdx_licenses_declared(doc: &Value) -> BTreeSet<String> {
    cdx_licenses_typed(doc, "declared")
}
pub(super) fn cdx_licenses_concluded(doc: &Value) -> BTreeSet<String> {
    cdx_licenses_typed(doc, "concluded")
}

pub(super) fn cdx_supplier(doc: &Value) -> BTreeSet<String> {
    walk_cdx_components(doc)
        .iter()
        .filter_map(|c| {
            c.get("supplier")
                .and_then(|s| s.get("name"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect()
}

// ============================================================
// Section B — Graph structure (B1-B4)
// ============================================================

/// Collect (from_purl, to_purl) edges from CDX `dependencies[]`.
/// Uses `bom-ref` → `purl` lookup since dependencies are keyed
/// by bom-ref. Filters runtime vs dev edges via the
/// `mikebom:dev-dependency` property on the source component.
fn cdx_dependency_edges(doc: &Value, dev_only: bool) -> BTreeSet<String> {
    // Build bom-ref → component lookup.
    let mut comp_by_bomref: std::collections::BTreeMap<String, &Value> =
        std::collections::BTreeMap::new();
    for c in walk_cdx_components(doc) {
        if let Some(bref) = c.get("bom-ref").and_then(|v| v.as_str()) {
            comp_by_bomref.insert(bref.to_string(), c);
        }
    }
    let mut out = BTreeSet::new();
    let Some(deps) = doc.get("dependencies").and_then(|v| v.as_array()) else {
        return out;
    };
    for d in deps {
        let Some(from_ref) = d.get("ref").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(from_comp) = comp_by_bomref.get(from_ref) else {
            continue;
        };
        let from_purl = match from_comp.get("purl").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => continue,
        };
        let from_is_dev = from_comp
            .get("properties")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().any(|p| {
                    p.get("name").and_then(|x| x.as_str()) == Some("mikebom:dev-dependency")
                        && p.get("value").and_then(|x| x.as_str()) == Some("true")
                })
            })
            .unwrap_or(false);
        if dev_only != from_is_dev {
            continue;
        }
        let Some(targets) = d.get("dependsOn").and_then(|v| v.as_array()) else {
            continue;
        };
        for t in targets {
            let Some(to_ref) = t.as_str() else { continue };
            let Some(to_comp) = comp_by_bomref.get(to_ref) else {
                continue;
            };
            let Some(to_purl) = to_comp.get("purl").and_then(|v| v.as_str()) else {
                continue;
            };
            out.insert(format!("{from_purl}->{to_purl}"));
        }
    }
    out
}

pub(super) fn cdx_runtime_deps(doc: &Value) -> BTreeSet<String> {
    cdx_dependency_edges(doc, false)
}
pub(super) fn cdx_dev_deps(doc: &Value) -> BTreeSet<String> {
    cdx_dependency_edges(doc, true)
}

// B3 nested containment: CDX nests via `component.components[]`.
// Returns set of `parent_purl->child_purl` strings walked from the
// nested structure.
pub(super) fn cdx_containment(doc: &Value) -> BTreeSet<String> {
    fn recur<'a>(parent: Option<&'a str>, node: &'a Value, out: &mut BTreeSet<String>) {
        if let Some(arr) = node.get("components").and_then(|v| v.as_array()) {
            for c in arr {
                let purl = c.get("purl").and_then(|v| v.as_str());
                if let (Some(p), Some(child)) = (parent, purl) {
                    out.insert(format!("{p}->{child}"));
                }
                recur(purl, c, out);
            }
        }
    }
    let mut out = BTreeSet::new();
    recur(None, doc, &mut out);
    out
}

// B4 root: CDX `metadata.component.purl` (singleton).
pub(super) fn cdx_root(doc: &Value) -> BTreeSet<String> {
    doc.get("metadata")
        .and_then(|m| m.get("component"))
        .and_then(|c| c.get("purl"))
        .and_then(|v| v.as_str())
        .map(|s| BTreeSet::from([s.to_string()]))
        .unwrap_or_default()
}

// ============================================================
// Section C — mikebom-specific annotations (C1-C23 CDX side)
// ============================================================

cdx_anno!(c1_cdx, "mikebom:source-type", component);
cdx_anno!(c2_cdx, "mikebom:source-connection-ids", component);
cdx_anno!(c3_cdx, "mikebom:deps-dev-match", component);
cdx_anno!(c4_cdx, "mikebom:evidence-kind", component);
cdx_anno!(c5_cdx, "mikebom:sbom-tier", component);
cdx_anno!(c6_cdx, "mikebom:dev-dependency", component);
cdx_anno!(c7_cdx, "mikebom:co-owned-by", component);
cdx_anno!(c8_cdx, "mikebom:shade-relocation", component);
cdx_anno!(c9_cdx, "mikebom:npm-role", component);
cdx_anno!(c10_cdx, "mikebom:binary-class", component);
cdx_anno!(c11_cdx, "mikebom:binary-stripped", component);
cdx_anno!(c12_cdx, "mikebom:linkage-kind", component);
cdx_anno!(c13_cdx, "mikebom:buildinfo-status", component);
cdx_anno!(c14_cdx, "mikebom:detected-go", component);
cdx_anno!(c15_cdx, "mikebom:binary-packed", component);
cdx_anno!(c16_cdx, "mikebom:confidence", component);
cdx_anno!(c17_cdx, "mikebom:raw-version", component);
cdx_anno!(c18_cdx, "mikebom:source-files", component);

/// C19 cpe-candidates: CDX serializes the candidate list as a
/// pipe-separated string per property (mikebom convention,
/// matching the CycloneDX `cpe` field's single-value cardinality);
/// SPDX emits each candidate as its own annotation. Split the CDX
/// pipe-string into atoms so the directional containment test
/// (`CDX ⊆ SPDX`) compares apples-to-apples atomic CPEs.
pub(super) fn c19_cdx(doc: &Value) -> BTreeSet<String> {
    cdx_property_values(doc, "mikebom:cpe-candidates", false)
        .into_iter()
        .flat_map(|raw| {
            // `cdx_property_values` JSON-encodes the string ⇒ the
            // raw entry is `"cpe1 | cpe2"` (quotes-wrapped). Strip
            // the outer quotes before splitting on the pipe
            // delimiter, then re-encode each atom via `to_string`
            // so the form matches the SPDX side
            // (`"cpe1"` / `"cpe2"` post-canonicalization).
            let unquoted = raw.trim_matches('"');
            unquoted
                .split(" | ")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| serde_json::to_string(s).unwrap_or_else(|_| s.to_string()))
                .collect::<Vec<_>>()
        })
        .collect()
}

cdx_anno!(c20_cdx, "mikebom:requirement-range", component);

// C21-C23 (document-level).
cdx_anno!(c21_cdx, "mikebom:generation-context", document);
cdx_anno!(c22_cdx, "mikebom:os-release-missing-fields", document);
// C23 actually expands into 4 sub-fields (ring-buffer-overflows,
// events-dropped, uprobe-attach-failures, kprobe-attach-failures);
// the parity test treats it as one row per the catalog. Use the
// ring-buffer-overflows scalar as the canary; the other three
// share the same emit path.
cdx_anno!(c23_cdx, "mikebom:trace-integrity-ring-buffer-overflows", document);

// C24-C26 (milestone 023 — ELF identity, surfaced via the
// extra_annotations bag in entry.rs::make_file_level_component).
cdx_anno!(c24_cdx, "mikebom:elf-build-id", component);
cdx_anno!(c25_cdx, "mikebom:elf-runpath", component);
cdx_anno!(c26_cdx, "mikebom:elf-debuglink", component);

// C27-C29 (milestone 025 — Go VCS metadata, surfaced via the
// extra_annotations bag in go_binary.rs::build_vcs_annotations on
// the main-module Go entry only).
cdx_anno!(c27_cdx, "mikebom:go-vcs-revision", component);
cdx_anno!(c28_cdx, "mikebom:go-vcs-time", component);
cdx_anno!(c29_cdx, "mikebom:go-vcs-modified", component);

// ============================================================
// Section D — Evidence (D1, D2 — CDX-native shape)
// ============================================================

// CDX shape is different (native evidence model under
// `component.evidence`) — use a custom CDX extractor that
// serializes the array verbatim.
pub(super) fn d1_cdx(doc: &Value) -> BTreeSet<String> {
    walk_cdx_components(doc)
        .iter()
        .filter_map(|c| {
            let id = c.get("evidence")?.get("identity")?;
            // Match the SPDX-side serialized shape: an array of
            // {technique, confidence}. CDX has the array under
            // evidence.identity.
            serde_json::to_string(id).ok()
        })
        .collect()
}
pub(super) fn d2_cdx(doc: &Value) -> BTreeSet<String> {
    walk_cdx_components(doc)
        .iter()
        .filter_map(|c| {
            let occ = c.get("evidence")?.get("occurrences")?;
            serde_json::to_string(occ).ok()
        })
        .collect()
}

// ============================================================
// Section E — Compositions (E1)
// ============================================================

// E1 compositions — document-level. CDX has /compositions[] with
// every aggregate (`complete`, `incomplete_first_party_only`,
// etc.); SPDX 2.3 + 3 emit a `compositions` annotation only when
// at least one *complete* ecosystem claim is present (the SPDX
// annotation collapses to `{complete_ecosystems: [...]}`, which
// is empty for incomplete-only scans). For PresenceOnly parity,
// the CDX side reports presence only when CDX has at least one
// `aggregate == "complete"` entry — matching the SPDX semantics
// and avoiding false-positive failures on incomplete-only
// fixtures (e.g., rpm/bdb-only).
pub(super) fn e1_cdx(doc: &Value) -> BTreeSet<String> {
    let Some(comps) = doc.get("compositions").and_then(|v| v.as_array()) else {
        return BTreeSet::new();
    };
    let any_complete = comps
        .iter()
        .any(|c| c.get("aggregate").and_then(|v| v.as_str()) == Some("complete"));
    if any_complete {
        serde_json::to_string(comps).into_iter().collect()
    } else {
        BTreeSet::new()
    }
}

// ============================================================
// Section F — VEX (F1)
// ============================================================

pub(super) fn f1_cdx(doc: &Value) -> BTreeSet<String> {
    doc.get("vulnerabilities")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.get("id")).filter_map(|v| v.as_str()).map(String::from).collect())
        .unwrap_or_default()
}

// ============================================================
// Section G — Document envelope (G1 tool name)
// ============================================================

pub(super) fn g1_cdx(doc: &Value) -> BTreeSet<String> {
    doc.get("metadata")
        .and_then(|m| m.get("tools"))
        .and_then(|t| t.get("components"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("name").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
