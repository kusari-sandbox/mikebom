//! Cross-sibling helpers shared by `cdx`, `spdx2`, and `spdx3` (milestone 022).
//!
//! Owns:
//!   - the cross-format types (`ParityExtractor`, `Directionality`)
//!   - structural document walkers (one per format — kept here so SPDX-
//!     shared logic like `spdx_relationship_edges` can reach them
//!     without an upward dep into format submodules)
//!   - SPDX-side annotation envelope decoding (used by both SPDX 2.3
//!     and SPDX 3 sides)
//!   - `spdx_relationship_edges` (169 LOC graph traversal shared by
//!     SPDX 2.3 + SPDX 3 dependency-edge extractors per spec edge case)
//!   - sentinel `empty` / `g_empty` (referenced by EXTRACTORS table
//!     entries in `mod.rs`)
//!   - `normalize_alg` (used by all three formats' hash extractors)
//!
//! Visibility ladder (matches milestone 019 R4):
//!   - `pub` items are re-exported from `extractors/mod.rs` to preserve
//!     the public API path `mikebom::parity::extractors::*`.
//!   - `pub(super)` items are visible to `cdx`/`spdx2`/`spdx3`/`mod`
//!     siblings only.
//!   - private items live within this module.

use std::collections::BTreeSet;

use serde_json::Value;

/// Per-row extractor entry — one closure per format + a
/// directionality flag indicating whether the three extracted
/// sets must be symmetrically equal or whether a subset rule
/// applies.
pub struct ParityExtractor {
    pub row_id: &'static str,
    pub label: &'static str,
    pub cdx: fn(&Value) -> BTreeSet<String>,
    pub spdx23: fn(&Value) -> BTreeSet<String>,
    pub spdx3: fn(&Value) -> BTreeSet<String>,
    pub directional: Directionality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Directionality {
    /// CDX, SPDX 2.3, and SPDX 3 sets must all be equal.
    SymmetricEqual,
    /// `CDX ⊆ SPDX 2.3 ∧ CDX ⊆ SPDX 3`. The SPDX sides MAY
    /// carry additional values not in CDX (e.g., A12 CPE: CDX
    /// primary only; SPDX 3 every fully-resolved candidate).
    CdxSubsetOfSpdx,
    /// All three formats carry the datum but in shapes that
    /// structurally diverge (e.g., D1 evidence model — CDX
    /// `evidence.identity[]` vs SPDX flat `{technique,
    /// confidence}`; E1 compositions — CDX full array vs SPDX
    /// `{complete_ecosystems: [...]}`). The parity test only
    /// asserts that all three formats have a non-empty set —
    /// the spec calls this "presence parity," consistent with
    /// the user's clarification "data should be very similar,
    /// just formatting and structure should be different."
    PresenceOnly,
}

/// Decode the `MikebomAnnotationCommentV1` envelope from SPDX
/// 2.3 `annotations[].comment` / SPDX 3 `Annotation.statement`
/// entries, returning the set of values observed for the named
/// `mikebom:<field>`. When `subject_is_document` is true, the
/// helper checks document-level annotations (SPDX 2.3 top-level
/// `annotations[]` / SPDX 3 `@graph[Annotation].subject ==
/// document-iri`); otherwise it walks per-Package annotations
/// (SPDX 2.3 `packages[].annotations[]` / SPDX 3 `@graph[Annotation]`
/// keyed by Package subject IRIs).
///
/// Used by Section C / D / E catalog rows whose extractors are
/// otherwise repetitive 30-line walks. Centralizing the envelope-
/// decoding here keeps extractor entries one-line per row.
pub fn extract_mikebom_annotation_values(
    doc: &Value,
    field_name: &str,
    subject_is_document: bool,
) -> BTreeSet<String> {
    // Guess the format by document shape: SPDX 2.3 has top-
    // level `packages[]`; SPDX 3 has `@graph[]`; CDX has
    // `components[]`. The catalog rows that route through this
    // helper are SPDX-only (CDX uses property-name lookups
    // directly), so we only handle the two SPDX shapes here.
    if doc.get("@graph").is_some() {
        extract_spdx3_annotation_values(doc, field_name, subject_is_document)
    } else {
        extract_spdx23_annotation_values(doc, field_name, subject_is_document)
    }
}

fn extract_spdx23_annotation_values(
    doc: &Value,
    field_name: &str,
    subject_is_document: bool,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let pools: Vec<&Value> = if subject_is_document {
        doc.get("annotations").into_iter().collect()
    } else {
        doc.get("packages")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| p.get("annotations"))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    for pool in pools {
        let Some(arr) = pool.as_array() else { continue };
        for anno in arr {
            let Some(comment) = anno.get("comment").and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some(values) = decode_envelope(comment, field_name) {
                for v in values {
                    out.insert(v);
                }
            }
        }
    }
    out
}

fn extract_spdx3_annotation_values(
    doc: &Value,
    field_name: &str,
    subject_is_document: bool,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return out;
    };
    let document_iri = graph
        .iter()
        .find(|el| el.get("type").and_then(|v| v.as_str()) == Some("SpdxDocument"))
        .and_then(|el| el.get("spdxId"))
        .and_then(|v| v.as_str())
        .map(String::from);
    for el in graph {
        if el.get("type").and_then(|v| v.as_str()) != Some("Annotation") {
            continue;
        }
        let Some(subject_iri) = el.get("subject").and_then(|v| v.as_str()) else {
            continue;
        };
        let is_doc_subject = Some(subject_iri) == document_iri.as_deref();
        if subject_is_document != is_doc_subject {
            continue;
        }
        let Some(statement) = el.get("statement").and_then(|v| v.as_str()) else {
            continue;
        };
        if let Some(values) = decode_envelope(statement, field_name) {
            for v in values {
                out.insert(v);
            }
        }
    }
    out
}

/// Decode a `MikebomAnnotationCommentV1` JSON-string envelope and
/// return the canonicalized atomic-value set if `field` matches
/// `field_name`, else None. Applied flatten-and-canonicalize
/// matches the CDX-side property-walk so a CDX scalar property
/// `value: "true"` (JSON-encoded string) compares equal to a SPDX
/// envelope `value: true` (real JSON bool); a CDX list-shape (one
/// property per element) compares equal to a SPDX array-shape
/// (one annotation, array-valued envelope).
pub(super) fn decode_envelope(serialized: &str, field_name: &str) -> Option<Vec<String>> {
    let v: Value = serde_json::from_str(serialized).ok()?;
    if v.get("schema")?.as_str()? != "mikebom-annotation/v1" {
        return None;
    }
    if v.get("field")?.as_str()? != field_name {
        return None;
    }
    let value = v.get("value")?;
    Some(canonicalize_atomic_values(value))
}

/// Reduce a `serde_json::Value` to a flat set of canonical
/// strings. Strings that themselves encode JSON (e.g., the CDX
/// property-value convention of stringifying booleans / numbers /
/// short JSON-y values) are recursively decoded. Arrays are
/// flattened one level. Other shapes (bool, number, plain string,
/// object) canonicalize via `to_string`. This is the canonical
/// form both the CDX-property side and the SPDX-annotation side
/// reduce to before set-comparison.
pub(super) fn canonicalize_atomic_values(value: &Value) -> Vec<String> {
    if let Some(s) = value.as_str() {
        let trimmed = s.trim();
        let looks_like_json = matches!(
            trimmed.chars().next(),
            Some('[' | '{' | '"' | 't' | 'f' | 'n' | '-' | '0'..='9')
        );
        if looks_like_json {
            if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                return canonicalize_atomic_values(&parsed);
            }
        }
        return vec![serde_json::to_string(value).unwrap_or_default()];
    }
    if let Some(arr) = value.as_array() {
        let mut out = Vec::new();
        for el in arr {
            out.extend(canonicalize_atomic_values(el));
        }
        return out;
    }
    vec![serde_json::to_string(value).unwrap_or_default()]
}

/// Walk every CycloneDX component (top-level + recursively
/// nested under `components[].components[]`), yielding each
/// component object. Used by Section A / B / C extractors.
pub fn walk_cdx_components(doc: &Value) -> Vec<&Value> {
    fn recur<'a>(node: &'a Value, out: &mut Vec<&'a Value>) {
        if let Some(arr) = node.get("components").and_then(|v| v.as_array()) {
            for c in arr {
                out.push(c);
                recur(c, out);
            }
        }
    }
    let mut out = Vec::new();
    recur(doc, &mut out);
    out
}

/// Iterate SPDX 2.3 `packages[]`, skipping the synthetic root
/// (SPDXID begins with `SPDXRef-DocumentRoot-`).
pub fn walk_spdx23_packages(doc: &Value) -> Vec<&Value> {
    let Some(arr) = doc.get("packages").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter(|p| {
            !p.get("SPDXID")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.starts_with("SPDXRef-DocumentRoot-"))
        })
        .collect()
}

/// Iterate SPDX 3 `@graph[]` Package elements, skipping the
/// synthetic root (spdxId path segment includes `/pkg-root-`).
pub fn walk_spdx3_packages(doc: &Value) -> Vec<&Value> {
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    graph
        .iter()
        .filter(|el| el.get("type").and_then(|v| v.as_str()) == Some("software_Package"))
        .filter(|el| {
            !el.get("spdxId")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.contains("/pkg-root-"))
        })
        .collect()
}

/// Empty extractor — used for format-restricted columns + sentinel
/// G/H rows that don't carry cross-format-comparable signal.
pub(super) fn empty(_doc: &Value) -> BTreeSet<String> {
    BTreeSet::new()
}

/// Normalize a hash-algorithm name to a canonical comparison
/// form (`SHA256` etc.). CDX uses `SHA-256`; SPDX 2.3 uses
/// `SHA256`; SPDX 3 uses `sha256` (lowercase). We uppercase +
/// strip hyphens for symmetric comparison.
pub(super) fn normalize_alg(s: &str) -> String {
    s.replace('-', "").to_uppercase()
}

/// Shared SPDX 2.3 + SPDX 3 graph-traversal: walks Relationship
/// records for the given relationship type, returning a set of
/// "from-purl -> to-purl" strings. Branches at runtime on
/// `@graph` presence to detect SPDX 3 vs SPDX 2.3 shape. Used by
/// B1/B2 (runtime/dev dependency edges) on both SPDX sides.
pub(super) fn spdx_relationship_edges(
    doc: &Value,
    rel_type_2_3: &str,
    rel_type_3: &str,
) -> BTreeSet<String> {
    if doc.get("@graph").is_some() {
        // SPDX 3
        let mut out = BTreeSet::new();
        let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
            return out;
        };
        // Build IRI → PURL lookup.
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
        for el in graph {
            if el.get("type").and_then(|v| v.as_str()) != Some("Relationship") {
                continue;
            }
            if el.get("relationshipType").and_then(|v| v.as_str()) != Some(rel_type_3) {
                continue;
            }
            let from_iri = el.get("from").and_then(|v| v.as_str());
            let to_arr = el.get("to").and_then(|v| v.as_array());
            if let (Some(f), Some(t_arr)) = (from_iri, to_arr) {
                let Some(from_purl) = purl_by_iri.get(f) else {
                    continue;
                };
                for t in t_arr {
                    if let Some(t_iri) = t.as_str() {
                        if let Some(to_purl) = purl_by_iri.get(t_iri) {
                            out.insert(format!("{from_purl}->{to_purl}"));
                        }
                    }
                }
            }
        }
        out
    } else {
        // SPDX 2.3
        let mut out = BTreeSet::new();
        let mut purl_by_spdxid: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for p in walk_spdx23_packages(doc) {
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
        let Some(rels) = doc.get("relationships").and_then(|v| v.as_array()) else {
            return out;
        };
        for r in rels {
            if r.get("relationshipType").and_then(|v| v.as_str()) != Some(rel_type_2_3) {
                continue;
            }
            let Some(from) = r.get("spdxElementId").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(to) = r.get("relatedSpdxElement").and_then(|v| v.as_str()) else {
                continue;
            };
            if let (Some(from_purl), Some(to_purl)) =
                (purl_by_spdxid.get(from), purl_by_spdxid.get(to))
            {
                out.insert(format!("{from_purl}->{to_purl}"));
            }
        }
        out
    }
}
