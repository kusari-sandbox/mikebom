//! SPDX 3.0.1 `simplelicensing_LicenseExpression` element builder
//! (milestone 011).
//!
//! Per `data-model.md` Element Catalog §`simplelicensing_License
//! Expression`: each declared and concluded license expression
//! becomes one element with `simplelicensing_licenseExpression`
//! carrying the canonical SPDX expression. The element is wired
//! to its owning Package by a `Relationship` with
//! `relationshipType: "hasDeclaredLicense"` or
//! `"hasConcludedLicense"`. Concluded-license element + edge are
//! omitted when the concluded expression equals the declared
//! expression.
//!
//! Canonicalization uses `spdx::Expression::try_canonical(&str)`
//! (the SPDX 2.3 path's helper); on failure, the raw string is
//! preserved verbatim per FR-008.

use std::collections::{BTreeMap, BTreeSet};

use data_encoding::BASE32_NOPAD;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use mikebom_common::resolution::ResolvedComponent;
use mikebom_common::types::license::SpdxExpression;

use super::v3_relationships::build_relationship;

/// Build `simplelicensing_LicenseExpression` elements + the
/// associated `hasDeclaredLicense` / `hasConcludedLicense`
/// `Relationship` elements.
///
/// LicenseExpression elements are deduplicated by `(kind, expr)`
/// across the scan: if 50 packages declare `MIT`, exactly one
/// declared-MIT LicenseExpression element is emitted; the 50
/// Relationships all point at it. Concluded-license element is
/// omitted when its canonical expression equals the declared
/// canonical expression for the same Package (no redundant edge).
pub fn build_license_elements_and_relationships(
    components: &[ResolvedComponent],
    package_iri_by_purl: &BTreeMap<String, String>,
    doc_iri: &str,
    creation_info_id: &str,
) -> (Vec<Value>, Vec<Value>) {
    // Dedup: (kind, canonical-or-raw expression) → element IRI.
    let mut elements_by_key: BTreeMap<(LicenseKind, String), String> =
        BTreeMap::new();
    let mut elements: Vec<Value> = Vec::new();
    let mut relationships: Vec<Value> = Vec::new();
    let mut seen_iris: BTreeSet<String> = BTreeSet::new();

    for c in components {
        let Some(pkg_iri) = package_iri_by_purl.get(c.purl.as_str()) else {
            continue;
        };

        let declared_expr = reduce_license_vec(&c.licenses);
        let concluded_expr = reduce_license_vec(&c.concluded_licenses);

        if let Some(expr) = &declared_expr {
            let iri = element_iri_for(LicenseKind::Declared, expr, doc_iri);
            elements_by_key
                .entry((LicenseKind::Declared, expr.clone()))
                .or_insert_with(|| {
                    let element = json!({
                        "type": "simplelicensing_LicenseExpression",
                        "spdxId": iri,
                        "creationInfo": creation_info_id,
                        "simplelicensing_licenseExpression": expr,
                    });
                    if seen_iris.insert(iri.clone()) {
                        elements.push(element);
                    }
                    iri.clone()
                });
            relationships.push(build_relationship(
                pkg_iri,
                "hasDeclaredLicense",
                &iri,
                doc_iri,
                creation_info_id,
            ));
        }

        if let Some(expr) = &concluded_expr {
            // Skip when concluded equals declared — no redundant edge.
            if Some(expr) == declared_expr.as_ref() {
                continue;
            }
            let iri = element_iri_for(LicenseKind::Concluded, expr, doc_iri);
            elements_by_key
                .entry((LicenseKind::Concluded, expr.clone()))
                .or_insert_with(|| {
                    let element = json!({
                        "type": "simplelicensing_LicenseExpression",
                        "spdxId": iri,
                        "creationInfo": creation_info_id,
                        "simplelicensing_licenseExpression": expr,
                    });
                    if seen_iris.insert(iri.clone()) {
                        elements.push(element);
                    }
                    iri.clone()
                });
            relationships.push(build_relationship(
                pkg_iri,
                "hasConcludedLicense",
                &iri,
                doc_iri,
                creation_info_id,
            ));
        }
    }

    sort_by_spdx_id(&mut elements);
    sort_by_spdx_id(&mut relationships);
    (elements, relationships)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LicenseKind {
    Declared,
    Concluded,
}

fn element_iri_for(kind: LicenseKind, expr: &str, doc_iri: &str) -> String {
    let prefix = match kind {
        LicenseKind::Declared => "license-decl",
        LicenseKind::Concluded => "license-conc",
    };
    let h = hash_prefix(expr.as_bytes(), 16);
    format!("{doc_iri}/{prefix}-{h}")
}

/// Reduce a `Vec<SpdxExpression>` to a single canonical-or-raw
/// expression string, or `None` when the list is empty. Multiple
/// declared expressions on a component (rare) are joined with
/// ` AND ` and re-canonicalized; canonicalization failure preserves
/// the raw joined string verbatim per FR-008 (no silent drop).
fn reduce_license_vec(items: &[SpdxExpression]) -> Option<String> {
    match items.len() {
        0 => None,
        1 => Some(canonicalize_or_raw(items[0].as_str())),
        _ => {
            let joined = items
                .iter()
                .map(|e| e.as_str())
                .collect::<Vec<_>>()
                .join(" AND ");
            Some(canonicalize_or_raw(&joined))
        }
    }
}

fn canonicalize_or_raw(expr: &str) -> String {
    match SpdxExpression::try_canonical(expr) {
        Ok(canon) => canon.as_str().to_string(),
        Err(_) => expr.to_string(),
    }
}

fn sort_by_spdx_id(values: &mut [Value]) {
    values.sort_by(|a, b| {
        let key = |v: &Value| v["spdxId"].as_str().unwrap_or("").to_string();
        key(a).cmp(&key(b))
    });
}

fn hash_prefix(input: &[u8], chars: usize) -> String {
    let digest = Sha256::digest(input);
    let encoded = BASE32_NOPAD.encode(&digest);
    encoded[..chars].to_string()
}
