//! SPDX 3.0.1 `ExternalIdentifier` value-object builder (milestone 011).
//!
//! Per `data-model.md` Element Catalog §`ExternalIdentifier`:
//! every emitted `software_Package` carries an `externalIdentifier`
//! list with exactly one PURL entry (`externalIdentifierType:
//! "purl"`) plus zero-or-more CPE 2.3 entries
//! (`externalIdentifierType: "cpe23"`) — one per fully-resolved
//! candidate. Unresolved CPE candidates land in an `Annotation`
//! per the C19 split (research.md §R3 / §R5).
//!
//! `ExternalIdentifier` is value-typed (no `spdxId`); the JSON
//! shape is `{type, externalIdentifierType, identifier}`.

use serde_json::{json, Value};

use mikebom_common::resolution::ResolvedComponent;

/// Build the `externalIdentifier[]` list for one component.
///
/// Always includes a `purl` entry. Includes one `cpe23` entry per
/// fully-resolved CPE in `component.cpes`. Sorted by
/// `(externalIdentifierType, identifier)` for determinism.
pub fn build_external_identifiers_for(component: &ResolvedComponent) -> Vec<Value> {
    let mut entries: Vec<Value> = Vec::new();

    // PURL — always exactly one entry. SPDX 3 vocabulary names the
    // PURL externalIdentifierType `"packageUrl"` (per
    // `prop_ExternalIdentifier_externalIdentifierType` enum in the
    // bundled schema); "purl" is not a valid value.
    entries.push(json!({
        "type": "ExternalIdentifier",
        "externalIdentifierType": "packageUrl",
        "identifier": component.purl.as_str(),
    }));

    // CPE 2.3 — one entry per fully-resolved candidate. A "fully
    // resolved" CPE 2.3 vector has no wildcards (`*` or `-`) in
    // any of the 11 required attribute slots: cpe:2.3:part:vendor:
    // product:version:update:edition:language:sw_edition:target_sw:
    // target_hw:other. mikebom's `cpes` array contains the
    // synthesized candidate set; entries that pass the
    // resolution check land here, the rest go to the C19
    // Annotation (build_component_annotations in US2).
    for cpe in &component.cpes {
        if is_fully_resolved_cpe23(cpe) {
            entries.push(json!({
                "type": "ExternalIdentifier",
                "externalIdentifierType": "cpe23",
                "identifier": cpe,
            }));
        }
    }

    // Deterministic order: by (type, identifier).
    entries.sort_by(|a, b| {
        let key = |v: &Value| -> (String, String) {
            (
                v["externalIdentifierType"].as_str().unwrap_or("").to_string(),
                v["identifier"].as_str().unwrap_or("").to_string(),
            )
        };
        key(a).cmp(&key(b))
    });

    entries
}

/// True when a CPE 2.3 string has no wildcards in its required
/// attribute slots — vendor, product, and version specifically.
/// CPE 2.3 syntax: `cpe:2.3:<part>:<vendor>:<product>:<version>:<...8 more>`.
/// We enforce non-wildcard in the first five fields after the prefix
/// (part / vendor / product / version / update); other fields
/// commonly use `*` as legitimate "any" markers in real-world CPE
/// vectors and don't constitute a "candidate set" signal.
fn is_fully_resolved_cpe23(cpe: &str) -> bool {
    let parts: Vec<&str> = cpe.split(':').collect();
    // Need at least the prefix `cpe:2.3:` plus 5 attribute slots.
    if parts.len() < 7 || parts[0] != "cpe" || parts[1] != "2.3" {
        return false;
    }
    // parts[2..7] = part, vendor, product, version, update.
    parts[2..7]
        .iter()
        .all(|s| !s.is_empty() && *s != "*" && *s != "-")
}
