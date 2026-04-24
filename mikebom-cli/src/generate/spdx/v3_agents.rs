//! SPDX 3.0.1 `Organization` / `Person` (Agent subtype) element
//! builder (milestone 011).
//!
//! Per `data-model.md` Element Catalog §`Organization` /
//! `Person`: each distinct supplier (Section A row A4) and each
//! distinct originator/author (A5) becomes one Agent-subtype
//! element.
//!
//! In SPDX 3.0.1, supplier/originator are NOT Relationship-typed
//! edges — they're direct properties on the Package element
//! (`suppliedBy: <Agent IRI>` and `originatedBy: [<Agent IRI>]`
//! on Artifact_props, which software_Package inherits). This
//! module returns the Agent elements plus a `by-package-iri`
//! attachment map that the Package builder consumes; there are
//! no Relationship elements for supplier/originator in the SPDX 3
//! output.
//!
//! Agents are deduplicated by name across the scan so a supplier
//! that ships 50 packages produces one Organization element, not
//! 50.

use std::collections::BTreeMap;

use data_encoding::BASE32_NOPAD;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use mikebom_common::resolution::ResolvedComponent;

/// Per-Package agent attachments. The Package builder reads
/// `suppliedBy` and `originatedBy` entries here and inlines them
/// onto the emitted software_Package.
#[derive(Debug, Default, Clone)]
pub struct PackageAgentAttachments {
    pub supplied_by: Option<String>,
    pub originated_by: Vec<String>,
}

/// Result of agent-element construction.
pub struct AgentBuild {
    /// One `Organization` or `Person` element per distinct
    /// supplier/originator encountered during the scan.
    pub elements: Vec<Value>,
    /// `package IRI → (suppliedBy, originatedBy)` map consumed by
    /// `v3_packages::build_packages`.
    pub attachments: BTreeMap<String, PackageAgentAttachments>,
}

/// Build the `Organization` / `Person` elements and return the
/// per-package attachment map. Agents dedup by `(kind, name)`.
pub fn build_agents(
    components: &[ResolvedComponent],
    package_iri_by_purl: &BTreeMap<String, String>,
    doc_iri: &str,
    creation_info_id: &str,
) -> AgentBuild {
    let mut iri_by_name: BTreeMap<String, String> = BTreeMap::new();
    let mut elements: Vec<Value> = Vec::new();
    let mut attachments: BTreeMap<String, PackageAgentAttachments> =
        BTreeMap::new();

    for c in components {
        let Some(pkg_iri) = package_iri_by_purl.get(c.purl.as_str()) else {
            continue;
        };
        let attach = attachments.entry(pkg_iri.clone()).or_default();

        if let Some(supplier) = &c.supplier {
            if !supplier.is_empty() {
                let iri = iri_by_name
                    .entry(supplier.clone())
                    .or_insert_with(|| agent_iri("org", supplier, doc_iri))
                    .clone();
                if !elements
                    .iter()
                    .any(|e| e["spdxId"].as_str() == Some(iri.as_str()))
                {
                    elements.push(json!({
                        "type": "Organization",
                        "spdxId": iri,
                        "creationInfo": creation_info_id,
                        "name": supplier,
                    }));
                }
                attach.supplied_by = Some(iri);
            }
        }
    }

    elements.sort_by(|a, b| {
        let key = |v: &Value| v["spdxId"].as_str().unwrap_or("").to_string();
        key(a).cmp(&key(b))
    });

    AgentBuild {
        elements,
        attachments,
    }
}

fn agent_iri(kind: &str, name: &str, doc_iri: &str) -> String {
    let h = hash_prefix(format!("{kind}|{name}").as_bytes(), 16);
    format!("{doc_iri}/agent-{kind}-{h}")
}

fn hash_prefix(input: &[u8], chars: usize) -> String {
    let digest = Sha256::digest(input);
    let encoded = BASE32_NOPAD.encode(&digest);
    encoded[..chars].to_string()
}
