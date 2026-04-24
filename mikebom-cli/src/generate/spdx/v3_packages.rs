//! SPDX 3.0.1 `software_Package` element builder (milestone 011).
//!
//! Per `data-model.md` Element Catalog §`software_Package`:
//! emits one Package per discovered component with `name`,
//! `software_packageVersion`, `software_packageUrl`,
//! `verifiedUsing[]` (Hash value-objects), `software_homePage`,
//! `software_sourceInfo`, `software_downloadLocation`, and the
//! Package's `externalIdentifier[]` (PURL + any fully-resolved
//! CPE 2.3 vectors).
//!
//! Output is deterministically ordered by `spdxId`. The IRI for
//! each Package is `<doc IRI>/pkg-<base32(SHA256(<purl>))[..16]>`,
//! identical to the milestone-010 stub's derivation.

use std::collections::BTreeMap;

use data_encoding::BASE32_NOPAD;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use mikebom_common::resolution::ResolvedComponent;

use super::v3_agents::PackageAgentAttachments;
use super::v3_external_ids::build_external_identifiers_for;

/// Build the PURL → Package-IRI lookup table. Used as a first
/// pass by `v3_document::build_document` so Agent and License
/// builders can reference Package IRIs before Packages are
/// composed.
pub fn build_iri_lookup(
    components: &[ResolvedComponent],
    doc_iri: &str,
) -> BTreeMap<String, String> {
    let mut lookup: BTreeMap<String, String> = BTreeMap::new();
    for c in components {
        let purl_str = c.purl.as_str();
        let pkg_iri = format!("{doc_iri}/pkg-{}", hash_prefix(purl_str.as_bytes(), 16));
        lookup.insert(purl_str.to_string(), pkg_iri);
    }
    lookup
}

/// Build the `software_Package` elements for a scan plus the
/// PURL → IRI lookup needed by relationship/license/agent
/// builders. Returns `(packages, package_iri_by_purl)` with
/// packages already sorted by `spdxId` for determinism.
///
/// `agent_attachments` (per-package `suppliedBy`/`originatedBy`)
/// comes from `v3_agents::build_agents` and is inlined onto each
/// Package — SPDX 3 puts these as direct Artifact_props fields,
/// not Relationship edges.
pub fn build_packages(
    components: &[ResolvedComponent],
    doc_iri: &str,
    creation_info_id: &str,
    agent_attachments: &BTreeMap<String, PackageAgentAttachments>,
) -> (Vec<Value>, BTreeMap<String, String>) {
    let mut package_iri_by_purl: BTreeMap<String, String> = BTreeMap::new();
    let mut packages: Vec<Value> = Vec::with_capacity(components.len());

    for c in components {
        let purl_str = c.purl.as_str();
        let pkg_iri = format!("{doc_iri}/pkg-{}", hash_prefix(purl_str.as_bytes(), 16));
        package_iri_by_purl.insert(purl_str.to_string(), pkg_iri.clone());

        let mut pkg = serde_json::Map::new();
        pkg.insert("type".to_string(), json!("software_Package"));
        pkg.insert("spdxId".to_string(), json!(pkg_iri));
        pkg.insert("creationInfo".to_string(), json!(creation_info_id));
        pkg.insert("name".to_string(), json!(c.name));
        if !c.version.is_empty() {
            pkg.insert("software_packageVersion".to_string(), json!(c.version));
        }
        pkg.insert("software_packageUrl".to_string(), json!(purl_str));

        // verifiedUsing[] — Hash value-objects, one per integrity
        // checksum mikebom computed. SPDX 3's algorithm enum uses
        // lowercase-with-no-hyphen form (`sha256`, `sha1`, `md5`).
        // See `prop_Hash_algorithm` in the bundled schema.
        if !c.hashes.is_empty() {
            let mut hashes: Vec<Value> = c
                .hashes
                .iter()
                .map(|h| {
                    json!({
                        "type": "Hash",
                        "algorithm": spdx3_algorithm_name(h.algorithm),
                        "hashValue": h.value.as_str(),
                    })
                })
                .collect();
            // Deterministic ordering inside the array per
            // data-model.md §"Deterministic ordering rules".
            hashes.sort_by(|a, b| {
                let key = |v: &Value| -> (String, String) {
                    (
                        v["algorithm"].as_str().unwrap_or("").to_string(),
                        v["hashValue"].as_str().unwrap_or("").to_string(),
                    )
                };
                key(a).cmp(&key(b))
            });
            pkg.insert("verifiedUsing".to_string(), json!(hashes));
        }

        // software_homePage / software_sourceInfo / software_downloadLocation
        // — populated from the first matching CycloneDX
        // externalReferences entry per A9/A10/A11.
        for r in &c.external_references {
            match r.ref_type.as_str() {
                "homepage" | "website" => {
                    pkg.entry("software_homePage")
                        .or_insert_with(|| json!(r.url));
                }
                "vcs" => {
                    pkg.entry("software_sourceInfo")
                        .or_insert_with(|| json!(r.url));
                }
                "distribution" => {
                    pkg.entry("software_downloadLocation")
                        .or_insert_with(|| json!(r.url));
                }
                _ => {}
            }
        }

        // externalIdentifier[] — PURL (always one entry) plus any
        // fully-resolved CPE vectors. Delegated to
        // v3_external_ids::build_external_identifiers_for so the
        // shape is owned by one module.
        let ext_ids = build_external_identifiers_for(c);
        if !ext_ids.is_empty() {
            pkg.insert("externalIdentifier".to_string(), json!(ext_ids));
        }

        // suppliedBy / originatedBy — per-Package Agent attachments.
        // SPDX 3 puts these as Artifact_props properties, not
        // Relationship edges (unlike SPDX 2.3).
        if let Some(attach) = agent_attachments.get(&pkg_iri) {
            if let Some(iri) = &attach.supplied_by {
                pkg.insert("suppliedBy".to_string(), json!(iri));
            }
            if !attach.originated_by.is_empty() {
                pkg.insert("originatedBy".to_string(), json!(attach.originated_by));
            }
        }

        packages.push(Value::Object(pkg));
    }

    // Deterministic ordering by spdxId (data-model.md §"Deterministic
    // ordering rules").
    packages.sort_by(|a, b| {
        let key = |v: &Value| v["spdxId"].as_str().unwrap_or("").to_string();
        key(a).cmp(&key(b))
    });

    (packages, package_iri_by_purl)
}

/// Deterministic base32 prefix of SHA-256(input). Used for IRI path
/// segments. Identical to the helper in v3_stub.rs.
fn hash_prefix(input: &[u8], chars: usize) -> String {
    let digest = Sha256::digest(input);
    let encoded = BASE32_NOPAD.encode(&digest);
    encoded[..chars].to_string()
}

/// Convert a mikebom `HashAlgorithm` to the SPDX 3 `Hash.algorithm`
/// enum value (lowercase, no hyphens) per `prop_Hash_algorithm` in
/// the bundled schema.
fn spdx3_algorithm_name(algo: mikebom_common::types::hash::HashAlgorithm) -> &'static str {
    use mikebom_common::types::hash::HashAlgorithm;
    match algo {
        HashAlgorithm::Sha1 => "sha1",
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha512 => "sha512",
        HashAlgorithm::Md5 => "md5",
    }
}
