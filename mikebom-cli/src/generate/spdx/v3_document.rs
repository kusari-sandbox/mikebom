//! SPDX 3.0.1 JSON-LD document builder (milestone 011).
//!
//! Top-level entry point — composes Packages, Relationships,
//! LicenseExpressions, Agents, Annotations, and the SpdxDocument
//! root element into one `@graph`. Per `data-model.md` §"Element
//! catalog" + §"Deterministic ordering rules".
//!
//! See `specs/011-spdx-3-full-support/data-model.md` for the
//! authoritative element catalog.

use data_encoding::BASE32_NOPAD;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use mikebom_common::resolution::ResolvedComponent;

use crate::generate::{OutputConfig, ScanArtifacts};

const SPDX_3_CONTEXT: &str = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld";
const IRI_BASE: &str = "https://mikebom.kusari.dev/spdx3/";
const CREATION_INFO_ID: &str = "_:creation-info";

/// Build a complete SPDX 3.0.1 JSON-LD document from a scan.
///
/// `@graph` ordering (data-model.md §"Deterministic ordering rules"):
/// 1. CreationInfo (single)
/// 2. Tool
/// 3. SpdxDocument
/// 4. software_Package elements (sorted by spdxId)
/// 5. Organization / Person elements (sorted by spdxId)
/// 6. simplelicensing_LicenseExpression elements (sorted by spdxId)
/// 7. Relationship elements (sorted by spdxId)
/// 8. Annotation elements (sorted by spdxId) — milestone 011 US2
pub fn build_document(
    scan: &ScanArtifacts<'_>,
    cfg: &OutputConfig,
) -> anyhow::Result<Value> {
    let fingerprint = scan_fingerprint(scan, cfg);
    let doc_iri = format!("{IRI_BASE}doc-{fingerprint}");
    let tool_iri = format!("{doc_iri}/tool/mikebom");
    let created = cfg
        .created
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut graph: Vec<Value> = Vec::new();

    // 1. CreationInfo.
    graph.push(json!({
        "type": "CreationInfo",
        "@id": CREATION_INFO_ID,
        "specVersion": "3.0.1",
        "created": created,
        "createdBy": [tool_iri],
    }));

    // 2. Tool.
    graph.push(json!({
        "type": "Tool",
        "spdxId": tool_iri,
        "creationInfo": CREATION_INFO_ID,
        "name": format!("mikebom-{}", cfg.mikebom_version),
    }));

    // Two-pass Package build: (a) precompute the PURL → IRI
    // lookup, (b) build agents against the lookup, (c) build
    // Packages with agent attachments inlined.
    let package_iri_by_purl =
        super::v3_packages::build_iri_lookup(scan.components, &doc_iri);

    let agent_build = super::v3_agents::build_agents(
        scan.components,
        &package_iri_by_purl,
        &doc_iri,
        CREATION_INFO_ID,
    );

    let (mut packages, _) = super::v3_packages::build_packages(
        scan.components,
        &doc_iri,
        CREATION_INFO_ID,
        &agent_build.attachments,
    );

    // Choose root element. If no Package matches the scan target
    // and the scan is non-empty, fall back to the first Package.
    // Empty-scan case: synthesize a root Package so the document
    // is still structurally valid (matches SPDX 2.3 path's
    // synthesize-root behavior for sbomqs parity).
    let (root_iri, synthetic_root_added) = pick_root_iri(
        scan,
        &doc_iri,
        &package_iri_by_purl,
        &mut packages,
        scan.components,
    );

    // 3. SpdxDocument (placed in the graph before the per-element
    // sections so a JSON-walker reading top-down hits the document
    // shape early).
    graph.push(json!({
        "type": "SpdxDocument",
        "spdxId": doc_iri,
        "creationInfo": CREATION_INFO_ID,
        "name": scan.target_name,
        "dataLicense": "https://spdx.org/licenses/CC0-1.0",
        "rootElement": [root_iri],
    }));

    // 4 (cont). Append the Package elements.
    for pkg in packages {
        graph.push(pkg);
    }

    // 5. Organization / Person Agent elements. (Supplier/originator
    //    attachments are already inlined on Packages above; no
    //    Relationship edges needed — SPDX 3 puts these as
    //    Artifact_props fields.)
    for agent in agent_build.elements {
        graph.push(agent);
    }

    // 6. simplelicensing_LicenseExpression elements + their
    //    Relationships.
    let (license_elements, license_relationships) =
        super::v3_licenses::build_license_elements_and_relationships(
            scan.components,
            &package_iri_by_purl,
            &doc_iri,
            CREATION_INFO_ID,
        );
    for elem in license_elements {
        graph.push(elem);
    }

    // 7. Relationship elements — dependency edges, containment edges,
    //    license/agent edges, document-describes edge. Combined into
    //    one bucket so they sort together by spdxId.
    let mut all_relationships: Vec<Value> = Vec::new();
    all_relationships.extend(super::v3_relationships::build_dependency_relationships(
        scan.relationships,
        &package_iri_by_purl,
        &doc_iri,
        CREATION_INFO_ID,
    ));
    all_relationships.extend(super::v3_relationships::build_containment_relationships(
        scan.components,
        &package_iri_by_purl,
        &doc_iri,
        CREATION_INFO_ID,
    ));
    all_relationships.extend(license_relationships);
    if !synthetic_root_added {
        if let Some(describes) = super::v3_relationships::build_describes_relationship(
            &doc_iri,
            &root_iri,
            CREATION_INFO_ID,
        ) {
            all_relationships.push(describes);
        }
    }
    all_relationships.sort_by(|a, b| {
        let key = |v: &Value| v["spdxId"].as_str().unwrap_or("").to_string();
        key(a).cmp(&key(b))
    });
    for rel in all_relationships {
        graph.push(rel);
    }

    // 8. Annotation elements — milestone 011 US2 (T020-T024).

    Ok(json!({
        "@context": SPDX_3_CONTEXT,
        "@graph": graph,
    }))
}

/// Pick the root Package IRI. Preference order:
/// 1. A Package whose name matches `scan.target_name`.
/// 2. The first Package in the (already sorted) packages list.
/// 3. Synthesize a root Package and prepend it — used for the
///    empty-scan case + the scan-target-isn't-a-package case
///    (e.g., scanning a directory whose name doesn't match any
///    discovered component).
///
/// Returns `(root_iri, synthetic_root_added)`.
fn pick_root_iri(
    scan: &ScanArtifacts<'_>,
    doc_iri: &str,
    package_iri_by_purl: &std::collections::BTreeMap<String, String>,
    packages: &mut Vec<Value>,
    components: &[ResolvedComponent],
) -> (String, bool) {
    if let Some(c) = components.iter().find(|c| c.name == scan.target_name) {
        if let Some(iri) = package_iri_by_purl.get(c.purl.as_str()) {
            return (iri.clone(), false);
        }
    }

    // Synthesize a root Package. Mirrors the SPDX 2.3 emitter's
    // synthesize_root behavior — preserves sbomqs scoring parity
    // (a document with no rootElement scores worse).
    let synth_purl = format!("pkg:generic/{}@0.0.0", url_friendly(scan.target_name));
    let synth_iri = format!(
        "{doc_iri}/pkg-root-{}",
        hash_prefix(synth_purl.as_bytes(), 16)
    );
    let synth_cpe = format!(
        "cpe:2.3:a:mikebom:{}:0.0.0:*:*:*:*:*:*:*",
        url_friendly(scan.target_name)
    );
    let synth_pkg = json!({
        "type": "software_Package",
        "spdxId": synth_iri,
        "creationInfo": CREATION_INFO_ID,
        "name": scan.target_name,
        "software_packageVersion": "0.0.0",
        "software_packageUrl": synth_purl,
        "externalIdentifier": [
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": "cpe23",
                "identifier": synth_cpe,
            },
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": "packageUrl",
                "identifier": synth_purl,
            },
        ],
    });
    packages.insert(0, synth_pkg);
    (synth_iri, true)
}

/// Replace characters that aren't legal in a PURL name with `-`.
fn url_friendly(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn hash_prefix(input: &[u8], chars: usize) -> String {
    let digest = Sha256::digest(input);
    let encoded = BASE32_NOPAD.encode(&digest);
    encoded[..chars].to_string()
}

/// Stable scan fingerprint — same inputs the SPDX 2.3
/// `documentNamespace` and the milestone-010 stub use, so re-runs
/// produce the same document IRI (FR-015 / SC-006).
fn scan_fingerprint(scan: &ScanArtifacts<'_>, cfg: &OutputConfig) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"spdx3\n");
    hasher.update(b"target=");
    hasher.update(scan.target_name.as_bytes());
    hasher.update(b"\nmikebom=");
    hasher.update(cfg.mikebom_version.as_bytes());
    hasher.update(b"\npurls=");
    let mut purls: Vec<&str> =
        scan.components.iter().map(|c| c.purl.as_str()).collect();
    purls.sort_unstable();
    for p in purls {
        hasher.update(p.as_bytes());
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    BASE32_NOPAD.encode(&digest)[..24].to_string()
}
