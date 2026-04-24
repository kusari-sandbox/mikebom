//! SPDX 3.0.1 minimal stub emitter — opt-in experimental (milestone
//! 010, T044).
//!
//! **Coverage**: npm only (research.md R3). Non-npm scans return a
//! document with zero Packages — the stub's job is to exercise the
//! format-dispatch layer against SPDX 3, not to replicate the 2.3
//! serializer's ecosystem coverage.
//!
//! **Output shape**: JSON-LD document at
//! `https://spdx.org/rdf/3.0.1/spdx-context.jsonld`, `@graph`
//! containing:
//!   - one `CreationInfo` element (referenced by every other element)
//!   - one `Tool` Agent for mikebom (the `createdBy`)
//!   - one `SpdxDocument` element naming the root
//!   - one `software_Package` per npm component
//!   - one `Relationship` per npm dependency edge
//!
//! **Experimental labeling**: every produced document carries the
//! literal string `"experimental"` in `comment` on both the
//! CreationInfo and SpdxDocument, so consumers reading the document
//! can tell it's a stub (FR-019b).

use data_encoding::BASE32_NOPAD;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use mikebom_common::resolution::{RelationshipType, ResolvedComponent};

use crate::generate::{OutputConfig, ScanArtifacts};

const SPDX_3_CONTEXT: &str = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld";
const IRI_BASE: &str = "https://mikebom.kusari.dev/spdx3/";
const EXPERIMENTAL_MARKER: &str =
    "EXPERIMENTAL SPDX 3.0.1 stub emitted by mikebom — npm ecosystem \
     only. See specs/010-spdx-output-support/ for the scope contract. \
     Not suitable for production consumers that need full SPDX 3 \
     fidelity.";

/// Build a minimal SPDX 3.0.1 JSON-LD document from a scan.
///
/// For non-npm scans, returns a document with zero `software_Package`
/// elements — still structurally valid, just empty. That's the
/// "stub coverage limitation" documented in the data-placement map.
///
/// Intentional scope limits (stub, NOT a full SPDX 3 emitter):
///   - Only `name`, `software_packageVersion`, `software_packageUrl`,
///     and `verifiedUsing` on Packages. Licenses are NOT emitted —
///     SPDX 3 expresses them as `Relationship { hasDeclaredLicense }`
///     edges to LicenseExpression elements, which roughly doubles
///     the stub's surface and is better deferred to a follow-up
///     milestone (see `docs/reference/sbom-format-mapping.md`).
///   - All `spdxId` values are real IRIs (not blank-node `_:` refs).
///     SPDX 3.0.1's schema restricts `spdxId` to IRI (pattern
///     `^(?!_:).+:.+`); `BlankNodeOrIRI` is only accepted on
///     `CreationInfo.@id`.
pub fn serialize_v3_stub(
    scan: &ScanArtifacts<'_>,
    cfg: &OutputConfig,
) -> anyhow::Result<Value> {
    let fingerprint = scan_fingerprint(scan, cfg);
    let doc_iri = format!("{IRI_BASE}doc-{fingerprint}");
    let tool_iri = format!("{doc_iri}/tool/mikebom");
    let creation_info_id = "_:creation-info";
    let created = cfg
        .created
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut graph: Vec<Value> = Vec::new();

    // CreationInfo — the one element whose id may be a blank
    // node per schema (`@id: BlankNodeOrIRI`). Referenced from
    // every other element via `creationInfo`. The comment carries
    // the `experimental` marker so T042 can assert on it.
    graph.push(json!({
        "type": "CreationInfo",
        "@id": creation_info_id,
        "specVersion": "3.0.1",
        "created": created,
        "createdBy": [tool_iri],
        "comment": EXPERIMENTAL_MARKER,
    }));

    // Tool Agent that produced the document. Must use a real IRI
    // in `spdxId` — blank nodes are rejected at the schema level.
    graph.push(json!({
        "type": "Tool",
        "spdxId": tool_iri,
        "creationInfo": creation_info_id,
        "name": format!("mikebom-{}", cfg.mikebom_version),
    }));

    // Filter components down to the npm ecosystem only (stub
    // coverage limitation — see module docs). Emit one Package
    // per eligible component.
    let npm_components: Vec<&ResolvedComponent> = scan
        .components
        .iter()
        .filter(|c| c.purl.as_str().starts_with("pkg:npm/"))
        .collect();

    let package_iri_by_purl: std::collections::BTreeMap<String, String> =
        npm_components
            .iter()
            .map(|c| {
                let iri = format!(
                    "{}/pkg-{}",
                    doc_iri,
                    hash_prefix(c.purl.as_str().as_bytes(), 16)
                );
                (c.purl.as_str().to_string(), iri)
            })
            .collect();

    for c in &npm_components {
        let pkg_iri = &package_iri_by_purl[c.purl.as_str()];
        let mut pkg = json!({
            "type": "software_Package",
            "spdxId": pkg_iri,
            "creationInfo": creation_info_id,
            "name": c.name,
            "software_packageVersion": c.version,
            "software_packageUrl": c.purl.as_str(),
        });
        if !c.hashes.is_empty() {
            let hashes: Vec<Value> = c
                .hashes
                .iter()
                .map(|h| {
                    json!({
                        "type": "Hash",
                        "algorithm": format!("{}", h.algorithm),
                        "hashValue": h.value.as_str(),
                    })
                })
                .collect();
            pkg["verifiedUsing"] = json!(hashes);
        }
        // License emission deliberately omitted — see module docs.
        graph.push(pkg);
    }

    // SpdxDocument — its rootElement names the npm-root package by
    // heuristic: a Package whose name matches the scan target, else
    // the first npm package (if any), else the document's own
    // spdxId (degenerate empty-scan case — document is still
    // structurally valid and the ref is a legal IRI).
    let root_element = choose_root(
        &npm_components,
        scan.target_name,
        &package_iri_by_purl,
        &doc_iri,
    );
    graph.push(json!({
        "type": "SpdxDocument",
        "spdxId": doc_iri,
        "creationInfo": creation_info_id,
        "name": scan.target_name,
        "rootElement": [root_element],
        "dataLicense": "https://spdx.org/licenses/CC0-1.0",
        "comment": EXPERIMENTAL_MARKER,
    }));

    // Relationship elements — one per npm dependency edge (both
    // endpoints in the npm package set). Edges crossing into
    // non-npm components are dropped (stub coverage limitation).
    for rel in scan.relationships {
        let Some(from_iri) = package_iri_by_purl.get(&rel.from) else {
            continue;
        };
        let Some(to_iri) = package_iri_by_purl.get(&rel.to) else {
            continue;
        };
        let (source_iri, target_iri, rel_type) = match rel.relationship_type {
            RelationshipType::DependsOn => (from_iri, to_iri, "dependsOn"),
            // SPDX 3 uses `devDependencyOf` as the camelCase of the
            // 2.3 DEV_DEPENDENCY_OF; same direction-reversal rule
            // as the 2.3 emitter.
            RelationshipType::DevDependsOn => (to_iri, from_iri, "devDependencyOf"),
            RelationshipType::BuildDependsOn => {
                (to_iri, from_iri, "buildDependencyOf")
            }
        };
        let rel_iri = format!(
            "{doc_iri}/rel-{}",
            hash_prefix(
                format!("{source_iri}|{rel_type}|{target_iri}").as_bytes(),
                16
            )
        );
        graph.push(json!({
            "type": "Relationship",
            "spdxId": rel_iri,
            "creationInfo": creation_info_id,
            "from": source_iri,
            "to": [target_iri],
            "relationshipType": rel_type,
        }));
    }

    Ok(json!({
        "@context": SPDX_3_CONTEXT,
        "@graph": graph,
    }))
}

/// Pick the SPDX 3 root element — preferred order: package whose
/// name matches `target_name`, else first npm package, else the
/// synthetic root-IRI literal.
fn choose_root(
    npm_components: &[&ResolvedComponent],
    target_name: &str,
    package_iri_by_purl: &std::collections::BTreeMap<String, String>,
    synthetic_root_iri: &str,
) -> String {
    if let Some(c) = npm_components.iter().find(|c| c.name == target_name) {
        return package_iri_by_purl[c.purl.as_str()].clone();
    }
    if let Some(c) = npm_components.first() {
        return package_iri_by_purl[c.purl.as_str()].clone();
    }
    synthetic_root_iri.to_string()
}

/// Deterministic base32 prefix of SHA-256(input). Used for
/// blank-node IDs and package IRI path segments.
fn hash_prefix(input: &[u8], chars: usize) -> String {
    let digest = Sha256::digest(input);
    let encoded = BASE32_NOPAD.encode(&digest);
    encoded[..chars].to_string()
}

/// Stable scan fingerprint — same inputs the SPDX 2.3
/// documentNamespace uses — so re-runs produce the same document
/// IRI.
fn scan_fingerprint(scan: &ScanArtifacts<'_>, cfg: &OutputConfig) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"spdx3-stub\n");
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
