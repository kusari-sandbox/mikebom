//! OpenVEX 0.2.0 JSON sidecar emitter (milestone 010).
//!
//! Emitted next to the SPDX 2.3 file when a scan produces VEX
//! statements. Cross-referenced from the SPDX document via
//! `externalDocumentRefs` with `SHA256`. Not emitted when the scan
//! produces no VEX statements (FR-016a).
//!
//! Current status: mikebom's scan pipeline doesn't yet populate
//! `ResolvedComponent.advisories` anywhere — AdvisoryRef exists as
//! a data-model placeholder only. This emitter is therefore
//! scaffolding that fires a no-op for every present-day scan. The
//! moment a future milestone wires advisory discovery (OSV lookup,
//! NVD feed, etc.), the sidecar starts emitting without any change
//! to the SPDX serializer or the CLI surface.
//!
//! See [`statements`] for the typed model.

pub mod statements;

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Context;
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

use crate::generate::{EmittedArtifact, OutputConfig, ScanArtifacts};

use statements::{
    OpenVexDocument, OpenVexProduct, OpenVexStatement, OpenVexStatus,
    OpenVexVulnerability, OPENVEX_CONTEXT_V0_2_0,
};

/// Default sidecar filename. Kept in lockstep with the SPDX
/// serializer's `externalDocumentRefs` entry so a consumer reading
/// only the SPDX file can locate the sidecar.
pub const OPENVEX_DEFAULT_FILENAME: &str = "mikebom.openvex.json";

/// Length of the base32 prefix used in the `@id` URI — same
/// 160-bit budget as SPDX's `documentNamespace` (32 chars × 5 bits).
const ID_HASH_PREFIX_LEN: usize = 32;
const ID_BASE: &str = "https://mikebom.kusari.dev/openvex/";

/// Build the OpenVEX sidecar for a scan. Returns `Ok(None)` when the
/// scan has zero advisories across every component — no file is
/// then written and the SPDX serializer skips the
/// `externalDocumentRefs` entry.
pub fn serialize_openvex(
    artifacts: &ScanArtifacts<'_>,
    cfg: &OutputConfig,
) -> anyhow::Result<Option<EmittedArtifact>> {
    // Group advisories by id so one CVE that affects three
    // components emits one statement with three products[] — the
    // OpenVEX idiom, not three separate statements.
    let mut products_by_advisory: BTreeMap<String, Vec<OpenVexProduct>> =
        BTreeMap::new();
    for c in artifacts.components {
        for adv in &c.advisories {
            products_by_advisory
                .entry(adv.id.clone())
                .or_default()
                .push(OpenVexProduct {
                    id: c.purl.as_str().to_string(),
                });
        }
    }
    if products_by_advisory.is_empty() {
        return Ok(None);
    }

    // One statement per advisory id, products[] deduped within.
    // `under_investigation` is the status mikebom can honestly
    // emit today — the scanner has discovered the advisory but
    // hasn't produced an impact analysis. A future milestone's VEX
    // enrichment pass will widen the status mapping.
    let statements: Vec<OpenVexStatement> = products_by_advisory
        .into_iter()
        .map(|(id, mut products)| {
            products.sort_by(|a, b| a.id.cmp(&b.id));
            products.dedup_by(|a, b| a.id == b.id);
            OpenVexStatement {
                vulnerability: OpenVexVulnerability {
                    name: id,
                    description: None,
                    aliases: Vec::new(),
                },
                products,
                status: OpenVexStatus::UnderInvestigation,
                justification: None,
                impact_statement: None,
                action_statement: None,
            }
        })
        .collect();

    let author = format!("mikebom-{}", cfg.mikebom_version);
    let timestamp = cfg
        .created
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let id = derive_openvex_id(artifacts, cfg.mikebom_version);

    let doc = OpenVexDocument {
        context: OPENVEX_CONTEXT_V0_2_0,
        id,
        author: author.clone(),
        timestamp,
        version: 1,
        tooling: Some(author),
        statements,
    };

    let bytes = serde_json::to_string_pretty(&doc)
        .context("serializing OpenVEX document")?
        .into_bytes();

    Ok(Some(EmittedArtifact {
        relative_path: PathBuf::from(OPENVEX_DEFAULT_FILENAME),
        bytes,
    }))
}

/// Derive a stable `@id` URI from the same inputs the SPDX
/// `documentNamespace` uses — target name + mikebom version + sorted
/// component PURLs — plus a salt so the two IDs never collide.
fn derive_openvex_id(artifacts: &ScanArtifacts<'_>, mikebom_version: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"openvex-sidecar\n");
    hasher.update(b"target=");
    hasher.update(artifacts.target_name.as_bytes());
    hasher.update(b"\nmikebom=");
    hasher.update(mikebom_version.as_bytes());
    hasher.update(b"\npurls=");
    let mut purls: Vec<&str> =
        artifacts.components.iter().map(|c| c.purl.as_str()).collect();
    purls.sort_unstable();
    for p in purls {
        hasher.update(p.as_bytes());
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    let encoded = BASE32_NOPAD.encode(&digest);
    format!("{ID_BASE}{}", &encoded[..ID_HASH_PREFIX_LEN])
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::attestation::integrity::TraceIntegrity;
    use mikebom_common::attestation::metadata::GenerationContext;
    use mikebom_common::resolution::{
        AdvisoryRef, ResolutionEvidence, ResolutionTechnique, ResolvedComponent,
    };
    use mikebom_common::types::purl::Purl;

    fn mk_component(purl: &str) -> ResolvedComponent {
        ResolvedComponent {
            purl: Purl::new(purl).unwrap(),
            name: "x".to_string(),
            version: "1".to_string(),
            evidence: ResolutionEvidence {
                technique: ResolutionTechnique::UrlPattern,
                confidence: 0.9,
                source_connection_ids: vec![],
                source_file_paths: vec![],
                deps_dev_match: None,
            },
            licenses: vec![],
            concluded_licenses: vec![],
            hashes: vec![],
            supplier: None,
            cpes: vec![],
            advisories: vec![],
            occurrences: vec![],
            is_dev: None,
            requirement_range: None,
            source_type: None,
            sbom_tier: None,
            buildinfo_status: None,
            evidence_kind: None,
            binary_class: None,
            binary_stripped: None,
            linkage_kind: None,
            detected_go: None,
            confidence: None,
            binary_packed: None,
            npm_role: None,
            raw_version: None,
            parent_purl: None,
            co_owned_by: None,
            shade_relocation: None,
            external_references: Vec::new(),
        }
    }

    fn empty_integrity() -> TraceIntegrity {
        TraceIntegrity {
            ring_buffer_overflows: 0,
            events_dropped: 0,
            uprobe_attach_failures: vec![],
            kprobe_attach_failures: vec![],
            partial_captures: vec![],
            bloom_filter_capacity: 0,
            bloom_filter_false_positive_rate: 0.0,
        }
    }

    fn mk_cfg() -> OutputConfig {
        OutputConfig {
            mikebom_version: "0.0.0-test",
            created: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            overrides: std::collections::BTreeMap::new(),
        }
    }

    fn mk_artifacts<'a>(
        comps: &'a [ResolvedComponent],
        integ: &'a TraceIntegrity,
    ) -> ScanArtifacts<'a> {
        ScanArtifacts {
            target_name: "demo",
            components: comps,
            relationships: &[],
            integrity: integ,
            complete_ecosystems: &[],
            os_release_missing_fields: &[],
            scan_target_coord: None,
            generation_context: GenerationContext::FilesystemScan,
            include_dev: false,
            include_hashes: true,
            include_source_files: false,
        }
    }

    #[test]
    fn empty_scan_returns_none() {
        let integ = empty_integrity();
        let comps = vec![mk_component("pkg:cargo/a@1")];
        let arts = mk_artifacts(&comps, &integ);
        let result = serialize_openvex(&arts, &mk_cfg()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn scan_with_no_components_returns_none() {
        let integ = empty_integrity();
        let arts = mk_artifacts(&[], &integ);
        let result = serialize_openvex(&arts, &mk_cfg()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn one_advisory_produces_one_statement() {
        let mut c = mk_component("pkg:cargo/a@1");
        c.advisories = vec![AdvisoryRef {
            id: "CVE-2024-1234".to_string(),
            source: "osv".to_string(),
            url: None,
        }];
        let integ = empty_integrity();
        let comps = [c];
        let arts = mk_artifacts(&comps, &integ);
        let artifact = serialize_openvex(&arts, &mk_cfg()).unwrap().unwrap();
        assert_eq!(
            artifact.relative_path,
            std::path::PathBuf::from(OPENVEX_DEFAULT_FILENAME)
        );
        let doc: serde_json::Value = serde_json::from_slice(&artifact.bytes).unwrap();
        assert_eq!(doc["@context"], OPENVEX_CONTEXT_V0_2_0);
        assert!(doc["@id"].as_str().unwrap().starts_with(ID_BASE));
        assert_eq!(doc["version"], 1);
        assert_eq!(doc["author"], "mikebom-0.0.0-test");
        let stmts = doc["statements"].as_array().unwrap();
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0]["vulnerability"]["name"], "CVE-2024-1234");
        assert_eq!(stmts[0]["status"], "under_investigation");
        assert_eq!(stmts[0]["products"][0]["@id"], "pkg:cargo/a@1");
    }

    #[test]
    fn same_cve_across_two_components_emits_one_statement_with_two_products() {
        let mut c1 = mk_component("pkg:cargo/a@1");
        let mut c2 = mk_component("pkg:cargo/b@2");
        let adv = AdvisoryRef {
            id: "CVE-2024-5555".to_string(),
            source: "osv".to_string(),
            url: None,
        };
        c1.advisories = vec![adv.clone()];
        c2.advisories = vec![adv];
        let integ = empty_integrity();
        let comps = [c1, c2];
        let arts = mk_artifacts(&comps, &integ);
        let artifact = serialize_openvex(&arts, &mk_cfg()).unwrap().unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&artifact.bytes).unwrap();
        let stmts = doc["statements"].as_array().unwrap();
        assert_eq!(stmts.len(), 1, "one statement per CVE");
        let products = stmts[0]["products"].as_array().unwrap();
        assert_eq!(products.len(), 2);
        // Products are sorted alphabetically so re-runs are byte-stable.
        assert_eq!(products[0]["@id"], "pkg:cargo/a@1");
        assert_eq!(products[1]["@id"], "pkg:cargo/b@2");
    }

    #[test]
    fn two_cves_emit_two_statements_sorted_by_id() {
        let mut c = mk_component("pkg:cargo/a@1");
        c.advisories = vec![
            AdvisoryRef {
                id: "CVE-2024-0002".to_string(),
                source: "osv".to_string(),
                url: None,
            },
            AdvisoryRef {
                id: "CVE-2024-0001".to_string(),
                source: "osv".to_string(),
                url: None,
            },
        ];
        let integ = empty_integrity();
        let comps = [c];
        let arts = mk_artifacts(&comps, &integ);
        let artifact = serialize_openvex(&arts, &mk_cfg()).unwrap().unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&artifact.bytes).unwrap();
        let stmts = doc["statements"].as_array().unwrap();
        assert_eq!(stmts.len(), 2);
        // BTreeMap iteration is sorted, so CVE-0001 comes first.
        assert_eq!(stmts[0]["vulnerability"]["name"], "CVE-2024-0001");
        assert_eq!(stmts[1]["vulnerability"]["name"], "CVE-2024-0002");
    }

    #[test]
    fn id_is_deterministic_for_identical_inputs() {
        let mut c = mk_component("pkg:cargo/a@1");
        c.advisories = vec![AdvisoryRef {
            id: "CVE-X".to_string(),
            source: "osv".to_string(),
            url: None,
        }];
        let integ = empty_integrity();
        let comps = [c];
        let arts = mk_artifacts(&comps, &integ);
        let a = serialize_openvex(&arts, &mk_cfg()).unwrap().unwrap();
        let b = serialize_openvex(&arts, &mk_cfg()).unwrap().unwrap();
        let a_doc: serde_json::Value = serde_json::from_slice(&a.bytes).unwrap();
        let b_doc: serde_json::Value = serde_json::from_slice(&b.bytes).unwrap();
        assert_eq!(a_doc["@id"], b_doc["@id"]);
    }
}
