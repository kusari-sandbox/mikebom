//! SPDX output serializers (milestone 010).
//!
//! Two user-facing formats live here:
//!
//! * `spdx-2.3-json` — stable, covers all ecosystems supported by the
//!   CycloneDX path. See [`document`], [`packages`], [`relationships`].
//! * `spdx-3-json-experimental` — opt-in stub covering one ecosystem
//!   (npm); targets SPDX 3.0.1 JSON-LD. See [`v3_stub`].
//!
//! Mikebom-specific data without a native SPDX 2.3 home is preserved
//! losslessly via [`annotations`] with a versioned JSON envelope per
//! `contracts/mikebom-annotation.schema.json`.
//!
//! The data-placement map in `docs/reference/sbom-format-mapping.md`
//! is the authoritative cross-format contract these serializers honor.

pub mod annotations;
pub mod document;
pub mod ids;
pub mod packages;
pub mod relationships;
pub mod v3_stub;

use std::path::PathBuf;

use anyhow::Context;

use super::{EmittedArtifact, OutputConfig, SbomSerializer, ScanArtifacts};

/// SPDX 2.3 JSON serializer (T026).
///
/// Produces a document under the default filename `mikebom.spdx.json`.
/// Determinism is guaranteed by construction: the document's
/// `creationInfo.created` is taken from [`OutputConfig::created`] and
/// the `documentNamespace` is a SHA-256 hash of scan content; no
/// `Utc::now()` / `Uuid::new_v4()` inside the serialization path.
pub struct Spdx2_3JsonSerializer;

impl SbomSerializer for Spdx2_3JsonSerializer {
    fn id(&self) -> &'static str {
        "spdx-2.3-json"
    }

    fn default_filename(&self) -> &'static str {
        "mikebom.spdx.json"
    }

    fn serialize(
        &self,
        scan: &ScanArtifacts<'_>,
        cfg: &OutputConfig,
    ) -> anyhow::Result<Vec<EmittedArtifact>> {
        let mut doc = document::build_document(scan, cfg);

        // T037 — co-emit the OpenVEX sidecar when the scan produces
        // advisories. The cross-reference in the SPDX document's
        // `externalDocumentRefs` has to name the sidecar's relative
        // path and the SHA-256 of its bytes, so we build the sidecar
        // FIRST and then inject the reference before serializing the
        // SPDX document. When there are no advisories the sidecar is
        // skipped entirely — no cross-reference, no file written —
        // per FR-016a.
        let openvex_artifact = crate::generate::openvex::serialize_openvex(scan, cfg)
            .context("building OpenVEX sidecar")?;
        if let Some(ref artifact) = openvex_artifact {
            let hex_sha256 = sha256_hex(&artifact.bytes);
            // The cross-reference path must name where the sidecar
            // actually lands on disk. When the user has set
            // `--output openvex=<path>`, the CLI layer will write
            // the sidecar there — cfg.overrides carries that path
            // through so the SPDX document and the filesystem
            // agree on one string.
            let sidecar_path = cfg
                .overrides
                .get("openvex")
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| {
                    artifact.relative_path.to_string_lossy().into_owned()
                });
            doc.external_document_refs.push(
                document::SpdxExternalDocumentRef {
                    id: "DocumentRef-OpenVEX".to_string(),
                    spdx_document: sidecar_path,
                    checksum: packages::SpdxChecksum {
                        algorithm: packages::SpdxChecksumAlgorithm::SHA256,
                        value: hex_sha256,
                    },
                },
            );
        }

        let json_str = serde_json::to_string_pretty(&doc)
            .context("serializing SPDX 2.3 document to JSON")?;
        let mut out = vec![EmittedArtifact {
            relative_path: PathBuf::from(self.default_filename()),
            bytes: json_str.into_bytes(),
        }];
        if let Some(artifact) = openvex_artifact {
            out.push(artifact);
        }
        Ok(out)
    }
}

/// Lower-case hex SHA-256 of the given bytes. Used for the
/// `externalDocumentRefs.checksum.checksumValue` field per SPDX
/// 2.3 §6.6 (the value MUST match the linked document's bytes).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    //! Tests for the SPDX ↔ OpenVEX sidecar co-emit path (T030/T037).
    //! mikebom's scan pipeline doesn't populate `AdvisoryRef` anywhere
    //! today, so the only way to exercise the emit-with-VEX branch is
    //! to hand-build a `ScanArtifacts` with synthetic advisories. When
    //! the scanner grows a VEX-enrichment path later, these tests keep
    //! guarding the same contract via direct serializer calls.
    use super::*;
    use mikebom_common::attestation::integrity::TraceIntegrity;
    use mikebom_common::attestation::metadata::GenerationContext;
    use mikebom_common::resolution::{
        AdvisoryRef, ResolutionEvidence, ResolutionTechnique, ResolvedComponent,
    };
    use mikebom_common::types::purl::Purl;

    fn mk_component(purl: &str, advisories: Vec<AdvisoryRef>) -> ResolvedComponent {
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
            advisories,
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

    fn parse_spdx(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).expect("SPDX bytes are valid JSON")
    }

    #[test]
    fn spdx_no_vex_emits_no_sidecar_and_no_external_doc_refs() {
        let integ = empty_integrity();
        let comps = [mk_component("pkg:cargo/a@1", vec![])];
        let arts = mk_artifacts(&comps, &integ);
        let artifacts =
            Spdx2_3JsonSerializer.serialize(&arts, &mk_cfg()).unwrap();
        assert_eq!(
            artifacts.len(),
            1,
            "no advisories → SPDX only, no sidecar artifact"
        );
        let spdx = parse_spdx(&artifacts[0].bytes);
        // externalDocumentRefs is `skip_serializing_if = "Vec::is_empty"`, so
        // its absence is the expected shape when there are no cross-refs.
        assert!(
            spdx.get("externalDocumentRefs").is_none(),
            "no advisories → no externalDocumentRefs entry"
        );
    }

    #[test]
    fn spdx_with_vex_emits_sidecar_and_cross_reference() {
        let integ = empty_integrity();
        let comps = [mk_component(
            "pkg:cargo/a@1",
            vec![AdvisoryRef {
                id: "CVE-2026-0001".to_string(),
                source: "osv".to_string(),
                url: None,
            }],
        )];
        let arts = mk_artifacts(&comps, &integ);
        let artifacts =
            Spdx2_3JsonSerializer.serialize(&arts, &mk_cfg()).unwrap();
        assert_eq!(
            artifacts.len(),
            2,
            "advisory present → SPDX artifact + OpenVEX sidecar"
        );
        let (spdx_art, vex_art) = match artifacts[0].relative_path.to_string_lossy().as_ref() {
            "mikebom.spdx.json" => (&artifacts[0], &artifacts[1]),
            _ => (&artifacts[1], &artifacts[0]),
        };
        assert_eq!(
            spdx_art.relative_path,
            std::path::PathBuf::from("mikebom.spdx.json")
        );
        assert_eq!(
            vex_art.relative_path,
            std::path::PathBuf::from("mikebom.openvex.json")
        );

        let spdx = parse_spdx(&spdx_art.bytes);
        let refs = spdx["externalDocumentRefs"]
            .as_array()
            .expect("externalDocumentRefs present");
        assert_eq!(refs.len(), 1);
        let r = &refs[0];
        assert_eq!(r["externalDocumentId"], "DocumentRef-OpenVEX");
        assert_eq!(r["spdxDocument"], "mikebom.openvex.json");
        assert_eq!(r["checksum"]["algorithm"], "SHA256");
        // The checksum MUST match the sidecar bytes — if this drifts
        // a consumer would integrity-check and reject the sidecar.
        assert_eq!(
            r["checksum"]["checksumValue"],
            sha256_hex(&vex_art.bytes)
        );
    }

    #[test]
    fn openvex_override_path_threads_into_external_doc_refs() {
        let integ = empty_integrity();
        let comps = [mk_component(
            "pkg:cargo/a@1",
            vec![AdvisoryRef {
                id: "CVE-2026-0002".to_string(),
                source: "osv".to_string(),
                url: None,
            }],
        )];
        let arts = mk_artifacts(&comps, &integ);
        let mut cfg = mk_cfg();
        cfg.overrides
            .insert("openvex".to_string(), std::path::PathBuf::from("./vex/out.json"));
        let artifacts =
            Spdx2_3JsonSerializer.serialize(&arts, &cfg).unwrap();
        let spdx = parse_spdx(
            artifacts
                .iter()
                .find(|a| a.relative_path == std::path::Path::new("mikebom.spdx.json"))
                .map(|a| &a.bytes)
                .unwrap(),
        );
        assert_eq!(
            spdx["externalDocumentRefs"][0]["spdxDocument"],
            "./vex/out.json",
            "user override path must appear in the SPDX cross-reference"
        );
    }
}
