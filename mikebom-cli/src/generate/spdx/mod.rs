//! SPDX output serializers (milestones 010 + 011).
//!
//! Two stable user-facing formats live here plus one deprecated
//! alias:
//!
//! * `spdx-2.3-json` — stable, covers all ecosystems supported by the
//!   CycloneDX path. See [`document`], [`packages`], [`relationships`].
//! * `spdx-3-json` — stable SPDX 3.0.1 JSON-LD emitter, full ecosystem
//!   coverage with mikebom-specific signal fidelity vs. the SPDX 2.3
//!   path. See [`v3_document`], [`v3_packages`], [`v3_relationships`],
//!   [`v3_licenses`], [`v3_agents`], [`v3_external_ids`],
//!   [`v3_annotations`].
//! * `spdx-3-json-experimental` — deprecated alias (milestone 010
//!   legacy). Delegates verbatim to the stable `spdx-3-json`
//!   serializer; byte-identical output; removed in milestone 013 per
//!   research.md §R2. Prints a stderr deprecation notice at
//!   invocation time via the CLI layer in `cli/scan_cmd.rs`.
//!
//! Mikebom-specific data without a native SPDX 2.3 / 3.0.1 home is
//! preserved losslessly via [`annotations`] (SPDX 2.3) and
//! [`v3_annotations`] (SPDX 3) using the same versioned JSON envelope
//! per `contracts/mikebom-annotation.schema.json`.
//!
//! The data-placement map in `docs/reference/sbom-format-mapping.md`
//! is the authoritative cross-format contract these serializers honor.

pub mod annotations;
pub mod document;
pub mod ids;
pub mod packages;
pub mod relationships;
pub mod v3_agents;
pub mod v3_annotations;
pub mod v3_document;
pub mod v3_external_ids;
pub mod v3_licenses;
pub mod v3_packages;
pub mod v3_relationships;

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

/// SPDX 3.0.1 stable serializer (milestone 011).
///
/// Full coverage across all 9 ecosystems mikebom supports
/// (apk, cargo, deb, gem, go, maven, npm, pip, rpm); produces a
/// schema-valid SPDX 3.0.1 JSON-LD document with native-field
/// parity vs. the CycloneDX serializer (PURL, name, version,
/// license, hash, supplier/originator) plus mikebom-specific
/// signal fidelity vs. the SPDX 2.3 serializer (every `mikebom:*`
/// field reaches SPDX 3 either as a typed native property or as
/// an `Annotation` element under the Q2 strict-match rule).
/// `experimental()` returns `false` — this is a first-class
/// production-grade output format.
pub struct Spdx3JsonSerializer;

impl SbomSerializer for Spdx3JsonSerializer {
    fn id(&self) -> &'static str {
        "spdx-3-json"
    }

    fn default_filename(&self) -> &'static str {
        "mikebom.spdx3.json"
    }

    fn experimental(&self) -> bool {
        false
    }

    fn serialize(
        &self,
        scan: &ScanArtifacts<'_>,
        cfg: &OutputConfig,
    ) -> anyhow::Result<Vec<EmittedArtifact>> {
        // Co-emit the OpenVEX sidecar when the scan produced at
        // least one advisory, mirroring the SPDX 2.3 path's
        // behavior (FR-013 — same shape, same default filename).
        // Build it first so the SPDX 3 document can cross-reference
        // it via an ExternalRef on the SpdxDocument element (FR-014
        // / clarification Q1).
        let openvex_artifact = crate::generate::openvex::serialize_openvex(scan, cfg)
            .context("building OpenVEX sidecar")?;
        let sidecar_locator: Option<String> = openvex_artifact.as_ref().map(|a| {
            cfg.overrides
                .get("openvex")
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| a.relative_path.to_string_lossy().into_owned())
        });

        let doc = v3_document::build_document(scan, cfg, sidecar_locator.as_deref())?;
        let bytes = serde_json::to_string_pretty(&doc)
            .context("serializing SPDX 3.0.1 document to JSON")?
            .into_bytes();
        let mut out = vec![EmittedArtifact {
            relative_path: PathBuf::from(self.default_filename()),
            bytes,
        }];
        if let Some(artifact) = openvex_artifact {
            out.push(artifact);
        }
        Ok(out)
    }
}

/// SPDX 3.0.1 deprecation-track alias (milestone 010 stub →
/// milestone 011 alias).
///
/// Per spec FR-002 + research.md §R6: this identifier was the
/// milestone-010 experimental stub. Milestone 011 retains it as a
/// deprecation alias that delegates to [`Spdx3JsonSerializer::serialize`]
/// verbatim — byte-identical output, same `mikebom.spdx3.json`
/// default filename, no comment-marker injection.
///
/// The deprecation signal is carried by the stderr notice (emitted
/// by the CLI dispatch layer in `cli/scan_cmd.rs`) plus the
/// help-text "[DEPRECATED]" annotation (via the
/// [`crate::generate::SbomSerializer`]-adjacent rendering in
/// `format_help_list`). `experimental()` returns `false` — the
/// alias output is production-grade (same bytes as the stable
/// emitter), it's the *identifier* that's on a deprecation path,
/// not the output quality.
///
/// Lifecycle: alias accepted through milestone 012; removed in
/// milestone 013 unless usage signals say otherwise (research.md
/// §R2).
pub struct Spdx3JsonExperimentalSerializer;

impl SbomSerializer for Spdx3JsonExperimentalSerializer {
    fn id(&self) -> &'static str {
        "spdx-3-json-experimental"
    }

    fn default_filename(&self) -> &'static str {
        // Deliberately the same as `Spdx3JsonSerializer` per
        // research.md §R6 — alias produces byte-identical output
        // including the on-disk filename when no `--output`
        // override is set.
        "mikebom.spdx3.json"
    }

    fn experimental(&self) -> bool {
        // False — the alias's output is byte-identical to the
        // stable emitter (production-grade), so the constitution's
        // experimental-labeling clause doesn't apply. The
        // lifecycle signal (deprecation) is carried by the help
        // text + stderr notice, NOT by the `experimental` trait
        // flag.
        false
    }

    fn serialize(
        &self,
        scan: &ScanArtifacts<'_>,
        cfg: &OutputConfig,
    ) -> anyhow::Result<Vec<EmittedArtifact>> {
        // Delegate verbatim to the stable serializer — byte-for-byte
        // identity is the FR-002 + research.md §R6 contract.
        Spdx3JsonSerializer.serialize(scan, cfg)
    }
}

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

    // ---- SPDX 3 ↔ OpenVEX cross-ref (milestone 011 T019) ---------

    fn parse_spdx3(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).expect("SPDX 3 bytes are valid JSON")
    }

    /// Find the single SpdxDocument element in an emitted SPDX 3
    /// document. Panics if absent — every document has one.
    fn find_spdx3_document(doc: &serde_json::Value) -> &serde_json::Value {
        doc["@graph"]
            .as_array()
            .expect("@graph array")
            .iter()
            .find(|e| e["type"] == "SpdxDocument")
            .expect("SpdxDocument element")
    }

    #[test]
    fn spdx3_no_vex_emits_no_external_ref_on_document() {
        let integ = empty_integrity();
        let comps = [mk_component("pkg:cargo/a@1", vec![])];
        let arts = mk_artifacts(&comps, &integ);
        let artifacts = Spdx3JsonSerializer.serialize(&arts, &mk_cfg()).unwrap();
        assert_eq!(
            artifacts.len(),
            1,
            "no advisories → SPDX 3 only, no sidecar artifact"
        );
        let spdx3 = parse_spdx3(&artifacts[0].bytes);
        let spdx_doc = find_spdx3_document(&spdx3);
        assert!(
            spdx_doc.get("externalRef").is_none(),
            "no advisories → SpdxDocument must have no externalRef entry; got {:?}",
            spdx_doc.get("externalRef")
        );
    }

    #[test]
    fn spdx3_with_vex_emits_sidecar_and_external_ref_on_document() {
        let integ = empty_integrity();
        let comps = [mk_component(
            "pkg:cargo/a@1",
            vec![AdvisoryRef {
                id: "CVE-2026-0003".to_string(),
                source: "osv".to_string(),
                url: None,
            }],
        )];
        let arts = mk_artifacts(&comps, &integ);
        let artifacts = Spdx3JsonSerializer.serialize(&arts, &mk_cfg()).unwrap();
        assert_eq!(
            artifacts.len(),
            2,
            "advisory present → SPDX 3 artifact + OpenVEX sidecar"
        );
        let (spdx3_art, vex_art) = match artifacts[0].relative_path.to_string_lossy().as_ref() {
            "mikebom.spdx3.json" => (&artifacts[0], &artifacts[1]),
            _ => (&artifacts[1], &artifacts[0]),
        };
        assert_eq!(
            spdx3_art.relative_path,
            std::path::PathBuf::from("mikebom.spdx3.json")
        );
        assert_eq!(
            vex_art.relative_path,
            std::path::PathBuf::from("mikebom.openvex.json")
        );

        let spdx3 = parse_spdx3(&spdx3_art.bytes);
        let spdx_doc = find_spdx3_document(&spdx3);
        let refs = spdx_doc["externalRef"]
            .as_array()
            .expect("externalRef present on SpdxDocument");
        assert_eq!(refs.len(), 1);
        let r = &refs[0];
        assert_eq!(r["type"], "ExternalRef");
        // Per research.md §R3 / data-model.md §"ExternalRef → OpenVEX
        // sidecar", we use the VEX-precise SPDX 3.0.1 enum value.
        assert_eq!(
            r["externalRefType"], "vulnerabilityExploitabilityAssessment"
        );
        assert_eq!(r["contentType"], "application/openvex+json");
        // `locator` is array-typed in the SPDX 3 vocabulary.
        assert_eq!(
            r["locator"],
            serde_json::json!(["mikebom.openvex.json"])
        );
    }

    #[test]
    fn spdx3_openvex_override_path_threads_into_external_ref() {
        let integ = empty_integrity();
        let comps = [mk_component(
            "pkg:cargo/a@1",
            vec![AdvisoryRef {
                id: "CVE-2026-0004".to_string(),
                source: "osv".to_string(),
                url: None,
            }],
        )];
        let arts = mk_artifacts(&comps, &integ);
        let mut cfg = mk_cfg();
        cfg.overrides.insert(
            "openvex".to_string(),
            std::path::PathBuf::from("./vex/out.json"),
        );
        let artifacts = Spdx3JsonSerializer.serialize(&arts, &cfg).unwrap();
        let spdx3 = parse_spdx3(
            artifacts
                .iter()
                .find(|a| a.relative_path == std::path::Path::new("mikebom.spdx3.json"))
                .map(|a| &a.bytes)
                .unwrap(),
        );
        let spdx_doc = find_spdx3_document(&spdx3);
        assert_eq!(
            spdx_doc["externalRef"][0]["locator"],
            serde_json::json!(["./vex/out.json"]),
            "user override path must appear in the SPDX 3 ExternalRef locator"
        );
    }

    #[test]
    fn spdx3_alias_bytes_are_byte_identical_to_stable() {
        // Contract §4 / research.md §R6: the alias delegates
        // verbatim to Spdx3JsonSerializer — byte-for-byte identical.
        let integ = empty_integrity();
        let comps = [mk_component("pkg:cargo/a@1", vec![])];
        let arts = mk_artifacts(&comps, &integ);
        let cfg = mk_cfg();
        let stable = Spdx3JsonSerializer.serialize(&arts, &cfg).unwrap();
        let alias = Spdx3JsonExperimentalSerializer
            .serialize(&arts, &cfg)
            .unwrap();
        assert_eq!(stable.len(), alias.len());
        for (s, a) in stable.iter().zip(alias.iter()) {
            assert_eq!(s.relative_path, a.relative_path);
            assert_eq!(
                s.bytes, a.bytes,
                "alias must emit byte-identical bytes for {:?}",
                s.relative_path
            );
        }
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
