//! SPDX 2.3 document envelope + documentNamespace newtype
//! (milestone 010, T019 / T020 / T025).
//!
//! SPDX 2.3 §6.5 requires each document to declare a
//! `documentNamespace` URI that is globally unique for its content —
//! "A unique document identifier in the form of a URI that enables
//! the document to be referenced externally." We derive it
//! deterministically from scan inputs so two runs of the same scan
//! produce the same namespace (FR-020 / SC-007), and two different
//! scans produce different namespaces (so two SBOMs for two
//! different projects never collide).

use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

use super::ids::SpdxId;
use super::packages::SpdxPackage;
use super::relationships::SpdxRelationship;
use crate::generate::ScanArtifacts;

/// Length of the base32-encoded hash prefix used in the
/// documentNamespace URI. 32 chars × 5 bits = 160 bits of entropy.
/// Longer than the Package-ID prefix because the namespace is
/// document-global and participates in cross-document cross-references
/// — a collision here would silently merge two unrelated SBOMs.
const NAMESPACE_HASH_PREFIX_LEN: usize = 32;

const NAMESPACE_BASE: &str = "https://mikebom.kusari.dev/spdx/";

/// SPDX 2.3 document namespace URI (research.md R8).
///
/// Scheme: `https://mikebom.kusari.dev/spdx/<hash>` where `<hash>` is
/// the base32-encoded SHA-256 of:
///   * the scan target description (`ScanArtifacts::target_name`),
///   * the mikebom version string,
///   * the sorted set of component PURLs in the scan result.
///
/// Storing the target name + version separately means a scan of the
/// same tree under a different target name (e.g. via CI job renames)
/// produces a distinct namespace — that's desirable: two CI-runs of
/// different names are semantically different documents even if the
/// component set is identical.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct SpdxDocumentNamespace(String);

impl SpdxDocumentNamespace {
    /// Derive the namespace URI from a scan.
    ///
    /// Inputs folded into the hash are appended in a stable order
    /// (target, version, then PURLs pre-sorted) so the output does
    /// not depend on component-discovery ordering.
    pub fn derive(artifacts: &ScanArtifacts<'_>, mikebom_version: &str) -> Self {
        let mut hasher = Sha256::new();
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
        let prefix = &encoded[..NAMESPACE_HASH_PREFIX_LEN];
        SpdxDocumentNamespace(format!("{NAMESPACE_BASE}{prefix}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SPDX 2.3 annotation type enum (spec §8.6).
///
/// Mikebom uses `OTHER` for its namespaced JSON-comment envelopes
/// (FR-016 fallback for `mikebom:*` properties). `REVIEW` is reserved
/// for human-curated annotations and is not produced automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
#[allow(dead_code)]
pub enum SpdxAnnotationType {
    Other,
    Review,
}

/// One SPDX 2.3 annotation. The `comment` field carries the
/// serialized `MikebomAnnotationCommentV1` JSON envelope for
/// mikebom-specific data (US2). Empty in US1 — [`SpdxPackage`] and
/// [`SpdxDocument`] both default to an empty annotations list and
/// the US2 phase populates them without touching the envelope shape.
#[derive(Debug, Clone, serde::Serialize)]
#[allow(dead_code)]
pub struct SpdxAnnotation {
    pub annotator: String,
    #[serde(rename = "annotationDate")]
    pub date: String,
    #[serde(rename = "annotationType")]
    pub kind: SpdxAnnotationType,
    pub comment: String,
}

/// SPDX 2.3 external document reference. Populated by the
/// OpenVEX-sidecar co-emission path in
/// [`super::Spdx2_3JsonSerializer::serialize`] per FR-016a — the
/// entry names the sidecar's relative path and a SHA-256 of its
/// bytes so a consumer reading only the SPDX file can locate and
/// integrity-check the sidecar.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpdxExternalDocumentRef {
    #[serde(rename = "externalDocumentId")]
    pub id: String,
    #[serde(rename = "spdxDocument")]
    pub spdx_document: String,
    pub checksum: super::packages::SpdxChecksum,
}

/// SPDX 2.3 `creationInfo` object (spec §6.8 / §6.9).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CreationInfo {
    /// RFC 3339 UTC timestamp — sourced from `OutputConfig.created`,
    /// never `Utc::now()` (determinism contract, data-model §8).
    pub created: String,
    /// `["Tool: mikebom-<version>"]` at minimum. Experimental
    /// formats append a label to the tool creator string so
    /// consumers reading the document can see it's a stub (FR-019b).
    pub creators: Vec<String>,
    #[serde(rename = "licenseListVersion", skip_serializing_if = "Option::is_none")]
    pub license_list_version: Option<String>,
}

/// SPDX 2.3 top-level document (spec §6).
///
/// Field ordering follows the spec's table-of-contents order so the
/// emitted JSON matches common reader expectations. Omitted fields
/// use `serde(skip_serializing_if)` rather than `Option<Vec<_>>` to
/// keep the builder API simple.
#[derive(Debug, serde::Serialize)]
pub struct SpdxDocument {
    #[serde(rename = "spdxVersion")]
    pub spdx_version: &'static str,
    #[serde(rename = "dataLicense")]
    pub data_license: &'static str,
    #[serde(rename = "SPDXID")]
    pub spdx_id: SpdxId,
    pub name: String,
    #[serde(rename = "documentNamespace")]
    pub namespace: SpdxDocumentNamespace,
    #[serde(rename = "creationInfo")]
    pub creation_info: CreationInfo,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<SpdxPackage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<SpdxRelationship>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<SpdxAnnotation>,
    #[serde(
        rename = "externalDocumentRefs",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub external_document_refs: Vec<SpdxExternalDocumentRef>,
    #[serde(rename = "documentDescribes")]
    pub document_describes: Vec<SpdxId>,
}

/// Assemble the SPDX 2.3 document envelope from a scan.
///
/// (T025) Picks a deterministic root: if the scan carries exactly
/// one top-level component (no `parent_purl` on that entry, nothing
/// else top-level), that component is the `documentDescribes`
/// target; otherwise a synthetic `SPDXRef-DOCUMENT-ROOT`-style
/// Package is synthesized so consumers always have exactly one
/// described root (spec edge case "Multiple roots / no root").
///
/// The synthetic-root path is exercised by the pip + gem + deb +
/// apk fixtures which each have multiple independent components but
/// no single scan-target coord.
pub fn build_document(
    artifacts: &ScanArtifacts<'_>,
    cfg: &crate::generate::OutputConfig,
) -> SpdxDocument {
    let namespace = SpdxDocumentNamespace::derive(artifacts, cfg.mikebom_version);

    // Single annotator + date pair used across every annotation
    // emitted from this scan: Package-level (from `build_packages`)
    // and Document-level (from `annotate_document`). Both mirror
    // the first `CreationInfo.creators` entry + `created` value so
    // a consumer can see that annotations were produced in the
    // same run as the document.
    let annotator = format!("Tool: mikebom-{}", cfg.mikebom_version);
    let date = cfg
        .created
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let packages =
        super::packages::build_packages(artifacts, &annotator, &date);

    // Root selection: deterministic single-root algorithm.
    //   1. If a top-level component (no parent_purl) carries a PURL
    //      whose name matches `artifacts.target_name`, use that.
    //   2. Else if exactly one top-level component exists, use it.
    //   3. Else synthesize a root package and prepend it.
    let top_level: Vec<usize> = artifacts
        .components
        .iter()
        .enumerate()
        .filter(|(_, c)| c.parent_purl.is_none())
        .map(|(i, _)| i)
        .collect();

    let (root_id, synthetic_root) = match top_level.len() {
        0 => {
            let (id, root) = synthesize_root(artifacts.target_name, &namespace);
            (id, Some(root))
        }
        1 => {
            let idx = top_level[0];
            let purl = &artifacts.components[idx].purl;
            (SpdxId::for_purl(purl), None)
        }
        _ => {
            // Prefer a top-level component whose name matches the
            // scan target exactly. Otherwise synthesize.
            if let Some(idx) = top_level.iter().find(|&&i| {
                artifacts.components[i].name == artifacts.target_name
            }) {
                let purl = &artifacts.components[*idx].purl;
                (SpdxId::for_purl(purl), None)
            } else {
                let (id, root) = synthesize_root(artifacts.target_name, &namespace);
                (id, Some(root))
            }
        }
    };

    // Prepend the synthetic-root package (if any) so it precedes
    // every component-derived package in the output.
    let mut packages = packages;
    if let Some(root_pkg) = synthetic_root {
        packages.insert(0, root_pkg);
    }

    let relationships =
        super::relationships::build_relationships(artifacts, &root_id);

    // Two creator entries: a `Tool:` identifying mikebom (used
    // throughout the document as the `annotator` field on every
    // annotation we emit), plus an `Organization:` identifying the
    // mikebom project as the SBOM's sbomqs-facing author.
    // sbomqs's `sbom_authors` feature checks for a non-Tool creator
    // — giving it an Organization entry mirrors what CDX emits in
    // `metadata.supplier` + `metadata.authors` and closes the
    // cross-format sbomqs Provenance gap.
    let creation_info = CreationInfo {
        created: date.clone(),
        creators: vec![
            annotator.clone(),
            "Organization: mikebom contributors".to_string(),
        ],
        license_list_version: None,
    };

    // Document-level mikebom annotations (Sections C21–C23 + E1).
    let annotations =
        super::annotations::annotate_document(&annotator, &date, artifacts);

    SpdxDocument {
        spdx_version: "SPDX-2.3",
        data_license: "CC0-1.0",
        spdx_id: SpdxId::document(),
        name: artifacts.target_name.to_string(),
        namespace,
        creation_info,
        packages,
        relationships,
        annotations,
        external_document_refs: Vec::new(),
        document_describes: vec![root_id],
    }
}

/// Deterministically derive a synthetic-root SPDXID and a
/// placeholder Package for it. Used when the scan has no natural
/// single root (multi-project trees, image scans, empty scans).
fn synthesize_root(
    target_name: &str,
    namespace: &SpdxDocumentNamespace,
) -> (SpdxId, SpdxPackage) {
    use super::packages::{
        SpdxExternalRef, SpdxExternalRefCategory, SpdxLicenseField,
    };

    // Stable SPDXID for the synthetic root: hash the namespace URI
    // (already scan-derived + mikebom-version-stamped) plus a fixed
    // salt so it cannot collide with a PURL-derived package ID.
    let mut hasher = Sha256::new();
    hasher.update(b"synthetic-root\n");
    hasher.update(namespace.as_str().as_bytes());
    let digest = hasher.finalize();
    let encoded = BASE32_NOPAD.encode(&digest);
    let id = SpdxId::synthetic_root(&encoded[..16]);

    // Synthesize identity externalRefs for the synthetic root so
    // sbomqs's Vulnerability/comp_with_purl + comp_with_cpe features
    // don't ding every mikebom SPDX document for "one component is
    // missing PURL/CPE" (the synthetic root is the one component).
    // The PURL uses `pkg:generic/<target>@0.0.0` — the same shape
    // CDX uses for the scan-subject metadata.component. The CPE
    // mirrors `metadata.component.cpe` in CDX. Both are synthetic
    // but spec-valid; consumers that want a real PURL/CPE look at
    // the component-level Packages, not the root.
    let sanitized = sanitize_for_coord(target_name);
    let version = "0.0.0";
    let synth_purl = format!("pkg:generic/{sanitized}@{version}");
    let synth_cpe =
        format!("cpe:2.3:a:mikebom:{sanitized}:{version}:*:*:*:*:*:*:*");

    let root = SpdxPackage {
        spdx_id: id.clone(),
        name: target_name.to_string(),
        version_info: version.to_string(),
        download_location: "NOASSERTION".to_string(),
        supplier: Some("Organization: mikebom contributors".to_string()),
        originator: None,
        files_analyzed: false,
        checksums: Vec::new(),
        license_declared: SpdxLicenseField::NoAssertion,
        license_concluded: SpdxLicenseField::NoAssertion,
        copyright_text: None,
        external_refs: vec![
            SpdxExternalRef {
                category: SpdxExternalRefCategory::PackageManager,
                ref_type: "purl".to_string(),
                locator: synth_purl,
            },
            SpdxExternalRef {
                category: SpdxExternalRefCategory::Security,
                ref_type: "cpe23Type".to_string(),
                locator: synth_cpe,
            },
        ],
        annotations: Vec::new(),
    };
    (id, root)
}

/// Normalize a target-name string for inclusion in a PURL/CPE
/// coord. Matches the loose shape CDX uses for its synthesized
/// scan-subject PURL (see `metadata.rs::cpe_sanitize`): lowercase
/// ASCII alphanumerics + `_` / `-` / `.` preserved; everything
/// else collapses to `_`.
fn sanitize_for_coord(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::attestation::integrity::TraceIntegrity;
    use mikebom_common::attestation::metadata::GenerationContext;
    use mikebom_common::resolution::{
        ResolutionEvidence, ResolutionTechnique, ResolvedComponent,
    };
    use mikebom_common::types::purl::Purl;

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

    fn mk_component(purl: &str, name: &str, version: &str) -> ResolvedComponent {
        ResolvedComponent {
            purl: Purl::new(purl).unwrap(),
            name: name.to_string(),
            version: version.to_string(),
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

    fn mk_artifacts<'a>(
        target_name: &'a str,
        components: &'a [ResolvedComponent],
        relationships: &'a [mikebom_common::resolution::Relationship],
        integrity: &'a TraceIntegrity,
    ) -> ScanArtifacts<'a> {
        ScanArtifacts {
            target_name,
            components,
            relationships,
            integrity,
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
    fn namespace_is_deterministic_for_identical_inputs() {
        let components = vec![mk_component("pkg:cargo/a@1", "a", "1")];
        let integ = empty_integrity();
        let a = SpdxDocumentNamespace::derive(
            &mk_artifacts("demo", &components, &[], &integ),
            "0.1.0",
        );
        let b = SpdxDocumentNamespace::derive(
            &mk_artifacts("demo", &components, &[], &integ),
            "0.1.0",
        );
        assert_eq!(a, b);
    }

    #[test]
    fn namespace_differs_for_different_components() {
        let integ = empty_integrity();
        let c1 = vec![mk_component("pkg:cargo/a@1", "a", "1")];
        let c2 = vec![mk_component("pkg:cargo/b@1", "b", "1")];
        let a = SpdxDocumentNamespace::derive(
            &mk_artifacts("demo", &c1, &[], &integ),
            "0.1.0",
        );
        let b = SpdxDocumentNamespace::derive(
            &mk_artifacts("demo", &c2, &[], &integ),
            "0.1.0",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn namespace_differs_for_different_target_name() {
        let integ = empty_integrity();
        let c = vec![mk_component("pkg:cargo/a@1", "a", "1")];
        let a = SpdxDocumentNamespace::derive(
            &mk_artifacts("project-a", &c, &[], &integ),
            "0.1.0",
        );
        let b = SpdxDocumentNamespace::derive(
            &mk_artifacts("project-b", &c, &[], &integ),
            "0.1.0",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn namespace_differs_for_different_mikebom_version() {
        let integ = empty_integrity();
        let c = vec![mk_component("pkg:cargo/a@1", "a", "1")];
        let a = SpdxDocumentNamespace::derive(
            &mk_artifacts("demo", &c, &[], &integ),
            "0.1.0",
        );
        let b = SpdxDocumentNamespace::derive(
            &mk_artifacts("demo", &c, &[], &integ),
            "0.2.0",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn namespace_starts_with_mikebom_base_uri() {
        let integ = empty_integrity();
        let c = vec![mk_component("pkg:cargo/a@1", "a", "1")];
        let ns = SpdxDocumentNamespace::derive(
            &mk_artifacts("demo", &c, &[], &integ),
            "0.1.0",
        );
        assert!(
            ns.as_str().starts_with(NAMESPACE_BASE),
            "namespace {} should start with {NAMESPACE_BASE}",
            ns.as_str()
        );
    }
}
