//! SPDX 2.3 Package + license + checksum + externalRef structs
//! (milestone 010, T021 / T023).
//!
//! SPDX 2.3 §7 defines a `Package` as the unit-of-interest in an SPDX
//! document. For mikebom, one `ResolvedComponent` emits exactly one
//! `SpdxPackage` (FR-006). Nested CycloneDX components (shade-jar
//! children, etc.) flatten into top-level Packages connected by
//! CONTAINS/CONTAINED_BY relationships (FR-011) — the nesting happens
//! in `relationships.rs`, not here.

use mikebom_common::resolution::ResolvedComponent;
use mikebom_common::types::hash::HashAlgorithm;
use mikebom_common::types::license::SpdxExpression;

use super::annotations::annotate_component;
use super::document::SpdxAnnotation;
use super::ids::SpdxId;
use crate::generate::ScanArtifacts;

/// SPDX 2.3 hash algorithm enum (spec §7.10).
///
/// Full list in spec; mikebom emits only what its hasher produces
/// today. Others are reserved and added on demand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum SpdxChecksumAlgorithm {
    SHA1,
    SHA256,
    SHA512,
    MD5,
}

impl SpdxChecksumAlgorithm {
    pub fn from_internal(algo: HashAlgorithm) -> Self {
        match algo {
            HashAlgorithm::Sha1 => Self::SHA1,
            HashAlgorithm::Sha256 => Self::SHA256,
            HashAlgorithm::Sha512 => Self::SHA512,
            HashAlgorithm::Md5 => Self::MD5,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SpdxChecksum {
    pub algorithm: SpdxChecksumAlgorithm,
    #[serde(rename = "checksumValue")]
    pub value: String,
}

/// SPDX 2.3 license field (§7.13 / §7.15).
///
/// The spec allows three shapes: a canonical SPDX expression string,
/// the literal `NOASSERTION`, or the literal `NONE`. A custom
/// `Serialize` impl emits the two sentinel forms as bare strings
/// without ever producing `{"NoAssertion": null}` or similar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpdxLicenseField {
    /// A canonical SPDX license expression string (as validated via
    /// `spdx::Expression::canonicalize`). Passed through verbatim so
    /// upstream canonicalization's output wins.
    Expression(String),
    /// Spec literal "NOASSERTION" — emitted when mikebom has no
    /// value for the field (FR-009).
    NoAssertion,
    /// Spec literal "NONE" — currently unused by mikebom; reserved
    /// for upstream sources that explicitly assert "no license."
    #[allow(dead_code)]
    None,
    /// SPDX 2.3 §10.1 `LicenseRef-<hash>` reference. Emitted when
    /// the source CycloneDX `licenses[]` contained any term that
    /// fails `spdx::Expression::try_canonical` — the all-or-nothing
    /// rule per milestone-012 clarification Q1. The document-level
    /// `hasExtractedLicensingInfos[]` array carries the matching
    /// entry with `extractedText` holding the raw expression.
    LicenseRef(String),
}

impl serde::Serialize for SpdxLicenseField {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Expression(s) => ser.serialize_str(s),
            Self::NoAssertion => ser.serialize_str("NOASSERTION"),
            Self::None => ser.serialize_str("NONE"),
            // Emits a bare string like `"LicenseRef-ABC123…"` so the
            // output shape matches the canonical `Expression(s)` arm.
            Self::LicenseRef(s) => ser.serialize_str(s),
        }
    }
}

/// SPDX 2.3 external reference (spec §7.21).
///
/// Mikebom's primary use here is the PURL cross-reference
/// (`referenceCategory: "PACKAGE-MANAGER", referenceType: "purl"`)
/// per FR-007. CPE entries land under `SECURITY / cpe23Type` in US2.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpdxExternalRef {
    #[serde(rename = "referenceCategory")]
    pub category: SpdxExternalRefCategory,
    #[serde(rename = "referenceType")]
    pub ref_type: String,
    #[serde(rename = "referenceLocator")]
    pub locator: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SpdxExternalRefCategory {
    #[serde(rename = "PACKAGE-MANAGER")]
    PackageManager,
    #[serde(rename = "SECURITY")]
    Security,
    #[serde(rename = "PERSISTENT-ID")]
    #[allow(dead_code)]
    PersistentId,
    #[serde(rename = "OTHER")]
    Other,
}

/// SPDX 2.3 Package (spec §7).
///
/// Field ordering follows the spec's §7.x section numbering so the
/// resulting JSON resembles the SPDX reference examples.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    pub spdx_id: SpdxId,
    pub name: String,
    #[serde(rename = "versionInfo")]
    pub version_info: String,
    #[serde(rename = "downloadLocation")]
    pub download_location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub originator: Option<String>,
    #[serde(rename = "filesAnalyzed")]
    pub files_analyzed: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checksums: Vec<SpdxChecksum>,
    #[serde(rename = "licenseDeclared")]
    pub license_declared: SpdxLicenseField,
    #[serde(rename = "licenseConcluded")]
    pub license_concluded: SpdxLicenseField,
    #[serde(rename = "copyrightText", skip_serializing_if = "Option::is_none")]
    pub copyright_text: Option<String>,
    #[serde(rename = "externalRefs", skip_serializing_if = "Vec::is_empty")]
    pub external_refs: Vec<SpdxExternalRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<SpdxAnnotation>,
}

/// Reduce a `Vec<SpdxExpression>` to an SPDX license field plus
/// (when a LicenseRef path fires) the matching document-level
/// `hasExtractedLicensingInfos[]` entry.
///
/// SPDX 2.3 `licenseDeclared` / `licenseConcluded` are single-valued,
/// unlike CycloneDX's array form. The reduction rule per milestone-
/// 012 FR-007 / FR-010 + clarification Q1 (all-or-nothing):
///
/// * empty input         → `(NoAssertion, None)`
/// * all terms canonicalize → `(Expression(joined_canonical), None)`
///   — byte-identical to pre-milestone-012 behavior (FR-008).
/// * any term fails canon  → `(LicenseRef(id), Some(extracted_info))`
///   where `id = SpdxId::for_license_ref(joined_raw).as_str()` and
///   `extracted_info.extracted_text = joined_raw`. The Package's
///   `licenseDeclared` gets the `LicenseRef-<hash>` string;
///   document.rs collects and dedupes the extracted-info entries.
///
/// Per Q1 / FR-010: the rule is all-or-nothing — any non-
/// canonicalizable term in a multi-term expression triggers the
/// LicenseRef path for the whole expression. Mixed
/// `licenseDeclared` of the form `"MIT AND LicenseRef-<x>"` is NOT
/// emitted; the consumer recovers canonical terms from
/// `extractedText` if they need them.
fn reduce_license_vec(
    items: &[SpdxExpression],
) -> (
    SpdxLicenseField,
    Option<super::document::SpdxExtractedLicensingInfo>,
) {
    use super::document::SpdxExtractedLicensingInfo;
    use super::ids::SpdxId;
    if items.is_empty() {
        return (SpdxLicenseField::NoAssertion, None);
    }

    // Join raw expressions verbatim by ` AND ` — this is the single
    // string that either becomes the canonical `Expression` (if all
    // terms canonicalize) or the `LicenseRef` + `extractedText`.
    let joined_raw = items
        .iter()
        .map(|e| e.as_str())
        .collect::<Vec<_>>()
        .join(" AND ");

    match SpdxExpression::try_canonical(&joined_raw) {
        Ok(canon) => (
            SpdxLicenseField::Expression(canon.as_str().to_string()),
            None,
        ),
        Err(_) => {
            let license_id = SpdxId::for_license_ref(&joined_raw).as_str().to_string();
            let info = SpdxExtractedLicensingInfo {
                license_id: license_id.clone(),
                extracted_text: joined_raw,
                name: "mikebom-extracted-license".to_string(),
            };
            (SpdxLicenseField::LicenseRef(license_id), Some(info))
        }
    }
}

/// Derive an SPDX `supplier` / `originator` string from a mikebom
/// supplier name. SPDX 2.3 §7.5/§7.6 require either
/// `Organization: <name>`, `Person: <name>`, or the literal
/// `NOASSERTION`. We default to `Organization:` because the
/// supplier field for package-registry sources (npm, maven, deb,
/// etc.) is organizational in practice; the one place where "Person"
/// would win (cargo `authors`) isn't the `supplier` field — it
/// populates `originator` when we wire authors in.
fn supplier_string(name: &str) -> String {
    if name.is_empty() {
        "NOASSERTION".to_string()
    } else {
        format!("Organization: {name}")
    }
}

/// Build the `packages[]` array for an SPDX 2.3 document (T023).
///
/// One `SpdxPackage` per `ResolvedComponent`, in the scan's iteration
/// order (already stable since milestone 002; guaranteed by the
/// deduplicator).
///
/// `annotator` and `date` are threaded in from `build_document` so
/// the per-package annotations (T034 — the `mikebom:*` + evidence
/// envelopes) carry the same creator + timestamp strings as the
/// document's `creationInfo`. Match is what lets a consumer treat
/// the annotations as provenanced by the same tool run.
pub fn build_packages(
    artifacts: &ScanArtifacts<'_>,
    annotator: &str,
    date: &str,
) -> (Vec<SpdxPackage>, Vec<super::document::SpdxExtractedLicensingInfo>) {
    use std::collections::BTreeMap;
    let mut packages = Vec::with_capacity(artifacts.components.len());
    // Dedup extracted-licensing-info entries by `license_id` —
    // multiple components sharing the same raw license expression
    // produce one document-level entry referenced many times.
    let mut extracted_by_id: BTreeMap<String, super::document::SpdxExtractedLicensingInfo> =
        BTreeMap::new();
    for c in artifacts.components {
        let (pkg, decl_extracted, conc_extracted) = component_to_package(
            c,
            artifacts.include_hashes,
            artifacts.include_dev,
            artifacts.include_source_files,
            annotator,
            date,
        );
        packages.push(pkg);
        if let Some(info) = decl_extracted {
            extracted_by_id.entry(info.license_id.clone()).or_insert(info);
        }
        if let Some(info) = conc_extracted {
            extracted_by_id.entry(info.license_id.clone()).or_insert(info);
        }
    }
    // BTreeMap iterates in license_id-sorted order, which gives
    // deterministic document output (FR-009 / SC-007).
    let extracted: Vec<super::document::SpdxExtractedLicensingInfo> =
        extracted_by_id.into_values().collect();
    (packages, extracted)
}

fn component_to_package(
    c: &ResolvedComponent,
    include_hashes: bool,
    include_dev: bool,
    include_source_files: bool,
    annotator: &str,
    date: &str,
) -> (
    SpdxPackage,
    Option<super::document::SpdxExtractedLicensingInfo>,
    Option<super::document::SpdxExtractedLicensingInfo>,
) {
    let spdx_id = SpdxId::for_purl(&c.purl);
    let checksums: Vec<SpdxChecksum> = if include_hashes {
        c.hashes
            .iter()
            .map(|h| SpdxChecksum {
                algorithm: SpdxChecksumAlgorithm::from_internal(h.algorithm),
                value: h.value.as_str().to_string(),
            })
            .collect()
    } else {
        Vec::new()
    };

    // A1: PURL. Always first so the primary cross-reference is at
    // the top of the array (stable reader expectation).
    let mut external_refs = vec![SpdxExternalRef {
        category: SpdxExternalRefCategory::PackageManager,
        ref_type: "purl".to_string(),
        locator: c.purl.as_str().to_string(),
    }];

    // A12: primary CPE. The first entry in `c.cpes` is the
    // highest-signal synthesized candidate; the full set lives in
    // the `mikebom:cpe-candidates` annotation (C19).
    if let Some(primary_cpe) = c.cpes.first() {
        external_refs.push(SpdxExternalRef {
            category: SpdxExternalRefCategory::Security,
            ref_type: "cpe23Type".to_string(),
            locator: primary_cpe.clone(),
        });
    }

    // A9/A10/A11: external references — homepage, vcs, distribution,
    // etc. CDX uses a free-form `type` string; SPDX 2.3's
    // `externalRefs[]` with `category: OTHER` accepts any
    // `referenceType`, so we pass the ref_type through verbatim.
    // This preserves the CDX → SPDX mapping documented in the map.
    for r in &c.external_references {
        external_refs.push(SpdxExternalRef {
            category: SpdxExternalRefCategory::Other,
            ref_type: r.ref_type.clone(),
            locator: r.url.clone(),
        });
    }

    let supplier = c.supplier.as_deref().map(supplier_string);

    let annotations = annotate_component(
        annotator,
        date,
        c,
        include_dev,
        include_source_files,
    );

    let (license_declared, decl_extracted) = reduce_license_vec(&c.licenses);
    let (license_concluded, conc_extracted) = reduce_license_vec(&c.concluded_licenses);
    let pkg = SpdxPackage {
        spdx_id,
        name: c.name.clone(),
        version_info: c.version.clone(),
        download_location: "NOASSERTION".to_string(),
        supplier,
        originator: None,
        files_analyzed: false,
        checksums,
        license_declared,
        license_concluded,
        copyright_text: None,
        external_refs,
        annotations,
    };
    (pkg, decl_extracted, conc_extracted)
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
    use mikebom_common::types::hash::ContentHash;
    use mikebom_common::types::purl::Purl;

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

    fn mk_artifacts<'a>(
        target: &'a str,
        comps: &'a [ResolvedComponent],
        rels: &'a [mikebom_common::resolution::Relationship],
        integ: &'a TraceIntegrity,
    ) -> ScanArtifacts<'a> {
        ScanArtifacts {
            target_name: target,
            components: comps,
            relationships: rels,
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
    fn one_package_per_component() {
        let comps = vec![
            mk_component("pkg:cargo/serde@1.0.197", "serde", "1.0.197"),
            mk_component("pkg:cargo/tokio@1.35.0", "tokio", "1.35.0"),
        ];
        let integ = empty_integrity();
        let (pkgs, _extracted) = build_packages(&mk_artifacts("demo", &comps, &[], &integ), "Tool: mikebom-test", "2026-01-01T00:00:00Z");
        assert_eq!(pkgs.len(), 2);
    }

    #[test]
    fn package_carries_purl_external_ref() {
        let comps = vec![mk_component("pkg:cargo/serde@1.0.197", "serde", "1.0.197")];
        let integ = empty_integrity();
        let (pkgs, _extracted) = build_packages(&mk_artifacts("demo", &comps, &[], &integ), "Tool: mikebom-test", "2026-01-01T00:00:00Z");
        let purl_ref = pkgs[0]
            .external_refs
            .iter()
            .find(|r| r.ref_type == "purl")
            .expect("every package must carry a purl externalRef");
        assert_eq!(purl_ref.category, SpdxExternalRefCategory::PackageManager);
        assert_eq!(purl_ref.locator, "pkg:cargo/serde@1.0.197");
    }

    #[test]
    fn hashes_land_in_checksums_with_spdx_algorithm_names() {
        let mut c = mk_component("pkg:cargo/x@1", "x", "1");
        c.hashes = vec![ContentHash::sha256(
            "3fb1c873e1b9b056a4dc4c0c198b24c3ffa59243c322bfd971d2d5ef4f463ee1",
        )
        .unwrap()];
        let integ = empty_integrity();
        let comps = [c];
        let (pkgs, _extracted) = build_packages(&mk_artifacts("demo", &comps, &[], &integ), "Tool: mikebom-test", "2026-01-01T00:00:00Z");
        assert_eq!(pkgs[0].checksums.len(), 1);
        assert_eq!(pkgs[0].checksums[0].algorithm, SpdxChecksumAlgorithm::SHA256);
    }

    #[test]
    fn no_hashes_when_include_hashes_is_false() {
        let mut c = mk_component("pkg:cargo/x@1", "x", "1");
        c.hashes = vec![ContentHash::sha256(
            "3fb1c873e1b9b056a4dc4c0c198b24c3ffa59243c322bfd971d2d5ef4f463ee1",
        )
        .unwrap()];
        let integ = empty_integrity();
        let comps = [c];
        let mut artifacts = mk_artifacts("demo", &comps, &[], &integ);
        artifacts.include_hashes = false;
        let (pkgs, _extracted) = build_packages(&artifacts, "Tool: mikebom-test", "2026-01-01T00:00:00Z");
        assert!(pkgs[0].checksums.is_empty());
    }

    #[test]
    fn declared_license_passes_through_canonicalized() {
        // Input already-canonical so the strict spdx-crate parser
        // accepts it; test verifies the expression reaches the SPDX
        // output unchanged rather than getting silently NOASSERTION'd.
        let mut c = mk_component("pkg:cargo/x@1", "x", "1");
        c.licenses = vec![SpdxExpression::new("MIT").unwrap()];
        let integ = empty_integrity();
        let comps = [c];
        let (pkgs, _extracted) = build_packages(&mk_artifacts("demo", &comps, &[], &integ), "Tool: mikebom-test", "2026-01-01T00:00:00Z");
        match &pkgs[0].license_declared {
            SpdxLicenseField::Expression(s) => assert_eq!(s, "MIT"),
            other => panic!("expected Expression, got {other:?}"),
        }
    }

    #[test]
    fn unparseable_license_emits_license_ref_and_extracted_info() {
        // Post-milestone-012 US3: the permissive `new()` accepts any
        // non-empty, non-control string; only `try_canonical` is
        // strict. A free-text license that can't be canonicalized
        // flows to the LicenseRef-<hash> path with the raw string
        // preserved in `hasExtractedLicensingInfos[]`. Pre-US3 this
        // dropped to NOASSERTION (silent data loss); post-US3 it's
        // preserved verbatim.
        let mut c = mk_component("pkg:cargo/x@1", "x", "1");
        c.licenses = vec![SpdxExpression::new("Some Free-Text License").unwrap()];
        let integ = empty_integrity();
        let comps = [c];
        let (pkgs, extracted) = build_packages(
            &mk_artifacts("demo", &comps, &[], &integ),
            "Tool: mikebom-test",
            "2026-01-01T00:00:00Z",
        );
        // licenseDeclared is a LicenseRef-<hash> reference.
        let license_id = match &pkgs[0].license_declared {
            SpdxLicenseField::LicenseRef(id) => id.clone(),
            other => panic!("expected LicenseRef, got {other:?}"),
        };
        assert!(license_id.starts_with("LicenseRef-"));
        // hasExtractedLicensingInfos carries the matching entry.
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].license_id, license_id);
        assert_eq!(extracted[0].extracted_text, "Some Free-Text License");
        assert_eq!(extracted[0].name, "mikebom-extracted-license");
    }

    #[test]
    fn mixed_canonical_and_noncanonical_triggers_all_or_nothing_license_ref() {
        // Clarification Q1 / FR-010: if ANY term in a multi-term
        // expression fails canonicalization, the whole expression
        // flows through the LicenseRef path. No mixed
        // `licenseDeclared` of the form `"MIT AND LicenseRef-<x>"`.
        let mut c = mk_component("pkg:cargo/x@1", "x", "1");
        c.licenses = vec![
            SpdxExpression::new("MIT").unwrap(),
            SpdxExpression::new("GNU General Public").unwrap(),
        ];
        let integ = empty_integrity();
        let comps = [c];
        let (pkgs, extracted) = build_packages(
            &mk_artifacts("demo", &comps, &[], &integ),
            "Tool: mikebom-test",
            "2026-01-01T00:00:00Z",
        );
        match &pkgs[0].license_declared {
            SpdxLicenseField::LicenseRef(_) => {}
            other => panic!("expected LicenseRef (all-or-nothing rule), got {other:?}"),
        };
        // Joined raw expression preserved verbatim in extractedText.
        assert_eq!(extracted.len(), 1);
        assert_eq!(
            extracted[0].extracted_text,
            "MIT AND GNU General Public"
        );
    }

    #[test]
    fn dedup_extracted_infos_when_same_expression_on_two_components() {
        let mut c1 = mk_component("pkg:cargo/a@1", "a", "1");
        let mut c2 = mk_component("pkg:cargo/b@1", "b", "1");
        c1.licenses = vec![SpdxExpression::new("Some Free-Text License").unwrap()];
        c2.licenses = vec![SpdxExpression::new("Some Free-Text License").unwrap()];
        let integ = empty_integrity();
        let comps = [c1, c2];
        let (_pkgs, extracted) = build_packages(
            &mk_artifacts("demo", &comps, &[], &integ),
            "Tool: mikebom-test",
            "2026-01-01T00:00:00Z",
        );
        // Document-level extracted-info is deduped by license_id —
        // one entry referenced by both Package's licenseDeclared.
        assert_eq!(extracted.len(), 1);
    }

    #[test]
    fn concluded_license_populates_license_concluded() {
        let mut c = mk_component("pkg:cargo/x@1", "x", "1");
        c.concluded_licenses = vec![SpdxExpression::new("Apache-2.0").unwrap()];
        let integ = empty_integrity();
        let comps = [c];
        let (pkgs, _extracted) = build_packages(&mk_artifacts("demo", &comps, &[], &integ), "Tool: mikebom-test", "2026-01-01T00:00:00Z");
        match &pkgs[0].license_concluded {
            SpdxLicenseField::Expression(s) => assert_eq!(s, "Apache-2.0"),
            other => panic!("expected Expression, got {other:?}"),
        }
    }

    #[test]
    fn missing_license_emits_noassertion() {
        let c = mk_component("pkg:cargo/x@1", "x", "1");
        let integ = empty_integrity();
        let comps = [c];
        let (pkgs, _extracted) = build_packages(&mk_artifacts("demo", &comps, &[], &integ), "Tool: mikebom-test", "2026-01-01T00:00:00Z");
        assert!(matches!(pkgs[0].license_declared, SpdxLicenseField::NoAssertion));
        assert!(matches!(pkgs[0].license_concluded, SpdxLicenseField::NoAssertion));
    }

    #[test]
    fn supplier_serializes_as_organization_prefix() {
        let mut c = mk_component("pkg:cargo/x@1", "x", "1");
        c.supplier = Some("Acme Corp".to_string());
        let integ = empty_integrity();
        let comps = [c];
        let (pkgs, _extracted) = build_packages(&mk_artifacts("demo", &comps, &[], &integ), "Tool: mikebom-test", "2026-01-01T00:00:00Z");
        assert_eq!(pkgs[0].supplier.as_deref(), Some("Organization: Acme Corp"));
    }

    #[test]
    fn license_noassertion_serializes_as_bare_string() {
        let j = serde_json::to_string(&SpdxLicenseField::NoAssertion).unwrap();
        assert_eq!(j, "\"NOASSERTION\"");
    }

    #[test]
    fn license_none_serializes_as_bare_string() {
        let j = serde_json::to_string(&SpdxLicenseField::None).unwrap();
        assert_eq!(j, "\"NONE\"");
    }

    #[test]
    fn license_expression_serializes_as_bare_string() {
        let field = SpdxLicenseField::Expression("MIT".to_string());
        let j = serde_json::to_string(&field).unwrap();
        assert_eq!(j, "\"MIT\"");
    }
}
