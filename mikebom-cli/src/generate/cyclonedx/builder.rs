use serde_json::json;
use uuid::Uuid;

use mikebom_common::attestation::integrity::TraceIntegrity;
use mikebom_common::attestation::metadata::GenerationContext;
use mikebom_common::resolution::{Relationship, ResolvedComponent};

use super::compositions::build_compositions;
use super::dependencies::build_dependencies;
use super::evidence::{build_evidence, evidence_to_properties};
use super::metadata::build_metadata;
use super::vex::build_vulnerabilities;

/// Configuration for CycloneDX BOM generation.
#[derive(Clone, Debug)]
pub struct CycloneDxConfig {
    /// Whether to include per-component content hashes.
    pub include_hashes: bool,
    /// Whether to include source file paths in evidence.
    pub include_source_files: bool,
    /// How this SBOM was produced. Gets surfaced in the CycloneDX
    /// `mikebom:generation-context` property so downstream consumers can
    /// distinguish a build-time trace from a post-hoc filesystem scan.
    pub generation_context: GenerationContext,
    /// Whether the caller ran the scan with `--include-dev`. Controls
    /// emission of the `mikebom:dev-dependency` property on dev-flagged
    /// components — the flag is only ever emitted when dev components
    /// were intentionally included, so downstream consumers can trust
    /// the absence of the property to mean "this component is prod".
    pub include_dev: bool,
}

impl Default for CycloneDxConfig {
    fn default() -> Self {
        Self {
            include_hashes: true,
            include_source_files: false,
            generation_context: GenerationContext::BuildTimeTrace,
            include_dev: false,
        }
    }
}

/// Builder that assembles a complete CycloneDX 1.6 BOM document.
pub struct CycloneDxBuilder {
    config: CycloneDxConfig,
    /// Feature 005 SC-009 — names of `/etc/os-release` fields that were
    /// missing during the scan. Populated by the caller via
    /// `set_os_release_missing_fields`; emitted into the SBOM's
    /// `metadata.properties` as `mikebom:os-release-missing-fields`
    /// when non-empty.
    os_release_missing_fields: Vec<String>,
}

impl CycloneDxBuilder {
    /// Create a new builder with the given configuration.
    pub fn new(config: CycloneDxConfig) -> Self {
        Self { config, os_release_missing_fields: Vec::new() }
    }

    /// Feature 005 — record diagnostic fields observed during the scan.
    /// When non-empty, they drive the `mikebom:os-release-missing-fields`
    /// CycloneDX metadata property.
    pub fn with_os_release_missing_fields(mut self, fields: Vec<String>) -> Self {
        self.os_release_missing_fields = fields;
        self
    }

    /// Build a complete CycloneDX 1.6 JSON BOM.
    ///
    /// Assembles all sections: metadata, components, compositions,
    /// dependencies, and vulnerabilities.
    pub fn build(
        &self,
        components: &[ResolvedComponent],
        relationships: &[Relationship],
        integrity: &TraceIntegrity,
        target_name: &str,
        complete_ecosystems: &[String],
    ) -> anyhow::Result<serde_json::Value> {
        let serial_number = format!("urn:uuid:{}", Uuid::new_v4());
        let target_version = "0.0.0"; // Derived from build metadata when available
        let target_ref = format!("{}@{}", target_name, target_version);

        let metadata = build_metadata(
            target_name,
            target_version,
            self.config.generation_context.clone(),
            components,
            &self.os_release_missing_fields,
        );
        let cdx_components = self.build_components(components)?;
        let compositions =
            build_compositions(integrity, &target_ref, components, complete_ecosystems);
        let deps = build_dependencies(components, relationships, &target_ref);
        let vulnerabilities = build_vulnerabilities(components);

        let bom = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": serial_number,
            "version": 1,
            "metadata": metadata,
            "components": cdx_components,
            "compositions": compositions,
            "dependencies": deps,
            "vulnerabilities": vulnerabilities
        });

        Ok(bom)
    }

    /// Build the CycloneDX components array from resolved components.
    fn build_components(
        &self,
        components: &[ResolvedComponent],
    ) -> anyhow::Result<serde_json::Value> {
        let mut cdx_components = Vec::new();

        for component in components {
            let mut entry = json!({
                "type": "library",
                "name": component.name,
                "version": component.version,
                "purl": component.purl.as_str(),
                "bom-ref": component.purl.as_str(),
                "evidence": build_evidence(&component.evidence, &component.occurrences)
            });

            // Include hashes if configured.
            if self.config.include_hashes && !component.hashes.is_empty() {
                let hashes: Vec<serde_json::Value> = component
                    .hashes
                    .iter()
                    .map(|h| {
                        json!({
                            "alg": format!("{}", h.algorithm).to_uppercase().replace("SHA", "SHA-"),
                            "content": h.value.as_str()
                        })
                    })
                    .collect();
                entry["hashes"] = json!(hashes);
            }

            // Include licenses if present.
            if !component.licenses.is_empty() {
                let licenses: Vec<serde_json::Value> = component
                    .licenses
                    .iter()
                    .map(|l| {
                        json!({
                            "expression": l.as_str()
                        })
                    })
                    .collect();
                entry["licenses"] = json!(licenses);
            }

            // Include supplier if present.
            if let Some(ref supplier) = component.supplier {
                entry["supplier"] = json!({
                    "name": supplier
                });
            }

            // CycloneDX `component.cpe` is single-valued. Emit the first
            // (highest-signal) synthesized candidate there; stash the full
            // vendor-candidate list under a property so downstream NVD
            // matchers can take the union of heuristics instead of being
            // locked to one guess.
            let mut properties: Vec<serde_json::Value> = Vec::new();
            if !component.cpes.is_empty() {
                entry["cpe"] = json!(component.cpes[0]);
                if component.cpes.len() > 1 {
                    properties.push(json!({
                        "name": "mikebom:cpe-candidates",
                        "value": component.cpes.join(" | ")
                    }));
                }
            }

            // Include source file paths if configured and present.
            if self.config.include_source_files
                && !component.evidence.source_file_paths.is_empty()
            {
                properties.push(json!({
                    "name": "mikebom:source-files",
                    "value": component.evidence.source_file_paths.join(", ")
                }));
            }

            // Milestone 002 traceability + scoping properties.
            // `mikebom:dev-dependency` only emits when the component was
            // flagged dev-only AND the caller actually opted in — the
            // absence of the property on a dev-capable-ecosystem component
            // is a positive signal that it's a prod dep.
            if self.config.include_dev && component.is_dev == Some(true) {
                properties.push(json!({
                    "name": "mikebom:dev-dependency",
                    "value": "true"
                }));
            }
            if let Some(ref range) = component.requirement_range {
                properties.push(json!({
                    "name": "mikebom:requirement-range",
                    "value": range
                }));
            }
            if let Some(ref src_type) = component.source_type {
                properties.push(json!({
                    "name": "mikebom:source-type",
                    "value": src_type
                }));
            }
            // Evidence-derived provenance properties. Replaces the
            // former `evidence.identity[].tools` entries — those fail
            // CDX 1.6 schema because `tools[]` must be bom-refs to
            // declared BOM elements, which source_connection_ids and
            // deps.dev markers are not. Properties are the idiomatic
            // home for scanner-specific provenance data.
            properties.extend(evidence_to_properties(&component.evidence));
            // `mikebom:sbom-tier` — the traceability-ladder classifier
            // introduced in milestone 002 (spec FR-021a, research R13).
            // Emitted on every component that carries one. Values:
            // build | deployed | analyzed | source | design.
            if let Some(ref tier) = component.sbom_tier {
                properties.push(json!({
                    "name": "mikebom:sbom-tier",
                    "value": tier
                }));
            }
            // `mikebom:npm-role` — feature 005 US1 (spec FR-001, FR-003).
            // Emitted only on npm components discovered inside npm's own
            // bundled tree (`**/node_modules/npm/node_modules/**`) during
            // --image scans. Value: `internal`. Absent on application
            // deps (the vast majority) and on all --path-mode scans,
            // where the internals are filtered out before they reach
            // the builder. See data-model.md §PackageDbEntry.npm_role.
            if let Some(ref role) = component.npm_role {
                properties.push(json!({
                    "name": "mikebom:npm-role",
                    "value": role
                }));
            }
            // `mikebom:raw-version` — feature 005 US4 (spec FR-013).
            // Verbatim `VERSION-RELEASE` string from the rpmdb header.
            // Populated on every rpm component so downstream consumers
            // can cross-reference `rpm -qa`'s `%{VERSION}-%{RELEASE}`
            // column without re-parsing the PURL. Absent on non-rpm
            // components today; reserved for other ecosystems to opt
            // in later via the same field on `PackageDbEntry`.
            if let Some(ref raw) = component.raw_version {
                properties.push(json!({
                    "name": "mikebom:raw-version",
                    "value": raw
                }));
            }
            // `mikebom:buildinfo-status` — milestone 003 (spec FR-015).
            // Emitted ONLY on file-level Go binary components where
            // `runtime/debug.BuildInfo` couldn't be recovered. Operators
            // distinguish "no modules found" from "scan failed" via the
            // value: `"missing"` (stripped binary, magic absent) or
            // `"unsupported"` (Go <1.18 pre-inline format).
            if let Some(ref status) = component.buildinfo_status {
                properties.push(json!({
                    "name": "mikebom:buildinfo-status",
                    "value": status
                }));
            }
            // `mikebom:evidence-kind` — milestone 004 (spec FR-004,
            // contracts/schema.md). Six-value canonical enum identifying
            // how the component was discovered. Consumers filter by this.
            // Valid values enforced by `debug_assert!` per data-model.md
            // §Validation rules.
            if let Some(ref kind) = component.evidence_kind {
                debug_assert!(
                    matches!(
                        kind.as_str(),
                        "rpm-file"
                            | "rpmdb-sqlite"
                            | "rpmdb-bdb"
                            | "dynamic-linkage"
                            | "elf-note-package"
                            | "embedded-version-string"
                            | "python-stdlib-collapsed"
                            | "jdk-runtime-collapsed"
                    ),
                    "mikebom:evidence-kind value '{}' is not in the canonical \
                     enum (rpm-file | rpmdb-sqlite | rpmdb-bdb | \
                     dynamic-linkage | elf-note-package | \
                     embedded-version-string | python-stdlib-collapsed | \
                     jdk-runtime-collapsed)",
                    kind
                );
                properties.push(json!({
                    "name": "mikebom:evidence-kind",
                    "value": kind
                }));
            }
            // Milestone 004 US2 binary-component properties. Each is
            // emitted only when Some(...) — the absence of the property
            // is itself informative (e.g. no `mikebom:binary-class` =
            // non-binary component).
            if let Some(ref confidence) = component.confidence {
                debug_assert_eq!(
                    confidence, "heuristic",
                    "mikebom:confidence is currently only valid as 'heuristic'"
                );
                properties.push(json!({
                    "name": "mikebom:confidence",
                    "value": confidence
                }));
            }
            if let Some(ref class) = component.binary_class {
                debug_assert!(
                    matches!(class.as_str(), "elf" | "macho" | "pe"),
                    "mikebom:binary-class value '{class}' is not in {{elf, macho, pe}}"
                );
                properties.push(json!({
                    "name": "mikebom:binary-class",
                    "value": class
                }));
            }
            if let Some(stripped) = component.binary_stripped {
                properties.push(json!({
                    "name": "mikebom:binary-stripped",
                    "value": if stripped { "true" } else { "false" }
                }));
            }
            if let Some(ref linkage) = component.linkage_kind {
                debug_assert!(
                    matches!(linkage.as_str(), "dynamic" | "static" | "mixed"),
                    "mikebom:linkage-kind value '{linkage}' is not in {{dynamic, static, mixed}}"
                );
                properties.push(json!({
                    "name": "mikebom:linkage-kind",
                    "value": linkage
                }));
            }
            if component.detected_go == Some(true) {
                properties.push(json!({
                    "name": "mikebom:detected-go",
                    "value": "true"
                }));
            }
            if let Some(ref packed) = component.binary_packed {
                debug_assert_eq!(
                    packed, "upx",
                    "mikebom:binary-packed currently only valid as 'upx'"
                );
                properties.push(json!({
                    "name": "mikebom:binary-packed",
                    "value": packed
                }));
            }

            if !properties.is_empty() {
                entry["properties"] = json!(properties);
            }

            cdx_components.push(entry);
        }

        Ok(json!(cdx_components))
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::resolution::{ResolutionEvidence, ResolutionTechnique};
    use mikebom_common::types::purl::Purl;

    fn clean_integrity() -> TraceIntegrity {
        TraceIntegrity {
            ring_buffer_overflows: 0,
            events_dropped: 0,
            uprobe_attach_failures: vec![],
            kprobe_attach_failures: vec![],
            partial_captures: vec![],
            bloom_filter_capacity: 100_000,
            bloom_filter_false_positive_rate: 0.01,
        }
    }

    fn make_component(name: &str, version: &str) -> ResolvedComponent {
        let purl_str = format!("pkg:cargo/{}@{}", name, version);
        ResolvedComponent {
            purl: Purl::new(&purl_str).expect("valid purl"),
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
        }
    }

    #[test]
    fn bom_has_correct_top_level_structure() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let components = vec![make_component("serde", "1.0.197")];
        let integrity = clean_integrity();

        let bom = builder
            .build(&components, &[], &integrity, "myapp", &[])
            .expect("build bom");

        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.6");
        assert_eq!(bom["version"], 1);
        assert!(bom["serialNumber"]
            .as_str()
            .expect("serial number")
            .starts_with("urn:uuid:"));
        assert!(bom["metadata"].is_object());
        assert!(bom["components"].is_array());
        assert!(bom["compositions"].is_array());
        assert!(bom["dependencies"].is_array());
        assert!(bom["vulnerabilities"].is_array());
    }

    #[test]
    fn components_include_purl_and_evidence() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let components = vec![make_component("serde", "1.0.197")];
        let integrity = clean_integrity();

        let bom = builder
            .build(&components, &[], &integrity, "myapp", &[])
            .expect("build bom");

        let cdx_components = bom["components"].as_array().expect("components array");
        assert_eq!(cdx_components.len(), 1);

        let comp = &cdx_components[0];
        assert_eq!(comp["name"], "serde");
        assert_eq!(comp["version"], "1.0.197");
        assert_eq!(comp["type"], "library");
        assert!(comp["purl"].as_str().expect("purl").contains("serde"));
        assert!(comp["evidence"].is_object());
    }

    #[test]
    fn no_hashes_config_omits_hashes() {
        let config = CycloneDxConfig {
            include_hashes: false,
            include_source_files: false,
            generation_context: GenerationContext::BuildTimeTrace,
            include_dev: false,
        };
        let builder = CycloneDxBuilder::new(config);

        let mut component = make_component("serde", "1.0.197");
        // Even with hashes on the component, they should be omitted.
        component.hashes = vec![
            mikebom_common::types::hash::ContentHash::sha256(
                "3fb1c873e1b9b056a4dc4c0c198b24c3ffa59243c322bfd971d2d5ef4f463ee1",
            )
            .expect("valid hash"),
        ];

        let integrity = clean_integrity();
        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");

        let cdx_components = bom["components"].as_array().expect("components array");
        assert!(cdx_components[0].get("hashes").is_none());
    }

    #[test]
    fn metadata_references_target() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let integrity = clean_integrity();

        let bom = builder
            .build(&[], &[], &integrity, "myapp", &[])
            .expect("build bom");

        assert_eq!(bom["metadata"]["component"]["name"], "myapp");
    }

    #[test]
    fn cpes_emit_primary_plus_candidate_property() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("jq", "1.6-2.1");
        component.cpes = vec![
            "cpe:2.3:a:debian:jq:1.6-2.1:*:*:*:*:*:*:*".to_string(),
            "cpe:2.3:a:jq:jq:1.6-2.1:*:*:*:*:*:*:*".to_string(),
        ];
        let integrity = clean_integrity();

        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");

        let cdx = bom["components"].as_array().expect("components");
        assert_eq!(cdx.len(), 1);
        assert_eq!(
            cdx[0]["cpe"].as_str().expect("cpe field"),
            "cpe:2.3:a:debian:jq:1.6-2.1:*:*:*:*:*:*:*"
        );
        let props = cdx[0]["properties"]
            .as_array()
            .expect("properties array");
        assert!(
            props.iter().any(|p| p["name"] == "mikebom:cpe-candidates"
                && p["value"].as_str().unwrap().contains("jq:jq")),
            "expected cpe-candidates property, got {props:?}"
        );
    }

    #[test]
    fn single_cpe_omits_candidates_property() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("serde", "1.0.197");
        component.cpes = vec!["cpe:2.3:a:serde:serde:1.0.197:*:*:*:*:*:*:*".to_string()];
        let integrity = clean_integrity();

        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");

        let cdx = bom["components"].as_array().expect("components");
        assert_eq!(cdx[0]["cpe"], "cpe:2.3:a:serde:serde:1.0.197:*:*:*:*:*:*:*");
        // Only one candidate — no candidates property needed.
        let props = cdx[0].get("properties");
        if let Some(props) = props {
            assert!(
                !props
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["name"] == "mikebom:cpe-candidates"),
                "unexpected cpe-candidates property with single CPE"
            );
        }
    }

    #[test]
    fn buildinfo_status_missing_surfaces_property() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("stripped-hello", "unknown");
        component.buildinfo_status = Some("missing".to_string());
        let integrity = clean_integrity();
        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");
        let cdx = bom["components"].as_array().expect("components");
        let props = cdx[0]["properties"].as_array().expect("properties");
        let found = props
            .iter()
            .find(|p| p["name"] == "mikebom:buildinfo-status")
            .expect("mikebom:buildinfo-status property must be present");
        assert_eq!(found["value"], "missing");
    }

    #[test]
    fn buildinfo_status_unsupported_surfaces_property() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("pre118-hello", "unknown");
        component.buildinfo_status = Some("unsupported".to_string());
        let integrity = clean_integrity();
        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");
        let cdx = bom["components"].as_array().expect("components");
        let props = cdx[0]["properties"].as_array().expect("properties");
        let found = props
            .iter()
            .find(|p| p["name"] == "mikebom:buildinfo-status")
            .expect("mikebom:buildinfo-status property must be present");
        assert_eq!(found["value"], "unsupported");
    }

    #[test]
    fn buildinfo_status_none_does_not_surface_property() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let component = make_component("serde", "1.0.197");
        // buildinfo_status is None by default on non-Go components.
        let integrity = clean_integrity();
        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");
        let cdx = bom["components"].as_array().expect("components");
        let props = cdx[0].get("properties");
        if let Some(props) = props {
            assert!(
                !props
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["name"] == "mikebom:buildinfo-status"),
                "non-Go component must not surface mikebom:buildinfo-status"
            );
        }
    }

    // --- CDX 1.6 evidence serialization (sbomqs parse-failure fix) -----

    #[test]
    fn evidence_connection_ids_land_in_component_properties() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("serde", "1.0.197");
        component.evidence.source_connection_ids =
            vec!["conn-1".to_string(), "conn-2".to_string()];
        let integrity = clean_integrity();

        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");

        let comp = &bom["components"].as_array().expect("components")[0];
        let props = comp["properties"]
            .as_array()
            .expect("component must have properties");
        let conn_prop = props
            .iter()
            .find(|p| p["name"] == "mikebom:source-connection-ids")
            .expect("source-connection-ids property must be present");
        assert_eq!(conn_prop["value"], "conn-1,conn-2");
    }

    #[test]
    fn evidence_tools_field_absent_from_serialized_output() {
        // Regression guard for sbomqs parse failure:
        // `cannot unmarshal object into Go struct field
        //  Component.components.evidence.tools of type cyclonedx.BOMReference`.
        // Build a component with every flavor of provenance populated
        // (connection IDs, deps.dev match) and confirm nothing surfaces
        // under `evidence.identity[].tools`.
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("express", "4.19.2");
        component.evidence.source_connection_ids = vec!["conn-42".to_string()];
        component.evidence.deps_dev_match = Some(
            mikebom_common::resolution::DepsDevMatch {
                system: "npm".to_string(),
                name: "express".to_string(),
                version: "4.19.2".to_string(),
            },
        );
        let integrity = clean_integrity();

        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");

        let comp = &bom["components"].as_array().expect("components")[0];
        let identity = comp["evidence"]["identity"]
            .as_array()
            .expect("evidence.identity must be an array (CDX 1.6)");
        assert_eq!(identity.len(), 1);
        assert!(
            identity[0].get("tools").is_none(),
            "evidence.identity[].tools must not be emitted; got {:?}",
            identity[0].get("tools")
        );
    }

    #[test]
    fn deps_dev_match_lands_in_component_properties() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("express", "4.19.2");
        component.evidence.deps_dev_match = Some(
            mikebom_common::resolution::DepsDevMatch {
                system: "npm".to_string(),
                name: "express".to_string(),
                version: "4.19.2".to_string(),
            },
        );
        let integrity = clean_integrity();

        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");

        let comp = &bom["components"].as_array().expect("components")[0];
        let props = comp["properties"]
            .as_array()
            .expect("component must have properties");
        let dd_prop = props
            .iter()
            .find(|p| p["name"] == "mikebom:deps-dev-match")
            .expect("deps-dev-match property must be present");
        assert_eq!(dd_prop["value"], "npm:express@4.19.2");
    }
}