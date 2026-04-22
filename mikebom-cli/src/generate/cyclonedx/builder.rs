use serde_json::json;
use uuid::Uuid;

use mikebom_common::attestation::integrity::TraceIntegrity;
use mikebom_common::attestation::metadata::GenerationContext;
use mikebom_common::resolution::{Relationship, ResolvedComponent};
use mikebom_common::types::license::SpdxExpression;

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
            integrity,
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

            // CDX 1.6 license emission. Two shapes per item:
            // - `{"license": {"id": "<SPDX>", "acknowledgement": "..."}}`
            //   for single-identifier licenses on the SPDX list.
            //   sbomqs's `comp_with_valid_licenses` requires this form.
            // - `{"expression": "<expr>", "acknowledgement": "..."}` for
            //   compound (AND/OR/WITH), unknown identifiers, LicenseRefs.
            //
            // The `acknowledgement` enum (CDX 1.6) distinguishes:
            // - "declared" — what the package author asserted in their
            //   manifest (mikebom: `component.licenses`)
            // - "concluded" — result of comprehensive analysis
            //   (mikebom: `component.concluded_licenses`, populated by
            //   the ClearlyDefined enrichment source)
            // sbomqs's `comp_with_licenses`, `comp_with_valid_licenses`,
            // `comp_no_deprecated_licenses`, `comp_no_restrictive_licenses`
            // all read concluded; `comp_with_declared_licenses` reads
            // declared.
            // CDX 1.6 `licenses` schema is oneOf:
            // - An array of `{license: {id/name, ...}}` objects (any
            //   length), OR
            // - An array of exactly ONE `{expression: ...}` entry.
            // Mixing the two shapes, or emitting multiple expression
            // entries, is a schema error. We accumulate both declared
            // + concluded sources, split `A OR B` compounds into
            // individual ids when possible, and fall back to a single
            // expression entry (concluded > declared) only when a
            // genuine compound remains.
            let mut all_licenses: Vec<serde_json::Value> = Vec::new();
            let mut pending_expression: Option<(&str, &str)> = None;
            let sources: [(&[SpdxExpression], &str); 2] = [
                (&component.licenses, "declared"),
                (&component.concluded_licenses, "concluded"),
            ];
            for (exprs, ack) in sources {
                for l in exprs {
                    if let Some(id) = l.as_spdx_id() {
                        all_licenses.push(json!({
                            "license": { "id": id, "acknowledgement": ack }
                        }));
                    } else if l.as_str().starts_with("LicenseRef-")
                        || l.as_str().starts_with("DocumentRef-")
                    {
                        // Bare LicenseRef-* / DocumentRef-* aren't valid
                        // in CDX `license.id` (id is restricted to the
                        // SPDX list). Emit via `license.name` — schema-
                        // legal and counted by sbomqs.
                        all_licenses.push(json!({
                            "license": { "name": l.as_str(), "acknowledgement": ack }
                        }));
                    } else if let Some(tokens) = try_split_or_compound(l.as_str()) {
                        for tok in tokens {
                            all_licenses.push(license_entry_for_token(&tok, ack));
                        }
                    } else {
                        pending_expression = Some((l.as_str(), ack));
                    }
                }
            }
            let final_licenses = if let Some((expr, ack)) = pending_expression {
                vec![json!({ "expression": expr, "acknowledgement": ack })]
            } else {
                all_licenses
            };
            if !final_licenses.is_empty() {
                entry["licenses"] = json!(final_licenses);
            }

            // Include supplier if present.
            if let Some(ref supplier) = component.supplier {
                entry["supplier"] = json!({
                    "name": supplier
                });
            }

            // External references — VCS repos, homepages, etc.
            // Drives sbomqs `comp_with_source_code` when a `vcs`
            // entry is present.
            if !component.external_references.is_empty() {
                let refs: Vec<serde_json::Value> = component
                    .external_references
                    .iter()
                    .map(|r| json!({ "type": r.ref_type, "url": r.url }))
                    .collect();
                entry["externalReferences"] = json!(refs);
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

/// Split an SPDX expression of the shape `A OR B OR C` OR
/// `A AND B AND C` into its constituent identifiers. Returns `None`
/// for expressions that mix operators, contain `WITH`, parentheses,
/// license refs, or any component that isn't a bare SPDX-list
/// identifier — those can't be represented as a set of independent
/// `{license: {id}}` entries without losing semantics.
///
/// Motivation: CDX 1.6 allows only ONE `{expression}` entry per
/// `licenses[]` array, and sbomqs `comp_with_licenses` scores credit
/// on `license.id` / `license.name` only, not on `expression`. So
/// `Apache-2.0 OR MIT` (cargo dual-licensed pattern) and
/// `BSD-2-Clause AND BSD-3-Clause` (ClearlyDefined curated-AND
/// pattern) both become multiple `{license: {id}}` entries.
///
/// For AND the split is semantically faithful (both licenses apply →
/// list both). For OR it's a compromise (the disjunction relation is
/// lost) but downstream readers still see every candidate ID.
fn try_split_or_compound(expr: &str) -> Option<Vec<String>> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains('(') || trimmed.contains(')') {
        return None;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.iter().any(|&t| t == "WITH") {
        return None;
    }
    // Pick a single top-level operator. Mixed operators (e.g.
    // `A AND B OR C`) require parens for unambiguous parsing, so
    // bail — let the single-expression fallback handle them.
    let has_or = tokens.iter().any(|&t| t == "OR");
    let has_and = tokens.iter().any(|&t| t == "AND");
    let separator = match (has_or, has_and) {
        (true, false) => " OR ",
        (false, true) => " AND ",
        _ => return None,
    };
    let parts: Vec<&str> = trimmed.split(separator).map(str::trim).collect();
    if parts.len() < 2 {
        return None;
    }
    let mut tokens_out = Vec::with_capacity(parts.len());
    for p in parts {
        // Every operand must be a single token (SPDX id or
        // LicenseRef-*); whitespace inside an operand means the
        // expression has nested operators we can't flatten.
        if p.is_empty() || p.contains(char::is_whitespace) {
            return None;
        }
        tokens_out.push(p.to_string());
    }
    Some(tokens_out)
}

/// Map one split-expression token to the right CDX `license` shape.
/// SPDX-list IDs go into `license.id` (the canonical place, and
/// the CDX 1.6 schema enforces the SPDX list for that field).
/// `LicenseRef-*` / `DocumentRef-*` aren't on the SPDX list so they
/// go into `license.name` — schema-legal as a free-text label and
/// still counted by sbomqs's `comp_with_licenses`.
fn license_entry_for_token(token: &str, acknowledgement: &str) -> serde_json::Value {
    if token.starts_with("LicenseRef-") || token.starts_with("DocumentRef-") {
        json!({
            "license": {
                "name": token,
                "acknowledgement": acknowledgement,
            }
        })
    } else {
        json!({
            "license": {
                "id": token,
                "acknowledgement": acknowledgement,
            }
        })
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
            concluded_licenses: Vec::new(),
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
            external_references: Vec::new(),
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

    // --- License shape (sbomqs score lift Fix 1) -----------------------

    #[test]
    fn component_with_single_spdx_license_emits_id_form_with_acknowledgement() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("serde", "1.0.197");
        component.licenses = vec![
            mikebom_common::types::license::SpdxExpression::new("MIT").unwrap(),
        ];
        let integrity = clean_integrity();

        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");

        let comp = &bom["components"].as_array().expect("components")[0];
        let licenses = comp["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0]["license"]["id"], "MIT");
        assert_eq!(licenses[0]["license"]["acknowledgement"], "declared");
    }

    #[test]
    fn compound_or_license_splits_into_individual_ids() {
        // CDX 1.6 allows only ONE `{expression}` entry in a
        // `licenses[]` array and sbomqs scores `license.id`/`name`
        // only. `A OR B` becomes two separate `{license: {id}}`
        // entries — the disjunction is preserved structurally.
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("anyhow", "1.0.80");
        component.licenses = vec![
            mikebom_common::types::license::SpdxExpression::new(
                "Apache-2.0 OR MIT",
            )
            .unwrap(),
        ];
        let integrity = clean_integrity();
        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");
        let comp = &bom["components"].as_array().expect("components")[0];
        let licenses = comp["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 2);
        assert_eq!(licenses[0]["license"]["id"], "Apache-2.0");
        assert_eq!(licenses[0]["license"]["acknowledgement"], "declared");
        assert_eq!(licenses[1]["license"]["id"], "MIT");
        assert_eq!(licenses[1]["license"]["acknowledgement"], "declared");
    }

    #[test]
    fn compound_and_license_splits_into_individual_ids() {
        // AND splits cleanly: "both licenses apply" maps to listing
        // both as `{license: {id}}` entries (multiple listed licenses
        // = all apply, per CDX 1.6 `licenses` array semantics). This
        // is strictly more semantically faithful than an expression
        // for the AND case.
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("flask", "3.0.3");
        component.concluded_licenses = vec![
            mikebom_common::types::license::SpdxExpression::new(
                "BSD-2-Clause AND BSD-3-Clause",
            )
            .unwrap(),
        ];
        let integrity = clean_integrity();
        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");
        let comp = &bom["components"].as_array().expect("components")[0];
        let licenses = comp["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 2);
        assert_eq!(licenses[0]["license"]["id"], "BSD-2-Clause");
        assert_eq!(licenses[0]["license"]["acknowledgement"], "concluded");
        assert_eq!(licenses[1]["license"]["id"], "BSD-3-Clause");
    }

    #[test]
    fn compound_with_expression_falls_back_to_single_expression() {
        // `X WITH exception` can't be split — the WITH operator is
        // a semantic modifier on a base license, not a disjunction
        // or conjunction of independent licenses. Stays as one
        // `{expression}` entry.
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("openjdk", "21");
        component.concluded_licenses = vec![
            mikebom_common::types::license::SpdxExpression::new(
                "GPL-2.0-only WITH Classpath-exception-2.0",
            )
            .unwrap(),
        ];
        let integrity = clean_integrity();
        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");
        let comp = &bom["components"].as_array().expect("components")[0];
        let licenses = comp["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 1);
        assert_eq!(
            licenses[0]["expression"],
            "GPL-2.0-only WITH Classpath-exception-2.0",
        );
    }

    #[test]
    fn compound_and_with_license_ref_splits_using_name_field() {
        // ClearlyDefined returns shapes like
        // `BSD-3-Clause AND LicenseRef-scancode-google-patent-license-golang`
        // for `golang.org/x/sys`. CDX 1.6's `license.id` is SPDX-list
        // only, so the LicenseRef operand routes to `license.name`
        // instead. Both entries are schema-legal and sbomqs-countable.
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("x-sys", "0.5.0");
        component.concluded_licenses = vec![
            mikebom_common::types::license::SpdxExpression::new(
                "BSD-3-Clause AND LicenseRef-scancode-google-patent-license-golang",
            )
            .unwrap(),
        ];
        let integrity = clean_integrity();
        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");
        let comp = &bom["components"].as_array().expect("components")[0];
        let licenses = comp["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 2);
        assert_eq!(licenses[0]["license"]["id"], "BSD-3-Clause");
        assert_eq!(
            licenses[1]["license"]["name"],
            "LicenseRef-scancode-google-patent-license-golang",
        );
        assert!(licenses[1]["license"].get("id").is_none());
    }

    #[test]
    fn bare_license_ref_emits_name_form() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("proprietary", "1.0.0");
        component.licenses = vec![
            mikebom_common::types::license::SpdxExpression::new(
                "LicenseRef-internal-eula",
            )
            .unwrap(),
        ];
        let integrity = clean_integrity();
        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");
        let comp = &bom["components"].as_array().expect("components")[0];
        let licenses = comp["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0]["license"]["name"], "LicenseRef-internal-eula");
    }

    #[test]
    fn mixed_operators_fall_back_to_single_expression() {
        // `A AND B OR C` has ambiguous precedence without parens —
        // splitting would misrepresent either interpretation. Stays
        // as one `{expression}` entry.
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("complex", "1.0.0");
        component.concluded_licenses = vec![
            mikebom_common::types::license::SpdxExpression::new(
                "Apache-2.0 AND MIT OR BSD-3-Clause",
            )
            .unwrap(),
        ];
        let integrity = clean_integrity();
        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");
        let comp = &bom["components"].as_array().expect("components")[0];
        let licenses = comp["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 1);
        assert!(licenses[0]["expression"].is_string());
    }

    #[test]
    fn component_license_unknown_identifier_falls_back_to_expression() {
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("myapp", "0.1.0");
        component.licenses = vec![
            mikebom_common::types::license::SpdxExpression::new(
                "Custom-In-House-License",
            )
            .unwrap(),
        ];
        let integrity = clean_integrity();

        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");

        let comp = &bom["components"].as_array().expect("components")[0];
        let licenses = comp["licenses"].as_array().unwrap();
        assert_eq!(licenses[0]["expression"], "Custom-In-House-License");
        assert_eq!(licenses[0]["acknowledgement"], "declared");
    }

    #[test]
    fn concluded_licenses_emit_with_acknowledgement_concluded() {
        // Simulates the ClearlyDefined enrichment having added a
        // concluded SPDX expression after the package's manifest
        // declared one.
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("express", "4.18.2");
        component.licenses = vec![
            mikebom_common::types::license::SpdxExpression::new("MIT").unwrap(),
        ];
        component.concluded_licenses = vec![
            mikebom_common::types::license::SpdxExpression::new("MIT").unwrap(),
        ];
        let integrity = clean_integrity();

        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");

        let comp = &bom["components"].as_array().expect("components")[0];
        let licenses = comp["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 2);
        // First entry: declared MIT (from manifest).
        assert_eq!(licenses[0]["license"]["id"], "MIT");
        assert_eq!(licenses[0]["license"]["acknowledgement"], "declared");
        // Second entry: concluded MIT (from CD enrichment).
        assert_eq!(licenses[1]["license"]["id"], "MIT");
        assert_eq!(licenses[1]["license"]["acknowledgement"], "concluded");
    }

    #[test]
    fn concluded_licenses_can_differ_from_declared() {
        // CD's analysis may yield a different SPDX expression than the
        // package's own declared license — emit both side by side.
        let builder = CycloneDxBuilder::new(CycloneDxConfig::default());
        let mut component = make_component("foo", "1.0.0");
        component.licenses = vec![
            mikebom_common::types::license::SpdxExpression::new("MIT").unwrap(),
        ];
        component.concluded_licenses = vec![
            mikebom_common::types::license::SpdxExpression::new("Apache-2.0").unwrap(),
        ];
        let integrity = clean_integrity();

        let bom = builder
            .build(&[component], &[], &integrity, "myapp", &[])
            .expect("build bom");

        let comp = &bom["components"].as_array().expect("components")[0];
        let licenses = comp["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 2);
        let mut seen = std::collections::HashSet::new();
        for l in licenses {
            seen.insert((
                l["license"]["id"].as_str().unwrap().to_string(),
                l["license"]["acknowledgement"].as_str().unwrap().to_string(),
            ));
        }
        assert!(seen.contains(&("MIT".to_string(), "declared".to_string())));
        assert!(seen.contains(&("Apache-2.0".to_string(), "concluded".to_string())));
    }
}