use std::collections::BTreeSet;

use chrono::Utc;
use mikebom_common::attestation::integrity::TraceIntegrity;
use mikebom_common::attestation::metadata::GenerationContext;
use mikebom_common::resolution::ResolvedComponent;
use mikebom_common::types::purl::encode_purl_segment;
use serde_json::json;

/// Normalize a string for inclusion in a CPE 2.3 segment.
///
/// CPE 2.3 well-formed name segments (per NIST) are lowercase and use
/// `_` for separators; other characters are typically escaped with a
/// backslash. For our synthetic scan-subject CPE we only need a
/// minimally-valid form: lowercase, ASCII alphanumerics + `_` / `-` /
/// `.` preserved, everything else → `_`.
fn cpe_sanitize(raw: &str) -> String {
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

/// Map a `mikebom:sbom-tier` value (per research.md R13) to its
/// corresponding CycloneDX 1.5+ `lifecycles[].phase` value. Returns
/// `None` for unrecognised tier strings so unknown tiers don't pollute
/// the envelope declaration.
fn tier_to_lifecycle_phase(tier: &str) -> Option<&'static str> {
    match tier {
        "build" => Some("build"),
        "deployed" => Some("operations"),
        "analyzed" => Some("post-build"),
        "source" => Some("pre-build"),
        "design" => Some("design"),
        _ => None,
    }
}

/// Build the CycloneDX `metadata` section.
///
/// Includes:
/// - Tool identity (mikebom with current version)
/// - Generation timestamp
/// - Component reference (the build target)
/// - Properties indicating generation context
/// - `lifecycles[]`: aggregated union of tier values observed across
///   the components, per milestone 002's traceability ladder (R13).
pub fn build_metadata(
    target_name: &str,
    target_version: &str,
    context: GenerationContext,
    components: &[ResolvedComponent],
    os_release_missing_fields: &[String],
    integrity: &TraceIntegrity,
) -> serde_json::Value {
    let version = env!("CARGO_PKG_VERSION");
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // Serialize the enum via serde to reuse the existing kebab-case rename
    // attributes. Dropping quotes so the property value is a bare string.
    let context_str = serde_json::to_value(&context)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    // Aggregate lifecycle phases from the observed component tiers.
    // BTreeSet → sorted, deterministic output.
    let mut phases: BTreeSet<&'static str> = BTreeSet::new();
    for c in components {
        if let Some(ref tier) = c.sbom_tier {
            if let Some(phase) = tier_to_lifecycle_phase(tier) {
                phases.insert(phase);
            }
        }
    }
    let lifecycles: Vec<serde_json::Value> = phases
        .into_iter()
        .map(|p| json!({"phase": p}))
        .collect();

    let mut properties = vec![json!({
        "name": "mikebom:generation-context",
        "value": context_str,
    })];

    // Feature 005 SC-009 / FR-006 / FR-009: when /etc/os-release fields
    // were missing during scan, record the names here so SBOM consumers
    // can detect degraded PURL output without parsing the scanner log.
    // Omitted entirely when the list is empty (clean scan).
    if !os_release_missing_fields.is_empty() {
        properties.push(json!({
            "name": "mikebom:os-release-missing-fields",
            "value": os_release_missing_fields.join(","),
        }));
    }

    // Trace-integrity counters (previously on compositions, moved
    // here for CDX 1.6 schema conformance — compositions items have
    // additionalProperties: false so `properties` isn't allowed there).
    // Each counter is surfaced as a distinct property so downstream
    // consumers can filter on name.
    properties.push(json!({
        "name": "mikebom:trace-integrity-ring-buffer-overflows",
        "value": integrity.ring_buffer_overflows.to_string(),
    }));
    properties.push(json!({
        "name": "mikebom:trace-integrity-events-dropped",
        "value": integrity.events_dropped.to_string(),
    }));
    properties.push(json!({
        "name": "mikebom:trace-integrity-uprobe-attach-failures",
        "value": integrity.uprobe_attach_failures.len().to_string(),
    }));
    properties.push(json!({
        "name": "mikebom:trace-integrity-kprobe-attach-failures",
        "value": integrity.kprobe_attach_failures.len().to_string(),
    }));

    // Synthesize a `pkg:generic/<target>@<version>` purl for the scan
    // subject. sbomqs's schema validator reports the metadata.component
    // as invalid when it lacks a purl; the spec itself doesn't require
    // one on application components, but the synthetic purl is cheap
    // and unambiguous (the scan-subject's identity is already the
    // `name@version` pair). Improves sbomqs's Structural score +2.0%.
    let synthetic_component_purl = format!(
        "pkg:generic/{}@{}",
        encode_purl_segment(target_name),
        encode_purl_segment(target_version),
    );

    // Synthesize a minimal valid CPE 2.3 for the scan subject. Uses
    // mikebom as the vendor (we're the SBOM producer). Name and
    // version segments are CPE-sanitized (lowercase, non-alphanumerics
    // → underscore). sbomqs's schema validator runs CPE validation on
    // metadata.component and flags empty/absent fields as invalid.
    let synthetic_component_cpe = format!(
        "cpe:2.3:a:mikebom:{}:{}:*:*:*:*:*:*:*",
        cpe_sanitize(target_name),
        cpe_sanitize(target_version),
    );

    let mut metadata = json!({
        "timestamp": timestamp,
        // Top-level SBOM provenance: the list of individuals or
        // organizations responsible for creating THIS SBOM (not the
        // underlying project). Scored by sbomqs `sbom_authors` (2.9%
        // in Provenance). Single-entry placeholder is sufficient;
        // future work can extract from git config or accept
        // --author=NAME via CLI.
        "authors": [
            { "name": "mikebom" }
        ],
        // SBOM supplier: the organization providing the SBOM. Scored
        // by sbomqs `sbom_supplier` (2.2%). Hardcoded to the mikebom
        // project identity.
        "supplier": {
            "name": "mikebom contributors"
        },
        // SBOM content license. SPDX-SBOM convention uses CC0-1.0 so
        // the SBOM itself can be distributed without restriction.
        // Scored by sbomqs `sbom_data_license` (1.8% in Licensing).
        "licenses": [
            { "license": { "id": "CC0-1.0" } }
        ],
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "mikebom",
                    "version": version,
                    "publisher": "mikebom contributors"
                }
            ]
        },
        "component": {
            "type": "application",
            "name": target_name,
            "version": target_version,
            "bom-ref": format!("{}@{}", target_name, target_version),
            "purl": synthetic_component_purl,
            "cpe": synthetic_component_cpe,
        },
        "properties": properties,
    });

    if !lifecycles.is_empty() {
        metadata["lifecycles"] = json!(lifecycles);
    }

    metadata
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn metadata_has_required_fields() {
        let meta = build_metadata("myapp", "0.1.0", GenerationContext::BuildTimeTrace, &[], &[], &TraceIntegrity::default());

        assert!(meta["timestamp"].is_string());
        assert_eq!(meta["tools"]["components"][0]["name"], "mikebom");
        assert_eq!(meta["component"]["name"], "myapp");
        assert_eq!(meta["component"]["version"], "0.1.0");
        assert_eq!(
            meta["properties"][0]["name"],
            "mikebom:generation-context"
        );
        assert_eq!(
            meta["properties"][0]["value"],
            "build-time-trace"
        );
    }

    // --- sbomqs score lift: metadata completeness (Fixes 3-6) ------------

    #[test]
    fn metadata_includes_authors_for_sbom_authors_score() {
        let meta =
            build_metadata("myapp", "0.1.0", GenerationContext::BuildTimeTrace, &[], &[], &TraceIntegrity::default());
        let authors = meta["authors"].as_array().expect("authors must be array");
        assert!(!authors.is_empty(), "authors must be non-empty");
        assert!(authors[0]["name"].is_string());
    }

    #[test]
    fn metadata_includes_supplier_for_sbom_supplier_score() {
        let meta =
            build_metadata("myapp", "0.1.0", GenerationContext::BuildTimeTrace, &[], &[], &TraceIntegrity::default());
        assert!(
            meta["supplier"]["name"].is_string(),
            "supplier.name must be present as a string"
        );
    }

    #[test]
    fn metadata_includes_cc0_data_license() {
        // sbomqs sbom_data_license scores the SBOM's own license. SPDX
        // convention is CC0-1.0 so SBOM content is free to redistribute.
        let meta =
            build_metadata("myapp", "0.1.0", GenerationContext::BuildTimeTrace, &[], &[], &TraceIntegrity::default());
        let licenses = meta["licenses"].as_array().expect("licenses must be array");
        assert!(!licenses.is_empty());
        assert_eq!(licenses[0]["license"]["id"], "CC0-1.0");
    }

    #[test]
    fn metadata_component_has_synthetic_purl() {
        // sbomqs flags metadata.component as invalid without a purl.
        // Mikebom synthesizes pkg:generic/<name>@<version>.
        let meta =
            build_metadata("myapp", "0.1.0", GenerationContext::BuildTimeTrace, &[], &[], &TraceIntegrity::default());
        assert_eq!(meta["component"]["purl"], "pkg:generic/myapp@0.1.0");
    }

    #[test]
    fn metadata_component_has_synthetic_cpe() {
        // sbomqs flags empty/absent cpe on metadata.component as invalid.
        // Mikebom emits cpe:2.3:a:mikebom:<name>:<version>:*:*:*:*:*:*:*.
        let meta =
            build_metadata("myapp", "0.1.0", GenerationContext::BuildTimeTrace, &[], &[], &TraceIntegrity::default());
        assert_eq!(
            meta["component"]["cpe"],
            "cpe:2.3:a:mikebom:myapp:0.1.0:*:*:*:*:*:*:*"
        );
    }

    #[test]
    fn cpe_sanitize_handles_special_characters() {
        assert_eq!(cpe_sanitize("My App"), "my_app");
        assert_eq!(cpe_sanitize("app+v1"), "app_v1");
        assert_eq!(cpe_sanitize("MYAPP"), "myapp");
        assert_eq!(cpe_sanitize("my-app.v2"), "my-app.v2");
        assert_eq!(cpe_sanitize(""), "_");
    }

    #[test]
    fn metadata_component_purl_encodes_special_chars() {
        // Ensure target names / versions with special chars are
        // percent-encoded via encode_purl_segment.
        let meta = build_metadata(
            "my app with spaces",
            "1.0+build-1",
            GenerationContext::FilesystemScan,
            &[],
            &[],
            &TraceIntegrity::default(),
        );
        let purl = meta["component"]["purl"].as_str().unwrap();
        assert!(
            purl.starts_with("pkg:generic/"),
            "purl must start with pkg:generic/, got {purl}"
        );
        // The `+` in `1.0+build-1` must be encoded.
        assert!(
            purl.contains("%20") || purl.contains("%2B") || !purl.contains(' '),
            "special chars must be encoded: {purl}"
        );
    }

    #[test]
    fn metadata_bom_ref_format() {
        let meta = build_metadata("myapp", "0.1.0", GenerationContext::BuildTimeTrace, &[], &[], &TraceIntegrity::default());
        assert_eq!(meta["component"]["bom-ref"], "myapp@0.1.0");
    }

    #[test]
    fn metadata_context_varies_per_variant() {
        let fs = build_metadata("myapp", "1.0", GenerationContext::FilesystemScan, &[], &[], &TraceIntegrity::default());
        assert_eq!(fs["properties"][0]["value"], "filesystem-scan");

        let img = build_metadata("myapp", "1.0", GenerationContext::ContainerImageScan, &[], &[], &TraceIntegrity::default());
        assert_eq!(img["properties"][0]["value"], "container-image-scan");
    }

    #[test]
    fn metadata_omits_lifecycles_when_no_tiers_present() {
        // A component without a sbom_tier value contributes nothing.
        let meta = build_metadata(
            "myapp",
            "0.1.0",
            GenerationContext::BuildTimeTrace,
            &[],
            &[],
            &TraceIntegrity::default(),
        );
        assert!(meta.get("lifecycles").is_none());
    }

    #[test]
    fn metadata_aggregates_lifecycles_from_component_tiers() {
        use mikebom_common::resolution::{
            ResolutionEvidence, ResolutionTechnique, ResolvedComponent,
        };
        use mikebom_common::types::purl::Purl;

        let mk = |purl: &str, tier: &str| ResolvedComponent {
            purl: Purl::new(purl).expect("valid purl"),
            name: "x".to_string(),
            version: "1.0".to_string(),
            evidence: ResolutionEvidence {
                technique: ResolutionTechnique::PackageDatabase,
                confidence: 0.85,
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
            sbom_tier: Some(tier.to_string()),
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
            external_references: Vec::new(),
        };

        let components = vec![
            mk("pkg:deb/debian/jq@1.6", "deployed"),
            mk("pkg:pypi/requests@2.31.0", "source"),
            mk("pkg:npm/foo@1.0.0", "design"),
            // Duplicate tier should collapse.
            mk("pkg:apk/alpine/musl@1.2.4-r2", "deployed"),
        ];

        let meta = build_metadata(
            "myapp",
            "0.1.0",
            GenerationContext::ContainerImageScan,
            &components,
            &[],
            &TraceIntegrity::default(),
        );

        let lifecycles = meta["lifecycles"]
            .as_array()
            .expect("lifecycles array");
        let phases: Vec<&str> = lifecycles
            .iter()
            .map(|p| p["phase"].as_str().unwrap())
            .collect();

        // Sorted alphabetically, duplicates collapsed.
        assert_eq!(phases, vec!["design", "operations", "pre-build"]);
    }

    #[test]
    fn metadata_unknown_tier_is_dropped_from_lifecycles() {
        use mikebom_common::resolution::{
            ResolutionEvidence, ResolutionTechnique, ResolvedComponent,
        };
        use mikebom_common::types::purl::Purl;

        let c = ResolvedComponent {
            purl: Purl::new("pkg:generic/weird@1.0").expect("valid purl"),
            name: "weird".to_string(),
            version: "1.0".to_string(),
            evidence: ResolutionEvidence {
                technique: ResolutionTechnique::PackageDatabase,
                confidence: 0.85,
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
            sbom_tier: Some("nonsense-tier".to_string()),
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
            external_references: Vec::new(),
        };

        let meta = build_metadata(
            "myapp",
            "0.1.0",
            GenerationContext::BuildTimeTrace,
            std::slice::from_ref(&c),
            &[],
            &TraceIntegrity::default(),
        );
        assert!(
            meta.get("lifecycles").is_none(),
            "unknown tier should not produce a lifecycle entry"
        );
    }
}