use std::collections::BTreeSet;

use chrono::Utc;
use mikebom_common::attestation::metadata::GenerationContext;
use mikebom_common::resolution::ResolvedComponent;
use serde_json::json;

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

    let mut metadata = json!({
        "timestamp": timestamp,
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
            "bom-ref": format!("{}@{}", target_name, target_version)
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
        let meta = build_metadata("myapp", "0.1.0", GenerationContext::BuildTimeTrace, &[], &[]);

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

    #[test]
    fn metadata_bom_ref_format() {
        let meta = build_metadata("myapp", "0.1.0", GenerationContext::BuildTimeTrace, &[], &[]);
        assert_eq!(meta["component"]["bom-ref"], "myapp@0.1.0");
    }

    #[test]
    fn metadata_context_varies_per_variant() {
        let fs = build_metadata("myapp", "1.0", GenerationContext::FilesystemScan, &[], &[]);
        assert_eq!(fs["properties"][0]["value"], "filesystem-scan");

        let img = build_metadata("myapp", "1.0", GenerationContext::ContainerImageScan, &[], &[]);
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
        };

        let meta = build_metadata(
            "myapp",
            "0.1.0",
            GenerationContext::BuildTimeTrace,
            std::slice::from_ref(&c),
            &[],
        );
        assert!(
            meta.get("lifecycles").is_none(),
            "unknown tier should not produce a lifecycle entry"
        );
    }
}