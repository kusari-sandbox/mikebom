use serde_json::json;

use mikebom_common::resolution::{FileOccurrence, ResolutionEvidence, ResolutionTechnique};

/// Map a `ResolutionEvidence` (plus optional per-file occurrences) to a
/// CycloneDX 1.6 `evidence` object.
///
/// Technique mapping (right-hand side uses CycloneDX 1.6 technique
/// identifiers):
/// - UrlPattern        -> "instrumentation"
/// - HashMatch         -> "hash-comparison"
/// - PackageDatabase   -> "manifest-analysis"  (reads the package db manifest)
/// - FilePathPattern   -> "filename"
/// - HostnameHeuristic -> "other"
///
/// Per-file occurrences (deep-hashed dpkg components) are emitted under
/// `evidence.occurrences[]`. Each occurrence records its location, the
/// SHA-256 we computed at scan time, and — when dpkg's `.md5sums`
/// recorded one — the MD5 it shipped with, packed into
/// `additionalContext` for cross-reference.
///
/// CDX 1.6 notes:
/// - `evidence.identity` is emitted as an ARRAY of identity objects
///   (bom-1.6.schema.json:2091-2107). The single-object form from 1.5
///   is deprecated.
/// - `evidence.identity[].tools` used to carry source connection IDs
///   and deps.dev markers, but CDX 1.6 requires those entries to be
///   bom-refs of items declared elsewhere in the BOM. Neither mikebom
///   payload fits that — both are now emitted as component properties
///   via [`evidence_to_properties`] instead.
pub fn build_evidence(
    evidence: &ResolutionEvidence,
    occurrences: &[FileOccurrence],
) -> serde_json::Value {
    let technique = match evidence.technique {
        ResolutionTechnique::UrlPattern => "instrumentation",
        ResolutionTechnique::HashMatch => "hash-comparison",
        ResolutionTechnique::PackageDatabase => "manifest-analysis",
        ResolutionTechnique::FilePathPattern => "filename",
        ResolutionTechnique::HostnameHeuristic => "other",
    };

    let identity_obj = json!({
        "field": "purl",
        "confidence": evidence.confidence,
        "methods": [
            {
                "technique": technique,
                "confidence": evidence.confidence
            }
        ]
    });

    let mut out = json!({
        "identity": [identity_obj]
    });

    if !occurrences.is_empty() {
        let occ_entries: Vec<serde_json::Value> = occurrences
            .iter()
            .map(|o| {
                let mut ctx = serde_json::Map::new();
                ctx.insert("sha256".to_string(), json!(o.sha256));
                if let Some(ref md5) = o.md5_legacy {
                    ctx.insert("md5".to_string(), json!(md5));
                }
                json!({
                    "location": o.location,
                    "additionalContext": serde_json::to_string(&ctx)
                        .unwrap_or_default(),
                })
            })
            .collect();
        out["occurrences"] = json!(occ_entries);
    }

    out
}

/// Serialize `source_connection_ids` and `deps_dev_match` as CDX
/// component properties. These used to live under
/// `evidence.identity.tools` — per CDX 1.6 those entries must be
/// bom-refs to items declared elsewhere in the BOM, but connection IDs
/// (TLS session tokens from the build trace) and deps.dev markers are
/// neither. Properties are the idiomatic home for scanner-specific
/// provenance data.
pub fn evidence_to_properties(
    evidence: &ResolutionEvidence,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    if !evidence.source_connection_ids.is_empty() {
        out.push(json!({
            "name": "mikebom:source-connection-ids",
            "value": evidence.source_connection_ids.join(","),
        }));
    }
    if let Some(ref m) = evidence.deps_dev_match {
        out.push(json!({
            "name": "mikebom:deps-dev-match",
            "value": format!("{}:{}@{}", m.system, m.name, m.version),
        }));
    }
    out
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::resolution::DepsDevMatch;

    fn make_evidence(technique: ResolutionTechnique, confidence: f64) -> ResolutionEvidence {
        ResolutionEvidence {
            technique,
            confidence,
            source_connection_ids: vec![],
            source_file_paths: vec![],
            deps_dev_match: None,
        }
    }

    #[test]
    fn url_pattern_maps_to_instrumentation() {
        let ev = make_evidence(ResolutionTechnique::UrlPattern, 0.95);
        let result = build_evidence(&ev, &[]);
        assert_eq!(
            result["identity"][0]["methods"][0]["technique"],
            "instrumentation"
        );
    }

    #[test]
    fn hash_match_maps_to_hash_comparison() {
        let ev = make_evidence(ResolutionTechnique::HashMatch, 0.99);
        let result = build_evidence(&ev, &[]);
        assert_eq!(
            result["identity"][0]["methods"][0]["technique"],
            "hash-comparison"
        );
    }

    #[test]
    fn file_path_maps_to_filename() {
        let ev = make_evidence(ResolutionTechnique::FilePathPattern, 0.7);
        let result = build_evidence(&ev, &[]);
        assert_eq!(
            result["identity"][0]["methods"][0]["technique"],
            "filename"
        );
    }

    #[test]
    fn hostname_maps_to_other() {
        let ev = make_evidence(ResolutionTechnique::HostnameHeuristic, 0.5);
        let result = build_evidence(&ev, &[]);
        assert_eq!(result["identity"][0]["methods"][0]["technique"], "other");
    }

    #[test]
    fn package_database_maps_to_manifest_analysis() {
        let ev = make_evidence(ResolutionTechnique::PackageDatabase, 0.85);
        let result = build_evidence(&ev, &[]);
        assert_eq!(
            result["identity"][0]["methods"][0]["technique"],
            "manifest-analysis"
        );
    }

    #[test]
    fn confidence_is_preserved() {
        let ev = make_evidence(ResolutionTechnique::UrlPattern, 0.87);
        let result = build_evidence(&ev, &[]);
        assert_eq!(result["identity"][0]["confidence"], 0.87);
        assert_eq!(result["identity"][0]["methods"][0]["confidence"], 0.87);
    }

    #[test]
    fn identity_is_emitted_as_array_not_object() {
        // CDX 1.6 requires evidence.identity to be an array.
        let ev = make_evidence(ResolutionTechnique::UrlPattern, 0.9);
        let result = build_evidence(&ev, &[]);
        assert!(
            result["identity"].is_array(),
            "evidence.identity must be an array per CDX 1.6"
        );
        assert_eq!(result["identity"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn tools_field_is_never_emitted() {
        // Regression guard for the sbomqs parse failure: the CDX Go
        // library rejects our old `{"ref": "..."}` object shape.
        // Ensure the field simply isn't present, regardless of what's
        // on the evidence.
        let ev_with_everything = ResolutionEvidence {
            technique: ResolutionTechnique::UrlPattern,
            confidence: 0.9,
            source_connection_ids: vec!["conn-1".to_string(), "conn-2".to_string()],
            source_file_paths: vec![],
            deps_dev_match: Some(DepsDevMatch {
                system: "npm".to_string(),
                name: "express".to_string(),
                version: "4.19.2".to_string(),
            }),
        };
        let result = build_evidence(&ev_with_everything, &[]);
        assert!(
            result["identity"][0].get("tools").is_none(),
            "evidence.identity[].tools must not be emitted: got {:?}",
            result["identity"][0].get("tools")
        );
    }

    #[test]
    fn evidence_to_properties_emits_connection_ids() {
        let ev = ResolutionEvidence {
            technique: ResolutionTechnique::UrlPattern,
            confidence: 0.9,
            source_connection_ids: vec!["conn-1".to_string(), "conn-2".to_string()],
            source_file_paths: vec![],
            deps_dev_match: None,
        };
        let props = evidence_to_properties(&ev);
        assert_eq!(props.len(), 1);
        assert_eq!(props[0]["name"], "mikebom:source-connection-ids");
        assert_eq!(props[0]["value"], "conn-1,conn-2");
    }

    #[test]
    fn evidence_to_properties_emits_deps_dev_match() {
        let ev = ResolutionEvidence {
            technique: ResolutionTechnique::HashMatch,
            confidence: 0.9,
            source_connection_ids: vec![],
            source_file_paths: vec![],
            deps_dev_match: Some(DepsDevMatch {
                system: "npm".to_string(),
                name: "express".to_string(),
                version: "4.19.2".to_string(),
            }),
        };
        let props = evidence_to_properties(&ev);
        assert_eq!(props.len(), 1);
        assert_eq!(props[0]["name"], "mikebom:deps-dev-match");
        assert_eq!(props[0]["value"], "npm:express@4.19.2");
    }

    #[test]
    fn evidence_to_properties_returns_empty_when_no_provenance() {
        let ev = make_evidence(ResolutionTechnique::FilePathPattern, 0.7);
        let props = evidence_to_properties(&ev);
        assert!(props.is_empty());
    }

    #[test]
    fn evidence_to_properties_emits_both_when_both_present() {
        let ev = ResolutionEvidence {
            technique: ResolutionTechnique::UrlPattern,
            confidence: 0.95,
            source_connection_ids: vec!["conn-7".to_string()],
            source_file_paths: vec![],
            deps_dev_match: Some(DepsDevMatch {
                system: "maven".to_string(),
                name: "com.google.guava:guava".to_string(),
                version: "32.1.3-jre".to_string(),
            }),
        };
        let props = evidence_to_properties(&ev);
        assert_eq!(props.len(), 2);
        assert_eq!(props[0]["name"], "mikebom:source-connection-ids");
        assert_eq!(props[1]["name"], "mikebom:deps-dev-match");
    }

    #[test]
    fn occurrences_are_emitted_when_present() {
        let ev = make_evidence(ResolutionTechnique::PackageDatabase, 0.85);
        let occs = vec![
            FileOccurrence {
                location: "/usr/bin/jq".to_string(),
                sha256: "a".repeat(64),
                md5_legacy: Some("b".repeat(32)),
            },
            FileOccurrence {
                location: "/usr/share/doc/jq/copyright".to_string(),
                sha256: "c".repeat(64),
                md5_legacy: None,
            },
        ];
        let result = build_evidence(&ev, &occs);
        let out_occs = result["occurrences"]
            .as_array()
            .expect("occurrences array");
        assert_eq!(out_occs.len(), 2);
        assert_eq!(out_occs[0]["location"], "/usr/bin/jq");
        let ctx0: serde_json::Value =
            serde_json::from_str(out_occs[0]["additionalContext"].as_str().unwrap())
                .expect("ctx parses");
        assert_eq!(ctx0["sha256"], "a".repeat(64));
        assert_eq!(ctx0["md5"], "b".repeat(32));

        let ctx1: serde_json::Value =
            serde_json::from_str(out_occs[1]["additionalContext"].as_str().unwrap())
                .expect("ctx parses");
        assert!(ctx1.get("md5").is_none());
    }

    #[test]
    fn occurrences_omitted_when_empty() {
        let ev = make_evidence(ResolutionTechnique::PackageDatabase, 0.85);
        let result = build_evidence(&ev, &[]);
        assert!(result.get("occurrences").is_none());
    }
}
