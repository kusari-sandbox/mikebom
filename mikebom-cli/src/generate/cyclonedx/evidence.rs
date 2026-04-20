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

    let mut identity = json!({
        "field": "purl",
        "confidence": evidence.confidence,
        "methods": [
            {
                "technique": technique,
                "confidence": evidence.confidence
            }
        ]
    });

    // Include source connection IDs as additional evidence if present.
    if !evidence.source_connection_ids.is_empty() {
        identity["tools"] = json!(evidence
            .source_connection_ids
            .iter()
            .map(|id| json!({"ref": id}))
            .collect::<Vec<_>>());
    }

    let mut out = json!({
        "identity": identity
    });

    // Emit the deps.dev enrichment stamp as an evidence tool reference,
    // so downstream consumers can tell a license/CPE was upgraded via
    // the API rather than derived purely from local sources.
    if let Some(ref m) = evidence.deps_dev_match {
        let tool_ref =
            format!("deps.dev:{}:{}@{}", m.system, m.name, m.version);
        let existing_tools = out["identity"]["tools"].as_array().cloned();
        let mut tools = existing_tools.unwrap_or_default();
        tools.push(json!({"ref": tool_ref}));
        out["identity"]["tools"] = json!(tools);
    }

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

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

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
            result["identity"]["methods"][0]["technique"],
            "instrumentation"
        );
    }

    #[test]
    fn hash_match_maps_to_hash_comparison() {
        let ev = make_evidence(ResolutionTechnique::HashMatch, 0.99);
        let result = build_evidence(&ev, &[]);
        assert_eq!(
            result["identity"]["methods"][0]["technique"],
            "hash-comparison"
        );
    }

    #[test]
    fn file_path_maps_to_filename() {
        let ev = make_evidence(ResolutionTechnique::FilePathPattern, 0.7);
        let result = build_evidence(&ev, &[]);
        assert_eq!(result["identity"]["methods"][0]["technique"], "filename");
    }

    #[test]
    fn hostname_maps_to_other() {
        let ev = make_evidence(ResolutionTechnique::HostnameHeuristic, 0.5);
        let result = build_evidence(&ev, &[]);
        assert_eq!(result["identity"]["methods"][0]["technique"], "other");
    }

    #[test]
    fn package_database_maps_to_manifest_analysis() {
        let ev = make_evidence(ResolutionTechnique::PackageDatabase, 0.85);
        let result = build_evidence(&ev, &[]);
        assert_eq!(
            result["identity"]["methods"][0]["technique"],
            "manifest-analysis"
        );
    }

    #[test]
    fn confidence_is_preserved() {
        let ev = make_evidence(ResolutionTechnique::UrlPattern, 0.87);
        let result = build_evidence(&ev, &[]);
        assert_eq!(result["identity"]["confidence"], 0.87);
        assert_eq!(result["identity"]["methods"][0]["confidence"], 0.87);
    }

    #[test]
    fn source_connections_appear_as_tools() {
        let ev = ResolutionEvidence {
            technique: ResolutionTechnique::UrlPattern,
            confidence: 0.9,
            source_connection_ids: vec!["conn-1".to_string(), "conn-2".to_string()],
            source_file_paths: vec![],
            deps_dev_match: None,
        };
        let result = build_evidence(&ev, &[]);
        let tools = result["identity"]["tools"].as_array().expect("tools array");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["ref"], "conn-1");
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
