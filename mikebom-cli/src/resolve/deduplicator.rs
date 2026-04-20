//! Merge duplicate component resolutions, keeping the highest confidence.
//!
//! When multiple resolution techniques identify the same package (e.g., URL
//! pattern matching and hash-based lookup both find `serde@1.0.197`), we
//! merge them into a single `ResolvedComponent` with the highest confidence
//! score and combined evidence from all sources.

use std::collections::HashMap;

use mikebom_common::resolution::ResolvedComponent;

/// Deduplicate resolved components by (ecosystem, name, version).
///
/// For each group of duplicates:
/// - Keep the entry with the highest confidence score.
/// - Merge `source_connection_ids` and `source_file_paths` from all entries.
/// - Merge hashes, retaining unique values.
pub fn deduplicate(components: Vec<ResolvedComponent>) -> Vec<ResolvedComponent> {
    if components.is_empty() {
        return Vec::new();
    }

    // Group by (ecosystem, name, version).
    let mut groups: HashMap<(String, String, String), Vec<ResolvedComponent>> = HashMap::new();

    for component in components {
        let key = (
            component.purl.ecosystem().to_string(),
            component.name.clone(),
            component.version.clone(),
        );
        groups.entry(key).or_default().push(component);
    }

    let mut result = Vec::with_capacity(groups.len());

    for (_key, mut group) in groups {
        if group.len() == 1 {
            result.push(group.remove(0));
            continue;
        }

        // Sort by confidence descending; the first entry is our "winner".
        group.sort_by(|a, b| {
            b.evidence
                .confidence
                .partial_cmp(&a.evidence.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut best = group.remove(0);

        // Merge evidence from remaining entries.
        for other in group {
            for conn_id in other.evidence.source_connection_ids {
                if !best.evidence.source_connection_ids.contains(&conn_id) {
                    best.evidence.source_connection_ids.push(conn_id);
                }
            }
            for file_path in other.evidence.source_file_paths {
                if !best.evidence.source_file_paths.contains(&file_path) {
                    best.evidence.source_file_paths.push(file_path);
                }
            }
            for hash in other.hashes {
                if !best.hashes.contains(&hash) {
                    best.hashes.push(hash);
                }
            }
            // If the best doesn't have a deps_dev_match but another does, take it.
            if best.evidence.deps_dev_match.is_none() && other.evidence.deps_dev_match.is_some() {
                best.evidence.deps_dev_match = other.evidence.deps_dev_match;
            }
            // Dev-flag merge rule per research.md R8: `Some(false)` (prod)
            // wins over `Some(true)` (dev-only). `None` (source without
            // dev/prod info) merges with either without overriding.
            best.is_dev = match (best.is_dev, other.is_dev) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), _) | (_, Some(true)) => Some(true),
                _ => None,
            };
            // Prefer an existing requirement_range / source_type /
            // sbom_tier; only adopt from `other` when best's is None.
            if best.requirement_range.is_none() {
                best.requirement_range = other.requirement_range;
            }
            if best.source_type.is_none() {
                best.source_type = other.source_type;
            }
            if best.sbom_tier.is_none() {
                best.sbom_tier = other.sbom_tier.clone();
            }
            // Go-specific rule (milestone 003 US1 T024): when the same
            // pkg:golang/...@... PURL appears once as `source` (go.sum)
            // and once as `analyzed` (binary BuildInfo), prefer
            // `source` — the lockfile hash is authoritative, the
            // binary's embedded module list is derived. The dedup
            // winner is already picked by confidence, but for Go we
            // override the tier choice after the fact.
            if best.purl.ecosystem() == "golang" {
                let other_is_source = matches!(other.sbom_tier.as_deref(), Some("source"));
                let best_is_analyzed = matches!(best.sbom_tier.as_deref(), Some("analyzed"));
                if best_is_analyzed && other_is_source {
                    best.sbom_tier = Some("source".to_string());
                }
            }
        }

        result.push(best);
    }

    // Sort the output deterministically by PURL string.
    result.sort_by(|a, b| a.purl.as_str().cmp(b.purl.as_str()));

    result
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::resolution::{ResolutionEvidence, ResolutionTechnique};
    use mikebom_common::types::hash::ContentHash;
    use mikebom_common::types::purl::Purl;

    fn make_component(
        purl_str: &str,
        technique: ResolutionTechnique,
        confidence: f64,
        conn_ids: Vec<&str>,
        file_paths: Vec<&str>,
    ) -> ResolvedComponent {
        let purl = Purl::new(purl_str).expect("valid purl");
        ResolvedComponent {
            name: purl.name().to_string(),
            version: purl.version().unwrap_or("0.0.0").to_string(),
            purl,
            evidence: ResolutionEvidence {
                technique,
                confidence,
                source_connection_ids: conn_ids.into_iter().map(String::from).collect(),
                source_file_paths: file_paths.into_iter().map(String::from).collect(),
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
    fn no_duplicates_unchanged() {
        let components = vec![
            make_component(
                "pkg:cargo/serde@1.0.197",
                ResolutionTechnique::UrlPattern,
                0.95,
                vec!["conn-1"],
                vec![],
            ),
            make_component(
                "pkg:cargo/tokio@1.38.0",
                ResolutionTechnique::UrlPattern,
                0.95,
                vec!["conn-2"],
                vec![],
            ),
        ];

        let deduped = deduplicate(components);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn duplicates_merged_highest_confidence_wins() {
        let components = vec![
            make_component(
                "pkg:cargo/serde@1.0.197",
                ResolutionTechnique::UrlPattern,
                0.95,
                vec!["conn-1"],
                vec![],
            ),
            make_component(
                "pkg:cargo/serde@1.0.197",
                ResolutionTechnique::HashMatch,
                0.90,
                vec!["conn-2"],
                vec!["/path/to/serde"],
            ),
        ];

        let deduped = deduplicate(components);
        assert_eq!(deduped.len(), 1);

        let merged = &deduped[0];
        assert_eq!(merged.evidence.confidence, 0.95);
        assert_eq!(merged.evidence.technique, ResolutionTechnique::UrlPattern);
        // Evidence from both sources should be merged.
        assert!(merged.evidence.source_connection_ids.contains(&"conn-1".to_string()));
        assert!(merged.evidence.source_connection_ids.contains(&"conn-2".to_string()));
        assert!(merged.evidence.source_file_paths.contains(&"/path/to/serde".to_string()));
    }

    #[test]
    fn hashes_merged_across_duplicates() {
        let hash1 = ContentHash::sha256(
            "3fb1c873e1b9b056a4dc4c0c198b24c3ffa59243c322bfd971d2d5ef4f463ee1",
        )
        .expect("valid");
        let hash2 = ContentHash::sha256(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        )
        .expect("valid");

        let mut c1 = make_component(
            "pkg:cargo/serde@1.0.197",
            ResolutionTechnique::UrlPattern,
            0.95,
            vec![],
            vec![],
        );
        c1.hashes.push(hash1.clone());

        let mut c2 = make_component(
            "pkg:cargo/serde@1.0.197",
            ResolutionTechnique::HashMatch,
            0.90,
            vec![],
            vec![],
        );
        c2.hashes.push(hash2.clone());

        let deduped = deduplicate(vec![c1, c2]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].hashes.len(), 2);
    }

    #[test]
    fn empty_input_returns_empty() {
        let deduped = deduplicate(vec![]);
        assert!(deduped.is_empty());
    }

    #[test]
    fn is_dev_merge_prod_wins_over_dev() {
        // Same package appears as prod in one source and dev in another.
        // Prod should win per research.md R8 — a package pulled in by
        // any prod dep chain is not really "dev-only".
        let mut prod = make_component(
            "pkg:npm/foo@1.0.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/path/prod-lockfile"],
        );
        prod.is_dev = Some(false);
        let mut dev = make_component(
            "pkg:npm/foo@1.0.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/path/dev-lockfile"],
        );
        dev.is_dev = Some(true);

        let deduped = deduplicate(vec![prod, dev]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].is_dev, Some(false));
    }

    #[test]
    fn is_dev_merge_none_preserves_explicit_flag() {
        // One side has None (source carries no dev/prod), other has
        // Some(true). The flag propagates through the merge.
        let explicit_dev = {
            let mut c = make_component(
                "pkg:npm/bar@2.0.0",
                ResolutionTechnique::PackageDatabase,
                0.85,
                vec![],
                vec![],
            );
            c.is_dev = Some(true);
            c
        };
        let no_flag = make_component(
            "pkg:npm/bar@2.0.0",
            ResolutionTechnique::FilePathPattern,
            0.70,
            vec![],
            vec![],
        ); // is_dev = None by default

        let deduped = deduplicate(vec![explicit_dev, no_flag]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].is_dev, Some(true));
    }

    #[test]
    fn sbom_tier_propagates_when_winner_is_none() {
        let mut lockfile = make_component(
            "pkg:pypi/requests@2.31.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/poetry.lock"],
        );
        lockfile.sbom_tier = Some("source".to_string());
        let venv = make_component(
            "pkg:pypi/requests@2.31.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/venv/.../requests-2.31.0.dist-info/METADATA"],
        ); // sbom_tier = None

        let deduped = deduplicate(vec![lockfile, venv]);
        assert_eq!(deduped.len(), 1);
        // Winner's tier takes precedence; since winners sort-by-confidence
        // is equal here, order-first wins — but either way, the merge
        // preserves the non-None value when the winner is None.
        assert!(deduped[0].sbom_tier.is_some());
    }

    #[test]
    fn different_versions_not_merged() {
        let components = vec![
            make_component(
                "pkg:cargo/serde@1.0.197",
                ResolutionTechnique::UrlPattern,
                0.95,
                vec!["conn-1"],
                vec![],
            ),
            make_component(
                "pkg:cargo/serde@1.0.198",
                ResolutionTechnique::UrlPattern,
                0.95,
                vec!["conn-2"],
                vec![],
            ),
        ];

        let deduped = deduplicate(components);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn golang_source_wins_over_analyzed_on_dedup() {
        // Same pkg:golang/...@... PURL, one from go.sum (source tier)
        // and one from binary BuildInfo (analyzed tier). The source
        // tier must carry forward; evidence.source_file_paths from
        // both must merge.
        let mut go_source = make_component(
            "pkg:golang/github.com/spf13/cobra@v1.7.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/go.sum"],
        );
        go_source.sbom_tier = Some("source".to_string());
        let mut go_analyzed = make_component(
            "pkg:golang/github.com/spf13/cobra@v1.7.0",
            ResolutionTechnique::PackageDatabase,
            0.85,
            vec![],
            vec!["/app/hello-bin"],
        );
        go_analyzed.sbom_tier = Some("analyzed".to_string());

        // Put analyzed FIRST so it naturally wins sort-by-confidence
        // with matching scores — this exercises the override path.
        let deduped = deduplicate(vec![go_analyzed, go_source]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].sbom_tier.as_deref(), Some("source"));
        // Both evidence paths present.
        let paths: std::collections::HashSet<&str> = deduped[0]
            .evidence
            .source_file_paths
            .iter()
            .map(String::as_str)
            .collect();
        assert!(paths.contains("/app/go.sum"));
        assert!(paths.contains("/app/hello-bin"));
    }
}