use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use mikebom_common::resolution::{Relationship, ResolvedComponent};

/// Build the CycloneDX `dependencies` array from enriched relationships.
///
/// Each entry has a `ref` (the component bom-ref, which is its PURL)
/// and a `dependsOn` array listing direct dependencies.
///
/// Components without explicit dependencies still appear with an
/// empty `dependsOn` array.
///
/// Primary-dependency fallback (sbomqs `comp_with_dependencies`): the
/// CDX scoring tooling expects the primary component
/// (`metadata.component`, here `target_ref`) to have at least one
/// outgoing `dependsOn` edge — without it, sbomqs reports
/// "no dependency graph present" even when component-to-component
/// edges are populated. When mikebom skips the lockfile root entry
/// (workspace root, npm path_key=""), the primary has no source for
/// direct-dep names. Fall back to "primary depends on all root
/// components" — i.e., every component that isn't pointed at by any
/// other component's dependsOn. This produces a usable graph: the
/// primary at the top, transitives correctly chained underneath.
pub fn build_dependencies(
    components: &[ResolvedComponent],
    relationships: &[Relationship],
    target_ref: &str,
) -> serde_json::Value {
    // Build a map of ref -> set of dependency refs.
    let mut dep_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    // Initialize all components with empty dependency sets.
    for component in components {
        dep_map.entry(component.purl.as_str().to_string()).or_default();
    }

    // Also include the target ref (the build artifact itself).
    dep_map.entry(target_ref.to_string()).or_default();

    // Populate relationships.
    for rel in relationships {
        dep_map
            .entry(rel.from.clone())
            .or_default()
            .insert(rel.to.clone());
    }

    // Primary-dependency fallback: if target_ref has no outgoing edges
    // but we DO have components, synthesize edges from target_ref to
    // every component that nothing else depends on (the roots of the
    // component-side graph). For a flat scan with no relationships,
    // this means target_ref → every component. For a transitive scan,
    // it's just the top-level packages.
    let target_has_no_edges = dep_map
        .get(target_ref)
        .map(|set| set.is_empty())
        .unwrap_or(true);
    if target_has_no_edges && !components.is_empty() {
        let mut depended_on: BTreeSet<String> = BTreeSet::new();
        for set in dep_map.values() {
            depended_on.extend(set.iter().cloned());
        }
        let roots: BTreeSet<String> = components
            .iter()
            .map(|c| c.purl.as_str().to_string())
            .filter(|r| !depended_on.contains(r))
            .collect();
        if !roots.is_empty() {
            dep_map.insert(target_ref.to_string(), roots);
        }
    }

    // Convert to CycloneDX format.
    let entries: Vec<serde_json::Value> = dep_map
        .into_iter()
        .map(|(ref_str, depends_on)| {
            json!({
                "ref": ref_str,
                "dependsOn": depends_on.into_iter().collect::<Vec<String>>()
            })
        })
        .collect();

    json!(entries)
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::resolution::{
        EnrichmentProvenance, RelationshipType, ResolutionEvidence, ResolutionTechnique,
    };
    use mikebom_common::types::purl::Purl;

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
            external_references: Vec::new(),
        }
    }

    #[test]
    fn dependencies_include_all_components() {
        let components = vec![
            make_component("serde", "1.0.197"),
            make_component("tokio", "1.38.0"),
        ];

        let result = build_dependencies(&components, &[], "myapp@0.1.0");
        let deps = result.as_array().expect("array");

        // Should have 3 entries: myapp target + 2 components.
        assert_eq!(deps.len(), 3);

        // Primary-dependency fallback (sbomqs comp_with_dependencies):
        // when no relationships exist, the target_ref synthetically
        // depends on all components. Here both serde and tokio are
        // roots (nothing else points at them).
        let target = deps
            .iter()
            .find(|d| d["ref"] == "myapp@0.1.0")
            .expect("target dep entry");
        let target_deps: Vec<&str> = target["dependsOn"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(target_deps.len(), 2);
        // Components themselves remain leaves.
        for dep in deps {
            if dep["ref"] != "myapp@0.1.0" {
                assert!(dep["dependsOn"].as_array().expect("array").is_empty());
            }
        }
    }

    #[test]
    fn primary_fallback_only_lists_roots_not_transitives() {
        // express depends on body-parser; body-parser depends on bytes.
        // Roots = [express] (the only one nothing depends on).
        // Target should depend on express only.
        let components = vec![
            make_component("express", "4.18.2"),
            make_component("body-parser", "1.20.1"),
            make_component("bytes", "3.1.2"),
        ];
        let relationships = vec![
            Relationship {
                from: "pkg:cargo/express@4.18.2".to_string(),
                to: "pkg:cargo/body-parser@1.20.1".to_string(),
                relationship_type: RelationshipType::DependsOn,
                provenance: EnrichmentProvenance {
                    source: "test".to_string(),
                    data_type: "test".to_string(),
                },
            },
            Relationship {
                from: "pkg:cargo/body-parser@1.20.1".to_string(),
                to: "pkg:cargo/bytes@3.1.2".to_string(),
                relationship_type: RelationshipType::DependsOn,
                provenance: EnrichmentProvenance {
                    source: "test".to_string(),
                    data_type: "test".to_string(),
                },
            },
        ];

        let result = build_dependencies(&components, &relationships, "myapp@0.1.0");
        let deps = result.as_array().unwrap();
        let target = deps.iter().find(|d| d["ref"] == "myapp@0.1.0").unwrap();
        let target_deps: Vec<&str> = target["dependsOn"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(target_deps, vec!["pkg:cargo/express@4.18.2"]);
    }

    #[test]
    fn primary_fallback_skipped_when_target_already_has_deps() {
        // If something already populated target's dependsOn, don't
        // override it.
        let components = vec![make_component("serde", "1.0.197")];
        let relationships = vec![Relationship {
            from: "myapp@0.1.0".to_string(),
            to: "pkg:cargo/serde@1.0.197".to_string(),
            relationship_type: RelationshipType::DependsOn,
            provenance: EnrichmentProvenance {
                source: "test".to_string(),
                data_type: "test".to_string(),
            },
        }];
        let result = build_dependencies(&components, &relationships, "myapp@0.1.0");
        let deps = result.as_array().unwrap();
        let target = deps.iter().find(|d| d["ref"] == "myapp@0.1.0").unwrap();
        let target_deps: Vec<&str> = target["dependsOn"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(target_deps, vec!["pkg:cargo/serde@1.0.197"]);
    }

    #[test]
    fn dependencies_map_relationships() {
        let components = vec![
            make_component("myapp", "0.1.0"),
            make_component("serde", "1.0.197"),
            make_component("tokio", "1.38.0"),
        ];

        let relationships = vec![
            Relationship {
                from: "pkg:cargo/myapp@0.1.0".to_string(),
                to: "pkg:cargo/serde@1.0.197".to_string(),
                relationship_type: RelationshipType::DependsOn,
                provenance: EnrichmentProvenance {
                    source: "test".to_string(),
                    data_type: "test".to_string(),
                },
            },
            Relationship {
                from: "pkg:cargo/myapp@0.1.0".to_string(),
                to: "pkg:cargo/tokio@1.38.0".to_string(),
                relationship_type: RelationshipType::DependsOn,
                provenance: EnrichmentProvenance {
                    source: "test".to_string(),
                    data_type: "test".to_string(),
                },
            },
        ];

        let result = build_dependencies(&components, &relationships, "target@0.1.0");
        let deps = result.as_array().expect("array");

        // Find the myapp entry.
        let myapp_dep = deps
            .iter()
            .find(|d| d["ref"] == "pkg:cargo/myapp@0.1.0")
            .expect("myapp dependency entry");

        let depends_on = myapp_dep["dependsOn"].as_array().expect("array");
        assert_eq!(depends_on.len(), 2);
        assert!(depends_on.iter().any(|v| v == "pkg:cargo/serde@1.0.197"));
        assert!(depends_on.iter().any(|v| v == "pkg:cargo/tokio@1.38.0"));
    }

    #[test]
    fn dependencies_are_sorted_deterministically() {
        let components = vec![
            make_component("zebra", "1.0.0"),
            make_component("alpha", "1.0.0"),
        ];

        let result = build_dependencies(&components, &[], "target@0.1.0");
        let deps = result.as_array().expect("array");

        // BTreeMap ensures alphabetical ordering by ref.
        let refs: Vec<&str> = deps.iter().map(|d| d["ref"].as_str().unwrap()).collect();
        assert!(refs.windows(2).all(|w| w[0] <= w[1]));
    }
}