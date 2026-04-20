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
    fn dependencies_include_all_components() {
        let components = vec![
            make_component("serde", "1.0.197"),
            make_component("tokio", "1.38.0"),
        ];

        let result = build_dependencies(&components, &[], "myapp@0.1.0");
        let deps = result.as_array().expect("array");

        // Should have 3 entries: myapp target + 2 components.
        assert_eq!(deps.len(), 3);

        // All should have empty dependsOn arrays.
        for dep in deps {
            assert!(dep["dependsOn"].as_array().expect("array").is_empty());
        }
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