use std::collections::HashSet;

use tracing::{debug, info, warn};

use mikebom_common::resolution::{Relationship, ResolvedComponent};

use super::source::EnrichmentSource;

/// Enrichment pipeline that runs all registered sources in order.
///
/// Enforces the guard rail that relationships can only reference
/// components already present in the input set.
pub struct EnrichmentPipeline {
    sources: Vec<Box<dyn EnrichmentSource>>,
}

impl EnrichmentPipeline {
    /// Create a new empty enrichment pipeline.
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Register an enrichment source.
    pub fn add_source(&mut self, source: Box<dyn EnrichmentSource>) {
        info!(source = source.name(), "registered enrichment source");
        self.sources.push(source);
    }

    /// Run all enrichment sources.
    ///
    /// Returns relationships and modifies components in place.
    /// Enforces the guard rail: relationships referencing PURLs not in
    /// the component set are filtered out.
    pub fn enrich(
        &self,
        components: &mut Vec<ResolvedComponent>,
    ) -> anyhow::Result<Vec<Relationship>> {
        let mut all_relationships = Vec::new();

        for source in &self.sources {
            info!(source = source.name(), "running enrichment source");

            // Collect relationships.
            match source.enrich_relationships(components) {
                Ok(rels) => {
                    debug!(
                        source = source.name(),
                        count = rels.len(),
                        "collected relationships"
                    );
                    all_relationships.extend(rels);
                }
                Err(e) => {
                    warn!(
                        source = source.name(),
                        error = %e,
                        "relationship enrichment failed, continuing with other sources"
                    );
                }
            }

            // Enrich metadata on each component.
            for component in components.iter_mut() {
                if let Err(e) = source.enrich_metadata(component) {
                    warn!(
                        source = source.name(),
                        purl = %component.purl,
                        error = %e,
                        "metadata enrichment failed for component"
                    );
                }
            }
        }

        // Guard rail: filter relationships to only those between known components.
        let known_purls: HashSet<String> = components
            .iter()
            .map(|c| c.purl.as_str().to_string())
            .collect();

        let before_count = all_relationships.len();
        all_relationships.retain(|rel| {
            let from_ok = known_purls.contains(&rel.from);
            let to_ok = known_purls.contains(&rel.to);
            if !from_ok || !to_ok {
                debug!(
                    from = %rel.from,
                    to = %rel.to,
                    from_known = from_ok,
                    to_known = to_ok,
                    "filtered relationship: references unknown component"
                );
            }
            from_ok && to_ok
        });

        let filtered_count = before_count - all_relationships.len();
        if filtered_count > 0 {
            info!(
                filtered = filtered_count,
                retained = all_relationships.len(),
                "applied guard rail: removed relationships with unknown components"
            );
        }

        info!(
            total_relationships = all_relationships.len(),
            "enrichment pipeline complete"
        );

        Ok(all_relationships)
    }
}

impl Default for EnrichmentPipeline {
    fn default() -> Self {
        Self::new()
    }
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

    /// A test source that returns a mix of valid and invalid relationships.
    struct TestSource {
        relationships: Vec<Relationship>,
    }

    impl EnrichmentSource for TestSource {
        fn name(&self) -> &str {
            "test-source"
        }

        fn enrich_relationships(
            &self,
            _components: &[ResolvedComponent],
        ) -> anyhow::Result<Vec<Relationship>> {
            Ok(self.relationships.clone())
        }

        fn enrich_metadata(
            &self,
            _component: &mut ResolvedComponent,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn pipeline_filters_unknown_relationships() {
        let mut pipeline = EnrichmentPipeline::new();

        let valid_rel = Relationship {
            from: "pkg:cargo/myapp@0.1.0".to_string(),
            to: "pkg:cargo/serde@1.0.197".to_string(),
            relationship_type: RelationshipType::DependsOn,
            provenance: EnrichmentProvenance {
                source: "test".to_string(),
                data_type: "test".to_string(),
            },
        };

        let invalid_rel = Relationship {
            from: "pkg:cargo/myapp@0.1.0".to_string(),
            to: "pkg:cargo/unknown@0.0.0".to_string(),
            relationship_type: RelationshipType::DependsOn,
            provenance: EnrichmentProvenance {
                source: "test".to_string(),
                data_type: "test".to_string(),
            },
        };

        pipeline.add_source(Box::new(TestSource {
            relationships: vec![valid_rel.clone(), invalid_rel],
        }));

        let mut components = vec![
            make_component("myapp", "0.1.0"),
            make_component("serde", "1.0.197"),
        ];

        let rels = pipeline.enrich(&mut components).expect("enrich");
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].from, "pkg:cargo/myapp@0.1.0");
        assert_eq!(rels[0].to, "pkg:cargo/serde@1.0.197");
    }

    #[test]
    fn empty_pipeline_returns_no_relationships() {
        let pipeline = EnrichmentPipeline::new();
        let mut components = vec![make_component("serde", "1.0.197")];
        let rels = pipeline.enrich(&mut components).expect("enrich");
        assert!(rels.is_empty());
    }
}