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
        components: &mut [ResolvedComponent],
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

        // Guard rail: keep relationships where AT LEAST ONE endpoint is a
        // known component. Edges with BOTH endpoints unknown are noise
        // (synthesized chains between declared-not-cached deps with no
        // on-disk anchor) and get dropped.
        //
        // We intentionally don't require BOTH endpoints to be known — when
        // --include-declared-deps is off (default), declared-not-cached
        // targets are absent from `components[]` but their edges from
        // on-disk roots still surface in `dependencies[]` as dangling
        // bom-refs. Strict CDX expects every `dependsOn` ref to exist in
        // `components[]`; we knowingly trade strict-validity for
        // topology-preservation so consumers can see what each on-disk
        // component declares as a dependency even when the declared target
        // doesn't physically ship.
        //
        // `--include-declared-deps` restores the old both-known semantics
        // by ensuring declared-not-cached comps land in components[],
        // making every edge fully-anchored.
        let known_purls: HashSet<String> = components
            .iter()
            .map(|c| c.purl.as_str().to_string())
            .collect();

        let before_count = all_relationships.len();
        all_relationships.retain(|rel| {
            let from_ok = known_purls.contains(&rel.from);
            let to_ok = known_purls.contains(&rel.to);
            if !from_ok && !to_ok {
                debug!(
                    from = %rel.from,
                    to = %rel.to,
                    "filtered relationship: neither endpoint is a known component"
                );
            }
            from_ok || to_ok
        });

        let filtered_count = before_count - all_relationships.len();
        if filtered_count > 0 {
            info!(
                filtered = filtered_count,
                retained = all_relationships.len(),
                "applied guard rail: removed relationships where neither endpoint is on disk"
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
        let purl_str = format!("pkg:cargo/{name}@{version}");
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
            co_owned_by: None,
            shade_relocation: None,
            external_references: Vec::new(),
            extra_annotations: Default::default(),
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

    /// Under the relaxed guard rail (from_ok || to_ok), an edge with a
    /// known source but unknown target is KEPT — this preserves dep-tree
    /// topology when `--include-declared-deps` is off and the target is
    /// a declared-not-cached coord absent from `components[]`. Strict
    /// CDX disallows dangling bom-refs; we trade strict-validity for
    /// topology-preservation.
    #[test]
    fn pipeline_keeps_edges_with_at_least_one_known_endpoint() {
        let mut pipeline = EnrichmentPipeline::new();

        let both_known = Relationship {
            from: "pkg:cargo/myapp@0.1.0".to_string(),
            to: "pkg:cargo/serde@1.0.197".to_string(),
            relationship_type: RelationshipType::DependsOn,
            provenance: EnrichmentProvenance {
                source: "test".to_string(),
                data_type: "test".to_string(),
            },
        };

        let only_source_known = Relationship {
            from: "pkg:cargo/myapp@0.1.0".to_string(),
            to: "pkg:cargo/declared-not-cached@0.0.0".to_string(),
            relationship_type: RelationshipType::DependsOn,
            provenance: EnrichmentProvenance {
                source: "test".to_string(),
                data_type: "test".to_string(),
            },
        };

        let neither_known = Relationship {
            from: "pkg:cargo/ghost-a@0.0.0".to_string(),
            to: "pkg:cargo/ghost-b@0.0.0".to_string(),
            relationship_type: RelationshipType::DependsOn,
            provenance: EnrichmentProvenance {
                source: "test".to_string(),
                data_type: "test".to_string(),
            },
        };

        pipeline.add_source(Box::new(TestSource {
            relationships: vec![
                both_known.clone(),
                only_source_known.clone(),
                neither_known,
            ],
        }));

        let mut components = vec![
            make_component("myapp", "0.1.0"),
            make_component("serde", "1.0.197"),
        ];

        let rels = pipeline.enrich(&mut components).expect("enrich");
        // Both-known + only-source-known survive; neither-known drops.
        assert_eq!(rels.len(), 2);
        assert!(rels.iter().any(|r| r == &both_known));
        assert!(rels.iter().any(|r| r == &only_source_known));
    }

    #[test]
    fn pipeline_drops_edges_with_both_endpoints_unknown() {
        let mut pipeline = EnrichmentPipeline::new();

        let neither_known = Relationship {
            from: "pkg:cargo/unknown-src@0.0.0".to_string(),
            to: "pkg:cargo/unknown-dst@0.0.0".to_string(),
            relationship_type: RelationshipType::DependsOn,
            provenance: EnrichmentProvenance {
                source: "test".to_string(),
                data_type: "test".to_string(),
            },
        };

        pipeline.add_source(Box::new(TestSource {
            relationships: vec![neither_known],
        }));

        let mut components = vec![make_component("myapp", "0.1.0")];
        let rels = pipeline.enrich(&mut components).expect("enrich");
        assert!(rels.is_empty(), "edges with no on-disk anchor should drop");
    }

    #[test]
    fn empty_pipeline_returns_no_relationships() {
        let pipeline = EnrichmentPipeline::new();
        let mut components = vec![make_component("serde", "1.0.197")];
        let rels = pipeline.enrich(&mut components).expect("enrich");
        assert!(rels.is_empty());
    }
}