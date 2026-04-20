use mikebom_common::resolution::{Relationship, ResolvedComponent};

/// Trait for pluggable enrichment data sources (Constitution Principle XII).
///
/// Each source can contribute dependency relationships and/or additional
/// metadata (licenses, supplier info, advisories) to already-resolved
/// components. Sources MUST NOT introduce components that are not already
/// present in the input set.
pub trait EnrichmentSource: Send + Sync {
    /// Human-readable name of this source (e.g., "Cargo.lock", "deps.dev").
    fn name(&self) -> &str;

    /// Discover dependency relationships between already-resolved components.
    ///
    /// MUST NOT introduce components not in the input set. Relationships
    /// referencing unknown PURLs will be filtered by the pipeline.
    fn enrich_relationships(
        &self,
        components: &[ResolvedComponent],
    ) -> anyhow::Result<Vec<Relationship>>;

    /// Enrich a component with additional metadata (licenses, supplier, etc).
    ///
    /// Modifies the component in place. Returns `Ok(())` if no enrichment
    /// was applicable or if enrichment succeeded.
    fn enrich_metadata(
        &self,
        component: &mut ResolvedComponent,
    ) -> anyhow::Result<()>;
}
