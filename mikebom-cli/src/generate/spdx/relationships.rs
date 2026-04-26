//! SPDX 2.3 Relationship struct + mapping from internal
//! `Relationship.kind` (milestone 010, T022 / T024).
//!
//! SPDX 2.3 models every edge in an SBOM's graph as an entry in
//! `relationships[]` (spec §11). Mikebom's internal model carries:
//!
//!   * `Relationship { from: PURL, to: PURL, kind: RelationshipType }`
//!     — the dependency-graph edges the CDX serializer consumes.
//!   * `ResolvedComponent.parent_purl` — the containment edge for
//!     CycloneDX nested components (shade-jar children, image layers).
//!
//! Both surfaces have to be flattened into explicit SPDX relationships
//! here (FR-010, FR-011). The document-level `DESCRIBES` edge from
//! `SPDXRef-DOCUMENT` to the root package is also emitted from this
//! builder so callers get a complete edge list in one place.

use std::collections::BTreeMap;

use mikebom_common::resolution::RelationshipType;

use super::ids::SpdxId;
use crate::generate::ScanArtifacts;

/// SPDX 2.3 relationship-type enum (spec §11.1).
///
/// Mikebom emits a subset today; unused variants from the spec are
/// added as new ecosystems or US2 annotations demand them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(dead_code)] // ContainedBy is the symmetric inverse of Contains, included for spec completeness against the SPDX 2.3 relationshipType enum.
pub enum SpdxRelationshipType {
    Describes,
    DependsOn,
    DevDependencyOf,
    BuildDependencyOf,
    Contains,
    ContainedBy,
}

/// One SPDX 2.3 relationship edge.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpdxRelationship {
    #[serde(rename = "spdxElementId")]
    pub source: SpdxId,
    #[serde(rename = "relatedSpdxElement")]
    pub target: SpdxId,
    #[serde(rename = "relationshipType")]
    pub kind: SpdxRelationshipType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Build the `relationships[]` array for an SPDX 2.3 document (T024).
///
/// Emits three categories:
///
/// 1. **Document root**: one `DESCRIBES` edge from
///    `SPDXRef-DOCUMENT` to the caller-chosen root SPDXID.
///
/// 2. **Dependency edges** (FR-010): one SPDX edge per
///    `ScanArtifacts.relationships` entry. `from`/`to` are PURL
///    strings; we resolve them back to SPDXIDs via
///    [`SpdxId::for_purl`]. If a PURL fails to parse or doesn't
///    correspond to any component in the scan, the edge is skipped
///    with a debug log rather than crashing — edge corruption from
///    upstream enrichment shouldn't poison the SBOM. Direction and
///    verb per the data-model.md §3.4 table:
///
///    | internal `RelationshipType` | SPDX `relationshipType`          | direction |
///    |-----------------------------|----------------------------------|-----------|
///    | `DependsOn`                 | `DEPENDS_ON`                     | same      |
///    | `DevDependsOn`              | `DEV_DEPENDENCY_OF`              | reversed  |
///    | `BuildDependsOn`            | `BUILD_DEPENDENCY_OF`            | reversed  |
///
///    Reversal for dev/build dep edges matches SPDX semantics —
///    `(A) DEV_DEPENDENCY_OF (B)` means "A is a dev dep of B", so
///    internal `(A DevDependsOn B)` "A needs B for dev" swaps to
///    `(B) DEV_DEPENDENCY_OF (A)` = "B is a dev dep of A".
///
/// 3. **Containment edges** (FR-011): for each component whose
///    `parent_purl` is set AND points at a top-level component in
///    the scan, one `CONTAINS` edge from parent → child (and SPDX
///    implicitly carries `CONTAINED_BY` as the inverse — consumers
///    get both readings). Orphans (parent_purl points nowhere
///    resolvable) are dropped rather than producing dangling edges.
pub fn build_relationships(
    artifacts: &ScanArtifacts<'_>,
    root: &SpdxId,
) -> Vec<SpdxRelationship> {
    let mut out: Vec<SpdxRelationship> = Vec::new();

    // 1. Document describes the root.
    out.push(SpdxRelationship {
        source: SpdxId::document(),
        target: root.clone(),
        kind: SpdxRelationshipType::Describes,
        comment: None,
    });

    // Build a PURL→SpdxId map once so dependency edges don't re-hash
    // each PURL. BTreeMap keeps iteration deterministic if we ever
    // need it, though here we only do O(1) lookups.
    let mut purl_to_id: BTreeMap<String, SpdxId> = BTreeMap::new();
    for c in artifacts.components {
        purl_to_id.insert(c.purl.as_str().to_string(), SpdxId::for_purl(&c.purl));
    }

    // 2. Dependency edges.
    for rel in artifacts.relationships {
        let from_id = match purl_to_id.get(&rel.from) {
            Some(id) => id.clone(),
            None => {
                tracing::debug!(
                    purl = %rel.from,
                    "dropping relationship: 'from' PURL not present in component set"
                );
                continue;
            }
        };
        let to_id = match purl_to_id.get(&rel.to) {
            Some(id) => id.clone(),
            None => {
                tracing::debug!(
                    purl = %rel.to,
                    "dropping relationship: 'to' PURL not present in component set"
                );
                continue;
            }
        };
        let (source, target, kind) = match rel.relationship_type {
            RelationshipType::DependsOn => {
                (from_id, to_id, SpdxRelationshipType::DependsOn)
            }
            RelationshipType::DevDependsOn => {
                // Reverse direction for *_DEPENDENCY_OF verbs (see
                // module docs).
                (to_id, from_id, SpdxRelationshipType::DevDependencyOf)
            }
            RelationshipType::BuildDependsOn => {
                (to_id, from_id, SpdxRelationshipType::BuildDependencyOf)
            }
        };
        out.push(SpdxRelationship {
            source,
            target,
            kind,
            comment: None,
        });
    }

    // 3. Containment edges from parent_purl. Top-level PURLs (set of
    //    components with `parent_purl = None`) are the only valid
    //    parent targets; orphan pointers are dropped.
    let top_level: std::collections::HashSet<&str> = artifacts
        .components
        .iter()
        .filter(|c| c.parent_purl.is_none())
        .map(|c| c.purl.as_str())
        .collect();
    for c in artifacts.components {
        let Some(parent_purl) = c.parent_purl.as_deref() else {
            continue;
        };
        if !top_level.contains(parent_purl) {
            continue; // orphan — CDX emits these at top-level; we just don't synthesize a containment edge
        }
        let Some(parent_id) = purl_to_id.get(parent_purl) else {
            continue;
        };
        let child_id = SpdxId::for_purl(&c.purl);
        out.push(SpdxRelationship {
            source: parent_id.clone(),
            target: child_id,
            kind: SpdxRelationshipType::Contains,
            comment: None,
        });
    }

    out
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::attestation::integrity::TraceIntegrity;
    use mikebom_common::attestation::metadata::GenerationContext;
    use mikebom_common::resolution::{
        EnrichmentProvenance, Relationship, ResolutionEvidence, ResolutionTechnique,
        ResolvedComponent,
    };
    use mikebom_common::types::purl::Purl;

    fn mk_component(purl: &str, name: &str, version: &str) -> ResolvedComponent {
        ResolvedComponent {
            purl: Purl::new(purl).unwrap(),
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
            concluded_licenses: vec![],
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

    fn prov() -> EnrichmentProvenance {
        EnrichmentProvenance {
            source: "test".to_string(),
            data_type: "runtime".to_string(),
        }
    }

    fn empty_integrity() -> TraceIntegrity {
        TraceIntegrity {
            ring_buffer_overflows: 0,
            events_dropped: 0,
            uprobe_attach_failures: vec![],
            kprobe_attach_failures: vec![],
            partial_captures: vec![],
            bloom_filter_capacity: 0,
            bloom_filter_false_positive_rate: 0.0,
        }
    }

    fn mk_artifacts<'a>(
        comps: &'a [ResolvedComponent],
        rels: &'a [Relationship],
        integ: &'a TraceIntegrity,
    ) -> ScanArtifacts<'a> {
        ScanArtifacts {
            target_name: "demo",
            components: comps,
            relationships: rels,
            integrity: integ,
            complete_ecosystems: &[],
            os_release_missing_fields: &[],
            scan_target_coord: None,
            generation_context: GenerationContext::FilesystemScan,
            include_dev: false,
            include_hashes: true,
            include_source_files: false,
        }
    }

    #[test]
    fn emits_describes_edge_from_document_to_root() {
        let integ = empty_integrity();
        let comps: Vec<ResolvedComponent> = vec![];
        let arts = mk_artifacts(&comps, &[], &integ);
        let root = SpdxId::synthetic_root("AAAAAAAAAAAAAAAA");
        let rels = build_relationships(&arts, &root);
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].source, SpdxId::document());
        assert_eq!(rels[0].target, root);
        assert_eq!(rels[0].kind, SpdxRelationshipType::Describes);
    }

    #[test]
    fn depends_on_keeps_same_direction() {
        let a = mk_component("pkg:cargo/a@1", "a", "1");
        let b = mk_component("pkg:cargo/b@1", "b", "1");
        let rel = Relationship {
            from: a.purl.as_str().to_string(),
            to: b.purl.as_str().to_string(),
            relationship_type: RelationshipType::DependsOn,
            provenance: prov(),
        };
        let integ = empty_integrity();
        let comps = vec![a, b];
        let rels_arr = [rel];
        let arts = mk_artifacts(&comps, &rels_arr, &integ);
        let root = SpdxId::for_purl(&comps[0].purl);
        let rels = build_relationships(&arts, &root);
        let dep = rels
            .iter()
            .find(|r| r.kind == SpdxRelationshipType::DependsOn)
            .expect("DEPENDS_ON edge present");
        assert_eq!(dep.source, SpdxId::for_purl(&comps[0].purl));
        assert_eq!(dep.target, SpdxId::for_purl(&comps[1].purl));
    }

    #[test]
    fn dev_depends_on_reverses_to_dev_dependency_of() {
        let a = mk_component("pkg:npm/a@1", "a", "1");
        let b = mk_component("pkg:npm/b@1", "b", "1");
        let rel = Relationship {
            from: a.purl.as_str().to_string(),
            to: b.purl.as_str().to_string(),
            relationship_type: RelationshipType::DevDependsOn,
            provenance: prov(),
        };
        let integ = empty_integrity();
        let comps = vec![a, b];
        let rels_arr = [rel];
        let arts = mk_artifacts(&comps, &rels_arr, &integ);
        let root = SpdxId::for_purl(&comps[0].purl);
        let rels = build_relationships(&arts, &root);
        let dev = rels
            .iter()
            .find(|r| r.kind == SpdxRelationshipType::DevDependencyOf)
            .expect("DEV_DEPENDENCY_OF edge present");
        // Internal A DevDependsOn B  =>  SPDX B DEV_DEPENDENCY_OF A.
        assert_eq!(dev.source, SpdxId::for_purl(&comps[1].purl));
        assert_eq!(dev.target, SpdxId::for_purl(&comps[0].purl));
    }

    #[test]
    fn containment_parent_to_child_contains_edge() {
        let parent = mk_component("pkg:maven/com/example/parent@1", "parent", "1");
        let mut child = mk_component("pkg:maven/com/example/child@1", "child", "1");
        child.parent_purl = Some(parent.purl.as_str().to_string());
        let integ = empty_integrity();
        let comps = vec![parent, child];
        let arts = mk_artifacts(&comps, &[], &integ);
        let root = SpdxId::for_purl(&comps[0].purl);
        let rels = build_relationships(&arts, &root);
        let contains = rels
            .iter()
            .find(|r| r.kind == SpdxRelationshipType::Contains)
            .expect("CONTAINS edge for parent→child");
        assert_eq!(contains.source, SpdxId::for_purl(&comps[0].purl));
        assert_eq!(contains.target, SpdxId::for_purl(&comps[1].purl));
    }

    #[test]
    fn orphan_containment_is_dropped() {
        // child's parent_purl points at a PURL that isn't in the scan.
        let mut child = mk_component("pkg:maven/x/y/child@1", "child", "1");
        child.parent_purl = Some("pkg:maven/x/y/not-present@9".to_string());
        let integ = empty_integrity();
        let comps = vec![child];
        let arts = mk_artifacts(&comps, &[], &integ);
        let root = SpdxId::synthetic_root("AAAAAAAAAAAAAAAA");
        let rels = build_relationships(&arts, &root);
        // Only the DESCRIBES edge; the orphan containment is dropped.
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].kind, SpdxRelationshipType::Describes);
    }

    #[test]
    fn unknown_purl_in_relationship_is_dropped() {
        // Relationship references a PURL that's not in the component set.
        let a = mk_component("pkg:cargo/a@1", "a", "1");
        let rel = Relationship {
            from: a.purl.as_str().to_string(),
            to: "pkg:cargo/not-present@9".to_string(),
            relationship_type: RelationshipType::DependsOn,
            provenance: prov(),
        };
        let integ = empty_integrity();
        let comps = vec![a];
        let rels_arr = [rel];
        let arts = mk_artifacts(&comps, &rels_arr, &integ);
        let root = SpdxId::for_purl(&comps[0].purl);
        let rels = build_relationships(&arts, &root);
        // Only the DESCRIBES edge remains.
        assert_eq!(rels.len(), 1);
    }
}
