//! deps.dev transitive dep-graph fallback.
//!
//! Fills in Maven transitive edges that the local scan can't see:
//!
//! - **Shaded JARs** strip `META-INF/maven/` for their vendored
//!   dependencies, so `walk_jar_maven_meta` only sees the top-level
//!   artefact's POM. deps.dev knows the full tree for any coord
//!   published to Maven Central.
//! - **Cold `~/.m2` cache** (CI without a warmup step, or scanning a
//!   container image that doesn't ship the cache) means BFS hits
//!   cache-miss on every direct-dep pom. deps.dev gives us the
//!   declared tree without requiring the cache to be populated.
//!
//! Policy (see earlier design discussion in plan file):
//!
//! - deps.dev is authoritative for **edge topology** — it tells us
//!   "A depends on B". Never authoritative for **versions** — the
//!   local scan (JAR walk, pom-cache walk) is. When deps.dev says
//!   "A depends on B@1.0" and the local scan already emitted B@1.5,
//!   the edge target is the local B@1.5 (what's actually on disk).
//! - When deps.dev mentions a coord that doesn't exist locally at
//!   any version, emit it as a new component with
//!   `source_type = "declared-not-cached"` so downstream consumers
//!   can distinguish "observed" from "declared-but-not-seen-on-disk".
//! - Offline mode skips the whole pass. Failed lookups warn + skip.

use std::collections::{HashMap, HashSet};

use tracing::{debug, info, warn};

use mikebom_common::resolution::{
    EnrichmentProvenance, Relationship, RelationshipType, ResolutionEvidence,
    ResolutionTechnique, ResolvedComponent,
};
use mikebom_common::types::purl::Purl;

use super::deps_dev_client::DepsDevClient;
use super::deps_dev_system::{deps_dev_package_name, deps_dev_system_for};

/// How many deps.dev requests to run in parallel. deps.dev is
/// generous but still rate-limited; 8 keeps the scan responsive
/// without stressing the API.
const CONCURRENT_REQUESTS: usize = 8;

/// Ecosystems this enricher currently covers. Maven is the primary
/// target (JAR-based discovery misses shaded transitives; local-cache
/// discovery misses anything pre-build). Could be extended to others
/// in the future, but Go/Cargo/Ruby have authoritative lockfiles that
/// already produce complete graphs without network lookup.
const SUPPORTED_ECOSYSTEMS: &[&str] = &["maven"];

/// Public entry point — run the deps.dev dep-graph enrichment pass.
/// Mutates `components` (adds new declared-not-cached entries) and
/// returns additional `Relationship` edges to merge into the
/// scan-wide relationships list.
///
/// The caller is expected to:
///   1. Run the local scan first (produces `components` and
///      scan-wide relationships).
///   2. Call this function to fill in missing transitive edges.
///   3. Merge returned relationships into the running list.
///
/// Offline mode and no-supported-components paths return an empty
/// relationships vec without making any HTTP calls.
pub async fn enrich_dep_graph(
    client: &DepsDevClient,
    components: &mut Vec<ResolvedComponent>,
    offline: bool,
    include_declared_deps: bool,
) -> Vec<Relationship> {
    if offline {
        debug!("deps.dev dep-graph enrichment skipped — offline mode");
        return Vec::new();
    }

    // Build the set of coords we're going to query. Only queries for
    // supported ecosystems; dedup by (ecosystem, package-name, version).
    // Each supported coord gets one HTTP call — deps.dev's response
    // includes the full transitive tree so we don't need per-transitive
    // follow-up calls.
    let mut seed_coords: Vec<(String, String, String, String)> = Vec::new(); // (ecosystem, depsdev_system, name, version)
    let mut seen_seeds: HashSet<String> = HashSet::new();
    for c in components.iter() {
        let eco = c.purl.ecosystem();
        if !SUPPORTED_ECOSYSTEMS.contains(&eco) {
            continue;
        }
        let Some(system) = deps_dev_system_for(eco) else {
            continue;
        };
        let name = deps_dev_package_name(eco, c.purl.namespace(), &c.name);
        let key = format!("{system}::{name}::{}", c.version);
        if !seen_seeds.insert(key) {
            continue;
        }
        seed_coords.push((eco.to_string(), system.to_string(), name, c.version.clone()));
    }

    if seed_coords.is_empty() {
        return Vec::new();
    }

    info!(
        seeds = seed_coords.len(),
        concurrency = CONCURRENT_REQUESTS,
        "deps.dev dep-graph enrichment starting",
    );

    // Fetch seeds in batches capped at CONCURRENT_REQUESTS in-flight.
    // `tokio::task::JoinSet` is part of tokio (which we already depend
    // on) so no new crate is needed. The worker sub-tasks borrow the
    // client, so we Arc it up front.
    let client = std::sync::Arc::new(client.clone());
    let mut fetches: Vec<(String, String, String, String, anyhow::Result<super::deps_dev_client::DependencyGraph>)> =
        Vec::with_capacity(seed_coords.len());
    for chunk in seed_coords.chunks(CONCURRENT_REQUESTS) {
        let mut set = tokio::task::JoinSet::new();
        for (eco, system, name, version) in chunk.iter().cloned() {
            let c = client.clone();
            set.spawn(async move {
                let graph = c.get_dependency_graph(&system, &name, &version).await;
                (eco, system, name, version, graph)
            });
        }
        while let Some(result) = set.join_next().await {
            match result {
                Ok(tuple) => fetches.push(tuple),
                Err(e) => warn!(error = %e, "deps.dev worker task panicked"),
            }
        }
    }

    // Local version index keyed on (ecosystem, deps-dev-format-name)
    // → version. Used to substitute deps.dev-reported versions with
    // what's actually on disk ("same group:artifact but different
    // version" case).
    let mut local_version_index: HashMap<(String, String), String> = HashMap::new();
    for c in components.iter() {
        let eco = c.purl.ecosystem();
        if !SUPPORTED_ECOSYSTEMS.contains(&eco) {
            continue;
        }
        let name = deps_dev_package_name(eco, c.purl.namespace(), &c.name);
        local_version_index
            .entry((eco.to_string(), name))
            .or_insert_with(|| c.version.clone());
    }

    let mut new_relationships: Vec<Relationship> = Vec::new();
    let mut components_by_purl: HashSet<String> = components
        .iter()
        .map(|c| c.purl.as_str().to_string())
        .collect();
    let mut ok_count = 0usize;
    let mut err_count = 0usize;
    let mut added_components = 0usize;

    for (eco, _system, name, version, graph_result) in fetches {
        let graph = match graph_result {
            Ok(g) => g,
            Err(e) => {
                err_count += 1;
                warn!(
                    ecosystem = %eco,
                    name = %name,
                    version = %version,
                    error = %e,
                    "deps.dev dep-graph lookup failed — skipping",
                );
                continue;
            }
        };
        ok_count += 1;

        // Build a per-response node→effective-coord table. For each
        // deps.dev-reported coord, prefer the local version when
        // we've seen any version of the same (ecosystem, name)
        // already. Otherwise use deps.dev's declared version and
        // emit a new `declared-not-cached` component.
        let mut effective_coords: Vec<Option<(String, String)>> = Vec::with_capacity(graph.nodes.len());
        for node in &graph.nodes {
            let node_name = node.version_key.name.clone();
            let node_version = node.version_key.version.clone();
            // Look up local version of (eco, node_name). The local
            // index wins — deps.dev reported versions are declarative,
            // not authoritative.
            let resolved_version = local_version_index
                .get(&(eco.clone(), node_name.clone()))
                .cloned()
                .unwrap_or_else(|| node_version.clone());
            effective_coords.push(Some((node_name.clone(), resolved_version.clone())));

            // If the (eco, name, version) coord isn't already in the
            // component set, emit it as declared-not-cached. This
            // fires for nodes deps.dev reports that the local scan
            // couldn't see — typically shade-stripped transitives.
            let purl_str = build_purl_for_coord(&eco, &node_name, &resolved_version);
            let Some(purl_str) = purl_str else {
                continue;
            };
            if components_by_purl.insert(purl_str.clone()) {
                if let Ok(purl) = Purl::new(&purl_str) {
                    // Honor the "if it's in the image, it's in the
                    // SBOM" principle by default. `declared-not-cached`
                    // coords from deps.dev — provided-scope deps,
                    // JDK-bundled classes, optional deps, closure-union
                    // inflation across many roots — represent packages
                    // that don't physically ship in the scanned tree /
                    // image. The edge to this coord still gets pushed
                    // into `new_relationships` below; the relaxed
                    // pipeline guard rail (`from_ok || to_ok`) keeps
                    // edges walkable from on-disk components even when
                    // their targets aren't emitted as components.
                    //
                    // TODO(declared-scope): CDX 1.6 `component.scope:
                    // "excluded"` is the CDX-canonical way to represent
                    // "acknowledged dep, not shipped". When we can
                    // distinguish Maven compile / test / provided /
                    // runtime scopes from deps.dev's graph (requires a
                    // richer client query — the current `:dependencies`
                    // endpoint doesn't return scope), emit
                    // declared-not-cached with `scope: "excluded"`
                    // instead of dropping. Preserves topology without
                    // violating the "on-disk = in-SBOM" rule.
                    if include_declared_deps {
                        let component_name = short_name_for_purl(&eco, &node_name);
                        components.push(ResolvedComponent {
                            name: component_name,
                            version: resolved_version,
                            purl,
                            evidence: ResolutionEvidence {
                                technique: ResolutionTechnique::UrlPattern,
                                // Lower confidence than locally-observed
                                // components. deps.dev is reliable but
                                // secondary — on-disk observation beats
                                // declared.
                                confidence: 0.75,
                                source_connection_ids: Vec::new(),
                                source_file_paths: vec!["deps.dev".to_string()],
                                deps_dev_match: None,
                            },
                            licenses: Vec::new(),
                            concluded_licenses: Vec::new(),
                            hashes: Vec::new(),
                            supplier: None,
                            cpes: Vec::new(),
                            advisories: Vec::new(),
                            occurrences: Vec::new(),
                            is_dev: None,
                            requirement_range: None,
                            source_type: Some("declared-not-cached".to_string()),
                            sbom_tier: Some("source".to_string()),
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
                            external_references: Vec::new(),
                        });
                        added_components += 1;
                    }
                }
            }
        }

        // Emit edges. Each `(fromNode, toNode)` becomes a
        // Relationship using the resolved coord on each side. The
        // pipeline's guard rail will drop any edge whose endpoints
        // aren't in the component set — but we just added every
        // node above, so edges referencing nodes should survive.
        for edge in &graph.edges {
            let (Some(from), Some(to)) = (
                effective_coords.get(edge.from_node).and_then(|o| o.as_ref()),
                effective_coords.get(edge.to_node).and_then(|o| o.as_ref()),
            ) else {
                continue;
            };
            let Some(from_purl) = build_purl_for_coord(&eco, &from.0, &from.1) else {
                continue;
            };
            let Some(to_purl) = build_purl_for_coord(&eco, &to.0, &to.1) else {
                continue;
            };
            if from_purl == to_purl {
                continue;
            }
            new_relationships.push(Relationship {
                from: from_purl,
                to: to_purl,
                relationship_type: RelationshipType::DependsOn,
                provenance: EnrichmentProvenance {
                    source: "deps.dev".to_string(),
                    data_type: "dependency-graph".to_string(),
                },
            });
        }
    }

    info!(
        queries_ok = ok_count,
        queries_err = err_count,
        new_components = added_components,
        new_edges = new_relationships.len(),
        "deps.dev dep-graph enrichment complete",
    );

    new_relationships
}

/// Reverse the deps.dev naming convention back into a PURL string
/// for the given ecosystem. Mirrors `deps_dev_package_name`.
fn build_purl_for_coord(ecosystem: &str, name: &str, version: &str) -> Option<String> {
    if name.is_empty() || version.is_empty() {
        return None;
    }
    let purl_str = match ecosystem {
        "maven" => {
            let (g, a) = name.split_once(':')?;
            if g.is_empty() || a.is_empty() {
                return None;
            }
            format!("pkg:maven/{g}/{a}@{version}")
        }
        "golang" | "go" => format!("pkg:golang/{name}@{version}"),
        "cargo" => format!("pkg:cargo/{name}@{version}"),
        "pypi" => format!("pkg:pypi/{name}@{version}"),
        "npm" => {
            if let Some(rest) = name.strip_prefix('@') {
                let (scope, a) = rest.split_once('/')?;
                format!("pkg:npm/%40{scope}/{a}@{version}")
            } else {
                format!("pkg:npm/{name}@{version}")
            }
        }
        _ => return None,
    };
    Some(purl_str)
}

/// Short display name for a component emitted from a deps.dev
/// response. For Maven, `group:artifact` → `artifact`. For Go,
/// `github.com/spf13/cobra` → `cobra` (final path segment). For
/// others, the name is already short.
fn short_name_for_purl(ecosystem: &str, deps_dev_name: &str) -> String {
    match ecosystem {
        "maven" => deps_dev_name
            .split_once(':')
            .map(|(_, a)| a.to_string())
            .unwrap_or_else(|| deps_dev_name.to_string()),
        "golang" | "go" => deps_dev_name
            .rsplit_once('/')
            .map(|(_, a)| a.to_string())
            .unwrap_or_else(|| deps_dev_name.to_string()),
        _ => deps_dev_name.to_string(),
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn builds_maven_purl_from_group_colon_artifact() {
        assert_eq!(
            build_purl_for_coord("maven", "com.google.guava:guava", "32.1.3-jre"),
            Some("pkg:maven/com.google.guava/guava@32.1.3-jre".to_string()),
        );
    }

    #[test]
    fn rejects_malformed_maven_name() {
        // No colon — not a valid group:artifact. Caller shouldn't
        // fabricate a fake component.
        assert_eq!(
            build_purl_for_coord("maven", "no-colon-here", "1.0"),
            None,
        );
    }

    #[test]
    fn builds_go_purl_from_module_path() {
        assert_eq!(
            build_purl_for_coord("golang", "github.com/spf13/cobra", "v1.10.2"),
            Some("pkg:golang/github.com/spf13/cobra@v1.10.2".to_string()),
        );
    }

    #[test]
    fn builds_npm_scoped_purl() {
        assert_eq!(
            build_purl_for_coord("npm", "@angular/core", "16.0.0"),
            Some("pkg:npm/%40angular/core@16.0.0".to_string()),
        );
    }

    #[test]
    fn short_name_takes_artifact_id_for_maven() {
        assert_eq!(
            short_name_for_purl("maven", "com.google.guava:failureaccess"),
            "failureaccess",
        );
    }

    #[test]
    fn short_name_takes_tail_for_go() {
        assert_eq!(
            short_name_for_purl("go", "github.com/spf13/cobra"),
            "cobra",
        );
    }
}