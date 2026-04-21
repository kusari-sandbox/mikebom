use std::collections::HashMap;
use std::sync::Mutex;

use tracing::{debug, info};

use mikebom_common::resolution::{DepsDevMatch, Relationship, ResolvedComponent};
use mikebom_common::types::license::SpdxExpression;

use super::deps_dev_client::{DepsDevClient, VersionInfo};
use super::deps_dev_system::deps_dev_system_for;
use super::source::EnrichmentSource;

/// An enrichment source backed by the deps.dev v3 API.
///
/// Covers ecosystems deps.dev actually indexes (cargo, npm, pypi, go,
/// maven, nuget). Components with ecosystems outside that set (deb,
/// apk, generic, …) are skipped silently — no API call, no error.
///
/// Behaves as a strict enhancement layer: failures (404s, timeouts,
/// unparseable SPDX strings) are logged at `debug` / `warn` and the
/// component is left exactly as it was. Never fails the enclosing
/// scan.
pub struct DepsDevSource {
    client: DepsDevClient,
    offline: bool,
    /// In-memory cache keyed by (system, name, version). `None` caches
    /// the "API returned 404 / error" result so we don't re-hit the
    /// same miss for every duplicate component in a single scan.
    cache: Mutex<HashMap<(String, String, String), Option<VersionInfo>>>,
}

impl DepsDevSource {
    /// Create a new deps.dev enrichment source. When `offline` is true
    /// the source skips every API call (serves as a cheap no-op) —
    /// useful when the global `--offline` flag is set or tests want to
    /// exercise the enrichment path without hitting the network.
    pub fn new(client: DepsDevClient, offline: bool) -> Self {
        Self {
            client,
            offline,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Look up `(system, name, version)` in deps.dev, returning the
    /// cached result when available. Errors are converted to `None` so
    /// the caller can treat "not found" and "API transiently broken"
    /// uniformly.
    async fn fetch_version_info(
        &self,
        system: &str,
        name: &str,
        version: &str,
    ) -> Option<VersionInfo> {
        let key = (system.to_string(), name.to_string(), version.to_string());
        if let Some(cached) = self.cache.lock().expect("deps.dev cache mutex poisoned").get(&key) {
            return cached.clone();
        }
        let result = match self.client.get_version(system, name, version).await {
            Ok(info) => Some(info),
            Err(e) => {
                debug!(
                    system = %system,
                    name = %name,
                    version = %version,
                    error = %e,
                    "deps.dev get_version failed — caching as miss"
                );
                None
            }
        };
        self.cache.lock().expect("deps.dev cache mutex poisoned").insert(key, result.clone());
        result
    }

    /// Apply one deps.dev `VersionInfo` payload to a component. Adds any
    /// SPDX-canonical licenses to `component.licenses` (de-duped against
    /// what's already there) and stamps the `deps_dev_match` evidence
    /// field so downstream consumers see where the enrichment came from.
    fn apply_version_info(
        component: &mut ResolvedComponent,
        system: &str,
        info: &VersionInfo,
    ) {
        for raw in &info.licenses {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let expr = match SpdxExpression::try_canonical(trimmed) {
                Ok(e) => e,
                Err(e) => {
                    debug!(
                        raw = %trimmed,
                        error = %e,
                        "deps.dev returned a non-canonical SPDX expression"
                    );
                    continue;
                }
            };
            let canonical = expr.as_str().to_string();
            if !component
                .licenses
                .iter()
                .any(|existing| existing.as_str() == canonical)
            {
                component.licenses.push(expr);
            }
        }
        component.evidence.deps_dev_match = Some(DepsDevMatch {
            system: system.to_string(),
            name: component.name.clone(),
            version: component.version.clone(),
        });
    }
}

impl EnrichmentSource for DepsDevSource {
    fn name(&self) -> &str {
        "deps.dev"
    }

    fn enrich_relationships(
        &self,
        components: &[ResolvedComponent],
    ) -> anyhow::Result<Vec<Relationship>> {
        info!(
            component_count = components.len(),
            "deps.dev relationship enrichment (not implemented — licenses + CPE only)"
        );
        // Relationship enrichment via deps.dev's GetDependencies endpoint
        // is tracked as its own follow-up. The current round only
        // populates metadata.
        Ok(vec![])
    }

    fn enrich_metadata(
        &self,
        _component: &mut ResolvedComponent,
    ) -> anyhow::Result<()> {
        // The sync trait contract doesn't match deps.dev's async client.
        // Callers that want the real enrichment use
        // [`enrich_components`] (defined below) instead — it takes the
        // full set in one async pass so we can batch + cache.
        Ok(())
    }
}

/// Enrich a whole vector of components against deps.dev. Offline-aware
/// and lossy-friendly: components in unsupported ecosystems are left
/// untouched, API errors cache as misses without failing the scan.
///
/// Returns the number of components that received at least one new
/// license or CPE candidate from deps.dev. Useful for a post-scan log
/// line.
pub async fn enrich_components(source: &DepsDevSource, components: &mut [ResolvedComponent]) -> usize {
    if source.offline {
        debug!("deps.dev enrichment skipped — offline mode active");
        return 0;
    }
    let mut enriched_count = 0usize;
    for component in components.iter_mut() {
        let ecosystem = component.purl.ecosystem();
        let Some(system) = deps_dev_system_for(ecosystem) else {
            continue;
        };
        if component.name.is_empty() || component.version.is_empty() {
            continue;
        }
        // deps.dev keys Maven packages by `group:artifact` (and Go by
        // module path, npm scoped by `@scope/name`). `component.name`
        // is just the artifact / short name, which for Maven/Go/npm
        // produces 404s. Format through the helper so the URL is
        // correct for every supported ecosystem.
        let name =
            super::deps_dev_system::deps_dev_package_name(
                ecosystem,
                component.purl.namespace(),
                &component.name,
            );
        let licenses_before = component.licenses.len();
        if let Some(info) = source
            .fetch_version_info(system, &name, &component.version)
            .await
        {
            DepsDevSource::apply_version_info(component, system, &info);
            if component.licenses.len() > licenses_before {
                enriched_count += 1;
            }
        }
    }
    if enriched_count > 0 {
        info!(
            count = enriched_count,
            "deps.dev enriched components with new licenses"
        );
    }
    enriched_count
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::resolution::{ResolutionEvidence, ResolutionTechnique};
    use mikebom_common::types::purl::Purl;
    use std::time::Duration;

    fn make_component(purl_str: &str) -> ResolvedComponent {
        let purl = Purl::new(purl_str).expect("valid purl");
        ResolvedComponent {
            name: purl.name().to_string(),
            version: purl.version().unwrap_or("0.0.0").to_string(),
            purl,
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
        }
    }

    #[tokio::test]
    async fn offline_mode_skips_api_and_leaves_components_untouched() {
        // Pointing at a deliberately-unreachable URL would prove the
        // skip, but using offline=true is safer: the client is never
        // invoked at all so there's no network dependency in the test.
        let client = DepsDevClient::new(Duration::from_secs(1));
        let source = DepsDevSource::new(client, /*offline=*/ true);
        let mut components = vec![make_component("pkg:cargo/serde@1.0.197")];
        let n = enrich_components(&source, &mut components).await;
        assert_eq!(n, 0);
        assert!(components[0].licenses.is_empty());
        assert!(components[0].evidence.deps_dev_match.is_none());
    }

    #[tokio::test]
    async fn unsupported_ecosystems_are_skipped_without_cache_entry() {
        let client = DepsDevClient::new(Duration::from_secs(1));
        let source = DepsDevSource::new(client, /*offline=*/ false);
        let mut components = vec![
            make_component("pkg:deb/debian/jq@1.6-2.1"),
            make_component("pkg:apk/alpine/musl@1.2.4-r2"),
        ];
        let n = enrich_components(&source, &mut components).await;
        assert_eq!(n, 0);
        // Cache must stay empty — we never looked these up.
        assert!(source.cache.lock().unwrap().is_empty());
    }

    #[test]
    fn apply_version_info_deduplicates_licenses() {
        // Pre-seed with MIT; deps.dev returns MIT + Apache-2.0 — only
        // Apache-2.0 should be appended.
        let mut c = make_component("pkg:cargo/foo@1.0.0");
        c.licenses.push(SpdxExpression::try_canonical("MIT").unwrap());
        let info = VersionInfo {
            licenses: vec!["MIT".into(), "Apache-2.0".into()],
            advisory_keys: vec![],
            links: vec![],
        };
        DepsDevSource::apply_version_info(&mut c, "cargo", &info);
        assert_eq!(c.licenses.len(), 2);
        assert!(c.licenses.iter().any(|l| l.as_str() == "MIT"));
        assert!(c.licenses.iter().any(|l| l.as_str() == "Apache-2.0"));
        assert!(c.evidence.deps_dev_match.is_some());
    }

    #[test]
    fn apply_version_info_rejects_unparseable_license_strings() {
        let mut c = make_component("pkg:cargo/foo@1.0.0");
        let info = VersionInfo {
            licenses: vec!["Not a real SPDX token $%^".into()],
            advisory_keys: vec![],
            links: vec![],
        };
        DepsDevSource::apply_version_info(&mut c, "cargo", &info);
        assert!(c.licenses.is_empty());
        // We still stamp the deps_dev_match (we did look it up,
        // successfully — the payload just happened to be garbage).
        assert!(c.evidence.deps_dev_match.is_some());
    }
}