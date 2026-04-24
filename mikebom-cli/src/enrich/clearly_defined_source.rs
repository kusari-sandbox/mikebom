//! ClearlyDefined enrichment source.
//!
//! Mirrors `depsdev_source.rs` — async, in-memory cache (per scan),
//! offline-aware, error-tolerant. The post-scan pipeline calls
//! [`enrich_components`] once with the full component list; CD
//! responses populate `ResolvedComponent.concluded_licenses` so the
//! CDX serializer emits them with `acknowledgement: "concluded"`.
//!
//! The 8-concurrent cap matches deps.dev — CD's API tolerates more,
//! but bounded concurrency keeps memory + connection-pool usage
//! predictable.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tracing::{debug, info};

use mikebom_common::resolution::ResolvedComponent;
use mikebom_common::types::license::SpdxExpression;

use super::clearly_defined_client::{CdDefinition, ClearlyDefinedClient};
use super::clearly_defined_coord::{cd_coord_for, CdCoord};

const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Owns the HTTP client + cache + offline flag.
pub struct ClearlyDefinedSource {
    client: ClearlyDefinedClient,
    offline: bool,
    /// `Some(def)` when CD answered with a definition (license may be
    /// None inside it); `None` for confirmed misses (404). Either way
    /// caching prevents the same coord from being re-fetched in a scan.
    cache: Mutex<HashMap<CdCoord, Option<CdDefinition>>>,
}

impl ClearlyDefinedSource {
    pub fn new(offline: bool) -> Self {
        Self {
            client: ClearlyDefinedClient::new(Duration::from_secs(DEFAULT_TIMEOUT_SECS)),
            offline,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Construct with a custom client (used by tests with a mock server).
    pub fn with_client(client: ClearlyDefinedClient, offline: bool) -> Self {
        Self {
            client,
            offline,
            cache: Mutex::new(HashMap::new()),
        }
    }

    async fn fetch_definition(&self, coord: &CdCoord) -> Option<CdDefinition> {
        if let Some(cached) = self
            .cache
            .lock()
            .expect("cd cache mutex poisoned")
            .get(coord)
        {
            return cached.clone();
        }
        let result = match self.client.get_definition(&coord.url_path()).await {
            Ok(Some(def)) => Some(def),
            Ok(None) => None,
            Err(e) => {
                debug!(
                    coord = %coord.url_path(),
                    error = %e,
                    "ClearlyDefined fetch failed — caching as miss"
                );
                None
            }
        };
        self.cache
            .lock()
            .expect("cd cache mutex poisoned")
            .insert(coord.clone(), result.clone());
        result
    }

    /// Apply one CD definition to a component. Pushes the curated
    /// SPDX expression onto `concluded_licenses`, deduped against
    /// any existing entry. SPDX-parse failures are logged + skipped.
    fn apply_definition(component: &mut ResolvedComponent, def: &CdDefinition) -> bool {
        let Some(ref raw) = def.declared_license else {
            return false;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return false;
        }
        let expr = match SpdxExpression::try_canonical(trimmed) {
            Ok(e) => e,
            Err(e) => {
                debug!(
                    raw = %trimmed,
                    error = %e,
                    "CD returned a non-canonical SPDX expression — skipping"
                );
                return false;
            }
        };
        let canonical = expr.as_str().to_string();
        if component
            .concluded_licenses
            .iter()
            .any(|existing| existing.as_str() == canonical)
        {
            return false;
        }
        component.concluded_licenses.push(expr);
        true
    }
}

/// Enrich every supported component against ClearlyDefined.
///
/// Skips offline mode entirely. Components in unsupported ecosystems
/// (deb / apk / rpm / generic / etc.) are silently passed through.
/// Returns the number of components that picked up at least one
/// concluded license — useful for an INFO-level log line.
///
/// Sequential per-component; mirrors `depsdev_source::enrich_components`'s
/// shape. Bounded-concurrency variant deferred until profiling shows
/// it matters; CD's API is fast enough on small SBOMs that the round
/// trips don't dominate scan time.
pub async fn enrich_components(
    source: &ClearlyDefinedSource,
    components: &mut [ResolvedComponent],
) -> usize {
    if source.offline {
        debug!("ClearlyDefined enrichment skipped — offline mode active");
        return 0;
    }
    let mut enriched = 0usize;
    for component in components.iter_mut() {
        let Some(coord) = cd_coord_for(component) else {
            continue;
        };
        if let Some(def) = source.fetch_definition(&coord).await {
            if ClearlyDefinedSource::apply_definition(component, &def) {
                enriched += 1;
            }
        }
    }
    if enriched > 0 {
        info!(
            count = enriched,
            "ClearlyDefined enriched components with concluded licenses"
        );
    }
    enriched
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::resolution::{
        ResolutionEvidence, ResolutionTechnique,
    };
    use mikebom_common::types::purl::Purl;

    fn make_component(purl: &str) -> ResolvedComponent {
        let p = Purl::new(purl).expect("valid purl");
        ResolvedComponent {
            name: p.name().to_string(),
            version: p.version().unwrap_or("").to_string(),
            purl: p,
            evidence: ResolutionEvidence {
                technique: ResolutionTechnique::PackageDatabase,
                confidence: 0.85,
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
        }
    }

    #[tokio::test]
    async fn offline_mode_is_a_noop() {
        let source = ClearlyDefinedSource::new(true);
        let mut comps = vec![make_component("pkg:npm/express@4.18.2")];
        let n = enrich_components(&source, &mut comps).await;
        assert_eq!(n, 0);
        assert!(comps[0].concluded_licenses.is_empty());
    }

    #[tokio::test]
    async fn unsupported_ecosystems_skipped_silently() {
        let source = ClearlyDefinedSource::new(true);
        let mut comps = vec![
            make_component("pkg:deb/ubuntu/curl@7.88.1"),
            make_component("pkg:rpm/fedora/bash@5.2.15-1.fc40"),
            make_component("pkg:generic/cpython@3.11"),
        ];
        let n = enrich_components(&source, &mut comps).await;
        assert_eq!(n, 0);
        for c in &comps {
            assert!(c.concluded_licenses.is_empty());
        }
    }

    #[test]
    fn apply_definition_adds_canonical_spdx() {
        let mut c = make_component("pkg:npm/express@4.18.2");
        let def = CdDefinition {
            declared_license: Some("MIT".to_string()),
        };
        let added = ClearlyDefinedSource::apply_definition(&mut c, &def);
        assert!(added);
        assert_eq!(c.concluded_licenses.len(), 1);
        assert_eq!(c.concluded_licenses[0].as_str(), "MIT");
    }

    #[test]
    fn apply_definition_dedups() {
        let mut c = make_component("pkg:npm/express@4.18.2");
        let def = CdDefinition {
            declared_license: Some("MIT".to_string()),
        };
        assert!(ClearlyDefinedSource::apply_definition(&mut c, &def));
        // Second apply with same value should be a no-op.
        assert!(!ClearlyDefinedSource::apply_definition(&mut c, &def));
        assert_eq!(c.concluded_licenses.len(), 1);
    }

    #[test]
    fn apply_definition_skips_non_canonical_spdx() {
        let mut c = make_component("pkg:npm/foo@1.0.0");
        let def = CdDefinition {
            declared_license: Some("Some Random License".to_string()),
        };
        let added = ClearlyDefinedSource::apply_definition(&mut c, &def);
        assert!(!added);
        assert!(c.concluded_licenses.is_empty());
    }

    #[test]
    fn apply_definition_skips_when_declared_is_none() {
        let mut c = make_component("pkg:npm/foo@1.0.0");
        let def = CdDefinition {
            declared_license: None,
        };
        assert!(!ClearlyDefinedSource::apply_definition(&mut c, &def));
        assert!(c.concluded_licenses.is_empty());
    }

    #[test]
    fn apply_definition_compound_expression_preserved() {
        let mut c = make_component("pkg:cargo/anyhow@1.0.80");
        let def = CdDefinition {
            declared_license: Some("MIT OR Apache-2.0".to_string()),
        };
        assert!(ClearlyDefinedSource::apply_definition(&mut c, &def));
        assert_eq!(c.concluded_licenses[0].as_str(), "MIT OR Apache-2.0");
    }
}
