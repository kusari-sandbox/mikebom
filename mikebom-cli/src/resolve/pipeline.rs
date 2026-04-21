//! Orchestrate all resolvers in priority order to produce resolved components.
//!
//! The resolution pipeline runs each resolver against traced connections and
//! file operations, assigns confidence scores, then deduplicates results.

use std::collections::HashMap;
use std::time::Duration;

use mikebom_common::attestation::statement::InTotoStatement;
use mikebom_common::resolution::{
    ResolvedComponent, ResolutionEvidence, ResolutionTechnique,
};
use mikebom_common::types::hash::ContentHash;

use super::deduplicator::deduplicate;
use super::hash_resolver::HashResolver;
use super::hostname_resolver::resolve_hostname;
use super::path_resolver::resolve_path_with_context;
use super::url_resolver::resolve_url_with_context;

/// Configuration for the resolution pipeline.
#[derive(Clone, Debug)]
pub struct ResolutionConfig {
    /// Timeout for deps.dev API requests.
    pub deps_dev_timeout: Duration,
    /// Skip online API calls (hash resolution via deps.dev).
    pub skip_online_validation: bool,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            deps_dev_timeout: Duration::from_secs(10),
            skip_online_validation: false,
        }
    }
}

/// The resolution pipeline orchestrates all resolvers in priority order.
pub struct ResolutionPipeline {
    config: ResolutionConfig,
    hash_resolver: HashResolver,
}

impl ResolutionPipeline {
    /// Create a new pipeline with the given configuration.
    pub fn new(config: ResolutionConfig) -> Self {
        let hash_resolver = HashResolver::new(config.deps_dev_timeout);
        Self {
            config,
            hash_resolver,
        }
    }

    /// Resolve all connections and file operations from an attestation
    /// into identified software components.
    ///
    /// Resolution order (by confidence):
    /// 1. URL pattern resolution (confidence 0.95)
    /// 2. Hash resolution via deps.dev (confidence 0.90)
    /// 3. File path resolution for correlated file ops (confidence 0.70)
    /// 4. Hostname heuristic (confidence 0.40)
    ///
    /// Results are then deduplicated to produce a unique component list.
    pub async fn resolve(
        &self,
        attestation: &InTotoStatement,
    ) -> anyhow::Result<Vec<ResolvedComponent>> {
        let mut components = Vec::new();

        // Pull the distro codename off the attestation's host metadata.
        // Resolvers that need it (deb) use this as the `distro` qualifier;
        // others ignore it. Falls back to `None` on non-Debian hosts.
        let deb_codename: Option<&str> = attestation
            .predicate
            .metadata
            .host
            .distro_codename
            .as_deref();

        // Basename → content hash map built from file-access events.
        // URL-pattern resolution alone doesn't know the file's bytes; we
        // correlate by matching the last path segment of the URL
        // (`.../foo_1.0_arm64.deb`) to a file op with the same basename
        // whose userspace post-trace hash pass populated `content_hash`.
        // If the trace captured multiple files with the same basename
        // (rare), the first one wins — they should be byte-identical if
        // named the same.
        let basename_to_hash: HashMap<&str, &ContentHash> = attestation
            .predicate
            .file_access
            .operations
            .iter()
            .filter_map(|op| {
                let h = op.content_hash.as_ref()?;
                let base = std::path::Path::new(&op.path)
                    .file_name()
                    .and_then(|s| s.to_str())?;
                Some((base, h))
            })
            .collect();

        // Process each network connection.
        for conn in &attestation.predicate.network_trace.connections {
            let hostname = conn
                .destination
                .hostname
                .as_deref()
                .or_else(|| conn.tls.as_ref().and_then(|t| t.sni.as_deref()))
                .unwrap_or("");

            let path = conn
                .request
                .as_ref()
                .map(|r| r.path.as_str())
                .unwrap_or("");

            // 1. URL pattern resolution (confidence 0.95).
            if !hostname.is_empty() && !path.is_empty() {
                if let Some(purl) = resolve_url_with_context(hostname, path, deb_codename) {
                    // Attach the hash of the file whose name matches this
                    // URL's last path segment, if we saw one land on disk.
                    let url_basename = path.rsplit('/').next().unwrap_or("");
                    let mut hashes = collect_connection_hashes(conn);
                    let mut matched_file_path: Vec<String> = Vec::new();
                    if !url_basename.is_empty() {
                        if let Some(h) = basename_to_hash.get(url_basename) {
                            hashes.push((*h).clone());
                            // Record which file-access event contributed
                            // the hash as part of the component's evidence.
                            if let Some(op) = attestation
                                .predicate
                                .file_access
                                .operations
                                .iter()
                                .find(|o| {
                                    std::path::Path::new(&o.path)
                                        .file_name()
                                        .and_then(|s| s.to_str())
                                        == Some(url_basename)
                                })
                            {
                                matched_file_path.push(op.path.clone());
                            }
                        }
                    }
                    let component = ResolvedComponent {
                        name: purl.name().to_string(),
                        version: purl.version().unwrap_or("").to_string(),
                        purl,
                        evidence: ResolutionEvidence {
                            technique: ResolutionTechnique::UrlPattern,
                            confidence: 0.95,
                            source_connection_ids: vec![conn.id.clone()],
                            source_file_paths: matched_file_path,
                            deps_dev_match: None,
                        },
                        licenses: vec![],
                        concluded_licenses: Vec::new(),
                        hashes,
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
                    };
                    components.push(component);
                    continue; // URL match found; skip lower-priority resolvers for this connection.
                }
            }

            // 2. Hash resolution via deps.dev (confidence 0.90).
            if !self.config.skip_online_validation {
                if let Some(content_hash) = conn
                    .response
                    .as_ref()
                    .and_then(|r| r.content_hash.as_ref())
                {
                    match self.hash_resolver.resolve(content_hash).await {
                        Ok(matches) => {
                            for m in matches {
                                let component = ResolvedComponent {
                                    name: m.name.clone(),
                                    version: m.version.clone(),
                                    purl: m.purl,
                                    evidence: ResolutionEvidence {
                                        technique: ResolutionTechnique::HashMatch,
                                        confidence: 0.90,
                                        source_connection_ids: vec![conn.id.clone()],
                                        source_file_paths: vec![],
                                        deps_dev_match: Some(
                                            mikebom_common::resolution::DepsDevMatch {
                                                system: m.system,
                                                name: m.name,
                                                version: m.version,
                                            },
                                        ),
                                    },
                                    licenses: vec![],
                                    concluded_licenses: Vec::new(),
                                    hashes: collect_connection_hashes(conn),
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
                                };
                                components.push(component);
                            }
                            // If hash resolution produced results, skip lower-priority.
                            if !components.is_empty() {
                                continue;
                            }
                        }
                        Err(e) => {
                            tracing::debug!("hash resolution failed for {}: {e}", conn.id);
                        }
                    }
                }
            }

            // 4. Hostname heuristic (confidence 0.40).
            // (This only tells us the ecosystem, not name/version — limited utility.
            //  We skip creating a component here since we lack name/version.)
            if !hostname.is_empty() {
                if let Some(ecosystem) = resolve_hostname(hostname) {
                    tracing::debug!(
                        "hostname heuristic for {}: ecosystem={ecosystem} (no PURL created, insufficient info)",
                        conn.id,
                    );
                }
            }
        }

        // 3. File path resolution for file operations (confidence 0.70).
        for file_op in &attestation.predicate.file_access.operations {
            if let Some(purl) = resolve_path_with_context(&file_op.path, deb_codename) {
                let component = ResolvedComponent {
                    name: purl.name().to_string(),
                    version: purl.version().unwrap_or("").to_string(),
                    purl,
                    evidence: ResolutionEvidence {
                        technique: ResolutionTechnique::FilePathPattern,
                        confidence: 0.70,
                        source_connection_ids: vec![],
                        source_file_paths: vec![file_op.path.clone()],
                        deps_dev_match: None,
                    },
                    licenses: vec![],
                    concluded_licenses: Vec::new(),
                    hashes: file_op
                        .content_hash
                        .as_ref()
                        .cloned()
                        .into_iter()
                        .collect(),
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
                };
                components.push(component);
            }
        }

        // Deduplicate across all resolution techniques.
        let deduped = deduplicate(components);

        Ok(deduped)
    }
}

/// Collect content hashes from a connection's response.
fn collect_connection_hashes(
    conn: &mikebom_common::attestation::network::Connection,
) -> Vec<ContentHash> {
    conn.response
        .as_ref()
        .and_then(|r| r.content_hash.as_ref())
        .cloned()
        .into_iter()
        .collect()
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    /// Load the sample attestation fixture and verify URL resolution works.
    #[tokio::test]
    async fn resolve_sample_attestation() {
        let fixture = std::fs::read_to_string(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../tests/fixtures/sample-attestation.json"
            ),
        )
        .expect("should read sample attestation fixture");

        let attestation: InTotoStatement =
            serde_json::from_str(&fixture).expect("should parse attestation");

        // Create a pipeline that skips online validation (no real API calls).
        let config = ResolutionConfig {
            deps_dev_timeout: Duration::from_secs(1),
            skip_online_validation: true,
        };
        let pipeline = ResolutionPipeline::new(config);

        let components = pipeline
            .resolve(&attestation)
            .await
            .expect("resolution should succeed");

        // The sample attestation has 3 connections to crates.io / static.crates.io
        // plus 2 file operations.
        // After deduplication (URL + file path both finding serde and tokio),
        // we should have at least serde, tokio, and anyhow.
        assert!(
            components.len() >= 3,
            "expected at least 3 components, got {}",
            components.len(),
        );

        // Verify specific packages were resolved.
        let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"serde"), "expected serde in {names:?}");
        assert!(names.contains(&"tokio"), "expected tokio in {names:?}");
        assert!(names.contains(&"anyhow"), "expected anyhow in {names:?}");

        // Verify that the URL-resolved components have the right confidence.
        for component in &components {
            match component.evidence.technique {
                ResolutionTechnique::UrlPattern => {
                    assert_eq!(component.evidence.confidence, 0.95);
                }
                ResolutionTechnique::FilePathPattern => {
                    assert_eq!(component.evidence.confidence, 0.70);
                }
                _ => {}
            }
        }

        // Verify serde was deduplicated (URL match + file path match merged).
        let serde = components.iter().find(|c| c.name == "serde").unwrap();
        assert_eq!(
            serde.evidence.confidence, 0.95,
            "URL pattern should win over file path pattern"
        );
        // After dedup, serde should have evidence from both URL and file path.
        assert!(
            !serde.evidence.source_connection_ids.is_empty(),
            "should have connection ID from URL resolution"
        );
        assert!(
            !serde.evidence.source_file_paths.is_empty(),
            "should have file path from path resolution"
        );
    }

    #[test]
    fn default_config() {
        let config = ResolutionConfig::default();
        assert_eq!(config.deps_dev_timeout, Duration::from_secs(10));
        assert!(!config.skip_online_validation);
    }

    #[tokio::test]
    async fn empty_attestation_returns_empty() {
        use mikebom_common::attestation::file::{FileAccess, FileAccessSummary};
        use mikebom_common::attestation::integrity::TraceIntegrity;
        use mikebom_common::attestation::metadata::{
            GenerationContext, HostInfo, ProcessInfo, ToolInfo, TraceMetadata,
        };
        use mikebom_common::attestation::network::{NetworkSummary, NetworkTrace};
        use mikebom_common::attestation::statement::{InTotoStatement, ResourceDescriptor};
        use mikebom_common::types::timestamp::Timestamp;
        use std::collections::BTreeMap;

        let attestation = InTotoStatement {
            statement_type: InTotoStatement::STATEMENT_TYPE.to_string(),
            subject: vec![ResourceDescriptor {
                name: "empty".to_string(),
                digest: BTreeMap::new(),
            }],
            predicate_type: InTotoStatement::PREDICATE_TYPE.to_string(),
            predicate: mikebom_common::attestation::statement::BuildTracePredicate {
                metadata: TraceMetadata {
                    tool: ToolInfo {
                        name: "mikebom".to_string(),
                        version: "0.1.0".to_string(),
                    },
                    trace_start: Timestamp::now(),
                    trace_end: Timestamp::now(),
                    target_process: ProcessInfo {
                        pid: 1,
                        command: "test".to_string(),
                        cgroup_id: 1,
                    },
                    host: HostInfo {
                        os: "linux".to_string(),
                        kernel_version: "6.5.0".to_string(),
                        arch: "x86_64".to_string(),
                        distro_codename: Some("bookworm".to_string()),
                    },
                    generation_context: GenerationContext::BuildTimeTrace,
                },
                network_trace: NetworkTrace {
                    connections: vec![],
                    summary: NetworkSummary {
                        total_connections: 0,
                        unique_hosts: vec![],
                        unique_ips: vec![],
                        protocol_counts: BTreeMap::new(),
                        total_bytes_received: 0,
                    },
                },
                file_access: FileAccess {
                    operations: vec![],
                    summary: FileAccessSummary {
                        total_operations: 0,
                        unique_paths: 0,
                        operations_by_type: BTreeMap::new(),
                    },
                },
                trace_integrity: TraceIntegrity {
                    ring_buffer_overflows: 0,
                    events_dropped: 0,
                    uprobe_attach_failures: vec![],
                    kprobe_attach_failures: vec![],
                    partial_captures: vec![],
                    bloom_filter_capacity: 100_000,
                    bloom_filter_false_positive_rate: 0.01,
                },
            },
        };

        let config = ResolutionConfig {
            deps_dev_timeout: Duration::from_secs(1),
            skip_online_validation: true,
        };
        let pipeline = ResolutionPipeline::new(config);
        let components = pipeline.resolve(&attestation).await.expect("should succeed");
        assert!(components.is_empty());
    }
}