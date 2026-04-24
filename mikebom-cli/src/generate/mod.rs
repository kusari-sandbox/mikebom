//! SBOM output generation — format dispatch layer (milestone 010).
//!
//! The [`SbomSerializer`] trait is the sole extension point for
//! adding a new SBOM output format. Every concrete emitter
//! ([`cyclonedx::CycloneDxJsonSerializer`] today; SPDX 2.3 +
//! SPDX 3.0.1 stub + OpenVEX sidecar land in later phases of this
//! milestone) consumes a neutral [`ScanArtifacts`] bundle and a shared
//! [`OutputConfig`] and returns one or more [`EmittedArtifact`] byte
//! buffers — the CLI layer owns filesystem placement.
//!
//! Per feature 010 FR-019, adding a future format (or extending the
//! SPDX 3 stub to more ecosystems) is a single-line registration in
//! [`SerializerRegistry::with_defaults`] plus a new module; the scan,
//! resolution, and other format implementations do not have to change.
//!
//! Determinism contract (data-model.md §8):
//!   - serializers MUST be pure functions of `(scan, cfg)`;
//!   - [`OutputConfig::created`] is the single timestamp source
//!     shared across every format emitted in one invocation;
//!   - any `HashMap` use is forbidden on the serialization path —
//!     use `BTreeMap` or an explicitly sorted `Vec`.

pub mod cpe;
pub mod cyclonedx;
pub mod openvex;
pub mod spdx;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use mikebom_common::attestation::integrity::TraceIntegrity;
use mikebom_common::attestation::metadata::GenerationContext;
use mikebom_common::resolution::{Relationship, ResolvedComponent};

/// Format-neutral bundle of everything a serializer might consume.
///
/// Mirrors the inputs the existing
/// [`cyclonedx::builder::CycloneDxBuilder::build`] has always taken,
/// so the CDX refactor behind [`SbomSerializer`] does not need to
/// change its output bytes — the load-bearing protection for
/// FR-022 / SC-006.
pub struct ScanArtifacts<'a> {
    pub target_name: &'a str,
    pub components: &'a [ResolvedComponent],
    pub relationships: &'a [Relationship],
    pub integrity: &'a TraceIntegrity,
    pub complete_ecosystems: &'a [String],
    pub os_release_missing_fields: &'a [String],
    pub scan_target_coord:
        Option<&'a crate::scan_fs::package_db::maven::ScanTargetCoord>,
    pub generation_context: GenerationContext,
    pub include_dev: bool,
    pub include_hashes: bool,
    pub include_source_files: bool,
}

/// Per-invocation configuration threaded through every serializer.
///
/// `created` is the single timestamp source used for any `timestamp`
/// / `creationInfo.created` / `annotationDate` field in any format —
/// serializers MUST NOT call `Utc::now()` directly. `overrides` is
/// the per-format output-path map built by the CLI layer from
/// `--output <fmt>=<path>` flags.
///
/// Note: today's [`cyclonedx::CycloneDxJsonSerializer`] does not
/// consume these fields — pre-milestone-010 CDX output uses its own
/// internal `Utc::now()` + `Uuid::new_v4()` to preserve byte-identity
/// (FR-022 / SC-006). SPDX 2.3, SPDX 3.0.1-experimental, and the
/// OpenVEX sidecar all consume them in later phases of this milestone.
#[allow(dead_code)]
pub struct OutputConfig {
    pub mikebom_version: &'static str,
    pub created: DateTime<Utc>,
    pub overrides: BTreeMap<String, PathBuf>,
}

/// One serialized file produced by a serializer.
///
/// Multi-artifact returns let a single serializer emit a primary
/// document plus side artifacts — e.g. the SPDX 2.3 emitter co-emits
/// the OpenVEX sidecar when a scan produces VEX, with the
/// cross-reference baked into the primary doc.
pub struct EmittedArtifact {
    /// Suggested filename relative to the output root. The CLI layer
    /// uses this when the user did not pass a `--output <fmt>=<path>`
    /// override for this format.
    pub relative_path: PathBuf,
    pub bytes: Vec<u8>,
}

/// One concrete SBOM output format.
pub trait SbomSerializer: Send + Sync {
    /// Stable identifier matching the CLI `--format` value (e.g.
    /// `"cyclonedx-json"`). Returned strings are compared case-sensitive.
    fn id(&self) -> &'static str;

    /// Default output filename when no per-format `--output` override
    /// is set. Distinct per format, so default paths never collide.
    fn default_filename(&self) -> &'static str;

    /// Whether this serializer is labeled experimental (FR-019b).
    fn experimental(&self) -> bool {
        false
    }

    /// Serialize a scan result into one or more output artifacts.
    fn serialize(
        &self,
        artifacts: &ScanArtifacts<'_>,
        cfg: &OutputConfig,
    ) -> anyhow::Result<Vec<EmittedArtifact>>;
}

/// Registry of every SBOM output format the CLI can dispatch to.
///
/// [`with_defaults`](Self::with_defaults) is the single registration
/// site for built-in serializers (FR-019). Adding a new format in a
/// future milestone is a one-line insertion here plus the serializer
/// implementation.
pub struct SerializerRegistry {
    by_id: BTreeMap<&'static str, Arc<dyn SbomSerializer>>,
}

impl SerializerRegistry {
    /// Register every stable, built-in serializer.
    ///
    /// Phase 3 of milestone 010 adds SPDX 2.3; the SPDX 3.0.1
    /// experimental stub lands in Phase 5 (US3) and extends this
    /// list.
    pub fn with_defaults() -> Self {
        let mut by_id: BTreeMap<&'static str, Arc<dyn SbomSerializer>> =
            BTreeMap::new();
        let cdx: Arc<dyn SbomSerializer> =
            Arc::new(cyclonedx::CycloneDxJsonSerializer);
        by_id.insert(cdx.id(), cdx);
        let spdx23: Arc<dyn SbomSerializer> =
            Arc::new(spdx::Spdx2_3JsonSerializer);
        by_id.insert(spdx23.id(), spdx23);
        Self { by_id }
    }

    /// Iterator over every registered format id, in deterministic order.
    pub fn ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.by_id.keys().copied()
    }

    /// Look up one serializer by format id.
    pub fn get(&self, id: &str) -> Option<Arc<dyn SbomSerializer>> {
        self.by_id.get(id).cloned()
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn defaults_include_cyclonedx_json() {
        let reg = SerializerRegistry::with_defaults();
        let ids: Vec<&str> = reg.ids().collect();
        assert!(
            ids.contains(&"cyclonedx-json"),
            "default registry must include cyclonedx-json, got {ids:?}"
        );
        let s = reg.get("cyclonedx-json").expect("cyclonedx-json registered");
        assert_eq!(s.id(), "cyclonedx-json");
        assert_eq!(s.default_filename(), "mikebom.cdx.json");
        assert!(!s.experimental());
    }

    #[test]
    fn unknown_id_returns_none() {
        let reg = SerializerRegistry::with_defaults();
        assert!(reg.get("not-a-real-format").is_none());
    }

    #[test]
    fn ids_are_in_deterministic_order() {
        // Two independent registries must iterate identically.
        let a: Vec<&str> = SerializerRegistry::with_defaults().ids().collect();
        let b: Vec<&str> = SerializerRegistry::with_defaults().ids().collect();
        assert_eq!(a, b);
    }
}
