//! CycloneDX 1.6 JSON serializer.
//!
//! Existing build logic lives in the per-section modules
//! ([`builder`], [`metadata`], [`evidence`], [`compositions`],
//! [`dependencies`], [`vex`]) — milestone 010 left that code
//! untouched. [`CycloneDxJsonSerializer`] wraps those helpers behind
//! the shared [`super::SbomSerializer`] trait so the CLI can dispatch
//! to it alongside SPDX and future formats, without changing the
//! output bytes (FR-022 / SC-006).

pub mod builder;
pub mod compositions;
pub mod dependencies;
pub mod evidence;
pub mod metadata;
pub mod serializer;
pub mod vex;

use std::path::PathBuf;

use anyhow::Context;

use super::{EmittedArtifact, OutputConfig, SbomSerializer, ScanArtifacts};
use builder::{CycloneDxBuilder, CycloneDxConfig};

/// CycloneDX 1.6 JSON serializer.
///
/// Delegates unchanged to [`CycloneDxBuilder`] and
/// `serde_json::to_string_pretty`; byte-for-byte identical to
/// pre-milestone-010 output for the same inputs (the inherently
/// volatile `serialNumber` and `metadata.timestamp` fields remain
/// generated internally, so cross-run byte-identity requires
/// normalization — see `tests/cdx_regression.rs`).
pub struct CycloneDxJsonSerializer;

impl SbomSerializer for CycloneDxJsonSerializer {
    fn id(&self) -> &'static str {
        "cyclonedx-json"
    }

    fn default_filename(&self) -> &'static str {
        "mikebom.cdx.json"
    }

    fn serialize(
        &self,
        scan: &ScanArtifacts<'_>,
        _cfg: &OutputConfig,
    ) -> anyhow::Result<Vec<EmittedArtifact>> {
        let cdx_config = CycloneDxConfig {
            include_hashes: scan.include_hashes,
            include_source_files: scan.include_source_files,
            generation_context: scan.generation_context.clone(),
            include_dev: scan.include_dev,
        };
        let builder = CycloneDxBuilder::new(cdx_config)
            .with_os_release_missing_fields(scan.os_release_missing_fields.to_vec());
        let bom = builder.build(
            scan.components,
            scan.relationships,
            scan.integrity,
            scan.target_name,
            scan.complete_ecosystems,
            scan.scan_target_coord,
        )?;
        let json_str = serde_json::to_string_pretty(&bom)
            .context("serializing CycloneDX BOM to JSON")?;
        Ok(vec![EmittedArtifact {
            relative_path: PathBuf::from(self.default_filename()),
            bytes: json_str.into_bytes(),
        }])
    }
}
