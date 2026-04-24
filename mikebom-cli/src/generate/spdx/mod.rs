//! SPDX output serializers (milestone 010).
//!
//! Two user-facing formats live here:
//!
//! * `spdx-2.3-json` — stable, covers all ecosystems supported by the
//!   CycloneDX path. See [`document`], [`packages`], [`relationships`].
//! * `spdx-3-json-experimental` — opt-in stub covering one ecosystem
//!   (npm); targets SPDX 3.0.1 JSON-LD. See [`v3_stub`].
//!
//! Mikebom-specific data without a native SPDX 2.3 home is preserved
//! losslessly via [`annotations`] with a versioned JSON envelope per
//! `contracts/mikebom-annotation.schema.json`.
//!
//! The data-placement map in `docs/reference/sbom-format-mapping.md`
//! is the authoritative cross-format contract these serializers honor.

pub mod annotations;
pub mod document;
pub mod ids;
pub mod packages;
pub mod relationships;
pub mod v3_stub;

use std::path::PathBuf;

use anyhow::Context;

use super::{EmittedArtifact, OutputConfig, SbomSerializer, ScanArtifacts};

/// SPDX 2.3 JSON serializer (T026).
///
/// Produces a document under the default filename `mikebom.spdx.json`.
/// Determinism is guaranteed by construction: the document's
/// `creationInfo.created` is taken from [`OutputConfig::created`] and
/// the `documentNamespace` is a SHA-256 hash of scan content; no
/// `Utc::now()` / `Uuid::new_v4()` inside the serialization path.
pub struct Spdx2_3JsonSerializer;

impl SbomSerializer for Spdx2_3JsonSerializer {
    fn id(&self) -> &'static str {
        "spdx-2.3-json"
    }

    fn default_filename(&self) -> &'static str {
        "mikebom.spdx.json"
    }

    fn serialize(
        &self,
        scan: &ScanArtifacts<'_>,
        cfg: &OutputConfig,
    ) -> anyhow::Result<Vec<EmittedArtifact>> {
        let doc = document::build_document(scan, cfg);
        let json_str = serde_json::to_string_pretty(&doc)
            .context("serializing SPDX 2.3 document to JSON")?;
        Ok(vec![EmittedArtifact {
            relative_path: PathBuf::from(self.default_filename()),
            bytes: json_str.into_bytes(),
        }])
    }
}
