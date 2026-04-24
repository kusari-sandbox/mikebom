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

pub mod ids;
pub mod document;
pub mod packages;
pub mod relationships;
pub mod annotations;
pub mod v3_stub;
