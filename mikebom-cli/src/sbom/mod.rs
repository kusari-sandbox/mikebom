//! Post-generation SBOM manipulation — feature 006 US5.
//!
//! The `mutator` submodule applies RFC 6902 JSON Patches to a
//! generated CycloneDX SBOM and records per-patch provenance so
//! downstream consumers can tell attested data apart from post-hoc
//! enrichment.

pub mod mutator;
