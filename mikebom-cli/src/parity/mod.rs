//! Cross-format datum-catalog parser + per-row extractor table
//! (milestone 013).
//!
//! Two submodules:
//!
//! * [`catalog`] — parses `docs/reference/sbom-format-mapping.md`
//!   into a `Vec<CatalogRow>`. Each row carries the CycloneDX,
//!   SPDX 2.3, and SPDX 3.0.1 location strings + a derived
//!   `Classification` indicating per-format coverage (Present /
//!   Omitted / Deferred). Per spec clarification Q1, the
//!   classification is inferred from the presence of `omitted —`
//!   or `defer —` in the format-column text.
//!
//! * [`extractors`] — per-row Rust-side extractor table. Each
//!   entry is keyed by catalog row id (`A1`, `A2`, …, `H1`) and
//!   carries three closures (CDX, SPDX 2.3, SPDX 3) plus a
//!   `Directionality` flag. The closures return the normalized
//!   set of "observable values" for that datum in the format's
//!   output. Universal-parity rows assert symmetric equality;
//!   directional-containment rows (e.g., A12 CPE — CDX single
//!   ⊆ SPDX 3 multi) assert subset.
//!
//! See `specs/013-format-parity-enforcement/data-model.md` for
//! the full type catalog and `specs/013-format-parity-enforcement/research.md`
//! §R3-R5 for the design rationale.

pub mod catalog;
pub mod extractors;
