//! OpenVEX 0.2.0 JSON sidecar emitter (milestone 010).
//!
//! Emitted next to the SPDX 2.3 file when a scan produces VEX
//! statements. Cross-referenced from the SPDX document via
//! `externalDocumentRefs` with `SHA256`. Not emitted when the scan
//! produces no VEX statements.
//!
//! See [`statements`] for the typed model.

pub mod statements;
