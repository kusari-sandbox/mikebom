//! Library-crate root for mikebom-cli.
//!
//! mikebom-cli is canonically a binary crate (`src/main.rs` is the
//! entry point); this library exists **only** to share a small
//! amount of code between the binary AND its integration tests
//! under `tests/`. Rust integration tests live in their own crate
//! and cannot import binary-internal modules; the lib + bin layout
//! is the standard solution.
//!
//! Today the library exposes one module:
//!
//! * [`parity`] — milestone 013: the canonical cross-format datum
//!   catalog parser (`parity::catalog`) + per-row extractor table
//!   (`parity::extractors`). Consumed by:
//!     * `src/cli/parity_cmd.rs` (US3 — the `mikebom sbom
//!       parity-check` diagnostic) via `crate::parity::*`
//!     * `mikebom-cli/tests/holistic_parity.rs` (US1 holistic
//!       parity test) via `mikebom::parity::*`
//!     * `mikebom-cli/tests/mapping_doc_bidirectional.rs` (US2
//!       auto-discovery + reverse check) via `mikebom::parity::*`
//!
//! Every other module (`cli`, `generate`, `resolve`, `enrich`,
//! `scan_fs`, `trace`, `attestation`, `policy`, `sbom`, `error`,
//! `config`) is intentionally NOT exposed here — they remain
//! binary-internal per Constitution Principle VI. Adding a new
//! module to this lib root is a deliberate decision that should
//! match the same pattern as `parity`: small, pure-data + pure-
//! function code that benefits from being importable by tests.

pub mod parity;


// Probe for milestone-016 SC-003: deliberately-dead private function to
// verify the new CI gate fails on a new clippy warning. To be deleted
// before merge — this branch is opened ONLY to confirm CI rejects new
// warnings. `pub` items don't trigger `dead_code` (they're part of the
// public API surface), so the probe must be private to fire the lint.
fn deliberate_dead_code_probe_for_sc003() {}
