//! Shared test helpers for mikebom-cli integration tests.
//!
//! Rust integration tests under `tests/*.rs` are each their own
//! crate, so they can't import private items from `mikebom-cli/src/`
//! and they can't directly share code with each other. The standard
//! pattern is to put shared definitions in `tests/common/mod.rs` and
//! pull them into each test file via `mod common;`. The `mod.rs`
//! suffix matters: a `tests/common.rs` would be treated as its own
//! test target by cargo (and emit "no tests" warnings); the
//! `mod.rs` form is silently consumed only by the files that
//! `mod common;` it.
//!
//! What lives here:
//!
//! * [`EcosystemCase`] + [`CASES`] — the canonical 9-ecosystem
//!   matrix exercised by every cross-format parity / regression /
//!   schema-validation test (apk, cargo, deb, gem, golang, maven,
//!   npm, pip, rpm). Before this module, every consumer redefined
//!   the same struct + 9-element array. Adding a new ecosystem
//!   (or changing a fixture path) used to require touching 14
//!   files; now it's one place.
//!
//! * [`bin`] — the path to the `mikebom` binary built by cargo's
//!   integration-test machinery. Before this module, ~10 files
//!   had a private `fn bin() -> &'static str { env!("CARGO_BIN_EXE_mikebom") }`.
//!
//! * [`workspace_root`] — the absolute path to the workspace root
//!   (the parent of `mikebom-cli/`). Used by tests that need to
//!   locate `tests/fixtures/` from the workspace root rather than
//!   from the test crate's own `CARGO_MANIFEST_DIR`. Before this
//!   module, 21 files carried byte-identical copies.
//!
//! Tests that don't need either helper don't need `mod common;`.
//! Tests that need only one of the three still cost nothing: the
//! `#[allow(dead_code)]` annotations below silence the per-test-file
//! "this item is unused" warnings that would otherwise fire when
//! a test imports `common` but uses (e.g.) only `bin()`.

#![allow(dead_code)]

use std::path::PathBuf;

/// One row of the cross-format-test fixture matrix. `label` names
/// the golden file or test report; `fixture_subpath` is appended to
/// the workspace `tests/fixtures/` directory; `deb_codename`, when
/// present, is passed via `--deb-codename` to keep PURL `distro=`
/// qualifiers stable across machines that may auto-detect something
/// different.
#[derive(Clone, Copy)]
pub struct EcosystemCase {
    pub label: &'static str,
    pub fixture_subpath: &'static str,
    pub deb_codename: Option<&'static str>,
}

/// The canonical 9-ecosystem fixture matrix. Order is alphabetical
/// by `label` and is byte-stable across all consumers — adding,
/// reordering, or removing entries is a breaking change for every
/// test that iterates `CASES` and produces per-index goldens.
pub const CASES: &[EcosystemCase] = &[
    EcosystemCase { label: "apk",    fixture_subpath: "apk/synthetic",         deb_codename: None },
    EcosystemCase { label: "cargo",  fixture_subpath: "cargo/lockfile-v3",     deb_codename: None },
    EcosystemCase { label: "deb",    fixture_subpath: "deb/synthetic",         deb_codename: Some("bookworm") },
    EcosystemCase { label: "gem",    fixture_subpath: "gem/simple-bundle",     deb_codename: None },
    EcosystemCase { label: "golang", fixture_subpath: "go/simple-module",      deb_codename: None },
    EcosystemCase { label: "maven",  fixture_subpath: "maven/pom-three-deps",  deb_codename: None },
    EcosystemCase { label: "npm",    fixture_subpath: "npm/node-modules-walk", deb_codename: None },
    EcosystemCase { label: "pip",    fixture_subpath: "python/simple-venv",    deb_codename: None },
    EcosystemCase { label: "rpm",    fixture_subpath: "rpm/bdb-only",          deb_codename: None },
];

/// Path to the `mikebom` binary built by cargo's integration-test
/// machinery. Tests use this to spawn the CLI as a subprocess —
/// `Command::new(common::bin())`.
pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mikebom")
}

/// Absolute path to the workspace root — the parent of
/// `mikebom-cli/`, where `tests/fixtures/` lives. Tests that need to
/// locate fixtures, goldens, or sibling crates start here.
///
/// `CARGO_MANIFEST_DIR` for an integration test resolves to the
/// containing crate's manifest dir (`mikebom-cli/`); the workspace
/// root is one level up. The `.parent()` lookup is infallible for any
/// crate that lives in a workspace; tests panicking here would mean a
/// truly broken cargo invocation.
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}
