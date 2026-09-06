//! Shared test helpers for waybill-cli integration tests.
//!
//! Rust integration tests under `tests/*.rs` are each their own
//! crate, so they can't import private items from `waybill-cli/src/`
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
//! * [`bin`] — the path to the `waybill` binary built by cargo's
//!   integration-test machinery. Before this module, ~10 files
//!   had a private `fn bin() -> &'static str { env!("CARGO_BIN_EXE_waybill") }`.
//!
//! * [`workspace_root`] — the absolute path to the workspace root
//!   (the parent of `waybill-cli/`). Used by tests that need to
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

pub mod cdx_schema;
pub mod normalize;

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

/// The canonical fixture matrix. Indices 0..=8 are the original 9
/// ecosystems in alphabetical order — this prefix is byte-stable
/// across all consumers because seven downstream tests hard-code
/// indices 0..=8 (cdx_regression, spdx_regression, spdx3_regression,
/// spdx_schema_validation, spdx3_schema_validation,
/// spdx_annotation_fidelity, spdx_cdx_parity, openvex_sidecar).
///
/// Indices 9+ are reserved for ecosystems added after milestone 010's
/// goldens shipped. Milestone 103 appends `bazel` (9) and `cmake` (10);
/// they live at the tail rather than alphabetical position to avoid
/// shifting every existing index. New entries MUST be appended only.
///
/// Reordering, inserting, or removing entries is a breaking change
/// for every index-based consumer above.
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
    // Milestone 103 — appended after original 9; see ordering note above.
    EcosystemCase { label: "bazel",  fixture_subpath: "bazel",                 deb_codename: None },
    EcosystemCase { label: "cmake",  fixture_subpath: "cmake",                 deb_codename: None },
];

/// Path to the `waybill` binary built by cargo's integration-test
/// machinery. Tests use this to spawn the CLI as a subprocess —
/// `Command::new(common::bin())`.
pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_waybill")
}

/// Absolute path to the workspace root — the parent of
/// `waybill-cli/`, where `tests/fixtures/` lives. Tests that need to
/// locate fixtures, goldens, or sibling crates start here.
///
/// `CARGO_MANIFEST_DIR` for an integration test resolves to the
/// containing crate's manifest dir (`waybill-cli/`); the workspace
/// root is one level up. The `.parent()` lookup is infallible for any
/// crate that lives in a workspace; tests panicking here would mean a
/// truly broken cargo invocation.
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

// ---------------------------------------------------------------------
// Milestone 090 — fixture-path helpers
// ---------------------------------------------------------------------
//
// The manifest-bearing fixtures (cargo / gem / go / maven / npm /
// polyglot-monorepo / python / transitive_parity / cargo-workspace /
// maven-multi-module-reactor / npm-scoped-package / npm-workspace /
// pip-pyproject-pep621 / pip-pyproject-poetry-only) live in the
// separate `waybill-test-fixtures` repo, fetched by `build.rs` into
// `~/.cache/waybill/fixtures/<sha>/`. The `WAYBILL_FIXTURES_DIR`
// compile-time env var (set by build.rs via cargo:rustc-env) holds
// the absolute path.
//
// The stay-set fixtures (apk/synthetic, deb/synthetic, rpm/*,
// binaries/*, bdb-rpmdb, gem-source-project, polyglot-rpm-binary,
// polyglot-five, reference/, sample-attestation.json, go/binaries/)
// live in waybill main repo at `tests/fixtures/<subpath>`. They have
// no source-language manifests and don't trigger SBOM scanners.
//
// See specs/090-split-test-fixtures-repo/contracts/fixture-path-helper.md.

/// Path to a moved fixture relative to the cloned `waybill-test-fixtures`
/// repo root. Resolves against `WAYBILL_FIXTURES_DIR` (set by build.rs).
///
/// Use this for: every manifest-bearing fixture per
/// `specs/090-split-test-fixtures-repo/research.md` §4 move-set.
pub fn fixture_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("WAYBILL_FIXTURES_DIR")).join(rel)
}

/// Path to a stay-set fixture relative to waybill main repo's
/// `tests/fixtures/` directory. Resolves against `workspace_root()`.
///
/// As of the post-103 migration the stay-set is narrow:
/// `sample-attestation.json`, plus the README-only placeholder dirs
/// (`binaries/`, `bdb-rpmdb/`, `polyglot-*/`, `rpm-files/`) that
/// will get real fixture bodies in future milestones. The
/// synthetic apk/deb/rpm trees + gem-source-project + the
/// build-manifest projects (conan/vcpkg/bazel/cmake) moved to the
/// sibling fixtures repo — use `fixture_path` for those.
pub fn local_fixture_path(rel: &str) -> PathBuf {
    workspace_root().join("tests").join("fixtures").join(rel)
}

/// Resolve an `EcosystemCase`'s fixture path. As of the post-103
/// fixture-migration PR, every CASES entry's fixture lives in the
/// sibling `waybill-test-fixtures` repo and resolves via
/// `fixture_path`. Earlier history had apk/deb/rpm at workspace-root
/// `tests/fixtures/` (milestone-090 stay-set) and bazel/cmake at
/// crate-local `waybill-cli/tests/fixtures/` (milestone-103
/// quick-implementation); both have been migrated out to keep the
/// main repo free of synthetic OS-image rpmdb data and full
/// build-manifest test projects.
pub fn case_fixture_path(case: &EcosystemCase) -> PathBuf {
    fixture_path(case.fixture_subpath)
}
