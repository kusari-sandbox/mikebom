//! Principle I regression test (milestone 003, T001).
//!
//! mikebom's constitution (Principle I) mandates zero C source files or
//! C-toolchain dependencies anywhere in the build pipeline. Historically,
//! the risk surface has been feature-flag-driven: adding a dependency
//! like `zip`, `flate2`, or `rusqlite` can silently pull in a C backend
//! via a default feature we didn't audit.
//!
//! This test shells out to `cargo tree` and asserts the dependency
//! graph contains none of the known C-backed crate names. If a future
//! `cargo update` or new-feature enablement introduces one of these,
//! CI fails here — before any reviewer has to read the full tree
//! diff in a PR.
//!
//! The blacklist is intentionally broad: any crate name containing
//! `libz`, `zlib`, `c-bindings`, or `libsqlite3` is forbidden.
//! Currently-clean state as of milestone 003:
//!   - `flate2` uses `miniz_oxide` (pure Rust) via its default
//!     `rust_backend` feature.
//!   - `zip` uses `deflate-miniz` (pinned explicitly in Cargo.toml)
//!     which routes through the same pure-Rust `flate2` backend.
//!   - `object` has no C deps in its default-features-off minimal
//!     configuration we use.
//!   - `quick-xml` is pure Rust.
//!
//! When this test fails:
//! 1. Run `cargo tree -p mikebom -e normal` locally.
//! 2. Identify which new crate triggered the match.
//! 3. Find the feature flag that pulled it in; either disable the
//!    feature or find a pure-Rust alternative.
//! 4. If no alternative exists, propose a constitution amendment
//!    before proceeding.

use std::process::Command;

const BLACKLIST: &[&str] = &[
    "libz-sys",
    "zlib-sys",
    "zlib-ng-sys",
    "libsqlite3-sys",
    "openssl-sys",
    "c-bindings",
];

#[test]
fn no_c_dependencies_in_tree() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let output = Command::new("cargo")
        .arg("tree")
        .arg("-p")
        .arg("mikebom")
        .arg("-e")
        .arg("normal")
        .current_dir(manifest_dir)
        .output()
        .expect("cargo tree should run");
    assert!(
        output.status.success(),
        "cargo tree failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    let matches: Vec<&str> = tree
        .lines()
        .filter(|line| {
            BLACKLIST.iter().any(|needle| line.contains(needle))
        })
        .collect();
    assert!(
        matches.is_empty(),
        "Principle I violation: C-backed crate found in dep tree:\n{}\n\
         Full blacklist: {:?}\n\
         See specs/003-multi-ecosystem-expansion/tasks.md T001 for the rationale.",
        matches.join("\n"),
        BLACKLIST,
    );
}
