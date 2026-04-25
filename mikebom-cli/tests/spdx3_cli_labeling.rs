//! SPDX 3 CLI-surface labeling tests (milestone 011 US3 / T027).
//!
//! Post-US3 state:
//!   * `spdx-3-json` appears in `--help` with **no** `[EXPERIMENTAL]`
//!     annotation — it's a first-class production format.
//!   * `spdx-3-json-experimental` still accepted but labeled
//!     `[DEPRECATED]` in the unknown-format-error known-id list
//!     (surface-level signal to pick a different id).
//!   * The bare `spdx-3-json` form is a valid registered identifier
//!     (regression guard for the milestone-010 typo-guard
//!     retirement).

use std::process::Command;



mod common;
use common::bin;
#[test]
fn help_text_lists_both_spdx_3_identifiers_without_experimental_label() {
    let output = Command::new(bin())
        .arg("sbom")
        .arg("scan")
        .arg("--help")
        .output()
        .expect("mikebom --help runs");
    assert!(output.status.success(), "sbom scan --help must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("spdx-3-json"),
        "--help text should mention the stable identifier, got:\n{stdout}"
    );
    assert!(
        stdout.contains("spdx-3-json-experimental"),
        "--help text should still mention the deprecated alias, got:\n{stdout}"
    );
    // [EXPERIMENTAL] must not appear in help — neither SPDX 3
    // identifier carries the label after US3 (research.md §R6).
    assert!(
        !stdout.contains("[EXPERIMENTAL"),
        "--help text must not carry [EXPERIMENTAL] after US3 flip; got:\n{stdout}"
    );
    // The deprecation signal is surfaced in the doc comment text.
    assert!(
        stdout.contains("DEPRECATED"),
        "--help text should mark the alias as deprecated; got:\n{stdout}"
    );
}

#[test]
fn spdx_3_json_is_a_first_class_format() {
    // Regression coverage for the milestone-010 typo-guard
    // retirement: `--format spdx-3-json` (no suffix) is now a
    // valid registered identifier, not a typo.
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let out_path = tmp.path().join("out.spdx3.json");
    let output = Command::new(bin())
        .current_dir(tmp.path())
        .env("HOME", fake_home.path())
        .env("M2_REPO", fake_home.path().join("no-m2-repo"))
        .env("MAVEN_HOME", fake_home.path().join("no-maven-home"))
        .env("GOPATH", fake_home.path().join("no-gopath"))
        .env("GOMODCACHE", fake_home.path().join("no-gomodcache"))
        .env("CARGO_HOME", fake_home.path().join("no-cargo-home"))
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("tests/fixtures/npm/node-modules-walk"),
        )
        .arg("--format")
        .arg("spdx-3-json")
        .arg("--output")
        .arg(format!("spdx-3-json={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom runs");
    assert!(
        output.status.success(),
        "spdx-3-json must be accepted as a first-class format; stderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        out_path.exists(),
        "spdx-3-json invocation should have written {}",
        out_path.display()
    );
    // No stderr deprecation notice when invoking the stable id.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("deprecated"),
        "stable identifier must not emit a deprecation notice; stderr=\n{stderr}"
    );
}

#[test]
fn unknown_format_error_labels_alias_as_deprecated_in_known_list() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let output = Command::new(bin())
        .current_dir(tmp.path())
        .env("HOME", fake_home.path())
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("tests/fixtures/npm/node-modules-walk"),
        )
        .arg("--format")
        .arg("not-a-format")
        .output()
        .expect("mikebom runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Post-US3: the unknown-format-error known-id list labels the
    // alias `[DEPRECATED]` instead of `[EXPERIMENTAL]`. The stable
    // `spdx-3-json` carries no label.
    assert!(
        stderr.contains("spdx-3-json-experimental [DEPRECATED]"),
        "unknown-format error should label the alias as deprecated, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("spdx-3-json-experimental [EXPERIMENTAL]"),
        "US3 retired the [EXPERIMENTAL] label on the alias, got:\n{stderr}"
    );
}
