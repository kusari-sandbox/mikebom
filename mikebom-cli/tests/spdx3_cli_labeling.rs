//! SPDX 3 CLI-surface labeling tests.
//!
//! Scoped across milestone 010 → milestone 011 Phase 3 → US3:
//!
//!   * Milestone 010 (the experimental stub): `--help` text marks
//!     `spdx-3-json-experimental` with `[EXPERIMENTAL]`. Typo
//!     `spdx-3-json` (no suffix) rejected with a "did you mean"
//!     hint. All three assertions live here.
//!   * Milestone 011 Phase 3 (this state): `spdx-3-json` is now a
//!     first-class identifier, routing through the
//!     full-ecosystem-coverage emitter, still labeled
//!     `[EXPERIMENTAL]` pending US3's flip. `spdx-3-json-experimental`
//!     is the deprecated alias, also labeled `[EXPERIMENTAL]`.
//!     "Did you mean" test is retired (the typo is no longer a
//!     typo).
//!   * Milestone 011 US3 (T027 rewrites this file): stable
//!     identifier loses `[EXPERIMENTAL]` in help; alias gets
//!     `[DEPRECATED]` instead.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mikebom")
}

#[test]
fn help_text_labels_spdx_3_as_experimental() {
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
        "--help text should mention the spdx-3-json format id, got:\n{stdout}"
    );
    assert!(
        stdout.contains("spdx-3-json-experimental"),
        "--help text should still mention the deprecated alias, got:\n{stdout}"
    );
    assert!(
        stdout.contains("[EXPERIMENTAL"),
        "--help text should label the SPDX 3 entries as [EXPERIMENTAL] (during milestone-011 Phase 3 both identifiers carry the label; US3 T029 retires it for the stable one), got:\n{stdout}"
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
}

#[test]
fn unknown_format_error_includes_experimental_label_in_known_list() {
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
    // The error lists every registered id; SPDX 3 entries should
    // carry their label so the reader sees what's stable vs not
    // when picking from the list.
    assert!(
        stderr.contains("spdx-3-json-experimental [EXPERIMENTAL]"),
        "unknown-format error's known-id list should label experimental \
         formats, got:\n{stderr}"
    );
}
