//! End-to-end test for `mikebom sbom parity-check` (milestone
//! 013 US3 / T018).
//!
//! Three scenarios cover the documented exit-code semantics
//! (0 / 1 / 2) and the two output formats (table / json).
//!
//! Each scenario shells out via `Command::new(CARGO_BIN_EXE_mikebom)`
//! against a fresh tempdir; HOME / package-cache env vars are
//! isolated per the cross-host-goldens convention.

use std::path::PathBuf;
use std::process::Command;


mod common;
use common::bin;
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}


/// Produce the three format outputs for the npm fixture into
/// `<dir>/mikebom.cdx.json` etc.
fn scan_into(dir: &std::path::Path) {
    let fixture = workspace_root().join("tests/fixtures/npm/node-modules-walk");
    let fake_home = tempfile::tempdir().expect("fake-home");
    let cdx = dir.join("mikebom.cdx.json");
    let spdx23 = dir.join("mikebom.spdx.json");
    let spdx3 = dir.join("mikebom.spdx3.json");
    let out = Command::new(bin())
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
        .arg(&fixture)
        .arg("--format")
        .arg("cyclonedx-json,spdx-2.3-json,spdx-3-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", cdx.to_string_lossy()))
        .arg("--output")
        .arg(format!("spdx-2.3-json={}", spdx23.to_string_lossy()))
        .arg("--output")
        .arg(format!("spdx-3-json={}", spdx3.to_string_lossy()))
        .arg("--no-deep-hash")
        .output()
        .expect("scan runs");
    assert!(
        out.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn parity_check_exit_code_zero_table_output() {
    let tmp = tempfile::tempdir().expect("tempdir");
    scan_into(tmp.path());

    let out = Command::new(bin())
        .current_dir(workspace_root())
        .arg("--offline")
        .arg("sbom")
        .arg("parity-check")
        .arg("--scan-dir")
        .arg(tmp.path())
        .output()
        .expect("parity-check runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "parity-check expected exit 0, got {:?}; stderr={stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("Section A"),
        "table output missing section header; stdout={stdout}"
    );
    assert!(
        stdout.contains("A1"),
        "table output missing row A1; stdout={stdout}"
    );
    assert!(
        stdout.contains("Universal-parity rows"),
        "table output missing summary footer; stdout={stdout}"
    );
}

#[test]
fn parity_check_exit_code_two_when_input_missing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    scan_into(tmp.path());
    // Delete one of the three files post-scan to provoke the
    // missing-input failure mode.
    std::fs::remove_file(tmp.path().join("mikebom.spdx3.json")).expect("remove spdx3 file");

    let out = Command::new(bin())
        .current_dir(workspace_root())
        .arg("--offline")
        .arg("sbom")
        .arg("parity-check")
        .arg("--scan-dir")
        .arg(tmp.path())
        .output()
        .expect("parity-check runs");
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 for missing input, got {:?}; stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found"),
        "expected 'not found' in stderr; got: {stderr}"
    );
}

#[test]
fn parity_check_json_output_is_parseable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    scan_into(tmp.path());

    let out = Command::new(bin())
        .current_dir(workspace_root())
        .arg("--offline")
        .arg("sbom")
        .arg("parity-check")
        .arg("--scan-dir")
        .arg(tmp.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("parity-check runs");
    assert!(
        out.status.success(),
        "parity-check --format json failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is parseable JSON");
    assert!(
        v.get("summary").is_some(),
        "missing summary field; got: {v}"
    );
    assert!(
        v.get("rows").and_then(|r| r.as_array()).is_some_and(|a| !a.is_empty()),
        "expected non-empty rows array; got: {v}"
    );
    let first_row = &v["rows"][0];
    assert!(
        first_row.get("row_id").is_some(),
        "row missing row_id; got: {first_row}"
    );
    assert!(
        first_row.get("cdx").is_some(),
        "row missing cdx; got: {first_row}"
    );
}
