//! Integration tests for the Cargo ecosystem (milestone 003 US4).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures/cargo")
        .join(sub)
}

fn run_scan(path: &Path) -> Output {
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    Command::new(bin)
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(path)
        .arg("--output")
        .arg(tmp.path())
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom should run")
}

fn run_scan_with_output(path: &Path) -> (Output, tempfile::TempDir, PathBuf) {
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_path = tmp.path().join("sbom.cdx.json");
    let output = Command::new(bin)
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(path)
        .arg("--output")
        .arg(&out_path)
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom should run");
    (output, tmp, out_path)
}

fn cargo_purls(sbom_path: &Path) -> Vec<String> {
    let raw = std::fs::read_to_string(sbom_path).expect("read sbom");
    let sbom: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    sbom["components"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .filter_map(|c| {
            let p = c["purl"].as_str()?;
            if p.starts_with("pkg:cargo/") {
                Some(p.to_string())
            } else {
                None
            }
        })
        .collect()
}

// --- T069: v3 + v4 conformant SBOMs -----------------------------------

#[test]
fn scan_cargo_v3_fixture_emits_conformant_sbom() {
    let (output, _tmp, sbom_path) = run_scan_with_output(&fixture("lockfile-v3"));
    assert!(
        output.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let purls = cargo_purls(&sbom_path);
    assert!(
        purls.len() >= 6,
        "expected ≥6 cargo components from v3 fixture, got {}: {purls:?}",
        purls.len(),
    );
    // Registry crate must be present.
    assert!(purls.iter().any(|p| p.starts_with("pkg:cargo/serde@")));
    // Git-sourced crate must be present.
    assert!(purls.iter().any(|p| p.starts_with("pkg:cargo/my-fork@")));
}

#[test]
fn scan_cargo_v4_fixture_emits_conformant_sbom() {
    let (output, _tmp, sbom_path) = run_scan_with_output(&fixture("lockfile-v4"));
    assert!(
        output.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let purls = cargo_purls(&sbom_path);
    assert!(
        purls.iter().any(|p| p.starts_with("pkg:cargo/anyhow@")),
        "anyhow missing from v4 scan: {purls:?}",
    );
}

#[test]
fn scan_cargo_v3_git_source_carries_source_type_property() {
    let (_output, _tmp, sbom_path) = run_scan_with_output(&fixture("lockfile-v3"));
    let raw = std::fs::read_to_string(&sbom_path).expect("read sbom");
    let sbom: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    let my_fork = sbom["components"]
        .as_array()
        .expect("components array")
        .iter()
        .find(|c| {
            c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with("pkg:cargo/my-fork@"))
        })
        .expect("my-fork component present");
    let props = my_fork["properties"]
        .as_array()
        .expect("properties array");
    let source_type = props
        .iter()
        .find(|p| p["name"].as_str() == Some("mikebom:source-type"))
        .expect("mikebom:source-type property present")
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(source_type, "git");
}

// --- T070: v1 / v2 refusal --------------------------------------------

#[test]
fn scan_cargo_v1_lockfile_refuses_with_actionable_error() {
    let output = run_scan(&fixture("lockfile-v1-refused"));
    assert!(
        !output.status.success(),
        "v1 lockfile scan should exit non-zero, got status {}",
        output.status,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Cargo.lock v1/v2 not supported"),
        "stderr missing refusal message: {stderr}",
    );
    assert!(
        stderr.contains("cargo ≥1.53"),
        "stderr missing remediation hint: {stderr}",
    );
}

#[test]
fn scan_cargo_v2_lockfile_refuses_with_actionable_error() {
    let output = run_scan(&fixture("lockfile-v2-refused"));
    assert!(
        !output.status.success(),
        "v2 lockfile scan should exit non-zero, got status {}",
        output.status,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Cargo.lock v1/v2 not supported"),
        "stderr missing refusal message: {stderr}",
    );
}
