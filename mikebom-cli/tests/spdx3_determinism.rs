//! SPDX 3 byte-determinism (milestone 011 T010).
//!
//! FR-015 / SC-006: Two runs of the same scan against the same
//! input MUST produce byte-identical SPDX 3 output after the
//! run-scoped document IRI and creation timestamp are normalized.
//!
//! This test invokes `mikebom sbom scan --format spdx-3-json`
//! twice against one fixture, parses both documents, strips the
//! timestamp + IRI-hash variance, and asserts byte-equality of the
//! remaining JSON. The SPDX 3 path uses a content-derived document
//! IRI (SHA-256 over target-name + version + sorted PURL list) so
//! two runs against the same scan input hit the same IRI — no
//! normalization needed in practice, but stripping the timestamp
//! handles any `OutputConfig.created` variance that could creep in.

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn run_scan(fixture_rel: &str) -> serde_json::Value {
    let fixture = workspace_root().join("tests/fixtures").join(fixture_rel);
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home");
    let out_path = tmp.path().join("out.spdx3.json");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let mut cmd = Command::new(bin);
    let out = cmd
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
        .arg("spdx-3-json")
        .arg("--output")
        .arg(format!("spdx-3-json={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom runs");
    assert!(
        out.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
        .expect("SPDX 3 output parses")
}

/// Strip the one field that is legitimately run-scoped: the
/// `created` timestamp on `CreationInfo`. Document IRI is
/// content-derived and stable across runs; no stripping needed
/// there.
fn normalize(mut doc: serde_json::Value) -> serde_json::Value {
    if let Some(graph) = doc.get_mut("@graph").and_then(|v| v.as_array_mut()) {
        for el in graph {
            if el.get("type").and_then(|v| v.as_str()) == Some("CreationInfo") {
                if let Some(obj) = el.as_object_mut() {
                    obj.insert(
                        "created".to_string(),
                        serde_json::Value::String("<NORMALIZED>".to_string()),
                    );
                }
            }
        }
    }
    doc
}

#[test]
fn two_runs_against_npm_fixture_are_byte_identical() {
    let a = normalize(run_scan("npm/node-modules-walk"));
    let b = normalize(run_scan("npm/node-modules-walk"));
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap(),
        "two SPDX 3 scans of the same input must be byte-identical after normalizing CreationInfo.created"
    );
}

#[test]
fn two_runs_against_cargo_fixture_are_byte_identical() {
    let a = normalize(run_scan("cargo/lockfile-v3"));
    let b = normalize(run_scan("cargo/lockfile-v3"));
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap(),
        "two SPDX 3 scans of the same input must be byte-identical after normalizing CreationInfo.created"
    );
}

#[test]
fn two_runs_against_deb_fixture_are_byte_identical() {
    // Multi-ecosystem case — deb scans with --deb-codename
    // exercise the deb dpkg-status reader path, which is the
    // highest-churn parser in the scan pipeline.
    let fixture = workspace_root().join("tests/fixtures/deb/synthetic");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home");
    let out_a = tmp.path().join("a.spdx3.json");
    let out_b = tmp.path().join("b.spdx3.json");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    for out_path in [&out_a, &out_b] {
        let st = Command::new(bin)
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
            .arg("spdx-3-json")
            .arg("--output")
            .arg(format!("spdx-3-json={}", out_path.to_string_lossy()))
            .arg("--no-deep-hash")
            .arg("--deb-codename")
            .arg("bookworm")
            .status()
            .expect("mikebom runs");
        assert!(st.success());
    }
    let a: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_a).unwrap()).unwrap();
    let b: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_b).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_string(&normalize(a)).unwrap(),
        serde_json::to_string(&normalize(b)).unwrap(),
        "two deb-fixture scans must be byte-identical"
    );
}
