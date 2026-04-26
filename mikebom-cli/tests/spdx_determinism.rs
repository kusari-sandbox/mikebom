//! SPDX 2.3 determinism regression (milestone 010 T016).
//!
//! FR-020 / SC-007 — two runs of the same scan must produce
//! byte-identical SPDX output after the canonical normalization
//! (`creationInfo.created` mask, `annotations[].annotationDate` mask,
//! `packages[].checksums[]` strip, workspace-path placeholder) is
//! applied. Every remaining field — `documentNamespace`, SPDXIDs,
//! package / relationship ordering — must match exactly.

use std::process::Command;

mod common;
use common::normalize::{apply_fake_home_env, normalize_spdx23_for_golden};
use common::workspace_root;

/// Run `mikebom sbom scan --format spdx-2.3-json` against `fixture`
/// in an isolated fake-HOME and return the produced raw JSON string.
/// Callers normalize via `normalize_spdx23_for_golden` (for byte
/// equality) or parse to `serde_json::Value` (for narrower
/// field-extraction assertions).
fn scan_to_spdx_raw(fixture: &std::path::Path) -> String {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let out = tmp.path().join("mikebom.spdx.json");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let mut cmd = Command::new(bin);
    apply_fake_home_env(&mut cmd, fake_home.path());
    let status = cmd
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture)
        .arg("--format")
        .arg("spdx-2.3-json")
        .arg("--output")
        .arg(format!("spdx-2.3-json={}", out.to_string_lossy()))
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom runs");
    assert!(
        status.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    std::fs::read_to_string(&out).expect("read SPDX output")
}

fn scan_to_spdx_json(fixture: &std::path::Path) -> serde_json::Value {
    let raw = scan_to_spdx_raw(fixture);
    serde_json::from_str(&raw).expect("SPDX output parses")
}

fn run_twice(subpath: &str) {
    let fixture = workspace_root().join("tests/fixtures").join(subpath);
    assert!(
        fixture.exists(),
        "fixture missing: {}",
        fixture.display()
    );
    let workspace = workspace_root();
    let a = normalize_spdx23_for_golden(&scan_to_spdx_raw(&fixture), &workspace);
    let b = normalize_spdx23_for_golden(&scan_to_spdx_raw(&fixture), &workspace);
    assert_eq!(
        a, b,
        "SPDX output differs between two identical scans (after the \
         canonical normalize_spdx23_for_golden masking) — determinism \
         contract violation"
    );
}

#[test]
fn cargo_scan_is_deterministic() {
    run_twice("cargo/lockfile-v3");
}

#[test]
fn npm_scan_is_deterministic() {
    run_twice("npm/node-modules-walk");
}

#[test]
fn deb_scan_is_deterministic() {
    run_twice("deb/synthetic");
}

#[test]
fn document_namespace_is_stable_across_runs() {
    // Narrower assertion: the SHA-256-derived `documentNamespace`
    // must match byte-for-byte between runs. This is the single
    // most-important determinism signal — if it drifts, every SBOM
    // consumer indexing by namespace is broken.
    let fixture = workspace_root().join("tests/fixtures/cargo/lockfile-v3");
    let a = scan_to_spdx_json(&fixture);
    let b = scan_to_spdx_json(&fixture);
    assert_eq!(a["documentNamespace"], b["documentNamespace"]);
}

#[test]
fn spdxids_are_stable_across_runs() {
    // Related determinism signal: the SPDXID set must match exactly.
    // Any drift here would break cross-run relationship references.
    let fixture = workspace_root().join("tests/fixtures/cargo/lockfile-v3");
    let a = scan_to_spdx_json(&fixture);
    let b = scan_to_spdx_json(&fixture);
    let ids_a: Vec<&str> = a["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["SPDXID"].as_str())
        .collect();
    let ids_b: Vec<&str> = b["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["SPDXID"].as_str())
        .collect();
    assert_eq!(ids_a, ids_b);
}
