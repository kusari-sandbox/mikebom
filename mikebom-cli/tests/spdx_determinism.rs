//! SPDX 2.3 determinism regression (milestone 010 T016).
//!
//! FR-020 / SC-007 — two runs of the same scan must produce
//! byte-identical SPDX output *except* for the
//! `creationInfo.created` timestamp, which the spec requires to
//! reflect when the document was generated. Within the test we feed
//! both runs the same scan and compare the produced files after
//! masking only `created`; every other field — `documentNamespace`,
//! SPDXIDs, package / relationship ordering — must match exactly.

use std::process::Command;

mod common;
use common::workspace_root;

fn scan_to_spdx_json(fixture: &std::path::Path) -> serde_json::Value {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("mikebom.spdx.json");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let status = Command::new(bin)
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
    serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap()
}

/// Clear the one field SPDX requires to vary per invocation
/// (`creationInfo.created` — wall-clock timestamp). Everything else
/// is deterministic by construction in our serializer.
fn mask_created(doc: &mut serde_json::Value) {
    if let Some(ci) = doc
        .as_object_mut()
        .and_then(|o| o.get_mut("creationInfo"))
        .and_then(|v| v.as_object_mut())
    {
        ci.insert(
            "created".to_string(),
            serde_json::Value::String("MASKED".to_string()),
        );
    }
}

fn run_twice(subpath: &str) {
    let fixture = workspace_root().join("tests/fixtures").join(subpath);
    assert!(
        fixture.exists(),
        "fixture missing: {}",
        fixture.display()
    );
    let mut a = scan_to_spdx_json(&fixture);
    let mut b = scan_to_spdx_json(&fixture);
    mask_created(&mut a);
    mask_created(&mut b);
    assert_eq!(
        serde_json::to_string_pretty(&a).unwrap(),
        serde_json::to_string_pretty(&b).unwrap(),
        "SPDX output differs between two identical scans (after masking \
         only creationInfo.created) — determinism contract violation"
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
