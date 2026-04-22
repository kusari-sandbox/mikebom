//! Integration tests for `mikebom sbom enrich` — feature 006 US5.

#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::path::Path;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mikebom")
}

fn sample_sbom() -> serde_json::Value {
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "library", "name": "alpha", "version": "1.0.0"},
            {"type": "library", "name": "beta", "version": "2.0.0"}
        ]
    })
}

fn write(path: &Path, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
}

#[test]
fn adds_supplier_to_component() {
    let tmp = tempfile::tempdir().unwrap();
    let sbom_path = tmp.path().join("sbom.cdx.json");
    let patch_path = tmp.path().join("add-supplier.patch.json");
    write(&sbom_path, &sample_sbom());
    write(
        &patch_path,
        &serde_json::json!([
            {"op": "add", "path": "/components/0/supplier", "value": {"name": "Example Corp"}}
        ]),
    );

    let out = Command::new(bin())
        .args([
            "sbom",
            "enrich",
            sbom_path.to_str().unwrap(),
            "--patch",
            patch_path.to_str().unwrap(),
            "--author",
            "security-team@example.com",
        ])
        .output()
        .expect("sbom enrich should run");
    assert!(
        out.status.success(),
        "enrich failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let result: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sbom_path).unwrap()).unwrap();
    assert_eq!(
        result["components"][0]["supplier"]["name"],
        serde_json::json!("Example Corp")
    );
    // Provenance property group present.
    let props = result["properties"].as_array().unwrap();
    assert_eq!(props.len(), 1);
    assert_eq!(
        props[0]["name"],
        serde_json::json!("mikebom:enrichment-patch[0]")
    );
    let value_str = props[0]["value"].as_str().unwrap();
    assert!(value_str.contains("security-team@example.com"));
}

#[test]
fn multiple_patches_apply_in_order() {
    let tmp = tempfile::tempdir().unwrap();
    let sbom_path = tmp.path().join("sbom.cdx.json");
    let p1 = tmp.path().join("p1.json");
    let p2 = tmp.path().join("p2.json");
    write(&sbom_path, &sample_sbom());
    write(
        &p1,
        &serde_json::json!([
            {"op": "add", "path": "/components/0/supplier", "value": {"name": "First"}}
        ]),
    );
    write(
        &p2,
        &serde_json::json!([
            {"op": "add", "path": "/components/0/supplier/contact", "value": "ops@example.com"}
        ]),
    );

    let out = Command::new(bin())
        .args([
            "sbom",
            "enrich",
            sbom_path.to_str().unwrap(),
            "--patch",
            p1.to_str().unwrap(),
            "--patch",
            p2.to_str().unwrap(),
            "--author",
            "alice",
        ])
        .output()
        .expect("sbom enrich should run");
    assert!(
        out.status.success(),
        "multi-patch enrich failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let result: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sbom_path).unwrap()).unwrap();
    assert_eq!(
        result["components"][0]["supplier"]["name"],
        serde_json::json!("First")
    );
    assert_eq!(
        result["components"][0]["supplier"]["contact"],
        serde_json::json!("ops@example.com")
    );
    assert_eq!(result["properties"].as_array().unwrap().len(), 2);
}

#[test]
fn base_attestation_sha256_embedded_in_provenance() {
    let tmp = tempfile::tempdir().unwrap();
    let sbom_path = tmp.path().join("sbom.cdx.json");
    let patch_path = tmp.path().join("patch.json");
    let attest_path = tmp.path().join("attest.json");
    write(&sbom_path, &sample_sbom());
    write(
        &patch_path,
        &serde_json::json!([
            {"op": "add", "path": "/metadata", "value": {"enriched": true}}
        ]),
    );
    std::fs::write(&attest_path, b"attestation-bytes").unwrap();

    let out = Command::new(bin())
        .args([
            "sbom",
            "enrich",
            sbom_path.to_str().unwrap(),
            "--patch",
            patch_path.to_str().unwrap(),
            "--author",
            "bob",
            "--base-attestation",
            attest_path.to_str().unwrap(),
        ])
        .output()
        .expect("sbom enrich should run");
    assert!(out.status.success());

    let result: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sbom_path).unwrap()).unwrap();
    let props = result["properties"].as_array().unwrap();
    let value_str = props[0]["value"].as_str().unwrap();
    // Compute expected SHA-256 of "attestation-bytes".
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"attestation-bytes");
    let expected: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
    assert!(
        value_str.contains(&expected),
        "expected sha-256 {expected} in property value; got {value_str}"
    );
}

#[test]
fn missing_patch_flag_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let sbom_path = tmp.path().join("sbom.cdx.json");
    write(&sbom_path, &sample_sbom());

    let out = Command::new(bin())
        .args(["sbom", "enrich", sbom_path.to_str().unwrap()])
        .output()
        .expect("sbom enrich should run");
    assert!(!out.status.success(), "missing --patch should fail");
}

#[test]
fn invalid_patch_path_errors_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let sbom_path = tmp.path().join("sbom.cdx.json");
    let bad_patch = tmp.path().join("nonexistent.patch.json");
    write(&sbom_path, &sample_sbom());

    let out = Command::new(bin())
        .args([
            "sbom",
            "enrich",
            sbom_path.to_str().unwrap(),
            "--patch",
            bad_patch.to_str().unwrap(),
        ])
        .output()
        .expect("sbom enrich should run");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot read patch") || stderr.contains("No such file"));
}
