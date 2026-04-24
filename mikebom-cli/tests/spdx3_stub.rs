//! SPDX 3.0.1 experimental stub — schema + opt-off tests
//! (milestone 010 T040 + T041).
//!
//! T040: the stub emits a JSON-LD document that validates clean
//! against the vendored SPDX 3.0.1 schema for the npm fixture.
//! T041: when `spdx-3-json-experimental` is NOT requested, no
//! `mikebom.spdx3-experimental.json` file is produced AND the CDX
//! output matches the Phase-2 pinned golden (i.e., behavior is
//! byte-identical to a build without the stub).

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/schemas/spdx-3.0.1.json")
}

/// Compile-once SPDX 3.0.1 validator. Same pattern as
/// `spdx_schema_validation.rs::validator` for 2.3.
fn validator() -> &'static jsonschema::Validator {
    static CELL: OnceLock<jsonschema::Validator> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw = std::fs::read_to_string(schema_path())
            .expect("read vendored SPDX 3.0.1 schema");
        let schema: serde_json::Value =
            serde_json::from_str(&raw).expect("parse schema");
        jsonschema::validator_for(&schema).expect("compile SPDX 3.0.1 schema")
    })
}

/// Public validation helper — returns the set of validator keyword
/// categories that fired. Empty set = clean validation. Mirrors
/// `spdx_schema_validation.rs::validate_spdx_2_3`.
pub fn validate_spdx_3_0_1(
    doc: &serde_json::Value,
) -> std::collections::BTreeSet<String> {
    validator()
        .iter_errors(doc)
        .map(|e| e.kind().keyword().to_string())
        .collect()
}

fn run_scan(format: &str) -> (tempfile::TempDir, PathBuf) {
    let fx = workspace_root().join("tests/fixtures/npm/node-modules-walk");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let out_path = tmp.path().join("out.json");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let output = Command::new(bin)
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
        .arg(&fx)
        .arg("--format")
        .arg(format)
        .arg("--output")
        .arg(format!("{}={}", format, out_path.to_string_lossy()))
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom runs");
    assert!(
        output.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    (tmp, out_path)
}

// ---------- T040: schema validation --------------------------------

#[test]
fn spdx3_stub_on_npm_fixture_validates_clean() {
    let (_guard, out) = run_scan("spdx-3-json-experimental");
    let raw = std::fs::read_to_string(&out).expect("read produced SPDX 3");
    let doc: serde_json::Value =
        serde_json::from_str(&raw).expect("SPDX 3 is valid JSON");
    let categories = validate_spdx_3_0_1(&doc);
    assert!(
        categories.is_empty(),
        "SPDX 3.0.1 stub produced validator categories: {:?}\nfirst 2000 chars of document:\n{}",
        categories,
        &raw[..raw.len().min(2000)]
    );
}

#[test]
fn spdx3_alias_bytes_are_byte_identical_to_stable_identifier() {
    // Per research.md §R6 / contract §4: milestone-011 drops the
    // experimental marker injection; the alias delegates verbatim
    // to the stable emitter. Verifies the byte-identity contract
    // at the document level (full bytes are tested in
    // spdx3_us3_acceptance.rs).
    let (_guard_a, out_a) = run_scan("spdx-3-json-experimental");
    let (_guard_b, out_b) = run_scan("spdx-3-json");
    let bytes_a = std::fs::read_to_string(&out_a).expect("alias output");
    let bytes_b = std::fs::read_to_string(&out_b).expect("stable output");
    assert_eq!(
        bytes_a, bytes_b,
        "alias `spdx-3-json-experimental` and stable `spdx-3-json` \
         must emit byte-identical output per research.md §R6"
    );
}

// ---------- T041: opt-off → no SPDX 3 output -----------------------

#[test]
fn cdx_only_scan_produces_no_spdx3_file() {
    let fx = workspace_root().join("tests/fixtures/npm/node-modules-walk");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let output = Command::new(bin)
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
        .arg(&fx)
        .arg("--format")
        .arg("cyclonedx-json")
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom runs");
    assert!(output.status.success());
    // No SPDX 3 file, and no SPDX 2.3 either (user asked for CDX only).
    // The milestone-010 default filename was
    // `mikebom.spdx3-experimental.json`; milestone 011 changed it to
    // `mikebom.spdx3.json`. Check both so a future user on an older
    // tag sees a clean assertion either way.
    assert!(
        !tmp.path().join("mikebom.spdx3-experimental.json").exists(),
        "no SPDX 3 experimental-default-named file should exist when \
         the format wasn't requested"
    );
    assert!(
        !tmp.path().join("mikebom.spdx3.json").exists(),
        "no SPDX 3 stable-default-named file should exist when the \
         format wasn't requested"
    );
    assert!(
        !tmp.path().join("mikebom.spdx.json").exists(),
        "no SPDX 2.3 file should exist when the format wasn't requested"
    );
    assert!(
        tmp.path().join("mikebom.cdx.json").exists(),
        "CDX output must be present at the default filename"
    );
}

#[test]
fn spdx3_stub_is_deterministic_across_runs() {
    // SC-007 parallel for SPDX 3 — mirror
    // spdx_determinism.rs::cargo_scan_is_deterministic. Two runs
    // of the same scan, same-masked output, byte-identical.
    let (_g1, out1) = run_scan("spdx-3-json-experimental");
    let (_g2, out2) = run_scan("spdx-3-json-experimental");
    let a: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out1).unwrap()).unwrap();
    let b: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out2).unwrap()).unwrap();
    // CreationInfo.created is the one wall-clock field. Mask it on
    // both sides.
    fn mask(d: &mut serde_json::Value) {
        let Some(graph) = d.get_mut("@graph").and_then(|v| v.as_array_mut()) else {
            return;
        };
        for e in graph {
            if e.get("type") == Some(&serde_json::Value::String("CreationInfo".into())) {
                if let Some(ci) = e.as_object_mut() {
                    ci.insert("created".to_string(),
                              serde_json::Value::String("MASKED".into()));
                }
            }
        }
    }
    let mut ma = a.clone();
    let mut mb = b.clone();
    mask(&mut ma);
    mask(&mut mb);
    assert_eq!(
        serde_json::to_string_pretty(&ma).unwrap(),
        serde_json::to_string_pretty(&mb).unwrap(),
        "SPDX 3 stub output drifted between two identical scans"
    );
}
