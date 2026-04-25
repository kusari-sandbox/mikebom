//! SPDX 2.3 JSON-schema validation (milestone 010 T014 + T015).
//!
//! FR-005 / SC-002 — produced SPDX 2.3 documents MUST validate clean
//! against the official SPDX 2.3 JSON schema, with only
//! "warning categories" (here: validator-keyword names) that the
//! SPDX project's own reference example `SPDXJSONExample-v2.3.spdx.json`
//! also produces under the same validator.
//!
//! The vendored reference is at
//! `mikebom-cli/tests/fixtures/reference/SPDXJSONExample-v2.3.spdx.json`
//! (downloaded in Phase 1 T056). It's not network-fetched at test
//! time — schema validation runs fully offline.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;


mod common;
use common::{workspace_root, EcosystemCase, CASES};

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/schemas/spdx-2.3.json")
}

fn reference_example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/reference/SPDXJSONExample-v2.3.spdx.json")
}

/// Shared validator instance. Compiling the SPDX 2.3 schema costs
/// several ms; amortizing across all 9 ecosystem tests keeps the
/// suite snappy. `OnceLock` gives us thread-safe lazy init.
fn validator() -> &'static jsonschema::Validator {
    static CELL: OnceLock<jsonschema::Validator> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw = std::fs::read_to_string(schema_path())
            .expect("read vendored SPDX 2.3 schema");
        let schema: serde_json::Value =
            serde_json::from_str(&raw).expect("parse schema");
        jsonschema::validator_for(&schema).expect("compile SPDX 2.3 schema")
    })
}

/// Validate an SPDX 2.3 document. Returns the set of distinct
/// validator keyword categories that fired (e.g. `"required"`,
/// `"pattern"`, `"type"`). Empty set = clean validation.
pub fn validate_spdx_2_3(doc: &serde_json::Value) -> std::collections::BTreeSet<String> {
    validator()
        .iter_errors(doc)
        .map(|e| e.kind().keyword().to_string())
        .collect()
}

/// Warning-baseline categories produced by validating the SPDX
/// reference example (`SPDXJSONExample-v2.3.spdx.json`) against the
/// same schema. Our produced documents' categories must be a subset
/// of this set — that's the "mikebom doesn't introduce new warning
/// categories beyond what the SPDX project's own reference produces"
/// rule from the spec.
fn reference_baseline_categories() -> &'static std::collections::BTreeSet<String> {
    static CELL: OnceLock<std::collections::BTreeSet<String>> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw = std::fs::read_to_string(reference_example_path())
            .expect("read vendored SPDX 2.3 reference example");
        let doc: serde_json::Value =
            serde_json::from_str(&raw).expect("parse reference example");
        validate_spdx_2_3(&doc)
    })
}/// Scan a fixture requesting SPDX 2.3 output, parse the result, and
/// return the parsed JSON for validation.
fn scan_to_spdx(case: &EcosystemCase) -> serde_json::Value {
    let fixture = workspace_root().join("tests/fixtures").join(case.fixture_subpath);
    assert!(
        fixture.exists(),
        "fixture missing for {}: {}",
        case.label,
        fixture.display()
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_path = tmp.path().join("mikebom.spdx.json");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let mut cmd = Command::new(bin);
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(&fixture)
        .arg("--format")
        .arg("spdx-2.3-json")
        .arg("--output")
        .arg(format!(
            "spdx-2.3-json={}",
            out_path.to_string_lossy()
        ))
        .arg("--no-deep-hash");
    if let Some(code) = case.deb_codename {
        cmd.arg("--deb-codename").arg(code);
    }
    let output = cmd.output().expect("mikebom should run");
    assert!(
        output.status.success(),
        "scan failed for {}: stderr={}",
        case.label,
        String::from_utf8_lossy(&output.stderr)
    );
    let raw = std::fs::read_to_string(&out_path).expect("read produced SPDX");
    serde_json::from_str(&raw).expect("produced SPDX is valid JSON")
}

fn assert_valid(case: &EcosystemCase) {
    let doc = scan_to_spdx(case);
    let categories = validate_spdx_2_3(&doc);
    let baseline = reference_baseline_categories();
    let introduced: Vec<&String> =
        categories.difference(baseline).collect();
    assert!(
        introduced.is_empty(),
        "SPDX 2.3 validation for {} introduced warning categories not present \
         in the SPDX reference example: {:?}. Reference baseline: {:?}",
        case.label,
        introduced,
        baseline
    );
}

/// Print the baseline once on first call to help debug.
#[test]
fn reference_example_baseline_probe() {
    let baseline = reference_baseline_categories();
    eprintln!(
        "SPDX 2.3 reference-example validator categories (baseline): {baseline:?}"
    );
    // No assertion — purely informational. Captures the baseline into
    // test output so a CI reader can see what the ceiling is.
}

#[test]
fn spdx_apk_validates() {
    assert_valid(&CASES[0]);
}

#[test]
fn spdx_cargo_validates() {
    assert_valid(&CASES[1]);
}

#[test]
fn spdx_deb_validates() {
    assert_valid(&CASES[2]);
}

#[test]
fn spdx_gem_validates() {
    assert_valid(&CASES[3]);
}

#[test]
fn spdx_golang_validates() {
    assert_valid(&CASES[4]);
}

#[test]
fn spdx_maven_validates() {
    assert_valid(&CASES[5]);
}

#[test]
fn spdx_npm_validates() {
    assert_valid(&CASES[6]);
}

#[test]
fn spdx_pip_validates() {
    assert_valid(&CASES[7]);
}

#[test]
fn spdx_rpm_validates() {
    assert_valid(&CASES[8]);
}

// Silence the unused-path-helper lint on some platforms.
#[allow(dead_code)]
fn _ensure_helpers_used(p: &Path) -> PathBuf {
    p.to_path_buf()
}
