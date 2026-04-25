//! SPDX 3.0.1 JSON-Schema validation (milestone 011 T007 + T008).
//!
//! FR-016 / SC-002 — every SPDX 3 document mikebom emits MUST
//! validate against the bundled SPDX 3.0.1 JSON-Schema with zero
//! errors. Schema is sourced from
//! https://spdx.org/schema/3.0.1/spdx-json-schema.json (SHA-256
//! `582c64e809d5b3ef9bd0c4de13a32391b47b0284a3e8d199569fb96f649234b1`,
//! fetched 2026-04-24) and bundled at
//! `mikebom-cli/tests/fixtures/schemas/spdx-3.0.1.json` so the
//! test runs fully offline (research.md §R1).
//!
//! One `#[test]` per ecosystem (9 total). A failure names the
//! offending ecosystem so the developer doesn't have to grep
//! through a single mega-test.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;


mod common;
use common::{workspace_root, EcosystemCase, CASES};

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/schemas/spdx-3.0.1.json")
}

/// Shared validator instance — compiling the SPDX 3.0.1 schema
/// is non-trivial (260 KB + cross-references) so we amortize the
/// cost across every per-ecosystem test via `OnceLock`.
fn validator() -> &'static jsonschema::Validator {
    static CELL: OnceLock<jsonschema::Validator> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw = std::fs::read_to_string(schema_path())
            .expect("read bundled SPDX 3.0.1 schema");
        let schema: serde_json::Value =
            serde_json::from_str(&raw).expect("parse SPDX 3.0.1 schema");
        jsonschema::validator_for(&schema).expect("compile SPDX 3.0.1 schema")
    })
}/// Run a `mikebom sbom scan --format spdx-3-json` against `fixture`
/// and return the parsed JSON document. Sandboxes HOME and the
/// per-ecosystem cache envs so per-host installed packages don't
/// leak into the document (cross-host byte-identity rules from
/// `feedback_cross_host_goldens.md`).
fn scan_to_spdx3(case: &EcosystemCase) -> serde_json::Value {
    let fixture = workspace_root().join("tests/fixtures").join(case.fixture_subpath);
    assert!(
        fixture.exists(),
        "fixture missing for {}: {}",
        case.label,
        fixture.display()
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let out_path = tmp.path().join("out.spdx3.json");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let mut cmd = Command::new(bin);
    cmd.env("HOME", fake_home.path())
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
        .arg("--no-deep-hash");
    if let Some(code) = case.deb_codename {
        cmd.arg("--deb-codename").arg(code);
    }
    let out = cmd.output().expect("mikebom runs");
    assert!(
        out.status.success(),
        "scan failed for {}: stderr={}",
        case.label,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap())
        .expect("emitted SPDX 3 is valid JSON")
}

fn validate(case: &EcosystemCase) {
    let doc = scan_to_spdx3(case);
    let errors: Vec<String> = validator()
        .iter_errors(&doc)
        .map(|e| format!("{} (path={})", e, e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "{}: SPDX 3.0.1 schema validation reported {} error(s):\n{}",
        case.label,
        errors.len(),
        errors.join("\n")
    );
}

#[test]
fn schema_loader_compiles() {
    let _ = validator();
}

#[test]
fn validates_apk() {
    validate(&CASES[0]);
}

#[test]
fn validates_cargo() {
    validate(&CASES[1]);
}

#[test]
fn validates_deb() {
    validate(&CASES[2]);
}

#[test]
fn validates_gem() {
    validate(&CASES[3]);
}

#[test]
fn validates_golang() {
    validate(&CASES[4]);
}

#[test]
fn validates_maven() {
    validate(&CASES[5]);
}

#[test]
fn validates_npm() {
    validate(&CASES[6]);
}

#[test]
fn validates_pip() {
    validate(&CASES[7]);
}

#[test]
fn validates_rpm() {
    validate(&CASES[8]);
}
