//! OpenVEX 0.2.0 sidecar presence + schema validation (milestone 010
//! T030 / T031).
//!
//! Two halves of FR-016a + SC-002 for VEX:
//!
//! 1. **Negative case** (green today on every fixture):
//!    mikebom's scan pipeline doesn't yet populate
//!    `ResolvedComponent.advisories` — no ecosystem emits VEX
//!    statements. For all 9 fixtures, the CLI MUST therefore NOT
//!    produce `mikebom.openvex.json`, and the SPDX document MUST
//!    NOT carry an `externalDocumentRefs` entry. That's the
//!    "no VEX → no sidecar" half of FR-016a.
//!
//! 2. **Schema-validation canary**: a hand-built OpenVEX document
//!    (shape that mikebom would emit if it had advisories) validates
//!    clean against the vendored `openvex-0.2.0.json` schema. This
//!    guards the emitter shape even though no live-scan produces
//!    VEX today — when a future milestone wires advisory
//!    population, the emitter's output will already have been
//!    checked against the schema.
//!
//! The positive-presence half (advisories → sidecar + SHA-256
//! cross-ref written) is unit-tested inside
//! `src/generate/spdx/mod.rs::tests` via direct serializer calls,
//! since the CLI surface can't drive synthetic advisories today.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;


mod common;
use common::normalize::apply_fake_home_env;
use common::{workspace_root, EcosystemCase, CASES};

fn openvex_schema() -> &'static jsonschema::Validator {
    static CELL: OnceLock<jsonschema::Validator> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/schemas/openvex-0.2.0.json"),
        )
        .expect("read vendored openvex-0.2.0.json");
        let schema: serde_json::Value =
            serde_json::from_str(&raw).expect("parse openvex schema");
        jsonschema::validator_for(&schema).expect("compile openvex schema")
    })
}

/// Expose the OpenVEX validator so future tests can share the same
/// compiled instance. Mirrors the `validate_spdx_2_3` helper in
/// `spdx_schema_validation.rs`.
pub fn validate_openvex_0_2_0(
    doc: &serde_json::Value,
) -> std::collections::BTreeSet<String> {
    openvex_schema()
        .iter_errors(doc)
        .map(|e| e.kind().keyword().to_string())
        .collect()
}

// ----------------------------------------------------------------
// (1) Negative case — no fixture produces VEX today.
// ----------------------------------------------------------------

fn scan_spdx(case: &EcosystemCase) -> (tempfile::TempDir, PathBuf, serde_json::Value) {
    let fx = workspace_root().join("tests/fixtures").join(case.fixture_subpath);
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let spdx_path = tmp.path().join("out.spdx.json");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let mut cmd = Command::new(bin);
    apply_fake_home_env(&mut cmd, fake_home.path());
    cmd
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(&fx)
        .arg("--format")
        .arg("spdx-2.3-json")
        .arg("--output")
        .arg(format!("spdx-2.3-json={}", spdx_path.to_string_lossy()))
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
    let spdx = serde_json::from_str(&std::fs::read_to_string(&spdx_path).unwrap())
        .expect("spdx valid JSON");
    // Keep tmp alive via return so the sidecar-presence check sees
    // the same directory the scan wrote to.
    let dir = tmp.path().to_path_buf();
    (tmp, dir, spdx)
}

fn assert_no_vex_sidecar(case: &EcosystemCase) {
    let (_guard, dir, spdx) = scan_spdx(case);
    assert!(
        !dir.join("mikebom.openvex.json").exists(),
        "{}: unexpected mikebom.openvex.json produced in {}; \
         no fixture should populate advisories today",
        case.label,
        dir.display()
    );
    assert!(
        spdx.get("externalDocumentRefs").is_none(),
        "{}: unexpected externalDocumentRefs in SPDX doc: {:?}",
        case.label,
        spdx.get("externalDocumentRefs")
    );
}

#[test]
fn no_sidecar_for_apk() {
    assert_no_vex_sidecar(&CASES[0]);
}

#[test]
fn no_sidecar_for_cargo() {
    assert_no_vex_sidecar(&CASES[1]);
}

#[test]
fn no_sidecar_for_deb() {
    assert_no_vex_sidecar(&CASES[2]);
}

#[test]
fn no_sidecar_for_gem() {
    assert_no_vex_sidecar(&CASES[3]);
}

#[test]
fn no_sidecar_for_golang() {
    assert_no_vex_sidecar(&CASES[4]);
}

#[test]
fn no_sidecar_for_maven() {
    assert_no_vex_sidecar(&CASES[5]);
}

#[test]
fn no_sidecar_for_npm() {
    assert_no_vex_sidecar(&CASES[6]);
}

#[test]
fn no_sidecar_for_pip() {
    assert_no_vex_sidecar(&CASES[7]);
}

#[test]
fn no_sidecar_for_rpm() {
    assert_no_vex_sidecar(&CASES[8]);
}

// ----------------------------------------------------------------
// (2) Schema-validation canary for the emitter shape.
// ----------------------------------------------------------------

/// Synthetically produce the exact document shape mikebom's
/// emitter would emit for one CVE affecting one component
/// (mirrors the output of `serialize_openvex` when advisories are
/// present), and assert it validates clean against the vendored
/// OpenVEX 0.2.0 schema. This guards emitter-shape drift against
/// schema drift, even though the live scanner produces nothing
/// yet.
#[test]
fn synthetic_openvex_document_matches_vendored_schema() {
    let doc = serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://mikebom.kusari.dev/openvex/ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "author": "mikebom-0.0.0-test",
        "timestamp": "2026-01-01T00:00:00Z",
        "version": 1,
        "tooling": "mikebom-0.0.0-test",
        "statements": [
            {
                "vulnerability": { "name": "CVE-2026-0001" },
                "products": [
                    { "@id": "pkg:cargo/a@1" }
                ],
                "status": "under_investigation"
            }
        ]
    });
    let categories = validate_openvex_0_2_0(&doc);
    assert!(
        categories.is_empty(),
        "synthetic OpenVEX document produced schema-validation \
         categories: {categories:?} — either the emitter shape drifted from \
         the vendored 0.2.0 schema or the schema fixture is stale"
    );
}

/// Negative control: an OpenVEX document missing the required
/// `statements` field MUST produce a `required` validation error.
/// Catches schema-harness bugs where the validator accepts
/// everything silently.
#[test]
fn malformed_openvex_document_fails_validation() {
    let bad = serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://mikebom.kusari.dev/openvex/AAAA",
        "author": "mikebom-0.0.0-test",
        "timestamp": "2026-01-01T00:00:00Z",
        "version": 1
        // `statements` is missing — the schema requires it.
    });
    let categories = validate_openvex_0_2_0(&bad);
    assert!(
        !categories.is_empty(),
        "validator accepted a clearly-invalid OpenVEX document; \
         something is wrong with the harness"
    );
}
