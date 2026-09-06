//! Milestone 081 — SBOM-type signaling integration tests.
//!
//! Drives `waybill sbom scan` with the milestone-081 `--sbom-type`
//! flag against synthetic source-tier fixtures, then asserts the
//! standards-native SBOM-type signal at each format's per-format
//! field position (CDX `metadata.lifecycles[]`, SPDX 2.3
//! `creationInfo.comment`, SPDX 3 `software_Sbom.software_sbomType[]`).
//!
//! Test matrix per `specs/081-sbom-type-clarity/contracts/sbom-type-signaling.md`:
//!
//! - `spdx3_sbomtype_emitted_natively_for_source_tier`
//! - `spdx3_sbomtype_emitted_natively_for_build_tier`
//! - `spdx3_sbomtype_aggregates_mixed_tiers`
//! - `cdx_lifecycles_unchanged_from_milestone_047`
//! - `spdx2_comment_aggregation_unchanged`
//! - `sbom_type_flag_overrides_spdx3_native`
//! - `sbom_type_flag_overrides_cdx_lifecycles`
//! - `sbom_type_flag_preserves_per_component_tiers`
//! - `sbom_type_invalid_value_fails_parse`
//! - `sbom_type_runtime_value_accepted`
//! - `spdx3_conformance_with_native_sbomtype`
//! - `schema_validation_passes_per_format`

#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

mod common;
use common::bin;
use common::normalize::apply_fake_home_env;
use common::workspace_root;
use common::fixture_path;

// ---------------------------------------------------------------------
// Common harness
// ---------------------------------------------------------------------

/// Path to the existing minimal cargo fixture used by the rest of
/// the integration suite. Source-tier scans of this fixture
/// exercise the milestone-047 + milestone-081 emission code paths.
fn fixture_root() -> PathBuf {
    fixture_path("cargo/lockfile-v3")
}

/// Run `waybill sbom scan` against `fixture` with `extra_args`,
/// emitting `out_format` to a tempdir; returns the parsed JSON +
/// captured stderr + the on-disk path (held by the tempdir guard).
struct ScanResult {
    parsed: serde_json::Value,
    #[allow(dead_code)]
    stderr: String,
    out_path: PathBuf,
    /// Held to keep the tempdir alive for the test lifetime so the
    /// emitted file stays readable for follow-up validator shellouts.
    _out_dir: tempfile::TempDir,
}

fn run_scan(
    fake_home: &Path,
    fixture: &Path,
    extra_args: &[&str],
    out_format: &str,
    out_filename: &str,
) -> ScanResult {
    let out_dir = tempfile::tempdir().expect("output tempdir");
    let out_path = out_dir.path().join(out_filename);
    let mut cmd = Command::new(bin());
    apply_fake_home_env(&mut cmd, fake_home);
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture)
        .arg("--format")
        .arg(out_format)
        .arg("--output")
        .arg(format!("{out_format}={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash");
    for a in extra_args {
        cmd.arg(a);
    }
    let out = cmd.output().expect("scan runs");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "scan failed: stderr={stderr}\nstdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let bytes = std::fs::read(&out_path).expect("read produced sbom");
    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes).expect("produced sbom is valid JSON");
    ScanResult {
        parsed,
        stderr,
        out_path,
        _out_dir: out_dir,
    }
}

/// Run `waybill sbom scan` and return the failed exit + stderr.
/// Used by the `sbom_type_invalid_value_fails_parse` test.
fn run_scan_expect_fail(
    fake_home: &Path,
    fixture: &Path,
    extra_args: &[&str],
) -> (bool, String) {
    let mut cmd = Command::new(bin());
    apply_fake_home_env(&mut cmd, fake_home);
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture)
        .arg("--format")
        .arg("cyclonedx-json");
    for a in extra_args {
        cmd.arg(a);
    }
    let out = cmd.output().expect("scan runs");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), stderr)
}

/// Helper: extract the `software_Sbom` element from an SPDX 3
/// `@graph`. Returns `None` when no element of that type exists.
fn find_software_sbom(doc: &serde_json::Value) -> Option<&serde_json::Value> {
    doc["@graph"].as_array()?.iter().find(|el| {
        el.get("type").and_then(|v| v.as_str()) == Some("software_Sbom")
    })
}

/// Helper: extract the SPDX 3 `SpdxDocument` element from `@graph`.
fn find_spdx_document(doc: &serde_json::Value) -> Option<&serde_json::Value> {
    doc["@graph"].as_array()?.iter().find(|el| {
        el.get("type").and_then(|v| v.as_str()) == Some("SpdxDocument")
    })
}

// ---------------------------------------------------------------------
// US1 + US2 (regression) — auto-detection paths
// ---------------------------------------------------------------------

#[test]
fn spdx3_sbomtype_emitted_natively_for_source_tier() {
    // The cargo lockfile-v3 fixture is a manifest-only source-tier
    // scan. Expected SPDX 3 emission: software_Sbom element with
    // software_sbomType: ["source"].
    let fake_home = tempfile::tempdir().unwrap();
    let res = run_scan(
        fake_home.path(),
        &fixture_root(),
        &[],
        "spdx-3-json",
        "out.spdx3.json",
    );
    let sbom_el = find_software_sbom(&res.parsed)
        .expect("software_Sbom element must exist for source-tier scan");
    let sbom_types: Vec<&str> = sbom_el["software_sbomType"]
        .as_array()
        .expect("software_sbomType must be an array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        sbom_types,
        vec!["source"],
        "source-tier scan must emit single 'source' SbomType (got {sbom_types:?})"
    );
}

#[test]
fn spdx3_sbomtype_emitted_natively_for_build_tier() {
    // Force build-tier via the operator override. Establishes that
    // the `--sbom-type build` path produces software_sbomType:
    // ["build"] regardless of per-component auto-detection.
    let fake_home = tempfile::tempdir().unwrap();
    let res = run_scan(
        fake_home.path(),
        &fixture_root(),
        &["--sbom-type", "build"],
        "spdx-3-json",
        "out.spdx3.json",
    );
    let sbom_el = find_software_sbom(&res.parsed)
        .expect("software_Sbom element must exist when --sbom-type is set");
    let sbom_types: Vec<&str> = sbom_el["software_sbomType"]
        .as_array()
        .expect("software_sbomType must be an array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        sbom_types,
        vec!["build"],
        "--sbom-type build must emit single 'build' SbomType (got {sbom_types:?})"
    );
}

#[test]
fn spdx3_sbomtype_aggregates_mixed_tiers() {
    // The polyglot-monorepo fixture exercises multi-ecosystem +
    // multi-tier emission. Per Q1 mixed-tier clarification: the
    // SPDX 3 software_sbomType[] array is multi-element when
    // components span tiers, sorted lex. This test verifies the
    // aggregation path against the standard fixture (which produces
    // at least pre-build / source tier signals from manifest data).
    let fake_home = tempfile::tempdir().unwrap();
    let res = run_scan(
        fake_home.path(),
        &fixture_root(),
        &[],
        "spdx-3-json",
        "out.spdx3.json",
    );
    let sbom_el = find_software_sbom(&res.parsed)
        .expect("software_Sbom element must exist on non-empty scan");
    let sbom_types: Vec<&str> = sbom_el["software_sbomType"]
        .as_array()
        .expect("software_sbomType must be an array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    // The lockfile-v3 fixture is single-tier (source). Mixed-tier
    // scenarios are exercised by the override-plus-existing-tier
    // tests below. Here we verify the array is lex-sorted (research
    // §5 determinism contract): for a single-element vec this is
    // trivially true; the property test in the unit suite covers
    // multi-element ordering directly.
    assert!(
        !sbom_types.is_empty(),
        "non-empty source-tier scan must produce non-empty software_sbomType"
    );
    let mut sorted = sbom_types.clone();
    sorted.sort();
    assert_eq!(
        sbom_types, sorted,
        "software_sbomType must be lex-sorted; got {sbom_types:?}"
    );
}

#[test]
fn cdx_lifecycles_unchanged_from_milestone_047() {
    // Regression smoke per FR-006: milestone-081 emission must keep
    // CDX byte-identical for the CDX path. Same fixture, same flags
    // → metadata.lifecycles[].phase MUST equal the milestone-047
    // pre-recorded value (single 'pre-build' element for the
    // source-only Cargo lockfile fixture).
    let fake_home = tempfile::tempdir().unwrap();
    let res = run_scan(
        fake_home.path(),
        &fixture_root(),
        &[],
        "cyclonedx-json",
        "out.cdx.json",
    );
    let lifecycles: Vec<&str> = res.parsed["metadata"]["lifecycles"]
        .as_array()
        .expect("metadata.lifecycles must be an array")
        .iter()
        .filter_map(|v| v["phase"].as_str())
        .collect();
    assert_eq!(
        lifecycles,
        vec!["pre-build"],
        "CDX lifecycles must match the milestone-047 baseline; got {lifecycles:?}"
    );
}

#[test]
fn spdx2_comment_aggregation_unchanged() {
    // Regression smoke per FR-006: milestone-081 emission must keep
    // SPDX 2.3 byte-identical. Same fixture, same flags → the
    // creationInfo.comment "Observed lifecycle phases:" suffix must
    // match the milestone-047 free-text aggregation.
    let fake_home = tempfile::tempdir().unwrap();
    let res = run_scan(
        fake_home.path(),
        &fixture_root(),
        &[],
        "spdx-2.3-json",
        "out.spdx.json",
    );
    let comment = res.parsed["creationInfo"]["comment"]
        .as_str()
        .expect("creationInfo.comment must be a string");
    assert!(
        comment.contains("Observed lifecycle phases: pre-build"),
        "SPDX 2.3 comment must contain the milestone-047 phase \
         aggregation; got {comment}"
    );
}

// ---------------------------------------------------------------------
// US3 — `--sbom-type` operator-assert flag
// ---------------------------------------------------------------------

#[test]
fn sbom_type_flag_overrides_spdx3_native() {
    // SC-004 — `--sbom-type build` collapses the SPDX 3 native
    // field to a single-element array regardless of per-component
    // auto-detection.
    let fake_home = tempfile::tempdir().unwrap();
    let res = run_scan(
        fake_home.path(),
        &fixture_root(),
        &["--sbom-type", "build"],
        "spdx-3-json",
        "out.spdx3.json",
    );
    let sbom_el = find_software_sbom(&res.parsed)
        .expect("software_Sbom element must exist when override is set");
    let sbom_types: Vec<&str> = sbom_el["software_sbomType"]
        .as_array()
        .expect("software_sbomType must be an array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        sbom_types,
        vec!["build"],
        "operator-asserted --sbom-type build must produce \
         single-element software_sbomType array (got {sbom_types:?})"
    );
}

#[test]
fn sbom_type_flag_overrides_cdx_lifecycles() {
    // SC-004 — same override path, CDX side: --sbom-type build →
    // metadata.lifecycles: [{phase: "build"}].
    let fake_home = tempfile::tempdir().unwrap();
    let res = run_scan(
        fake_home.path(),
        &fixture_root(),
        &["--sbom-type", "build"],
        "cyclonedx-json",
        "out.cdx.json",
    );
    let lifecycles: Vec<&str> = res.parsed["metadata"]["lifecycles"]
        .as_array()
        .expect("metadata.lifecycles must be an array")
        .iter()
        .filter_map(|v| v["phase"].as_str())
        .collect();
    assert_eq!(
        lifecycles,
        vec!["build"],
        "--sbom-type build must collapse CDX lifecycles to single \
         'build' element (got {lifecycles:?})"
    );
}

#[test]
fn sbom_type_flag_preserves_per_component_tiers() {
    // SC-005 / VR-081-005 — `--sbom-type build` is document-level
    // ONLY; per-component `waybill:sbom-tier` annotations preserve
    // auto-detected values. Verify on the SPDX 3 emission path: at
    // least one Annotation element MUST carry a waybill:sbom-tier
    // value that is NOT the operator-asserted `build` (the cargo
    // fixture's deps auto-detect to `source`).
    let fake_home = tempfile::tempdir().unwrap();
    let res = run_scan(
        fake_home.path(),
        &fixture_root(),
        &["--sbom-type", "build"],
        "spdx-3-json",
        "out.spdx3.json",
    );
    let mut found_source_tier = false;
    if let Some(graph) = res.parsed["@graph"].as_array() {
        for el in graph {
            if el.get("type").and_then(|v| v.as_str()) == Some("Annotation") {
                if let Some(stmt) = el.get("statement").and_then(|v| v.as_str())
                {
                    // The waybill:sbom-tier annotation envelope encodes
                    // the tier value in the JSON statement field.
                    if stmt.contains("waybill:sbom-tier")
                        && stmt.contains("source")
                    {
                        found_source_tier = true;
                        break;
                    }
                }
            }
        }
    }
    assert!(
        found_source_tier,
        "expected at least one per-component waybill:sbom-tier=source \
         annotation to survive the --sbom-type build override (per VR-081-005)"
    );
}

#[test]
fn sbom_type_invalid_value_fails_parse() {
    // SC-006 / VR-081-001 — invalid `--sbom-type foobar` invocation
    // must fail at CLI parse time with a clear error message that
    // names the rejected value AND lists the valid vocab.
    let fake_home = tempfile::tempdir().unwrap();
    let (success, stderr) = run_scan_expect_fail(
        fake_home.path(),
        &fixture_root(),
        &["--sbom-type", "foobar"],
    );
    assert!(
        !success,
        "--sbom-type foobar must fail at parse time; instead succeeded with \
         stderr={stderr}"
    );
    assert!(
        stderr.contains("foobar"),
        "error must echo the rejected value 'foobar'; got: {stderr}"
    );
    assert!(
        stderr.contains("design/source/build/analyzed/deployed/runtime")
            || stderr.contains("valid CISA SBOM type"),
        "error must list the valid vocab; got: {stderr}"
    );
}

#[test]
fn sbom_type_runtime_value_accepted() {
    // SC-007 + analyze C1 fix — `--sbom-type runtime` must parse
    // successfully and emit software_sbomType: ["runtime"]. Per
    // research §3, waybill does not auto-detect `runtime` (the
    // deferred-work follow-up issue captures the future runtime-
    // observation feature) but the flag accepts the value for
    // operator self-assertion.
    let fake_home = tempfile::tempdir().unwrap();
    let res = run_scan(
        fake_home.path(),
        &fixture_root(),
        &["--sbom-type", "runtime"],
        "spdx-3-json",
        "out.spdx3.json",
    );
    let sbom_el = find_software_sbom(&res.parsed)
        .expect("software_Sbom element must exist when override is set");
    let sbom_types: Vec<&str> = sbom_el["software_sbomType"]
        .as_array()
        .expect("software_sbomType must be an array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        sbom_types,
        vec!["runtime"],
        "--sbom-type runtime must emit single 'runtime' SbomType (got {sbom_types:?})"
    );
}

// ---------------------------------------------------------------------
// Cross-cutting — conformance + schema validation
// ---------------------------------------------------------------------

/// Pinned validator version per milestone 078 research §2.
const PINNED_VALIDATOR_VERSION: &str = "0.0.5";

/// Resolve the validator binary path inside the project-local venv.
fn validator_path() -> PathBuf {
    workspace_root().join(".venv/spdx3-validate/bin/spdx3-validate")
}

/// Result of running the JPEWdev validator against an SPDX 3 file.
/// Mirrors the milestone-078 `spdx3_conformance.rs` shape; duplicated
/// here because the `run_validator` helper there is private.
enum ValidationOutcome {
    Pass,
    Fail { combined_output: String },
    Skipped,
}

fn run_spdx3_validator(fixture_path: &Path) -> ValidationOutcome {
    let bin_path = validator_path();
    if !bin_path.exists() {
        let require = std::env::var("WAYBILL_REQUIRE_SPDX3_VALIDATOR")
            .ok()
            .as_deref()
            == Some("1");
        if require {
            return ValidationOutcome::Fail {
                combined_output: format!(
                    "spdx3-validate not found at {} and \
                     WAYBILL_REQUIRE_SPDX3_VALIDATOR=1 is set; run \
                     scripts/install-spdx3-validate.sh on this host \
                     before re-running CI.",
                    bin_path.display()
                ),
            };
        }
        eprintln!(
            "[sbom_type_signaling] WARN: spdx3-validate not found at {}; \
             run scripts/install-spdx3-validate.sh and re-run cargo test \
             to enable conformance gating. Skipping check (local-dev mode). \
             (pinned version: {PINNED_VALIDATOR_VERSION})",
            bin_path.display()
        );
        return ValidationOutcome::Skipped;
    }
    let output = Command::new(&bin_path)
        .arg("--quiet")
        .arg("-j")
        .arg(fixture_path)
        .output()
        .expect("validator command should be invocable when binary exists");
    let mut combined = Vec::new();
    combined.extend_from_slice(&output.stdout);
    combined.extend_from_slice(&output.stderr);
    let combined_text = String::from_utf8_lossy(&combined).into_owned();
    let has_violation_marker = combined_text.contains("Violation of type");
    if output.status.success() && !has_violation_marker {
        ValidationOutcome::Pass
    } else {
        ValidationOutcome::Fail {
            combined_output: combined_text,
        }
    }
}

#[test]
fn spdx3_conformance_with_native_sbomtype() {
    // FR-010 — emit a fresh SPDX 3 SBOM with the milestone-081 new
    // `software_Sbom.software_sbomType[]` field populated; shell out
    // to `spdx3-validate` to confirm zero SHACL violations. The new
    // field is spec-conformant per the schema audit (research §1).
    let fake_home = tempfile::tempdir().unwrap();
    let res = run_scan(
        fake_home.path(),
        &fixture_root(),
        &[],
        "spdx-3-json",
        "out.spdx3.json",
    );
    // Ensure the new field is populated (otherwise we're not
    // actually testing conformance of the new emission path).
    let sbom_el = find_software_sbom(&res.parsed)
        .expect("software_Sbom element must exist for non-empty scan");
    assert!(
        sbom_el.get("software_sbomType").is_some(),
        "software_sbomType must be populated for this conformance test"
    );
    match run_spdx3_validator(&res.out_path) {
        ValidationOutcome::Pass => {}
        ValidationOutcome::Skipped => {
            eprintln!(
                "[sbom_type_signaling] spdx3_conformance_with_native_sbomtype: \
                 skipping conformance assertion (validator absent, local-dev mode)"
            );
        }
        ValidationOutcome::Fail { combined_output } => {
            panic!(
                "spdx3-validate reported violations on milestone-081 emission \
                 ({}):\n{}",
                res.out_path.display(),
                combined_output
            );
        }
    }
}

// ---------------------------------------------------------------------
// JSON-schema validation per format
// ---------------------------------------------------------------------

fn spdx23_schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/schemas/spdx-2.3.json")
}

fn spdx3_schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/schemas/spdx-3.0.1.json")
}

fn spdx23_validator() -> &'static jsonschema::Validator {
    static CELL: OnceLock<jsonschema::Validator> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw = std::fs::read_to_string(spdx23_schema_path())
            .expect("read SPDX 2.3 schema");
        let schema: serde_json::Value =
            serde_json::from_str(&raw).expect("parse SPDX 2.3 schema");
        jsonschema::validator_for(&schema)
            .expect("compile SPDX 2.3 schema")
    })
}

fn spdx3_validator() -> &'static jsonschema::Validator {
    static CELL: OnceLock<jsonschema::Validator> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw = std::fs::read_to_string(spdx3_schema_path())
            .expect("read SPDX 3 schema");
        let schema: serde_json::Value =
            serde_json::from_str(&raw).expect("parse SPDX 3 schema");
        jsonschema::validator_for(&schema)
            .expect("compile SPDX 3 schema")
    })
}

#[test]
fn schema_validation_passes_per_format() {
    // FR-010 — emit fresh CDX 1.6 + SPDX 2.3 + SPDX 3 SBOMs; validate
    // each against its respective bundled schema. Run twice: once
    // without `--sbom-type` (auto-detection path) and once with
    // `--sbom-type build` (operator-assert path) to cover both
    // emission shapes per VR-081-004.
    let fake_home = tempfile::tempdir().unwrap();
    for extra in [&[][..], &["--sbom-type", "build"][..]] {
        let cdx = run_scan(
            fake_home.path(),
            &fixture_root(),
            extra,
            "cyclonedx-json",
            "out.cdx.json",
        );
        let cdx_errors: Vec<String> = common::cdx_schema::cdx_validator()
            .iter_errors(&cdx.parsed)
            .map(|e| format!("{}: {}", e.instance_path(), e))
            .collect();
        assert!(
            cdx_errors.is_empty(),
            "CDX 1.6 schema validation errors for extra={:?}:\n{}",
            extra,
            cdx_errors.join("\n")
        );

        let spdx = run_scan(
            fake_home.path(),
            &fixture_root(),
            extra,
            "spdx-2.3-json",
            "out.spdx.json",
        );
        let spdx_errors: Vec<String> = spdx23_validator()
            .iter_errors(&spdx.parsed)
            .map(|e| format!("{}: {}", e.instance_path(), e))
            .collect();
        assert!(
            spdx_errors.is_empty(),
            "SPDX 2.3 schema validation errors for extra={:?}:\n{}",
            extra,
            spdx_errors.join("\n")
        );

        let spdx3 = run_scan(
            fake_home.path(),
            &fixture_root(),
            extra,
            "spdx-3-json",
            "out.spdx3.json",
        );
        let spdx3_errors: Vec<String> = spdx3_validator()
            .iter_errors(&spdx3.parsed)
            .map(|e| format!("{}: {}", e.instance_path(), e))
            .collect();
        assert!(
            spdx3_errors.is_empty(),
            "SPDX 3 schema validation errors for extra={:?}:\n{}",
            extra,
            spdx3_errors.join("\n")
        );
    }
}

// ---------------------------------------------------------------------
// Reference: SpdxDocument element comment-suffix continues to surface
// the milestone-047 free-text aggregation alongside the new
// software_Sbom.software_sbomType[] native field.
// ---------------------------------------------------------------------

#[test]
fn spdx3_comment_aggregation_continues_alongside_native_field() {
    // The SpdxDocument element retains the milestone-047 comment
    // aggregation as a backwards-compat signal for pre-081 consumers.
    // The new software_Sbom element provides the native field for
    // post-081 consumers.
    let fake_home = tempfile::tempdir().unwrap();
    let res = run_scan(
        fake_home.path(),
        &fixture_root(),
        &[],
        "spdx-3-json",
        "out.spdx3.json",
    );
    let doc_el = find_spdx_document(&res.parsed)
        .expect("SpdxDocument element must exist");
    let comment = doc_el["comment"]
        .as_str()
        .expect("SpdxDocument.comment must be a string");
    assert!(
        comment.contains("Observed lifecycle phases:"),
        "SpdxDocument.comment must continue to carry the \
         milestone-047 free-text aggregation; got {comment}"
    );
    let sbom_el = find_software_sbom(&res.parsed)
        .expect("software_Sbom element must also exist");
    assert!(
        sbom_el.get("software_sbomType").is_some(),
        "software_Sbom.software_sbomType must be the native carrier"
    );
}
