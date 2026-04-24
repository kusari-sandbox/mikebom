//! CycloneDX byte-identity regression test — milestone 010 T010 + T011.
//!
//! The load-bearing guarantee behind FR-022 / SC-006: existing CDX
//! output must not drift as SPDX emission lands. For each of the 9
//! ecosystems mikebom supports today, this test runs `mikebom sbom
//! scan` against a committed fixture, normalizes the two fields
//! CycloneDX intentionally varies per invocation (`serialNumber`, a
//! fresh UUID; `metadata.timestamp`, `Utc::now()`), and compares the
//! result byte-for-byte against a pinned golden fixture under
//! `mikebom-cli/tests/fixtures/golden/cyclonedx/`.
//!
//! Updating a golden: set `MIKEBOM_UPDATE_CDX_GOLDENS=1` and rerun the
//! test. The normalized output is written back to the golden file.
//! Commit the diff only after reviewing — any change here is a real
//! CDX-output change and needs an audit.

use std::path::PathBuf;
use std::process::Command;

/// Deterministic placeholders used in both the pinned golden files
/// and the normalized freshly-produced output. The field values
/// themselves are guaranteed-volatile per the CycloneDX spec (a v4
/// UUID and a scan-time RFC 3339 stamp); masking them lets the rest
/// of the document carry the structural regression guarantee.
const SERIAL_PLACEHOLDER: &str = "urn:uuid:00000000-0000-0000-0000-000000000000";
const TIMESTAMP_PLACEHOLDER: &str = "1970-01-01T00:00:00Z";

#[derive(Clone, Copy)]
struct EcosystemCase {
    /// Short ecosystem label — used to name the golden file.
    label: &'static str,
    /// Path under the workspace `tests/fixtures/` directory.
    fixture_subpath: &'static str,
    /// When set, passed via `--deb-codename` so the PURL `distro=`
    /// qualifier is stable across machines that may auto-detect
    /// something different.
    deb_codename: Option<&'static str>,
}

const CASES: &[EcosystemCase] = &[
    EcosystemCase { label: "apk",    fixture_subpath: "apk/synthetic",     deb_codename: None },
    EcosystemCase { label: "cargo",  fixture_subpath: "cargo/lockfile-v3", deb_codename: None },
    EcosystemCase { label: "deb",    fixture_subpath: "deb/synthetic",     deb_codename: Some("bookworm") },
    EcosystemCase { label: "gem",    fixture_subpath: "gem/simple-bundle", deb_codename: None },
    EcosystemCase { label: "golang", fixture_subpath: "go/simple-module",  deb_codename: None },
    EcosystemCase { label: "maven",  fixture_subpath: "maven/pom-three-deps", deb_codename: None },
    EcosystemCase { label: "npm",    fixture_subpath: "npm/node-modules-walk", deb_codename: None },
    EcosystemCase { label: "pip",    fixture_subpath: "python/simple-venv", deb_codename: None },
    EcosystemCase { label: "rpm",    fixture_subpath: "rpm/bdb-only",      deb_codename: None },
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn fixture_path(subpath: &str) -> PathBuf {
    workspace_root().join("tests/fixtures").join(subpath)
}

fn golden_path(label: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden/cyclonedx")
        .join(format!("{label}.cdx.json"))
}

/// Run `mikebom sbom scan` against a fixture and return the raw CDX
/// JSON text.
fn run_scan(case: &EcosystemCase) -> String {
    let fx = fixture_path(case.fixture_subpath);
    assert!(
        fx.exists(),
        "fixture path missing for {}: {}",
        case.label,
        fx.display()
    );
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_path = tmp.path().join("mikebom.cdx.json");
    let mut cmd = Command::new(bin);
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(&fx)
        .arg("--output")
        .arg(&out_path)
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
    std::fs::read_to_string(&out_path).expect("read produced sbom")
}

/// Replace the two inherently volatile fields (`serialNumber` v4 UUID
/// and `metadata.timestamp` wall-clock stamp) with deterministic
/// placeholders so the rest of the document can be byte-compared.
/// Any other difference — component order, property keys, license
/// shape, added/removed fields — surfaces as a regression.
fn normalize(raw: &str) -> String {
    let mut json: serde_json::Value =
        serde_json::from_str(raw).expect("produced SBOM is valid JSON");
    if let Some(obj) = json.as_object_mut() {
        if obj.contains_key("serialNumber") {
            obj.insert(
                "serialNumber".to_string(),
                serde_json::Value::String(SERIAL_PLACEHOLDER.to_string()),
            );
        }
        if let Some(md) = obj.get_mut("metadata").and_then(|v| v.as_object_mut()) {
            if md.contains_key("timestamp") {
                md.insert(
                    "timestamp".to_string(),
                    serde_json::Value::String(TIMESTAMP_PLACEHOLDER.to_string()),
                );
            }
        }
    }
    serde_json::to_string_pretty(&json).expect("re-serialize")
}

/// Write or compare a golden file. Accepts a test-time toggle via
/// `MIKEBOM_UPDATE_CDX_GOLDENS=1` to rewrite instead of diff.
fn assert_or_update_golden(label: &str, normalized: &str) {
    let path = golden_path(label);
    let update = std::env::var("MIKEBOM_UPDATE_CDX_GOLDENS")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);
    if update || !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create golden dir");
        }
        std::fs::write(&path, normalized.as_bytes())
            .expect("write golden file");
        eprintln!(
            "[cdx_regression] updated golden for {label}: {}",
            path.display()
        );
        return;
    }
    let golden =
        std::fs::read_to_string(&path).expect("read pinned golden");
    if golden != normalized {
        // Write the actual produced output alongside the golden so a
        // maintainer can diff them with their own tooling — cleaner
        // than dumping kilobytes into the test failure message.
        let actual = path.with_extension("actual.json");
        std::fs::write(&actual, normalized.as_bytes())
            .expect("write actual.json for diff");
        panic!(
            "CDX regression for ecosystem {label}: output differs from \
             pinned golden.\n  golden: {}\n  actual: {}\nTo accept the \
             change, run: MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo test \
             --test cdx_regression",
            path.display(),
            actual.display()
        );
    }
}

fn run_case(case: &EcosystemCase) {
    let raw = run_scan(case);
    let normalized = normalize(&raw);
    // Sanity: the two volatile fields must exist in every produced
    // CDX document (they are required by the CDX 1.6 schema and by
    // mikebom's builder). If they ever stop being emitted, the
    // normalization below is a silent no-op and this test becomes
    // meaningless — fail loudly instead.
    let reparsed: serde_json::Value =
        serde_json::from_str(&raw).expect("produced SBOM is valid JSON");
    assert!(
        reparsed
            .get("serialNumber")
            .and_then(|v| v.as_str())
            .is_some(),
        "{}: CDX output missing serialNumber",
        case.label
    );
    assert!(
        reparsed
            .get("metadata")
            .and_then(|m| m.get("timestamp"))
            .and_then(|v| v.as_str())
            .is_some(),
        "{}: CDX output missing metadata.timestamp",
        case.label
    );
    assert_or_update_golden(case.label, &normalized);
}

// One test per ecosystem so a failure names the offender directly.

#[test]
fn cdx_regression_apk() {
    run_case(&CASES[0]);
}

#[test]
fn cdx_regression_cargo() {
    run_case(&CASES[1]);
}

#[test]
fn cdx_regression_deb() {
    run_case(&CASES[2]);
}

#[test]
fn cdx_regression_gem() {
    run_case(&CASES[3]);
}

#[test]
fn cdx_regression_golang() {
    run_case(&CASES[4]);
}

#[test]
fn cdx_regression_maven() {
    run_case(&CASES[5]);
}

#[test]
fn cdx_regression_npm() {
    run_case(&CASES[6]);
}

#[test]
fn cdx_regression_pip() {
    run_case(&CASES[7]);
}

#[test]
fn cdx_regression_rpm() {
    run_case(&CASES[8]);
}
