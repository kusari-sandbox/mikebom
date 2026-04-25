//! Bidirectional component-count parity across CDX ↔ SPDX 2.3 ↔ SPDX 3
//! (milestone 012 T005 / US2).
//!
//! FR-004 / SC-003: for every fixture, the count of components in
//! the CycloneDX output (recursively flattened through
//! `components[].components[]`) MUST equal the count of `Package`
//! elements in the SPDX 2.3 output minus the synthetic root (0 or 1),
//! AND the SPDX 3 `software_Package` count minus its synthetic root
//! (0 or 1).
//!
//! Per research.md §R2: the CDX-nesting-vs-SPDX-flattening structural
//! difference is the source of the user-reported 22-component drift
//! on the external polyglot-builder-image fixture. CDX's
//! `cdx.components.length` counts top-level only (CDX folds children
//! into their parents' `components[].components[]` array per CDX 1.6
//! §6.2.10); SPDX flattens to top-level Packages and expresses
//! parent-child via `CONTAINS` Relationships. Comparing the two raw
//! counts is apples-to-oranges; flattening CDX first yields equality.
//!
//! This test locks that invariant in CI. If the two counts diverge,
//! either CDX nesting changed (an emitter-side regression), SPDX
//! stopped emitting for nested children (another emitter-side
//! regression), or a new synthetic root was introduced (a structural
//! change that should be caught at review time).

use std::process::Command;


mod common;
use common::{workspace_root, EcosystemCase, CASES};

struct Scan {
    cdx: serde_json::Value,
    spdx23: serde_json::Value,
    spdx3: serde_json::Value,
}

fn triple_scan(case: &EcosystemCase) -> Scan {
    let fixture = workspace_root().join("tests/fixtures").join(case.fixture_subpath);
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home");
    let cdx_path = tmp.path().join("out.cdx.json");
    let spdx23_path = tmp.path().join("out.spdx.json");
    let spdx3_path = tmp.path().join("out.spdx3.json");
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
        .arg("cyclonedx-json,spdx-2.3-json,spdx-3-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", cdx_path.to_string_lossy()))
        .arg("--output")
        .arg(format!("spdx-2.3-json={}", spdx23_path.to_string_lossy()))
        .arg("--output")
        .arg(format!("spdx-3-json={}", spdx3_path.to_string_lossy()))
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
    Scan {
        cdx: serde_json::from_str(&std::fs::read_to_string(&cdx_path).unwrap())
            .expect("cdx valid JSON"),
        spdx23: serde_json::from_str(&std::fs::read_to_string(&spdx23_path).unwrap())
            .expect("spdx23 valid JSON"),
        spdx3: serde_json::from_str(&std::fs::read_to_string(&spdx3_path).unwrap())
            .expect("spdx3 valid JSON"),
    }
}

/// Count CDX components recursively — top-level + everything nested
/// under `components[].components[]`. Matches the total set of
/// `ResolvedComponent` entries the scan produced.
fn cdx_flattened_count(doc: &serde_json::Value) -> usize {
    fn recur(node: &serde_json::Value, n: &mut usize) {
        if let Some(arr) = node.get("components").and_then(|v| v.as_array()) {
            for c in arr {
                *n += 1;
                recur(c, n);
            }
        }
    }
    let mut n = 0;
    recur(doc, &mut n);
    n
}

/// Count SPDX 2.3 `packages[]` entries. SPDX 2.3 `synthesize_root`
/// adds exactly 0 or 1 synthetic root; we detect it via the
/// `SPDXRef-DocumentRoot-` SPDXID prefix.
fn spdx23_package_count_and_synthetic(doc: &serde_json::Value) -> (usize, usize) {
    let Some(pkgs) = doc.get("packages").and_then(|v| v.as_array()) else {
        return (0, 0);
    };
    let total = pkgs.len();
    let synthetic = pkgs
        .iter()
        .filter(|p| {
            p.get("SPDXID")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.starts_with("SPDXRef-DocumentRoot-"))
        })
        .count();
    (total, synthetic)
}

/// Count SPDX 3 `software_Package` elements + the synthetic-root
/// count (Packages whose spdxId path segment contains `/pkg-root-`).
fn spdx3_package_count_and_synthetic(doc: &serde_json::Value) -> (usize, usize) {
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return (0, 0);
    };
    let total = graph
        .iter()
        .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("software_Package"))
        .count();
    let synthetic = graph
        .iter()
        .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("software_Package"))
        .filter(|e| {
            e.get("spdxId")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.contains("/pkg-root-"))
        })
        .count();
    (total, synthetic)
}

fn assert_count_parity(case: &EcosystemCase) {
    let s = triple_scan(case);
    let cdx_count = cdx_flattened_count(&s.cdx);
    let (spdx23_total, spdx23_synth) = spdx23_package_count_and_synthetic(&s.spdx23);
    let (spdx3_total, spdx3_synth) = spdx3_package_count_and_synthetic(&s.spdx3);

    // Flattened CDX == SPDX 2.3 packages minus synthetic root.
    assert_eq!(
        cdx_count,
        spdx23_total - spdx23_synth,
        "{}: flattened CDX component count ({cdx_count}) != SPDX 2.3 packages ({spdx23_total}) minus synthetic root ({spdx23_synth})",
        case.label
    );

    // Flattened CDX == SPDX 3 software_Package count minus synthetic.
    assert_eq!(
        cdx_count,
        spdx3_total - spdx3_synth,
        "{}: flattened CDX component count ({cdx_count}) != SPDX 3 software_Package count ({spdx3_total}) minus synthetic root ({spdx3_synth})",
        case.label
    );

    // Cross-format sanity: SPDX 2.3 and SPDX 3 must agree on
    // non-synthetic Package count (same ResolvedComponent source).
    assert_eq!(
        spdx23_total - spdx23_synth,
        spdx3_total - spdx3_synth,
        "{}: SPDX 2.3 ({}) and SPDX 3 ({}) non-synthetic Package counts disagree",
        case.label,
        spdx23_total - spdx23_synth,
        spdx3_total - spdx3_synth
    );
}

#[test] fn count_parity_apk()    { assert_count_parity(&CASES[0]); }
#[test] fn count_parity_cargo()  { assert_count_parity(&CASES[1]); }
#[test] fn count_parity_deb()    { assert_count_parity(&CASES[2]); }
#[test] fn count_parity_gem()    { assert_count_parity(&CASES[3]); }
#[test] fn count_parity_golang() { assert_count_parity(&CASES[4]); }
#[test] fn count_parity_maven()  { assert_count_parity(&CASES[5]); }
#[test] fn count_parity_npm()    { assert_count_parity(&CASES[6]); }
#[test] fn count_parity_pip()    { assert_count_parity(&CASES[7]); }
#[test] fn count_parity_rpm()    { assert_count_parity(&CASES[8]); }
