//! SPDX annotation fidelity (milestone 010 T029).
//!
//! FR-015 / FR-016 promise: every `mikebom:*` property and every
//! `evidence.identity` / `evidence.occurrences` entry present in the
//! CycloneDX output for a scan has a matching
//! `MikebomAnnotationCommentV1`-envelope annotation in the SPDX
//! output for the same scan.
//!
//! This test walks the nine ecosystem fixtures and asserts that for
//! each distinct `mikebom:*` property name observed in the CDX
//! output, at least one SPDX `annotations[]` entry decodes to a
//! v1 envelope with a matching `field`. Full value-level parity is
//! out of scope here — the exhaustive map-coverage check in
//! `sbom_format_mapping_coverage.rs` already guards that every
//! property name has a documented target, and the unit tests in
//! `generate/spdx/annotations.rs` guard individual emission shapes.
//! The gap this test closes: "the field list observed in CDX
//! actually shows up as annotations in SPDX for the same scan."

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;


mod common;
use common::{workspace_root, EcosystemCase, CASES};

struct DualScan {
    cdx: serde_json::Value,
    spdx: serde_json::Value,
}

fn run_dual_scan(case: &EcosystemCase) -> DualScan {
    let fx = workspace_root().join("tests/fixtures").join(case.fixture_subpath);
    assert!(
        fx.exists(),
        "fixture missing for {}: {}",
        case.label,
        fx.display()
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    // Isolate HOME + friends so host-cache leak doesn't change
    // what CDX emits — see cdx_regression.rs::run_scan for the
    // full cross-host-byte-identity playbook this mirrors.
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let cdx_path = tmp.path().join("out.cdx.json");
    let spdx_path = tmp.path().join("out.spdx.json");
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
        .arg(&fx)
        .arg("--format")
        .arg("cyclonedx-json,spdx-2.3-json")
        .arg("--output")
        .arg(format!(
            "cyclonedx-json={}",
            cdx_path.to_string_lossy()
        ))
        .arg("--output")
        .arg(format!(
            "spdx-2.3-json={}",
            spdx_path.to_string_lossy()
        ))
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
    DualScan {
        cdx: serde_json::from_str(&std::fs::read_to_string(&cdx_path).unwrap())
            .expect("cdx valid JSON"),
        spdx: serde_json::from_str(&std::fs::read_to_string(&spdx_path).unwrap())
            .expect("spdx valid JSON"),
    }
}

/// Collect every distinct `mikebom:*` property name observed anywhere
/// in the CDX document — on components, on nested components, on
/// metadata. Returns the names as a sorted set for stable error
/// reporting.
fn cdx_mikebom_property_names(cdx: &serde_json::Value) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    fn walk_component(c: &serde_json::Value, out: &mut BTreeSet<String>) {
        if let Some(props) = c.get("properties").and_then(|v| v.as_array()) {
            for p in props {
                if let Some(name) = p.get("name").and_then(|v| v.as_str()) {
                    if name.starts_with("mikebom:") {
                        out.insert(name.to_string());
                    }
                }
            }
        }
        if let Some(nested) = c.get("components").and_then(|v| v.as_array()) {
            for nc in nested {
                walk_component(nc, out);
            }
        }
    }
    for c in cdx.get("components").and_then(|v| v.as_array()).into_iter().flatten() {
        walk_component(c, &mut out);
    }
    // Metadata-level mikebom properties.
    if let Some(props) = cdx
        .get("metadata")
        .and_then(|m| m.get("properties"))
        .and_then(|v| v.as_array())
    {
        for p in props {
            if let Some(name) = p.get("name").and_then(|v| v.as_str()) {
                if name.starts_with("mikebom:") {
                    out.insert(name.to_string());
                }
            }
        }
    }
    out
}

/// Collect every distinct annotation-envelope `field` value observed
/// anywhere in the SPDX document — on packages, on the document
/// itself. Values are the `field` strings inside the v1 envelope;
/// raw annotation comments that fail to decode as v1 are dropped
/// silently (a separate test could assert strict v1 coverage if we
/// ever grow other annotation kinds).
fn spdx_annotation_fields(spdx: &serde_json::Value) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    fn collect_from_array(
        arr: Option<&serde_json::Value>,
        out: &mut BTreeSet<String>,
    ) {
        let Some(arr) = arr.and_then(|v| v.as_array()) else {
            return;
        };
        for a in arr {
            let Some(comment) = a.get("comment").and_then(|v| v.as_str()) else {
                continue;
            };
            let Ok(env) = serde_json::from_str::<serde_json::Value>(comment) else {
                continue;
            };
            if env.get("schema").and_then(|v| v.as_str())
                != Some("mikebom-annotation/v1")
            {
                continue;
            }
            if let Some(field) = env.get("field").and_then(|v| v.as_str()) {
                out.insert(field.to_string());
            }
        }
    }
    collect_from_array(spdx.get("annotations"), &mut out);
    if let Some(pkgs) = spdx.get("packages").and_then(|v| v.as_array()) {
        for p in pkgs {
            collect_from_array(p.get("annotations"), &mut out);
        }
    }
    out
}

fn check_fidelity(case: &EcosystemCase) {
    let s = run_dual_scan(case);
    let cdx_props = cdx_mikebom_property_names(&s.cdx);
    let spdx_fields = spdx_annotation_fields(&s.spdx);
    let missing: Vec<&String> = cdx_props.difference(&spdx_fields).collect();
    assert!(
        missing.is_empty(),
        "{}: CDX emitted {} mikebom:* properties without matching SPDX \
         annotation:\n  {:?}\nSPDX annotation-field set was: {:?}",
        case.label,
        missing.len(),
        missing,
        spdx_fields
    );
}

#[test]
fn fidelity_apk() {
    check_fidelity(&CASES[0]);
}

#[test]
fn fidelity_cargo() {
    check_fidelity(&CASES[1]);
}

#[test]
fn fidelity_deb() {
    check_fidelity(&CASES[2]);
}

#[test]
fn fidelity_gem() {
    check_fidelity(&CASES[3]);
}

#[test]
fn fidelity_golang() {
    check_fidelity(&CASES[4]);
}

#[test]
fn fidelity_maven() {
    check_fidelity(&CASES[5]);
}

#[test]
fn fidelity_npm() {
    check_fidelity(&CASES[6]);
}

#[test]
fn fidelity_pip() {
    check_fidelity(&CASES[7]);
}

#[test]
fn fidelity_rpm() {
    check_fidelity(&CASES[8]);
}

// Silence dead-code lint when compiled standalone.
#[allow(dead_code)]
fn _noop_touch(_: &Path) {}
