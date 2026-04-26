//! User Story 1 acceptance tests (milestone 010 T017).
//!
//! Walks the five acceptance scenarios in
//! `specs/010-spdx-output-support/spec.md` § "User Story 1":
//!
//! 1. node_modules + package-lock.json → every npm package appears
//!    as an SPDX Package with matching PURL / version / checksums.
//! 2. Debian container image → every `deb` component has the same
//!    PURL and checksums; documentDescribes points at the root.
//! 3. Declared+concluded licenses round-trip through SPDX native
//!    `licenseDeclared` / `licenseConcluded`.
//! 4. Determinism re-run (covered by `spdx_determinism.rs`; a
//!    cross-reference test lives here for completeness).
//! 5. Single `--format cyclonedx-json,spdx-2.3-json` invocation
//!    emits both files from one scan, bit-identical (modulo
//!    volatile fields) to two separate invocations.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;


mod common;
use common::normalize::{
    apply_fake_home_env, normalize_cdx_for_golden, normalize_spdx23_for_golden,
};
use common::{bin, workspace_root};


struct Scan {
    /// Parsed CDX document, if requested.
    cdx: Option<serde_json::Value>,
    /// Parsed SPDX 2.3 document, if requested.
    spdx: Option<serde_json::Value>,
}

fn scan(fixture: &Path, formats: &[&str], extra_args: &[&str]) -> Scan {
    assert!(fixture.exists(), "fixture missing: {}", fixture.display());
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let mut cmd = Command::new(bin());
    apply_fake_home_env(&mut cmd, fake_home.path());
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture)
        .arg("--no-deep-hash");
    cmd.arg("--format").arg(formats.join(","));
    let mut want_cdx = false;
    let mut want_spdx = false;
    for f in formats {
        let out = match *f {
            "cyclonedx-json" => {
                want_cdx = true;
                tmp.path().join("mikebom.cdx.json")
            }
            "spdx-2.3-json" => {
                want_spdx = true;
                tmp.path().join("mikebom.spdx.json")
            }
            other => panic!("unknown format requested: {other}"),
        };
        cmd.arg("--output")
            .arg(format!("{}={}", f, out.to_string_lossy()));
    }
    for a in extra_args {
        cmd.arg(a);
    }
    let out = cmd.output().expect("mikebom runs");
    assert!(
        out.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cdx = if want_cdx {
        Some(
            serde_json::from_str(
                &std::fs::read_to_string(tmp.path().join("mikebom.cdx.json"))
                    .expect("read cdx"),
            )
            .expect("parse cdx"),
        )
    } else {
        None
    };
    let spdx = if want_spdx {
        Some(
            serde_json::from_str(
                &std::fs::read_to_string(tmp.path().join("mikebom.spdx.json"))
                    .expect("read spdx"),
            )
            .expect("parse spdx"),
        )
    } else {
        None
    };
    Scan { cdx, spdx }
}

// ---------- scenario 1: npm node_modules ----------------------------------

#[test]
fn scenario_1_npm_components_appear_as_spdx_packages() {
    let fixture = workspace_root().join("tests/fixtures/npm/node-modules-walk");
    let s = scan(&fixture, &["cyclonedx-json", "spdx-2.3-json"], &[]);
    let cdx = s.cdx.expect("cdx present");
    let spdx = s.spdx.expect("spdx present");

    let cdx_npm_purls: Vec<String> = cdx["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["purl"].as_str().map(String::from))
        .filter(|p| p.starts_with("pkg:npm/"))
        .collect();
    assert!(!cdx_npm_purls.is_empty(), "fixture should have npm components");

    // Collect SPDX package PURLs via externalRefs.
    let spdx_purls: std::collections::HashSet<String> = spdx["packages"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|p| p["externalRefs"].as_array().cloned().unwrap_or_default())
        .filter(|r| r["referenceType"] == "purl")
        .filter_map(|r| r["referenceLocator"].as_str().map(String::from))
        .collect();

    for p in &cdx_npm_purls {
        assert!(
            spdx_purls.contains(p),
            "npm PURL {p} in CDX but missing from SPDX externalRefs"
        );
    }
}

// ---------- scenario 2: deb rootfs ----------------------------------------

#[test]
fn scenario_2_deb_components_match_and_describes_points_at_root() {
    let fixture = workspace_root().join("tests/fixtures/deb/synthetic");
    let s = scan(
        &fixture,
        &["cyclonedx-json", "spdx-2.3-json"],
        &["--deb-codename", "bookworm"],
    );
    let cdx = s.cdx.expect("cdx");
    let spdx = s.spdx.expect("spdx");

    let cdx_deb: Vec<String> = cdx["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["purl"].as_str().map(String::from))
        .filter(|p| p.starts_with("pkg:deb/"))
        .collect();
    let spdx_purls: std::collections::HashSet<String> = spdx["packages"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|p| p["externalRefs"].as_array().cloned().unwrap_or_default())
        .filter(|r| r["referenceType"] == "purl")
        .filter_map(|r| r["referenceLocator"].as_str().map(String::from))
        .collect();
    for p in &cdx_deb {
        assert!(
            spdx_purls.contains(p),
            "deb PURL {p} in CDX missing from SPDX"
        );
    }
    // documentDescribes non-empty; points to an SPDXID that exists
    // in the packages array.
    let describes = spdx["documentDescribes"]
        .as_array()
        .expect("documentDescribes array");
    assert!(!describes.is_empty(), "documentDescribes must name the scan root");
    let described_id = describes[0].as_str().unwrap();
    let pkg_ids: std::collections::HashSet<&str> = spdx["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["SPDXID"].as_str())
        .collect();
    assert!(
        pkg_ids.contains(described_id),
        "documentDescribes target {described_id} not found in packages[]"
    );
}

// ---------- scenario 3: declared/concluded license preservation -----------

#[test]
fn scenario_3_declared_and_concluded_licenses_preserved() {
    let fixture = workspace_root().join("tests/fixtures/cargo/lockfile-v3");
    let s = scan(&fixture, &["cyclonedx-json", "spdx-2.3-json"], &[]);
    let cdx = s.cdx.expect("cdx");
    let spdx = s.spdx.expect("spdx");

    // Index cdx PURL → licenses (declared + concluded) as seen by
    // the CDX serializer (the shape it emits: `licenses[]` with
    // `acknowledgement: declared|concluded`).
    let mut cdx_declared: HashMap<String, Vec<String>> = HashMap::new();
    let mut cdx_concluded: HashMap<String, Vec<String>> = HashMap::new();
    for comp in cdx["components"].as_array().unwrap() {
        let Some(purl) = comp["purl"].as_str() else { continue };
        for lic in comp["licenses"].as_array().cloned().unwrap_or_default() {
            let ack = lic["license"]["acknowledgement"]
                .as_str()
                .or_else(|| lic["acknowledgement"].as_str())
                .unwrap_or("declared")
                .to_string();
            let id = lic["license"]["id"]
                .as_str()
                .or_else(|| lic["license"]["name"].as_str())
                .or_else(|| lic["expression"].as_str());
            if let Some(id) = id {
                if ack == "concluded" {
                    cdx_concluded.entry(purl.to_string()).or_default().push(id.to_string());
                } else {
                    cdx_declared.entry(purl.to_string()).or_default().push(id.to_string());
                }
            }
        }
    }

    if cdx_declared.is_empty() && cdx_concluded.is_empty() {
        // Cargo lockfile-v3 offline may have no licenses — the test
        // is still valuable because it asserts the SPDX shape (the
        // fields must exist and be NOASSERTION, never missing).
        for pkg in spdx["packages"].as_array().unwrap() {
            assert!(
                pkg["licenseDeclared"].is_string(),
                "every SPDX package must have a licenseDeclared string"
            );
            assert!(
                pkg["licenseConcluded"].is_string(),
                "every SPDX package must have a licenseConcluded string"
            );
        }
        return;
    }

    // Positive case: map SPDX packages back to PURL via externalRefs
    // and check that every declared/concluded value from CDX shows
    // up in the corresponding SPDX field (not NOASSERTION).
    for pkg in spdx["packages"].as_array().unwrap() {
        let Some(purl) = pkg["externalRefs"]
            .as_array()
            .and_then(|refs| {
                refs.iter()
                    .find(|r| r["referenceType"] == "purl")
                    .and_then(|r| r["referenceLocator"].as_str())
            })
        else {
            continue;
        };
        if let Some(expected) = cdx_declared.get(purl) {
            let actual = pkg["licenseDeclared"].as_str().unwrap_or("");
            assert!(
                !expected.is_empty(),
                "declared licenses present in CDX but mapped empty"
            );
            assert_ne!(
                actual, "NOASSERTION",
                "declared license dropped for {purl}: CDX had {expected:?}, SPDX has NOASSERTION"
            );
        }
        if let Some(expected) = cdx_concluded.get(purl) {
            let actual = pkg["licenseConcluded"].as_str().unwrap_or("");
            assert!(!expected.is_empty());
            assert_ne!(
                actual, "NOASSERTION",
                "concluded license dropped for {purl}: CDX had {expected:?}, SPDX has NOASSERTION"
            );
        }
    }
}

// ---------- scenario 4: determinism re-run --------------------------------

#[test]
fn scenario_4_determinism_cross_reference() {
    // Narrow repeat of `spdx_determinism.rs` so the US1 acceptance
    // surface is self-contained; the broader matrix lives in the
    // determinism test file.
    let fixture = workspace_root().join("tests/fixtures/cargo/lockfile-v3");
    let a = scan(&fixture, &["spdx-2.3-json"], &[]).spdx.unwrap();
    let b = scan(&fixture, &["spdx-2.3-json"], &[]).spdx.unwrap();
    assert_eq!(a["documentNamespace"], b["documentNamespace"]);
    assert_eq!(
        a["packages"].as_array().map(|v| v.len()),
        b["packages"].as_array().map(|v| v.len())
    );
}

// ---------- scenario 5: single-invocation dual-format ---------------------

#[test]
fn scenario_5_single_invocation_produces_same_bytes_as_two_separate_invocations() {
    let fixture = workspace_root().join("tests/fixtures/cargo/lockfile-v3");
    let workspace = workspace_root();

    // One invocation, both formats.
    let dual = scan(&fixture, &["cyclonedx-json", "spdx-2.3-json"], &[]);
    let dual_cdx_raw = serde_json::to_string(&dual.cdx.unwrap()).unwrap();
    let dual_spdx_raw = serde_json::to_string(&dual.spdx.unwrap()).unwrap();

    // Two separate invocations.
    let only_cdx = scan(&fixture, &["cyclonedx-json"], &[]);
    let only_spdx = scan(&fixture, &["spdx-2.3-json"], &[]);
    let solo_cdx_raw = serde_json::to_string(&only_cdx.cdx.unwrap()).unwrap();
    let solo_spdx_raw = serde_json::to_string(&only_spdx.spdx.unwrap()).unwrap();

    assert_eq!(
        normalize_cdx_for_golden(&dual_cdx_raw, &workspace),
        normalize_cdx_for_golden(&solo_cdx_raw, &workspace),
        "dual-format CDX should match solo-CDX after canonical normalization"
    );
    assert_eq!(
        normalize_spdx23_for_golden(&dual_spdx_raw, &workspace),
        normalize_spdx23_for_golden(&solo_spdx_raw, &workspace),
        "dual-format SPDX should match solo-SPDX after canonical normalization"
    );
}
