//! Integration tests for the RPM ecosystem (milestone 003 US2).

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures/rpm")
        .join(sub)
}

fn scan_path(path: &Path) -> (String, serde_json::Value) {
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_path = tmp.path().join("sbom.cdx.json");
    let output = Command::new(bin)
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(path)
        .arg("--output")
        .arg(&out_path)
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom should run");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "scan failed: stderr={stderr}",
    );
    let raw = std::fs::read_to_string(&out_path).expect("read sbom");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    (stderr, json)
}

fn rpm_purls(sbom: &serde_json::Value) -> Vec<String> {
    sbom["components"]
        .as_array()
        .expect("components array")
        .iter()
        .filter_map(|c| {
            let p = c["purl"].as_str()?;
            if p.starts_with("pkg:rpm/") {
                Some(p.to_string())
            } else {
                None
            }
        })
        .collect()
}

// --- T044: RHEL fixture emits canonical PURLs --------------------------

#[test]
fn scan_rpm_rhel_fixture_emits_canonical_purls() {
    let (_stderr, sbom) = scan_path(&fixture("rhel-image"));
    let purls = rpm_purls(&sbom);
    assert!(
        purls.len() >= 10,
        "expected ≥10 rpm components from rhel fixture, got {}: {purls:?}",
        purls.len(),
    );
    for p in &purls {
        assert!(
            p.starts_with("pkg:rpm/redhat/"),
            "expected pkg:rpm/redhat/... PURL, got {p}",
        );
    }
    // aggregate=complete for rpm.
    let compositions = sbom["compositions"].as_array();
    assert!(
        compositions.is_some_and(|c| c.iter().any(|comp| {
            comp["aggregate"].as_str() == Some("complete")
                && comp["assemblies"]
                    .as_array()
                    .map(|asm| {
                        asm.iter()
                            .any(|s| s.as_str().unwrap_or("").starts_with("pkg:rpm/"))
                    })
                    .unwrap_or(false)
        })),
        "rpm aggregate=complete composition expected",
    );
}

// --- T045: vendor mapping across distros -------------------------------

#[test]
fn scan_rpm_vendor_mapping_across_distros() {
    for (sub, expected_vendor) in [
        ("rocky-image", "rocky"),
        ("amzn-image", "amazon"),
        ("opensuse-image", "opensuse"),
    ] {
        let (_stderr, sbom) = scan_path(&fixture(sub));
        let purls = rpm_purls(&sbom);
        assert!(!purls.is_empty(), "no rpm components for {sub}");
        for p in &purls {
            let prefix = format!("pkg:rpm/{expected_vendor}/");
            assert!(
                p.starts_with(&prefix),
                "{sub}: expected vendor {expected_vendor}, got {p}",
            );
        }
    }
}

// --- T046: BDB-only rootfs diagnoses and emits zero -------------------

#[test]
fn scan_rpm_bdb_diagnoses_and_emits_zero() {
    let (stderr, sbom) = scan_path(&fixture("bdb-only"));
    let purls = rpm_purls(&sbom);
    assert!(purls.is_empty(), "expected zero rpm components; got {purls:?}");
    assert!(
        stderr.contains("legacy rpmdb") || stderr.contains("Berkeley DB"),
        "stderr missing BDB diagnostic: {stderr}",
    );
}

// --- T047: depends edges resolve to observed PURLs --------------------

#[test]
fn scan_rpm_depends_edges_resolve_to_observed_purls() {
    let (_stderr, sbom) = scan_path(&fixture("rhel-image"));
    let deps = sbom["dependencies"]
        .as_array()
        .expect("dependencies array");
    // Our fixture has curl depending on openssl-libs; confirm the edge
    // appears after dep resolution.
    let curl_deps = deps
        .iter()
        .find(|d| {
            d["ref"]
                .as_str()
                .is_some_and(|s| s.contains("/curl@"))
        });
    assert!(
        curl_deps.is_some(),
        "no dependencies entry for curl: {}",
        serde_json::to_string_pretty(deps).unwrap_or_default(),
    );
    let curl_targets: Vec<&str> = curl_deps
        .unwrap()
        ["dependsOn"]
        .as_array()
        .map(|a| a.iter().filter_map(|s| s.as_str()).collect())
        .unwrap_or_default();
    assert!(
        curl_targets.iter().any(|t| t.contains("openssl-libs")),
        "curl dependency edge missing openssl-libs: {curl_targets:?}",
    );
}
