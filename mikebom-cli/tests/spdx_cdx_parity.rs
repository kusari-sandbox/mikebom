//! Native-field parity guard (milestone 010 T028).
//!
//! SC-003: "For every ecosystem, every component that appears in the
//! CycloneDX output for a given scan appears as exactly one SPDX
//! Package in the SPDX output for the same scan, with matching PURL
//! and checksum values."
//!
//! This test runs a single dual-format scan per ecosystem — exercising
//! the FR-004 single-pass guarantee at the same time — and verifies:
//!
//!   (1) every CDX `component.purl` is the `referenceLocator` of
//!       exactly one SPDX package's `externalRefs[PACKAGE-MANAGER/purl]`
//!       entry.
//!   (2) for each matched pair, `component.version` == `versionInfo`
//!       (byte-identical string).
//!   (3) for each matched pair, the set of `{algorithm, value}`
//!       checksum tuples is identical. CDX `alg` normalizes "SHA-256"
//!       → "SHA256" (drop hyphen, uppercase) to match SPDX's enum form.
//!
//! Currently green on US1's native surface. Any future change that
//! drops or renames one of these fields in either format trips the
//! test. Phase 4 (US2) will add `mikebom-cli/tests/spdx_annotation_fidelity.rs`
//! alongside this file to cover the annotation-fidelity half of the
//! data-placement contract; the two tests together answer the
//! "same info?" question for the whole surface.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::process::Command;

mod common;
use common::{workspace_root, EcosystemCase, CASES};

struct Scan {
    cdx: serde_json::Value,
    spdx: serde_json::Value,
}

/// Run `mikebom sbom scan --format cyclonedx-json,spdx-2.3-json`
/// against a fixture (single invocation) and return both parsed docs.
fn dual_scan(case: &EcosystemCase) -> Scan {
    let fixture = workspace_root().join("tests/fixtures").join(case.fixture_subpath);
    assert!(
        fixture.exists(),
        "fixture missing for {}: {}",
        case.label,
        fixture.display()
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let cdx_path = tmp.path().join("out.cdx.json");
    let spdx_path = tmp.path().join("out.spdx.json");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let mut cmd = Command::new(bin);
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(&fixture)
        .arg("--format")
        .arg("cyclonedx-json,spdx-2.3-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", cdx_path.to_string_lossy()))
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
    Scan {
        cdx: serde_json::from_str(&std::fs::read_to_string(&cdx_path).unwrap())
            .expect("cdx valid JSON"),
        spdx: serde_json::from_str(&std::fs::read_to_string(&spdx_path).unwrap())
            .expect("spdx valid JSON"),
    }
}

/// Collect every CDX `component.purl`, including those nested under
/// `component.components[]` (shade-jar children, image-layer nested
/// shapes — FR-011 containment is flattened in SPDX, so both
/// top-level and nested CDX entries must land in SPDX packages).
fn walk_cdx_components(doc: &serde_json::Value) -> Vec<&serde_json::Value> {
    fn recur<'a>(node: &'a serde_json::Value, out: &mut Vec<&'a serde_json::Value>) {
        if let Some(arr) = node.get("components").and_then(|v| v.as_array()) {
            for c in arr {
                out.push(c);
                recur(c, out);
            }
        }
    }
    let mut out = Vec::new();
    recur(doc, &mut out);
    out
}

/// Build a PURL → SPDX Package lookup for an SPDX 2.3 document.
/// A package is indexed by the `referenceLocator` of each
/// `externalRefs[]` entry whose `referenceType` is `"purl"` (there is
/// exactly one such entry per Package in our current emitter — the
/// PackageManager externalRef from T023).
fn index_spdx_by_purl(doc: &serde_json::Value) -> HashMap<String, &serde_json::Value> {
    let mut map: HashMap<String, &serde_json::Value> = HashMap::new();
    let Some(pkgs) = doc.get("packages").and_then(|v| v.as_array()) else {
        return map;
    };
    for pkg in pkgs {
        let Some(refs) = pkg.get("externalRefs").and_then(|v| v.as_array()) else {
            continue;
        };
        for r in refs {
            if r.get("referenceType").and_then(|v| v.as_str()) != Some("purl") {
                continue;
            }
            let Some(loc) = r.get("referenceLocator").and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some(prev) = map.insert(loc.to_string(), pkg) {
                panic!(
                    "PURL {loc} mapped to two SPDX packages: {:?} and {:?}",
                    prev.get("SPDXID"),
                    pkg.get("SPDXID")
                );
            }
        }
    }
    map
}

/// Normalize a CDX hash-algorithm name (`"SHA-256"`, `"SHA-512"`,
/// `"SHA-1"`, `"MD5"`) to the SPDX enum form (`"SHA256"`, `"SHA512"`,
/// `"SHA1"`, `"MD5"`). The two formats use the same letters; only
/// punctuation and case differ.
fn normalize_alg(cdx_alg: &str) -> String {
    cdx_alg.replace('-', "").to_uppercase()
}

fn assert_parity(case: &EcosystemCase) {
    let s = dual_scan(case);
    let spdx_by_purl = index_spdx_by_purl(&s.spdx);
    let cdx_components = walk_cdx_components(&s.cdx);

    for c in &cdx_components {
        let Some(purl) = c.get("purl").and_then(|v| v.as_str()) else {
            continue; // CDX shouldn't emit a component without a purl, but be defensive
        };
        let pkg = spdx_by_purl.get(purl).unwrap_or_else(|| {
            let keys: Vec<&String> = spdx_by_purl.keys().collect();
            panic!(
                "{}: CDX PURL {purl} has no matching SPDX package. \
                 SPDX carries {} packages via externalRefs[purl]: {:?}",
                case.label,
                keys.len(),
                keys
            );
        });

        // (2) Version parity.
        let cdx_version = c.get("version").and_then(|v| v.as_str()).unwrap_or("");
        let spdx_version = pkg.get("versionInfo").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(
            cdx_version, spdx_version,
            "{}: version drift for {purl}: CDX {cdx_version:?} vs SPDX {spdx_version:?}",
            case.label
        );

        // (3) Checksum-set parity.
        let cdx_checksums: BTreeSet<(String, String)> = c
            .get("hashes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|h| {
                        let alg = h.get("alg").and_then(|v| v.as_str())?;
                        let content = h.get("content").and_then(|v| v.as_str())?;
                        Some((normalize_alg(alg), content.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let spdx_checksums: BTreeSet<(String, String)> = pkg
            .get("checksums")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| {
                        let alg = c.get("algorithm").and_then(|v| v.as_str())?;
                        let val = c.get("checksumValue").and_then(|v| v.as_str())?;
                        Some((alg.to_string(), val.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            cdx_checksums, spdx_checksums,
            "{}: checksum-set drift for {purl}: \n  CDX: {:?}\n  SPDX: {:?}",
            case.label, cdx_checksums, spdx_checksums
        );
    }

    // (1, reverse): every SPDX package that is NOT the synthetic
    // document root should correspond to exactly one CDX component.
    // The synthetic root now carries a synthesized
    // `pkg:generic/<target>@0.0.0` PURL + a synthesized
    // `cpe:2.3:a:mikebom:<target>:0.0.0:*` CPE externalRef (so
    // sbomqs's comp_with_purl / comp_with_cpe features don't dock
    // the document for a missing-identity component). That PURL is
    // SPDX-only — CDX emits the scan subject as
    // `metadata.component`, not as a `components[]` entry — so skip
    // synthetic-root SPDXIDs when walking the SPDX → CDX direction.
    let cdx_purls: BTreeSet<String> = cdx_components
        .iter()
        .filter_map(|c| c.get("purl").and_then(|v| v.as_str()).map(String::from))
        .collect();
    for (purl, pkg) in &spdx_by_purl {
        let is_synthetic_root = pkg
            .get("SPDXID")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.starts_with("SPDXRef-DocumentRoot-"));
        if is_synthetic_root {
            continue;
        }
        assert!(
            cdx_purls.contains(purl),
            "{}: SPDX package {} has PURL {purl} with no matching CDX component",
            case.label,
            pkg.get("SPDXID")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing SPDXID>")
        );
    }
}

// One test per ecosystem so a failure names the offender.

#[test]
fn parity_apk() {
    assert_parity(&CASES[0]);
}

#[test]
fn parity_cargo() {
    assert_parity(&CASES[1]);
}

#[test]
fn parity_deb() {
    assert_parity(&CASES[2]);
}

#[test]
fn parity_gem() {
    assert_parity(&CASES[3]);
}

#[test]
fn parity_golang() {
    assert_parity(&CASES[4]);
}

#[test]
fn parity_maven() {
    assert_parity(&CASES[5]);
}

#[test]
fn parity_npm() {
    assert_parity(&CASES[6]);
}

#[test]
fn parity_pip() {
    assert_parity(&CASES[7]);
}

#[test]
fn parity_rpm() {
    assert_parity(&CASES[8]);
}

// Silence an unused-import lint when compiled in isolation.
#[allow(dead_code)]
fn _noop_touch(_p: &Path) {}
