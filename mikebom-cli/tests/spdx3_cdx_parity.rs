//! CDX ↔ SPDX 3 native-field parity (milestone 011 T009).
//!
//! SC-003 / FR-017: "For every ecosystem, every component that
//! appears in the CycloneDX output for a given scan appears as
//! exactly one SPDX 3 Package in the SPDX 3 output for the same
//! scan, with matching PURL and checksum values."
//!
//! Runs one dual-format scan per ecosystem (exercising the FR-004
//! single-pass guarantee for cdx + spdx-3 simultaneously) and
//! verifies:
//!   (1) every CDX `component.purl` is the `identifier` of an
//!       SPDX 3 `ExternalIdentifier[packageUrl]` entry on exactly
//!       one Package; Package's `software_packageUrl` matches.
//!   (2) version parity: `component.version` == Package's
//!       `software_packageVersion`.
//!   (3) checksum-set parity: the set of `{algorithm, hashValue}`
//!       tuples on Package's `verifiedUsing[]` equals the set of
//!       `{alg, content}` tuples on CDX `component.hashes[]`
//!       (after alg normalization: CDX "SHA-256" → "SHA256").
//!
//! Skip-synthetic-root rule: Packages whose spdxId starts with
//! `<doc>/pkg-root-` are synthesized roots that don't correspond
//! to any CDX component; they're excluded from the reverse walk.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[derive(Clone, Copy)]
struct EcosystemCase {
    label: &'static str,
    fixture_subpath: &'static str,
    deb_codename: Option<&'static str>,
}

const CASES: &[EcosystemCase] = &[
    EcosystemCase { label: "apk",    fixture_subpath: "apk/synthetic",         deb_codename: None },
    EcosystemCase { label: "cargo",  fixture_subpath: "cargo/lockfile-v3",     deb_codename: None },
    EcosystemCase { label: "deb",    fixture_subpath: "deb/synthetic",         deb_codename: Some("bookworm") },
    EcosystemCase { label: "gem",    fixture_subpath: "gem/simple-bundle",     deb_codename: None },
    EcosystemCase { label: "golang", fixture_subpath: "go/simple-module",      deb_codename: None },
    EcosystemCase { label: "maven",  fixture_subpath: "maven/pom-three-deps",  deb_codename: None },
    EcosystemCase { label: "npm",    fixture_subpath: "npm/node-modules-walk", deb_codename: None },
    EcosystemCase { label: "pip",    fixture_subpath: "python/simple-venv",    deb_codename: None },
    EcosystemCase { label: "rpm",    fixture_subpath: "rpm/bdb-only",          deb_codename: None },
];

struct Scan {
    cdx: serde_json::Value,
    spdx3: serde_json::Value,
}

fn dual_scan(case: &EcosystemCase) -> Scan {
    let fixture = workspace_root().join("tests/fixtures").join(case.fixture_subpath);
    assert!(
        fixture.exists(),
        "fixture missing for {}: {}",
        case.label,
        fixture.display()
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home");
    let cdx_path = tmp.path().join("out.cdx.json");
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
        .arg("cyclonedx-json,spdx-3-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", cdx_path.to_string_lossy()))
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
            .expect("cdx is valid JSON"),
        spdx3: serde_json::from_str(&std::fs::read_to_string(&spdx3_path).unwrap())
            .expect("spdx3 is valid JSON"),
    }
}

/// Collect every CDX `component.purl`, including those nested
/// under `component.components[]` (shade-jar children, image-layer
/// nested shapes).
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

/// Index SPDX 3 Packages by the `identifier` of each
/// `ExternalIdentifier[packageUrl]` entry.
fn index_spdx3_by_purl(
    doc: &serde_json::Value,
) -> HashMap<String, &serde_json::Value> {
    let mut map: HashMap<String, &serde_json::Value> = HashMap::new();
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return map;
    };
    for el in graph {
        if el.get("type").and_then(|v| v.as_str()) != Some("software_Package") {
            continue;
        }
        let Some(ext_ids) = el.get("externalIdentifier").and_then(|v| v.as_array()) else {
            continue;
        };
        for entry in ext_ids {
            if entry.get("externalIdentifierType").and_then(|v| v.as_str())
                != Some("packageUrl")
            {
                continue;
            }
            let Some(id) = entry.get("identifier").and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some(prev) = map.insert(id.to_string(), el) {
                panic!(
                    "PURL {id} mapped to two SPDX 3 packages: {:?} and {:?}",
                    prev.get("spdxId"),
                    el.get("spdxId")
                );
            }
        }
    }
    map
}

/// CDX hash-algorithm names (`"SHA-256"`, `"SHA-1"`) → SPDX 3
/// Hash.algorithm enum form (lowercase, no hyphens — `"sha256"`,
/// `"sha1"`). Matches `prop_Hash_algorithm` in the bundled schema.
fn normalize_alg(cdx_alg: &str) -> String {
    cdx_alg.replace('-', "").to_lowercase()
}

fn assert_parity(case: &EcosystemCase) {
    let s = dual_scan(case);
    let spdx3_by_purl = index_spdx3_by_purl(&s.spdx3);
    let cdx_components = walk_cdx_components(&s.cdx);

    for c in &cdx_components {
        let Some(purl) = c.get("purl").and_then(|v| v.as_str()) else {
            continue;
        };
        let pkg = spdx3_by_purl.get(purl).unwrap_or_else(|| {
            let keys: Vec<&String> = spdx3_by_purl.keys().collect();
            panic!(
                "{}: CDX PURL {purl} has no matching SPDX 3 Package. \
                 SPDX 3 indexed {} packages via externalIdentifier[packageUrl]: {:?}",
                case.label,
                keys.len(),
                keys
            );
        });

        // (1b) software_packageUrl matches PURL byte-for-byte.
        let pkg_purl = pkg
            .get("software_packageUrl")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(
            purl, pkg_purl,
            "{}: software_packageUrl drift for {purl}: expected {purl:?} got {pkg_purl:?}",
            case.label
        );

        // (2) version parity.
        let cdx_version = c.get("version").and_then(|v| v.as_str()).unwrap_or("");
        let spdx3_version = pkg
            .get("software_packageVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(
            cdx_version, spdx3_version,
            "{}: version drift for {purl}: CDX {cdx_version:?} vs SPDX 3 {spdx3_version:?}",
            case.label
        );

        // (3) checksum-set parity.
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
        let spdx3_checksums: BTreeSet<(String, String)> = pkg
            .get("verifiedUsing")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|h| {
                        let alg = h.get("algorithm").and_then(|v| v.as_str())?;
                        let val = h.get("hashValue").and_then(|v| v.as_str())?;
                        Some((alg.to_string(), val.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            cdx_checksums, spdx3_checksums,
            "{}: checksum-set drift for {purl}:\n  CDX: {cdx_checksums:?}\n  SPDX 3: {spdx3_checksums:?}",
            case.label
        );
    }

    // (1, reverse): every SPDX 3 Package (that isn't the synthetic
    // root) corresponds to exactly one CDX component.
    let cdx_purls: BTreeSet<String> = cdx_components
        .iter()
        .filter_map(|c| c.get("purl").and_then(|v| v.as_str()).map(String::from))
        .collect();
    for (purl, pkg) in &spdx3_by_purl {
        let is_synthetic_root = pkg
            .get("spdxId")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.contains("/pkg-root-"));
        if is_synthetic_root {
            continue;
        }
        assert!(
            cdx_purls.contains(purl),
            "{}: SPDX 3 Package {} has PURL {purl} with no matching CDX component",
            case.label,
            pkg.get("spdxId")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing spdxId>")
        );
    }
}

#[test] fn parity_apk()    { assert_parity(&CASES[0]); }
#[test] fn parity_cargo()  { assert_parity(&CASES[1]); }
#[test] fn parity_deb()    { assert_parity(&CASES[2]); }
#[test] fn parity_gem()    { assert_parity(&CASES[3]); }
#[test] fn parity_golang() { assert_parity(&CASES[4]); }
#[test] fn parity_maven()  { assert_parity(&CASES[5]); }
#[test] fn parity_npm()    { assert_parity(&CASES[6]); }
#[test] fn parity_pip()    { assert_parity(&CASES[7]); }
#[test] fn parity_rpm()    { assert_parity(&CASES[8]); }
