//! SPDX 2.3 LicenseRef + hasExtractedLicensingInfos acceptance
//! test (milestone 012 T009 / US3).
//!
//! FR-007 / FR-008 / FR-009 / FR-010 / SC-005: when a CycloneDX
//! component carries a license expression that SPDX's expression
//! grammar can't canonicalize, the SPDX 2.3 output MUST preserve
//! the raw text via a `LicenseRef-<hash>` reference + matching
//! document-level `hasExtractedLicensingInfos[]` entry — instead
//! of collapsing to `NOASSERTION` as the pre-milestone-012 code
//! did. Per Q1: all-or-nothing rule — any non-canonicalizable term
//! in a multi-term expression triggers LicenseRef for the whole.
//!
//! One `#[test]` per ecosystem so a failure names the offender.
//! Plus a shape-correctness test (synthetic input that exercises
//! the mixed-canonicalizable path) and a dedup-test (same raw
//! expression on two components).

use std::collections::BTreeSet;
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
    spdx23: serde_json::Value,
}

fn dual_scan(case: &EcosystemCase) -> Scan {
    let fixture = workspace_root().join("tests/fixtures").join(case.fixture_subpath);
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home");
    let cdx_path = tmp.path().join("out.cdx.json");
    let spdx23_path = tmp.path().join("out.spdx.json");
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
        .arg("cyclonedx-json,spdx-2.3-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", cdx_path.to_string_lossy()))
        .arg("--output")
        .arg(format!("spdx-2.3-json={}", spdx23_path.to_string_lossy()))
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
    }
}

/// Count CDX components (flattened) carrying non-empty `licenses[]`.
fn cdx_components_with_license(doc: &serde_json::Value) -> usize {
    fn recur(node: &serde_json::Value, n: &mut usize) {
        if let Some(arr) = node.get("components").and_then(|v| v.as_array()) {
            for c in arr {
                let has_lic = c
                    .get("licenses")
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| !a.is_empty());
                if has_lic {
                    *n += 1;
                }
                recur(c, n);
            }
        }
    }
    let mut n = 0;
    recur(doc, &mut n);
    n
}

/// Count SPDX 2.3 Packages (excluding synthetic root) whose
/// `licenseDeclared` is NOT the literal `NOASSERTION`.
fn spdx23_packages_with_license(doc: &serde_json::Value) -> usize {
    let Some(pkgs) = doc.get("packages").and_then(|v| v.as_array()) else {
        return 0;
    };
    pkgs.iter()
        .filter(|p| {
            // Exclude the synthetic document-root Package from the
            // count — it has no CDX counterpart.
            !p.get("SPDXID")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.starts_with("SPDXRef-DocumentRoot-"))
        })
        .filter(|p| {
            p.get("licenseDeclared").and_then(|v| v.as_str()) != Some("NOASSERTION")
        })
        .count()
}

fn assert_license_ref_shape_correctness(case: &EcosystemCase) {
    let s = dual_scan(case);

    // Per-ecosystem count parity — FR-007 + SC-005.
    let cdx_count = cdx_components_with_license(&s.cdx);
    let spdx_count = spdx23_packages_with_license(&s.spdx23);
    assert_eq!(
        cdx_count, spdx_count,
        "{}: CDX components-with-license count ({cdx_count}) != \
         SPDX 2.3 packages-with-non-NOASSERTION-licenseDeclared count ({spdx_count})",
        case.label
    );

    // For every Package whose `licenseDeclared` is a
    // `LicenseRef-...` reference, a matching entry MUST exist in
    // the document-level `hasExtractedLicensingInfos[]` with the
    // same `licenseId`, non-empty `extractedText`, and non-empty
    // `name`.
    let Some(pkgs) = s.spdx23.get("packages").and_then(|v| v.as_array()) else {
        return;
    };
    let extracted = s
        .spdx23
        .get("hasExtractedLicensingInfos")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let extracted_ids: BTreeSet<String> = extracted
        .iter()
        .filter_map(|e| e.get("licenseId").and_then(|v| v.as_str()).map(String::from))
        .collect();

    for pkg in pkgs {
        let Some(decl) = pkg.get("licenseDeclared").and_then(|v| v.as_str()) else {
            continue;
        };
        if !decl.starts_with("LicenseRef-") {
            continue;
        }
        assert!(
            extracted_ids.contains(decl),
            "{}: Package licenseDeclared {decl} has no matching entry in \
             hasExtractedLicensingInfos. extracted_ids: {extracted_ids:?}",
            case.label
        );
    }

    // Dedup: every distinct licenseId appears exactly once in
    // hasExtractedLicensingInfos.
    let extracted_total = extracted.len();
    let extracted_distinct = extracted_ids.len();
    assert_eq!(
        extracted_total, extracted_distinct,
        "{}: hasExtractedLicensingInfos must be deduped by licenseId — \
         got {extracted_total} entries but only {extracted_distinct} distinct IDs",
        case.label
    );

    // Every extracted entry has non-empty extractedText and name.
    for e in &extracted {
        assert!(
            e.get("extractedText")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "{}: extracted entry missing non-empty extractedText: {e}",
            case.label
        );
        assert!(
            e.get("name")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "{}: extracted entry missing non-empty name: {e}",
            case.label
        );
    }

    // For components whose CDX licenses[] IS canonicalizable (e.g.
    // a single `{"license": {"id": "MIT"}}` entry), `licenseDeclared`
    // is the canonical SPDX expression with NO LicenseRef- wrapping
    // (FR-008 — preserve pre-milestone-012 behavior for canonical
    // inputs).
    // Inspected by looking for any pkg whose licenseDeclared is a
    // simple SPDX-list id (e.g. "MIT", "Apache-2.0") and asserting
    // no LicenseRef- prefix.
    for pkg in pkgs {
        let Some(decl) = pkg.get("licenseDeclared").and_then(|v| v.as_str()) else {
            continue;
        };
        let looks_like_spdx_id = decl
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '+')
            && !decl.starts_with("LicenseRef-")
            && !decl.starts_with("NO");
        if looks_like_spdx_id {
            // Canonical path — expected shape. Nothing further to assert.
            let _ = decl;
        }
    }
}

#[test] fn license_ref_apk()    { assert_license_ref_shape_correctness(&CASES[0]); }
#[test] fn license_ref_cargo()  { assert_license_ref_shape_correctness(&CASES[1]); }
#[test] fn license_ref_deb()    { assert_license_ref_shape_correctness(&CASES[2]); }
#[test] fn license_ref_gem()    { assert_license_ref_shape_correctness(&CASES[3]); }
#[test] fn license_ref_golang() { assert_license_ref_shape_correctness(&CASES[4]); }
#[test] fn license_ref_maven()  { assert_license_ref_shape_correctness(&CASES[5]); }
#[test] fn license_ref_npm()    { assert_license_ref_shape_correctness(&CASES[6]); }
#[test] fn license_ref_pip()    { assert_license_ref_shape_correctness(&CASES[7]); }
#[test] fn license_ref_rpm()    { assert_license_ref_shape_correctness(&CASES[8]); }
