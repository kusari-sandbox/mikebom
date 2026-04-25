//! SPDX 3 CPE coverage acceptance test (milestone 012 T002 / US1).
//!
//! FR-001 / FR-002 / FR-003 / SC-001: the SPDX 3 output MUST emit
//! one `software_Package.externalIdentifier[]` entry with
//! `externalIdentifierType: "cpe23"` for every CPE the CycloneDX
//! output emits on the same scan, for every ecosystem in the test
//! matrix. Pre-milestone-012, `is_fully_resolved_cpe23` in
//! `v3_external_ids.rs` rejected CPEs with `update=*` (which is
//! ~every synthesized CPE) — this test locks the post-fix
//! behavior.
//!
//! One `#[test]` per ecosystem so a failure names the offender.

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
            .expect("cdx valid JSON"),
        spdx3: serde_json::from_str(&std::fs::read_to_string(&spdx3_path).unwrap())
            .expect("spdx3 valid JSON"),
    }
}

/// Collect every `component.cpe` value (including nested
/// components) from a CycloneDX document.
fn cdx_cpes(doc: &serde_json::Value) -> Vec<String> {
    fn recur(node: &serde_json::Value, out: &mut Vec<String>) {
        if let Some(arr) = node.get("components").and_then(|v| v.as_array()) {
            for c in arr {
                if let Some(cpe) = c.get("cpe").and_then(|v| v.as_str()) {
                    out.push(cpe.to_string());
                }
                recur(c, out);
            }
        }
    }
    let mut out = Vec::new();
    recur(doc, &mut out);
    out
}

/// Collect every `cpe23` ExternalIdentifier identifier value from
/// a SPDX 3 document's `software_Package` elements.
fn spdx3_cpes(doc: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) else {
        return out;
    };
    for el in graph {
        if el.get("type").and_then(|v| v.as_str()) != Some("software_Package") {
            continue;
        }
        let Some(ext_ids) = el.get("externalIdentifier").and_then(|v| v.as_array())
        else {
            continue;
        };
        for entry in ext_ids {
            if entry.get("externalIdentifierType").and_then(|v| v.as_str())
                == Some("cpe23")
            {
                if let Some(id) = entry.get("identifier").and_then(|v| v.as_str()) {
                    out.push(id.to_string());
                }
            }
        }
    }
    out
}

fn assert_cpe_parity(case: &EcosystemCase) {
    let s = dual_scan(case);
    let cdx_set: std::collections::BTreeSet<String> =
        cdx_cpes(&s.cdx).into_iter().collect();
    let spdx3_set: std::collections::BTreeSet<String> =
        spdx3_cpes(&s.spdx3).into_iter().collect();

    // FR-001 (directional CDX → SPDX 3): every CDX `component.cpe`
    // value MUST appear as a `cpe23` ExternalIdentifier in SPDX 3.
    // This is the load-bearing invariant — the pre-milestone-012 bug
    // dropped ~every CPE; post-fix the directional containment must
    // hold. Note: SPDX 3 may carry MORE CPEs than CDX, because
    // CycloneDX's `component.cpe` is single-valued (primary candidate
    // only; the full candidate set lives in a `mikebom:cpe-candidates`
    // CDX property), while SPDX 3 per FR-003 emits every fully-
    // resolved candidate as a separate ExternalIdentifier entry.
    for cdx_cpe in &cdx_set {
        assert!(
            spdx3_set.contains(cdx_cpe),
            "{}: CDX CPE {cdx_cpe} has no matching SPDX 3 ExternalIdentifier[cpe23]. \
             SPDX 3 carries {} cpe23 entries; CDX carries {}.",
            case.label,
            spdx3_set.len(),
            cdx_set.len()
        );
    }

    // Lower-bound sanity: SPDX 3 count must be ≥ CDX count. A count
    // below CDX's means entries got dropped.
    assert!(
        spdx3_set.len() >= cdx_set.len(),
        "{}: SPDX 3 CPE count {} must be ≥ CDX CPE count {} — entries dropped",
        case.label,
        spdx3_set.len(),
        cdx_set.len()
    );
}

#[test] fn cpe_apk()    { assert_cpe_parity(&CASES[0]); }
#[test] fn cpe_cargo()  { assert_cpe_parity(&CASES[1]); }
#[test] fn cpe_deb()    { assert_cpe_parity(&CASES[2]); }
#[test] fn cpe_gem()    { assert_cpe_parity(&CASES[3]); }
#[test] fn cpe_golang() { assert_cpe_parity(&CASES[4]); }
#[test] fn cpe_maven()  { assert_cpe_parity(&CASES[5]); }
#[test] fn cpe_npm()    { assert_cpe_parity(&CASES[6]); }
#[test] fn cpe_pip()    { assert_cpe_parity(&CASES[7]); }
#[test] fn cpe_rpm()    { assert_cpe_parity(&CASES[8]); }
