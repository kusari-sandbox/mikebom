//! Holistic cross-format parity (milestone 013 T010, US1).
//!
//! Spec clarification Q1 + Q2: drive the catalog at
//! `docs/reference/sbom-format-mapping.md`, look up each row's
//! extractor in `mikebom::parity::extractors::EXTRACTORS`, and for
//! every universal-parity row assert that the three formats carry
//! the same observable values (per the row's `Directionality`).
//!
//! One `#[test]` per ecosystem (9) + one for the synthetic
//! container-image fixture from `dual_format_perf::build_benchmark_fixture`.
//! Each test runs a single triple-format scan
//! (`--format cyclonedx-json,spdx-2.3-json,spdx-3-json`) so the
//! cross-format comparison is on outputs from one canonical
//! traversal.

mod dual_format_perf;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use mikebom::parity::{catalog, extractors};


mod common;
use common::{workspace_root, EcosystemCase, CASES};

fn mapping_doc_path() -> PathBuf {
    workspace_root().join("docs/reference/sbom-format-mapping.md")
}struct TripleScan {
    cdx: serde_json::Value,
    spdx23: serde_json::Value,
    spdx3: serde_json::Value,
}

enum InputKind {
    Path,
    Image,
}

fn triple_scan_at_path(
    label: &str,
    fixture: &PathBuf,
    deb_codename: Option<&str>,
    input: InputKind,
) -> TripleScan {
    assert!(
        fixture.exists(),
        "fixture missing for {label}: {}",
        fixture.display()
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home");
    let cdx_path = tmp.path().join("out.cdx.json");
    let spdx23_path = tmp.path().join("out.spdx.json");
    let spdx3_path = tmp.path().join("out.spdx3.json");
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let mut cmd = Command::new(bin);
    let input_flag = match input {
        InputKind::Path => "--path",
        InputKind::Image => "--image",
    };
    cmd.env("HOME", fake_home.path())
        .env("M2_REPO", fake_home.path().join("no-m2-repo"))
        .env("MAVEN_HOME", fake_home.path().join("no-maven-home"))
        .env("GOPATH", fake_home.path().join("no-gopath"))
        .env("GOMODCACHE", fake_home.path().join("no-gomodcache"))
        .env("CARGO_HOME", fake_home.path().join("no-cargo-home"))
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg(input_flag)
        .arg(fixture)
        .arg("--format")
        .arg("cyclonedx-json,spdx-2.3-json,spdx-3-json")
        .arg("--output")
        .arg(format!("cyclonedx-json={}", cdx_path.to_string_lossy()))
        .arg("--output")
        .arg(format!("spdx-2.3-json={}", spdx23_path.to_string_lossy()))
        .arg("--output")
        .arg(format!("spdx-3-json={}", spdx3_path.to_string_lossy()))
        .arg("--no-deep-hash");
    if let Some(code) = deb_codename {
        cmd.arg("--deb-codename").arg(code);
    }
    let out = cmd.output().expect("mikebom runs");
    assert!(
        out.status.success(),
        "scan failed for {label}: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let read = |p: &PathBuf| -> serde_json::Value {
        let s = std::fs::read_to_string(p)
            .unwrap_or_else(|e| panic!("{label}: read {} failed: {e}", p.display()));
        serde_json::from_str(&s)
            .unwrap_or_else(|e| panic!("{label}: parse {} failed: {e}", p.display()))
    };
    TripleScan {
        cdx: read(&cdx_path),
        spdx23: read(&spdx23_path),
        spdx3: read(&spdx3_path),
    }
}

fn assert_holistic_parity(label: &str, scan: &TripleScan) {
    let rows = catalog::parse_mapping_doc(&mapping_doc_path());
    assert!(
        !rows.is_empty(),
        "{label}: catalog parse returned zero rows; mapping doc path or parser is broken"
    );

    let mut universal_count = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for row in &rows {
        let classification = row.classification();
        if !classification.is_universal_parity() {
            continue;
        }
        let extractor = extractors::EXTRACTORS
            .iter()
            .find(|e| e.row_id == row.id)
            .unwrap_or_else(|| {
                panic!(
                    "{label}: catalog row {} ({}) is universal-parity but has no entry in EXTRACTORS",
                    row.id, row.label
                )
            });
        universal_count += 1;

        let cdx_set = (extractor.cdx)(&scan.cdx);
        let spdx23_set = (extractor.spdx23)(&scan.spdx23);
        let spdx3_set = (extractor.spdx3)(&scan.spdx3);

        match extractor.directional {
            extractors::Directionality::SymmetricEqual => {
                let three_way_equal = cdx_set == spdx23_set && spdx23_set == spdx3_set;
                if !three_way_equal {
                    let only_cdx: BTreeSet<_> =
                        cdx_set.difference(&spdx23_set).cloned().collect();
                    let only_spdx23: BTreeSet<_> =
                        spdx23_set.difference(&cdx_set).cloned().collect();
                    let only_spdx3: BTreeSet<_> =
                        spdx3_set.difference(&cdx_set).cloned().collect();
                    failures.push(format!(
                        "  {} ({}) [SymmetricEqual]\n    CDX={cdx_set:?}\n    SPDX2.3={spdx23_set:?}\n    SPDX3={spdx3_set:?}\n    only-in-CDX vs SPDX2.3: {only_cdx:?}\n    only-in-SPDX2.3: {only_spdx23:?}\n    only-in-SPDX3 vs CDX: {only_spdx3:?}",
                        row.id, row.label
                    ));
                }
            }
            extractors::Directionality::CdxSubsetOfSpdx => {
                let cdx_subset_spdx23 = cdx_set.is_subset(&spdx23_set);
                let cdx_subset_spdx3 = cdx_set.is_subset(&spdx3_set);
                if !(cdx_subset_spdx23 && cdx_subset_spdx3) {
                    let missing_spdx23: BTreeSet<_> =
                        cdx_set.difference(&spdx23_set).cloned().collect();
                    let missing_spdx3: BTreeSet<_> =
                        cdx_set.difference(&spdx3_set).cloned().collect();
                    failures.push(format!(
                        "  {} ({}) [CdxSubsetOfSpdx]\n    CDX={cdx_set:?}\n    SPDX2.3={spdx23_set:?}\n    SPDX3={spdx3_set:?}\n    in-CDX-not-in-SPDX2.3: {missing_spdx23:?}\n    in-CDX-not-in-SPDX3: {missing_spdx3:?}",
                        row.id, row.label
                    ));
                }
            }
            extractors::Directionality::PresenceOnly => {
                let any_present =
                    !cdx_set.is_empty() || !spdx23_set.is_empty() || !spdx3_set.is_empty();
                if any_present {
                    let all_present =
                        !cdx_set.is_empty() && !spdx23_set.is_empty() && !spdx3_set.is_empty();
                    if !all_present {
                        failures.push(format!(
                            "  {} ({}) [PresenceOnly]\n    CDX-empty={} SPDX2.3-empty={} SPDX3-empty={}\n    CDX={cdx_set:?}\n    SPDX2.3={spdx23_set:?}\n    SPDX3={spdx3_set:?}",
                            row.id,
                            row.label,
                            cdx_set.is_empty(),
                            spdx23_set.is_empty(),
                            spdx3_set.is_empty()
                        ));
                    }
                }
            }
        }
    }

    assert!(
        universal_count > 0,
        "{label}: catalog parsed but produced zero universal-parity rows; classification is broken"
    );

    if !failures.is_empty() {
        panic!(
            "{label}: holistic parity failed for {} of {} universal-parity rows:\n{}",
            failures.len(),
            universal_count,
            failures.join("\n")
        );
    }
}

fn run_ecosystem(case: &EcosystemCase) {
    let fixture = workspace_root()
        .join("tests/fixtures")
        .join(case.fixture_subpath);
    let scan = triple_scan_at_path(case.label, &fixture, case.deb_codename, InputKind::Path);
    assert_holistic_parity(case.label, &scan);
}

#[test] fn parity_apk()    { run_ecosystem(&CASES[0]); }
#[test] fn parity_cargo()  { run_ecosystem(&CASES[1]); }
#[test] fn parity_deb()    { run_ecosystem(&CASES[2]); }
#[test] fn parity_gem()    { run_ecosystem(&CASES[3]); }
#[test] fn parity_golang() { run_ecosystem(&CASES[4]); }
#[test] fn parity_maven()  { run_ecosystem(&CASES[5]); }
#[test] fn parity_npm()    { run_ecosystem(&CASES[6]); }
#[test] fn parity_pip()    { run_ecosystem(&CASES[7]); }
#[test] fn parity_rpm()    { run_ecosystem(&CASES[8]); }

#[test]
fn parity_synthetic_container_image() {
    let (_keep_alive, image_path) = dual_format_perf::build_benchmark_fixture();
    let scan = triple_scan_at_path(
        "synthetic-container-image",
        &image_path,
        None,
        InputKind::Image,
    );
    assert_holistic_parity("synthetic-container-image", &scan);
}
