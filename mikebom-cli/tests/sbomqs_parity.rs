//! sbomqs cross-format scoring (milestone 010 T055 / SC-001).
//!
//! Spec: for each of the 9 supported ecosystems, `sbomqs score`
//! against mikebom's SPDX 2.3 output MUST meet or beat the score
//! against its CycloneDX output on the features both formats
//! express natively (NTIA-minimum: name, version, supplier,
//! checksums, license, PURL, CPE, spec-conformance).
//!
//! Discovery gate: `sbomqs` is an external Go binary that isn't
//! vendored in the tree. CI provisions it in a setup step (see
//! `.github/workflows/ci.yml`); local runs pick it up from `$PATH`
//! or `MIKEBOM_SBOMQS_BIN=<abs-path>`. When the binary is not
//! available the test exits cleanly with an informational skip
//! rather than failing — this keeps the test non-blocking for
//! devs who haven't installed sbomqs while still enforcing SC-001
//! in CI.
//!
//! The NTIA-minimum category subset mikebom expects parity on:
//! `sbomqs score` emits per-category numerical scores; we parse the
//! JSON output (`sbomqs score --json`), extract the categories we
//! care about, and assert `spdx ≥ cdx` on each.

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Locate `sbomqs`. Env var overrides the `$PATH` lookup.
fn sbomqs_bin() -> Option<PathBuf> {
    if let Ok(env) = std::env::var("MIKEBOM_SBOMQS_BIN") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
    }
    // `which` via `Command`'s PATH search. Plain `Command::new` on a
    // non-existent binary returns `NotFound` from `spawn`, which we
    // treat as "skip the test" rather than "fail".
    Command::new("sbomqs")
        .arg("--help")
        .output()
        .ok()
        .map(|_| PathBuf::from("sbomqs"))
}

#[derive(Clone, Copy)]
struct EcosystemCase {
    label: &'static str,
    fixture_subpath: &'static str,
    deb_codename: Option<&'static str>,
}

const CASES: &[EcosystemCase] = &[
    EcosystemCase { label: "apk",    fixture_subpath: "apk/synthetic",        deb_codename: None },
    EcosystemCase { label: "cargo",  fixture_subpath: "cargo/lockfile-v3",    deb_codename: None },
    EcosystemCase { label: "deb",    fixture_subpath: "deb/synthetic",        deb_codename: Some("bookworm") },
    EcosystemCase { label: "gem",    fixture_subpath: "gem/simple-bundle",    deb_codename: None },
    EcosystemCase { label: "golang", fixture_subpath: "go/simple-module",     deb_codename: None },
    EcosystemCase { label: "maven",  fixture_subpath: "maven/pom-three-deps", deb_codename: None },
    EcosystemCase { label: "npm",    fixture_subpath: "npm/node-modules-walk", deb_codename: None },
    EcosystemCase { label: "pip",    fixture_subpath: "python/simple-venv",   deb_codename: None },
    EcosystemCase { label: "rpm",    fixture_subpath: "rpm/bdb-only",         deb_codename: None },
];

/// sbomqs **feature** keys (under the top-level category keys)
/// that express mikebom-significant data natively in both CDX and
/// SPDX. Excludes features sbomqs scores as "N/A (SPDX)" (no
/// equivalent in the SPDX 2.3 spec, not a mikebom gap) and features
/// tied to `component.type` / `primaryPurpose` (SPDX 2.3 has no
/// native home for it; annotations don't score).
///
/// Source: `sbomqs score --json` feature keys as of sbomqs v2.0.6.
/// Adding / removing keys here is the intended knob when the sbomqs
/// release tracked in CI changes its feature list.
const NATIVE_FEATURES: &[&str] = &[
    // Identification — all three should be 10 in both formats.
    "comp_with_name",
    "comp_with_version",
    "comp_with_local_id",
    // Provenance — authors + supplier at the document level.
    "sbom_authors",
    // Integrity — checksums per component.
    "comp_with_checksums",
    // Licensing — declared + valid license assertions.
    "comp_with_licenses",
    "comp_with_valid_licenses",
    // Vulnerability — PURL + CPE per component.
    "comp_with_purl",
    "comp_with_cpe",
    // Structural — spec/format conformance.
    "sbom_spec",
    "sbom_spec_file_format",
];

fn produce_sboms(
    case: &EcosystemCase,
    tmp: &std::path::Path,
) -> (PathBuf, PathBuf) {
    let fx = workspace_root().join("tests/fixtures").join(case.fixture_subpath);
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let cdx = tmp.join("out.cdx.json");
    let spdx = tmp.join("out.spdx.json");
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
        .arg(format!("cyclonedx-json={}", cdx.to_string_lossy()))
        .arg("--output")
        .arg(format!("spdx-2.3-json={}", spdx.to_string_lossy()))
        .arg("--no-deep-hash");
    if let Some(code) = case.deb_codename {
        cmd.arg("--deb-codename").arg(code);
    }
    let final_out = cmd.output().expect("mikebom runs");
    assert!(
        final_out.status.success(),
        "scan failed for {}: stderr={}",
        case.label,
        String::from_utf8_lossy(&final_out.stderr)
    );
    (cdx, spdx)
}

fn sbomqs_feature_scores(
    sbomqs: &std::path::Path,
    doc: &std::path::Path,
) -> std::collections::BTreeMap<String, f64> {
    let out = Command::new(sbomqs)
        .arg("score")
        .arg("--json")
        .arg(doc)
        .output()
        .expect("sbomqs runs");
    assert!(
        out.status.success(),
        "sbomqs score failed for {}: stderr={}",
        doc.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let body: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("sbomqs emits JSON");
    // sbomqs v2 JSON shape:
    //     files[0].comprehenssive[N].features[M] = { key, score, ... }
    // (Note: `comprehenssive` is sbomqs's literal key — it ships
    // with a typo. Tracking upstream.)
    let mut scores: std::collections::BTreeMap<String, f64> =
        std::collections::BTreeMap::new();
    let Some(categories) = body
        .pointer("/files/0/comprehenssive")
        .and_then(|v| v.as_array())
    else {
        return scores;
    };
    for cat in categories {
        let Some(features) = cat["features"].as_array() else {
            continue;
        };
        for feat in features {
            let Some(key) = feat["key"].as_str() else {
                continue;
            };
            let Some(score) = feat["score"].as_f64() else {
                continue;
            };
            scores.insert(key.to_string(), score);
        }
    }
    scores
}

fn run_case(sbomqs: &std::path::Path, case: &EcosystemCase) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (cdx_path, spdx_path) = produce_sboms(case, tmp.path());
    let cdx_scores = sbomqs_feature_scores(sbomqs, &cdx_path);
    let spdx_scores = sbomqs_feature_scores(sbomqs, &spdx_path);

    // For every NATIVE_FEATURES entry sbomqs scored on CDX, the
    // SPDX score must be ≥ CDX. Features absent from CDX are a
    // silent pass (sbomqs doesn't grade what the scan didn't
    // produce). Features absent from SPDX but present in CDX are
    // a hard fail — that's real data-placement regression.
    let mut regressions: Vec<String> = Vec::new();
    for feat in NATIVE_FEATURES {
        let Some(&cdx_score) = cdx_scores.get(*feat) else {
            continue;
        };
        let spdx_score = spdx_scores.get(*feat).copied().unwrap_or(0.0);
        if spdx_score < cdx_score {
            regressions.push(format!(
                "  {feat:<30}  CDX={cdx_score:>4.1}  SPDX={spdx_score:>4.1}"
            ));
        }
    }
    assert!(
        regressions.is_empty(),
        "{}: sbomqs features regressed from CDX → SPDX:\n{}",
        case.label,
        regressions.join("\n")
    );
}

#[test]
fn sbomqs_spdx_score_meets_or_beats_cdx_across_ecosystems() {
    let Some(sbomqs) = sbomqs_bin() else {
        // Local-dev skip: print a visible diagnostic but don't fail.
        // CI always has sbomqs provisioned (see
        // `.github/workflows/ci.yml` — "Install sbomqs" step); if
        // sbomqs is missing there, every other CI job using this
        // harness fails loudly anyway.
        eprintln!(
            "[sbomqs_parity] skipping: sbomqs binary not found on \
             PATH and MIKEBOM_SBOMQS_BIN not set. Install from \
             https://github.com/interlynk-io/sbomqs to enable \
             SC-001 enforcement locally."
        );
        return;
    };
    for case in CASES {
        run_case(&sbomqs, case);
    }
}
