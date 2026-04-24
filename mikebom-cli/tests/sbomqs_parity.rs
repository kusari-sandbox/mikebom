//! sbomqs cross-format scoring (milestone 010 T055 / SC-001).
//!
//! Spec: for each of the 9 supported ecosystems, `sbomqs score`
//! against mikebom's SPDX 2.3 output MUST meet or beat the score
//! against its CycloneDX output on the categories both formats
//! express natively (NTIA-minimum: name, version, supplier,
//! checksums, license, dependencies, externalRefs).
//!
//! This test is `#[ignore]`-gated because `sbomqs` is an external
//! Go binary that isn't vendored in the tree. CI provisions it
//! via a separate setup step and enables the test with
//! `cargo test -- --include-ignored`. Local runs pick up
//! `sbomqs` from `$PATH` or `MIKEBOM_SBOMQS_BIN=<abs-path>`.
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

/// NTIA-minimum field categories. mikebom asserts `spdx ≥ cdx` on
/// each; these are the dimensions both formats express natively so
/// a score drop going CDX → SPDX would indicate a real data-placement
/// regression.
const NATIVE_CATEGORIES: &[&str] = &[
    "NTIA-minimum-elements",
    "Component-Name",
    "Component-Version",
    "Component-Supplier",
    "Checksum",
    "License",
    "Dependencies",
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

fn sbomqs_score_categories(
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
    // sbomqs JSON shape (as of v1.x): top-level `files[0].scores[]`
    // each with `category` + `feature` + `score`. We collapse to
    // category → max(score within category) so we compare at the
    // coarser level the NTIA-minimum list targets.
    let mut out: std::collections::BTreeMap<String, f64> =
        std::collections::BTreeMap::new();
    if let Some(scores) = body.pointer("/files/0/scores").and_then(|v| v.as_array()) {
        for s in scores {
            let Some(cat) = s["category"].as_str() else {
                continue;
            };
            let Some(score) = s["score"].as_f64() else {
                continue;
            };
            out.entry(cat.to_string())
                .and_modify(|v| *v = v.max(score))
                .or_insert(score);
        }
    }
    out
}

fn run_case(sbomqs: &std::path::Path, case: &EcosystemCase) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (cdx_path, spdx_path) = produce_sboms(case, tmp.path());
    let cdx_scores = sbomqs_score_categories(sbomqs, &cdx_path);
    let spdx_scores = sbomqs_score_categories(sbomqs, &spdx_path);

    // For every NTIA-minimum category that sbomqs emitted for CDX,
    // the SPDX score must be ≥ CDX. Categories absent from CDX are
    // a silent pass (sbomqs doesn't grade what the format can't
    // express). Categories absent from SPDX but present in CDX
    // are a hard fail — that's real data-placement regression.
    for cat in NATIVE_CATEGORIES {
        let Some(&cdx_score) = cdx_scores.get(*cat) else {
            continue;
        };
        let spdx_score = spdx_scores.get(*cat).copied().unwrap_or(0.0);
        assert!(
            spdx_score >= cdx_score,
            "{}: sbomqs category {:?} regressed from CDX → SPDX: \
             CDX = {cdx_score}, SPDX = {spdx_score}",
            case.label,
            cat
        );
    }
}

#[test]
#[ignore = "requires sbomqs on PATH or MIKEBOM_SBOMQS_BIN=<abs-path>; run via --include-ignored"]
fn sbomqs_spdx_score_meets_or_beats_cdx_across_ecosystems() {
    let Some(sbomqs) = sbomqs_bin() else {
        panic!(
            "sbomqs binary not found. Install from \
             https://github.com/interlynk-io/sbomqs and ensure it \
             is on PATH, or set MIKEBOM_SBOMQS_BIN=<abs-path>."
        );
    };
    for case in CASES {
        run_case(&sbomqs, case);
    }
}
