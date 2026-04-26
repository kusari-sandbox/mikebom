//! SPDX 3 byte-identity regression test — milestone 017.
//!
//! Sibling of `cdx_regression.rs` and `spdx_regression.rs` for the
//! SPDX 3.0.1 emitter. Closes the gap that milestone 011 left
//! behind: SPDX 3 shipped with per-run determinism guards
//! (`spdx3_determinism.rs`) but no committed byte-identity goldens.
//!
//! For each of the 9 ecosystems, scans the committed fixture, applies
//! `common::normalize::normalize_spdx3_for_golden` (workspace-path
//! placeholder + every `@graph[]` `CreationInfo.created` mask +
//! `Package.verifiedUsing[]` strip), and compares the result
//! byte-for-byte against
//! `tests/fixtures/golden/spdx-3/{label}.spdx3.json`.
//!
//! Updating a golden: set `MIKEBOM_UPDATE_SPDX3_GOLDENS=1` and rerun
//! the test. The normalized output is written back to the golden
//! file. Commit the diff only after reviewing — any change here is a
//! real SPDX-3-output change and needs an audit per the regen
//! contract at
//! `specs/017-spdx-byte-identity-goldens/contracts/golden-regen.md`.

use std::path::PathBuf;
use std::process::Command;

mod common;
use common::normalize::{apply_fake_home_env, normalize_spdx3_for_golden};
use common::{workspace_root, EcosystemCase, CASES};

fn fixture_path(subpath: &str) -> PathBuf {
    workspace_root().join("tests/fixtures").join(subpath)
}

fn golden_path(label: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden/spdx-3")
        .join(format!("{label}.spdx3.json"))
}

/// Run `mikebom sbom scan --format spdx-3-json` against a fixture
/// under fake-HOME isolation; return the raw SPDX 3 JSON text.
fn run_scan(case: &EcosystemCase) -> String {
    let fx = fixture_path(case.fixture_subpath);
    assert!(
        fx.exists(),
        "fixture path missing for {}: {}",
        case.label,
        fx.display()
    );
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_path = tmp.path().join("mikebom.spdx3.json");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let mut cmd = Command::new(bin);
    apply_fake_home_env(&mut cmd, fake_home.path());
    cmd.arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(&fx)
        .arg("--format")
        .arg("spdx-3-json")
        .arg("--output")
        .arg(format!("spdx-3-json={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash");
    if let Some(code) = case.deb_codename {
        cmd.arg("--deb-codename").arg(code);
    }
    let output = cmd.output().expect("mikebom should run");
    assert!(
        output.status.success(),
        "scan failed for {}: stderr={}",
        case.label,
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read_to_string(&out_path).expect("read produced sbom")
}

/// Write or compare a golden file. Accepts a test-time toggle via
/// `MIKEBOM_UPDATE_SPDX3_GOLDENS=1` to rewrite instead of diff.
fn assert_or_update_golden(label: &str, normalized: &str) {
    let path = golden_path(label);
    let update = std::env::var("MIKEBOM_UPDATE_SPDX3_GOLDENS")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);
    if update || !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create golden dir");
        }
        std::fs::write(&path, normalized.as_bytes()).expect("write golden file");
        eprintln!(
            "[spdx3_regression] updated golden for {label}: {}",
            path.display()
        );
        return;
    }
    let golden = std::fs::read_to_string(&path).expect("read pinned golden");
    if golden != normalized {
        let actual = path.with_extension("actual.json");
        std::fs::write(&actual, normalized.as_bytes()).expect("write actual.json for diff");

        eprintln!("\n--- GOLDEN/ACTUAL DIFF for ecosystem {label} ---");
        diff_to_stderr(&golden, normalized);
        eprintln!("--- end diff ---\n");

        panic!(
            "SPDX 3 regression for ecosystem {label}: output differs from \
             pinned golden.\n  golden: {}\n  actual: {}\nTo accept the change, \
             run: MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo test --test spdx3_regression",
            path.display(),
            actual.display()
        );
    }
}

/// Plain line-diff between `golden` and `actual`, printed to stderr.
/// Mirrors `cdx_regression.rs::diff_to_stderr` so CI logs are
/// readable without re-running locally.
fn diff_to_stderr(golden: &str, actual: &str) {
    let g: Vec<&str> = golden.lines().collect();
    let a: Vec<&str> = actual.lines().collect();
    let max_lines = g.len().max(a.len());
    let mut printed = 0usize;
    const CAP: usize = 100;
    for i in 0..max_lines {
        let gl = g.get(i).copied().unwrap_or("<absent>");
        let al = a.get(i).copied().unwrap_or("<absent>");
        if gl != al {
            if printed >= CAP {
                eprintln!("... (diff capped at {CAP} lines)");
                break;
            }
            eprintln!("  line {:4}:", i + 1);
            eprintln!("    - {gl}");
            eprintln!("    + {al}");
            printed += 1;
        }
    }
}

fn run_case(case: &EcosystemCase) {
    let raw = run_scan(case);
    let normalized = normalize_spdx3_for_golden(&raw, &workspace_root());
    // Sanity: the produced SPDX 3 must be a `@graph`-shaped document
    // with at least one `CreationInfo` element carrying `created`. If
    // the emitter ever stops emitting that, the normalization above
    // becomes a silent no-op and this test stops being meaningful.
    let reparsed: serde_json::Value =
        serde_json::from_str(&raw).expect("produced SBOM is valid JSON");
    let creation_info_with_created = reparsed
        .get("@graph")
        .and_then(|g| g.as_array())
        .map(|arr| {
            arr.iter().any(|e| {
                e.get("type").and_then(|v| v.as_str()) == Some("CreationInfo")
                    && e.get("created").and_then(|v| v.as_str()).is_some()
            })
        })
        .unwrap_or(false);
    assert!(
        creation_info_with_created,
        "{}: SPDX 3 output missing @graph[].CreationInfo with `created`",
        case.label
    );
    assert_or_update_golden(case.label, &normalized);
}

// One test per ecosystem so a failure names the offender directly.

#[test]
fn apk_byte_identity() {
    run_case(&CASES[0]);
}

#[test]
fn cargo_byte_identity() {
    run_case(&CASES[1]);
}

#[test]
fn deb_byte_identity() {
    run_case(&CASES[2]);
}

#[test]
fn gem_byte_identity() {
    run_case(&CASES[3]);
}

#[test]
fn golang_byte_identity() {
    run_case(&CASES[4]);
}

#[test]
fn maven_byte_identity() {
    run_case(&CASES[5]);
}

#[test]
fn npm_byte_identity() {
    run_case(&CASES[6]);
}

#[test]
fn pip_byte_identity() {
    run_case(&CASES[7]);
}

#[test]
fn rpm_byte_identity() {
    run_case(&CASES[8]);
}
