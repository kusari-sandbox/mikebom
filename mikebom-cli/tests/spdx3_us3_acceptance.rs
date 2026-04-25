//! User Story 3 acceptance tests (milestone 010 T043).
//!
//! Walks the five US3 scenarios from
//! `specs/010-spdx-output-support/spec.md`:
//!
//! 1. **Format-neutral internal types.** Scan + resolution code
//!    has no SPDX-3-specific struct — the emitter consumes the
//!    same `ScanArtifacts` / `ResolvedComponent` / `Relationship`
//!    types the CycloneDX and SPDX 2.3 emitters consume. Asserted
//!    as a grep against `src/scan_fs/`, `src/resolve/`,
//!    `mikebom-common/src/resolution.rs`.
//!
//! 2. **Data-placement map carries populated SPDX 3 column.**
//!    Every row of `docs/reference/sbom-format-mapping.md` has a
//!    non-empty SPDX 3.0.1 entry (either a concrete location or
//!    a `defer until ...` note). The existing
//!    `sbom_format_mapping_coverage.rs` guards the full rule;
//!    this acceptance scenario re-checks the SPDX 3 column
//!    specifically so a US3-scoped failure names US3.
//!
//! 3. **CLI dispatch isolation.** Registering the stub touched
//!    only `generate/spdx/v3_stub.rs`, `generate/spdx/mod.rs`,
//!    `generate/mod.rs`, and `cli/scan_cmd.rs` (the last for
//!    labeling). No scan / resolution / CycloneDX / SPDX 2.3
//!    helper files reference the stub.
//!
//! 4. **npm fixture → valid SPDX 3 + PURL parity with CDX.**
//!    Every npm component that CDX emits appears as a
//!    `software_Package` in the SPDX 3 output with matching PURL.
//!    (Schema-validation half is covered by `spdx3_stub.rs`;
//!    this test adds the CDX-parity half.)
//!
//! 5. **Opt-in not selected → behavior byte-identical to no-stub
//!    build.** Covered by `spdx3_stub.rs::cdx_only_scan_produces_
//!    no_spdx3_file` + the existing `cdx_regression.rs` goldens;
//!    a narrower restatement lives here for US3 surface
//!    completeness.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

mod common;
use common::workspace_root;

// ---------- scenario 1: format-neutral internal types -------------

#[test]
fn scenario_1_scan_and_resolve_code_has_no_spdx3_struct_leaks() {
    // Any mention of an SPDX-3-specific identifier outside the
    // SPDX emitter tree means the internal model leaked a
    // format-specific shape — a regression against FR-017.
    let roots = [
        workspace_root().join("mikebom-cli/src/scan_fs"),
        workspace_root().join("mikebom-cli/src/resolve"),
        workspace_root().join("mikebom-cli/src/enrich"),
        workspace_root().join("mikebom-common/src/resolution.rs"),
    ];
    // Tokens that would betray SPDX-3 leakage. Chosen so
    // unrelated mentions (e.g. "spdx" in a URL, "Spdx" in a
    // comment about SPDX 2.3) don't trip the check.
    let leak_tokens = [
        "software_Package",
        "simplelicensing_LicenseExpression",
        "spdx-3-json",
        "Spdx3",
    ];
    for root in &roots {
        scan_for_leaks(root, &leak_tokens);
    }
}

fn scan_for_leaks(root: &std::path::Path, tokens: &[&str]) {
    if !root.exists() {
        return;
    }
    let walk = if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        let mut out = Vec::new();
        collect_rs(root, &mut out);
        out
    };
    for path in walk {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for tok in tokens {
            assert!(
                !text.contains(tok),
                "SPDX 3 leak: `{tok}` appears in {} — scan/resolution \
                 code should stay format-neutral (FR-017)",
                path.display()
            );
        }
    }
}

fn collect_rs(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

// ---------- scenario 2: map SPDX 3 column populated ---------------

#[test]
fn scenario_2_map_spdx_3_column_has_no_todo_placeholders() {
    let map = std::fs::read_to_string(
        workspace_root().join("docs/reference/sbom-format-mapping.md"),
    )
    .expect("read canonical map");
    let mut offenders: Vec<(usize, String)> = Vec::new();
    for (i, line) in map.lines().enumerate() {
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.split('|').collect();
        if cells.len() < 7 {
            continue;
        }
        let row_id = cells[1].trim();
        if row_id.is_empty()
            || row_id.chars().next().is_none_or(|c| !c.is_ascii_uppercase())
            || row_id.chars().skip(1).any(|c| !c.is_ascii_digit())
        {
            continue;
        }
        let spdx3 = cells[5].trim().trim_matches('`');
        let lower = spdx3.to_lowercase();
        if spdx3.is_empty()
            || lower == "todo"
            || lower == "tbd"
            || lower == "?"
        {
            offenders.push((i + 1, row_id.to_string()));
        }
    }
    assert!(
        offenders.is_empty(),
        "SPDX 3 column has placeholder cells at rows: {offenders:?}"
    );
}

// ---------- scenario 3: dispatch isolation ------------------------

#[test]
fn scenario_3_stub_touches_only_expected_files() {
    // Enumerate files that reference the stub's central exports.
    // Expected: v3_stub.rs (the impl), spdx/mod.rs (the
    // serializer struct + registration site), generate/mod.rs
    // (the registry), cli/scan_cmd.rs (the --help + typo hint),
    // and the acceptance/unit tests themselves. Anything else is
    // a surface leak.
    let allowed_substrings = [
        "src/generate/spdx/v3_stub.rs",
        "src/generate/spdx/mod.rs",
        "src/generate/mod.rs",
        "src/cli/scan_cmd.rs",
        "tests/spdx3_",
    ];
    let mut offenders: BTreeSet<PathBuf> = BTreeSet::new();
    let mut all_rs: Vec<PathBuf> = Vec::new();
    collect_rs(&workspace_root().join("mikebom-cli/src"), &mut all_rs);
    for path in all_rs {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let hits = text.contains("Spdx3JsonExperimentalSerializer")
            || text.contains("serialize_v3_stub")
            || text.contains("spdx-3-json-experimental");
        if !hits {
            continue;
        }
        let p = path.to_string_lossy().to_string();
        if !allowed_substrings.iter().any(|s| p.contains(s)) {
            offenders.insert(path);
        }
    }
    assert!(
        offenders.is_empty(),
        "SPDX 3 stub reference leaked into unexpected files: {offenders:?}"
    );
}

// ---------- scenario 4: npm PURL parity with CDX ------------------

#[test]
fn scenario_4_npm_fixture_has_purl_parity_between_cdx_and_spdx3() {
    let fx = workspace_root().join("tests/fixtures/npm/node-modules-walk");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let cdx_path = tmp.path().join("out.cdx.json");
    let spdx3_path = tmp.path().join("out.spdx3.json");
    let out = Command::new(env!("CARGO_BIN_EXE_mikebom"))
        .env("HOME", fake_home.path())
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
        .arg("cyclonedx-json,spdx-3-json-experimental")
        .arg("--output")
        .arg(format!(
            "cyclonedx-json={}",
            cdx_path.to_string_lossy()
        ))
        .arg("--output")
        .arg(format!(
            "spdx-3-json-experimental={}",
            spdx3_path.to_string_lossy()
        ))
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom runs");
    assert!(
        out.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cdx: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cdx_path).unwrap())
            .unwrap();
    let spdx3: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&spdx3_path).unwrap())
            .unwrap();

    let cdx_npm_purls: BTreeSet<String> = cdx["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["purl"].as_str().map(String::from))
        .filter(|p| p.starts_with("pkg:npm/"))
        .collect();

    // SPDX 3 carries PURLs on software_Package.software_packageUrl.
    // Filter to npm-only to match the CDX filter — milestone 011 emits
    // a synthesized-root Package (pkg:generic/<target>@0.0.0) for
    // sbomqs parity which has no CDX counterpart.
    let spdx3_purls: BTreeSet<String> = spdx3["@graph"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "software_Package")
        .filter_map(|e| e["software_packageUrl"].as_str().map(String::from))
        .filter(|p| p.starts_with("pkg:npm/"))
        .collect();

    assert_eq!(
        cdx_npm_purls, spdx3_purls,
        "npm PURL set differs between CDX and SPDX 3 stub \
         (CDX ∆ SPDX3 = {:?}; SPDX3 ∆ CDX = {:?})",
        cdx_npm_purls.difference(&spdx3_purls).collect::<Vec<_>>(),
        spdx3_purls.difference(&cdx_npm_purls).collect::<Vec<_>>(),
    );
    assert!(
        !cdx_npm_purls.is_empty(),
        "npm fixture should have at least one component"
    );
}

// ---------- scenario 5: opt-out = no-stub-build behavior ----------

#[test]
fn scenario_5_opt_in_not_selected_produces_no_spdx3_artifact() {
    // Narrower restatement of cdx_only_scan_produces_no_spdx3_file
    // for US3-surface completeness.
    let fx = workspace_root().join("tests/fixtures/cargo/lockfile-v3");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_mikebom"))
        .current_dir(tmp.path())
        .env("HOME", fake_home.path())
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
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom runs");
    assert!(out.status.success());
    assert!(
        !tmp.path().join("mikebom.spdx3-experimental.json").exists(),
        "no SPDX 3 artifact should appear when the format wasn't requested"
    );
    assert!(
        !tmp.path().join("mikebom.spdx.json").exists(),
        "no SPDX 2.3 artifact should appear either"
    );
    assert!(tmp.path().join("mikebom.cdx.json").exists());
}

// ---------- milestone 011 US3: alias-deprecation semantics --------
//
// Three scenarios from the milestone-011 spec's US3 + research.md
// §R2 + contract §4:
//   (6) alias exits zero + prints the two-line stderr deprecation
//       notice exactly once per invocation
//   (7) alias bytes are byte-identical to the stable identifier's
//       bytes for the same scan (research.md §R6)
//   (8) MIKEBOM_NO_DEPRECATION_NOTICE=1 suppresses the stderr
//       warning without changing the document bytes

/// Helper: run mikebom against the npm fixture with the given
/// format identifier and optional env override. Returns
/// (document_bytes, stderr_text).
fn run_scan_with_format(
    format: &str,
    extra_env: &[(&str, &str)],
) -> (Vec<u8>, String) {
    let fx = workspace_root().join("tests/fixtures/npm/node-modules-walk");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let out_path = tmp.path().join("out.spdx3.json");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mikebom"));
    cmd.env("HOME", fake_home.path())
        .env("M2_REPO", fake_home.path().join("no-m2-repo"))
        .env("MAVEN_HOME", fake_home.path().join("no-maven-home"))
        .env("GOPATH", fake_home.path().join("no-gopath"))
        .env("GOMODCACHE", fake_home.path().join("no-gomodcache"))
        .env("CARGO_HOME", fake_home.path().join("no-cargo-home"));
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(&fx)
        .arg("--format")
        .arg(format)
        .arg("--output")
        .arg(format!("{format}={}", out_path.to_string_lossy()))
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom runs");
    assert!(
        out.status.success(),
        "scan failed for {format}: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = std::fs::read(&out_path).expect("output written");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (bytes, stderr)
}

#[test]
fn scenario_6_alias_emits_two_line_deprecation_notice_once_per_invocation() {
    let (_bytes, stderr) = run_scan_with_format("spdx-3-json-experimental", &[]);
    assert!(
        stderr.contains("warning: --format spdx-3-json-experimental is deprecated"),
        "alias must emit the deprecation directive on stderr; got:\n{stderr}"
    );
    assert!(
        stderr.contains("pre-011 releases of this alias emitted an npm-only stub"),
        "deprecation notice must carry the shape-change advisory per research.md §R2; got:\n{stderr}"
    );
    // Exactly once per invocation — two-line notice, not four
    // (would indicate double-emission).
    let warning_count = stderr.matches("warning: --format").count();
    assert_eq!(
        warning_count, 1,
        "deprecation notice must emit exactly once, got {warning_count} occurrences:\n{stderr}"
    );
}

#[test]
fn scenario_7_alias_bytes_are_byte_identical_to_stable_identifier() {
    let (alias_bytes, _) = run_scan_with_format("spdx-3-json-experimental", &[]);
    let (stable_bytes, stable_stderr) = run_scan_with_format("spdx-3-json", &[]);
    assert_eq!(
        alias_bytes, stable_bytes,
        "alias output must be byte-identical to stable per research.md §R6 / contract §4"
    );
    // Stable identifier must NOT emit a deprecation notice.
    assert!(
        !stable_stderr.contains("deprecated"),
        "stable identifier must not emit deprecation notice; got:\n{stable_stderr}"
    );
}

#[test]
fn scenario_8_mikebom_no_deprecation_notice_env_suppresses_stderr_warning() {
    let (bytes_with_notice, stderr_with) =
        run_scan_with_format("spdx-3-json-experimental", &[]);
    let (bytes_without_notice, stderr_without) = run_scan_with_format(
        "spdx-3-json-experimental",
        &[("MIKEBOM_NO_DEPRECATION_NOTICE", "1")],
    );
    assert!(
        stderr_with.contains("deprecated"),
        "baseline invocation should emit the notice; got:\n{stderr_with}"
    );
    assert!(
        !stderr_without.contains("deprecated"),
        "MIKEBOM_NO_DEPRECATION_NOTICE=1 must suppress the warning; got:\n{stderr_without}"
    );
    // Document bytes are unaffected by the env flag.
    assert_eq!(
        bytes_with_notice, bytes_without_notice,
        "suppressing the notice must not change the emitted document bytes"
    );
}
