//! CLI format-dispatch integration tests — milestone 010 T013.
//!
//! End-to-end coverage of the multi-value `--format` + per-format
//! `--output <fmt>=<path>` surface added in Phase 2 of
//! `specs/010-spdx-output-support/`. The unit tests in
//! `src/cli/scan_cmd.rs::tests` cover the pure `resolve_dispatch`
//! helper; these tests run the compiled binary so they catch wiring
//! regressions in clap attributes, output-writing, and error-exit
//! behavior.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Canonical cargo fixture — small, offline-friendly, and already
/// pinned by `cdx_regression.rs`. Choosing one fixture keeps these
/// tests fast (<2 s total on a warm cache).
fn cargo_fixture() -> PathBuf {
    workspace_root().join("tests/fixtures/cargo/lockfile-v3")
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mikebom")
}

/// Run `mikebom sbom scan` with the given extra args, returning the
/// completed process output. The caller chooses the working
/// directory — most tests use a tempdir so default-filename emission
/// can be observed without stamping on cwd.
///
/// `HOME` and friends are redirected to a tempdir so host-level
/// package caches (`~/.m2/`, `~/go/pkg/mod/`, etc.) don't leak
/// extra discovered components into the test output. See
/// `cdx_regression.rs::run_scan` for the full rationale.
fn run_scan_in(
    cwd: &Path,
    extra_args: &[&str],
) -> std::process::Output {
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
    let mut cmd = Command::new(bin());
    cmd.current_dir(cwd)
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
        .arg(cargo_fixture())
        .arg("--no-deep-hash");
    for a in extra_args {
        cmd.arg(a);
    }
    cmd.output().expect("mikebom should run")
}

/// Normalize CDX volatile fields (serialNumber + metadata.timestamp)
/// so two runs of the same scan are byte-comparable. Mirrors the
/// helper in `cdx_regression.rs` — workspace-absolute-path rewrite
/// AND per-component `hashes[]` stripping, both needed for
/// cross-host byte identity (local package caches on dev vs empty
/// caches on CI change which components the scanner can hash).
/// See `cdx_regression.rs::normalize` for the full story.
fn normalize_cdx(raw: &str) -> String {
    let ws = workspace_root();
    let ws_str = ws.to_string_lossy().to_string();
    let replaced = raw.replace(ws_str.as_str(), "<WORKSPACE>");

    let mut json: serde_json::Value =
        serde_json::from_str(&replaced).expect("produced SBOM is valid JSON");
    if let Some(obj) = json.as_object_mut() {
        if obj.contains_key("serialNumber") {
            obj.insert(
                "serialNumber".to_string(),
                serde_json::Value::String(
                    "urn:uuid:00000000-0000-0000-0000-000000000000".to_string(),
                ),
            );
        }
        if let Some(md) = obj.get_mut("metadata").and_then(|v| v.as_object_mut()) {
            if md.contains_key("timestamp") {
                md.insert(
                    "timestamp".to_string(),
                    serde_json::Value::String(
                        "1970-01-01T00:00:00Z".to_string(),
                    ),
                );
            }
        }
        if let Some(comps) = obj.get_mut("components").and_then(|v| v.as_array_mut())
        {
            for c in comps {
                strip_hashes(c);
            }
        }
    }
    serde_json::to_string_pretty(&json).expect("re-serialize")
}

fn strip_hashes(c: &mut serde_json::Value) {
    let Some(obj) = c.as_object_mut() else { return };
    obj.remove("hashes");
    if let Some(nested) = obj.get_mut("components").and_then(|v| v.as_array_mut()) {
        for nc in nested {
            strip_hashes(nc);
        }
    }
}

fn pinned_cargo_golden() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden/cyclonedx/cargo.cdx.json");
    std::fs::read_to_string(path).expect("read pinned cargo golden")
}

// ---- (a) default path + byte-identity ------------------------------------

/// No `--format`, no `--output`: produces exactly one file at the
/// default name `mikebom.cdx.json`, byte-identical (modulo the two
/// pinned volatile fields) to the T010 cargo golden.
#[test]
fn default_invocation_emits_single_cdx_file_matching_pinned_golden() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scan_in(tmp.path(), &[]);
    assert!(
        out.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let produced = tmp.path().join("mikebom.cdx.json");
    assert!(
        produced.exists(),
        "default invocation did not write mikebom.cdx.json in cwd"
    );
    // No other SBOM files should appear.
    let stray: Vec<_> = std::fs::read_dir(tmp.path())
        .expect("read tmp")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .filter(|n| {
            n.to_string_lossy().ends_with(".json")
                && n.to_string_lossy() != "mikebom.cdx.json"
        })
        .collect();
    assert!(
        stray.is_empty(),
        "unexpected JSON files in cwd: {stray:?}"
    );
    let raw = std::fs::read_to_string(&produced).expect("read produced");
    assert_eq!(
        normalize_cdx(&raw),
        pinned_cargo_golden(),
        "default-format CDX output drifted from pinned cargo golden — \
         this is the FR-022 / SC-006 regression guard."
    );
}

// ---- (b) format de-duplication -------------------------------------------

#[test]
fn comma_separated_duplicate_formats_dedupe_silently() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scan_in(
        tmp.path(),
        &["--format", "cyclonedx-json,cyclonedx-json"],
    );
    assert!(
        out.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(tmp.path().join("mikebom.cdx.json").exists());
}

#[test]
fn repeated_flag_duplicate_formats_dedupe_silently() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scan_in(
        tmp.path(),
        &[
            "--format",
            "cyclonedx-json",
            "--format",
            "cyclonedx-json",
        ],
    );
    assert!(
        out.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(tmp.path().join("mikebom.cdx.json").exists());
}

// ---- (c) unknown format id -----------------------------------------------

#[test]
fn unknown_format_id_exits_non_zero_and_lists_registered_ids() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scan_in(tmp.path(), &["--format", "totally-fake"]);
    assert!(
        !out.status.success(),
        "unknown format id must fail the process"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown format identifier"),
        "error should say 'unknown format identifier', got: {stderr}"
    );
    assert!(
        stderr.contains("cyclonedx-json"),
        "error should enumerate registered ids (at least cyclonedx-json), got: {stderr}"
    );
    // No SBOM file should be written on this error path.
    assert!(!tmp.path().join("mikebom.cdx.json").exists());
}

// ---- (d) --output for unrequested format ---------------------------------

#[test]
fn output_override_for_unrequested_format_is_hard_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = run_scan_in(
        tmp.path(),
        &[
            "--format",
            "cyclonedx-json",
            "--output",
            "spdx-2.3-json=custom.spdx.json",
        ],
    );
    assert!(
        !out.status.success(),
        "--output for unrequested format must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("but --format did not request it"),
        "error should say '--format did not request it', got: {stderr}"
    );
    assert!(!tmp.path().join("mikebom.cdx.json").exists());
    assert!(!tmp.path().join("custom.spdx.json").exists());
}

// ---- (e) override-path collision -----------------------------------------

/// A collision is most naturally observed between two per-format
/// overrides. With SPDX not yet registered, we exercise the
/// collision detector directly: bare `--output` and per-format
/// `--output cyclonedx-json=<same>` both target the CDX file — the
/// CLI must reject this before scan work starts (and therefore
/// before any file is written to the collision path).
#[test]
fn override_path_collision_aborts_before_writing_any_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path_str = tmp
        .path()
        .join("shared.cdx.json")
        .to_string_lossy()
        .into_owned();
    let out = run_scan_in(
        tmp.path(),
        &[
            "--output",
            &path_str,
            "--output",
            &format!("cyclonedx-json={path_str}"),
        ],
    );
    assert!(
        !out.status.success(),
        "colliding --output entries must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("conflicts with --output")
            || stderr.contains("output path collision"),
        "error should name the collision, got: {stderr}"
    );
    // No file should have been written to the collision target.
    assert!(
        !Path::new(&path_str).exists(),
        "collision target was created before the error fired"
    );
}

// ---- per-format override honored (positive control) ---------------------

#[test]
fn per_format_override_writes_to_named_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("nested/dir/my-sbom.cdx.json");
    let out = run_scan_in(
        tmp.path(),
        &[
            "--format",
            "cyclonedx-json",
            "--output",
            &format!(
                "cyclonedx-json={}",
                target.to_string_lossy()
            ),
        ],
    );
    assert!(
        out.status.success(),
        "per-format override scan failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        target.exists(),
        "expected output at {}",
        target.display()
    );
    // Default filename must not have also been written.
    assert!(!tmp.path().join("mikebom.cdx.json").exists());
}

// ---- Milestone 011 US3 dispatch surface --------------------------

#[test]
fn both_spdx_3_identifiers_dispatch_and_emit_the_same_default_filename() {
    // Post-US3 state (research.md §R6 / contract §4):
    // `spdx-3-json` and `spdx-3-json-experimental` both dispatch
    // through the registry, both emit `mikebom.spdx3.json` as the
    // default filename, both route through the same emitter so
    // output bytes are byte-identical. The alias additionally
    // prints a stderr deprecation notice.
    for (format, should_emit_notice) in [
        ("spdx-3-json", false),
        ("spdx-3-json-experimental", true),
    ] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let out = run_scan_in(tmp.path(), &["--format", format]);
        assert!(
            out.status.success(),
            "`--format {format}` must dispatch successfully; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let default_file = tmp.path().join("mikebom.spdx3.json");
        assert!(
            default_file.exists(),
            "`--format {format}` must emit `mikebom.spdx3.json` at the default location"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        let has_notice = stderr.contains("is deprecated");
        assert_eq!(
            has_notice, should_emit_notice,
            "`--format {format}`: expected deprecation-notice emission \
             = {should_emit_notice}, got {has_notice}. stderr=\n{stderr}"
        );
    }
}

#[test]
fn spdx_3_alias_bytes_are_byte_identical_to_stable_identifier() {
    // End-to-end byte-identity — the last defense against the
    // alias drifting away from the stable emitter.
    let tmp_stable = tempfile::tempdir().expect("tempdir");
    let tmp_alias = tempfile::tempdir().expect("tempdir");
    let stable_path = tmp_stable.path().join("stable.spdx3.json");
    let alias_path = tmp_alias.path().join("alias.spdx3.json");

    let stable = run_scan_in(
        tmp_stable.path(),
        &[
            "--format",
            "spdx-3-json",
            "--output",
            &format!("spdx-3-json={}", stable_path.to_string_lossy()),
        ],
    );
    let alias = run_scan_in(
        tmp_alias.path(),
        &[
            "--format",
            "spdx-3-json-experimental",
            "--output",
            &format!(
                "spdx-3-json-experimental={}",
                alias_path.to_string_lossy()
            ),
        ],
    );
    assert!(stable.status.success());
    assert!(alias.status.success());

    let stable_bytes = std::fs::read(&stable_path).expect("stable output");
    let alias_bytes = std::fs::read(&alias_path).expect("alias output");
    assert_eq!(
        stable_bytes, alias_bytes,
        "alias must emit byte-identical output to the stable identifier \
         per research.md §R6 / contract §4"
    );
}
