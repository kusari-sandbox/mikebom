//! CycloneDX byte-identity regression test — milestone 010 T010 + T011.
//!
//! The load-bearing guarantee behind FR-022 / SC-006: existing CDX
//! output must not drift as SPDX emission lands. For each of the 9
//! ecosystems mikebom supports today, this test runs `mikebom sbom
//! scan` against a committed fixture, normalizes the two fields
//! CycloneDX intentionally varies per invocation (`serialNumber`, a
//! fresh UUID; `metadata.timestamp`, `Utc::now()`), and compares the
//! result byte-for-byte against a pinned golden fixture under
//! `mikebom-cli/tests/fixtures/golden/cyclonedx/`.
//!
//! Updating a golden: set `MIKEBOM_UPDATE_CDX_GOLDENS=1` and rerun the
//! test. The normalized output is written back to the golden file.
//! Commit the diff only after reviewing — any change here is a real
//! CDX-output change and needs an audit.

use std::path::PathBuf;
use std::process::Command;


mod common;
use common::{workspace_root, EcosystemCase, CASES};

/// Deterministic placeholders used in both the pinned golden files
/// and the normalized freshly-produced output. The field values
/// themselves are guaranteed-volatile per the CycloneDX spec (a v4
/// UUID and a scan-time RFC 3339 stamp); masking them lets the rest
/// of the document carry the structural regression guarantee.
const SERIAL_PLACEHOLDER: &str = "urn:uuid:00000000-0000-0000-0000-000000000000";
const TIMESTAMP_PLACEHOLDER: &str = "1970-01-01T00:00:00Z";
/// Stand-in for the absolute path of the workspace root when a scan
/// target's absolute path leaks into `mikebom:source-files` /
/// `evidence.source_file_paths` / `evidence.occurrences[].location`.
/// Macs emit `/Users/<user>/Projects/mikebom/...`; CI Linux emits
/// `/home/runner/work/mikebom/mikebom/...`; both rewrite to
/// `<WORKSPACE>` for cross-host byte comparison.
const WORKSPACE_PLACEHOLDER: &str = "<WORKSPACE>";

fn fixture_path(subpath: &str) -> PathBuf {
    workspace_root().join("tests/fixtures").join(subpath)
}

fn golden_path(label: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden/cyclonedx")
        .join(format!("{label}.cdx.json"))
}

/// Run `mikebom sbom scan` against a fixture and return the raw CDX
/// JSON text.
///
/// The scan subprocess runs with `HOME` and related cache-pointing
/// env vars redirected to an empty tempdir. Several ecosystem
/// scanners read home-dir caches to discover additional components
/// beyond what's in the fixture:
///
///   - Maven: `$HOME/.m2/repository/`, `$M2_REPO`, `$MAVEN_HOME` —
///     reads cached POMs to find transitives. My dev box has
///     commons-text cached; CI runners do not, so the dev-generated
///     golden had a commons-text Package that the CI output was
///     missing.
///   - Go: `$GOPATH`, `$GOMODCACHE` (defaults under `$HOME/go/`) —
///     reads module zip metadata when cached.
///   - Cargo: `$CARGO_HOME` (defaults to `$HOME/.cargo/`) — rarely
///     affects output today but isolate for future-proofing.
///
/// With all five redirected to a per-test tempdir, the scanner's
/// home-cache lookups uniformly hit an empty directory on both
/// macOS dev and Linux CI, making the golden portable. The scan
/// target (the fixture) still provides all the real component data.
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
    let out_path = tmp.path().join("mikebom.cdx.json");
    let fake_home = tempfile::tempdir().expect("fake-home tempdir");
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
        .arg("--output")
        .arg(&out_path)
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

/// Replace the four inherently volatile things in CDX output:
///
/// 1. `serialNumber` v4 UUID — regenerated per invocation by the CDX
///    builder (`Uuid::new_v4()`).
/// 2. `metadata.timestamp` — wall-clock stamp (`Utc::now()`).
/// 3. The workspace absolute path — embedded in
///    `mikebom:source-files` + `evidence.source_file_paths` and
///    therefore different on macOS-dev
///    (`/Users/<user>/Projects/mikebom/...`) vs Linux CI
///    (`/home/runner/work/mikebom/mikebom/...`). Everything past the
///    workspace root (e.g. `tests/fixtures/cargo/lockfile-v3/...`) IS
///    deterministic, so we rewrite the prefix to the literal
///    `<WORKSPACE>` placeholder in both golden and produced output
///    before byte-comparing.
/// 4. Per-component `hashes[]` arrays — for several ecosystems the
///    scanner derives hashes from local package caches: Maven JARs
///    from `~/.m2/repository/<coord>/<ver>/<jar>`, Go module zips
///    from `~/go/pkg/mod/cache/download/...`. That state varies by
///    host: on my dev machine I happen to have some JARs cached (so
///    `commons-lang3` gets `{SHA-1, SHA-256}` while `guava` gets
///    nothing); on CI the cache starts empty so no component gets
///    hashes. This isn't an emitter bug — it's "what do we actually
///    know about the bytes on *this* host?" — so we strip `hashes[]`
///    from every component (top-level and nested) before
///    byte-comparing. Hash-set parity between CDX and SPDX within a
///    single scan is still guarded by `spdx_cdx_parity.rs`
///    (in-memory, same host, same moment), so this doesn't lose the
///    cross-format invariant.
///
/// Any OTHER difference (component order, property keys, license
/// shape, added/removed fields) surfaces as a regression — those are
/// the invariants this test guards.
fn normalize(raw: &str) -> String {
    // (3) Do the workspace-root rewrite at string-level so it hits
    // every path that happens to contain it, regardless of which
    // field carries it (source-files property,
    // evidence.source_file_paths, evidence.occurrences[].location,
    // …). `workspace_root()` is the same canonical path the scan
    // was invoked with.
    let ws = workspace_root();
    let ws_str = ws.to_string_lossy().to_string();
    let replaced = raw.replace(ws_str.as_str(), WORKSPACE_PLACEHOLDER);

    let mut json: serde_json::Value = serde_json::from_str(&replaced)
        .expect("produced SBOM is valid JSON after workspace-path rewrite");
    if let Some(obj) = json.as_object_mut() {
        // (1) serialNumber
        if obj.contains_key("serialNumber") {
            obj.insert(
                "serialNumber".to_string(),
                serde_json::Value::String(SERIAL_PLACEHOLDER.to_string()),
            );
        }
        // (2) metadata.timestamp
        if let Some(md) = obj.get_mut("metadata").and_then(|v| v.as_object_mut()) {
            if md.contains_key("timestamp") {
                md.insert(
                    "timestamp".to_string(),
                    serde_json::Value::String(TIMESTAMP_PLACEHOLDER.to_string()),
                );
            }
        }
        // (4) strip per-component hashes[] (recurses into nested
        // components, which CDX 1.6 uses for shade-jar children and
        // image-layer-owned bundles).
        if let Some(comps) = obj.get_mut("components").and_then(|v| v.as_array_mut()) {
            for c in comps {
                strip_component_hashes(c);
            }
        }
    }
    serde_json::to_string_pretty(&json).expect("re-serialize")
}

fn strip_component_hashes(c: &mut serde_json::Value) {
    let Some(obj) = c.as_object_mut() else { return };
    obj.remove("hashes");
    if let Some(nested) = obj.get_mut("components").and_then(|v| v.as_array_mut()) {
        for nc in nested {
            strip_component_hashes(nc);
        }
    }
}

/// Write or compare a golden file. Accepts a test-time toggle via
/// `MIKEBOM_UPDATE_CDX_GOLDENS=1` to rewrite instead of diff.
fn assert_or_update_golden(label: &str, normalized: &str) {
    let path = golden_path(label);
    let update = std::env::var("MIKEBOM_UPDATE_CDX_GOLDENS")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);
    if update || !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create golden dir");
        }
        std::fs::write(&path, normalized.as_bytes())
            .expect("write golden file");
        eprintln!(
            "[cdx_regression] updated golden for {label}: {}",
            path.display()
        );
        return;
    }
    let golden =
        std::fs::read_to_string(&path).expect("read pinned golden");
    if golden != normalized {
        // Write the actual produced output alongside the golden so a
        // maintainer can diff them with their own tooling — cleaner
        // than dumping kilobytes into the test failure message.
        let actual = path.with_extension("actual.json");
        std::fs::write(&actual, normalized.as_bytes())
            .expect("write actual.json for diff");

        // Line-level diff dump to stderr so CI logs show exactly
        // what changed without needing to download an artifact or
        // re-run locally. First 100 differing lines is enough for
        // any realistic drift; silently capped so we don't flood
        // the log if the entire document shape changed.
        eprintln!("\n--- GOLDEN/ACTUAL DIFF for ecosystem {label} ---");
        diff_to_stderr(&golden, normalized);
        eprintln!("--- end diff ---\n");

        panic!(
            "CDX regression for ecosystem {label}: output differs from \
             pinned golden.\n  golden: {}\n  actual: {}\nTo accept the \
             change, run: MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo test \
             --test cdx_regression",
            path.display(),
            actual.display()
        );
    }
}

/// Plain line-diff between `golden` and `actual`, printed to stderr.
/// Each line that appears in `golden` but not `actual` is prefixed
/// with `-`; each line in `actual` but not `golden` is prefixed with
/// `+`. Context is implied by line number — we print the first
/// differing line-index and a few surrounding lines, up to a cap, so
/// the CI log shows the full picture without drowning in
/// same-on-both-sides lines.
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
    let normalized = normalize(&raw);
    // Sanity: the two volatile fields must exist in every produced
    // CDX document (they are required by the CDX 1.6 schema and by
    // mikebom's builder). If they ever stop being emitted, the
    // normalization below is a silent no-op and this test becomes
    // meaningless — fail loudly instead.
    let reparsed: serde_json::Value =
        serde_json::from_str(&raw).expect("produced SBOM is valid JSON");
    assert!(
        reparsed
            .get("serialNumber")
            .and_then(|v| v.as_str())
            .is_some(),
        "{}: CDX output missing serialNumber",
        case.label
    );
    assert!(
        reparsed
            .get("metadata")
            .and_then(|m| m.get("timestamp"))
            .and_then(|v| v.as_str())
            .is_some(),
        "{}: CDX output missing metadata.timestamp",
        case.label
    );
    assert_or_update_golden(case.label, &normalized);
}

// One test per ecosystem so a failure names the offender directly.

#[test]
fn cdx_regression_apk() {
    run_case(&CASES[0]);
}

#[test]
fn cdx_regression_cargo() {
    run_case(&CASES[1]);
}

#[test]
fn cdx_regression_deb() {
    run_case(&CASES[2]);
}

#[test]
fn cdx_regression_gem() {
    run_case(&CASES[3]);
}

#[test]
fn cdx_regression_golang() {
    run_case(&CASES[4]);
}

#[test]
fn cdx_regression_maven() {
    run_case(&CASES[5]);
}

#[test]
fn cdx_regression_npm() {
    run_case(&CASES[6]);
}

#[test]
fn cdx_regression_pip() {
    run_case(&CASES[7]);
}

#[test]
fn cdx_regression_rpm() {
    run_case(&CASES[8]);
}
