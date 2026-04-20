//! Integration tests for the Go ecosystem (milestone 003 US1).
//!
//! Covers the four spec-declared scenarios:
//!
//! 1. Source-tree scan (`go.mod` + `go.sum`) emits canonical PURLs for
//!    every go.sum `Module`-kind line plus the main module from go.mod.
//! 2. Binary scan (`runtime/debug.BuildInfo`) emits analyzed-tier
//!    components for the embedded module list.
//! 3. A binary with no readable BuildInfo (synthesized in-test with a
//!    truncated payload) emits a file-level diagnostic entry.
//! 4. A scratch "image-shaped" rootfs (bare binary, no go.mod) still
//!    produces the full module list — that's the distroless win.
//!
//! All four shell out to the `mikebom` CLI (same pattern as
//! `scan_python.rs` / `scan_npm.rs`).

use std::path::PathBuf;
use std::process::Command;

fn fixture(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures/go")
        .join(sub)
}

fn scan_path(path: &std::path::Path) -> serde_json::Value {
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let out_path = tmp.path().to_path_buf();
    let output = Command::new(bin)
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(path)
        .arg("--output")
        .arg(&out_path)
        .arg("--no-deep-hash")
        .output()
        .expect("mikebom should run");
    assert!(
        output.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let raw = std::fs::read_to_string(&out_path).expect("read sbom");
    serde_json::from_str(&raw).expect("valid JSON")
}

fn golang_purls(sbom: &serde_json::Value) -> Vec<String> {
    sbom["components"]
        .as_array()
        .expect("components array")
        .iter()
        .filter_map(|c| {
            let p = c["purl"].as_str()?;
            if p.starts_with("pkg:golang/") {
                Some(p.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn go_sum_module_count(fixture_sub: &str) -> usize {
    let go_sum = fixture(fixture_sub).join("go.sum");
    let text = std::fs::read_to_string(&go_sum)
        .unwrap_or_else(|_| panic!("fixture {fixture_sub}/go.sum must exist"));
    text.lines()
        .filter(|l| {
            let mut parts = l.split_whitespace();
            let _m = parts.next();
            let v = parts.next();
            matches!(v, Some(v) if !v.ends_with("/go.mod"))
        })
        .count()
}

// --- T029: source-tree scan --------------------------------------------

#[test]
fn scan_go_source_tree_emits_canonical_purls() {
    let sbom = scan_path(&fixture("simple-module"));
    let purls = golang_purls(&sbom);
    let gosum_modules = go_sum_module_count("simple-module");
    // SC-001 tolerance: we expect at least gosum_modules components
    // (plus the main module from go.mod). The scanner might drop one
    // for a replace-to-local target; the tolerance is `gosum_modules - 1`.
    assert!(
        purls.len() >= gosum_modules.saturating_sub(1),
        "expected ≥{} golang components, got {}: {purls:?}",
        gosum_modules.saturating_sub(1),
        purls.len(),
    );
    // The main module should be present.
    assert!(
        purls.iter().any(|p| p.contains("example.com/simple")),
        "main module PURL missing: {purls:?}",
    );
    // Canonical PURLs always have `pkg:golang/` + a `/`-separated module path.
    for p in &purls {
        assert!(
            p.starts_with("pkg:golang/"),
            "non-canonical Go PURL: {p}"
        );
    }
}

// --- T030: binary BuildInfo scan --------------------------------------

#[test]
fn scan_go_binary_emits_buildinfo_modules() {
    let sbom = scan_path(&fixture("binaries"));
    let purls = golang_purls(&sbom);
    // ≥3: at least main + cobra + logrus — the simple-module binary
    // pulls in nine transitive deps by construction.
    assert!(
        purls.len() >= 3,
        "expected ≥3 golang components from binary, got {}: {purls:?}",
        purls.len(),
    );
    // Specific modules we know should be present.
    let must_have = ["github.com/spf13/cobra", "github.com/sirupsen/logrus"];
    for needle in must_have {
        assert!(
            purls.iter().any(|p| p.contains(needle)),
            "expected PURL containing {needle}, got {purls:?}",
        );
    }
    // aggregate=complete for the golang ecosystem.
    let compositions = sbom["compositions"].as_array();
    assert!(
        compositions.is_some_and(|c| c.iter().any(|comp| {
            comp["aggregate"].as_str() == Some("complete")
                && comp["assemblies"]
                    .as_array()
                    .map(|asm| {
                        asm.iter()
                            .any(|s| s.as_str().unwrap_or("").starts_with("pkg:golang/"))
                    })
                    .unwrap_or(false)
        })),
        "golang aggregate=complete composition expected",
    );
}

// --- T031: stripped / unreadable binary emits diagnostic --------------

#[test]
fn scan_go_stripped_binary_emits_diagnostic_property() {
    // Build a synthetic rootfs with a single Go-magic-bearing file that
    // is deliberately malformed (truncated after the header). This
    // simulates a stripped binary where the BuildInfo section is gone
    // but the magic bytes happen to be elsewhere in the binary.
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_path = dir.path().join("corrupted");
    let mut bytes = vec![0u8; 4096];
    // Append the magic + a non-inline flags byte to trigger the
    // "unsupported" path.
    let magic = b"\xff Go buildinf:";
    let mut header: Vec<u8> = Vec::new();
    header.extend_from_slice(magic);
    header.push(8); // ptr size
    header.push(0x0); // no inline flag → unsupported
    header.extend_from_slice(&[0u8; 16]);
    bytes.extend_from_slice(&header);
    std::fs::write(&bin_path, &bytes).expect("write bin");

    let sbom = scan_path(dir.path());
    // Exit 0 is implicit (scan_path asserts success). We expect one
    // file-level diagnostic component — it carries a generic PURL
    // with the filename, and the `mikebom:buildinfo-status` property.
    let diagnostics: Vec<_> = sbom["components"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .filter(|c| {
            c["properties"]
                .as_array()
                .map(|props| {
                    props.iter().any(|p| {
                        p["name"].as_str() == Some("mikebom:buildinfo-status")
                    })
                })
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !diagnostics.is_empty(),
        "expected ≥1 component with mikebom:buildinfo-status property; got components: {}",
        serde_json::to_string_pretty(&sbom["components"]).unwrap_or_default(),
    );
    let status = diagnostics[0]["properties"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["name"].as_str() == Some("mikebom:buildinfo-status")))
        .and_then(|p| p["value"].as_str())
        .unwrap_or("");
    assert!(
        status == "unsupported" || status == "missing",
        "unexpected buildinfo-status value: {status}",
    );
}

// --- Transitive dep-graph via module cache ---------------------------

#[test]
fn scan_go_source_tree_emits_transitive_edges_when_cache_present() {
    // The Go module cache discovery honours $GOMODCACHE / $HOME/go.
    // If neither points at a populated cache on the test runner, the
    // graph is expected to be empty beyond the root — skip rather
    // than fail, since this test is observational of a real cache.
    let gomodcache = std::env::var("GOMODCACHE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .filter(|s| !s.is_empty())
                .map(|h| std::path::PathBuf::from(h).join("go/pkg/mod"))
        });
    let Some(cache_root) = gomodcache else {
        eprintln!("skipping: no GOMODCACHE or HOME/go/pkg/mod");
        return;
    };
    let cached_cobra_mod = cache_root
        .join("cache/download/github.com/spf13/cobra/@v/v1.10.2.mod");
    if !cached_cobra_mod.is_file() {
        eprintln!(
            "skipping: no cached cobra/@v/v1.10.2.mod at {}",
            cached_cobra_mod.display()
        );
        return;
    }

    let sbom = scan_path(&fixture("simple-module"));
    let deps = sbom["dependencies"]
        .as_array()
        .expect("dependencies array");
    let go_deps: Vec<_> = deps
        .iter()
        .filter(|d| {
            d["ref"]
                .as_str()
                .is_some_and(|s| s.starts_with("pkg:golang/"))
        })
        .collect();
    let with_edges: Vec<_> = go_deps
        .iter()
        .filter(|d| {
            d.get("dependsOn")
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty())
        })
        .collect();
    // Root + ≥2 transitive nodes with outbound edges (logrus + cobra
    // both declare their own requires in their cached .mod files).
    assert!(
        with_edges.len() >= 3,
        "expected ≥3 golang records with dependsOn edges, got {}",
        with_edges.len(),
    );
    // logrus → x/sys specifically.
    let logrus = go_deps
        .iter()
        .find(|d| {
            d["ref"]
                .as_str()
                .is_some_and(|s| s.starts_with("pkg:golang/github.com/sirupsen/logrus@"))
        })
        .expect("logrus dependency record");
    let logrus_targets: Vec<String> = logrus["dependsOn"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        logrus_targets
            .iter()
            .any(|t| t.contains("pkg:golang/golang.org/x/sys@")),
        "logrus → x/sys edge missing (cached go.mod resolution failed): {logrus_targets:?}",
    );
}

// --- T032: scratch / distroless image emits binary-sourced modules ----

#[test]
fn scan_go_scratch_rootfs_via_path_flag() {
    // Simulate a scratch image by copying just the binary into a bare
    // directory — no go.mod, no /etc, no other signals. This is the
    // "distroless win" spec scenario.
    let dir = tempfile::tempdir().expect("tempdir");
    let src = fixture("binaries").join("hello-linux-amd64");
    let dst = dir.path().join("app");
    std::fs::copy(&src, &dst).expect("copy binary into scratch rootfs");

    let sbom = scan_path(dir.path());
    let purls = golang_purls(&sbom);
    assert!(
        purls.len() >= 3,
        "scratch scan produced too few golang components: {purls:?}",
    );
    // Dedup test: these modules match the source-tree fixture set, so
    // the same PURL shape is expected.
    assert!(
        purls.iter().any(|p| p.contains("github.com/spf13/cobra")),
        "cobra missing from scratch scan: {purls:?}",
    );
}
