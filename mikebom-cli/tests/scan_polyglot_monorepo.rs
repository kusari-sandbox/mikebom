//! End-to-end integration test for polyglot monorepos — a single
//! `mikebom sbom scan --path` invocation over a repo containing both
//! a Python backend and an npm frontend must emit one SBOM carrying
//! components from BOTH ecosystems, with per-ecosystem compositions
//! records where authoritative.
//!
//! This exercises the bounded-depth project-root walks in pip.rs and
//! npm.rs working in parallel against the same scan root.

use std::path::PathBuf;
use std::process::Command;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures/polyglot-monorepo")
}

fn scan(include_dev: bool) -> serde_json::Value {
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let out_path = tempfile::NamedTempFile::new()
        .expect("tempfile")
        .path()
        .to_path_buf();
    let mut cmd = Command::new(bin);
    cmd.arg("--offline");
    if include_dev {
        cmd.arg("--include-dev");
    }
    cmd.arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture())
        .arg("--output")
        .arg(&out_path)
        .arg("--no-deep-hash");
    let output = cmd.output().expect("mikebom should run");
    assert!(
        output.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let raw = std::fs::read_to_string(&out_path).expect("read sbom");
    serde_json::from_str(&raw).expect("valid JSON")
}

fn components_by_prefix<'a>(
    sbom: &'a serde_json::Value,
    prefix: &str,
) -> Vec<&'a serde_json::Value> {
    sbom["components"]
        .as_array()
        .expect("components array")
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with(prefix))
        })
        .collect()
}

#[test]
fn polyglot_monorepo_emits_both_python_and_npm_components() {
    let sbom = scan(false);

    let pypi = components_by_prefix(&sbom, "pkg:pypi/");
    let npm = components_by_prefix(&sbom, "pkg:npm/");

    // Backend: 3 design-tier requirements.txt entries.
    assert_eq!(
        pypi.len(),
        3,
        "backend: expected fastapi + uvicorn + httpx, got {:?}",
        pypi.iter().map(|c| c["name"].as_str()).collect::<Vec<_>>()
    );
    let pypi_names: Vec<&str> = pypi.iter().filter_map(|c| c["name"].as_str()).collect();
    assert!(pypi_names.contains(&"fastapi"));
    assert!(pypi_names.contains(&"uvicorn"));
    assert!(pypi_names.contains(&"httpx"));

    // Frontend: 2 source-tier lockfile entries (prod-only default
    // filters vite out).
    assert_eq!(
        npm.len(),
        2,
        "frontend: expected react + axios (prod only), got {:?}",
        npm.iter().map(|c| c["name"].as_str()).collect::<Vec<_>>()
    );
    let npm_names: Vec<&str> = npm.iter().filter_map(|c| c["name"].as_str()).collect();
    assert!(npm_names.contains(&"react"));
    assert!(npm_names.contains(&"axios"));
}

#[test]
fn polyglot_monorepo_include_dev_surfaces_both_ecosystems_dev_deps() {
    let sbom = scan(true);
    let npm = components_by_prefix(&sbom, "pkg:npm/");
    let names: Vec<&str> = npm.iter().filter_map(|c| c["name"].as_str()).collect();
    assert!(
        names.contains(&"vite"),
        "vite dev-dep must appear under --include-dev; got {names:?}"
    );
}

#[test]
fn polyglot_monorepo_marks_npm_authoritative_but_not_pypi_design_only() {
    // The frontend has a lockfile → npm ecosystem is marked
    // `aggregate: complete`. The backend only has requirements.txt
    // (design tier) → pypi is NOT marked complete per R13.
    let sbom = scan(false);
    let compositions = sbom["compositions"].as_array().expect("compositions array");

    let has_complete_for = |ecosystem_prefix: &str| -> bool {
        compositions.iter().any(|r| {
            r["aggregate"].as_str() == Some("complete")
                && r["assemblies"]
                    .as_array()
                    .map(|a| {
                        a.iter().any(|p| {
                            p.as_str().is_some_and(|s| s.starts_with(ecosystem_prefix))
                        })
                    })
                    .unwrap_or(false)
        })
    };

    assert!(
        has_complete_for("pkg:npm/"),
        "npm ecosystem must be aggregate=complete (lockfile-sourced)"
    );
    assert!(
        !has_complete_for("pkg:pypi/"),
        "pypi ecosystem must NOT be aggregate=complete (design-tier only)"
    );
}
