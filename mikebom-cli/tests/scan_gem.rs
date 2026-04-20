//! Integration tests for the Gem/Ruby ecosystem (milestone 003 US5).

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures/gem")
        .join(sub)
}

fn scan_path(path: &Path) -> serde_json::Value {
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_path = tmp.path().join("sbom.cdx.json");
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
        String::from_utf8_lossy(&output.stderr),
    );
    let raw = std::fs::read_to_string(&out_path).expect("read sbom");
    serde_json::from_str(&raw).expect("valid JSON")
}

fn gem_purls(sbom: &serde_json::Value) -> Vec<String> {
    sbom["components"]
        .as_array()
        .expect("components array")
        .iter()
        .filter_map(|c| {
            let p = c["purl"].as_str()?;
            if p.starts_with("pkg:gem/") {
                Some(p.to_string())
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn scan_gem_fixture_emits_canonical_purls() {
    let sbom = scan_path(&fixture("simple-bundle"));
    let purls = gem_purls(&sbom);
    // The fixture declares ~15 gems across GEM + GIT + PATH sections.
    assert!(
        purls.len() >= 15,
        "expected ≥15 gem components, got {}: {purls:?}",
        purls.len(),
    );
    // Direct deps from the DEPENDENCIES block must be present.
    for needle in ["activesupport", "rails", "my-gem", "rspec"] {
        assert!(
            purls.iter().any(|p| p.starts_with(&format!("pkg:gem/{needle}@"))),
            "expected {needle} in gem purls: {purls:?}",
        );
    }
    // Canonical PURL shape.
    for p in &purls {
        assert!(p.starts_with("pkg:gem/"), "non-canonical gem PURL: {p}");
        assert!(p.contains('@'), "gem PURL missing version: {p}");
    }
}

#[test]
fn scan_gem_emits_transitive_dep_edges_from_lockfile() {
    // Gemfile.lock's indent-6 lines encode the per-gem dep graph.
    // Milestone 003 US5 gem.rs now captures those; verify the edges
    // show up in CycloneDX `dependencies[]`.
    let sbom = scan_path(&fixture("simple-bundle"));
    let deps = sbom["dependencies"]
        .as_array()
        .expect("dependencies array");
    let gem_deps: Vec<_> = deps
        .iter()
        .filter(|d| {
            d["ref"]
                .as_str()
                .is_some_and(|s| s.starts_with("pkg:gem/"))
        })
        .collect();
    assert!(
        gem_deps.len() >= 15,
        "expected ≥15 gem dependency records, got {}",
        gem_deps.len(),
    );
    let ref_targets = |needle: &str| -> Vec<String> {
        gem_deps
            .iter()
            .find(|d| {
                d["ref"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(&format!("pkg:gem/{needle}@")))
            })
            .and_then(|d| d["dependsOn"].as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    // activesupport declares 9 transitive deps in the fixture lockfile.
    let active = ref_targets("activesupport");
    assert!(
        active.iter().any(|t| t.contains("pkg:gem/concurrent-ruby@")),
        "activesupport → concurrent-ruby edge missing: {active:?}",
    );
    assert!(
        active.iter().any(|t| t.contains("pkg:gem/i18n@")),
        "activesupport → i18n edge missing: {active:?}",
    );
    // i18n → concurrent-ruby edge (chained transitive).
    let i18n = ref_targets("i18n");
    assert!(
        i18n.iter().any(|t| t.contains("pkg:gem/concurrent-ruby@")),
        "i18n → concurrent-ruby edge missing: {i18n:?}",
    );
    // rspec chain: rspec-core → rspec-support.
    let rspec_core = ref_targets("rspec-core");
    assert!(
        rspec_core.iter().any(|t| t.contains("pkg:gem/rspec-support@")),
        "rspec-core → rspec-support edge missing: {rspec_core:?}",
    );
}

#[test]
fn scan_gem_git_and_path_entries_tagged_with_source_type() {
    let sbom = scan_path(&fixture("simple-bundle"));
    let components = sbom["components"].as_array().expect("components array");
    let rails = components
        .iter()
        .find(|c| {
            c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with("pkg:gem/rails@"))
        })
        .expect("rails component present");
    let my_gem = components
        .iter()
        .find(|c| {
            c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with("pkg:gem/my-gem@"))
        })
        .expect("my-gem component present");
    let rails_src = rails["properties"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["name"].as_str() == Some("mikebom:source-type")))
        .and_then(|p| p["value"].as_str())
        .unwrap_or("");
    let my_gem_src = my_gem["properties"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["name"].as_str() == Some("mikebom:source-type")))
        .and_then(|p| p["value"].as_str())
        .unwrap_or("");
    assert_eq!(rails_src, "git");
    assert_eq!(my_gem_src, "path");
}
