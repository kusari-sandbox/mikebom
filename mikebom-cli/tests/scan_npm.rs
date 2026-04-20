//! Integration tests for npm-ecosystem scanning (US2 of milestone 002).
//!
//! Shells out to the `mikebom sbom scan --path <fixture>` binary the same
//! way `scan_python.rs` does. Each test asserts the per-story acceptance
//! scenarios + success criteria for the npm pathway documented in
//! `specs/002-python-npm-ecosystem/spec.md`.

use std::path::PathBuf;
use std::process::Command;

fn fixture(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures/npm")
        .join(sub)
}

/// Run `mikebom sbom scan --path <fixture>` and return the parsed
/// CycloneDX JSON. Returns None if the binary exits non-zero so the
/// caller can assert refusal cases.
fn scan(fixture_sub: &str, include_dev: bool) -> serde_json::Value {
    let output = scan_raw(fixture_sub, include_dev);
    assert!(
        output.status.success(),
        "scan failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let out_path = output_path_hint();
    let raw = std::fs::read_to_string(&out_path).expect("read sbom");
    serde_json::from_str(&raw).expect("valid JSON")
}

/// One shared temp path per test thread so scan() and scan_raw_with_path
/// agree. Picks a fresh file each call.
fn output_path_hint() -> PathBuf {
    // Re-derive the same path we passed to the invocation — see scan_raw.
    LAST_OUT_PATH.with(|c| c.borrow().clone().expect("no prior scan"))
}

thread_local! {
    static LAST_OUT_PATH: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

fn scan_raw(fixture_sub: &str, include_dev: bool) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let out_path = tempfile::NamedTempFile::new()
        .expect("tempfile")
        .path()
        .to_path_buf();
    LAST_OUT_PATH.with(|c| *c.borrow_mut() = Some(out_path.clone()));
    let mut cmd = Command::new(bin);
    cmd.arg("--offline");
    if include_dev {
        cmd.arg("--include-dev");
    }
    cmd.arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(fixture(fixture_sub))
        .arg("--output")
        .arg(&out_path)
        .arg("--no-deep-hash");
    cmd.output().expect("mikebom should run")
}

fn npm_components(sbom: &serde_json::Value) -> Vec<&serde_json::Value> {
    sbom["components"]
        .as_array()
        .expect("components array")
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with("pkg:npm/"))
        })
        .collect()
}

fn prop_value<'a>(component: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    component["properties"]
        .as_array()?
        .iter()
        .find(|p| p["name"].as_str() == Some(name))?
        .get("value")?
        .as_str()
}

#[test]
fn lockfile_v3_fixture_emits_source_tier_prod_only_by_default() {
    let sbom = scan("lockfile-v3", false);
    let npm = npm_components(&sbom);
    // Only prod deps surface at default — jest is dev-only.
    assert_eq!(
        npm.len(),
        2,
        "lockfile-v3 prod-only: expected chalk + lodash only, got {:?}",
        npm.iter().map(|c| c["name"].as_str()).collect::<Vec<_>>()
    );
    for c in &npm {
        assert_eq!(prop_value(c, "mikebom:sbom-tier"), Some("source"));
        // Prod entries don't emit the dev-dependency property — only
        // true values are surfaced to reduce noise. Absence ≡ prod.
        assert!(
            prop_value(c, "mikebom:dev-dependency").is_none(),
            "{}: prod entries should not surface mikebom:dev-dependency",
            c["name"]
        );
    }
    for c in &npm {
        let purl = c["purl"].as_str().expect("purl");
        assert!(purl.starts_with("pkg:npm/"), "{purl}");
    }
}

#[test]
fn lockfile_v3_marks_npm_ecosystem_complete() {
    let sbom = scan("lockfile-v3", false);
    let compositions = sbom["compositions"]
        .as_array()
        .expect("compositions array");
    let npm_complete = compositions.iter().any(|r| {
        r["aggregate"].as_str() == Some("complete")
            && r["assemblies"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .any(|p| p.as_str().is_some_and(|s| s.starts_with("pkg:npm/")))
                })
                .unwrap_or(false)
    });
    assert!(
        npm_complete,
        "lockfile-sourced npm scan must emit aggregate=complete composition"
    );
}

#[test]
fn lockfile_v3_fixture_with_include_dev_surfaces_jest() {
    let sbom = scan("lockfile-v3", true);
    let npm = npm_components(&sbom);
    assert_eq!(npm.len(), 3, "lockfile-v3 --include-dev: expected 3");
    let jest = npm
        .iter()
        .find(|c| c["name"] == "jest")
        .expect("jest present under --include-dev");
    assert_eq!(
        prop_value(jest, "mikebom:dev-dependency"),
        Some("true"),
        "jest must carry dev-dependency property"
    );
}

#[test]
fn scoped_package_emits_encoded_purl() {
    let sbom = scan("scoped-package", false);
    let npm = npm_components(&sbom);
    let angular = npm
        .iter()
        .find(|c| c["name"] == "@angular/core")
        .expect("@angular/core present");
    assert_eq!(
        angular["purl"].as_str().unwrap(),
        "pkg:npm/%40angular/core@16.2.12",
        "scoped PURL must encode @ per packageurl reference impl"
    );
}

#[test]
fn pnpm_v8_fixture_parses_prod_and_filters_dev() {
    let sbom = scan("pnpm-v8", false);
    let npm = npm_components(&sbom);
    assert_eq!(npm.len(), 1);
    assert_eq!(npm[0]["name"], "is-odd");
    assert_eq!(prop_value(npm[0], "mikebom:sbom-tier"), Some("source"));

    let sbom_all = scan("pnpm-v8", true);
    let npm_all = npm_components(&sbom_all);
    assert_eq!(npm_all.len(), 2);
    let mocha = npm_all
        .iter()
        .find(|c| c["name"] == "mocha")
        .expect("mocha present with --include-dev");
    assert_eq!(prop_value(mocha, "mikebom:dev-dependency"), Some("true"));
}

#[test]
fn node_modules_walk_emits_deployed_tier() {
    let sbom = scan("node-modules-walk", false);
    let npm = npm_components(&sbom);
    assert_eq!(npm.len(), 2, "expected express + safe-buffer");
    for c in &npm {
        assert_eq!(
            prop_value(c, "mikebom:sbom-tier"),
            Some("deployed"),
            "{}: node_modules walk must tag deployed",
            c["name"]
        );
    }
}

#[test]
fn package_json_only_emits_design_tier_and_source_type() {
    let sbom = scan("package-json-only", false);
    let npm = npm_components(&sbom);
    // dependencies has axios (registry) + local-helper (file:) +
    // internal-tool (git+). devDependencies is filtered without
    // --include-dev.
    assert_eq!(npm.len(), 3);
    for c in &npm {
        assert_eq!(
            prop_value(c, "mikebom:sbom-tier"),
            Some("design"),
            "{}: must be design-tier",
            c["name"]
        );
        assert!(
            prop_value(c, "mikebom:requirement-range").is_some(),
            "{}: must carry requirement-range",
            c["name"]
        );
    }
    let local = npm.iter().find(|c| c["name"] == "local-helper").unwrap();
    assert_eq!(prop_value(local, "mikebom:source-type"), Some("local"));
    let git = npm.iter().find(|c| c["name"] == "internal-tool").unwrap();
    assert_eq!(prop_value(git, "mikebom:source-type"), Some("git"));
    let reg = npm.iter().find(|c| c["name"] == "axios").unwrap();
    assert!(
        prop_value(reg, "mikebom:source-type").is_none(),
        "registry entries emit no source-type property"
    );

    // Design-tier-only scans MUST NOT mark the ecosystem complete.
    let compositions = sbom["compositions"].as_array().unwrap();
    let npm_complete = compositions.iter().any(|r| {
        r["aggregate"].as_str() == Some("complete")
            && r["assemblies"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .any(|p| p.as_str().is_some_and(|s| s.starts_with("pkg:npm/")))
                })
                .unwrap_or(false)
    });
    assert!(
        !npm_complete,
        "package.json-only must NOT mark npm ecosystem complete"
    );
}

#[test]
fn npm_dependency_tree_reflects_lockfile() {
    // The lockfile-v3-transitive fixture declares express@4.18.2 with
    // an explicit `dependencies:` section listing body-parser,
    // cookie-signature, and safe-buffer — all of which are sibling
    // entries in the same lockfile. The SBOM's `dependencies[]` block
    // must carry a `{ref: pkg:npm/express@4.18.2, dependsOn: [...]}`
    // record listing all three at their lockfile-resolved versions.
    let sbom = scan("lockfile-v3-transitive", false);
    let deps = sbom["dependencies"]
        .as_array()
        .expect("dependencies array");

    let express_record = deps
        .iter()
        .find(|r| {
            r["ref"]
                .as_str()
                .is_some_and(|s| s == "pkg:npm/express@4.18.2")
        })
        .expect("express must have a dependencies[] record");

    let depends_on: Vec<&str> = express_record["dependsOn"]
        .as_array()
        .expect("dependsOn array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    assert!(
        depends_on
            .iter()
            .any(|s| *s == "pkg:npm/body-parser@1.20.1"),
        "express → body-parser@1.20.1 expected; got {depends_on:?}"
    );
    assert!(
        depends_on
            .iter()
            .any(|s| *s == "pkg:npm/cookie-signature@1.0.6"),
        "express → cookie-signature@1.0.6 expected; got {depends_on:?}"
    );
    assert!(
        depends_on
            .iter()
            .any(|s| *s == "pkg:npm/safe-buffer@5.2.1"),
        "express → safe-buffer@5.2.1 expected; got {depends_on:?}"
    );
}

#[test]
fn v1_lockfile_refuses_with_actionable_error() {
    let output = scan_raw("lockfile-v1-refused", false);
    assert!(
        !output.status.success(),
        "v1 lockfile must cause non-zero exit"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("package-lock.json v1 not supported")
            && stderr.contains("regenerate with npm"),
        "stderr must match the actionable message; got: {stderr}"
    );
}
