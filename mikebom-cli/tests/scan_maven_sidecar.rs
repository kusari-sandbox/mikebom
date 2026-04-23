//! Integration tests for feature 007 US1 — Fedora sidecar POM reading.
//!
//! These tests construct synthetic rootfs trees shaped like Fedora-family
//! images (JARs under `/usr/share/maven/lib/`, sidecar POMs under
//! `/usr/share/maven-poms/`) and assert that mikebom's scan emits the
//! expected Maven components.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fedora_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures/maven/fedora_sidecar")
}

fn scan_path(path: &Path) -> serde_json::Value {
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

fn maven_purls(sbom: &serde_json::Value) -> Vec<String> {
    sbom["components"]
        .as_array()
        .expect("components array")
        .iter()
        .filter_map(|c| {
            let p = c["purl"].as_str()?;
            if p.starts_with("pkg:maven/") {
                Some(p.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Fixture rootfs contains:
/// - /usr/share/maven/lib/guice-5.1.0.jar          (no META-INF/maven/)
/// - /usr/share/maven/lib/aopalliance-1.0.jar      (no META-INF/maven/)
/// - /usr/share/maven/lib/guice-child-5.1.0.jar    (no META-INF/maven/; parent chain)
/// - /usr/share/maven/lib/orphan-3.0.jar           (no sidecar POM)
/// - /usr/share/maven-poms/JPP-guice.pom           (Fedora JPP-prefixed)
/// - /usr/share/maven-poms/aopalliance.pom         (plain <name>.pom)
/// - /usr/share/maven-poms/guice-parent.pom        (parent POM)
/// - /usr/share/maven-poms/guice-child.pom         (child, inherits groupId)
#[test]
fn jpp_prefixed_sidecar_resolves_to_maven_component() {
    let sbom = scan_path(&fedora_fixture_root());
    let purls = maven_purls(&sbom);
    assert!(
        purls
            .iter()
            .any(|p| p == "pkg:maven/com.google.inject/guice@5.1.0"),
        "expected pkg:maven/com.google.inject/guice@5.1.0 in {:?}",
        purls
    );
}

#[test]
fn plain_name_sidecar_resolves_to_maven_component() {
    let sbom = scan_path(&fedora_fixture_root());
    let purls = maven_purls(&sbom);
    assert!(
        purls.iter().any(|p| p == "pkg:maven/aopalliance/aopalliance@1.0"),
        "expected pkg:maven/aopalliance/aopalliance@1.0 in {:?}",
        purls
    );
}

#[test]
fn parent_inheritance_resolves_missing_group_id() {
    let sbom = scan_path(&fedora_fixture_root());
    let purls = maven_purls(&sbom);
    // guice-child inherits groupId=com.google.inject and version=5.1.0
    // from guice-parent.pom.
    assert!(
        purls
            .iter()
            .any(|p| p == "pkg:maven/com.google.inject/guice-child@5.1.0"),
        "expected pkg:maven/com.google.inject/guice-child@5.1.0 in {:?}",
        purls
    );
}

#[test]
fn orphan_jar_without_sidecar_is_not_emitted_as_maven_component() {
    let sbom = scan_path(&fedora_fixture_root());
    let purls = maven_purls(&sbom);
    assert!(
        !purls.iter().any(|p| p.contains("orphan")),
        "orphan-3.0.jar has no sidecar POM and must not appear as a Maven component; got {:?}",
        purls
    );
}

#[test]
fn scan_of_empty_rootfs_without_maven_poms_dir_is_clean() {
    // Scan a rootfs that has NO `/usr/share/maven-poms/` directory.
    // The sidecar index should be empty and the scan must succeed
    // without emitting bogus Maven components.
    let tmp = tempfile::tempdir().expect("tempdir");
    let sbom = scan_path(tmp.path());
    let purls = maven_purls(&sbom);
    assert!(
        purls.is_empty(),
        "empty rootfs produced Maven components: {:?}",
        purls
    );
}
