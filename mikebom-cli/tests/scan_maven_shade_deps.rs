//! Integration tests for feature 009 — shade-relocation ancestor
//! emission from JAR `META-INF/DEPENDENCIES` files.

use std::io::Write;
use std::path::Path;
use std::process::Command;

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

/// Build a synthetic JAR at `<out_dir>/<artifact>-<version>.jar`
/// with the given embedded primary coord, embedded pom.properties +
/// pom.xml for the primary, and a META-INF/DEPENDENCIES body.
/// Builds a synthetic shaded JAR fixture. Writes `META-INF/MANIFEST.MF`,
/// an embedded primary `pom.properties` + `pom.xml`, a
/// `META-INF/DEPENDENCIES` body, and any supplied synthetic `.class`
/// entries (FR-002b bytecode-presence fixtures). The filter only
/// looks at archive paths, never the class file contents.
fn build_shaded_jar_with_classes(
    out_dir: &Path,
    group: &str,
    artifact: &str,
    version: &str,
    dependencies_body: &str,
    class_paths: &[&str],
) -> std::path::PathBuf {
    std::fs::create_dir_all(out_dir).unwrap();
    let jar_path = out_dir.join(format!("{artifact}-{version}.jar"));
    let file = std::fs::File::create(&jar_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);
    zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
    zip.write_all(b"Manifest-Version: 1.0\n").unwrap();
    let pom_dir = format!("META-INF/maven/{group}/{artifact}/");
    zip.start_file(format!("{pom_dir}pom.properties"), options).unwrap();
    zip.write_all(
        format!("groupId={group}\nartifactId={artifact}\nversion={version}\n").as_bytes(),
    )
    .unwrap();
    zip.start_file(format!("{pom_dir}pom.xml"), options).unwrap();
    zip.write_all(
        format!(
            "<?xml version=\"1.0\"?><project xmlns=\"http://maven.apache.org/POM/4.0.0\">\
             <modelVersion>4.0.0</modelVersion>\
             <groupId>{group}</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version></project>"
        )
        .as_bytes(),
    )
    .unwrap();
    zip.start_file("META-INF/DEPENDENCIES", options).unwrap();
    zip.write_all(dependencies_body.as_bytes()).unwrap();
    for class_path in class_paths {
        zip.start_file(*class_path, options).unwrap();
        zip.write_all(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34").unwrap();
    }
    zip.finish().unwrap();
    jar_path
}

fn maven_components_all(sbom: &serde_json::Value) -> Vec<serde_json::Value> {
    // Flatten top-level + one level of nested components.
    let mut out: Vec<serde_json::Value> = Vec::new();
    if let Some(arr) = sbom["components"].as_array() {
        for c in arr {
            if c["purl"].as_str().map(|p| p.starts_with("pkg:maven/")).unwrap_or(false) {
                out.push(c.clone());
            }
            if let Some(nested) = c["components"].as_array() {
                for child in nested {
                    if child["purl"]
                        .as_str()
                        .map(|p| p.starts_with("pkg:maven/"))
                        .unwrap_or(false)
                    {
                        out.push(child.clone());
                    }
                }
            }
        }
    }
    out
}

fn has_shade_relocation_property(c: &serde_json::Value) -> bool {
    c["properties"]
        .as_array()
        .map(|props| {
            props.iter().any(|p| {
                p["name"].as_str() == Some("mikebom:shade-relocation")
                    && p["value"].as_str() == Some("true")
            })
        })
        .unwrap_or(false)
}

// --- US1 Story 1 core test ---

#[test]
fn shade_relocated_jar_emits_ancestors_with_marker_and_licenses() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Three ancestors: one canonical SPDX, one free-form, one no License.
    let deps = "// Transitive dependencies block\n\
         \n\
         Outer Project\n\
         \n\
         From: 'Test'\n\
         \n\
         - Apache Commons Compress (https://example.com/) org.apache.commons:commons-compress:jar:1.23.0\n\
             License: Apache-2.0  (https://example.com/LICENSE)\n\
         \n\
         - Apache Commons Lang (https://example.com/) org.apache.commons:commons-lang3:jar:3.12.0\n\
             License: Apache License, Version 2.0  (https://example.com/LICENSE)\n\
         \n\
         - Test No License (https://example.com/) com.example:no-license:jar:1.0.0\n";
    let target_dir = dir.path().join("app");
    // Shade-relocated class evidence for each declared ancestor —
    // primary is `com.example:outer`, ancestors live at distinctive
    // leaf paths (compress, lang3, no-license). FR-002b requires
    // bytecode presence before emission.
    let classes: Vec<&str> = vec![
        "com/example/outer/App.class",
        "com/example/shaded/compress/ArchiveStream.class",
        "com/example/shaded/lang3/StringUtils.class",
        "com/example/shaded/license/Foo.class",
    ];
    build_shaded_jar_with_classes(
        &target_dir,
        "com.example",
        "outer",
        "1.0.0",
        deps,
        &classes,
    );

    let sbom = scan_path(dir.path());
    let components = maven_components_all(&sbom);

    let shaded: Vec<_> = components.iter().filter(|c| has_shade_relocation_property(c)).collect();
    let purls: Vec<&str> = shaded.iter().filter_map(|c| c["purl"].as_str()).collect();

    assert!(
        purls.iter().any(|p| p.contains("commons-compress@1.23.0")),
        "canonical SPDX ancestor must emit: {purls:?}"
    );
    assert!(
        purls.iter().any(|p| p.contains("commons-lang3@3.12.0")),
        "free-form-license ancestor must emit (with empty licenses): {purls:?}"
    );
    assert!(
        purls.iter().any(|p| p.contains("com.example/no-license@1.0.0")),
        "no-License-line ancestor must emit: {purls:?}"
    );
}

// --- US1 classifier preservation ---

#[test]
fn shade_relocated_jar_preserves_classifier_in_purl() {
    let dir = tempfile::tempdir().expect("tempdir");
    let deps = "- With Classifier (https://example.com/) com.example:tools:jar:tests:2.0.0\n";
    let target_dir = dir.path().join("app");
    let classes: Vec<&str> = vec![
        "com/example/outer/App.class",
        "com/example/shaded/tools/Helper.class",
    ];
    build_shaded_jar_with_classes(
        &target_dir,
        "com.example",
        "outer",
        "1.0.0",
        deps,
        &classes,
    );

    let sbom = scan_path(dir.path());
    let components = maven_components_all(&sbom);
    let purls: Vec<&str> = components
        .iter()
        .filter(|c| has_shade_relocation_property(c))
        .filter_map(|c| c["purl"].as_str())
        .collect();

    assert!(
        purls.iter().any(|p| p.contains("?classifier=tests")),
        "classifier qualifier must be preserved in PURL: {purls:?}"
    );
}

// --- US1 regression: non-shaded JAR produces pre-feature output ---

#[test]
fn non_shaded_jar_produces_no_shade_relocation_entries() {
    // Build a JAR WITHOUT META-INF/DEPENDENCIES.
    let dir = tempfile::tempdir().expect("tempdir");
    let target_dir = dir.path().join("app");
    std::fs::create_dir_all(&target_dir).unwrap();
    let jar_path = target_dir.join("plain-1.0.0.jar");
    let file = std::fs::File::create(&jar_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);
    zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
    zip.write_all(b"Manifest-Version: 1.0\n").unwrap();
    zip.start_file("META-INF/maven/com.example/plain/pom.properties", options)
        .unwrap();
    zip.write_all(b"groupId=com.example\nartifactId=plain\nversion=1.0.0\n")
        .unwrap();
    zip.start_file("META-INF/maven/com.example/plain/pom.xml", options).unwrap();
    zip.write_all(
        b"<?xml version=\"1.0\"?><project xmlns=\"http://maven.apache.org/POM/4.0.0\">\
        <modelVersion>4.0.0</modelVersion>\
        <groupId>com.example</groupId><artifactId>plain</artifactId><version>1.0.0</version>\
        </project>",
    )
    .unwrap();
    zip.finish().unwrap();

    let sbom = scan_path(dir.path());
    let components = maven_components_all(&sbom);
    let shaded: Vec<_> = components
        .iter()
        .filter(|c| has_shade_relocation_property(c))
        .collect();

    assert!(
        shaded.is_empty(),
        "non-shaded JAR must produce zero shade-relocation entries; got {:?}",
        shaded
            .iter()
            .filter_map(|c| c["purl"].as_str())
            .collect::<Vec<_>>()
    );
}

// --- US1 self-reference guard ---

#[test]
fn self_reference_in_dependencies_is_dropped() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The JAR's DEPENDENCIES lists its OWN coord among the ancestors.
    let deps = "- Outer Self (https://example.com/) com.example:outer:jar:1.0.0\n\
                    License: Apache-2.0 (https://example.com/LICENSE)\n\
         - Real Ancestor (https://example.com/) org.apache.commons:commons-compress:jar:1.23.0\n";
    let target_dir = dir.path().join("app");
    let classes: Vec<&str> = vec![
        "com/example/outer/App.class",
        "com/example/shaded/compress/ArchiveStream.class",
    ];
    build_shaded_jar_with_classes(
        &target_dir,
        "com.example",
        "outer",
        "1.0.0",
        deps,
        &classes,
    );

    let sbom = scan_path(dir.path());
    let components = maven_components_all(&sbom);
    let shaded_purls: Vec<&str> = components
        .iter()
        .filter(|c| has_shade_relocation_property(c))
        .filter_map(|c| c["purl"].as_str())
        .collect();

    // The self-reference must NOT be re-emitted as a shade child.
    let self_count = shaded_purls
        .iter()
        .filter(|p| p.contains("com.example/outer@1.0.0"))
        .count();
    assert_eq!(
        self_count, 0,
        "self-reference must not re-emit as shade child: {shaded_purls:?}"
    );
    // Real ancestor must still emit.
    assert!(
        shaded_purls.iter().any(|p| p.contains("commons-compress@1.23.0")),
        "real ancestor must still emit: {shaded_purls:?}"
    );
}

// --- FR-002b bytecode-presence gating (feature 009 refinement) ---

/// A JAR whose `META-INF/DEPENDENCIES` declares ancestors but whose
/// `.class` entries all live under the JAR's own primary group path
/// must emit zero shade-relocation entries. Apache's
/// maven-dependency-plugin emits `DEPENDENCIES` into any JAR it's
/// configured on; without bytecode-presence gating we'd report every
/// declared transitive as shade-relocated even for non-fat JARs.
#[test]
fn deps_declared_but_not_shaded_produces_no_emission() {
    let dir = tempfile::tempdir().expect("tempdir");
    let deps = "- Apache Commons Compress (https://example.com/) org.apache.commons:commons-compress:jar:1.23.0\n\
                    License: Apache-2.0 (https://example.com/LICENSE)\n\
         - Apache Commons IO (https://example.com/) org.apache.commons:commons-io:jar:2.12.0\n\
                    License: Apache-2.0 (https://example.com/LICENSE)\n";
    let target_dir = dir.path().join("app");
    // Only primary-coord classes — no shaded evidence for either ancestor.
    let classes: Vec<&str> = vec!["com/example/plain/App.class"];
    build_shaded_jar_with_classes(
        &target_dir,
        "com.example",
        "plain",
        "1.0.0",
        deps,
        &classes,
    );

    let sbom = scan_path(dir.path());
    let components = maven_components_all(&sbom);
    let shaded: Vec<&str> = components
        .iter()
        .filter(|c| has_shade_relocation_property(c))
        .filter_map(|c| c["purl"].as_str())
        .collect();

    assert!(
        shaded.is_empty(),
        "declared-only DEPENDENCIES must not emit without bytecode: {shaded:?}"
    );
}

/// A JAR with classes at a shade-relocated path (distinctive leaf
/// matching the ancestor's artifact-id trailing fragment) must emit
/// the ancestor as a shade-relocation entry.
#[test]
fn shaded_dep_at_relocated_path_is_emitted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let deps = "- Apache Commons Compress (https://example.com/) org.apache.commons:commons-compress:jar:1.23.0\n\
                    License: Apache-2.0 (https://example.com/LICENSE)\n";
    let target_dir = dir.path().join("app");
    let classes: Vec<&str> = vec![
        "com/example/outer/App.class",
        "com/example/shaded/compress/ArchiveStream.class",
    ];
    build_shaded_jar_with_classes(
        &target_dir,
        "com.example",
        "outer",
        "1.0.0",
        deps,
        &classes,
    );

    let sbom = scan_path(dir.path());
    let components = maven_components_all(&sbom);
    let shaded: Vec<&str> = components
        .iter()
        .filter(|c| has_shade_relocation_property(c))
        .filter_map(|c| c["purl"].as_str())
        .collect();

    assert!(
        shaded.iter().any(|p| p.contains("commons-compress@1.23.0")),
        "shade-leaf match must emit the ancestor: {shaded:?}"
    );
}

/// A JAR whose bundled classes live at an ancestor's original group
/// path (from a different group namespace than the primary) must emit
/// the ancestor. Covers the "unshaded bundled dep" case.
#[test]
fn unshaded_dep_at_original_group_path_is_emitted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let deps = "- Apache Commons Compress (https://example.com/) org.apache.commons:commons-compress:jar:1.23.0\n\
                    License: Apache-2.0 (https://example.com/LICENSE)\n";
    let target_dir = dir.path().join("app");
    // Primary at `com.example`, ancestor's classes at the natural
    // `org/apache/commons/compress/` path — distinct namespaces, so
    // the unshaded-path check fires.
    let classes: Vec<&str> = vec![
        "com/example/outer/App.class",
        "org/apache/commons/compress/ArchiveStream.class",
    ];
    build_shaded_jar_with_classes(
        &target_dir,
        "com.example",
        "outer",
        "1.0.0",
        deps,
        &classes,
    );

    let sbom = scan_path(dir.path());
    let components = maven_components_all(&sbom);
    let shaded: Vec<&str> = components
        .iter()
        .filter(|c| has_shade_relocation_property(c))
        .filter_map(|c| c["purl"].as_str())
        .collect();

    assert!(
        shaded.iter().any(|p| p.contains("commons-compress@1.23.0")),
        "unshaded-path match must emit the ancestor: {shaded:?}"
    );
}

/// Ancestors whose artifact-id trailing fragment lands in the
/// generic-leaf set (e.g. `io`, `api`, `util`) can only be trusted
/// via the unshaded-path check — a `/io/` substring in an arbitrary
/// shade layout isn't specific enough to prove presence.
#[test]
fn generic_leaf_ancestor_requires_unshaded_match() {
    let dir = tempfile::tempdir().expect("tempdir");
    let deps = "- Apache Commons IO (https://example.com/) org.apache.commons:commons-io:jar:2.12.0\n\
                    License: Apache-2.0 (https://example.com/LICENSE)\n";
    let target_dir = dir.path().join("app");
    // Shade-layout `/io/` fragment is the only evidence. Leaf "io"
    // is generic → must be dropped.
    let classes: Vec<&str> = vec![
        "com/example/outer/App.class",
        "com/example/shaded/io/IOUtils.class",
    ];
    build_shaded_jar_with_classes(
        &target_dir,
        "com.example",
        "outer",
        "1.0.0",
        deps,
        &classes,
    );

    let sbom = scan_path(dir.path());
    let components = maven_components_all(&sbom);
    let shaded: Vec<&str> = components
        .iter()
        .filter(|c| has_shade_relocation_property(c))
        .filter_map(|c| c["purl"].as_str())
        .collect();

    assert!(
        !shaded.iter().any(|p| p.contains("commons-io@2.12.0")),
        "generic-leaf ancestor must not emit on shade-path evidence alone: {shaded:?}"
    );
}
