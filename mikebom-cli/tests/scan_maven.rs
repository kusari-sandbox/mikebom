//! Integration tests for the Maven/Java ecosystem (milestone 003 US3).

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests/fixtures/maven")
}

fn scan_subpath(sub: &str) -> serde_json::Value {
    scan_path(&fixture_dir().join(sub))
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

fn maven_components(sbom: &serde_json::Value) -> Vec<&serde_json::Value> {
    sbom["components"]
        .as_array()
        .expect("components array")
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with("pkg:maven/"))
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

// --- T059: pom.xml source-tier ---------------------------------------

#[test]
fn scan_maven_pom_emits_source_tier_components() {
    let sbom = scan_subpath("pom-three-deps");
    let maven = maven_components(&sbom);
    // Project itself + guava + commons-lang3 (junit is test-scope, dropped).
    let names: Vec<&str> = maven
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(names.contains(&"guava"), "guava missing: {names:?}");
    assert!(
        names.contains(&"commons-lang3"),
        "commons-lang3 missing: {names:?}"
    );
    assert!(
        !names.contains(&"junit"),
        "junit test-scope should be dropped without --include-dev: {names:?}"
    );
}

// --- T060: JAR analyzed-tier -----------------------------------------

#[test]
fn scan_maven_jar_emits_analyzed_tier_components() {
    // Place the fat JAR into its own dir so the walker only processes it.
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::copy(
        fixture_dir().join("fat-jar-three-vendored.jar"),
        dir.path().join("fat.jar"),
    )
    .unwrap();
    let sbom = scan_path(dir.path());
    let maven = maven_components(&sbom);
    let names: Vec<&str> = maven.iter().filter_map(|c| c["name"].as_str()).collect();
    assert!(names.contains(&"guava"));
    assert!(names.contains(&"commons-lang3"));
    assert!(names.contains(&"jackson-databind"));
    // All three should be analyzed-tier (from JAR).
    for c in &maven {
        let tier = prop_value(c, "mikebom:sbom-tier").unwrap_or("");
        assert_eq!(
            tier, "analyzed",
            "JAR-sourced {} has wrong tier: {tier}",
            c["name"].as_str().unwrap_or(""),
        );
    }
}

// --- M2 repo cache: transitive edge reconstruction -------------------

#[test]
fn scan_maven_pulls_transitive_edges_from_cached_m2_repo() {
    // Set up a synthetic rootfs with:
    //   <rootfs>/project/pom.xml         — declares foo, bar, baz
    //   <rootfs>/root/.m2/repository/... — cached poms for foo (deps:
    //                                      bar) and bar (deps: baz).
    // Scan the rootfs. The cache walker should pull foo's declared
    // dependency on bar through to the `dependencies[]` edges.
    let dir = tempfile::tempdir().expect("tempdir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("pom.xml"),
        r#"<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>foo</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();

    // Synthetic ~/.m2 cache inside the rootfs.
    let cache = dir.path().join("root/.m2/repository/com/example");
    let foo_dir = cache.join("foo/1.0.0");
    let bar_dir = cache.join("bar/2.0.0");
    std::fs::create_dir_all(&foo_dir).unwrap();
    std::fs::create_dir_all(&bar_dir).unwrap();
    std::fs::write(
        foo_dir.join("foo-1.0.0.pom"),
        r#"<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>foo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>bar</artifactId>
      <version>2.0.0</version>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();
    std::fs::write(
        bar_dir.join("bar-2.0.0.pom"),
        r#"<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>bar</artifactId>
  <version>2.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>baz</artifactId>
      <version>3.0.0</version>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();

    let sbom = scan_path(dir.path());
    let deps = sbom["dependencies"]
        .as_array()
        .expect("dependencies array");
    let edge_targets = |needle: &str| -> Vec<String> {
        deps.iter()
            .find(|d| {
                d["ref"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(&format!("pkg:maven/com.example/{needle}@")))
            })
            .and_then(|d| d["dependsOn"].as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    // foo → bar edge expected (from foo's cached pom).
    let foo = edge_targets("foo");
    assert!(
        foo.iter()
            .any(|t| t.starts_with("pkg:maven/com.example/bar@")),
        "foo → bar transitive edge missing; foo deps: {foo:?}",
    );
    // bar → baz edge expected (from bar's cached pom).
    let bar = edge_targets("bar");
    assert!(
        bar.iter()
            .any(|t| t.starts_with("pkg:maven/com.example/baz@")),
        "bar → baz transitive edge missing; bar deps: {bar:?}",
    );

    // Transitive coords must appear as components too — not just as
    // edge targets. bar and baz are BFS-discovered; they should carry
    // the `mikebom:source-type=transitive` property.
    let components = sbom["components"]
        .as_array()
        .expect("components array");
    let find_by_artifact = |needle: &str| -> Option<&serde_json::Value> {
        components.iter().find(|c| {
            c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with(&format!("pkg:maven/com.example/{needle}@")))
        })
    };
    for needle in ["bar", "baz"] {
        let comp = find_by_artifact(needle)
            .unwrap_or_else(|| panic!("component for {needle} missing from SBOM"));
        let src_type = comp["properties"]
            .as_array()
            .and_then(|a| a.iter().find(|p| p["name"].as_str() == Some("mikebom:source-type")))
            .and_then(|p| p["value"].as_str())
            .unwrap_or("");
        assert_eq!(
            src_type, "transitive",
            "{needle} should be tagged source_type=transitive",
        );
    }
    // The scanned project's direct dep (foo) stays as "workspace" —
    // it came from the pom.xml, not BFS inference.
    let foo_comp = find_by_artifact("foo").expect("foo component");
    let foo_src = foo_comp["properties"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["name"].as_str() == Some("mikebom:source-type")))
        .and_then(|p| p["value"].as_str())
        .unwrap_or("");
    assert_eq!(
        foo_src, "workspace",
        "direct dep foo should keep source_type=workspace",
    );
}

// --- Cache-only scan: .m2/repository populated but no pom.xml, no JARs ---
// This is the polyglot case where mikebom reported 7/46 vs trivy's 46/46.
// A warm `.m2` cache with no seed source (no scanned pom.xml, no packed
// JAR with META-INF/maven) should still surface every cached artifact as
// a component via the unconditional cache walk.

#[test]
fn scan_maven_cached_only_rootfs_emits_all_cached_coords() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Build a synthetic rootfs with a `.m2/repository/` containing
    // three unrelated cached artifacts — none of which is referenced
    // by any scanned pom.xml or packed JAR (there are none).
    let cache = dir.path().join("root/.m2/repository");
    let alpha_dir = cache.join("com/example/alpha/1.0.0");
    let beta_dir = cache.join("org/sample/beta/2.1.5");
    let gamma_dir = cache.join("io/test/gamma/0.9.0");
    for d in [&alpha_dir, &beta_dir, &gamma_dir] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(
        alpha_dir.join("alpha-1.0.0.pom"),
        r#"<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>alpha</artifactId>
  <version>1.0.0</version>
</project>"#,
    )
    .unwrap();
    std::fs::write(
        beta_dir.join("beta-2.1.5.pom"),
        r#"<?xml version="1.0"?>
<project>
  <groupId>org.sample</groupId>
  <artifactId>beta</artifactId>
  <version>2.1.5</version>
</project>"#,
    )
    .unwrap();
    std::fs::write(
        gamma_dir.join("gamma-0.9.0.pom"),
        r#"<?xml version="1.0"?>
<project>
  <groupId>io.test</groupId>
  <artifactId>gamma</artifactId>
  <version>0.9.0</version>
</project>"#,
    )
    .unwrap();

    let sbom = scan_path(dir.path());
    let maven = maven_components(&sbom);
    let purls: Vec<String> = maven
        .iter()
        .filter_map(|c| c["purl"].as_str().map(String::from))
        .collect();

    // Every cached coord must surface as a Maven component.
    for expected in [
        "pkg:maven/com.example/alpha@1.0.0",
        "pkg:maven/org.sample/beta@2.1.5",
        "pkg:maven/io.test/gamma@0.9.0",
    ] {
        assert!(
            purls.iter().any(|p| p == expected),
            "cache-walk missed {expected}; got: {purls:?}",
        );
    }

    // Each cache-walk-discovered coord must carry source_type = "transitive"
    // (matches the BFS emission shape; no schema divergence).
    for c in &maven {
        let src_type = prop_value(c, "mikebom:source-type").unwrap_or("");
        assert_eq!(
            src_type,
            "transitive",
            "cache-walked component {} has wrong source_type: {src_type}",
            c["name"].as_str().unwrap_or(""),
        );
    }
}

// --- Container-like scan: JARs only, no project pom.xml, no .m2 ------

#[test]
fn scan_maven_container_layout_emits_tree_from_jar_embedded_pom_xml() {
    // Simulates a deployed container image: a directory full of JAR
    // files with embedded pom.properties + pom.xml, but NO project
    // pom.xml and NO .m2 repo. The JAR walker alone should
    // reconstruct the full tree.
    use std::io::Write;

    fn write_jar(path: &std::path::Path, entries: &[(&str, Vec<u8>)]) {
        let file = std::fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in entries {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(body).unwrap();
        }
        zip.finish().unwrap();
    }

    fn props(g: &str, a: &str, v: &str) -> Vec<u8> {
        format!("groupId={g}\nartifactId={a}\nversion={v}\n").into_bytes()
    }

    fn pom_xml(g: &str, a: &str, v: &str, deps: &[(&str, &str, &str)]) -> Vec<u8> {
        let mut x = format!(
            "<project><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version>"
        );
        if !deps.is_empty() {
            x.push_str("<dependencies>");
            for (dg, da, dv) in deps {
                x.push_str(&format!(
                    "<dependency><groupId>{dg}</groupId><artifactId>{da}</artifactId><version>{dv}</version></dependency>"
                ));
            }
            x.push_str("</dependencies>");
        }
        x.push_str("</project>");
        x.into_bytes()
    }

    let dir = tempfile::tempdir().expect("tempdir");
    // /app/lib/app.jar — declares guava + commons-lang3 as deps.
    // /app/lib/guava-32.1.3-jre.jar — declares failureaccess.
    // /app/lib/commons-lang3-3.14.0.jar — leaf.
    // /app/lib/failureaccess-1.0.1.jar — leaf.
    let lib = dir.path().join("app/lib");
    std::fs::create_dir_all(&lib).unwrap();
    write_jar(
        &lib.join("app.jar"),
        &[
            (
                "META-INF/maven/com.example/app/pom.properties",
                props("com.example", "app", "1.0"),
            ),
            (
                "META-INF/maven/com.example/app/pom.xml",
                pom_xml(
                    "com.example",
                    "app",
                    "1.0",
                    &[
                        ("com.google.guava", "guava", "32.1.3-jre"),
                        ("org.apache.commons", "commons-lang3", "3.14.0"),
                    ],
                ),
            ),
        ],
    );
    write_jar(
        &lib.join("guava-32.1.3-jre.jar"),
        &[
            (
                "META-INF/maven/com.google.guava/guava/pom.properties",
                props("com.google.guava", "guava", "32.1.3-jre"),
            ),
            (
                "META-INF/maven/com.google.guava/guava/pom.xml",
                pom_xml(
                    "com.google.guava",
                    "guava",
                    "32.1.3-jre",
                    &[("com.google.guava", "failureaccess", "1.0.1")],
                ),
            ),
        ],
    );
    write_jar(
        &lib.join("commons-lang3-3.14.0.jar"),
        &[(
            "META-INF/maven/org.apache.commons/commons-lang3/pom.properties",
            props("org.apache.commons", "commons-lang3", "3.14.0"),
        )],
    );
    write_jar(
        &lib.join("failureaccess-1.0.1.jar"),
        &[(
            "META-INF/maven/com.google.guava/failureaccess/pom.properties",
            props("com.google.guava", "failureaccess", "1.0.1"),
        )],
    );

    let sbom = scan_path(dir.path());
    let comps = sbom["components"].as_array().expect("components");
    let maven_names: Vec<&str> = comps
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with("pkg:maven/"))
        })
        .filter_map(|c| c["name"].as_str())
        .collect();
    for expected in ["app", "guava", "commons-lang3", "failureaccess"] {
        assert!(
            maven_names.contains(&expected),
            "{expected} missing from container scan; got {maven_names:?}",
        );
    }

    let deps = sbom["dependencies"].as_array().expect("dependencies");
    let edge_targets = |needle: &str| -> Vec<String> {
        deps.iter()
            .find(|d| {
                d["ref"]
                    .as_str()
                    .is_some_and(|s| s.contains(&format!("/{needle}@")))
            })
            .and_then(|d| d["dependsOn"].as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    // app → guava + commons-lang3
    let app_edges = edge_targets("app");
    assert!(
        app_edges.iter().any(|t| t.contains("/guava@")),
        "app → guava edge missing: {app_edges:?}",
    );
    assert!(
        app_edges.iter().any(|t| t.contains("/commons-lang3@")),
        "app → commons-lang3 edge missing: {app_edges:?}",
    );
    // guava → failureaccess (transitive, from JAR-embedded pom.xml)
    let guava_edges = edge_targets("guava");
    assert!(
        guava_edges.iter().any(|t| t.contains("/failureaccess@")),
        "guava → failureaccess edge missing: {guava_edges:?}",
    );
}

// --- Parent-chain effective-POM resolution ---------------------------

#[test]
fn scan_maven_parent_chain_resolves_full_transitive_tree() {
    // Synthetic rootfs: project pom declares libfoo@1.0 directly.
    // libfoo's cached pom declares libbar WITHOUT an inline version —
    // the version lives in libfoo-parent's <dependencyManagement>.
    // This edge only resolves if parent-chain walking fires.
    let dir = tempfile::tempdir().expect("tempdir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("pom.xml"),
        r#"<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>libfoo</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();

    // Synthetic ~/.m2 inside the rootfs so discovery finds it under
    // <rootfs>/root/.m2/repository.
    let cache = dir.path().join("root/.m2/repository/com/example");
    let libfoo_dir = cache.join("libfoo/1.0");
    let libfoo_parent_dir = cache.join("libfoo-parent/1.0");
    let libbar_dir = cache.join("libbar/2.0");
    for d in [&libfoo_dir, &libfoo_parent_dir, &libbar_dir] {
        std::fs::create_dir_all(d).unwrap();
    }

    // libfoo-parent: declares libbar version 2.0 in <dependencyManagement>.
    std::fs::write(
        libfoo_parent_dir.join("libfoo-parent-1.0.pom"),
        r#"<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>libfoo-parent</artifactId>
  <version>1.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.example</groupId>
        <artifactId>libbar</artifactId>
        <version>2.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>"#,
    )
    .unwrap();
    // libfoo: declares libbar as a dep with NO inline version.
    std::fs::write(
        libfoo_dir.join("libfoo-1.0.pom"),
        r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>libfoo-parent</artifactId>
    <version>1.0</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>libfoo</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>libbar</artifactId>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();
    // libbar: leaf.
    std::fs::write(
        libbar_dir.join("libbar-2.0.pom"),
        r#"<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>libbar</artifactId>
  <version>2.0</version>
</project>"#,
    )
    .unwrap();

    let sbom = scan_path(dir.path());
    let deps = sbom["dependencies"]
        .as_array()
        .expect("dependencies array");
    let libfoo_targets: Vec<String> = deps
        .iter()
        .find(|d| {
            d["ref"]
                .as_str()
                .is_some_and(|s| s.starts_with("pkg:maven/com.example/libfoo@"))
        })
        .and_then(|d| d["dependsOn"].as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        libfoo_targets
            .iter()
            .any(|t| t.starts_with("pkg:maven/com.example/libbar@2.0")),
        "libfoo → libbar@2.0 edge missing; without parent-chain resolution, version-less deps like this one would be dropped: {libfoo_targets:?}",
    );
    // libbar must appear as a component too (BFS emits it once the
    // dep-mgmt version resolves).
    let components = sbom["components"].as_array().expect("components");
    assert!(
        components.iter().any(|c| {
            c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with("pkg:maven/com.example/libbar@2.0"))
        }),
        "libbar@2.0 component missing from SBOM",
    );
}

// --- T061: placeholder version becomes design tier -------------------

#[test]
fn scan_maven_placeholder_version_becomes_design_tier() {
    let sbom = scan_subpath("pom-with-property-ref");
    let maven = maven_components(&sbom);
    let sibling = maven
        .iter()
        .find(|c| c["name"].as_str() == Some("sibling"))
        .expect("sibling component present");
    let tier = prop_value(sibling, "mikebom:sbom-tier").unwrap_or("");
    assert_eq!(tier, "design");
    let range = prop_value(sibling, "mikebom:requirement-range").unwrap_or("");
    assert_eq!(range, "${sibling.version}");
}
