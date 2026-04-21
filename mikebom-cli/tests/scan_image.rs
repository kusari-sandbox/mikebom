//! Integration tests for US3 (container-image scans with Python / npm
//! workloads). Synthesises minimal docker-save tarballs on the fly so
//! CI doesn't need Docker, pull bandwidth, or large checked-in blobs.
//!
//! Each test builds an outer tar holding `manifest.json` + one layer
//! tar whose contents are the image's rootfs. The mikebom CLI is then
//! invoked with `--image <tarball>`; the resulting SBOM is inspected.
//!
//! This is the integration-test counterpart to the per-module image-
//! mode unit tests in `pip.rs` and `npm.rs` — those verify the walker
//! logic; this verifies the full pipeline (extract → walk → enrich →
//! serialize) end-to-end.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One file to plant in the synthetic image's rootfs.
struct ImageFile {
    path: &'static str,
    content: Vec<u8>,
}

/// Build a docker-save tarball containing `files` as a single layer.
/// Returns the on-disk path; the caller is responsible for the TempDir
/// lifetime (the TempDir is moved out via `.into_path()` so the
/// tarball survives the test function).
fn build_synthetic_image(files: &[ImageFile]) -> PathBuf {
    // Inner layer tar.
    let mut layer_bytes = Vec::new();
    {
        let mut layer_tar = tar::Builder::new(&mut layer_bytes);
        for f in files {
            let mut header = tar::Header::new_ustar();
            header.set_path(f.path).unwrap();
            header.set_size(f.content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            layer_tar.append(&header, f.content.as_slice()).unwrap();
        }
        layer_tar.finish().unwrap();
    }

    // Outer tarball.
    let manifest =
        r#"[{"Config":"config.json","RepoTags":["mikebom-test:latest"],"Layers":["layer0/layer.tar"]}]"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    let file = tmp.reopen().unwrap();
    {
        let mut outer = tar::Builder::new(file);

        let mut mh = tar::Header::new_ustar();
        mh.set_path("manifest.json").unwrap();
        mh.set_size(manifest.len() as u64);
        mh.set_mode(0o644);
        mh.set_cksum();
        outer.append(&mh, manifest.as_bytes()).unwrap();

        let mut lh = tar::Header::new_ustar();
        lh.set_path("layer0/layer.tar").unwrap();
        lh.set_size(layer_bytes.len() as u64);
        lh.set_mode(0o644);
        lh.set_cksum();
        outer.append(&lh, layer_bytes.as_slice()).unwrap();

        outer.into_inner().unwrap().flush().unwrap();
    }
    tmp.persist(&path).unwrap();
    path
}

fn scan_image(tarball: &Path) -> serde_json::Value {
    let bin = env!("CARGO_BIN_EXE_mikebom");
    let out_path = tempfile::NamedTempFile::new()
        .unwrap()
        .path()
        .to_path_buf();
    let output = Command::new(bin)
        .arg("--offline")
        .arg("sbom")
        .arg("scan")
        .arg("--image")
        .arg(tarball)
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

fn components_by_prefix<'a>(
    sbom: &'a serde_json::Value,
    prefix: &str,
) -> Vec<&'a serde_json::Value> {
    sbom["components"]
        .as_array()
        .expect("components array")
        .iter()
        .filter(|c| c["purl"].as_str().is_some_and(|p| p.starts_with(prefix)))
        .collect()
}

fn has_aggregate_complete_for(sbom: &serde_json::Value, purl_prefix: &str) -> bool {
    sbom["compositions"]
        .as_array()
        .expect("compositions array")
        .iter()
        .any(|r| {
            r["aggregate"].as_str() == Some("complete")
                && r["assemblies"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .any(|p| p.as_str().is_some_and(|s| s.starts_with(purl_prefix)))
                    })
                    .unwrap_or(false)
        })
}

// ----------------------------------------------------------------------
// T040 — Python-on-Debian image scan
// ----------------------------------------------------------------------

/// A minimal dpkg status stanza — three fields, newline-terminated.
fn dpkg_stanza(name: &str, version: &str, arch: &str) -> String {
    format!(
        "Package: {name}\nStatus: install ok installed\nVersion: {version}\nArchitecture: {arch}\nMaintainer: Debian <debian@example.org>\n\n"
    )
}

/// A minimal PEP 639 METADATA blob.
fn pypi_metadata(name: &str, version: &str, license: &str) -> String {
    format!(
        "Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nLicense-Expression: {license}\nAuthor: Test\n"
    )
}

#[test]
fn scan_python_image_emits_mixed_deb_and_pypi_components() {
    let files = vec![
        // Distro identity — this synthetic image carries no VERSION_ID, so
        // the distro tag falls back to VERSION_CODENAME and deb PURLs get
        // `distro=bookworm`. Real images with ID + VERSION_ID would emit
        // `distro=debian-12` (the canonical form) instead.
        ImageFile {
            path: "etc/os-release",
            content: b"ID=debian\nVERSION_CODENAME=bookworm\n".to_vec(),
        },
        // Two deb packages in the dpkg status db.
        ImageFile {
            path: "var/lib/dpkg/status",
            content: [
                dpkg_stanza("libc6", "2.36-9", "amd64"),
                dpkg_stanza("python3", "3.11.2-1", "amd64"),
            ]
            .concat()
            .into_bytes(),
        },
        // Two pypi packages under the Debian system-python site-packages.
        ImageFile {
            path: "usr/lib/python3.11/dist-packages/fastapi-0.109.0.dist-info/METADATA",
            content: pypi_metadata("fastapi", "0.109.0", "MIT").into_bytes(),
        },
        ImageFile {
            path: "usr/lib/python3.11/dist-packages/httpx-0.25.0.dist-info/METADATA",
            content: pypi_metadata("httpx", "0.25.0", "BSD-3-Clause").into_bytes(),
        },
    ];
    let tarball = build_synthetic_image(&files);
    let sbom = scan_image(&tarball);

    let deb = components_by_prefix(&sbom, "pkg:deb/");
    let pypi = components_by_prefix(&sbom, "pkg:pypi/");

    assert_eq!(
        deb.len(),
        2,
        "expected libc6 + python3, got {:?}",
        deb.iter().map(|c| c["name"].as_str()).collect::<Vec<_>>()
    );
    assert_eq!(
        pypi.len(),
        2,
        "expected fastapi + httpx, got {:?}",
        pypi.iter().map(|c| c["name"].as_str()).collect::<Vec<_>>()
    );

    // Both ecosystems must be marked aggregate=complete — dpkg db was
    // read in full, and the pypi entries came from authoritative
    // dist-info (deployed tier).
    assert!(
        has_aggregate_complete_for(&sbom, "pkg:deb/"),
        "deb ecosystem must be aggregate=complete"
    );
    assert!(
        has_aggregate_complete_for(&sbom, "pkg:pypi/"),
        "pypi ecosystem must be aggregate=complete"
    );

    // Every PURL starts with a well-formed prefix (conformance smoke).
    for c in sbom["components"].as_array().unwrap() {
        let p = c["purl"].as_str().unwrap();
        assert!(
            p.starts_with("pkg:deb/") || p.starts_with("pkg:pypi/") || p.starts_with("pkg:apk/"),
            "unexpected PURL prefix: {p}"
        );
    }
}

// ----------------------------------------------------------------------
// T041 — Node-on-Alpine image scan
// ----------------------------------------------------------------------

/// A minimal apk installed-db entry. `C:` is the SHA-1-base64 marker
/// that `apk` uses per package — we leave it unset because
/// `has_npm_signal` / the apk reader tolerate missing fields.
fn apk_stanza(name: &str, version: &str) -> String {
    format!("P:{name}\nV:{version}\nA:x86_64\n\n")
}

fn npm_package_json(name: &str, version: &str, license: &str) -> String {
    format!(r#"{{"name":"{name}","version":"{version}","license":"{license}"}}"#)
}

#[test]
fn scan_node_image_emits_mixed_apk_and_npm_components() {
    let files = vec![
        // Alpine identity — no codename, but `os-release` is still
        // consumed.
        ImageFile {
            path: "etc/os-release",
            content: b"ID=alpine\nVERSION_ID=3.19.1\n".to_vec(),
        },
        // Two apk packages.
        ImageFile {
            path: "lib/apk/db/installed",
            content: [apk_stanza("musl", "1.2.4_git20230717-r4"), apk_stanza("nodejs", "20.10.0-r0")]
                .concat()
                .into_bytes(),
        },
        // App root at the node:*-image convention: /usr/src/app/.
        ImageFile {
            path: "usr/src/app/package.json",
            content: br#"{"name":"myapp","version":"0.1.0","dependencies":{"express":"^4.18.2"}}"#.to_vec(),
        },
        // node_modules/ installed tree.
        ImageFile {
            path: "usr/src/app/node_modules/express/package.json",
            content: npm_package_json("express", "4.18.2", "MIT").into_bytes(),
        },
        ImageFile {
            path: "usr/src/app/node_modules/safe-buffer/package.json",
            content: npm_package_json("safe-buffer", "5.2.1", "MIT").into_bytes(),
        },
    ];
    let tarball = build_synthetic_image(&files);
    let sbom = scan_image(&tarball);

    let apk = components_by_prefix(&sbom, "pkg:apk/");
    let npm = components_by_prefix(&sbom, "pkg:npm/");

    assert_eq!(
        apk.len(),
        2,
        "expected musl + nodejs, got {:?}",
        apk.iter().map(|c| c["name"].as_str()).collect::<Vec<_>>()
    );
    assert_eq!(
        npm.len(),
        2,
        "expected express + safe-buffer (from node_modules walk under /usr/src/app/), got {:?}",
        npm.iter().map(|c| c["name"].as_str()).collect::<Vec<_>>()
    );

    assert!(
        has_aggregate_complete_for(&sbom, "pkg:apk/"),
        "apk ecosystem must be aggregate=complete"
    );
    assert!(
        has_aggregate_complete_for(&sbom, "pkg:npm/"),
        "npm ecosystem must be aggregate=complete (node_modules is deployed tier)"
    );
}

#[test]
fn scan_image_with_mixed_deb_pypi_npm_surfaces_all_three() {
    // Polyglot image: Debian base + a pypi install + an npm app. The
    // whole point of US3 is that all three ecosystems land in the same
    // SBOM from a single `--image` invocation.
    let files = vec![
        ImageFile {
            path: "etc/os-release",
            content: b"ID=debian\nVERSION_CODENAME=bookworm\n".to_vec(),
        },
        ImageFile {
            path: "var/lib/dpkg/status",
            content: dpkg_stanza("libc6", "2.36-9", "amd64").into_bytes(),
        },
        ImageFile {
            path: "usr/lib/python3.11/dist-packages/requests-2.31.0.dist-info/METADATA",
            content: pypi_metadata("requests", "2.31.0", "Apache-2.0").into_bytes(),
        },
        ImageFile {
            path: "app/package.json",
            content: br#"{"name":"service","version":"0.0.1","dependencies":{"lodash":"^4"}}"#.to_vec(),
        },
        ImageFile {
            path: "app/node_modules/lodash/package.json",
            content: npm_package_json("lodash", "4.17.21", "MIT").into_bytes(),
        },
    ];
    let tarball = build_synthetic_image(&files);
    let sbom = scan_image(&tarball);

    assert_eq!(components_by_prefix(&sbom, "pkg:deb/").len(), 1);
    assert_eq!(components_by_prefix(&sbom, "pkg:pypi/").len(), 1);
    assert_eq!(components_by_prefix(&sbom, "pkg:npm/").len(), 1);
}

// ----------------------------------------------------------------------
// Feature 005 US1 — npm scoping in --image mode
// ----------------------------------------------------------------------

/// T021 — `--image` scans must emit npm-internals components with the
/// `mikebom:npm-role = internal` property so downstream consumers can
/// distinguish application deps from the npm tooling that ships in the
/// base image.
#[test]
fn image_scan_emits_mikebom_npm_role_property() {
    let files = vec![
        // npm itself at the canonical global-install layout.
        ImageFile {
            path: "usr/lib/node_modules/npm/package.json",
            content: npm_package_json("npm", "10.2.4", "Artistic-2.0").into_bytes(),
        },
        // One bundled internal dep under npm's own node_modules tree.
        ImageFile {
            path: "usr/lib/node_modules/npm/node_modules/@npmcli/arborist/package.json",
            content: npm_package_json("@npmcli/arborist", "7.0.0", "ISC").into_bytes(),
        },
    ];
    let tarball = build_synthetic_image(&files);
    let sbom = scan_image(&tarball);

    // At least one component should carry mikebom:npm-role=internal.
    let components = sbom["components"].as_array().expect("components");
    let tagged: Vec<&serde_json::Value> = components
        .iter()
        .filter(|c| {
            c["properties"]
                .as_array()
                .map(|props| {
                    props.iter().any(|p| {
                        p["name"].as_str() == Some("mikebom:npm-role")
                            && p["value"].as_str() == Some("internal")
                    })
                })
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !tagged.is_empty(),
        "expected at least one component with mikebom:npm-role=internal in --image output"
    );
}
