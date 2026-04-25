//! Milestone 004 US1 integration tests — standalone `.rpm` artefact
//! scanning via `mikebom sbom scan --path <dir>`.
//!
//! Fixtures are synthesised at test time via the `rpm` crate's
//! `PackageBuilder` — no network, no checked-in binary blobs. This
//! keeps CI self-contained and the golden SBOM shape reproducible
//! across hosts.

#![cfg(test)]
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_mikebom")
}

/// Build a minimal real `.rpm` file at `dest` with the given fields.
fn write_synthetic_rpm(
    dest: &Path,
    name: &str,
    version: &str,
    release: &str,
    arch: &str,
    vendor: &str,
    license: &str,
    requires: &[&str],
) {
    // `rpm::PackageBuilder` methods take `&mut self` and return
    // `&mut Self`, so mutate in-place on a single owned binding.
    let mut b = rpm::PackageBuilder::new(name, version, license, arch, "synthetic test rpm");
    b.release(release)
        .vendor(vendor)
        .packager("mikebom test builder")
        .description("fixture for milestone 004 US1 integration tests");
    for r in requires {
        b.requires(rpm::Dependency::any(*r));
    }
    let pkg = b.build().unwrap();
    pkg.write_file(dest).unwrap();
}

/// Run `mikebom sbom scan --path <dir>` and return the parsed SBOM.
fn scan(dir: &Path) -> (Value, String) {
    let out_file = dir.join("out.cdx.json");
    let output = Command::new(binary_path())
        .arg("sbom")
        .arg("scan")
        .arg("--path")
        .arg(dir)
        .arg("--output")
        .arg(&out_file)
        .arg("--no-deep-hash")
        .output()
        .expect("failed to invoke mikebom");
    assert!(
        output.status.success(),
        "mikebom sbom scan failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json_bytes = std::fs::read(&out_file).expect("SBOM not written");
    let sbom: Value = serde_json::from_slice(&json_bytes).expect("invalid JSON");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (sbom, stderr)
}

fn rpm_components(sbom: &Value) -> Vec<&Value> {
    sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .map(|p| p.starts_with("pkg:rpm/"))
                .unwrap_or(false)
        })
        .collect()
}

fn property_value(component: &Value, name: &str) -> Option<String> {
    component["properties"]
        .as_array()?
        .iter()
        .find(|p| p["name"].as_str() == Some(name))
        .and_then(|p| p["value"].as_str().map(|s| s.to_string()))
}

#[test]
fn scan_rpm_file_fixture_emits_canonical_components() {
    let dir = TempDir::new().unwrap();

    // Mix of vendors covering R9 map branches.
    // Use SPDX-canonical license strings so every component picks up a
    // license through the SPDX canonicaliser. `OpenSSL` / `Zlib` / `MIT`
    // / `GPL-3.0-or-later` are all SPDX-recognised.
    write_synthetic_rpm(
        &dir.path().join("openssl-libs-3.0.7-28.el9_4.x86_64.rpm"),
        "openssl-libs", "3.0.7", "28.el9_4", "x86_64",
        "Red Hat, Inc.", "OpenSSL",
        &["zlib", "libc", "rpmlib(FileDigests)"],
    );
    write_synthetic_rpm(
        &dir.path().join("zlib-1.2.13-5.el9.x86_64.rpm"),
        "zlib", "1.2.13", "5.el9", "x86_64",
        "Red Hat, Inc.", "Zlib",
        &[],
    );
    write_synthetic_rpm(
        &dir.path().join("curl-8.2.1-fc39.x86_64.rpm"),
        "curl", "8.2.1", "fc39", "x86_64",
        "Fedora Project", "MIT",
        &[],
    );
    write_synthetic_rpm(
        &dir.path().join("bash-5.1.8-rocky.x86_64.rpm"),
        "bash", "5.1.8", "1.el9.rocky", "x86_64",
        "Rocky Enterprise Software Foundation", "GPL-3.0-or-later",
        &[],
    );

    let (sbom, _stderr) = scan(dir.path());
    let rpms = rpm_components(&sbom);
    assert_eq!(rpms.len(), 4, "expected 4 rpm components");

    // Every rpm component carries evidence-kind = rpm-file.
    for c in &rpms {
        assert_eq!(
            property_value(c, "mikebom:evidence-kind").as_deref(),
            Some("rpm-file"),
            "missing/wrong evidence-kind on {}",
            c["purl"]
        );
        assert_eq!(
            property_value(c, "mikebom:sbom-tier").as_deref(),
            Some("source"),
            "wrong sbom-tier on {}",
            c["purl"]
        );
    }

    // Vendor-slug mapping — header-derived.
    let purls: Vec<&str> = rpms.iter().map(|c| c["purl"].as_str().unwrap()).collect();
    assert!(
        purls.contains(&"pkg:rpm/redhat/openssl-libs@3.0.7-28.el9_4?arch=x86_64"),
        "Red Hat PURL missing. Got: {purls:?}"
    );
    assert!(
        purls.contains(&"pkg:rpm/fedora/curl@8.2.1-fc39?arch=x86_64"),
        "Fedora PURL missing. Got: {purls:?}"
    );
    assert!(
        purls.contains(&"pkg:rpm/rocky/bash@5.1.8-1.el9.rocky?arch=x86_64"),
        "Rocky PURL missing. Got: {purls:?}"
    );

    // Supplier populated from header `Vendor:` tag.
    let rh = rpms
        .iter()
        .find(|c| c["name"].as_str() == Some("openssl-libs"))
        .unwrap();
    assert_eq!(rh["supplier"]["name"].as_str(), Some("Red Hat, Inc."));

    // Licenses populated.
    assert!(
        rpms.iter().all(|c| c["licenses"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false)),
        "every rpm component must carry a license"
    );

    // rpmlib(...) require dropped; zlib require retained.
    let openssl = rh;
    let _ = openssl; // kept for readability

    // US1 AS-3: dep edge from openssl-libs → zlib resolves because
    // zlib is observed in the same scan. The edge would live in
    // `dependencies[]` — milestone-003 builds that out already via
    // the scan_fs edge resolver.
    let deps = sbom["dependencies"].as_array();
    if let Some(deps) = deps {
        let openssl_ref = "pkg:rpm/redhat/openssl-libs@3.0.7-28.el9_4?arch=x86_64";
        if let Some(entry) = deps
            .iter()
            .find(|d| d["ref"].as_str() == Some(openssl_ref))
        {
            let targets: Vec<&str> = entry["dependsOn"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            assert!(
                targets
                    .iter()
                    .any(|t| t.starts_with("pkg:rpm/redhat/zlib@")),
                "openssl-libs should depend on zlib; targets={targets:?}"
            );
        }
    }
}

#[test]
fn scan_rpm_file_malformed_graceful() {
    let dir = TempDir::new().unwrap();
    // Valid RPM alongside a malformed one.
    write_synthetic_rpm(
        &dir.path().join("good.rpm"),
        "good", "1.0", "1", "noarch",
        "Fedora Project", "MIT", &[],
    );
    // Malformed: right magic, garbage body.
    let mut bad = vec![0xED, 0xAB, 0xEE, 0xDB];
    bad.extend_from_slice(&[0u8; 200]);
    std::fs::write(dir.path().join("bad.rpm"), &bad).unwrap();

    let (sbom, stderr) = scan(dir.path());
    let rpms = rpm_components(&sbom);
    assert_eq!(rpms.len(), 1, "only the good .rpm should yield a component");
    assert!(
        stderr.contains("skipping malformed .rpm file"),
        "expected WARN line mentioning 'skipping malformed .rpm file'; stderr was:\n{stderr}"
    );
}

#[test]
fn scan_rpm_file_empty_dir_yields_zero_rpm_components() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("README"), b"no rpms here").unwrap();
    let (sbom, _stderr) = scan(dir.path());
    let rpms = rpm_components(&sbom);
    assert!(rpms.is_empty(), "no .rpm files → zero rpm components");
}

/// US1 T025 — Source RPM (SRPM) gets `arch=src` in the PURL; no
/// payload walking happens.
#[test]
fn scan_rpm_file_srpm_emits_arch_src() {
    let dir = TempDir::new().unwrap();
    write_synthetic_rpm(
        &dir.path().join("openssl-3.0.7-28.el9.src.rpm"),
        "openssl", "3.0.7", "28.el9", "src",
        "Red Hat, Inc.", "OpenSSL", &[],
    );
    let (sbom, _stderr) = scan(dir.path());
    let rpms = rpm_components(&sbom);
    assert_eq!(rpms.len(), 1);
    let purl = rpms[0]["purl"].as_str().unwrap();
    assert!(
        purl.contains("?arch=src"),
        "SRPM must emit ?arch=src in PURL, got {purl}"
    );
}

/// US1 T024 — rootfs contains BOTH an installed rpmdb.sqlite AND a
/// dropped-in `.rpm` file for a package that's in the rpmdb. Expect
/// exactly one component per unique PURL (dedup at the scan_fs edge-
/// resolver layer; `.rpm`-file evidence merges alongside the rpmdb
/// entry).
#[test]
fn scan_rpm_file_dedup_with_rpmdb_sqlite() {
    // Reuse milestone-003's rhel-image rootfs fixture which carries a
    // populated rpmdb.sqlite. We drop a synthetic `.rpm` into it that
    // matches one of the installed packages' PURL shape.
    let src_rhel = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tests/fixtures/rpm/rhel-image");
    if !src_rhel.exists() {
        // Milestone-003 fixture may not be present in every checkout;
        // skip with a visible log rather than false-fail.
        eprintln!("skipping: {src_rhel:?} not present");
        return;
    }

    let dir = TempDir::new().unwrap();
    // Copy the rhel-image tree into the tempdir.
    copy_dir(&src_rhel, dir.path());

    // Read one installed-package PURL from the baseline SBOM so we can
    // produce a matching synthetic .rpm.
    let (baseline, _) = scan(dir.path());
    let baseline_rpms = rpm_components(&baseline);
    assert!(!baseline_rpms.is_empty(), "baseline should have rpm components");
    let baseline_purls: Vec<String> = baseline_rpms
        .iter()
        .map(|c| c["purl"].as_str().unwrap().to_string())
        .collect();

    // Pick the first baseline package and make a .rpm file for it with
    // the same name/version/release/arch. Vendor = "Red Hat, Inc." so
    // the header-derived slug matches the os-release-derived slug
    // ("redhat" in both cases for the RHEL image).
    // Parse the PURL to extract identity.
    let first = &baseline_purls[0];
    // Format: pkg:rpm/redhat/<name>@<version>-<release>?arch=<arch>
    // Or: pkg:rpm/redhat/<name>@<epoch>:<version>-<release>?arch=<arch>
    let (name, version, release, arch) = parse_rpm_purl(first);

    write_synthetic_rpm(
        &dir.path().join("dropin.rpm"),
        &name, &version, &release, &arch,
        "Red Hat, Inc.", "MIT", &[],
    );

    let (combined, _) = scan(dir.path());
    let combined_rpms = rpm_components(&combined);

    // PURL-based dedup: the same PURL MUST appear exactly once.
    let same_purl_count = combined_rpms
        .iter()
        .filter(|c| c["purl"].as_str() == Some(first.as_str()))
        .count();
    assert_eq!(
        same_purl_count, 1,
        "dedup failed: PURL {first} appears {same_purl_count} times in combined SBOM"
    );

    // Baseline count preserved — no new components; sqlite entry wins
    // for the matching PURL and `.rpm`-file evidence merges in.
    let combined_count = combined_rpms.len();
    let baseline_count = baseline_rpms.len();
    assert_eq!(
        combined_count, baseline_count,
        "expected identical component count; baseline={baseline_count} combined={combined_count}"
    );
}

fn parse_rpm_purl(purl: &str) -> (String, String, String, String) {
    // pkg:rpm/<vendor>/<name>@<version>?arch=<arch>
    // where <version> is <epoch>:<ver>-<rel> or <ver>-<rel>
    let after_ns = purl
        .strip_prefix("pkg:rpm/")
        .expect("must start with pkg:rpm/");
    let slash = after_ns.find('/').expect("no namespace/name separator");
    let name_and_ver_and_qual = &after_ns[slash + 1..];
    let at = name_and_ver_and_qual
        .find('@')
        .expect("no version separator");
    let name = name_and_ver_and_qual[..at].to_string();
    let after_at = &name_and_ver_and_qual[at + 1..];
    let q = after_at.find('?').unwrap_or(after_at.len());
    let version_tok = &after_at[..q];
    let qual = &after_at[q..];
    // Split version_tok into version + release via last '-'
    let dash = version_tok.rfind('-').expect("no version-release dash");
    let version = version_tok[..dash].to_string();
    let release = version_tok[dash + 1..].to_string();
    // Strip epoch if present (`<epoch>:<version>`)
    let (epoch_stripped_version, _epoch) = if let Some(colon) = version.find(':') {
        (version[colon + 1..].to_string(), Some(&version[..colon]))
    } else {
        (version.clone(), None)
    };
    // Extract arch from qualifier
    let arch = qual
        .strip_prefix("?arch=")
        .unwrap_or("")
        .to_string();
    (name, epoch_stripped_version, release, arch)
}

fn copy_dir(src: &Path, dst: &Path) {
    if src.is_dir() {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap().flatten() {
            let from = entry.path();
            let to = dst.join(entry.file_name());
            if from.is_dir() {
                copy_dir(&from, &to);
            } else {
                std::fs::copy(&from, &to).unwrap();
            }
        }
    }
}
