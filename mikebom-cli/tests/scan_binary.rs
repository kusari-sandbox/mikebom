//! Milestone 004 US2 integration tests — generic-binary reader
//! (ELF / Mach-O / PE) end-to-end.
//!
//! These tests invoke the compiled `mikebom` binary against real
//! system binaries (Mach-O on darwin; ELF if any are present). They
//! SKIP cleanly on platforms where no suitable binary exists rather
//! than false-failing.

#![cfg(test)]
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_mikebom")
}

fn scan(dir: &Path) -> Value {
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
        "mikebom sbom scan failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let json_bytes = std::fs::read(&out_file).expect("SBOM not written");
    serde_json::from_slice(&json_bytes).expect("invalid JSON")
}

fn property_value(component: &Value, name: &str) -> Option<String> {
    component["properties"]
        .as_array()?
        .iter()
        .find(|p| p["name"].as_str() == Some(name))
        .and_then(|p| p["value"].as_str().map(|s| s.to_string()))
}

fn find_file_level(sbom: &Value) -> Option<&Value> {
    sbom["components"]
        .as_array()?
        .iter()
        .find(|c| property_value(c, "mikebom:binary-class").is_some())
}

fn find_system_binary() -> Option<PathBuf> {
    // On macOS: /bin/ls is a fat Mach-O (CAFEBABE). On Linux:
    // /bin/ls is ELF. Both work with our reader.
    for candidate in ["/bin/ls", "/usr/bin/ls"] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[test]
fn scan_system_binary_emits_file_level_and_linkage() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no /bin/ls found");
        return;
    };

    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("ls-sample");
    std::fs::copy(&src, &dest).unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();
    assert!(!components.is_empty(), "scan must produce components");

    // File-level binary component exists and is well-formed.
    let file_level =
        find_file_level(&sbom).expect("file-level binary component missing");
    let class = property_value(file_level, "mikebom:binary-class").unwrap();
    assert!(
        matches!(class.as_str(), "elf" | "macho" | "pe"),
        "binary-class must be one of elf/macho/pe, got {class}"
    );
    // Stripped bit is always emitted (true or false).
    let stripped = property_value(file_level, "mikebom:binary-stripped");
    assert!(
        matches!(stripped.as_deref(), Some("true") | Some("false")),
        "binary-stripped must be 'true' or 'false', got {stripped:?}"
    );
    // Linkage kind is always emitted on a binary component.
    let linkage = property_value(file_level, "mikebom:linkage-kind");
    assert!(
        matches!(
            linkage.as_deref(),
            Some("dynamic") | Some("static") | Some("mixed")
        ),
        "linkage-kind must be one of dynamic/static/mixed, got {linkage:?}"
    );

    // At least one linkage-evidence component (every real /bin/ls
    // dynamically links against libc).
    let linkage_components: Vec<&Value> = components
        .iter()
        .filter(|c| {
            property_value(c, "mikebom:evidence-kind").as_deref()
                == Some("dynamic-linkage")
        })
        .collect();
    assert!(
        !linkage_components.is_empty(),
        "expected ≥1 dynamic-linkage component from /bin/ls"
    );

    // Every linkage-evidence component has the canonical pkg:generic
    // PURL + sbom-tier=analyzed + evidence-kind=dynamic-linkage.
    for c in &linkage_components {
        let purl = c["purl"].as_str().unwrap();
        assert!(
            purl.starts_with("pkg:generic/"),
            "linkage PURL must be pkg:generic/... got {purl}"
        );
        assert_eq!(
            property_value(c, "mikebom:sbom-tier").as_deref(),
            Some("analyzed")
        );
    }
}

#[test]
fn scan_non_binary_files_skipped() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("script.sh"), b"#!/bin/sh\necho hi").unwrap();
    std::fs::write(dir.path().join("data.txt"), b"hello").unwrap();
    // 1024-byte buffer that's not a recognised binary magic.
    std::fs::write(dir.path().join("noise.bin"), vec![0u8; 2048]).unwrap();

    let sbom = scan(dir.path());
    let has_binary = sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| property_value(c, "mikebom:binary-class").is_some());
    assert!(
        !has_binary,
        "no binary components should be emitted for non-binary files"
    );
}

/// Helper — produce a minimal Debian-like rootfs under `dir`:
/// - `/etc/os-release` → ID=debian
/// - `/var/lib/dpkg/status` with a single installed-package stanza
/// - `/var/lib/dpkg/info/<pkg>.list` with one file entry (absolute path)
///
/// The caller is responsible for writing the binary at the claimed path.
fn setup_debian_rootfs(
    dir: &Path,
    pkg_name: &str,
    version: &str,
    arch: &str,
    claimed_abs_paths: &[&str],
) {
    std::fs::create_dir_all(dir.join("etc")).unwrap();
    std::fs::create_dir_all(dir.join("var/lib/dpkg/info")).unwrap();
    std::fs::write(dir.join("etc/os-release"), b"ID=debian\n").unwrap();
    std::fs::write(
        dir.join("var/lib/dpkg/status"),
        format!(
            "Package: {pkg_name}\nVersion: {version}\nArchitecture: {arch}\nStatus: install ok installed\n\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let mut list_body = String::from("/.\n");
    for p in claimed_abs_paths {
        list_body.push_str(p);
        list_body.push('\n');
    }
    std::fs::write(
        dir.join(format!("var/lib/dpkg/info/{pkg_name}.list")),
        list_body,
    )
    .unwrap();
}

/// Count `pkg:generic/` components whose PURL contains `file-sha256=…` AND
/// whose basename matches `needle`. This is the specific signature of a
/// file-level binary component from the binary walker (as opposed to
/// linkage-evidence pkg:generic/<soname> components).
fn count_file_level_for(sbom: &Value, needle: &str) -> usize {
    sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            let p = c["purl"].as_str().unwrap_or("");
            p.starts_with("pkg:generic/")
                && p.contains("file-sha256=")
                && p.contains(needle)
        })
        .count()
}

/// Primary regression test (Test A in the v2 plan) — reproduces the
/// user's reported ~917 FP failure mode. A Debian rootfs with the
/// modern usrmerge layout (`/bin` is a symlink to `usr/bin`). A binary
/// is placed at its real location (`/usr/bin/base64`); dpkg's
/// `coreutils.list` claims that canonical path. The binary walker
/// enters via the `/bin` symlink — so `read_dir` returns
/// `<rootfs>/bin/base64` while the claim is `<rootfs>/usr/bin/base64`.
/// Without canonicalization, the claim-skip misses and the binary
/// emits a spurious `pkg:generic/base64?file-sha256=…` on top of the
/// `pkg:deb/…/coreutils` component.
#[cfg(unix)]
#[test]
fn dpkg_usrmerge_rootfs_skips_symlinked_binaries() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();

    // Real directory for usr/bin; /bin is a symlink → usr/bin (usrmerge).
    std::fs::create_dir_all(dir.path().join("usr/bin")).unwrap();
    std::os::unix::fs::symlink("usr/bin", dir.path().join("bin")).unwrap();
    std::fs::copy(&src, dir.path().join("usr/bin/base64")).unwrap();

    setup_debian_rootfs(
        dir.path(),
        "coreutils",
        "8.32-4",
        "amd64",
        &["/usr/bin/base64"],
    );

    let sbom = scan(dir.path());

    // Deb component present.
    let has_deb = sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| {
            c["purl"]
                .as_str()
                .map(|p| p.starts_with("pkg:deb/") && p.contains("coreutils"))
                .unwrap_or(false)
        });
    assert!(has_deb, "pkg:deb/…/coreutils component must be present");

    // ZERO file-level pkg:generic for the usrmerge-claimed binary.
    // This is the specific regression: pre-fix, the walker enters via
    // /bin/base64 (symlink traversal) and the path `<rootfs>/bin/base64`
    // doesn't match the claim `<rootfs>/usr/bin/base64` character-for-
    // character, so the skip misses and a redundant pkg:generic/base64
    // file-level component gets emitted.
    let fp = count_file_level_for(&sbom, "base64");
    assert_eq!(
        fp, 0,
        "usrmerge-claimed binary must NOT emit pkg:generic file-level component; \
         got {fp}. Components: {:?}",
        sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["purl"].as_str().unwrap_or("").to_string())
            .collect::<Vec<_>>()
    );
}

/// Test C in the v2 plan — regression guard: the non-usrmerge rootfs
/// (plain directories, no symlinks) MUST continue working after the
/// canonicalization change. This is the pattern the earlier
/// `dpkg_rootfs_suppresses_owned_binaries` test exercised; keeping it
/// separate ensures the simpler code path doesn't silently regress.
#[cfg(unix)]
#[test]
fn dpkg_non_usrmerge_rootfs_still_works() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();

    // Plain directory — no /bin symlink.
    std::fs::create_dir_all(dir.path().join("usr/bin")).unwrap();
    std::fs::copy(&src, dir.path().join("usr/bin/mytool")).unwrap();

    setup_debian_rootfs(
        dir.path(),
        "mytool",
        "1.0",
        "amd64",
        &["/usr/bin/mytool"],
    );

    let sbom = scan(dir.path());
    let fp = count_file_level_for(&sbom, "mytool");
    assert_eq!(
        fp, 0,
        "non-usrmerge dpkg-claimed binary must be skipped; got {fp} file-level components"
    );
}

/// Test E in the v2 plan — unmanaged binaries MUST still be reported.
/// Usrmerge rootfs, binary at `/opt/bin/jq`, no dpkg claim. This is the
/// target use case: the user curl'd a binary that no package manager
/// owns; we MUST flag it.
#[cfg(unix)]
#[test]
fn dpkg_unmanaged_binary_under_opt_still_emits() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();

    // Usrmerge structure + unclaimed binary at /opt/bin/.
    std::fs::create_dir_all(dir.path().join("usr/bin")).unwrap();
    std::os::unix::fs::symlink("usr/bin", dir.path().join("bin")).unwrap();
    std::fs::create_dir_all(dir.path().join("opt/bin")).unwrap();
    std::fs::copy(&src, dir.path().join("opt/bin/unmanaged-jq")).unwrap();
    setup_debian_rootfs(dir.path(), "placeholder", "1.0", "amd64", &[]);

    let sbom = scan(dir.path());

    // The unmanaged /opt/bin/unmanaged-jq MUST emit a file-level
    // binary component. The binary-class filter is format-aware — on
    // darwin this scans a Mach-O in a Linux rootfs, which gets
    // filtered BEFORE the claim check. So this assertion is gated by
    // the host format. On Linux CI the walker sees an ELF and emits;
    // on darwin, the format filter suppresses everything and the
    // assertion becomes "zero file-level, zero pkg:deb for
    // placeholder". We check the latter shape so the test is
    // portable.
    let has_unmanaged = count_file_level_for(&sbom, "unmanaged-jq") > 0;
    let is_linux_host = cfg!(target_os = "linux");
    if is_linux_host {
        assert!(
            has_unmanaged,
            "unmanaged /opt/bin/unmanaged-jq MUST emit a file-level component"
        );
    } else {
        // darwin: Mach-O-in-Linux-rootfs filter suppresses the binary
        // walker output entirely. Still assert the deb component is
        // present (proves the rootfs wiring runs).
        let has_placeholder = sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| {
                c["purl"]
                    .as_str()
                    .map(|p| p.contains("placeholder"))
                    .unwrap_or(false)
            });
        assert!(
            has_placeholder,
            "placeholder deb component must be present"
        );
    }
}

/// Post-ship regression guard — binary walker MUST skip the file-level
/// component for any binary whose path is claimed by a dpkg `.list` file.
/// Reproduces the user's reported Debian/Ubuntu fixture regression where
/// every `/usr/bin/*` emitted both `pkg:deb/…/<pkg>` (from dpkg status) AND
/// `pkg:generic/<filename>?file-sha256=…` (redundant, from the binary walker).
#[test]
fn dpkg_rootfs_suppresses_owned_binaries() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };

    let dir = TempDir::new().unwrap();
    // Debian-style rootfs markers.
    std::fs::create_dir_all(dir.path().join("var/lib/dpkg/info")).unwrap();
    std::fs::create_dir_all(dir.path().join("usr/bin")).unwrap();
    std::fs::create_dir_all(dir.path().join("etc")).unwrap();
    std::fs::write(dir.path().join("etc/os-release"), b"ID=debian\n").unwrap();

    // Minimal valid dpkg status stanza for the package that owns
    // the binary at /usr/bin/my-tool. The test binary itself won't
    // pass our ELF-only filter on macOS (Mach-O), BUT the claim path
    // check fires regardless of format. We drop a Mach-O into the
    // claimed path and verify it's filtered by the path-claim check
    // BEFORE the Linux format filter would have applied (both filters
    // OR-together to produce the same skip result).
    std::fs::write(
        dir.path().join("var/lib/dpkg/status"),
        b"Package: mytool\nVersion: 1.0\nArchitecture: amd64\nStatus: install ok installed\n\n",
    )
    .unwrap();
    // .list file declares ownership of /usr/bin/my-tool.
    std::fs::write(
        dir.path().join("var/lib/dpkg/info/mytool.list"),
        b"/.\n/usr\n/usr/bin\n/usr/bin/my-tool\n",
    )
    .unwrap();
    // Copy the real system binary to the claimed path.
    std::fs::copy(&src, dir.path().join("usr/bin/my-tool")).unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();

    // Should see the deb package component.
    let has_deb = components.iter().any(|c| {
        c["purl"]
            .as_str()
            .map(|p| p.starts_with("pkg:deb/"))
            .unwrap_or(false)
    });
    assert!(has_deb, "expected pkg:deb/… component for mytool");

    // MUST NOT see a pkg:generic/<name>?file-sha256=… for the binary
    // whose path is claimed.
    let has_generic_filelevel = components.iter().any(|c| {
        let purl = c["purl"].as_str().unwrap_or("");
        purl.starts_with("pkg:generic/my-tool") && purl.contains("file-sha256=")
    });
    assert!(
        !has_generic_filelevel,
        "dpkg-claimed binary must NOT emit a pkg:generic file-level component; \
         saw one at claim-path /usr/bin/my-tool. Components: {:?}",
        components
            .iter()
            .map(|c| c["purl"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
    );
}

/// v6 behavior change (conformance bug 6a): embedded-version-string
/// scans are now GATED on `skip_file_level_and_linkage`. Claimed
/// binaries (dpkg-owned, rpm-dir-heuristic, go-in-linux,
/// python/jdk-collapsed) do NOT run the curated version-string
/// scanner.
///
/// Rationale: previously, dpkg-owned `/usr/bin/curl` would double-
/// emit as both `pkg:deb/.../curl@7.88.1` (from dpkg) and
/// `pkg:generic/curl@7.88.1` (from the curl version-string pattern
/// matching `libcurl/7.88.1` in the binary). The deduplicator groups
/// by (ecosystem, name, version) so the two don't merge. The FP flood
/// from self-identifying claimed binaries was the larger correctness
/// problem than losing static-library version detection inside
/// claimed binaries.
///
/// The v6 gate lives at `binary/mod.rs` — the `if !skip_file_level_and_linkage`
/// now wraps `version_strings::scan` as well. Unit tests on
/// `version_strings::scan` (binary/version_strings.rs::tests) continue
/// to verify the pattern library in isolation.
#[test]
fn version_strings_gated_on_claim_documented() {
    // Placeholder: an ELF fixture with `OpenSSL 3.0.11` in .rodata
    // + a dpkg `.list` entry claiming its path would exercise end-to-end.
    // Covered today by:
    //  - version_strings::scan unit tests (pattern library still correct)
    //  - unclaimed-binary scan_binary tests (version-strings still emit for unclaimed)
}

/// Test B1 from the v3 plan — CPython stdlib files (extension
/// modules + libpython + versioned executable) collapse into ONE
/// `pkg:generic/cpython@<X.Y>` umbrella component, regardless of how
/// many individual files are present. Uses no rootfs markers so the
/// format filter doesn't pre-empt the walker on macOS hosts.
#[test]
fn python_stdlib_collapses_to_single_cpython_component() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };

    let dir = TempDir::new().unwrap();
    // Simulated python:3.11-slim install layout.
    std::fs::create_dir_all(
        dir.path()
            .join("usr/local/lib/python3.11/lib-dynload"),
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("usr/local/bin")).unwrap();
    // A dozen .cpython extensions that normally emit as 12 separate
    // pkg:generic components.
    for module in [
        "_bisect", "_ssl", "_sha256", "_hashlib", "_struct",
        "_json", "_random", "_socket", "_pickle", "_bz2", "_lzma",
        "_decimal",
    ] {
        std::fs::copy(
            &src,
            dir.path().join(format!(
                "usr/local/lib/python3.11/lib-dynload/{module}.cpython-311-aarch64-linux-gnu.so"
            )),
        )
        .unwrap();
    }
    // libpython + python binary.
    std::fs::copy(
        &src,
        dir.path().join("usr/local/lib/libpython3.11.so.1.0"),
    )
    .unwrap();
    std::fs::copy(&src, dir.path().join("usr/local/bin/python3.11")).unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();

    // ZERO pkg:generic/<file>?file-sha256= components for stdlib paths.
    let stdlib_filelevels = components
        .iter()
        .filter(|c| {
            let p = c["purl"].as_str().unwrap_or("");
            p.starts_with("pkg:generic/")
                && p.contains("file-sha256=")
                && (p.contains(".cpython-311") || p.contains("libpython") || p.contains("/python3.11"))
        })
        .count();
    assert_eq!(
        stdlib_filelevels, 0,
        "Python stdlib files MUST collapse (none should emit individually); got {stdlib_filelevels}"
    );

    // Exactly ONE cpython umbrella.
    let umbrellas: Vec<&Value> = components
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .map(|p| p.starts_with("pkg:generic/cpython@"))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(
        umbrellas.len(),
        1,
        "exactly one cpython umbrella expected; got {}",
        umbrellas.len()
    );
    assert_eq!(
        umbrellas[0]["purl"].as_str().unwrap(),
        "pkg:generic/cpython@3.11"
    );
    assert_eq!(
        property_value(umbrellas[0], "mikebom:evidence-kind").as_deref(),
        Some("python-stdlib-collapsed")
    );
    assert_eq!(
        property_value(umbrellas[0], "mikebom:confidence").as_deref(),
        Some("heuristic")
    );
    // mikebom:source-files property lists all source paths.
    let sources = property_value(umbrellas[0], "mikebom:source-files")
        .expect("mikebom:source-files must be set on collapsed umbrella");
    assert!(sources.contains("_bisect.cpython-311"));
    assert!(sources.contains("libpython3.11.so.1.0"));
    assert!(sources.contains("usr/local/bin/python3.11"));
}

/// Test B3 — multi-version layouts produce one umbrella per
/// `<major>.<minor>` version.
#[test]
fn python_collapse_emits_one_umbrella_per_version() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();
    for ver in ["3.9", "3.11"] {
        let libdir = dir.path().join(format!("usr/lib/python{ver}/lib-dynload"));
        std::fs::create_dir_all(&libdir).unwrap();
        std::fs::copy(
            &src,
            libdir.join(format!("_ssl.cpython-{}-aarch64-linux-gnu.so", ver.replace(".", ""))),
        )
        .unwrap();
    }

    let sbom = scan(dir.path());
    let umbrellas: Vec<String> = sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| {
            c["purl"].as_str().and_then(|p| {
                if p.starts_with("pkg:generic/cpython@") {
                    Some(p.to_string())
                } else {
                    None
                }
            })
        })
        .collect();
    assert_eq!(umbrellas.len(), 2, "expected 2 umbrellas, got {umbrellas:?}");
    assert!(umbrellas.contains(&"pkg:generic/cpython@3.9".to_string()));
    assert!(umbrellas.contains(&"pkg:generic/cpython@3.11".to_string()));
}

/// Test B4 — non-python `.so` files MUST still emit as normal
/// file-level components. Guards against pattern over-fire.
#[test]
fn python_collapse_does_not_eat_non_python_so() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("opt/bin")).unwrap();
    std::fs::copy(&src, dir.path().join("opt/bin/libmyapp.so")).unwrap();

    let sbom = scan(dir.path());
    let has_libmyapp = sbom["components"].as_array().unwrap().iter().any(|c| {
        let p = c["purl"].as_str().unwrap_or("");
        p.contains("libmyapp.so") && p.contains("file-sha256=")
    });
    assert!(
        has_libmyapp,
        "non-python /opt/bin/libmyapp.so MUST emit as file-level component"
    );
    // No cpython umbrella.
    let umbrella_count = sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .map(|p| p.starts_with("pkg:generic/cpython@"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(umbrella_count, 0);
}

/// Test C1 (v4 plan) — unversioned Python symlinks (`python3`, `python`)
/// must collapse into the cpython umbrella via symlink resolution. Before
/// the fix, `python3` failed the pattern match (no `<major>.<minor>` in
/// the basename) and emitted as a separate pkg:generic component.
#[cfg(unix)]
#[test]
fn python_collapse_catches_unversioned_symlink() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("usr/local/bin")).unwrap();
    std::fs::copy(&src, dir.path().join("usr/local/bin/python3.11")).unwrap();
    std::os::unix::fs::symlink("python3.11", dir.path().join("usr/local/bin/python3")).unwrap();
    std::os::unix::fs::symlink("python3.11", dir.path().join("usr/local/bin/python")).unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();

    // ZERO file-level components for any of the three python binaries.
    for name in ["python3.11", "python3", "python"] {
        let count = components
            .iter()
            .filter(|c| {
                let p = c["purl"].as_str().unwrap_or("");
                p.contains("file-sha256=")
                    && p.starts_with(&format!("pkg:generic/{name}"))
            })
            .count();
        assert_eq!(
            count, 0,
            "python binary `{name}` must NOT emit a file-level component; collapsed into umbrella"
        );
    }

    // Exactly ONE cpython@3.11 umbrella.
    let umbrella: Vec<&Value> = components
        .iter()
        .filter(|c| c["purl"].as_str() == Some("pkg:generic/cpython@3.11"))
        .collect();
    assert_eq!(umbrella.len(), 1, "expected exactly one cpython@3.11 umbrella");

    // The `mikebom:source-files` property lists ALL three python paths
    // (including the unversioned symlinks — recorded as the walker saw them).
    let sources = property_value(umbrella[0], "mikebom:source-files")
        .expect("umbrella must carry mikebom:source-files");
    assert!(sources.contains("python3.11"), "sources missing python3.11: {sources}");
    assert!(sources.contains("/python3"), "sources missing python3: {sources}");
    // The bare `python` symlink should also be listed.
    assert!(
        sources.contains("/python\""
            .trim_end_matches('"'))
        || sources.ends_with("/python")
        || sources.contains("/python;")
        || sources.contains("/python "),
        "sources missing bare python symlink: {sources}"
    );
}

/// Test C2 — source-tree build artifacts (`Python-<ver>/python` and
/// `Python-<ver>/Modules/python.o`) must collapse into the cpython
/// umbrella instead of emitting as individual components.
#[cfg(unix)]
#[test]
fn python_collapse_catches_source_tree_build_artifacts() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("usr/src/Python-3.11.4/Modules")).unwrap();
    std::fs::copy(&src, dir.path().join("usr/src/Python-3.11.4/python")).unwrap();
    std::fs::copy(&src, dir.path().join("usr/src/Python-3.11.4/Modules/python.o")).unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();

    // No file-level components for source-tree artifacts.
    let leaked = components
        .iter()
        .filter(|c| {
            let p = c["purl"].as_str().unwrap_or("");
            p.contains("file-sha256=") && (p.contains("python.o") || p.ends_with("/python"))
        })
        .count();
    assert_eq!(leaked, 0, "source-tree build artifacts must not emit individually");

    // Exactly one cpython@3.11 umbrella.
    let umbrella: Vec<&Value> = components
        .iter()
        .filter(|c| c["purl"].as_str() == Some("pkg:generic/cpython@3.11"))
        .collect();
    assert_eq!(umbrella.len(), 1);
}

/// Test C3 — `.o` files outside any Python source tree must be
/// silently skipped by the walker. They're compilation intermediates
/// with no place in a runtime SBOM.
#[cfg(unix)]
#[test]
fn object_files_skipped_at_walker() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("opt/build")).unwrap();
    // A .o that's not under any Python source tree — must be dropped.
    std::fs::copy(&src, dir.path().join("opt/build/random.o")).unwrap();
    // A .a static archive — same treatment.
    std::fs::copy(&src, dir.path().join("opt/build/random.a")).unwrap();

    let sbom = scan(dir.path());
    let leaked = sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            let p = c["purl"].as_str().unwrap_or("");
            p.contains("file-sha256=") && (p.contains("random.o") || p.contains("random.a"))
        })
        .count();
    assert_eq!(
        leaked, 0,
        ".o / .a files must be skipped at the walker (not shipped in runtime images)"
    );
}

/// Test C5 — over-fire guard. Paths containing "python" as a
/// substring but NOT matching a real Python runtime pattern
/// (`python3.11-config`, `ipython`, `pythonic`) must NOT be routed to
/// the collapser.
#[cfg(unix)]
#[test]
fn py_suffix_does_not_over_match() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("usr/bin")).unwrap();
    std::fs::create_dir_all(dir.path().join("usr/local/bin")).unwrap();
    // These all contain the substring "python" but none is a python
    // runtime we should collapse.
    std::fs::copy(&src, dir.path().join("usr/bin/pythonic")).unwrap();
    std::fs::copy(&src, dir.path().join("usr/bin/python3.11-config")).unwrap();
    std::fs::copy(&src, dir.path().join("usr/local/bin/ipython")).unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();

    // Zero cpython umbrella emitted.
    let umbrella_count = components
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .map(|p| p.starts_with("pkg:generic/cpython@"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        umbrella_count, 0,
        "no cpython umbrella expected; none of these are Python runtime binaries"
    );

    // Each binary emits as its own file-level component (or is
    // processed normally — the important thing is they're NOT
    // collapsed).
    for name in ["pythonic", "python3.11-config", "ipython"] {
        let has_filelevel = components.iter().any(|c| {
            let p = c["purl"].as_str().unwrap_or("");
            p.contains("file-sha256=") && p.contains(name)
        });
        assert!(
            has_filelevel,
            "`{name}` must emit as its own file-level component (not collapsed)"
        );
    }
}

#[test]
fn linux_rootfs_skips_macho_host_system_leakage() {
    // Regression test for reported macOS framework leakage:
    // scanning a Linux container image tarball was picking up
    // `/System/Library/Frameworks/...` linkage entries from
    // contaminating Mach-O binaries whose LC_LOAD_DYLIB entries
    // pointed at host-system paths. The OS-aware filter skips
    // Mach-O / PE binaries inside Linux rootfs.
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };

    let dir = TempDir::new().unwrap();
    // Make this look like a Linux rootfs.
    std::fs::create_dir_all(dir.path().join("etc")).unwrap();
    std::fs::write(
        dir.path().join("etc/os-release"),
        b"ID=alpine\nVERSION_ID=3.20\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("lib/apk/db")).unwrap();
    std::fs::write(dir.path().join("lib/apk/db/installed"), b"").unwrap();
    // Drop a Mach-O binary inside the "Linux" rootfs — simulates the
    // reported host-leakage scenario.
    std::fs::copy(&src, dir.path().join("usr/bin/stray-macho"))
        .or_else(|_| {
            std::fs::create_dir_all(dir.path().join("usr/bin")).unwrap();
            std::fs::copy(&src, dir.path().join("usr/bin/stray-macho"))
        })
        .unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();

    // Zero Mach-O file-level components (filtered by rootfs-kind check).
    let macho_count = components
        .iter()
        .filter(|c| property_value(c, "mikebom:binary-class").as_deref() == Some("macho"))
        .count();
    assert_eq!(
        macho_count, 0,
        "Mach-O binary inside Linux rootfs must NOT produce file-level components"
    );

    // Zero /System/Library/... linkage entries.
    let leaked = components
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .map(|p| p.contains("System%2FLibrary") || p.contains("%2FSystem%2F"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        leaked, 0,
        "no /System/Library/... linkage entries should appear in Linux-rootfs scan"
    );
}

#[test]
fn linkage_evidence_dedups_across_parent_binaries() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no /bin/ls found");
        return;
    };

    let dir = TempDir::new().unwrap();
    // Drop two copies of the same binary — every DT_NEEDED / LC_LOAD_DYLIB
    // entry from both should merge into ONE linkage-evidence component
    // with two occurrences per FR-028a / Q5.
    std::fs::copy(&src, dir.path().join("bin-a")).unwrap();
    std::fs::copy(&src, dir.path().join("bin-b")).unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();

    // Count file-level components — should be exactly 2 (one per bin).
    let file_levels: Vec<&Value> = components
        .iter()
        .filter(|c| property_value(c, "mikebom:binary-class").is_some())
        .collect();
    assert_eq!(
        file_levels.len(),
        2,
        "exactly two file-level binary components expected"
    );

    // No linkage-evidence PURL appears more than once in components[] —
    // dedup must collapse identical sonames across the two binaries.
    let mut seen_purls = std::collections::HashSet::new();
    let mut dupe = None;
    for c in components.iter().filter(|c| {
        property_value(c, "mikebom:evidence-kind").as_deref() == Some("dynamic-linkage")
    }) {
        let purl = c["purl"].as_str().unwrap().to_string();
        if !seen_purls.insert(purl.clone()) {
            dupe = Some(purl);
            break;
        }
    }
    assert!(
        dupe.is_none(),
        "linkage-evidence PURL duplicated: {dupe:?} (FR-028a dedup failed)"
    );
}

// ===== v5 Phase C — JDK umbrella collapse tests (D1–D4) =====

/// D1 — Debian/Ubuntu openjdk install tree: `usr/lib/jvm/java-17-openjdk-amd64/`
/// with bin/ + lib/ + lib/server/ binaries should collapse to ONE
/// `pkg:generic/openjdk@17` umbrella, zero file-level components for
/// those paths.
#[cfg(unix)]
#[test]
fn jdk_collapses_debian_openjdk_tree() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();
    let jdk = dir
        .path()
        .join("usr/lib/jvm/java-17-openjdk-amd64");
    std::fs::create_dir_all(jdk.join("bin")).unwrap();
    std::fs::create_dir_all(jdk.join("lib/server")).unwrap();
    std::fs::copy(&src, jdk.join("bin/java")).unwrap();
    std::fs::copy(&src, jdk.join("bin/javac")).unwrap();
    std::fs::copy(&src, jdk.join("bin/jar")).unwrap();
    std::fs::copy(&src, jdk.join("lib/libjli.so")).unwrap();
    std::fs::copy(&src, jdk.join("lib/server/libjvm.so")).unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();

    // Zero file-level pkg:generic for any JDK path.
    let jdk_filelevels = components
        .iter()
        .filter(|c| {
            let p = c["purl"].as_str().unwrap_or("");
            p.starts_with("pkg:generic/")
                && p.contains("file-sha256=")
                && (p.contains("/java") || p.contains("libjvm") || p.contains("libjli"))
        })
        .count();
    assert_eq!(
        jdk_filelevels, 0,
        "JDK binaries must collapse; got {jdk_filelevels} file-level"
    );

    // Exactly one openjdk@17 umbrella.
    let umbrellas: Vec<&Value> = components
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .map(|p| p.starts_with("pkg:generic/openjdk@"))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(umbrellas.len(), 1, "exactly one openjdk umbrella expected");
    assert_eq!(
        umbrellas[0]["purl"].as_str().unwrap(),
        "pkg:generic/openjdk@17"
    );
    assert_eq!(
        property_value(umbrellas[0], "mikebom:evidence-kind").as_deref(),
        Some("jdk-runtime-collapsed")
    );
    let sources = property_value(umbrellas[0], "mikebom:source-files")
        .expect("mikebom:source-files must be set");
    assert!(sources.contains("bin/java"));
    assert!(sources.contains("libjvm.so"));
}

/// D2 — Manual tarball layout under `/opt/java/<N>/` should also
/// collapse (common in multi-stage Docker: `COPY --from=eclipse-temurin`).
#[cfg(unix)]
#[test]
fn jdk_collapses_opt_java_layout() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("opt/java/21/bin")).unwrap();
    std::fs::create_dir_all(dir.path().join("opt/java/21/lib")).unwrap();
    std::fs::copy(&src, dir.path().join("opt/java/21/bin/java")).unwrap();
    std::fs::copy(&src, dir.path().join("opt/java/21/lib/libjli.so")).unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();

    let umbrellas: Vec<&Value> = components
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .map(|p| p.starts_with("pkg:generic/openjdk@"))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(umbrellas.len(), 1);
    assert_eq!(
        umbrellas[0]["purl"].as_str().unwrap(),
        "pkg:generic/openjdk@21"
    );
}

/// D3 — Regression guard: a non-JDK shared library under `/usr/lib/`
/// must NOT be absorbed by the JDK collapser. It should emit as a
/// normal file-level component.
#[cfg(unix)]
#[test]
fn jdk_does_not_eat_non_jdk_so() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("usr/lib/foo")).unwrap();
    std::fs::copy(&src, dir.path().join("usr/lib/foo/libbar.so")).unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();

    // No openjdk umbrella — nothing JDK-shaped in the tree.
    let umbrellas = components
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .map(|p| p.starts_with("pkg:generic/openjdk@"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(umbrellas, 0, "libbar.so must not produce a jdk umbrella");

    // libbar.so should emit as a normal file-level pkg:generic.
    let libbar_filelevel = components
        .iter()
        .filter(|c| {
            let p = c["purl"].as_str().unwrap_or("");
            p.starts_with("pkg:generic/") && p.contains("libbar.so")
        })
        .count();
    assert!(
        libbar_filelevel >= 1,
        "libbar.so must still emit as a file-level component; got {libbar_filelevel}"
    );
}

/// D4 — Version edge case: `java-8-openjdk-*` should produce an
/// umbrella at `@8`, not `@1` or `@1.8`.
#[cfg(unix)]
#[test]
fn jdk_version_edge_cases() {
    let Some(src) = find_system_binary() else {
        eprintln!("skipping: no system binary on host");
        return;
    };
    let dir = TempDir::new().unwrap();
    let jdk = dir
        .path()
        .join("usr/lib/jvm/java-8-openjdk-amd64");
    std::fs::create_dir_all(jdk.join("bin")).unwrap();
    std::fs::copy(&src, jdk.join("bin/java")).unwrap();

    let sbom = scan(dir.path());
    let components = sbom["components"].as_array().unwrap();

    let umbrella = components
        .iter()
        .find(|c| {
            c["purl"]
                .as_str()
                .map(|p| p.starts_with("pkg:generic/openjdk@"))
                .unwrap_or(false)
        })
        .expect("expected one openjdk umbrella");
    assert_eq!(
        umbrella["purl"].as_str().unwrap(),
        "pkg:generic/openjdk@8",
        "Java 8 major should surface as @8, not something longer"
    );
}

// ----------------------------------------------------------------------
// Feature 005 US4 — RPM raw_version property
// ----------------------------------------------------------------------

/// T048 — every rpm component in an rpmdb-sourced scan must carry the
/// `mikebom:raw-version` property. Uses the Rocky-9 rpmdb fixture when
/// present (skips cleanly when absent, so CI without the sbom-
/// conformance checkout still passes).
#[test]
fn rpm_components_carry_raw_version_property() {
    let rocky = Path::new(
        "/Users/mlieberman/Projects/sbom-conformance/fixtures/rocky-9-minimal/project/var/lib/rpm/rpmdb.sqlite",
    );
    if !rocky.is_file() {
        eprintln!("sbom-conformance fixture absent; skipping rpm_components_carry_raw_version_property");
        return;
    }
    let dir = TempDir::new().unwrap();
    let rootfs = dir.path();
    let rpm_dir = rootfs.join("var/lib/rpm");
    std::fs::create_dir_all(&rpm_dir).unwrap();
    std::fs::copy(rocky, rpm_dir.join("rpmdb.sqlite")).unwrap();
    // os-release so distro qualifier comes out correctly — not
    // strictly required for the raw-version check but keeps the
    // emitted SBOM realistic.
    std::fs::create_dir_all(rootfs.join("etc")).unwrap();
    std::fs::write(
        rootfs.join("etc/os-release"),
        "ID=rocky\nVERSION_ID=\"9.3\"\n",
    )
    .unwrap();

    let sbom = scan(rootfs);
    let rpms: Vec<&Value> = sbom["components"]
        .as_array()
        .expect("components")
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with("pkg:rpm/"))
        })
        .collect();
    assert!(!rpms.is_empty(), "expected at least one rpm component");
    for c in &rpms {
        let has_raw = property_value(c, "mikebom:raw-version").is_some();
        assert!(
            has_raw,
            "rpm component missing mikebom:raw-version: purl={}",
            c["purl"].as_str().unwrap_or("")
        );
    }
}

// ----------------------------------------------------------------------
// Feature 005 US2 / US3 — deb PURL distro qualifier + namespace
// ----------------------------------------------------------------------

fn dpkg_stanza(name: &str, version: &str, arch: &str) -> String {
    format!(
        "Package: {name}\nStatus: install ok installed\nVersion: {version}\nArchitecture: {arch}\n\n"
    )
}

fn plant_os_release(rootfs: &Path, id: &str, version_id: &str) {
    let etc = rootfs.join("etc");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(
        etc.join("os-release"),
        format!("ID={id}\nVERSION_ID=\"{version_id}\"\n"),
    )
    .unwrap();
}

fn plant_dpkg_status(rootfs: &Path, stanzas: &[(&str, &str, &str)]) {
    let dpkg_dir = rootfs.join("var/lib/dpkg");
    std::fs::create_dir_all(&dpkg_dir).unwrap();
    let mut body = String::new();
    for (name, ver, arch) in stanzas {
        body.push_str(&dpkg_stanza(name, ver, arch));
    }
    std::fs::write(dpkg_dir.join("status"), body).unwrap();
}

fn deb_components(sbom: &Value) -> Vec<&Value> {
    sbom["components"]
        .as_array()
        .expect("components array")
        .iter()
        .filter(|c| {
            c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with("pkg:deb/"))
        })
        .collect()
}

/// T031 — Debian rootfs (ID=debian, VERSION_ID=12) emits every deb
/// PURL with `&distro=debian-12`. No more legacy `distro=bookworm`.
#[test]
fn debian_rootfs_stamps_debian_n_qualifier() {
    let dir = TempDir::new().unwrap();
    let rootfs = dir.path();
    plant_os_release(rootfs, "debian", "12");
    plant_dpkg_status(rootfs, &[("libc6", "2.36-9", "amd64"), ("curl", "7.88.1-10", "amd64")]);

    let sbom = scan(rootfs);
    let debs = deb_components(&sbom);
    assert!(!debs.is_empty(), "expected at least one deb component");
    for c in &debs {
        let purl = c["purl"].as_str().unwrap();
        assert!(
            purl.contains("&distro=debian-12") || purl.contains("?distro=debian-12"),
            "expected distro=debian-12 on {purl}"
        );
    }
}

/// T036 — Ubuntu rootfs (ID=ubuntu, VERSION_ID=24.04) emits every deb
/// PURL under `pkg:deb/ubuntu/` (no silent rewrite to `debian`) AND
/// carries `&distro=ubuntu-24.04`.
#[test]
fn ubuntu_rootfs_emits_ubuntu_namespace() {
    let dir = TempDir::new().unwrap();
    let rootfs = dir.path();
    plant_os_release(rootfs, "ubuntu", "24.04");
    plant_dpkg_status(rootfs, &[("libssl3", "3.0.13-0ubuntu3", "amd64")]);

    let sbom = scan(rootfs);
    let debs = deb_components(&sbom);
    assert!(!debs.is_empty(), "expected at least one deb component");
    for c in &debs {
        let purl = c["purl"].as_str().unwrap();
        assert!(
            purl.starts_with("pkg:deb/ubuntu/"),
            "expected pkg:deb/ubuntu/ namespace, got {purl}"
        );
        assert!(
            purl.contains("distro=ubuntu-24.04"),
            "expected distro=ubuntu-24.04 on {purl}"
        );
    }
}

/// T037 — when `/etc/os-release` is absent, the emitted CDX's metadata
/// properties must surface the diagnostic so downstream consumers know
/// the scanner couldn't derive distro identity.
#[test]
fn missing_os_release_emits_diagnostic_metadata_property() {
    let dir = TempDir::new().unwrap();
    let rootfs = dir.path();
    // No /etc/os-release. dpkg status still present so a deb entry
    // exists in the SBOM.
    plant_dpkg_status(rootfs, &[("libc6", "2.36-9", "amd64")]);

    let sbom = scan(rootfs);
    let props = sbom["metadata"]["properties"]
        .as_array()
        .expect("metadata.properties");
    let missing = props
        .iter()
        .find(|p| p["name"].as_str() == Some("mikebom:os-release-missing-fields"))
        .expect("expected mikebom:os-release-missing-fields property");
    let value = missing["value"].as_str().expect("value is string");
    assert!(
        value.contains("ID") && value.contains("VERSION_ID"),
        "expected property value to name both ID and VERSION_ID; got {value}"
    );
}

// ----------------------------------------------------------------------
// Feature 005 US1 — npm scoping in --path mode
// ----------------------------------------------------------------------

/// T022 — `--path` scans must exclude the npm-internals tree entirely,
/// so no component should carry `mikebom:npm-role`. The scoping
/// decision: when a caller scans a source tree, npm's own bundled deps
/// are scanner tooling, not application deps.
#[test]
fn path_scan_emits_no_npm_role_property() {
    let dir = TempDir::new().unwrap();
    let rootfs = dir.path();
    // Plant npm's canonical global-install layout in the --path root.
    let npm_root = rootfs.join("usr/lib/node_modules/npm");
    std::fs::create_dir_all(&npm_root).unwrap();
    std::fs::write(
        npm_root.join("package.json"),
        br#"{"name":"npm","version":"10.2.4"}"#,
    )
    .unwrap();
    let arborist = rootfs.join("usr/lib/node_modules/npm/node_modules/@npmcli/arborist");
    std::fs::create_dir_all(&arborist).unwrap();
    std::fs::write(
        arborist.join("package.json"),
        br#"{"name":"@npmcli/arborist","version":"7.0.0"}"#,
    )
    .unwrap();
    // Add one legitimate app dep so the scan is not empty.
    let app_nm = rootfs.join("app/node_modules/lodash");
    std::fs::create_dir_all(&app_nm).unwrap();
    std::fs::write(
        app_nm.join("package.json"),
        br#"{"name":"lodash","version":"4.17.21","license":"MIT"}"#,
    )
    .unwrap();

    let sbom = scan(rootfs);
    let components = sbom["components"].as_array().expect("components");
    let offending: Vec<&str> = components
        .iter()
        .filter(|c| property_value(c, "mikebom:npm-role").is_some())
        .map(|c| c["name"].as_str().unwrap_or(""))
        .collect();
    assert!(
        offending.is_empty(),
        "--path scans must not emit mikebom:npm-role; got {offending:?}"
    );
    // Sanity: the legitimate app dep must still be present.
    let names: Vec<&str> = components
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(
        names.contains(&"lodash"),
        "lodash (the app dep) must still appear; got {names:?}"
    );
}
