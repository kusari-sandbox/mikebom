//! Parse `/lib/apk/db/installed` — Alpine's installed-package database.
//!
//! The format is a sequence of stanzas separated by blank lines. Each
//! stanza has single-letter key lines (`KEY:value`). Keys we consume:
//! - `P:` — package name
//! - `V:` — version
//! - `A:` — architecture
//! - `D:` — whitespace-separated dependency specifiers
//!
//! Other keys (`C:` checksum, `I:` install size, `M:` maintainer, etc.)
//! are ignored. Unlike dpkg, apk has no continuation-line syntax —
//! every line is `<letter>:<value>`.

use std::path::Path;

use anyhow::{Context, Result};
use mikebom_common::types::purl::Purl;

use super::PackageDbEntry;

const APK_INSTALLED_PATH: &str = "lib/apk/db/installed";

/// Read and parse the apk installed-db beneath `rootfs`. Empty output
/// when the file is absent (typical for Debian/Ubuntu rootfs); errors
/// only on present-but-malformed.
///
/// v6 Phase E: `distro_version` — when `Some`, stamp
/// `&distro=alpine-<VERSION_ID>` on every PURL, matching the
/// packaging-purl convention for apk. Callers typically pass the
/// value of `/etc/os-release::VERSION_ID` read by the dispatcher.
pub fn read(rootfs: &Path, distro_version: Option<&str>) -> Result<Vec<PackageDbEntry>> {
    let path = rootfs.join(APK_INSTALLED_PATH);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let source = path.to_string_lossy().into_owned();
    Ok(parse(&text, &source, distro_version))
}

/// Parse `/lib/apk/db/installed` a second time in scan-claim mode —
/// collect every file owned by some installed apk package into
/// `claimed` as a rootfs-joined absolute path.
///
/// apk's installed-db interleaves package fields with file listings:
/// `F:<dirpath>` lines declare a directory, and each subsequent
/// `R:<basename>` line names a regular file inside that directory.
/// A new `F:` resets the current directory; a new package (blank-line
/// delimited stanza) implicitly resets too.
///
/// Milestone 004 post-ship fix — drives binary walker's skip gate.
/// No-op when the file is absent; malformed lines are tolerated
/// (partial claims don't cause a scan failure).
pub fn collect_claimed_paths(
    rootfs: &Path,
    claimed: &mut std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &mut std::collections::HashSet<(u64, u64)>,
) {
    let path = rootfs.join(APK_INSTALLED_PATH);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let mut current_dir: Option<String> = None;
    for line in text.lines() {
        if line.is_empty() {
            current_dir = None;
            continue;
        }
        if line.len() < 2 || line.as_bytes()[1] != b':' {
            continue;
        }
        match line.as_bytes()[0] {
            b'F' => {
                current_dir = Some(line[2..].to_string());
            }
            b'R' => {
                let basename = &line[2..];
                if let Some(dir) = &current_dir {
                    let rel = if dir.is_empty() {
                        basename.to_string()
                    } else {
                        format!("{dir}/{basename}")
                    };
                    // apk `F:` + `R:` paths are relative to the
                    // rootfs. Resolve to absolute form (rootfs-joined)
                    // and dual-insert (raw + parent-canonical) so the
                    // walker matches regardless of symlinked layout.
                    super::insert_claim_with_canonical(
                        claimed,
                        #[cfg(unix)]
                        claimed_inodes,
                        rootfs.join(&rel),
                    );
                }
            }
            _ => {}
        }
    }
}

fn parse(text: &str, source_path: &str, distro_version: Option<&str>) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();
    for stanza in text.split("\n\n") {
        if stanza.trim().is_empty() {
            continue;
        }
        if let Some(entry) = parse_stanza(stanza, source_path, distro_version) {
            out.push(entry);
        }
    }
    out
}

fn parse_stanza(
    stanza: &str,
    source_path: &str,
    distro_version: Option<&str>,
) -> Option<PackageDbEntry> {
    let mut name = None;
    let mut version = None;
    let mut arch = None;
    let mut depends_raw: Option<String> = None;
    for line in stanza.lines() {
        if line.len() < 2 || line.as_bytes()[1] != b':' {
            continue;
        }
        let key = line.as_bytes()[0];
        let val = line[2..].to_string();
        match key {
            b'P' => name = Some(val),
            b'V' => version = Some(val),
            b'A' => arch = Some(val),
            b'D' => depends_raw = Some(val),
            _ => {}
        }
    }
    let name = name?;
    let version = version?;
    if name.is_empty() || version.is_empty() {
        return None;
    }

    let purl_str = build_apk_purl(&name, &version, arch.as_deref(), distro_version);
    let purl = Purl::new(&purl_str).ok()?;

    let depends = depends_raw
        .as_deref()
        .map(parse_depends)
        .unwrap_or_default();

    Some(PackageDbEntry {
        purl,
        name,
        version,
        arch,
        source_path: source_path.to_string(),
        depends,
        // apk's installed-db doesn't carry a per-package maintainer
        // field equivalent to dpkg's `Maintainer:`. Leave None.
        maintainer: None,
        // apk /lib/apk/db/installed is the installed-package record
        // for Alpine — deployed tier per research.md R13. No dev/prod
        // distinction, no range spec, always registry-sourced.
        licenses: Vec::new(),
        is_dev: None,
        requirement_range: None,
        source_type: None,
        buildinfo_status: None,
        evidence_kind: None,
        binary_class: None,
        binary_stripped: None,
        linkage_kind: None,
        detected_go: None,
        confidence: None,
        binary_packed: None,
        raw_version: None,
        npm_role: None,
        sbom_tier: Some("deployed".to_string()),
    })
}

/// Assemble an apk PURL.
///
/// Shape: `pkg:apk/alpine/<name>@<version>[?arch=<arch>][{&|?}distro=alpine-<ver>]`.
///
/// - `arch`: Optional `arch` qualifier stamped first.
/// - `distro_version`: Optional raw `VERSION_ID` (e.g. `3.20.9`) — when
///   present, emitted as `distro=alpine-<version_id>` per the purl-spec
///   apk convention. Prefix-delimited by `?` or `&` depending on
///   whether arch already opened the qualifier list.
fn build_apk_purl(
    name: &str,
    version: &str,
    arch: Option<&str>,
    distro_version: Option<&str>,
) -> String {
    let mut s = format!("pkg:apk/alpine/{name}@{version}");
    let mut qualifier_open = false;
    if let Some(a) = arch {
        if !a.is_empty() {
            s.push_str(&format!("?arch={a}"));
            qualifier_open = true;
        }
    }
    if let Some(dv) = distro_version {
        if !dv.is_empty() {
            s.push(if qualifier_open { '&' } else { '?' });
            s.push_str("distro=alpine-");
            s.push_str(dv);
        }
    }
    s
}

/// Tokenise apk's `D:` field. Format is whitespace-separated; tokens
/// may embed version constraints (`libc>=1.2`) or look like
/// `provides=value`. Filter rules:
/// - Leading `!` is a **conflict**, not a dependency — skip entirely.
/// - Tokens starting with `/` are file-path dependencies (`/bin/sh`) —
///   not packages, skip.
/// - Tokens containing `:` are pkgconfig/sonames (`so:libc.so.6`) —
///   not packages, skip.
/// - Otherwise, truncate at the first version-constraint operator.
fn parse_depends(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok in raw.split_whitespace() {
        if tok.starts_with('!') {
            continue;
        }
        let end = tok
            .find(|c: char| matches!(c, '<' | '>' | '=' | '~'))
            .unwrap_or(tok.len());
        let name = &tok[..end];
        if name.is_empty() || name.starts_with('/') || name.contains(':') {
            continue;
        }
        out.push(name.to_string());
    }
    out
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    const SOURCE: &str = "/lib/apk/db/installed";

    #[test]
    fn parses_single_package_stanza() {
        let text = "\
C:Q1hfcDK11P2x+nDzvAZKQl8oV4QFE=
P:musl
V:1.2.4-r2
A:aarch64
T:the musl c library (libc) implementation
";
        let entries = parse(text, SOURCE, None);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.name, "musl");
        assert_eq!(e.version, "1.2.4-r2");
        assert_eq!(e.arch.as_deref(), Some("aarch64"));
        assert_eq!(
            e.purl.as_str(),
            "pkg:apk/alpine/musl@1.2.4-r2?arch=aarch64"
        );
    }

    #[test]
    fn parses_multiple_stanzas_with_depends() {
        let text = "\
P:alpine-baselayout
V:3.4.3-r1
A:aarch64
D:alpine-baselayout-data=3.4.3-r1 /bin/sh so:libc.musl-aarch64.so.1

P:busybox
V:1.36.1-r5
A:aarch64
D:so:libc.musl-aarch64.so.1
";
        let entries = parse(text, SOURCE, None);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].depends, vec!["alpine-baselayout-data"]);
        // so:... and /bin/sh are pseudo-deps; both filtered out.
        assert!(entries[1].depends.is_empty());
    }

    #[test]
    fn depends_parser_handles_version_constraints() {
        assert_eq!(
            parse_depends("libc>=1.2 zlib~=1.0 openssl=3.1"),
            vec!["libc", "zlib", "openssl"]
        );
    }

    #[test]
    fn depends_parser_drops_conflict_markers_and_pseudo_deps() {
        assert_eq!(
            parse_depends("!bad-pkg /bin/sh so:libcrypto.so.3 curl"),
            vec!["curl"]
        );
    }

    #[test]
    fn missing_required_fields_skip_entry() {
        let text = "C:hash\nV:1.0\n";
        let entries = parse(text, SOURCE, None);
        assert!(entries.is_empty());
    }

    #[test]
    fn read_function_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let out = read(dir.path(), None).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn build_apk_purl_stamps_distro_qualifier_after_arch() {
        let p = build_apk_purl("busybox", "1.36.1-r31", Some("aarch64"), Some("3.20.9"));
        assert_eq!(p, "pkg:apk/alpine/busybox@1.36.1-r31?arch=aarch64&distro=alpine-3.20.9");
    }

    #[test]
    fn build_apk_purl_stamps_distro_when_no_arch() {
        let p = build_apk_purl("busybox", "1.36.1-r31", None, Some("3.20.9"));
        assert_eq!(p, "pkg:apk/alpine/busybox@1.36.1-r31?distro=alpine-3.20.9");
    }

    #[test]
    fn build_apk_purl_without_distro_unchanged() {
        let p = build_apk_purl("busybox", "1.36.1-r31", Some("aarch64"), None);
        assert_eq!(p, "pkg:apk/alpine/busybox@1.36.1-r31?arch=aarch64");
    }

    #[test]
    fn parse_threads_distro_version_to_stanza_purls() {
        let text = "P:busybox\nV:1.36.1-r31\nA:aarch64\n";
        let entries = parse(text, SOURCE, Some("3.20.9"));
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].purl.as_str(),
            "pkg:apk/alpine/busybox@1.36.1-r31?arch=aarch64&distro=alpine-3.20.9"
        );
    }

    #[test]
    fn read_function_reads_from_rootfs_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(APK_INSTALLED_PATH);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            "P:zlib\nV:1.3-r0\nA:x86_64\n",
        )
        .unwrap();
        let out = read(dir.path(), None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "zlib");
        assert!(out[0].source_path.ends_with("/lib/apk/db/installed"));
    }
}