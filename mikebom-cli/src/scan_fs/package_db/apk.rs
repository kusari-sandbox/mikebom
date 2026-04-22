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
use mikebom_common::types::license::SpdxExpression;
use mikebom_common::types::purl::{encode_purl_segment, Purl};

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
    let mut maintainer: Option<String> = None;
    let mut license_raw: Option<String> = None;
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
            // `m:` (lowercase) — package maintainer, e.g.
            // `Natanael Copa <ncopa@alpinelinux.org>`. Note: Alpine
            // uses lowercase for this field; capital M is unused in
            // the installed-db format. Freeform, passed through
            // verbatim.
            b'm' => maintainer = Some(val),
            // `L:` (uppercase) — license string. Usually an SPDX
            // expression (`MIT`, `MIT AND BSD-2-Clause`), occasionally
            // prose like `GPL-2.0-only OR GPL-3.0-only`. Canonicalised
            // below; non-canonical values drop silently.
            b'L' => license_raw = Some(val),
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

    let licenses: Vec<SpdxExpression> = license_raw
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| SpdxExpression::try_canonical(s).ok())
        .into_iter()
        .collect();

    Some(PackageDbEntry {
        purl,
        name,
        version,
        arch,
        source_path: source_path.to_string(),
        depends,
        maintainer: maintainer.filter(|s| !s.is_empty()),
        licenses,
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
        hashes: Vec::new(),
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
    // purl-spec § Character encoding: name and version are
    // percent-encoded strings. `+` in apk names (e.g. `libxml++`) and
    // versions (e.g. `3.2.0+alpine1`) MUST encode to `%2B`.
    let mut s = format!(
        "pkg:apk/alpine/{}@{}",
        encode_purl_segment(name),
        encode_purl_segment(version),
    );
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
    fn parses_maintainer_and_license_fields() {
        // Real APK installed-db entries carry `M:` (maintainer) and
        // `L:` (license) — lifts sbomqs NTIA 2025 `comp_supplier`
        // and `comp_license` on alpine fixtures.
        let text = "\
P:musl
V:1.2.4-r2
A:aarch64
m:Timo Teras <timo.teras@iki.fi>
L:MIT
";
        let entries = parse(text, SOURCE, None);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.maintainer.as_deref(), Some("Timo Teras <timo.teras@iki.fi>"));
        assert_eq!(e.licenses.len(), 1);
        assert_eq!(e.licenses[0].as_str(), "MIT");
    }

    #[test]
    fn parses_compound_license_expression() {
        let text = "\
P:gnu-utils
V:1.0-r0
A:x86_64
L:GPL-2.0-only OR GPL-3.0-only
";
        let entries = parse(text, SOURCE, None);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].licenses[0].as_str(),
            "GPL-2.0-only OR GPL-3.0-only"
        );
    }

    #[test]
    fn non_canonical_license_drops_silently() {
        // Freeform prose that can't be canonicalised to SPDX
        // shouldn't fail the whole record — the component still
        // surfaces with no license, same as today's baseline.
        let text = "\
P:obscure-pkg
V:1.0-r0
A:x86_64
L:custom internal license see LICENSE file
";
        let entries = parse(text, SOURCE, None);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].licenses.is_empty());
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