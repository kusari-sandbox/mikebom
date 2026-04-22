//! Parse `/var/lib/dpkg/status` — the authoritative list of installed
//! packages on a Debian/Ubuntu system.
//!
//! The file is a sequence of RFC-822-style stanzas, each describing one
//! package, separated by blank lines. The fields we consume:
//! - `Package`, `Version`, `Architecture` — identity triplet
//! - `Status` — must contain `install ok installed` for the entry to
//!   count as actually installed (everything else is `deinstall`,
//!   `half-installed`, `config-files`, etc.)
//! - `Depends` — comma-separated dependency list, tokens may include
//!   version constraints `(>= 1.0)` and alternatives `libjq1 | libonig5`

use std::path::Path;

use anyhow::{Context, Result};
use mikebom_common::types::purl::Purl;

use super::PackageDbEntry;

/// The dpkg status path relative to a rootfs.
const DPKG_STATUS_PATH: &str = "var/lib/dpkg/status";

/// Read and parse the dpkg status file beneath `rootfs`. Returns an
/// empty vector when the file is absent; returns an error only when
/// the file is present but malformed.
///
/// Feature 005 US2/US3:
/// * `namespace` — the deb PURL namespace segment (e.g. `"debian"`,
///   `"ubuntu"`). Derived from `/etc/os-release::ID` by the caller
///   (`package_db::read_all`) with `"debian"` as the fallback when ID
///   is absent. Used as-is; no internal rewrite table (derivatives like
///   `kali` stay as `kali`, per FR-011).
/// * `distro_version` — optional `VERSION_ID` (e.g. `"12"`, `"24.04"`).
///   When `Some(non_empty)`, emitted as `&distro=<namespace>-<version>`
///   on every generated PURL. When `None` or empty, the qualifier is
///   omitted entirely.
pub fn read(
    rootfs: &Path,
    namespace: &str,
    distro_version: Option<&str>,
) -> Result<Vec<PackageDbEntry>> {
    let status_path = rootfs.join(DPKG_STATUS_PATH);
    if !status_path.is_file() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&status_path)
        .with_context(|| format!("reading {}", status_path.display()))?;
    let source = status_path.to_string_lossy().into_owned();
    Ok(parse(&text, &source, namespace, distro_version))
}

/// Iterate every `<pkg>.list` under `<rootfs>/var/lib/dpkg/info/` and
/// insert every listed absolute path (rootfs-joined) into `claimed`.
///
/// Drives the binary walker's skip gate — files owned by a dpkg
/// package shouldn't also produce `pkg:generic/<filename>` file-level
/// components. Milestone 004 post-ship fix.
///
/// No-op when the dpkg info directory is absent. Malformed `.list`
/// files are tolerated (non-empty non-path lines silently ignored);
/// this function never errors — a failed claim-collection just means
/// more binaries might emit redundant file-level components, not a
/// scan failure.
pub fn collect_claimed_paths(
    rootfs: &Path,
    claimed: &mut std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &mut std::collections::HashSet<(u64, u64)>,
) {
    let info_dir = rootfs.join("var/lib/dpkg/info");
    let Ok(entries) = std::fs::read_dir(&info_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("list") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let line = line.trim();
            if !line.starts_with('/') {
                continue;
            }
            let stripped = line.strip_prefix('/').unwrap_or(line);
            let joined = rootfs.join(stripped);
            super::insert_claim_with_canonical(
                claimed,
                #[cfg(unix)]
                claimed_inodes,
                joined,
            );
        }
    }
}

fn parse(
    text: &str,
    source_path: &str,
    namespace: &str,
    distro_version: Option<&str>,
) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();
    for stanza in split_stanzas(text) {
        if let Some(entry) = parse_stanza(&stanza, source_path, namespace, distro_version) {
            out.push(entry);
        }
    }
    out
}

/// Split on blank lines. Honours RFC-822 continuation: a line starting
/// with a space is part of the preceding field. Continuation is handled
/// inside `parse_stanza`, not here — this just yields stanza strings.
fn split_stanzas(text: &str) -> Vec<String> {
    let mut stanzas = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                stanzas.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push_str(line);
            cur.push('\n');
        }
    }
    if !cur.is_empty() {
        stanzas.push(cur);
    }
    stanzas
}

fn parse_stanza(
    stanza: &str,
    source_path: &str,
    namespace: &str,
    distro_version: Option<&str>,
) -> Option<PackageDbEntry> {
    // Collect fields. Continuation lines (start with space) extend the
    // last field. Keys are compared case-insensitively.
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in stanza.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = fields.last_mut() {
                last.1.push('\n');
                last.1.push_str(line.trim_start());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            fields.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }

    let get = |name: &str| -> Option<&str> {
        fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    // Only count entries whose status is fully installed. dpkg's Status
    // is three space-separated tokens; we want the exact phrase
    // `install ok installed`.
    let status = get("status").unwrap_or("");
    if !status.contains("install ok installed") {
        return None;
    }

    let name = get("package")?.to_string();
    let version = get("version")?.to_string();
    let arch = get("architecture").map(|s| s.to_string());
    if name.is_empty() || version.is_empty() {
        return None;
    }

    let purl_str = build_deb_purl(&name, &version, arch.as_deref(), namespace, distro_version);
    let purl = Purl::new(&purl_str).ok()?;

    let depends = get("depends")
        .map(parse_depends)
        .unwrap_or_default();

    // CycloneDX `component.supplier.name` is free-form text, so the
    // raw "Name <email>" form is fine and useful — it preserves the
    // contact path that distros publish without us having to parse the
    // angle-bracket address out.
    let maintainer = get("maintainer")
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    Some(PackageDbEntry {
        purl,
        name,
        version,
        arch,
        source_path: source_path.to_string(),
        depends,
        maintainer,
        // dpkg status records what's INSTALLED on the rootfs — deployed
        // tier per research.md R13. dpkg doesn't carry a dev/prod
        // distinction or range spec, and the source is always the
        // registry (never local/git/url).
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
        parent_purl: None,
        npm_role: None,
        hashes: Vec::new(),
        sbom_tier: Some("deployed".to_string()),
    })
}

/// Build a deb PURL. Matches the shape that
/// `resolve::path_resolver::resolve_deb_path` emits so the deduplicator
/// merges entries from both sources when they describe the same
/// installed package. The name + version are run through the shared
/// PURL encoder so `+` → `%2B` per the packageurl reference impl.
///
/// Feature 005 US2/US3:
/// * `namespace` is the PURL path segment (the "vendor" per
///   `deb-definition.json`): `debian`, `ubuntu`, or any other distro ID
///   from `/etc/os-release`. The caller derives it; we use it verbatim
///   (no rewrite table).
/// * `distro_version` is `/etc/os-release::VERSION_ID`. When
///   `Some(non_empty)`, the PURL carries `&distro=<namespace>-<ver>`
///   (e.g. `debian-12`, `ubuntu-24.04`, `alpine-3.20`). When `None` or
///   empty, the qualifier is omitted entirely.
fn build_deb_purl(
    name: &str,
    version: &str,
    arch: Option<&str>,
    namespace: &str,
    distro_version: Option<&str>,
) -> String {
    // Encode `+` in the name too (e.g. `libstdc++6` → `libstdc%2B%2B6`)
    // and in the version — both use the same rules per reference impl.
    let encoded_name = mikebom_common::types::purl::encode_purl_segment(name);
    let encoded_version = mikebom_common::types::purl::encode_purl_segment(version);
    let mut s = format!("pkg:deb/{namespace}/{encoded_name}@{encoded_version}");
    let mut have_qualifier = false;
    if let Some(a) = arch {
        if !a.is_empty() {
            s.push_str(&format!("?arch={a}"));
            have_qualifier = true;
        }
    }
    if let Some(v) = distro_version {
        if !v.is_empty() {
            s.push(if have_qualifier { '&' } else { '?' });
            s.push_str("distro=");
            s.push_str(namespace);
            s.push('-');
            s.push_str(v);
        }
    }
    s
}

/// Tokenise a `Depends:` field value into plain package names.
///
/// Input shape: `libc6 (>= 2.34), libjq1 (= 1.6-2.1+deb12u1) | libonig5`
/// Output:      `["libc6", "libjq1", "libonig5"]`
///
/// We drop version constraints (the string inside parentheses) because
/// CycloneDX `dependsOn[]` is a flat reference list — constraints are
/// validated by the package manager at install time, and by the time
/// we're scanning, those edges are already resolved.
///
/// For alternatives (`a | b`), we keep **all** alternates and let the
/// scan orchestrator drop the ones that don't resolve to another entry
/// in this scan. That produces the correct outcome for both cases:
/// - "libjq1 | libonig5" when only libjq1 is installed → edge to libjq1
/// - "libcurl4 | libcurl3-gnutls" when only libcurl4 is installed → edge
///   to libcurl4.
fn parse_depends(raw: &str) -> Vec<String> {
    // dpkg field values can span multiple lines via continuation; a
    // newline between commas is equivalent to a space.
    let flattened: String = raw.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    let mut out = Vec::new();
    for group in flattened.split(',') {
        for alt in group.split('|') {
            let name = alt.trim();
            // Strip version constraint: "name (>= 1.0)" → "name"
            let name = match name.split_once('(') {
                Some((before, _)) => before.trim(),
                None => name,
            };
            // Strip architecture qualifier (multiarch): "name:any" → "name"
            let name = match name.split_once(':') {
                Some((before, _)) => before.trim(),
                None => name,
            };
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    const SOURCE: &str = "/var/lib/dpkg/status";

    #[test]
    fn parses_single_installed_package() {
        let text = "\
Package: jq
Status: install ok installed
Version: 1.6-2.1+deb12u1
Architecture: arm64
Maintainer: Debian Jq Maintainers <pkg-jq-maintainers@alioth-lists.debian.net>
Depends: libc6 (>= 2.34), libjq1 (= 1.6-2.1+deb12u1)
Description: command-line JSON processor
";
        let entries = parse(text, SOURCE, "debian", Some("12"));
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.name, "jq");
        // Typed accessors hold the human-readable literal form.
        assert_eq!(e.version, "1.6-2.1+deb12u1");
        assert_eq!(e.arch.as_deref(), Some("arm64"));
        // Canonical PURL encodes `+` as `%2B` per the packageurl-python
        // reference implementation; `:` stays literal. Both the name
        // and version segments get the same treatment (the name rule
        // kicks in for packages like `libstdc++6`, covered in its
        // own test below).
        assert_eq!(
            e.purl.as_str(),
            "pkg:deb/debian/jq@1.6-2.1%2Bdeb12u1?arch=arm64&distro=debian-12"
        );
        assert_eq!(e.depends, vec!["libc6", "libjq1"]);
        assert_eq!(e.source_path, SOURCE);
        // Supplier extracted as the raw "Name <email>" string — the
        // angle-bracket address is preserved because CycloneDX's
        // `supplier.name` is free-form and downstream tooling commonly
        // wants the contact path intact.
        assert_eq!(
            e.maintainer.as_deref(),
            Some("Debian Jq Maintainers <pkg-jq-maintainers@alioth-lists.debian.net>")
        );
    }

    #[test]
    fn missing_maintainer_field_is_none() {
        let text = "\
Package: minimal
Status: install ok installed
Version: 1.0
Architecture: amd64
";
        let entries = parse(text, SOURCE, "debian", None);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].maintainer.is_none());
    }

    #[test]
    fn empty_maintainer_field_is_none() {
        // dpkg occasionally writes `Maintainer: ` (trailing whitespace
        // only). Treat that as absent — we don't want a blank supplier.
        let text = "\
Package: weird
Status: install ok installed
Version: 1.0
Architecture: amd64
Maintainer:
";
        let entries = parse(text, SOURCE, "debian", None);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].maintainer.is_none());
    }

    #[test]
    fn skips_non_installed_status() {
        let text = "\
Package: ghostie
Status: deinstall ok config-files
Version: 1.0
Architecture: amd64
";
        let entries = parse(text, SOURCE, "debian", None);
        assert!(entries.is_empty());
    }

    #[test]
    fn multiple_stanzas_separated_by_blank_lines() {
        let text = "\
Package: a
Status: install ok installed
Version: 1.0
Architecture: amd64

Package: b
Status: install ok installed
Version: 2.0
Architecture: amd64
";
        let entries = parse(text, SOURCE, "debian", None);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a");
        assert_eq!(entries[1].name, "b");
    }

    #[test]
    fn depends_handles_alternatives_and_version_constraints() {
        let out = parse_depends("libc6 (>= 2.34), libjq1 (= 1.6-2.1+deb12u1) | libonig5");
        assert_eq!(out, vec!["libc6", "libjq1", "libonig5"]);
    }

    #[test]
    fn depends_handles_multiarch_qualifier() {
        let out = parse_depends("libc6:any, libdl:amd64");
        assert_eq!(out, vec!["libc6", "libdl"]);
    }

    #[test]
    fn depends_handles_empty_field() {
        assert!(parse_depends("").is_empty());
    }

    #[test]
    fn continuation_lines_extend_preceding_field() {
        // The Description is multi-line; it must not eat subsequent
        // fields. `Depends` that follows the continuation must still
        // parse cleanly.
        let text = "\
Package: foo
Status: install ok installed
Version: 1.0
Architecture: all
Description: first line
 second continuation line
 third continuation line
Depends: libc6, libm6
";
        let entries = parse(text, SOURCE, "debian", None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].depends, vec!["libc6", "libm6"]);
    }

    #[test]
    fn dpkg_name_with_plus_plus_encodes_to_percent_2b() {
        // `libstdc++6` is the canonical example of a deb package whose
        // name carries `++`. Per the packageurl-python reference impl,
        // both `+` must be percent-encoded in the name segment.
        let text = "\
Package: libstdc++6
Status: install ok installed
Version: 12.2.0-14
Architecture: arm64
";
        let entries = parse(text, SOURCE, "debian", Some("12"));
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        // Typed accessors keep the literal form.
        assert_eq!(e.name, "libstdc++6");
        // Canonical PURL encodes `++` → `%2B%2B`.
        assert_eq!(
            e.purl.as_str(),
            "pkg:deb/debian/libstdc%2B%2B6@12.2.0-14?arch=arm64&distro=debian-12"
        );
    }

    #[test]
    fn omits_distro_qualifier_when_codename_absent() {
        let text = "\
Package: foo
Status: install ok installed
Version: 1.0
Architecture: amd64
";
        let entries = parse(text, SOURCE, "debian", None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].purl.as_str(), "pkg:deb/debian/foo@1.0?arch=amd64");
    }

    #[test]
    fn missing_required_fields_skip_entry() {
        // No Version — entry is dropped, not fatal.
        let text = "\
Package: onlyname
Status: install ok installed
Architecture: amd64
";
        let entries = parse(text, SOURCE, "debian", None);
        assert!(entries.is_empty());
    }

    #[test]
    fn handles_dpkg_status_that_ends_without_trailing_newline() {
        // Last stanza shouldn't be dropped just because the file lacks
        // a terminating blank line.
        let text = "\
Package: foo
Status: install ok installed
Version: 1.0
Architecture: amd64";
        let entries = parse(text, SOURCE, "debian", None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "foo");
    }

    #[test]
    fn read_function_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        // rootfs with no var/lib/dpkg/status — return empty.
        let out = read(dir.path(), "debian", None).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn read_function_reads_from_rootfs_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(DPKG_STATUS_PATH);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            "\
Package: curl
Status: install ok installed
Version: 8.0.0
Architecture: arm64
",
        )
        .unwrap();
        let out = read(dir.path(), "debian", Some("12")).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "curl");
        assert!(out[0].source_path.ends_with("/var/lib/dpkg/status"));
    }

    // ---- Feature 005 US2/US3 --------------------------------------------

    /// T028 — build_deb_purl stamps `<ID>-<VERSION_ID>` into the distro
    /// qualifier when both are present.
    #[test]
    fn build_deb_purl_stamps_id_version_qualifier() {
        let purl = build_deb_purl("libc6", "2.36-9", Some("amd64"), "debian", Some("12"));
        assert_eq!(
            purl,
            "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12"
        );
    }

    /// T029 — `distro_version = None` means no qualifier at all.
    #[test]
    fn build_deb_purl_omits_qualifier_when_distro_version_none() {
        let purl = build_deb_purl("libc6", "2.36-9", Some("amd64"), "debian", None);
        assert_eq!(purl, "pkg:deb/debian/libc6@2.36-9?arch=amd64");
    }

    /// T030 — `Some("")` is the same as `None` (empty VERSION_ID
    /// shouldn't produce `distro=debian-` with a trailing dash).
    #[test]
    fn build_deb_purl_omits_qualifier_when_distro_version_empty() {
        let purl = build_deb_purl("libc6", "2.36-9", Some("amd64"), "debian", Some(""));
        assert_eq!(purl, "pkg:deb/debian/libc6@2.36-9?arch=amd64");
    }

    /// T033 — the `namespace` parameter drives the PURL path segment
    /// (this is the US3 guarantee). No internal rewrite table — the
    /// caller's value is used verbatim.
    #[test]
    fn build_deb_purl_uses_namespace_parameter() {
        let purl =
            build_deb_purl("libssl3", "3.0.13", Some("amd64"), "ubuntu", Some("24.04"));
        assert_eq!(
            purl,
            "pkg:deb/ubuntu/libssl3@3.0.13?arch=amd64&distro=ubuntu-24.04"
        );
    }

    /// T034 — Derivative distros (Kali, Pop!_OS, etc.) must pass
    /// through without silent rewrite to `debian`. The contract is
    /// that whatever `/etc/os-release::ID` says, that's what we put in
    /// the PURL.
    #[test]
    fn build_deb_purl_preserves_raw_id_no_lookup_rewrite() {
        let purl =
            build_deb_purl("foo", "1.0", Some("amd64"), "kali", Some("2024.1"));
        assert_eq!(
            purl,
            "pkg:deb/kali/foo@1.0?arch=amd64&distro=kali-2024.1"
        );
    }
}