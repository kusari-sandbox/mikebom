//! Collapse JDK / JRE binaries (executables under `bin/`, native `.so`
//! libraries under `lib/`, etc.) into one umbrella
//! `pkg:generic/openjdk@<major>` component per unique Java major
//! version.
//!
//! **Why**: container images that install a JDK manually (e.g.
//! `COPY --from=eclipse-temurin:17-jdk` or `adoptium/temurin-binaries`
//! tarballs dropped into `/opt/java/17/`) end up with ~50 binaries
//! that the walker would otherwise emit as individual
//! `pkg:generic/<filename>?file-sha256=…` components — all describing
//! the same runtime. Aggregating them into one umbrella matches the
//! cpython treatment added in v3.
//!
//! **How**: detect files whose path contains a recognizable JDK
//! install prefix; extract the major version (e.g. `17`); record the
//! observation. At scan end, emit one umbrella per unique major
//! version with all source paths listed.
//!
//! Supported install layouts (all `*` are prefix-agnostic):
//! - `**/usr/lib/jvm/java-<N>-openjdk*/...`           — Debian/Ubuntu openjdk-<N>-jdk(-headless)
//! - `**/usr/lib/jvm/jre-<N>-openjdk*/...`            — Debian/Ubuntu openjdk-<N>-jre(-headless)
//! - `**/usr/lib/jvm/java-<N>[./-]...`                — Short-form symlinks
//! - `**/usr/lib/jvm/openjdk-<N>/...`                 — Alpine
//! - `**/opt/java/openjdk-<N>/...`                    — Docker adoptium layout
//! - `**/opt/java/<N>/...`                            — Manual tarball install
//! - `**/opt/jdk-<N>[./-]...`                         — Oracle / generic extract
//! - `**/opt/openjdk-<N>[./-]...`                     — Generic openjdk extract
//! - `**/opt/temurin/<N>/...`                         — Eclipse Temurin
//! - `**/opt/corretto-<N>[./-]...`                    — Amazon Corretto
//!
//! Files that don't match any pattern fall through to the normal
//! file-level emission path — the collapser only claims known JDK
//! trees.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mikebom_common::types::purl::Purl;

use crate::scan_fs::package_db::PackageDbEntry;

/// Accumulates observations of JDK/JRE binaries and emits one umbrella
/// component per unique Java major version at scan end.
#[derive(Default)]
pub struct JdkCollapser {
    /// Unique major versions detected → set of file paths matching
    /// that version's install tree. `BTreeSet` gives deterministic
    /// output order.
    by_version: BTreeMap<String, BTreeSet<PathBuf>>,
}

impl JdkCollapser {
    /// Attempt to classify `path` as a JDK/JRE binary. Returns `true`
    /// if the collapser claimed it (caller should skip file-level +
    /// linkage emission for it).
    pub fn try_collapse(&mut self, path: &Path, rootfs: &Path) -> bool {
        if let Some(version) = detect_jdk_version(path, rootfs) {
            self.by_version
                .entry(version)
                .or_default()
                .insert(path.to_path_buf());
            return true;
        }
        false
    }

    /// Emit one `pkg:generic/openjdk@<major>` umbrella per unique
    /// version. Every source path ends up in the component's
    /// `source_path` field (joined by `; `), the same convention the
    /// cpython umbrella uses.
    pub fn into_entries(self) -> Vec<PackageDbEntry> {
        self.by_version
            .into_iter()
            .filter_map(|(version, paths)| {
                let purl_str = format!("pkg:generic/openjdk@{version}");
                let purl = Purl::new(&purl_str).ok()?;
                let source_path = paths
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("; ");
                Some(PackageDbEntry {
                    purl,
                    name: "openjdk".to_string(),
                    version,
                    arch: None,
                    source_path,
                    depends: Vec::new(),
                    maintainer: None,
                    licenses: vec![],
                    is_dev: None,
                    requirement_range: None,
                    source_type: None,
                    sbom_tier: Some("analyzed".to_string()),
                    buildinfo_status: None,
                    evidence_kind: Some("jdk-runtime-collapsed".to_string()),
                    binary_class: None,
                    binary_stripped: None,
                    linkage_kind: None,
                    detected_go: None,
                    confidence: Some("heuristic".to_string()),
                    binary_packed: None,
                    raw_version: None,
                    npm_role: None,
                    hashes: Vec::new(),
                })
            })
            .collect()
    }
}

/// Inspect `path` and return the Java major version if the path
/// matches a known JDK install layout. Returns `None` for anything
/// else.
pub(crate) fn detect_jdk_version(path: &Path, rootfs: &Path) -> Option<String> {
    let rel = path.strip_prefix(rootfs).ok()?;
    let rel_str = rel.to_string_lossy();

    // Debian/Ubuntu openjdk package installs under /usr/lib/jvm/.
    // Patterns: `java-<N>-openjdk-<arch>`, `jre-<N>-openjdk-<arch>`,
    // `java-<N>-openjdk-<fullver>.<N>.<build>.<arch>` (Fedora long form),
    // `openjdk-<N>` (Alpine), `java-<N>` (short alias).
    if let Some(v) = version_after_prefix(&rel_str, "lib/jvm/java-") {
        return Some(v);
    }
    if let Some(v) = version_after_prefix(&rel_str, "lib/jvm/jre-") {
        return Some(v);
    }
    if let Some(v) = version_after_prefix(&rel_str, "lib/jvm/openjdk-") {
        return Some(v);
    }

    // Manual tarball / Docker layouts under /opt/.
    if let Some(v) = version_after_prefix(&rel_str, "opt/java/openjdk-") {
        return Some(v);
    }
    // `opt/java/<N>/...`
    if let Some(v) = version_after_opt_java(&rel_str) {
        return Some(v);
    }
    if let Some(v) = version_after_prefix(&rel_str, "opt/jdk-") {
        return Some(v);
    }
    if let Some(v) = version_after_prefix(&rel_str, "opt/openjdk-") {
        return Some(v);
    }
    if let Some(v) = version_after_prefix(&rel_str, "opt/corretto-") {
        return Some(v);
    }
    // `opt/temurin/<N>/...`
    if let Some(v) = version_after_prefix(&rel_str, "opt/temurin/") {
        return Some(v);
    }

    // v8 Phase J: Eclipse Temurin's canonical Docker layout installs to
    // `/opt/java/openjdk/` with no version segment in the path. The
    // version lives in `/opt/java/openjdk/release` as
    // `JAVA_VERSION="<full>"`. Read the release file to extract the
    // major. If the file is missing / unparseable, DON'T collapse —
    // matching an arbitrary `/opt/java/openjdk/` directory without
    // version evidence would risk eating unrelated binaries.
    if rel_str.contains("opt/java/openjdk/") {
        let release_path = rootfs.join("opt/java/openjdk/release");
        if let Some(v) = read_jdk_major_from_release(&release_path) {
            return Some(v);
        }
    }

    None
}

/// Parse the `JAVA_VERSION` key from an OpenJDK `release` file and
/// return its major version (the leading digit run). Handles
/// double-quoted, single-quoted, and bare values.
///
/// Returns `None` if the file is absent, unreadable, or lacks a valid
/// `JAVA_VERSION` line.
fn read_jdk_major_from_release(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("JAVA_VERSION=") else {
            continue;
        };
        let trimmed = rest.trim().trim_matches('"').trim_matches('\'');
        let major_end = trimmed
            .bytes()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(trimmed.len());
        if major_end == 0 {
            continue;
        }
        return Some(trimmed[..major_end].to_string());
    }
    None
}

/// After locating `prefix` in `rel`, consume leading ASCII digits
/// and require a terminator in `[/.-]` so we don't accidentally match
/// the middle of a longer name. Returns the digit run (the major
/// version). Rejects a digit run of zero length.
fn version_after_prefix(rel: &str, prefix: &str) -> Option<String> {
    let idx = rel.find(prefix)?;
    let tail = &rel[idx + prefix.len()..];
    let bytes = tail.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    // Must be followed by a path/version terminator, not another
    // letter — guards against matching `jdk-17abc` as version `17`.
    if i < bytes.len() && !matches!(bytes[i], b'/' | b'.' | b'-') {
        return None;
    }
    Some(tail[..i].to_string())
}

/// Special case for `opt/java/<N>/...` where the digits form a
/// standalone path segment (no trailing `.` or `-` within the
/// version itself). Requires `/` before and after the digit run.
fn version_after_opt_java(rel: &str) -> Option<String> {
    let idx = rel.find("opt/java/")?;
    let tail = &rel[idx + "opt/java/".len()..];
    let bytes = tail.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    // Must be followed by `/` (next path segment) for this bare-number
    // form. `opt/java/openjdk-*` is handled by a different branch.
    if i < bytes.len() && bytes[i] != b'/' {
        return None;
    }
    Some(tail[..i].to_string())
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    fn detect(rootfs: &str, path: &str) -> Option<String> {
        detect_jdk_version(Path::new(path), Path::new(rootfs))
    }

    // --- Common Debian/Ubuntu layouts ---

    #[test]
    fn matches_debian_openjdk_17_bin_java() {
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/usr/lib/jvm/java-17-openjdk-amd64/bin/java"
            ),
            Some("17".to_string())
        );
    }

    #[test]
    fn matches_debian_openjdk_17_lib_libjvm() {
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/usr/lib/jvm/java-17-openjdk-amd64/lib/server/libjvm.so"
            ),
            Some("17".to_string())
        );
    }

    #[test]
    fn matches_debian_openjdk_21_jre() {
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/usr/lib/jvm/jre-21-openjdk-amd64/lib/libjli.so"
            ),
            Some("21".to_string())
        );
    }

    #[test]
    fn matches_debian_openjdk_8_with_short_minor() {
        // Java 8 is typically labelled just "8" in the path.
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/usr/lib/jvm/java-8-openjdk-amd64/bin/java"
            ),
            Some("8".to_string())
        );
    }

    #[test]
    fn matches_fedora_long_version_path() {
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/usr/lib/jvm/java-17-openjdk-17.0.9.0.9-1.fc40.x86_64/bin/javac"
            ),
            Some("17".to_string())
        );
    }

    // --- Alpine ---

    #[test]
    fn matches_alpine_openjdk_layout() {
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/usr/lib/jvm/openjdk-17/bin/java"
            ),
            Some("17".to_string())
        );
    }

    // --- Manual / Docker / vendor layouts under /opt ---

    #[test]
    fn matches_opt_java_numbered_dir() {
        assert_eq!(
            detect("/rootfs", "/rootfs/opt/java/21/bin/java"),
            Some("21".to_string())
        );
        assert_eq!(
            detect("/rootfs", "/rootfs/opt/java/21/lib/libjli.so"),
            Some("21".to_string())
        );
    }

    #[test]
    fn matches_opt_java_openjdk_prefix() {
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/opt/java/openjdk-17/bin/java"
            ),
            Some("17".to_string())
        );
    }

    #[test]
    fn matches_opt_jdk_versioned() {
        assert_eq!(
            detect("/rootfs", "/rootfs/opt/jdk-17/bin/java"),
            Some("17".to_string())
        );
        assert_eq!(
            detect("/rootfs", "/rootfs/opt/jdk-17.0.9/bin/javac"),
            Some("17".to_string())
        );
    }

    #[test]
    fn matches_opt_corretto() {
        assert_eq!(
            detect("/rootfs", "/rootfs/opt/corretto-17/bin/java"),
            Some("17".to_string())
        );
    }

    #[test]
    fn matches_opt_temurin() {
        assert_eq!(
            detect("/rootfs", "/rootfs/opt/temurin/21/bin/java"),
            Some("21".to_string())
        );
    }

    // --- Over-fire guards ---

    #[test]
    fn does_not_match_non_jdk_path() {
        assert_eq!(detect("/rootfs", "/rootfs/usr/bin/java-like-tool"), None);
        assert_eq!(detect("/rootfs", "/rootfs/usr/lib/foo/libbar.so"), None);
        assert_eq!(detect("/rootfs", "/rootfs/bin/bash"), None);
    }

    #[test]
    fn does_not_match_jvm_dir_without_version_digits() {
        // `/usr/lib/jvm/java-cacerts/...` (just config, no runtime) —
        // prefix matches but there's no digit run; reject.
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/usr/lib/jvm/java-cacerts/config.file"
            ),
            None
        );
    }

    #[test]
    fn does_not_match_trailing_letter_after_digits() {
        // `jdk-17abc` — the digits are followed by a letter, not a
        // `.` / `-` / `/`. Reject to avoid absorbing unrelated names.
        assert_eq!(
            detect("/rootfs", "/rootfs/opt/jdk-17abc/bin/java"),
            None
        );
    }

    #[test]
    fn matches_build_with_dash_separator() {
        // Eclipse Temurin tarballs sometimes land as `opt/jdk-17-somebuild`.
        // The `-` after digits is a valid terminator.
        assert_eq!(
            detect("/rootfs", "/rootfs/opt/jdk-17-build1/bin/java"),
            Some("17".to_string())
        );
    }

    #[test]
    fn umbrella_roundtrip_produces_one_entry_per_major() {
        let mut c = JdkCollapser::default();
        // 3 paths in JDK 17, 2 in JDK 21 — expect 2 umbrellas.
        c.try_collapse(
            Path::new("/root/usr/lib/jvm/java-17-openjdk-amd64/bin/java"),
            Path::new("/root"),
        );
        c.try_collapse(
            Path::new("/root/usr/lib/jvm/java-17-openjdk-amd64/bin/javac"),
            Path::new("/root"),
        );
        c.try_collapse(
            Path::new("/root/usr/lib/jvm/java-17-openjdk-amd64/lib/libjvm.so"),
            Path::new("/root"),
        );
        c.try_collapse(Path::new("/root/opt/java/21/bin/java"), Path::new("/root"));
        c.try_collapse(
            Path::new("/root/opt/java/21/lib/libjli.so"),
            Path::new("/root"),
        );
        let entries = c.into_entries();
        assert_eq!(entries.len(), 2, "one umbrella per major version");
        let purls: Vec<_> = entries.iter().map(|e| e.purl.as_str()).collect();
        assert!(purls.contains(&"pkg:generic/openjdk@17"));
        assert!(purls.contains(&"pkg:generic/openjdk@21"));
    }

    // --- v8 Phase J: Eclipse Temurin unversioned layout ---

    /// J1 — `/opt/java/openjdk/` + `release` file with JAVA_VERSION.
    #[test]
    fn matches_temurin_unversioned_layout_with_release_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("opt/java/openjdk/bin")).unwrap();
        std::fs::write(
            dir.path().join("opt/java/openjdk/release"),
            "IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"17.0.18\"\n",
        )
        .unwrap();
        assert_eq!(
            detect_jdk_version(
                &dir.path().join("opt/java/openjdk/bin/java"),
                dir.path(),
            ),
            Some("17".to_string())
        );
        assert_eq!(
            detect_jdk_version(
                &dir.path().join("opt/java/openjdk/lib/libjli.so"),
                dir.path(),
            ),
            Some("17".to_string())
        );
    }

    /// J2 — unversioned layout without `release` file must NOT collapse.
    #[test]
    fn ignores_unversioned_layout_without_release_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("opt/java/openjdk/bin")).unwrap();
        // No `release` file.
        assert_eq!(
            detect_jdk_version(
                &dir.path().join("opt/java/openjdk/bin/java"),
                dir.path(),
            ),
            None
        );
    }

    /// J3 — release-file parser handles quirky quoting.
    #[test]
    fn release_file_with_quirky_quoting() {
        fn major_from(content: &str) -> Option<String> {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("opt/java/openjdk")).unwrap();
            std::fs::write(
                dir.path().join("opt/java/openjdk/release"),
                content,
            )
            .unwrap();
            read_jdk_major_from_release(&dir.path().join("opt/java/openjdk/release"))
        }
        assert_eq!(major_from("JAVA_VERSION=17\n"), Some("17".to_string()));
        assert_eq!(
            major_from("JAVA_VERSION=\"17.0.18\"\n"),
            Some("17".to_string())
        );
        assert_eq!(
            major_from("JAVA_VERSION='17.0.18'\n"),
            Some("17".to_string())
        );
        // Parser ignores unrelated lines.
        assert_eq!(
            major_from("IMPLEMENTOR=\"x\"\nJAVA_VERSION=\"21.0.1\"\nLIBC=\"glibc\"\n"),
            Some("21".to_string())
        );
    }

    /// J4 — regression guard: versioned `/opt/java/openjdk-17/` layout
    /// must still match (without needing a release file).
    #[test]
    fn unversioned_layout_does_not_affect_versioned_layout() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("opt/java/openjdk-17/bin")).unwrap();
        // No release file — irrelevant, the versioned path matches first.
        assert_eq!(
            detect_jdk_version(
                &dir.path().join("opt/java/openjdk-17/bin/java"),
                dir.path(),
            ),
            Some("17".to_string())
        );
    }
}
