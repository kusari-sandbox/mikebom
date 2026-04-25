//! Collapse CPython stdlib binaries (`.cpython-<ver>-*.so` extensions,
//! `libpython*.so`, `python<ver>` executable) into one umbrella
//! `pkg:generic/cpython@<X.Y>` component per unique Python version.
//!
//! **Why**: container images that compile Python from source (e.g.
//! `python:3.11-slim-bookworm`) end up with the Python runtime
//! installed under `/usr/local/lib/python3.11/` and `/usr/local/bin/`,
//! NOT owned by any package manager. The binary walker would emit a
//! separate `pkg:generic/<filename>?file-sha256=…` for each of 78+
//! `.so` extension modules plus libpython plus the `python3.11`
//! executable — all describing the same runtime with different
//! filenames, producing noise that drowns out legitimately-unmanaged
//! binaries (e.g. a curl'd `jq`).
//!
//! **How**: detect files matching documented Python install layouts
//! via path patterns. Extract the `X.Y` version. Collapse all matching
//! files into ONE `pkg:generic/cpython@<X.Y>` component with every
//! source path recorded via `evidence.occurrences[]`.
//!
//! Files under `site-packages/` are NOT collapsed — those are typically
//! pip-installed and already covered by the pip RECORD claim-skip. If
//! they slip through the claim, they emit as individual components
//! (expected — they're not part of the stdlib).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mikebom_common::types::purl::Purl;

use crate::scan_fs::package_db::PackageDbEntry;

/// Accumulates observations of Python-stdlib binaries and emits one
/// umbrella component per unique Python version at the end of the scan.
#[derive(Default)]
pub struct PythonStdlibCollapser {
    /// Unique Python versions detected → set of file paths that
    /// matched a stdlib pattern for that version. `BTreeSet` keeps
    /// the occurrences list sorted (deterministic output).
    by_version: BTreeMap<String, BTreeSet<PathBuf>>,
}

impl PythonStdlibCollapser {
    /// Attempt to classify `path` as a CPython stdlib binary. Returns
    /// `true` if the path was claimed by the collapser — the caller
    /// should then skip emitting a file-level component for it.
    ///
    /// Patterns (tested against the path's components relative to
    /// `rootfs`):
    ///
    /// - `**/lib/python<X.Y>/lib-dynload/*.so*` — C extension modules
    /// - `**/lib/python<X.Y>/*.so*` — top-level .so (rare)
    /// - `**/lib/libpython<X.Y>[dm]?.so*` — libpython shared library
    /// - `**/bin/python<X.Y>` — versioned python executable
    ///
    /// `site-packages/` is explicitly excluded — those are pip-owned,
    /// covered by the RECORD claim-skip earlier in the pipeline.
    ///
    /// v4: falls back to canonicalizing the walker path if the raw
    /// form doesn't match. Handles `usr/local/bin/python3 → python3.11`
    /// and `usr/local/bin/python → python3.11` symlinks — both of
    /// which have unversioned basenames that `detect_python_version`
    /// rejects on their own.
    pub fn try_collapse(&mut self, path: &Path, rootfs: &Path) -> bool {
        // Fast path: raw walker path matches a pattern directly.
        if let Some(version) = detect_python_version(path, rootfs) {
            self.by_version
                .entry(version)
                .or_default()
                .insert(path.to_path_buf());
            return true;
        }
        // Fallback: canonicalize to resolve unversioned symlinks
        // (`python3 → python3.11`). Record the ORIGINAL walker path so
        // the umbrella's source_files property reflects the observable
        // filesystem layout.
        if let Ok(canonical) = std::fs::canonicalize(path) {
            if canonical != path {
                if let Some(version) = detect_python_version(&canonical, rootfs) {
                    self.by_version
                        .entry(version)
                        .or_default()
                        .insert(path.to_path_buf());
                    return true;
                }
            }
        }
        false
    }

    /// Emit one `pkg:generic/cpython@<X.Y>` umbrella per unique
    /// version. Every input path becomes an entry in the component's
    /// `evidence.occurrences[]` — piped through `source_path` using the
    /// `"|"` delimiter the scan_fs conversion layer already splits on.
    pub fn into_entries(self) -> Vec<PackageDbEntry> {
        self.by_version
            .into_iter()
            .filter_map(|(version, paths)| {
                // purl-spec § Character encoding: version segment is a
                // percent-encoded string. Route through the canonical
                // encoder (CPython versions are `X.Y` today and don't
                // carry `+`, but the rule applies uniformly).
                let purl_str = format!(
                    "pkg:generic/cpython@{}",
                    mikebom_common::types::purl::encode_purl_segment(&version),
                );
                let purl = Purl::new(&purl_str).ok()?;
                // Join paths with "| " — the scan_fs conversion uses
                // source_path as evidence.source_file_paths[0] and we
                // retain the full list as a single field for now.
                let source_path = paths
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("; ");
                Some(PackageDbEntry {
                    purl,
                    name: "cpython".to_string(),
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
                    shade_relocation: None,
                    buildinfo_status: None,
                    // New evidence-kind — see `generate/cyclonedx/builder.rs`
                    // enum update.
                    evidence_kind: Some("python-stdlib-collapsed".to_string()),
                    binary_class: None,
                    binary_stripped: None,
                    linkage_kind: None,
                    detected_go: None,
                    confidence: Some("heuristic".to_string()),
                    binary_packed: None,
                    raw_version: None,
                    parent_purl: None,
                    npm_role: None,
                    co_owned_by: None,
                    hashes: Vec::new(),
                })
            })
            .collect()
    }
}

/// Inspect `path` and return the Python major.minor version if the
/// path matches one of the CPython stdlib layouts. Returns `None` for
/// any non-matching path (including `site-packages/` entries, which
/// should be pip-claimed and not collapsed).
pub(crate) fn detect_python_version(path: &Path, rootfs: &Path) -> Option<String> {
    let rel = path.strip_prefix(rootfs).ok()?;
    let rel_str = rel.to_string_lossy();

    // site-packages entries are pip-territory — skip.
    if rel_str.contains("site-packages/") {
        return None;
    }

    // 1. `**/lib/python<X.Y>/lib-dynload/*.so*` and siblings.
    // 2. `**/lib/python<X.Y>/<any>.so*`.
    if let Some(ver) = extract_version_from_python_lib_path(&rel_str) {
        // Must be a .so* (extension module) OR at bin/python<X.Y>.
        // Any other file under lib/python<X.Y>/ (e.g. .py source)
        // isn't a binary the walker would pick up, so we don't
        // need to exclude them here.
        if rel_str.ends_with(".so")
            || rel_str.contains(".so.")
            || rel_str.contains(".so-")
        {
            return Some(ver);
        }
    }

    // 3. `**/lib/libpython<X.Y>[dm]?.so*`
    if let Some(ver) = extract_version_from_libpython_path(&rel_str) {
        return Some(ver);
    }

    // 4. `**/bin/python<X.Y>` executable
    if let Some(ver) = extract_version_from_python_binary_path(&rel_str) {
        return Some(ver);
    }

    // 5. (v4) Python-from-source build tree — `Python-<X.Y>.<patch>/`
    //    root binary `python` (the ./python that `make` produces before
    //    `make install`), or `Python-<X.Y>/Modules/*.o`, or any `.o` /
    //    `.a` file under the source tree (all build intermediates that
    //    share the same runtime identity).
    if let Some(ver) = extract_version_from_python_source_tree(&rel_str) {
        return Some(ver);
    }

    None
}

/// Match paths inside a `Python-<X.Y>[.<patch>]/` source tree.
/// Covers:
/// - `**/Python-<X.Y>.<patch>/python` — the built interpreter at the tree root
/// - `**/Python-<X.Y>.<patch>/Modules/python.o` — standard main-module build artifact
/// - `**/Python-<X.Y>.<patch>/**/*.o` and `/*.a` — any compilation intermediate
///
/// Returns `<X.Y>` extracted from the `Python-<X.Y>[.<patch>]` segment.
fn extract_version_from_python_source_tree(rel: &str) -> Option<String> {
    // Find `Python-<digits>.<digits>` — the CPython source-tarball
    // convention. `Python-3.11.4/`, `Python-3.12/`, etc.
    let idx = rel.find("Python-")?;
    let tail = &rel[idx + "Python-".len()..];
    let (ver, rest) = parse_major_minor(tail)?;
    // Accept optional `.<patch>` segment (Python-3.11.4 vs Python-3.11).
    let rest = if let Some(after_dot) = rest.strip_prefix('.') {
        // Skip over `.<digits>` if present.
        let digit_end = after_dot
            .bytes()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(after_dot.len());
        if digit_end > 0 {
            &after_dot[digit_end..]
        } else {
            rest
        }
    } else {
        rest
    };
    // Require a path separator immediately after the version segment —
    // i.e., `Python-3.11.4/` not `Python-3.11.4something`.
    if !rest.starts_with('/') {
        return None;
    }
    let after_dir = &rest[1..];
    // Match one of:
    //   1. `python` at the end (root-dir interpreter)
    //   2. `<anything>/python` at the end (e.g. `build/python`)
    //   3. `<anything>.o` or `<anything>.a` anywhere under the tree
    if after_dir == "python"
        || after_dir.ends_with("/python")
        || after_dir.ends_with(".o")
        || after_dir.ends_with(".a")
    {
        Some(ver)
    } else {
        None
    }
}

/// Match `.../lib/python<X.Y>/...`, returning `"X.Y"`.
fn extract_version_from_python_lib_path(rel: &str) -> Option<String> {
    // Find `lib/python` followed by digits.dot.digits
    let idx = rel.find("lib/python")?;
    let tail = &rel[idx + "lib/python".len()..];
    parse_major_minor(tail).map(|(v, _rest)| v)
}

/// Match `.../lib/libpython<X.Y>[dm]?.so*`, returning `"X.Y"`.
fn extract_version_from_libpython_path(rel: &str) -> Option<String> {
    let idx = rel.find("lib/libpython")?;
    let tail = &rel[idx + "lib/libpython".len()..];
    let (ver, rest) = parse_major_minor(tail)?;
    // Optional suffix letter (d=debug, m=pymalloc) then .so
    let rest = rest.trim_start_matches(|c: char| c.is_ascii_lowercase());
    if rest.starts_with(".so") {
        Some(ver)
    } else {
        None
    }
}

/// Match `.../bin/python<X.Y>` exactly, returning `"X.Y"`.
fn extract_version_from_python_binary_path(rel: &str) -> Option<String> {
    // Must end with `bin/python<X.Y>` (no trailing slash, no extra
    // chars after the version).
    let idx = rel.rfind("bin/python")?;
    let tail = &rel[idx + "bin/python".len()..];
    let (ver, rest) = parse_major_minor(tail)?;
    if rest.is_empty() {
        Some(ver)
    } else {
        None
    }
}

/// Parse a leading `<digits>.<digits>` version from `s`, returning
/// `("<major>.<minor>", remaining)`. `None` if `s` doesn't start with
/// a digit or doesn't contain a `.<digits>` after the majors.
fn parse_major_minor(s: &str) -> Option<(String, &str)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 || i >= bytes.len() || bytes[i] != b'.' {
        return None;
    }
    let dot = i;
    i += 1;
    let minor_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == minor_start {
        return None;
    }
    let version = format!("{}.{}", &s[..dot], &s[minor_start..i]);
    Some((version, &s[i..]))
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    fn detect(rootfs: &str, path: &str) -> Option<String> {
        detect_python_version(Path::new(path), Path::new(rootfs))
    }

    #[test]
    fn matches_lib_dynload_extension() {
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/usr/local/lib/python3.11/lib-dynload/_bisect.cpython-311-aarch64-linux-gnu.so"
            ),
            Some("3.11".to_string())
        );
    }

    #[test]
    fn matches_lib_dynload_versioned_so() {
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/usr/lib/python3.9/lib-dynload/_ssl.so"
            ),
            Some("3.9".to_string())
        );
    }

    #[test]
    fn matches_libpython_shared_library() {
        assert_eq!(
            detect("/rootfs", "/rootfs/usr/local/lib/libpython3.11.so.1.0"),
            Some("3.11".to_string())
        );
    }

    #[test]
    fn matches_libpython_with_d_suffix() {
        assert_eq!(
            detect("/rootfs", "/rootfs/usr/lib/libpython3.12d.so"),
            Some("3.12".to_string())
        );
    }

    #[test]
    fn matches_bin_python_versioned() {
        assert_eq!(
            detect("/rootfs", "/rootfs/usr/local/bin/python3.11"),
            Some("3.11".to_string())
        );
    }

    #[test]
    fn matches_usr_bin_python() {
        assert_eq!(
            detect("/rootfs", "/rootfs/usr/bin/python3.9"),
            Some("3.9".to_string())
        );
    }

    #[test]
    fn site_packages_not_collapsed() {
        // pip-installed extension MUST NOT be swept into the umbrella;
        // pip RECORD handles it.
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/usr/local/lib/python3.11/site-packages/_native.cpython-311.so"
            ),
            None
        );
    }

    #[test]
    fn bin_python_with_trailing_path_not_matched() {
        // python3.11-config is NOT the interpreter.
        assert_eq!(
            detect("/rootfs", "/rootfs/usr/bin/python3.11-config"),
            None
        );
    }

    #[test]
    fn non_python_so_not_matched() {
        assert_eq!(
            detect("/rootfs", "/rootfs/usr/lib/libfoo.so.1"),
            None
        );
    }

    #[test]
    fn py_source_file_not_matched() {
        // .py files shouldn't be swept. They're also not binary so
        // the walker wouldn't pick them up, but belt-and-suspenders.
        assert_eq!(
            detect(
                "/rootfs",
                "/rootfs/usr/local/lib/python3.11/os.py"
            ),
            None
        );
    }

    #[test]
    fn collapser_emits_one_entry_per_version() {
        let mut c = PythonStdlibCollapser::default();
        let root = Path::new("/rootfs");
        assert!(c.try_collapse(
            Path::new(
                "/rootfs/usr/local/lib/python3.11/lib-dynload/_bisect.cpython-311-aarch64-linux-gnu.so"
            ),
            root
        ));
        assert!(c.try_collapse(
            Path::new(
                "/rootfs/usr/local/lib/python3.11/lib-dynload/_ssl.cpython-311-aarch64-linux-gnu.so"
            ),
            root
        ));
        assert!(c.try_collapse(
            Path::new("/rootfs/usr/local/lib/libpython3.11.so.1.0"),
            root
        ));
        assert!(c.try_collapse(
            Path::new("/rootfs/usr/local/bin/python3.11"),
            root
        ));
        // Different version — separate umbrella.
        assert!(c.try_collapse(
            Path::new("/rootfs/usr/lib/python3.9/lib-dynload/_ssl.so"),
            root
        ));

        let entries = c.into_entries();
        assert_eq!(entries.len(), 2, "one umbrella per version");
        let purls: Vec<String> = entries
            .iter()
            .map(|e| e.purl.as_str().to_string())
            .collect();
        assert!(purls.contains(&"pkg:generic/cpython@3.11".to_string()));
        assert!(purls.contains(&"pkg:generic/cpython@3.9".to_string()));
        // Evidence-kind and tier are set correctly.
        for e in &entries {
            assert_eq!(e.evidence_kind.as_deref(), Some("python-stdlib-collapsed"));
            assert_eq!(e.sbom_tier.as_deref(), Some("analyzed"));
            assert_eq!(e.confidence.as_deref(), Some("heuristic"));
        }
    }

    #[test]
    fn collapser_does_not_claim_non_python_paths() {
        let mut c = PythonStdlibCollapser::default();
        let root = Path::new("/rootfs");
        assert!(!c.try_collapse(Path::new("/rootfs/opt/bin/jq"), root));
        assert!(!c.try_collapse(Path::new("/rootfs/usr/bin/curl"), root));
        assert!(c.into_entries().is_empty());
    }
}
