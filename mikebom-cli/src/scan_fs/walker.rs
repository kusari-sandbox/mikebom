//! Cross-platform directory walker used by both trace mode's post-exit
//! artifact scan and the standalone `sbom scan` subcommand.
//!
//! This module has no eBPF or OS-privileged dependencies — it is just
//! directory traversal + SHA-256 hashing. It runs unchanged on macOS,
//! Linux, and Windows.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use mikebom_common::types::hash::ContentHash;

use crate::trace::hasher::sha256_file_hex;

/// File-extension allowlist. A path only becomes a hashing candidate if
/// its lowercased basename ends with one of these. Keeps the walker from
/// stream-hashing random logs and build intermediates.
pub const ARTIFACT_SUFFIXES: &[&str] = &[
    ".deb", ".udeb", ".crate", ".whl", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz",
    ".jar", ".war", ".aar", ".gem", ".zip", ".egg",
];

/// Default upper bound on per-file hashing. 256 MB covers the largest
/// realistic package artifact (fat Rust crates, monolithic .jars, Debian
/// kernel packages) while keeping a bounded worst-case stall.
pub const DEFAULT_SIZE_CAP_BYTES: u64 = 256 * 1024 * 1024;

/// A single artifact the walker found: absolute path, size on disk,
/// SHA-256 content hash, and file modification time.
#[derive(Clone, Debug)]
pub struct HashedArtifact {
    pub path: PathBuf,
    pub size: u64,
    pub hash: ContentHash,
    pub mtime: SystemTime,
}

/// Walk `root` recursively for files matching [`ARTIFACT_SUFFIXES`] and
/// stream-hash each one. Symlinks are intentionally not followed to avoid
/// escaping the scan scope.
///
/// * `since` — if `Some(t)`, skip any file whose mtime precedes `t`.
///   Used by the post-trace artifact scan to ignore pre-existing files
///   on disk. `None` returns every matching file.
/// * `size_cap` — files larger than this are skipped with a debug log.
pub fn walk_and_hash(
    root: &Path,
    since: Option<SystemTime>,
    size_cap: u64,
) -> Vec<HashedArtifact> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    walk(root, &mut candidates);

    let mut out = Vec::with_capacity(candidates.len());
    for path in candidates {
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let lc = name.to_ascii_lowercase();
        if !ARTIFACT_SUFFIXES.iter().any(|s| lc.ends_with(s)) {
            continue;
        }
        let Ok(meta) = path.metadata() else { continue };
        let Ok(mtime) = meta.modified() else { continue };
        if let Some(t) = since {
            if mtime < t {
                continue;
            }
        }
        if meta.len() > size_cap {
            tracing::debug!(
                path = %path.display(),
                size = meta.len(),
                "walk_and_hash: skipping oversized artifact"
            );
            continue;
        }
        let hex = match sha256_file_hex(&path, size_cap) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "hash failed");
                continue;
            }
        };
        let hash = match ContentHash::sha256(&hex) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(error = %e, "invalid sha256 hex");
                continue;
            }
        };
        out.push(HashedArtifact {
            path,
            size: meta.len(),
            hash,
            mtime,
        });
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_file() {
            out.push(p);
        } else if ft.is_dir() {
            walk(&p, out);
        }
        // Symlinks are intentionally skipped.
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn picks_up_matching_suffixes_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("serde-1.0.0.crate"), b"crate-bytes").unwrap();
        std::fs::write(dir.path().join("jq_1.6_arm64.deb"), b"deb-bytes").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"ignored").unwrap();

        let out = walk_and_hash(dir.path(), None, 1024);
        assert_eq!(out.len(), 2, "expected 2 artifacts, got {out:?}");
        let names: Vec<String> = out
            .iter()
            .map(|a| a.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"serde-1.0.0.crate".to_string()));
        assert!(names.contains(&"jq_1.6_arm64.deb".to_string()));
    }

    #[test]
    fn hashes_match_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("x-1.0.0.crate");
        std::fs::write(&p, b"abc").unwrap();
        // Known SHA-256 of "abc"
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        let out = walk_and_hash(dir.path(), None, 1024);
        assert_eq!(out.len(), 1);
        // ContentHash renders as a hex-encoded digest in its Display;
        // we compare via its underlying string representation.
        let h = &out[0].hash;
        assert!(
            format!("{h:?}").contains(expected) || format!("{h}").contains(expected),
            "hash should match NIST sha256 vector for 'abc': {h:?}"
        );
    }

    #[test]
    fn since_filter_excludes_older_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("old-1.0.0.crate");
        std::fs::write(&p, b"bytes").unwrap();

        // Pick a time safely in the future
        let future =
            SystemTime::now() + std::time::Duration::from_secs(60 * 60 * 24 * 365);
        let out = walk_and_hash(dir.path(), Some(future), 1024);
        assert!(out.is_empty(), "future since should exclude all files");
    }

    #[test]
    fn size_cap_drops_oversized_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("big-1.0.0.crate"), vec![0u8; 4096]).unwrap();

        let out = walk_and_hash(dir.path(), None, 1024); // cap below file size
        assert!(out.is_empty(), "oversized file should be skipped");
    }

    #[test]
    fn recurses_into_subdirectories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("nested/deeper");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("a-1.0.0.crate"), b"bytes").unwrap();

        let out = walk_and_hash(dir.path(), None, 1024);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn empty_dir_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = walk_and_hash(dir.path(), None, 1024);
        assert!(out.is_empty());
    }

    #[test]
    fn nonexistent_root_returns_empty() {
        let p = Path::new("/definitely/does/not/exist/anywhere/xyz123");
        let out = walk_and_hash(p, None, 1024);
        assert!(out.is_empty());
    }
}
