//! Compute per-file content hashes for dpkg-installed packages.
//!
//! Two functions, two cost profiles:
//! - [`hash_package_files`] — the default. Walks every path dpkg's
//!   `<pkg>.list` manifest claims the package owns, opens each one,
//!   stream-hashes the contents with SHA-256, and stitches the per-file
//!   hashes into a deterministic Merkle root. Cost is proportional to
//!   installed package size (~3-5 s on `debian:bookworm-slim`).
//! - [`hash_md5sums_only`] — the `--no-deep-hash` fast path. Just
//!   SHA-256s the dpkg-provided `.md5sums` file as-is. Microseconds per
//!   package; preserves the per-package identity claim but doesn't
//!   detect on-disk tampering and emits no per-file occurrences.
//!
//! Both produce a [`ContentHash`] suitable for `ResolvedComponent.hashes`.
//! Only the deep variant fills `ResolvedComponent.occurrences`.

use std::collections::HashMap;
use std::path::Path;

use mikebom_common::resolution::FileOccurrence;
use mikebom_common::types::hash::ContentHash;
use sha2::{Digest, Sha256};

use crate::trace::hasher::{sha256_file_hex, sha256_hex};

/// Maximum bytes to hash per individual installed file. Mirrors the
/// scan-mode artefact-walker cap. Files larger than this are skipped
/// (rare for dpkg-installed packages — they're almost always smaller).
const MAX_PER_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Deep-hash every file `<rootfs>/var/lib/dpkg/info/<pkg>[:<arch>].list`
/// claims the package owns. Returns the per-file occurrences and a
/// component-level Merkle root over them.
///
/// Multi-arch dpkg installs suffix each package's info files with
/// `:<arch>` (e.g. `libc6:arm64.list`). The `arch` parameter lets the
/// caller supply the architecture from the parsed status stanza; we
/// try `<pkg>.list` first (Architecture: all packages) and fall back
/// to `<pkg>:<arch>.list` when the plain form is absent.
///
/// Files that disappear between install time and scan time (configs the
/// admin removed, tmpfile entries that were never created, etc.) are
/// silently skipped. Directories listed in `.list` are ignored —
/// they're not hashable content and dpkg lists them only for ownership.
pub fn hash_package_files(
    rootfs: &Path,
    pkg_name: &str,
    arch: Option<&str>,
) -> (Vec<FileOccurrence>, Option<ContentHash>) {
    let Some(list_text) = read_info_file(rootfs, pkg_name, arch, "list") else {
        return (Vec::new(), None);
    };

    let md5_lookup = read_md5sums(rootfs, pkg_name, arch);

    let mut occurrences: Vec<FileOccurrence> = Vec::new();
    for raw in list_text.lines() {
        let path_in_pkg = raw.trim();
        if path_in_pkg.is_empty() || path_in_pkg == "/." {
            continue;
        }
        // dpkg's .list paths are absolute (`/usr/bin/jq`); resolve
        // against the rootfs so the same code works for "scan / on a
        // live host" and "scan an extracted image rootfs."
        let abs = rootfs.join(path_in_pkg.trim_start_matches('/'));
        let Ok(meta) = abs.symlink_metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        if meta.len() > MAX_PER_FILE_BYTES {
            tracing::debug!(
                path = %abs.display(),
                size = meta.len(),
                "skipping oversized file in deep hash"
            );
            continue;
        }
        let sha256 = match sha256_file_hex(&abs, MAX_PER_FILE_BYTES) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(path = %abs.display(), error = %e, "could not hash file");
                continue;
            }
        };
        // dpkg's .md5sums uses paths relative to root with no leading
        // slash (`usr/bin/jq`); look up via the same form.
        let md5_key = path_in_pkg.trim_start_matches('/');
        let md5_legacy = md5_lookup.get(md5_key).cloned();
        // Store the dpkg-declared path (the canonical deployed-filesystem
        // path), not the absolute path on the scanner. That keeps the
        // Merkle root stable across scans of the same package regardless
        // of where the rootfs was extracted.
        occurrences.push(FileOccurrence {
            location: path_in_pkg.to_string(),
            sha256,
            md5_legacy,
        });
    }

    let root = compute_merkle_root(&occurrences);
    (occurrences, root)
}

/// `--no-deep-hash` fast path. Reads `<rootfs>/var/lib/dpkg/info/<pkg>[:<arch>].md5sums`
/// and SHA-256s the raw bytes as the package's "fingerprint." Empty
/// `Option<ContentHash>` when the file is absent (some packages don't
/// ship one — e.g. essential virtual packages).
pub fn hash_md5sums_only(
    rootfs: &Path,
    pkg_name: &str,
    arch: Option<&str>,
) -> Option<ContentHash> {
    let bytes = read_info_file_bytes(rootfs, pkg_name, arch, "md5sums")?;
    let hex = sha256_hex(&bytes);
    ContentHash::sha256(&hex).ok()
}

/// Read a `var/lib/dpkg/info/<pkg>[:<arch>].<ext>` file as UTF-8.
/// Tries the plain `<pkg>.<ext>` first, then falls back to
/// `<pkg>:<arch>.<ext>` when an `arch` is supplied.
fn read_info_file(
    rootfs: &Path,
    pkg_name: &str,
    arch: Option<&str>,
    ext: &str,
) -> Option<String> {
    let info = rootfs.join("var/lib/dpkg/info");
    let plain = info.join(format!("{pkg_name}.{ext}"));
    if let Ok(text) = std::fs::read_to_string(&plain) {
        return Some(text);
    }
    if let Some(a) = arch.filter(|a| !a.is_empty()) {
        let archy = info.join(format!("{pkg_name}:{a}.{ext}"));
        if let Ok(text) = std::fs::read_to_string(&archy) {
            return Some(text);
        }
    }
    None
}

/// Raw-bytes variant of [`read_info_file`] for files we hash directly
/// (`.md5sums` on the fast path).
fn read_info_file_bytes(
    rootfs: &Path,
    pkg_name: &str,
    arch: Option<&str>,
    ext: &str,
) -> Option<Vec<u8>> {
    let info = rootfs.join("var/lib/dpkg/info");
    let plain = info.join(format!("{pkg_name}.{ext}"));
    if let Ok(bytes) = std::fs::read(&plain) {
        return Some(bytes);
    }
    if let Some(a) = arch.filter(|a| !a.is_empty()) {
        let archy = info.join(format!("{pkg_name}:{a}.{ext}"));
        if let Ok(bytes) = std::fs::read(&archy) {
            return Some(bytes);
        }
    }
    None
}

/// Read `<pkg>[:<arch>].md5sums` into a `path -> md5` map. Lines are
/// `<32-hex-md5>  <relative-path>` (two spaces between the two fields,
/// per dpkg convention). Missing file → empty map.
fn read_md5sums(
    rootfs: &Path,
    pkg_name: &str,
    arch: Option<&str>,
) -> HashMap<String, String> {
    let Some(text) = read_info_file(rootfs, pkg_name, arch, "md5sums") else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for line in text.lines() {
        // Split on the first whitespace run; dpkg uses two spaces but
        // be permissive with any whitespace count.
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(md5) = parts.next() else { continue };
        let Some(rest) = parts.next() else { continue };
        let path = rest.trim_start();
        if md5.len() == 32 && md5.chars().all(|c| c.is_ascii_hexdigit()) && !path.is_empty() {
            out.insert(path.to_string(), md5.to_string());
        }
    }
    out
}

/// Component-level fingerprint: SHA-256 of a deterministic concatenation
/// of per-file `<sha256>  <location>\n` lines, sorted by location. Stable
/// across scans of the same install regardless of walk order.
fn compute_merkle_root(occurrences: &[FileOccurrence]) -> Option<ContentHash> {
    if occurrences.is_empty() {
        return None;
    }
    let mut sorted: Vec<&FileOccurrence> = occurrences.iter().collect();
    sorted.sort_by(|a, b| a.location.cmp(&b.location));
    let mut hasher = Sha256::new();
    for occ in sorted {
        hasher.update(occ.sha256.as_bytes());
        hasher.update(b"  ");
        hasher.update(occ.location.as_bytes());
        hasher.update(b"\n");
    }
    let bytes = hasher.finalize();
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    ContentHash::sha256(&hex).ok()
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use std::fs;

    /// Build a fake rootfs at `<tmp>/` with one dpkg-installed package
    /// `pkg_name` that owns `files` (path-relative-to-rootfs ↔ contents).
    /// Optionally writes a `.md5sums` referencing those files.
    fn make_rootfs(
        pkg_name: &str,
        files: &[(&str, &[u8])],
        write_md5sums: bool,
    ) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let info = dir.path().join("var/lib/dpkg/info");
        fs::create_dir_all(&info).unwrap();

        // .list with absolute paths.
        let list: String = files
            .iter()
            .map(|(p, _)| format!("/{}", p.trim_start_matches('/')))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(info.join(format!("{pkg_name}.list")), list).unwrap();

        if write_md5sums {
            let mut md5_text = String::new();
            for (p, content) in files {
                let mut md5 = md5_like_string(content);
                md5.truncate(32);
                let rel = p.trim_start_matches('/');
                md5_text.push_str(&format!("{md5}  {rel}\n"));
            }
            fs::write(info.join(format!("{pkg_name}.md5sums")), md5_text).unwrap();
        }

        for (p, content) in files {
            let abs = dir.path().join(p.trim_start_matches('/'));
            fs::create_dir_all(abs.parent().unwrap()).unwrap();
            fs::write(&abs, content).unwrap();
        }
        dir
    }

    /// Build a 32-hex-char string from arbitrary bytes for MD5-shaped
    /// fixture data — we don't need real MD5 in tests, just a value
    /// that satisfies the parser's hex-digit check.
    fn md5_like_string(bytes: &[u8]) -> String {
        let mut h = String::new();
        for b in bytes.iter().take(16) {
            h.push_str(&format!("{b:02x}"));
        }
        while h.len() < 32 {
            h.push('0');
        }
        h
    }

    #[test]
    fn deep_hash_produces_per_file_occurrences_and_merkle_root() {
        let dir = make_rootfs(
            "jq",
            &[("usr/bin/jq", b"binary-bytes"), ("usr/share/man/man1/jq.1.gz", b"manpage")],
            true,
        );
        let (occs, root) = hash_package_files(dir.path(), "jq", None);
        assert_eq!(occs.len(), 2);
        assert!(root.is_some(), "must produce a per-component root");
        // Each occurrence carries both hashes.
        for o in &occs {
            assert_eq!(o.sha256.len(), 64, "sha256 hex length");
            assert!(o.md5_legacy.is_some(), "md5sums entry should be present");
        }
    }

    #[test]
    fn merkle_root_stable_across_walk_order() {
        // Build the same fileset twice; the resulting Merkle should
        // be byte-identical regardless of insertion order.
        let dir1 = make_rootfs(
            "p",
            &[("usr/a", b"first"), ("usr/b", b"second"), ("usr/c", b"third")],
            false,
        );
        let dir2 = make_rootfs(
            "p",
            &[("usr/c", b"third"), ("usr/a", b"first"), ("usr/b", b"second")],
            false,
        );
        let (_, root1) = hash_package_files(dir1.path(), "p", None);
        let (_, root2) = hash_package_files(dir2.path(), "p", None);
        // Both should be Some and equal (same path/content sets, just
        // different .list line order — sort makes the root deterministic).
        assert_eq!(root1.is_some(), root2.is_some());
        assert_eq!(
            root1.as_ref().map(|h| h.value.as_str().to_string()),
            root2.as_ref().map(|h| h.value.as_str().to_string())
        );
    }

    #[test]
    fn deep_hash_skips_files_listed_but_missing_on_disk() {
        // .list claims usr/bin/jq + /etc/jqrc; on disk, only jq exists.
        let dir = tempfile::tempdir().unwrap();
        let info = dir.path().join("var/lib/dpkg/info");
        fs::create_dir_all(&info).unwrap();
        fs::write(
            info.join("jq.list"),
            "/usr/bin/jq\n/etc/jqrc\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("usr/bin")).unwrap();
        fs::write(dir.path().join("usr/bin/jq"), b"binary").unwrap();

        let (occs, _root) = hash_package_files(dir.path(), "jq", None);
        assert_eq!(occs.len(), 1, "missing file must be skipped");
        assert!(occs[0].location.ends_with("usr/bin/jq"));
    }

    #[test]
    fn deep_hash_returns_empty_when_list_absent() {
        let dir = tempfile::tempdir().unwrap();
        let (occs, root) = hash_package_files(dir.path(), "ghost", None);
        assert!(occs.is_empty());
        assert!(root.is_none());
    }

    #[test]
    fn fast_path_md5sums_only() {
        let dir = make_rootfs("jq", &[("usr/bin/jq", b"x")], true);
        let h = hash_md5sums_only(dir.path(), "jq", None).expect("hash");
        // Sanity: same input → same output across calls.
        let h2 = hash_md5sums_only(dir.path(), "jq", None).expect("hash again");
        assert_eq!(h.value.as_str(), h2.value.as_str());
    }

    #[test]
    fn fast_path_returns_none_when_md5sums_absent() {
        let dir = tempfile::tempdir().unwrap();
        let info = dir.path().join("var/lib/dpkg/info");
        fs::create_dir_all(&info).unwrap();
        // Only .list, no .md5sums.
        fs::write(info.join("p.list"), "/x\n").unwrap();
        assert!(hash_md5sums_only(dir.path(), "p", None).is_none());
    }

    #[test]
    fn occurrence_md5_legacy_is_none_when_not_in_md5sums() {
        // .list has a file; .md5sums omits it (config files that dpkg
        // intentionally doesn't checksum).
        let dir = tempfile::tempdir().unwrap();
        let info = dir.path().join("var/lib/dpkg/info");
        fs::create_dir_all(&info).unwrap();
        fs::write(info.join("p.list"), "/etc/p.conf\n").unwrap();
        fs::write(info.join("p.md5sums"), "").unwrap(); // empty
        fs::create_dir_all(dir.path().join("etc")).unwrap();
        fs::write(dir.path().join("etc/p.conf"), b"config").unwrap();

        let (occs, _) = hash_package_files(dir.path(), "p", None);
        assert_eq!(occs.len(), 1);
        assert!(occs[0].md5_legacy.is_none());
    }

    #[test]
    fn multi_arch_info_files_resolve_via_colon_arch_fallback() {
        // Multi-arch dpkg installs name their info files with a
        // `:<arch>` suffix (e.g. libc6:arm64.list). The function must
        // fall back from `<pkg>.list` to `<pkg>:<arch>.list`.
        let dir = tempfile::tempdir().unwrap();
        let info = dir.path().join("var/lib/dpkg/info");
        fs::create_dir_all(&info).unwrap();
        // Only write the arch-suffixed variant — the plain name is absent.
        fs::write(info.join("libc6:arm64.list"), "/usr/lib/libc.so.6\n").unwrap();
        fs::write(
            info.join("libc6:arm64.md5sums"),
            "d41d8cd98f00b204e9800998ecf8427e  usr/lib/libc.so.6\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("usr/lib")).unwrap();
        fs::write(dir.path().join("usr/lib/libc.so.6"), b"libc-body").unwrap();

        // Without arch hint → plain lookup fails, no occurrences.
        let (occs_plain, _) = hash_package_files(dir.path(), "libc6", None);
        assert!(occs_plain.is_empty(), "must not match arch-suffixed file without arch hint");

        // With arch hint → fallback finds it.
        let (occs, root) = hash_package_files(dir.path(), "libc6", Some("arm64"));
        assert_eq!(occs.len(), 1);
        assert!(occs[0].md5_legacy.is_some(), "md5sums cross-ref must resolve too");
        assert!(root.is_some());

        // Fast path also resolves the arch-suffixed md5sums.
        assert!(hash_md5sums_only(dir.path(), "libc6", Some("arm64")).is_some());
        assert!(
            hash_md5sums_only(dir.path(), "libc6", None).is_none(),
            "plain lookup on fast path must not match the arch-suffixed file"
        );
    }
}
