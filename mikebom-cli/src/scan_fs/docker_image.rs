//! Extract a `docker save` tarball's layers onto disk so the filesystem
//! scanner can walk the resulting rootfs.
//!
//! Docker's `image save` format (also called the v1.2 tarball format) is a
//! plain tar archive containing:
//!
//! - `manifest.json` at the root: an array of
//!   `{Config, Layers: [...], RepoTags: [...]}` entries. We take the first
//!   entry.
//! - One file per layer at the paths named in `Layers[]` (typically
//!   `<sha256>/layer.tar` for older dockers, `blobs/sha256/<digest>` for
//!   newer OCI-formatted output). Each is itself a tar archive.
//! - Optional metadata files (config JSON, repositories) that we ignore.
//!
//! We stage the outer tarball into a temp directory, extract each layer
//! in order into a shared rootfs directory while applying OCI whiteouts
//! (`.wh.foo` removes `foo`; `.wh..wh..opq` empties the parent). The
//! returned [`ExtractedImage`] carries the rootfs path and some identity
//! metadata for the caller to attribute the SBOM to.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tempfile::TempDir;

/// Outcome of extracting a docker-save tarball.
#[derive(Debug)]
pub struct ExtractedImage {
    /// Owned tempdir that holds the extracted rootfs. Dropped when the
    /// caller is done scanning, which removes all extracted files.
    pub tempdir: TempDir,
    /// Root of the union filesystem (a subdirectory of `tempdir.path()`).
    pub rootfs: PathBuf,
    /// First `RepoTags` entry from the manifest, if any. Populated into
    /// the SBOM's subject `name` so downstream tooling can identify the
    /// image without having to re-read the tarball.
    pub repo_tag: Option<String>,
    /// SHA-256 of the outer `manifest.json` bytes. A stable identifier
    /// for the scanned tarball; useful for the SBOM's `serialNumber` or
    /// an accompanying attestation subject digest.
    pub manifest_digest: String,
    /// `VERSION_CODENAME` read from `<rootfs>/etc/os-release` after
    /// layer extraction, when available. Used as the default value for
    /// `--deb-codename` so deb PURLs pulled out of the rootfs carry
    /// the right `distro=` qualifier without the user having to pass
    /// it manually.
    pub distro_codename: Option<String>,
}

/// Parsed form of the top-level `manifest.json` in a docker save tarball.
/// Only the fields we consume are decoded; extras are ignored.
#[derive(Debug, Deserialize)]
struct DockerManifestEntry {
    #[serde(rename = "Config", default)]
    _config: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Vec<String>,
    #[serde(rename = "Layers", default)]
    layers: Vec<String>,
}

/// Extract a docker-save tarball at `archive_path` into a fresh tempdir
/// and return the resulting rootfs.
pub fn extract(archive_path: &Path) -> Result<ExtractedImage> {
    // We make two passes over the outer tarball: one to read the
    // manifest, one to extract each named layer. `tar::Archive` can't
    // rewind, so we reopen the file each time.
    let manifest_bytes = read_entry(archive_path, "manifest.json")
        .with_context(|| format!("reading manifest.json from {}", archive_path.display()))?;
    let manifest_digest = sha256_hex(&manifest_bytes);

    let entries: Vec<DockerManifestEntry> = serde_json::from_slice(&manifest_bytes)
        .context("parsing manifest.json")?;
    let Some(image) = entries.into_iter().next() else {
        bail!("manifest.json contains zero image entries");
    };

    let repo_tag = image.repo_tags.into_iter().next();
    if image.layers.is_empty() {
        bail!("image manifest has zero layers — not a valid docker save tarball?");
    }

    let tempdir = tempfile::Builder::new()
        .prefix("mikebom-image-")
        .tempdir()
        .context("creating tempdir for image extraction")?;
    let rootfs = tempdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).context("creating rootfs dir")?;

    for (idx, layer_name) in image.layers.iter().enumerate() {
        tracing::debug!(layer = idx, name = %layer_name, "extracting layer");
        let layer_bytes = read_entry(archive_path, layer_name).with_context(|| {
            format!("reading layer {layer_name} from {}", archive_path.display())
        })?;
        extract_layer_over_rootfs(&layer_bytes, &rootfs)
            .with_context(|| format!("extracting layer {layer_name}"))?;
    }

    // After the rootfs is fully assembled, read the distro tag (see
    // `os_release::read_distro_tag_from_rootfs`) so `mikebom sbom scan
    // --image` can stamp `distro=<ID>-<VERSION_ID>` (e.g. `debian-12`)
    // on deb PURLs without the user having to pass --deb-codename.
    // Rootfs-aware because /etc/os-release is commonly a symlink into
    // /usr/lib/os-release that can dangle after layer extraction.
    // Absent or unreadable is not an error — not every image carries
    // os-release (minimal FROM scratch, busybox).
    let distro_codename = super::os_release::read_distro_tag_from_rootfs(&rootfs);

    Ok(ExtractedImage {
        tempdir,
        rootfs,
        repo_tag,
        manifest_digest,
        distro_codename,
    })
}

/// Read a single named entry out of a tar archive into a `Vec<u8>`. The
/// outer tarball is opened from scratch, scanned for the entry, and
/// closed. `tar::Archive` doesn't let us hold a mutable borrow on the
/// reader across entries, so each call pays a fresh file-open cost.
fn read_entry(archive_path: &Path, entry_name: &str) -> Result<Vec<u8>> {
    let file = fs::File::open(archive_path)?;
    let mut archive = tar::Archive::new(file);
    for entry in archive.entries()? {
        let mut e = entry?;
        let path = e.path()?;
        if path.as_os_str() == entry_name {
            let mut buf = Vec::new();
            e.read_to_end(&mut buf)?;
            return Ok(buf);
        }
    }
    bail!("entry {entry_name} not found in tarball")
}

/// Extract an inner `layer.tar` byte stream on top of `rootfs`, applying
/// OCI whiteout semantics.
///
/// A regular file at `path/to/.wh.NAME` means "remove `path/to/NAME` from
/// the rootfs." The special name `.wh..wh..opq` under a directory means
/// "remove all existing contents of that directory." We implement the
/// common subset: remove-on-whiteout for both cases; the whiteout marker
/// files themselves are not extracted into the rootfs.
fn extract_layer_over_rootfs(layer_bytes: &[u8], rootfs: &Path) -> Result<()> {
    // Layers may be plain tar (legacy docker save) or gzipped tar (OCI
    // format emitted by modern docker save + most registries). Detect
    // by magic bytes so callers don't need to know which they have.
    let decompressed: Vec<u8> = if layer_bytes.len() >= 2
        && layer_bytes[0] == 0x1f
        && layer_bytes[1] == 0x8b
    {
        let mut out = Vec::with_capacity(layer_bytes.len() * 4);
        let mut decoder = flate2::read::GzDecoder::new(layer_bytes);
        decoder
            .read_to_end(&mut out)
            .context("gunzipping OCI layer")?;
        out
    } else {
        layer_bytes.to_vec()
    };
    let layer_bytes: &[u8] = &decompressed;

    // First pass: collect whiteout directives so we apply them up front.
    // Two-pass keeps the logic simple — one pass to find `.wh.*` names
    // and delete their targets, then another to unpack everything else.
    let mut archive = tar::Archive::new(std::io::Cursor::new(layer_bytes));
    let mut whiteouts: HashSet<PathBuf> = HashSet::new();
    let mut opaque_dirs: HashSet<PathBuf> = HashSet::new();
    for entry in archive.entries()? {
        let e = entry?;
        let path = e.path()?.into_owned();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name == ".wh..wh..opq" {
            if let Some(parent) = path.parent() {
                opaque_dirs.insert(parent.to_path_buf());
            }
        } else if let Some(target) = name.strip_prefix(".wh.") {
            if let Some(parent) = path.parent() {
                whiteouts.insert(parent.join(target));
            } else {
                whiteouts.insert(PathBuf::from(target));
            }
        }
    }

    for opq in &opaque_dirs {
        let full = rootfs.join(opq);
        if full.is_dir() {
            // Clear contents but keep the directory itself so subsequent
            // entries for this path can repopulate it.
            if let Ok(entries) = fs::read_dir(&full) {
                for entry in entries.flatten() {
                    let _ = if entry
                        .file_type()
                        .map(|t| t.is_dir())
                        .unwrap_or(false)
                    {
                        fs::remove_dir_all(entry.path())
                    } else {
                        fs::remove_file(entry.path())
                    };
                }
            }
        }
    }
    for wh in &whiteouts {
        let full = rootfs.join(wh);
        if full.is_dir() {
            let _ = fs::remove_dir_all(&full);
        } else if full.exists() {
            let _ = fs::remove_file(&full);
        }
    }

    // Second pass: unpack everything except whiteout marker files.
    //
    // v6 Phase F: tar entries iterate in storage order, which is NOT
    // topologically sorted against hardlinks. A hardlink entry can
    // appear before the file it's linking to (common on Fedora
    // images where /usr/bin/rpm / rpm2archive / rpm2cpio share
    // inodes). When that happens, `unpack_in` fails because the
    // link target doesn't exist yet, and the hardlink silently
    // vanishes from the extracted tree. We defer hardlinks to a
    // second pass so targets are guaranteed present.
    let mut archive = tar::Archive::new(std::io::Cursor::new(layer_bytes));
    let _ = &mut archive; // configuration setters below need the &mut.
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(true);
    archive.set_overwrite(true);

    // (link_path, target_path) pairs — applied after the main unpack.
    let mut deferred_links: Vec<(PathBuf, PathBuf)> = Vec::new();

    for entry in archive.entries()? {
        let mut e = entry?;
        let path = e.path()?.into_owned();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name == ".wh..wh..opq" || name.starts_with(".wh.") {
            continue;
        }
        // `tar` unpacks relative to a target directory. Reject entries
        // with `..` or absolute paths to avoid rootfs escapes; the tar
        // crate catches this in `unpack_in` but belt-and-suspenders.
        if path.is_absolute() || path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            tracing::debug!(path = %path.display(), "skipping unsafe tar entry");
            continue;
        }

        // Defer hardlink entries. Symlinks are fine to unpack in-order
        // because `fs::symlink` doesn't require the target to exist.
        if e.header().entry_type() == tar::EntryType::Link {
            if let Ok(Some(target)) = e.link_name() {
                let target = target.into_owned();
                if target.is_absolute()
                    || target
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    tracing::debug!(
                        link = %path.display(),
                        target = %target.display(),
                        "skipping hardlink with unsafe target",
                    );
                    continue;
                }
                deferred_links.push((path, target));
                continue;
            }
            tracing::debug!(path = %path.display(), "hardlink entry has no link_name; skipping");
            continue;
        }

        // v7 Phase I: the tar crate doesn't reliably create parent
        // directories when the parent's own directory entry hasn't been
        // processed yet (Fedora image layers reference deep paths like
        // `usr/lib/sysimage/rpm/rpmdb.sqlite` whose parent-directory
        // entries come later in the stream). Pre-create parents so
        // `unpack_in` never fails on missing-directory. For directory
        // entries themselves, `unpack_in` creates the leaf directory;
        // we pre-create the parent chain as belt-and-suspenders.
        let abs = rootfs.join(&path);
        if let Some(parent) = abs.parent() {
            let _ = fs::create_dir_all(parent);
        }

        // v9 Phase N: tar 0.4.45's Entry::unpack applies tar-header
        // permissions to extracted directories even with
        // `set_preserve_permissions(false)` (only SUID/SGID/sticky are
        // stripped; the rwx bits come from the header). Fedora images
        // ship directories like
        // `/etc/pki/ca-trust/extracted/pem/directory-hash/` with mode
        // 0555 (no write), which blocks every subsequent tar entry
        // that wants to land inside them with EACCES. Cumulative
        // effect on polyglot-builder: 20k+ extraction failures,
        // including the Layer 1 updated rpmdb.sqlite that would
        // otherwise carry 500+ rpm components.
        //
        // The fix: force the entry's parent directory to owner-rwx
        // (+0o700) before each unpack_in. The extracted rootfs is
        // a throw-away tempdir — original permission semantics don't
        // matter for SBOM reading. `symlink_metadata` so we don't
        // follow a legitimate symlink.
        #[cfg(unix)]
        if let Some(parent) = abs.parent() {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::symlink_metadata(parent) {
                let mode = meta.permissions().mode();
                if mode & 0o700 != 0o700 {
                    let mut p = meta.permissions();
                    p.set_mode(mode | 0o700);
                    let _ = fs::set_permissions(parent, p);
                }
            }
        }

        if let Err(err) = e.unpack_in(rootfs) {
            tracing::debug!(path = %path.display(), error = %err, "failed to unpack entry");
        }
    }

    // Second mini-pass: create hardlinks now that their targets are in
    // place. If `fs::hard_link` fails (e.g. cross-device, target missing
    // even here), fall back to a full copy so we don't silently lose a
    // binary the SBOM should see.
    for (link_rel, target_rel) in &deferred_links {
        let link_abs = rootfs.join(link_rel);
        let target_abs = rootfs.join(target_rel);
        if let Some(parent) = link_abs.parent() {
            let _ = fs::create_dir_all(parent);
            // v9 Phase N: same chmod fix as the main pass — ensure
            // the parent is owner-writable before linking, or the
            // hard_link / copy fallback will fail with EACCES under
            // Fedora's read-only-by-design directories.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::symlink_metadata(parent) {
                    let mode = meta.permissions().mode();
                    if mode & 0o700 != 0o700 {
                        let mut p = meta.permissions();
                        p.set_mode(mode | 0o700);
                        let _ = fs::set_permissions(parent, p);
                    }
                }
            }
        }
        // If the link already exists from a prior layer, remove it so
        // the new hardlink can be created (fs::hard_link fails when
        // the destination exists).
        if link_abs.exists() {
            let _ = fs::remove_file(&link_abs);
        }
        match fs::hard_link(&target_abs, &link_abs) {
            Ok(()) => {}
            Err(hard_err) => match fs::copy(&target_abs, &link_abs) {
                Ok(_) => {
                    tracing::debug!(
                        link = %link_rel.display(),
                        target = %target_rel.display(),
                        "hardlink failed; copied target instead",
                    );
                }
                Err(copy_err) => {
                    tracing::debug!(
                        link = %link_rel.display(),
                        target = %target_rel.display(),
                        hard_err = %hard_err,
                        copy_err = %copy_err,
                        "hardlink + copy both failed; entry dropped",
                    );
                }
            },
        }
    }

    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// `Seek` is unused in the public surface but kept in the import list so
// future streaming extractors (layer decompression) don't regress.
#[allow(dead_code)]
fn _keep_seek_in_scope<T: Seek>(_: T) {
    let _ = SeekFrom::Start(0);
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Build a minimal but spec-compliant docker-save tarball in memory:
    /// outer tar holding `manifest.json` + one layer tar (which itself
    /// contains a single file at `usr/local/bin/rg`).
    fn build_fake_image(layer_name: &str, files: &[(&str, &[u8])]) -> PathBuf {
        // Build inner layer tar.
        let mut layer_bytes = Vec::new();
        {
            let mut layer_tar = tar::Builder::new(&mut layer_bytes);
            for (path, content) in files {
                let mut header = tar::Header::new_ustar();
                header.set_path(path).unwrap();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                layer_tar.append(&header, *content).unwrap();
            }
            layer_tar.finish().unwrap();
        }

        // Manifest referring to that layer by name.
        let manifest = format!(
            r#"[{{"Config":"config.json","RepoTags":["demo:latest"],"Layers":["{layer_name}"]}}]"#
        );

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let file = tmp.reopen().unwrap();
        let mut outer = tar::Builder::new(file);

        let mut manifest_header = tar::Header::new_ustar();
        manifest_header.set_path("manifest.json").unwrap();
        manifest_header.set_size(manifest.len() as u64);
        manifest_header.set_mode(0o644);
        manifest_header.set_cksum();
        outer.append(&manifest_header, manifest.as_bytes()).unwrap();

        let mut layer_header = tar::Header::new_ustar();
        layer_header.set_path(layer_name).unwrap();
        layer_header.set_size(layer_bytes.len() as u64);
        layer_header.set_mode(0o644);
        layer_header.set_cksum();
        outer.append(&layer_header, layer_bytes.as_slice()).unwrap();

        outer.into_inner().unwrap().flush().unwrap();
        // Forget the tmp so it isn't dropped+removed before the test reads it.
        let _ = tmp.persist(&path);
        path
    }

    #[test]
    fn extract_minimal_image_populates_rootfs() {
        let tarball = build_fake_image(
            "layer0/layer.tar",
            &[("usr/local/bin/rg", b"rg-binary-bytes")],
        );

        let img = extract(&tarball).expect("extract");
        assert_eq!(img.repo_tag.as_deref(), Some("demo:latest"));
        assert_eq!(img.manifest_digest.len(), 64);
        let rg = img.rootfs.join("usr/local/bin/rg");
        assert!(rg.is_file(), "rootfs should contain unpacked file: {rg:?}");
        let content = fs::read(&rg).unwrap();
        assert_eq!(content, b"rg-binary-bytes");
    }

    #[test]
    fn whiteout_removes_earlier_layer_file() {
        // Layer 0 adds a file; layer 1 whites it out.
        let outer = {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            let path = tmp.path().to_path_buf();
            let file = tmp.reopen().unwrap();
            let mut outer_tar = tar::Builder::new(file);

            // Inner layer 0
            let mut l0 = Vec::new();
            {
                let mut t = tar::Builder::new(&mut l0);
                let mut h = tar::Header::new_ustar();
                h.set_path("etc/config").unwrap();
                h.set_size(4);
                h.set_mode(0o644);
                h.set_cksum();
                t.append(&h, b"old\n".as_slice()).unwrap();
                t.finish().unwrap();
            }
            // Inner layer 1: whiteout
            let mut l1 = Vec::new();
            {
                let mut t = tar::Builder::new(&mut l1);
                let mut h = tar::Header::new_ustar();
                h.set_path("etc/.wh.config").unwrap();
                h.set_size(0);
                h.set_mode(0o644);
                h.set_cksum();
                t.append(&h, &[][..]).unwrap();
                t.finish().unwrap();
            }

            let manifest = r#"[{"Config":"config.json","RepoTags":["wh:latest"],"Layers":["l0/layer.tar","l1/layer.tar"]}]"#;

            let mut h = tar::Header::new_ustar();
            h.set_path("manifest.json").unwrap();
            h.set_size(manifest.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            outer_tar.append(&h, manifest.as_bytes()).unwrap();
            let mut h = tar::Header::new_ustar();
            h.set_path("l0/layer.tar").unwrap();
            h.set_size(l0.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            outer_tar.append(&h, l0.as_slice()).unwrap();
            let mut h = tar::Header::new_ustar();
            h.set_path("l1/layer.tar").unwrap();
            h.set_size(l1.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            outer_tar.append(&h, l1.as_slice()).unwrap();
            outer_tar.into_inner().unwrap().flush().unwrap();
            tmp.persist(&path).unwrap();
            path
        };

        let img = extract(&outer).expect("extract");
        let etc_config = img.rootfs.join("etc/config");
        assert!(!etc_config.exists(), "whiteout should have removed etc/config");
    }

    #[test]
    fn missing_manifest_errors() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let file = tmp.reopen().unwrap();
        let outer = tar::Builder::new(file);
        // Empty archive — no manifest.json
        outer.into_inner().unwrap().flush().unwrap();

        let err = extract(tmp.path()).expect_err("expected failure");
        let msg = format!("{err:#}");
        assert!(msg.contains("manifest.json"), "error should mention manifest: {msg}");
    }

    // --- v6 Phase F: hardlink two-pass extraction ---

    /// Build a tar layer (uncompressed) containing two entries whose
    /// ORDER PUTS THE HARDLINK BEFORE ITS TARGET. Returns the tar bytes
    /// ready to hand to `extract_layer_over_rootfs`.
    fn build_tar_with_out_of_order_hardlink() -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let mut ar = tar::Builder::new(&mut buf);

        // Entry 1: a hardlink at usr/bin/rpm2archive pointing to usr/bin/rpm.
        // Target doesn't exist yet — this is the scenario that breaks
        // single-pass extraction.
        let mut hdr = tar::Header::new_gnu();
        hdr.set_path("usr/bin/rpm2archive").unwrap();
        hdr.set_size(0);
        hdr.set_entry_type(tar::EntryType::Link);
        hdr.set_link_name("usr/bin/rpm").unwrap();
        hdr.set_mode(0o755);
        hdr.set_cksum();
        ar.append(&hdr, std::io::empty()).unwrap();

        // Entry 2: the target file with actual contents.
        let contents = b"fake rpm binary contents\n";
        let mut hdr2 = tar::Header::new_gnu();
        hdr2.set_path("usr/bin/rpm").unwrap();
        hdr2.set_size(contents.len() as u64);
        hdr2.set_entry_type(tar::EntryType::Regular);
        hdr2.set_mode(0o755);
        hdr2.set_cksum();
        ar.append(&hdr2, contents.as_slice()).unwrap();

        ar.into_inner().unwrap();
        buf
    }

    #[test]
    fn hardlink_out_of_order_extracts_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let tar = build_tar_with_out_of_order_hardlink();
        extract_layer_over_rootfs(&tar, dir.path()).unwrap();

        let target = dir.path().join("usr/bin/rpm");
        let link = dir.path().join("usr/bin/rpm2archive");
        assert!(target.is_file(), "target binary must extract");
        assert!(
            link.is_file(),
            "hardlink must resolve post-extract (out-of-order v6 fix)"
        );
        let target_bytes = std::fs::read(&target).unwrap();
        let link_bytes = std::fs::read(&link).unwrap();
        assert_eq!(
            target_bytes, link_bytes,
            "hardlink contents must match target"
        );
    }

    #[test]
    fn hardlink_missing_target_does_not_crash() {
        // Tar with a hardlink whose target is never written. The
        // deferred-link pass should log debug and move on without
        // panicking.
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut buf);
            let mut hdr = tar::Header::new_gnu();
            hdr.set_path("usr/bin/orphan").unwrap();
            hdr.set_size(0);
            hdr.set_entry_type(tar::EntryType::Link);
            hdr.set_link_name("usr/bin/never-existed").unwrap();
            hdr.set_mode(0o755);
            hdr.set_cksum();
            ar.append(&hdr, std::io::empty()).unwrap();
            ar.into_inner().unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        // Should not panic or error — the hardlink is silently dropped.
        extract_layer_over_rootfs(&buf, dir.path()).unwrap();
        assert!(
            !dir.path().join("usr/bin/orphan").exists(),
            "orphan hardlink should not exist when target is missing"
        );
    }

    /// v7 Phase I — a tar containing a file entry whose parent
    /// directories were never declared as separate tar entries must
    /// still extract (the tar crate's default `unpack_in` fails in
    /// this case; we pre-create parents to fix it). Simulates the
    /// Fedora image layer pattern that dropped rpmdb.sqlite and rpm
    /// binaries.
    #[test]
    fn unpack_layer_creates_missing_parent_dirs() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut buf);
            // Deep path with no intermediate directory entries. Matches
            // the Fedora `usr/lib/sysimage/rpm/rpmdb.sqlite` layout.
            let contents = b"synthetic payload\n";
            let mut hdr = tar::Header::new_gnu();
            hdr.set_path("usr/lib/sysimage/rpm/rpmdb.sqlite").unwrap();
            hdr.set_size(contents.len() as u64);
            hdr.set_entry_type(tar::EntryType::Regular);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            ar.append(&hdr, contents.as_slice()).unwrap();
            ar.into_inner().unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        extract_layer_over_rootfs(&buf, dir.path()).unwrap();
        let target = dir.path().join("usr/lib/sysimage/rpm/rpmdb.sqlite");
        assert!(
            target.is_file(),
            "deep-path file must extract even without intermediate dir entries"
        );
        let observed = std::fs::read(&target).unwrap();
        assert_eq!(observed, b"synthetic payload\n");
    }

    // --- v9 Phase N: read-only directories mustn't block extraction ---

    /// N1 — a tar layer containing (a) a directory with mode 0555
    /// followed by (b) a regular-file entry inside that directory
    /// must produce BOTH the dir and the file on disk. Without the
    /// chmod fix, (b) fails with EACCES because (a) left the parent
    /// non-writable.
    #[cfg(unix)]
    #[test]
    fn unpack_layer_survives_readonly_dir() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut buf);
            let mut dhdr = tar::Header::new_gnu();
            dhdr.set_path("readonly/").unwrap();
            dhdr.set_size(0);
            dhdr.set_entry_type(tar::EntryType::Directory);
            dhdr.set_mode(0o555);
            dhdr.set_cksum();
            ar.append(&dhdr, std::io::empty()).unwrap();

            let contents = b"hello\n";
            let mut fhdr = tar::Header::new_gnu();
            fhdr.set_path("readonly/file.txt").unwrap();
            fhdr.set_size(contents.len() as u64);
            fhdr.set_entry_type(tar::EntryType::Regular);
            fhdr.set_mode(0o644);
            fhdr.set_cksum();
            ar.append(&fhdr, contents.as_slice()).unwrap();
            ar.into_inner().unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        extract_layer_over_rootfs(&buf, dir.path()).unwrap();

        assert!(dir.path().join("readonly").is_dir());
        let f = dir.path().join("readonly/file.txt");
        assert!(f.is_file(), "file inside read-only dir must extract");
        assert_eq!(std::fs::read(&f).unwrap(), b"hello\n");
    }

    /// N2 — realistic Fedora-style layout: mode-0555 directory with
    /// multiple symlink entries inside. Mirrors
    /// `/etc/pki/ca-trust/extracted/pem/directory-hash/` behaviour
    /// where the polyglot extraction failed thousands of times.
    #[cfg(unix)]
    #[test]
    fn unpack_layer_survives_readonly_symlink_chain() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut buf);

            // Read-only parent dir
            let mut dhdr = tar::Header::new_gnu();
            dhdr.set_path("trust/hashes/").unwrap();
            dhdr.set_size(0);
            dhdr.set_entry_type(tar::EntryType::Directory);
            dhdr.set_mode(0o555);
            dhdr.set_cksum();
            ar.append(&dhdr, std::io::empty()).unwrap();

            // 5 symlink entries inside
            for i in 0..5 {
                let mut shdr = tar::Header::new_gnu();
                shdr.set_path(format!("trust/hashes/hash_{i}.0")).unwrap();
                shdr.set_size(0);
                shdr.set_entry_type(tar::EntryType::Symlink);
                shdr.set_link_name(format!("cert_{i}.pem")).unwrap();
                shdr.set_mode(0o777);
                shdr.set_cksum();
                ar.append(&shdr, std::io::empty()).unwrap();
            }
            ar.into_inner().unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        extract_layer_over_rootfs(&buf, dir.path()).unwrap();

        for i in 0..5 {
            let p = dir.path().join(format!("trust/hashes/hash_{i}.0"));
            assert!(
                p.symlink_metadata().is_ok(),
                "symlink {} must extract even under a 0555 parent dir",
                p.display()
            );
        }
    }
}
