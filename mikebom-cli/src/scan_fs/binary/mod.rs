//! Generic (non-Go) binary SBOM reader — ELF in v1; Mach-O / PE
//! follow in later milestone-004 turns. Milestone 004 US2.
//!
//! Per-binary outputs (one file scanned → multiple `PackageDbEntry`
//! rows):
//! - One **file-level** binary component (`type=file`, carries
//!   `binary-class`, `binary-stripped`, `linkage-kind`).
//! - One **linkage-evidence** component per unique soname (deduped
//!   globally by PURL across the scan — see `linkage.rs`).
//! - One **ELF-note-package** component per binary that carries a
//!   `.note.package` section (source-tier, authoritative).
//!
//! Not yet emitted in this turn: embedded-version-string components
//! (T030), UPX packer detection (T031), Mach-O (T028/T034), PE
//! (T029/T035/T036). The `linkage::dedup_globally` pass runs at the
//! end of `read()` so cross-binary dedup happens before results leave
//! this module.

pub mod elf;
pub mod jdk_collapse;
pub mod linkage;
pub mod macho; // stub
pub mod packer; // stub
pub mod pe; // stub
pub mod python_collapse;
pub mod version_strings; // stub

use std::path::{Path, PathBuf};

use mikebom_common::types::hash::ContentHash;
use mikebom_common::types::purl::Purl;
use object::ObjectSection;
use sha2::{Digest, Sha256};

use super::package_db::{rpm_vendor_from_id, PackageDbEntry};

/// Detected OS family of the scan root. Drives the OS-aware binary-
/// format filter — we skip Mach-O / PE when scanning a Linux rootfs
/// because binaries of other formats inside a Linux container are
/// always contamination (test fixtures, build artefacts from a
/// developer's host that got packaged in). Their linkage entries
/// reference host paths like `/System/Library/Frameworks/...` that
/// don't exist in the container and shouldn't appear in its SBOM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootfsKind {
    Linux,
    Macos,
    Windows,
    /// No OS-specific signal found — treat as "any binary format allowed"
    /// (caller likely scanning a mixed directory, not a container rootfs).
    Unknown,
}

fn detect_rootfs_kind(rootfs: &Path) -> RootfsKind {
    // Linux rootfs signals: `/etc/os-release` with a recognised
    // Linux-family ID, `/lib/apk/db/installed`, `/var/lib/dpkg/status`,
    // or an rpmdb at any of the candidate locations (var/lib/rpm or
    // usr/lib/sysimage/rpm — Fedora ≥34 / RHEL ≥9.4).
    //
    // v9 Phase M: the rpmdb check was previously hardcoded to
    // `var/lib/rpm/`, which missed Fedora 40 (sysimage location). That
    // caused `rpm_dir_heuristic` to never fire on Fedora images
    // because `rootfs_kind` came back as `Unknown`. Now uses the same
    // candidate lists `rpm.rs` uses so the two can't drift apart.
    if rootfs.join("lib/apk/db/installed").exists()
        || rootfs.join("var/lib/dpkg/status").exists()
    {
        return RootfsKind::Linux;
    }
    {
        use crate::scan_fs::package_db::rpm;
        if rpm::RPMDB_SQLITE_CANDIDATES
            .iter()
            .any(|c| rootfs.join(c).is_file())
            || rpm::RPMDB_BDB_CANDIDATES
                .iter()
                .any(|c| rootfs.join(c).is_file())
        {
            return RootfsKind::Linux;
        }
    }
    // Generic os-release probe. Linux is by far the dominant ID.
    // Uses the rootfs-aware reader so Ubuntu/Fedora images whose
    // /etc/os-release is a symlink into /usr/lib/os-release still
    // resolve (see os_release::read_id_from_rootfs).
    if let Some(id) = crate::scan_fs::os_release::read_id_from_rootfs(rootfs) {
        let id_lower = id.to_lowercase();
        // Every RPM/DEB/APK-family distro + common musl / busybox ids.
        const LINUX_IDS: &[&str] = &[
            "alpine", "amzn", "arch", "centos", "debian", "fedora", "gentoo",
            "linux", "mageia", "nixos", "openmandriva", "opensuse",
            "opensuse-leap", "opensuse-tumbleweed", "ol", "ubuntu", "rhel",
            "rocky", "almalinux", "sles", "wolfi", "chainguard",
        ];
        if LINUX_IDS.iter().any(|&s| id_lower == s || id_lower.starts_with(s)) {
            return RootfsKind::Linux;
        }
    }
    RootfsKind::Unknown
}

/// Drop linkage-evidence entries whose install-names look like host-
/// OS absolute system paths. Mach-O binaries normally carry absolute
/// install-names (`/usr/lib/libSystem.B.dylib`) — inside a Linux
/// container these are host leakage; outside one they're real. We
/// err on the side of dropping obvious noise.
fn is_host_system_path(soname: &str) -> bool {
    soname.starts_with("/System/Library/")
        || soname.starts_with("/usr/lib/system/")
        || soname.starts_with("/System/iOSSupport/")
}

/// RPM directory heuristic per the milestone-004 post-ship plan. RPM
/// file-list extraction from HeaderBlob BASENAMES/DIRNAMES/DIRINDEXES
/// is deferred to a follow-on milestone; meanwhile, when we know a
/// rootfs has an rpmdb (so rpm OWNS the package-install story), any
/// binary under a well-known OS-managed directory is presumed owned
/// even if we can't enumerate its specific claim.
///
/// Well-known OS-managed directories chosen to match filesystem-
/// hierarchy standards — `/bin`, `/sbin`, `/usr/{bin,sbin,lib,lib64,libexec}`,
/// `/lib`, `/lib64`. Binaries in `/opt`, `/usr/local`, `/home`, etc.
/// are NOT presumed owned — those are typical locations for manually-
/// installed tools we DO want to flag.
/// v8 Phase K1 — does this rootfs carry an rpmdb (sqlite or legacy BDB)
/// at ANY of the locations rpm.rs supports? Replaces a historical
/// hard-coded `/var/lib/rpm/rpmdb.sqlite` check that missed Fedora ≥34
/// / RHEL ≥9.4 (which moved to `/usr/lib/sysimage/rpm/`).
///
/// Shares the candidate lists with `rpm.rs` so the two places can't
/// drift out of sync again.
fn has_rpmdb_at(rootfs: &std::path::Path) -> bool {
    use crate::scan_fs::package_db::rpm;
    rpm::RPMDB_SQLITE_CANDIDATES
        .iter()
        .any(|c| rootfs.join(c).is_file())
        || rpm::RPMDB_BDB_CANDIDATES
            .iter()
            .any(|c| rootfs.join(c).is_file())
}

fn is_os_managed_directory(rootfs: &std::path::Path, path: &std::path::Path) -> bool {
    let Ok(rel) = path.strip_prefix(rootfs) else {
        return false;
    };
    let rel_str = rel.to_string_lossy();
    const MANAGED_PREFIXES: &[&str] = &[
        "bin/",
        "sbin/",
        "lib/",
        "lib64/",
        "usr/bin/",
        "usr/sbin/",
        "usr/lib/",
        "usr/lib64/",
        "usr/libexec/",
        "usr/share/",
    ];
    MANAGED_PREFIXES.iter().any(|p| rel_str.starts_with(p))
}

/// Quick probe: does this ELF carry Go BuildInfo? Used by the Linux-
/// rootfs Go-suppression rule — when Go BuildInfo succeeds, the Go
/// modules emitted by `package_db::go_binary` carry the container
/// content; the file-level binary component is redundant noise.
///
/// Lightweight byte-scan for the BuildInfo magic prefix `\xff Go buildinf:`
/// — avoids re-parsing the binary. Same magic the `go_binary` reader
/// looks for (source: Go stdlib `debug/buildinfo`).
fn is_go_binary(bytes: &[u8]) -> bool {
    // Scan the first 2 MB — BuildInfo typically lives in a dedicated
    // `.go.buildinfo` section near the start of the file. Scanning
    // further would be worst-case ~100ms per binary; bounded probe
    // matches the existing `go_binary.rs` approach.
    const PROBE: usize = 2 * 1024 * 1024;
    let end = bytes.len().min(PROBE);
    bytes[..end]
        .windows(14)
        .any(|w| w == b"\xff Go buildinf:")
}

/// Check whether the walker's discovered path is covered by a claim
/// recorded by any installed-package-db reader.
///
/// Three independent matching layers, checked in order of cheapness:
/// 1. **Raw path match** — works on plain (non-usrmerge) rootfs
/// 2. **Canonical path match** — handles directory-level symlinks
///    (`/bin → usr/bin` in Debian usrmerge)
/// 3. **(device, inode) match** — handles hard links, final-component
///    symlinks, and canonicalize output-form differences
///
/// Layer 3 is the robust invariant: if walker path and any claim
/// point to the same physical file, their `(dev, ino)` match
/// regardless of how the path was constructed.
///
/// All three layers degrade to "not claimed" on `stat`/canonicalize
/// failure. Safe default: worst case a redundant `pkg:generic/`
/// component emits, matching pre-fix behaviour.
pub(crate) fn is_path_claimed(
    walker_path: &std::path::Path,
    claimed: &std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &std::collections::HashSet<(u64, u64)>,
) -> bool {
    // Layer 1: raw form — matches plain directory layouts.
    if claimed.contains(walker_path) {
        return true;
    }
    // Layer 2: canonical form — resolves symlinks on usrmerged rootfs.
    if let Ok(canonical) = std::fs::canonicalize(walker_path) {
        if claimed.contains(&canonical) {
            return true;
        }
    }
    // Layer 3: (device, inode) — handles hard links + any path-form
    // quirk canonicalize didn't normalise to the stored form.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(walker_path) {
            if claimed_inodes.contains(&(meta.dev(), meta.ino())) {
                return true;
            }
        }
    }
    false
}

/// Recursively scan `rootfs` for ELF / Mach-O / PE binaries, emit
/// file-level + linkage-evidence + ELF-note-package components, and
/// dedupe linkage evidence globally by PURL.
///
/// `claimed_paths` — files owned by an installed-package reader
/// (dpkg `.list`, apk `R:` lines, pip `RECORD`). Binaries whose paths
/// appear in this set skip their file-level + linkage emissions (the
/// owning package already accounts for them). `.note.package` +
/// embedded-version-string emissions remain unconditional — those
/// surface signals the package db can't produce (distro self-ID,
/// static TLS-library versions).
pub fn read(
    rootfs: &Path,
    claimed_paths: &std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &std::collections::HashSet<(u64, u64)>,
) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();
    let mut linkage_agg = linkage::LinkageAggregator::new();
    let mut python_collapser = python_collapse::PythonStdlibCollapser::default();
    let mut jdk_collapser = jdk_collapse::JdkCollapser::default();
    let rootfs_kind = detect_rootfs_kind(rootfs);
    let has_rpmdb = has_rpmdb_at(rootfs);
    // Conformance bug 1 fix: the ELF-note-package PURL builder needs
    // the scan's OS context to fall back on when the note itself
    // doesn't carry a `distro` string. Read once per scan.
    let os_release_id = crate::scan_fs::os_release::read_id_from_rootfs(rootfs);
    let os_release_version_id =
        crate::scan_fs::os_release::read_version_id_from_rootfs(rootfs);
    // v5 Phase A diagnostic: when MIKEBOM_WALKER_DEBUG=1 is set, every
    // filter decision emits a single line to stderr. Used to identify
    // which binaries get dropped by which rule (regression-diagnosis
    // workflow on real fixtures). Gated to zero cost when unset.
    let walker_debug = std::env::var_os("MIKEBOM_WALKER_DEBUG").is_some();

    for path in discover_binaries(rootfs) {
        let Ok(bytes) = std::fs::read(&path) else {
            if walker_debug {
                eprintln!("WALKER {}: DROPPED reason=read-error", path.display());
            }
            continue;
        };
        if bytes.len() < elf::MIN_BINARY_SIZE_BYTES as usize
            || bytes.len() > elf::MAX_BINARY_SIZE_BYTES as usize
        {
            if walker_debug {
                eprintln!(
                    "WALKER {}: DROPPED reason=size-out-of-bounds bytes={}",
                    path.display(),
                    bytes.len()
                );
            }
            continue;
        }
        let Some(scan) = scan_binary(&path, &bytes) else {
            if walker_debug {
                eprintln!(
                    "WALKER {}: DROPPED reason=scan-failed",
                    path.display()
                );
            }
            continue;
        };

        // OS-aware binary-format filter. Mach-O / PE binaries inside
        // a Linux container are nearly always contamination (test
        // fixtures, developer-host builds) whose linkage entries
        // point at host-OS paths. Skip them entirely to prevent the
        // SBOM from attributing `/System/Library/Frameworks/...`
        // dylibs to the container.
        if rootfs_kind == RootfsKind::Linux && scan.binary_class != "elf" {
            if walker_debug {
                eprintln!(
                    "WALKER {}: DROPPED reason=format-mismatch class={} rootfs=linux",
                    path.display(),
                    scan.binary_class
                );
            }
            continue;
        }
        if rootfs_kind == RootfsKind::Macos && scan.binary_class != "macho" {
            if walker_debug {
                eprintln!(
                    "WALKER {}: DROPPED reason=format-mismatch class={} rootfs=macos",
                    path.display(),
                    scan.binary_class
                );
            }
            continue;
        }
        if rootfs_kind == RootfsKind::Windows && scan.binary_class != "pe" {
            if walker_debug {
                eprintln!(
                    "WALKER {}: DROPPED reason=format-mismatch class={} rootfs=windows",
                    path.display(),
                    scan.binary_class
                );
            }
            continue;
        }

        // Milestone 004 post-ship double-counting fix. Suppress the
        // file-level + linkage-evidence emissions when the binary is
        // already owned by a package-db reader. `.note.package` remains
        // unconditional — it's authoritative distro self-identification.
        //
        // v2 fix: path_claimed now canonicalizes via `is_path_claimed`
        // so walker discoveries via /bin → usr/bin symlink traversal
        // (Debian usrmerge) correctly match claims recorded with the
        // canonical /usr/bin/... form. Pre-v2, the character-equality
        // lookup missed and 917/954 pkg:generic/ FPs leaked through.
        //
        // v6 fix (conformance bug 6a): embedded-version-string scans
        // were previously unconditional, which caused dpkg-owned
        // /usr/bin/curl to double-emit as `pkg:generic/curl@7.88.1`
        // alongside the dpkg `pkg:deb/.../curl@...` entry. The
        // deduplicator groups by (ecosystem, name, version) so the two
        // don't merge. Now gated on `skip_file_level_and_linkage` —
        // matches the same claim-aware skip that the file-level
        // emission uses. Trade-off: we lose static-library version
        // detection inside claimed binaries (e.g. statically-linked
        // OpenSSL in a dpkg-owned binary). Accepted because the FP
        // flood from self-identifying claimed binaries is the larger
        // correctness problem in practice.
        let path_claimed = is_path_claimed(
            &path,
            claimed_paths,
            #[cfg(unix)]
            claimed_inodes,
        );
        let rpm_dir_heuristic = rootfs_kind == RootfsKind::Linux
            && has_rpmdb
            && is_os_managed_directory(rootfs, &path);
        let go_in_linux =
            rootfs_kind == RootfsKind::Linux && is_go_binary(&bytes);

        // Python-stdlib collapse (v3 fix): when this binary matches
        // a CPython stdlib layout AND isn't already claimed by a
        // package-db reader, route it to the collapser instead of
        // emitting a file-level component. The collapser emits ONE
        // `pkg:generic/cpython@<X.Y>` umbrella per unique version at
        // scan end.
        let collapsed_by_python = !path_claimed
            && !rpm_dir_heuristic
            && !go_in_linux
            && python_collapser.try_collapse(&path, rootfs);

        // v5 Phase C: JDK umbrella collapse. Same pattern as Python —
        // one `pkg:generic/openjdk@<major>` umbrella per unique Java
        // version. Python gets first refusal (cheap, unlikely to match
        // JDK paths but belt-and-suspenders).
        let collapsed_by_jdk = !path_claimed
            && !rpm_dir_heuristic
            && !go_in_linux
            && !collapsed_by_python
            && jdk_collapser.try_collapse(&path, rootfs);

        // v4 Fix 3 — object files (.o) and static archives (.a) are
        // compilation intermediates, not runtime components. After the
        // Python collapser has had a chance to route them into the
        // cpython umbrella (for Python-<ver>/ source trees), any
        // remaining .o/.a gets silently dropped.
        //
        // Real static archives carry magic `!<arch>\n` and are
        // rejected upstream by `is_supported_binary` — so in practice
        // the `.a` arm only catches the edge case of an ELF file
        // misnamed with a `.a` extension (seen in some build
        // pipelines). Kept as defense-in-depth.
        let is_build_intermediate = !collapsed_by_python
            && matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("o") | Some("a")
            );
        if is_build_intermediate {
            if walker_debug {
                eprintln!(
                    "WALKER {}: DROPPED reason=build-intermediate ext={:?}",
                    path.display(),
                    path.extension().and_then(|e| e.to_str())
                );
            }
            continue;
        }

        if walker_debug {
            if path_claimed {
                eprintln!(
                    "WALKER {}: SKIPPED reason=path-claimed",
                    path.display()
                );
            } else if rpm_dir_heuristic {
                eprintln!(
                    "WALKER {}: SKIPPED reason=rpm-dir-heuristic",
                    path.display()
                );
            } else if go_in_linux {
                eprintln!(
                    "WALKER {}: SKIPPED reason=go-in-linux",
                    path.display()
                );
            } else if collapsed_by_python {
                eprintln!(
                    "WALKER {}: COLLAPSED-PYTHON",
                    path.display()
                );
            } else if collapsed_by_jdk {
                eprintln!(
                    "WALKER {}: COLLAPSED-JDK",
                    path.display()
                );
            } else {
                eprintln!(
                    "WALKER {}: EMITTED file-level class={}",
                    path.display(),
                    scan.binary_class
                );
            }
        }

        let skip_file_level_and_linkage = path_claimed
            || rpm_dir_heuristic
            || go_in_linux
            || collapsed_by_python
            || collapsed_by_jdk;

        if !skip_file_level_and_linkage {
            // File-level binary component.
            let file_level = make_file_level_component(&path, &bytes, &scan);
            let parent_bom_ref = file_level.purl.as_str().to_string();
            out.push(file_level);

            // Linkage-evidence components — accumulated into the global
            // dedup aggregator; emitted after the walk completes.
            // Host-system-path install-names filtered out to prevent
            // `/System/Library/Frameworks/...` leakage.
            //
            // v6 (conformance bug 6b): `add_with_claim_check` probes
            // standard library search paths and skips sonames that
            // resolve to a path claimed by a package-db reader.
            // Fixes `libc.so.6` double-emission alongside the libc6
            // deb.
            for soname in &scan.imports {
                if is_host_system_path(soname) {
                    continue;
                }
                linkage_agg.add_with_claim_check(
                    soname,
                    &path,
                    &parent_bom_ref,
                    rootfs,
                    claimed_paths,
                    #[cfg(unix)]
                    claimed_inodes,
                );
            }
        }

        // ELF-note-package component (authoritative, source-tier;
        // ELF-only — Mach-O / PE don't carry this section).
        //
        // v6 fix (conformance bug 1): gated on `skip_file_level_and_linkage`
        // so claimed binaries (dpkg/rpm/apk-owned) don't double-emit
        // `pkg:rpm/rpm/<source-package>@<ver>` ghosts alongside the
        // authoritative `pkg:rpm/<vendor>/<deployed-subpackage>@<ver>`
        // entry from the package-db reader. Fedora images previously
        // produced 50 such ghosts. Unclaimed binaries still emit —
        // this is the only identity source for them.
        if !skip_file_level_and_linkage {
            if let Some(note) = &scan.note_package {
                if let Some(note_entry) = note_package_to_entry(
                    note,
                    &path,
                    os_release_id.as_deref(),
                    os_release_version_id.as_deref(),
                ) {
                    out.push(note_entry);
                }
            }
        }

        // Curated embedded-version-string scanner per FR-025 / R6.
        // Confined to read-only string sections per Q4 resolution.
        // Every match emits `pkg:generic/<library>@<version>` tagged
        // confidence=heuristic + sbom-tier=analyzed.
        //
        // v6: gated on `skip_file_level_and_linkage` so claimed
        // binaries (dpkg/rpm-owned, collapsed-by-python/jdk, go
        // binaries on Linux) don't double-emit `pkg:generic/curl`
        // alongside the package-db scanner's authoritative entry.
        if !skip_file_level_and_linkage {
            for m in version_strings::scan(&scan.string_region) {
                if let Some(entry) = version_match_to_entry(&m, &path) {
                    out.push(entry);
                }
            }
        }
    }

    out.extend(linkage_agg.into_entries());
    out.extend(python_collapser.into_entries());
    out.extend(jdk_collapser.into_entries());
    out
}

/// Convert a curated-scanner match into a `PackageDbEntry`.
fn version_match_to_entry(
    m: &version_strings::EmbeddedVersionMatch,
    path: &Path,
) -> Option<PackageDbEntry> {
    let purl_str = format!("pkg:generic/{}@{}", m.library.slug(), m.version);
    let purl = Purl::new(&purl_str).ok()?;
    Some(PackageDbEntry {
        purl,
        name: m.library.slug().to_string(),
        version: m.version.clone(),
        arch: None,
        source_path: path.to_string_lossy().into_owned(),
        depends: Vec::new(),
        maintainer: None,
        licenses: vec![],
        is_dev: None,
        requirement_range: None,
        source_type: None,
        sbom_tier: Some("analyzed".to_string()),
        buildinfo_status: None,
        evidence_kind: Some("embedded-version-string".to_string()),
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
}

/// Cross-format scan result. Common fields populated from all three
/// formats via `object::read::File::imports()`; `note_package` is
/// ELF-specific and `None` for Mach-O / PE.
pub(crate) struct BinaryScan {
    pub binary_class: &'static str,
    pub imports: Vec<String>,
    pub has_dynamic: bool,
    pub stripped: bool,
    pub note_package: Option<elf::ElfNotePackage>,
    /// Concatenated read-only string-section bytes per FR-025 /
    /// research R6. Fed to the curated version-string scanner.
    /// Capped at 16 MB per binary.
    pub string_region: Vec<u8>,
    /// UPX or similar packer signature if detected (R7). `None`
    /// means no packer recognised; the linkage list is complete.
    pub packer: Option<packer::PackerKind>,
}

fn scan_binary(path: &Path, bytes: &[u8]) -> Option<BinaryScan> {
    use object::Object;

    // Fat Mach-O requires slice iteration — object's top-level
    // `File::parse` doesn't handle the fat format directly.
    if bytes.len() >= 4 {
        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if matches!(
            magic,
            [0xCA, 0xFE, 0xBA, 0xBE]
                | [0xBE, 0xBA, 0xFE, 0xCA]
                | [0xCA, 0xFE, 0xBA, 0xBF]
                | [0xBF, 0xBA, 0xFE, 0xCA]
        ) {
            return scan_fat_macho(path, bytes);
        }
    }

    let file = match object::read::File::parse(bytes) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "skipping binary parse");
            return None;
        }
    };
    let class = match file.format() {
        object::BinaryFormat::Elf => "elf",
        object::BinaryFormat::MachO => "macho",
        object::BinaryFormat::Pe => "pe",
        _ => return None,
    };

    // Linkage: object's high-level imports() returns `Vec<Import>`
    // where `library()` is the DT_NEEDED soname (ELF), LC_LOAD_DYLIB
    // install-name (Mach-O), or IMPORT DLL name (PE). Dedup by string.
    let mut imports = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Ok(imps) = file.imports() {
        for imp in imps {
            let lib = imp.library();
            if lib.is_empty() {
                continue;
            }
            if let Ok(s) = std::str::from_utf8(lib) {
                if seen.insert(s.to_string()) {
                    imports.push(s.to_string());
                }
            }
        }
    }

    // has_dynamic = linkage list non-empty OR ELF has .dynamic
    // section. Close enough for the dynamic/static classifier.
    let has_dynamic = !imports.is_empty()
        || (class == "elf" && file.section_by_name_bytes(b".dynamic").is_some());

    // Stripped classification per format:
    // - ELF: no .symtab / .dynsym AND no .note.package
    // - Mach-O: no LC_SYMTAB (indicated by absence of symbols)
    // - PE: no IMAGE_DEBUG_DIRECTORY entries AND no VS_VERSION_INFO
    //   (approximated via: has_debug_info() returning false)
    let stripped = match class {
        "elf" => {
            let has_sym = file.section_by_name_bytes(b".symtab").is_some()
                || file.section_by_name_bytes(b".dynsym").is_some();
            let has_note_pkg = file.section_by_name_bytes(b".note.package").is_some();
            !has_sym && !has_note_pkg
        }
        "macho" => file.symbols().next().is_none(),
        "pe" => !file.has_debug_symbols(),
        _ => false,
    };

    let note_package = if class == "elf" {
        file.section_by_name_bytes(b".note.package")
            .and_then(|s| s.data().ok())
            .and_then(elf::parse_note_package_public)
    } else {
        None
    };

    // Read-only string region per FR-025 / Q4 — format-appropriate
    // sections only. Used by the curated version-string scanner.
    let string_region = collect_string_region(&file, class);

    // Packer-signature probe (R7). UPX packs its stub early in the
    // file; a 4 KB byte-level probe catches it. PE-specific section
    // names `UPX0`/`UPX1` also match.
    let packer_kind = packer::detect(bytes);

    Some(BinaryScan {
        binary_class: class,
        imports,
        has_dynamic,
        stripped,
        note_package,
        string_region,
        packer: packer_kind,
    })
}

/// Collect bytes from the read-only string sections appropriate to
/// the binary format. Caps total accumulated bytes at 16 MB.
fn collect_string_region(file: &object::read::File<'_>, class: &str) -> Vec<u8> {
    use object::Object;

    const CAP: usize = 16 * 1024 * 1024;
    let candidates: &[&[u8]] = match class {
        "elf" => &[b".rodata", b".data.rel.ro"],
        "macho" => &[b"__cstring", b"__const"],
        "pe" => &[b".rdata"],
        _ => &[],
    };

    let mut out: Vec<u8> = Vec::new();
    for name in candidates {
        if out.len() >= CAP {
            break;
        }
        if let Some(section) = file.section_by_name_bytes(name) {
            if let Ok(data) = section.data() {
                let room = CAP.saturating_sub(out.len());
                let take = data.len().min(room);
                out.extend_from_slice(&data[..take]);
            }
        }
    }
    out
}

/// Scan a fat Mach-O binary per FR-023 edge case — iterate every
/// architecture slice, parse each as a regular Mach-O, merge the
/// linkage evidence (install-names are arch-invariant in practice,
/// so dedup by string collapses redundant entries).
fn scan_fat_macho(path: &Path, bytes: &[u8]) -> Option<BinaryScan> {
    use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};

    let mut imports = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut has_dynamic = false;
    let mut stripped = true; // AND-reduce across slices
    let mut string_region: Vec<u8> = Vec::new();

    // Try 32-bit fat first, fall back to 64-bit fat.
    let slice_datas: Vec<&[u8]> = if let Ok(fat) = MachOFatFile32::parse(bytes) {
        fat.arches()
            .iter()
            .filter_map(|a| a.data(bytes).ok())
            .collect()
    } else if let Ok(fat) = MachOFatFile64::parse(bytes) {
        fat.arches()
            .iter()
            .filter_map(|a| a.data(bytes).ok())
            .collect()
    } else {
        tracing::warn!(path = %path.display(), "fat Mach-O parse failed");
        return None;
    };

    if slice_datas.is_empty() {
        return None;
    }

    for slice_bytes in &slice_datas {
        let Ok(file) = object::read::File::parse(*slice_bytes) else {
            continue;
        };
        if !matches!(file.format(), object::BinaryFormat::MachO) {
            continue;
        }
        if let Ok(imps) = file.imports() {
            for imp in imps {
                if let Ok(s) = std::str::from_utf8(imp.library()) {
                    if !s.is_empty() && seen.insert(s.to_string()) {
                        imports.push(s.to_string());
                    }
                }
            }
        }
        if !has_dynamic {
            has_dynamic = !imports.is_empty();
        }
        // A slice with symbols un-strips the whole fat binary.
        use object::Object;
        if file.symbols().next().is_some() {
            stripped = false;
        }
        // Accumulate string regions across slices. Same sections
        // typically carry identical content but dedup happens
        // downstream in the version-string scanner (which dedups
        // by library+version).
        const CAP: usize = 16 * 1024 * 1024;
        for name in [b"__cstring".as_ref(), b"__const".as_ref()] {
            if string_region.len() >= CAP {
                break;
            }
            if let Some(section) = file.section_by_name_bytes(name) {
                if let Ok(data) = section.data() {
                    let room = CAP.saturating_sub(string_region.len());
                    let take = data.len().min(room);
                    string_region.extend_from_slice(&data[..take]);
                }
            }
        }
    }

    Some(BinaryScan {
        binary_class: "macho",
        imports,
        has_dynamic,
        stripped,
        note_package: None, // Mach-O doesn't carry .note.package
        string_region,
        packer: packer::detect(bytes),
    })
}

/// Walk `rootfs` for regular files, probing the first 16 bytes of
/// each for a known binary magic. Skips hidden / build dirs. Ignores
/// files <1 KB or >500 MB (defense-in-depth).
fn discover_binaries(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.is_file() {
        if is_supported_binary(root) {
            out.push(root.to_path_buf());
        }
        return out;
    }
    walk_dir(root, &mut out);
    out
}

fn walk_dir(dir: &Path, acc: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(
                name,
                ".git" | "target" | "node_modules" | ".cargo" | "__pycache__" | ".venv"
            ) {
                continue;
            }
            walk_dir(&path, acc);
        } else if path.is_file() && is_supported_binary(&path) {
            acc.push(path);
        }
    }
}

fn is_supported_binary(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    match f.read_exact(&mut magic) {
        Ok(()) => detect_format(&magic).is_some(),
        Err(_) => false,
    }
}

/// Detect binary format by first-4-bytes magic. Returns the
/// canonical `binary-class` string per FR-021.
pub(crate) fn detect_format(magic: &[u8]) -> Option<&'static str> {
    if magic.len() < 4 {
        return None;
    }
    // ELF: 0x7F 'E' 'L' 'F'
    if magic == [0x7F, b'E', b'L', b'F'] {
        return Some("elf");
    }
    // Mach-O: MH_MAGIC (0xFEEDFACE), MH_CIGAM (0xCEFAEDFE), MH_MAGIC_64
    // (0xFEEDFACF), MH_CIGAM_64 (0xCFFAEDFE), fat-binary variants
    // (0xCAFEBABE / 0xBEBAFECA).
    if matches!(
        magic,
        [0xFE, 0xED, 0xFA, 0xCE]
            | [0xCE, 0xFA, 0xED, 0xFE]
            | [0xFE, 0xED, 0xFA, 0xCF]
            | [0xCF, 0xFA, 0xED, 0xFE]
            | [0xCA, 0xFE, 0xBA, 0xBE]
            | [0xBE, 0xBA, 0xFE, 0xCA]
    ) {
        return Some("macho");
    }
    // PE: starts with "MZ" (0x4D 0x5A) in the DOS header; a real PE
    // also has a PE\0\0 signature at the offset stored at 0x3C.
    // First-4-bytes probe is necessarily optimistic — full PE
    // validation happens at parse time via `object::read::File::parse`.
    if &magic[..2] == b"MZ" {
        return Some("pe");
    }
    None
}

fn make_file_level_component(
    path: &Path,
    bytes: &[u8],
    scan: &BinaryScan,
) -> PackageDbEntry {
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    };
    let hash = ContentHash::sha256(&sha256)
        .expect("Sha256 hex is always well-formed");

    // File-level binary components get a synthetic pkg:generic PURL
    // keyed on sha256 so they have a stable identity. The filename
    // is preserved via the `name` field for human readability.
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let purl_str = format!("pkg:generic/{filename}?file-sha256={sha256}");
    let purl = Purl::new(&purl_str).unwrap_or_else(|_| {
        // Fallback: use a bare generic purl if filename has chars PURL
        // can't handle. Keyed on sha256 alone.
        Purl::new(&format!("pkg:generic/binary?file-sha256={sha256}"))
            .expect("bare pkg:generic must parse")
    });

    let linkage = if scan.has_dynamic && !scan.imports.is_empty() {
        "dynamic"
    } else if !scan.has_dynamic {
        "static"
    } else {
        "dynamic"
    }
    .to_string();

    PackageDbEntry {
        purl,
        name: filename,
        version: String::new(),
        arch: None,
        source_path: path.to_string_lossy().into_owned(),
        depends: Vec::new(),
        maintainer: None,
        licenses: vec![],
        is_dev: None,
        requirement_range: None,
        source_type: None,
        sbom_tier: Some("analyzed".to_string()),
        buildinfo_status: None,
        evidence_kind: None,
        binary_class: Some(scan.binary_class.to_string()),
        binary_stripped: Some(scan.stripped),
        linkage_kind: Some(linkage),
        detected_go: None,
        confidence: None,
        binary_packed: scan.packer.map(|p| p.as_str().to_string()),
        raw_version: None,
        npm_role: None,
        hashes: Vec::new(),
    }
    .with_sha256_placeholder(hash)
}

/// Extension helper: attach the file-SHA-256 as a `hashes` field.
impl PackageDbEntry {
    fn with_sha256_placeholder(self, _hash: ContentHash) -> Self {
        // `PackageDbEntry` doesn't currently carry hashes directly;
        // hashes land on the `ResolvedComponent` via the scan_fs
        // conversion layer from the artefact-file walker. Binary
        // file-level components bypass that walker (they're produced
        // here), so a follow-on could extend `PackageDbEntry` with a
        // hashes field. For this turn, hashes on binary components
        // are omitted — consumers see the file-level component with
        // the filename + bom-ref identity but without content hashes.
        // Future: hook into the milestone-003 `file_hashes` plumbing.
        self
    }
}

/// Convert a parsed `.note.package` payload into a `PackageDbEntry`
/// per FR-024. Vendor derived from `distro` via the milestone-003
/// `rpm_vendor_from_id` map for RPM-family notes.
fn note_package_to_entry(
    note: &elf::ElfNotePackage,
    path: &Path,
    os_release_id: Option<&str>,
    os_release_version_id: Option<&str>,
) -> Option<PackageDbEntry> {
    if note.name.is_empty() || note.version.is_empty() {
        return None;
    }
    let mut qualifiers = note
        .architecture
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|a| format!("?arch={a}"))
        .unwrap_or_default();

    // v6 fix (conformance bug 1 / ELF-note ghosts): vendor namespace
    // precedence is (1) the ELF note's own `distro` field when
    // populated, then (2) the scan-wide `/etc/os-release` ID, then
    // (3) a hardcoded default. Prior to this change, an unclaimed
    // Fedora binary with no `distro` in its ELF note emitted
    // `pkg:rpm/rpm/<name>@<ver>` — no OS context. Threading the
    // os-release ID recovers the correct namespace for the fallback
    // path.
    let resolve_vendor = |note_distro: Option<&str>, default_fallback: &str| -> String {
        let from_note = note_distro
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|d| d.to_lowercase());
        if let Some(d) = from_note {
            return d;
        }
        if let Some(id) = os_release_id.filter(|s| !s.is_empty()) {
            return id.to_lowercase();
        }
        default_fallback.to_string()
    };
    let append_distro_qualifier = |qualifiers: &mut String, vendor: &str| {
        // Emit `distro=<vendor>-<VERSION_ID>` only when both halves
        // are available. Mirrors the dpkg / rpm / apk package-db
        // readers' qualifier shape.
        if let Some(version_id) = os_release_version_id.filter(|s| !s.is_empty()) {
            let prefix = if qualifiers.is_empty() { '?' } else { '&' };
            qualifiers.push(prefix);
            qualifiers.push_str("distro=");
            qualifiers.push_str(vendor);
            qualifiers.push('-');
            qualifiers.push_str(version_id);
        }
    };

    let purl_str = match note.note_type.as_str() {
        "rpm" => {
            let raw_vendor = resolve_vendor(note.distro.as_deref(), "rpm");
            // rpm_vendor_from_id normalizes `rhel`→`redhat`, `ol`→`oracle`,
            // etc. Same mapping used by rpm.rs for the rpmdb reader.
            let vendor = rpm_vendor_from_id(&raw_vendor);
            append_distro_qualifier(&mut qualifiers, &vendor);
            format!(
                "pkg:rpm/{vendor}/{}@{}{qualifiers}",
                note.name, note.version,
            )
        }
        "deb" => {
            let vendor = resolve_vendor(note.distro.as_deref(), "debian");
            append_distro_qualifier(&mut qualifiers, &vendor);
            format!(
                "pkg:deb/{vendor}/{}@{}{qualifiers}",
                note.name, note.version,
            )
        }
        "apk" => {
            let vendor = resolve_vendor(note.distro.as_deref(), "alpine");
            append_distro_qualifier(&mut qualifiers, &vendor);
            format!(
                "pkg:apk/{vendor}/{}@{}{qualifiers}",
                note.name, note.version,
            )
        }
        "alpm" | "pacman" => {
            format!("pkg:alpm/arch/{}@{}{qualifiers}", note.name, note.version)
        }
        _ => format!("pkg:generic/{}@{}", note.name, note.version),
    };

    let purl = Purl::new(&purl_str).ok()?;
    Some(PackageDbEntry {
        purl,
        name: note.name.clone(),
        version: note.version.clone(),
        arch: note.architecture.clone(),
        source_path: path.to_string_lossy().into_owned(),
        depends: Vec::new(),
        maintainer: None,
        licenses: vec![],
        is_dev: None,
        requirement_range: None,
        source_type: None,
        sbom_tier: Some("source".to_string()),
        buildinfo_status: None,
        evidence_kind: Some("elf-note-package".to_string()),
        binary_class: None,
        binary_stripped: None,
        linkage_kind: None,
        detected_go: None,
        confidence: None,
        binary_packed: None,
        raw_version: None,
        npm_role: None,
        hashes: Vec::new(),
    })
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn note_package_rpm_produces_canonical_purl() {
        let note = elf::ElfNotePackage {
            note_type: "rpm".into(),
            name: "curl".into(),
            version: "8.2.1".into(),
            architecture: Some("x86_64".into()),
            distro: Some("fedora".into()),
            os_cpe: None,
        };
        let entry =
            note_package_to_entry(&note, Path::new("/opt/curl"), None, None).unwrap();
        assert_eq!(
            entry.purl.as_str(),
            "pkg:rpm/fedora/curl@8.2.1?arch=x86_64"
        );
        assert_eq!(entry.evidence_kind.as_deref(), Some("elf-note-package"));
        assert_eq!(entry.sbom_tier.as_deref(), Some("source"));
    }

    #[test]
    fn note_package_rpm_uses_os_release_namespace_when_note_distro_absent() {
        // Conformance bug 1 fix: when the ELF note has no distro field
        // but the scan's /etc/os-release ID is known, use the os-release
        // ID instead of the bare "rpm" fallback. Fixes Fedora ghosts
        // emitting pkg:rpm/rpm/<name>.
        let note = elf::ElfNotePackage {
            note_type: "rpm".into(),
            name: "ModemManager".into(),
            version: "1.22.0-3.fc40".into(),
            architecture: Some("aarch64".into()),
            distro: None,
            os_cpe: None,
        };
        let entry = note_package_to_entry(
            &note,
            Path::new("/usr/libexec/mm-plugin-broadband"),
            Some("fedora"),
            Some("40"),
        )
        .unwrap();
        assert_eq!(
            entry.purl.as_str(),
            "pkg:rpm/fedora/ModemManager@1.22.0-3.fc40?arch=aarch64&distro=fedora-40"
        );
    }

    #[test]
    fn note_package_rpm_prefers_note_distro_over_os_release() {
        // Precedence: ELF note's own `distro` wins over os-release ID.
        let note = elf::ElfNotePackage {
            note_type: "rpm".into(),
            name: "curl".into(),
            version: "8.2.1".into(),
            architecture: Some("x86_64".into()),
            distro: Some("rocky".into()),
            os_cpe: None,
        };
        // Note says rocky, os-release (hypothetically wrong) says fedora.
        // rocky wins; rpm_vendor_from_id keeps rocky→rocky, then appends
        // distro=rocky-9 from VERSION_ID.
        let entry = note_package_to_entry(
            &note,
            Path::new("/usr/bin/curl"),
            Some("fedora"),
            Some("9"),
        )
        .unwrap();
        assert_eq!(
            entry.purl.as_str(),
            "pkg:rpm/rocky/curl@8.2.1?arch=x86_64&distro=rocky-9"
        );
    }

    #[test]
    fn note_package_rpm_falls_back_to_rpm_when_no_context() {
        // Final fallback: no note distro, no os-release. Emits the
        // original bare "rpm" namespace. In practice this should never
        // happen on a real scan (os-release is read first), but the
        // defensive default preserves PURL validity.
        let note = elf::ElfNotePackage {
            note_type: "rpm".into(),
            name: "foo".into(),
            version: "1.0".into(),
            architecture: None,
            distro: None,
            os_cpe: None,
        };
        let entry =
            note_package_to_entry(&note, Path::new("/bin/foo"), None, None).unwrap();
        assert_eq!(entry.purl.as_str(), "pkg:rpm/rpm/foo@1.0");
    }

    #[test]
    fn note_package_alpm_uses_arch_namespace() {
        let note = elf::ElfNotePackage {
            note_type: "alpm".into(),
            name: "bash".into(),
            version: "5.2.015-1".into(),
            architecture: Some("x86_64".into()),
            distro: Some("Arch Linux".into()),
            os_cpe: None,
        };
        let entry = note_package_to_entry(
            &note,
            Path::new("/usr/bin/bash"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            entry.purl.as_str(),
            "pkg:alpm/arch/bash@5.2.015-1?arch=x86_64"
        );
    }

    #[test]
    fn note_package_deb_falls_back_to_debian_vendor() {
        let note = elf::ElfNotePackage {
            note_type: "deb".into(),
            name: "vim".into(),
            version: "9.0.0".into(),
            architecture: Some("amd64".into()),
            distro: None,
            os_cpe: None,
        };
        // No os-release context either → "debian" fallback.
        let entry = note_package_to_entry(
            &note,
            Path::new("/usr/bin/vim"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            entry.purl.as_str(),
            "pkg:deb/debian/vim@9.0.0?arch=amd64"
        );
    }

    #[test]
    fn note_package_deb_uses_os_release_namespace_for_ubuntu() {
        // Ubuntu image: ELF note lacks distro, os-release says ubuntu.
        let note = elf::ElfNotePackage {
            note_type: "deb".into(),
            name: "openssh-server".into(),
            version: "1:9.6p1-3ubuntu13".into(),
            architecture: Some("amd64".into()),
            distro: None,
            os_cpe: None,
        };
        let entry = note_package_to_entry(
            &note,
            Path::new("/usr/sbin/sshd"),
            Some("ubuntu"),
            Some("24.04"),
        )
        .unwrap();
        assert_eq!(
            entry.purl.as_str(),
            "pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13?arch=amd64&distro=ubuntu-24.04"
        );
    }

    #[test]
    fn note_package_unknown_type_becomes_generic() {
        let note = elf::ElfNotePackage {
            note_type: "xbps".into(),
            name: "foo".into(),
            version: "1.0".into(),
            architecture: None,
            distro: None,
            os_cpe: None,
        };
        let entry =
            note_package_to_entry(&note, Path::new("/bin/foo"), None, None).unwrap();
        assert_eq!(entry.purl.as_str(), "pkg:generic/foo@1.0");
    }

    #[test]
    fn empty_rootfs_yields_zero_binary_components() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(
            dir.path(),
            &Default::default(),
            #[cfg(unix)]
            &Default::default()
        )
        .is_empty());
    }

    #[test]
    fn non_elf_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("script.sh"), b"#!/bin/sh\necho hi").unwrap();
        std::fs::write(dir.path().join("data.txt"), b"hello world").unwrap();
        assert!(read(
            dir.path(),
            &Default::default(),
            #[cfg(unix)]
            &Default::default()
        )
        .is_empty());
    }

    #[test]
    fn detect_rootfs_kind_alpine_from_apk_db() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("lib/apk/db")).unwrap();
        std::fs::write(dir.path().join("lib/apk/db/installed"), b"C:Q1...\n").unwrap();
        assert_eq!(detect_rootfs_kind(dir.path()), RootfsKind::Linux);
    }

    #[test]
    fn detect_rootfs_kind_debian_from_dpkg_status() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("var/lib/dpkg")).unwrap();
        std::fs::write(dir.path().join("var/lib/dpkg/status"), b"Package: foo\n").unwrap();
        assert_eq!(detect_rootfs_kind(dir.path()), RootfsKind::Linux);
    }

    #[test]
    fn detect_rootfs_kind_rhel_from_rpmdb() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("var/lib/rpm")).unwrap();
        std::fs::write(dir.path().join("var/lib/rpm/rpmdb.sqlite"), b"stub").unwrap();
        assert_eq!(detect_rootfs_kind(dir.path()), RootfsKind::Linux);
    }

    /// v9 Phase M — Fedora ≥34 / RHEL ≥9.4 ship rpmdb at the
    /// `usr/lib/sysimage/rpm/` location. detect_rootfs_kind must
    /// recognize this as Linux so rpm_dir_heuristic fires.
    #[test]
    fn detect_rootfs_kind_fedora_sysimage_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("usr/lib/sysimage/rpm")).unwrap();
        std::fs::write(
            dir.path().join("usr/lib/sysimage/rpm/rpmdb.sqlite"),
            b"stub",
        )
        .unwrap();
        assert_eq!(detect_rootfs_kind(dir.path()), RootfsKind::Linux);
    }

    // --- v8 Phase K1: has_rpmdb_at covers both old and sysimage paths ---

    #[test]
    fn has_rpmdb_at_detects_legacy_var_lib_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("var/lib/rpm")).unwrap();
        std::fs::write(dir.path().join("var/lib/rpm/rpmdb.sqlite"), b"stub").unwrap();
        assert!(has_rpmdb_at(dir.path()));
    }

    #[test]
    fn has_rpmdb_at_detects_sysimage_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("usr/lib/sysimage/rpm")).unwrap();
        std::fs::write(
            dir.path().join("usr/lib/sysimage/rpm/rpmdb.sqlite"),
            b"stub",
        )
        .unwrap();
        assert!(
            has_rpmdb_at(dir.path()),
            "Fedora/RHEL9.4 sysimage rpmdb path must be detected"
        );
    }

    #[test]
    fn has_rpmdb_at_returns_false_on_bare_rootfs() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!has_rpmdb_at(dir.path()));
    }

    #[test]
    fn has_rpmdb_at_detects_legacy_bdb_packages_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("var/lib/rpm")).unwrap();
        std::fs::write(dir.path().join("var/lib/rpm/Packages"), b"BDB").unwrap();
        assert!(has_rpmdb_at(dir.path()));
    }

    #[test]
    fn detect_rootfs_kind_from_os_release_id() {
        for id in &["alpine", "ubuntu", "debian", "rhel", "rocky", "fedora"] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("etc")).unwrap();
            std::fs::write(
                dir.path().join("etc/os-release"),
                format!("ID={id}\n").as_bytes(),
            )
            .unwrap();
            assert_eq!(
                detect_rootfs_kind(dir.path()),
                RootfsKind::Linux,
                "ID={id} should detect as Linux"
            );
        }
    }

    #[test]
    fn detect_rootfs_kind_unknown_for_plain_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("random.txt"), b"hello").unwrap();
        assert_eq!(detect_rootfs_kind(dir.path()), RootfsKind::Unknown);
    }

    #[test]
    fn is_host_system_path_blocks_macos_frameworks() {
        assert!(is_host_system_path(
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
        ));
        assert!(is_host_system_path("/usr/lib/system/libsystem_kernel.dylib"));
        assert!(is_host_system_path(
            "/System/iOSSupport/System/Library/Frameworks/UIKit.framework/UIKit"
        ));
    }

    #[test]
    fn is_os_managed_directory_matches_standard_paths() {
        let rootfs = Path::new("/tmp/fakeroot");
        assert!(is_os_managed_directory(
            rootfs,
            &rootfs.join("usr/bin/base64")
        ));
        assert!(is_os_managed_directory(rootfs, &rootfs.join("bin/ls")));
        assert!(is_os_managed_directory(
            rootfs,
            &rootfs.join("usr/lib/libc.so.6")
        ));
        assert!(is_os_managed_directory(
            rootfs,
            &rootfs.join("usr/lib64/libcrypto.so.3")
        ));
        assert!(is_os_managed_directory(
            rootfs,
            &rootfs.join("usr/libexec/coreutils/libstdbuf.so")
        ));
    }

    #[test]
    fn is_os_managed_directory_allows_opt_and_local_paths() {
        let rootfs = Path::new("/tmp/fakeroot");
        // Manually-installed / user binaries should NOT be presumed owned.
        assert!(!is_os_managed_directory(
            rootfs,
            &rootfs.join("opt/myapp/bin/jq")
        ));
        assert!(!is_os_managed_directory(
            rootfs,
            &rootfs.join("usr/local/bin/custom-tool")
        ));
        assert!(!is_os_managed_directory(
            rootfs,
            &rootfs.join("home/user/bin/tool")
        ));
        assert!(!is_os_managed_directory(rootfs, &rootfs.join("app/server")));
    }

    #[test]
    fn is_go_binary_detects_buildinfo_magic() {
        // Minimal fixture: BuildInfo magic embedded in a larger buffer.
        let mut bytes = vec![0u8; 4096];
        bytes[2000..2014].copy_from_slice(b"\xff Go buildinf:");
        assert!(is_go_binary(&bytes));
    }

    #[test]
    fn is_go_binary_returns_false_without_magic() {
        let bytes = vec![0x7Fu8; 4096];
        assert!(!is_go_binary(&bytes));
    }

    #[test]
    fn is_go_binary_bounded_probe() {
        // Magic past the 2 MB probe window should NOT match.
        let mut bytes = vec![0u8; 3 * 1024 * 1024];
        bytes[2_500_000..2_500_014].copy_from_slice(b"\xff Go buildinf:");
        assert!(!is_go_binary(&bytes));
    }

    #[test]
    fn is_host_system_path_allows_real_sonames() {
        assert!(!is_host_system_path("libc.so.6"));
        assert!(!is_host_system_path("libssl.so.3"));
        assert!(!is_host_system_path("@rpath/libfoo.dylib"));
        assert!(!is_host_system_path("/usr/lib/libSystem.B.dylib"));
        // Note the last one is technically a host path BUT it's also
        // the identity Mach-O binaries always use; we keep it because
        // standalone macOS scans need it. The Linux-rootfs filter is
        // the primary defense against host-OS leak.
        assert!(!is_host_system_path("KERNEL32.dll"));
        assert!(!is_host_system_path("advapi32.dll"));
    }

    /// Regression test for the Docker-image usrmerge failure mode
    /// (reported: 917 of 954 `pkg:generic/` FPs had basename matches in
    /// dpkg `.list` but missed the path-containment check).
    ///
    /// Reproduces the exact mismatch: walker discovers the binary via
    /// a symlinked path (`/rootfs/bin/base64`), claim was recorded as
    /// the canonical path (`/rootfs/usr/bin/base64`) via the
    /// `insert_claim_with_canonical` helper (matching how the real
    /// dpkg / apk / pip readers populate the claim set). The
    /// `is_path_claimed` lookup at walker time MUST recognise the
    /// two paths refer to the same inode via canonicalization.
    #[cfg(unix)]
    #[test]
    fn claim_skip_recognizes_usrmerge_symlink_path() {
        use std::collections::HashSet;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Real /usr/bin directory with a dummy binary.
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/base64"), b"not a real binary").unwrap();
        // /bin → usr/bin symlink (Debian usrmerge).
        std::os::unix::fs::symlink("usr/bin", root.join("bin")).unwrap();

        // Claim inserted via the production helper — dual-inserts raw
        // (rootfs.join("usr/bin/base64")) + parent-canonical forms so
        // the HashSet contains both representations the walker might
        // produce. Also records (dev, inode) for symlink-robust match.
        let mut claimed: HashSet<std::path::PathBuf> = HashSet::new();
        let mut inodes: HashSet<(u64, u64)> = HashSet::new();
        crate::scan_fs::package_db::insert_claim_with_canonical(
            &mut claimed,
            &mut inodes,
            root.join("usr/bin/base64"),
        );

        // Walker discovers the binary via the symlinked path.
        let walker_path = root.join("bin/base64");
        assert!(
            walker_path.exists(),
            "walker path must resolve via symlink"
        );
        assert_ne!(
            walker_path,
            root.join("usr/bin/base64"),
            "pre-canonicalization, walker path must differ from claim path"
        );

        // The claim-skip mechanism must recognise these as the same
        // via canonicalization on the walker side + the dual-insert
        // on the claim side.
        assert!(
            is_path_claimed(
                &walker_path,
                &claimed,
                #[cfg(unix)]
                &inodes
            ),
            "usrmerge: walker path via symlink MUST be recognised as claimed. \
             walker={walker_path:?}, claimed={claimed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn claim_skip_without_symlink_still_works() {
        use std::collections::HashSet;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/cat"), b"not a real binary").unwrap();

        let mut claimed: HashSet<std::path::PathBuf> = HashSet::new();
        let inodes: HashSet<(u64, u64)> = HashSet::new();
        claimed.insert(root.join("usr/bin/cat"));

        let walker_path = root.join("usr/bin/cat");
        assert!(
            is_path_claimed(&walker_path, &claimed, &inodes),
            "plain (non-usrmerge) claim match must still work"
        );
    }

    #[cfg(unix)]
    #[test]
    fn claim_skip_broken_symlink_does_not_panic() {
        use std::collections::HashSet;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Symlink pointing at a nonexistent target — canonicalize fails.
        std::os::unix::fs::symlink("does-not-exist", root.join("dangling")).unwrap();

        let claimed: HashSet<std::path::PathBuf> = HashSet::new();
        let inodes: HashSet<(u64, u64)> = HashSet::new();
        let walker_path = root.join("dangling");
        // Must not panic; returns false (not claimed → file would
        // be processed if it were a valid binary, which it isn't).
        assert!(!is_path_claimed(&walker_path, &claimed, &inodes));
    }

    /// Test A1 from v3 plan — inode match catches a final-component
    /// symlink even when canonicalize's output form differs from the
    /// stored claim.
    #[cfg(unix)]
    #[test]
    fn claim_skip_via_inode_on_symlinked_library() {
        use std::collections::HashSet;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::write(root.join("usr/lib/libfoo.so.1"), b"dummy").unwrap();
        // Symlink libfoo.so → libfoo.so.1 in the same directory.
        std::os::unix::fs::symlink("libfoo.so.1", root.join("usr/lib/libfoo.so")).unwrap();

        // Claim only the real file.
        let mut claimed: HashSet<std::path::PathBuf> = HashSet::new();
        let mut inodes: HashSet<(u64, u64)> = HashSet::new();
        crate::scan_fs::package_db::insert_claim_with_canonical(
            &mut claimed,
            &mut inodes,
            root.join("usr/lib/libfoo.so.1"),
        );

        // Walker discovers the symlink path.
        let walker_path = root.join("usr/lib/libfoo.so");
        assert!(walker_path.exists());

        // Must recognize the symlink as claimed (via inode — canonicalize
        // also works here, but inode is the robust fallback that
        // closes the class of bug for more exotic symlink situations).
        assert!(
            is_path_claimed(&walker_path, &claimed, &inodes),
            "symlink library MUST be recognized as claimed. \
             walker={walker_path:?}, claimed={claimed:?}, inodes={inodes:?}"
        );
    }

    /// Test A2 from v3 plan — hard link. Canonicalize CANNOT collapse
    /// hard links (different directory entries for the same inode).
    /// Inode match is the only robust path.
    #[cfg(unix)]
    #[test]
    fn inode_match_survives_hard_link() {
        use std::collections::HashSet;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/a"), b"dummy").unwrap();
        // Hard link a → b in the same directory.
        std::fs::hard_link(root.join("usr/bin/a"), root.join("usr/bin/b")).unwrap();

        // Claim only `a`.
        let mut claimed: HashSet<std::path::PathBuf> = HashSet::new();
        let mut inodes: HashSet<(u64, u64)> = HashSet::new();
        crate::scan_fs::package_db::insert_claim_with_canonical(
            &mut claimed,
            &mut inodes,
            root.join("usr/bin/a"),
        );

        // Walker discovers `b` — different path, same inode.
        let walker_path = root.join("usr/bin/b");
        assert!(walker_path.exists());
        assert!(
            !claimed.contains(&walker_path),
            "raw path lookup must miss (hard link not path-equal)"
        );

        // Inode match is the only path that works here.
        assert!(
            is_path_claimed(&walker_path, &claimed, &inodes),
            "hard link MUST be recognized as claimed via inode match. \
             walker={walker_path:?}, inodes={inodes:?}"
        );
    }
}
