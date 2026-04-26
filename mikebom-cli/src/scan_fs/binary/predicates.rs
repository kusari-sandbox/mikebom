//! OS-aware predicates: rootfs kind detection + path classification.
//!
//! Used by the binary-scan orchestrator to decide which file formats
//! to accept (Linux rootfs → only ELF; macOS rootfs → only Mach-O;
//! Unknown rootfs → all formats) and which directories to filter as
//! OS-managed (skip when emitting file-level binary components).

use std::path::Path;


/// Detected OS family of the scan root. Drives the OS-aware binary-
/// format filter — we skip Mach-O / PE when scanning a Linux rootfs
/// because binaries of other formats inside a Linux container are
/// always contamination (test fixtures, build artefacts from a
/// developer's host that got packaged in). Their linkage entries
/// reference host paths like `/System/Library/Frameworks/...` that
/// don't exist in the container and shouldn't appear in its SBOM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RootfsKind {
    Linux,
    Macos,
    Windows,
    /// No OS-specific signal found — treat as "any binary format allowed"
    /// (caller likely scanning a mixed directory, not a container rootfs).
    Unknown,
}

pub(super) fn detect_rootfs_kind(rootfs: &Path) -> RootfsKind {
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
pub(super) fn is_host_system_path(soname: &str) -> bool {
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
pub(super) fn has_rpmdb_at(rootfs: &std::path::Path) -> bool {
    use crate::scan_fs::package_db::rpm;
    rpm::RPMDB_SQLITE_CANDIDATES
        .iter()
        .any(|c| rootfs.join(c).is_file())
        || rpm::RPMDB_BDB_CANDIDATES
            .iter()
            .any(|c| rootfs.join(c).is_file())
}

pub(super) fn is_os_managed_directory(rootfs: &std::path::Path, path: &std::path::Path) -> bool {
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

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
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
}
