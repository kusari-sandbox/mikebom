//! Shared `/etc/os-release` reader.
//!
//! Two call sites want the distro codename: the build-time attestation
//! builder (which reads the trace host's own os-release via the fixed
//! path `/etc/os-release`), and the scan pipeline (which reads it out
//! of an extracted container image rootfs or a --path root). Same
//! parsing rules in both cases — one small helper in one place.

use std::path::{Path, PathBuf};

/// Spec-compliant os-release location fallback list. Per
/// `man os-release`: applications check `/etc/os-release` first and
/// fall back to `/usr/lib/os-release` when the primary is missing.
/// Ubuntu 24.04 (and many Debian-derivatives) ship `/etc/os-release`
/// as a symlink to `/usr/lib/os-release`; when container-image
/// extraction preserves the symlink but the target lands in a layer
/// that gets whited out or reordered, the symlink dangles and the
/// primary read fails. The fallback recovers the data.
///
/// Takes a rootfs and yields absolute file paths within it in the
/// order callers should try.
pub fn os_release_candidates(rootfs: &Path) -> [PathBuf; 2] {
    [
        rootfs.join("etc/os-release"),
        rootfs.join("usr/lib/os-release"),
    ]
}

/// Read the first os-release file within `rootfs` that exists and is
/// readable, trying the spec-compliant paths in order
/// (see [`os_release_candidates`]). Returns the file contents for the
/// caller to parse. `None` when neither path resolves.
fn read_os_release_contents(rootfs: &Path) -> Option<String> {
    for candidate in os_release_candidates(rootfs) {
        if let Ok(text) = std::fs::read_to_string(&candidate) {
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

/// Rootfs-aware `ID=` reader. Tries `/etc/os-release` first, falls
/// back to `/usr/lib/os-release` per the os-release spec. Used by the
/// scan pipeline where the primary location may be a dangling symlink
/// after container-image extraction.
pub fn read_id_from_rootfs(rootfs: &Path) -> Option<String> {
    read_os_release_contents(rootfs).and_then(|t| parse_id(&t))
}

/// Rootfs-aware `VERSION_ID=` reader. Same fallback policy as
/// [`read_id_from_rootfs`].
pub fn read_version_id_from_rootfs(rootfs: &Path) -> Option<String> {
    read_os_release_contents(rootfs).and_then(|t| parse_version_id(&t))
}

/// Read `os-release` at an explicit path and pluck out `VERSION_CODENAME`.
/// Used by the scan-mode pipelines to grab the codename from an extracted
/// image's rootfs (`<rootfs>/etc/os-release`) or a user-supplied
/// rootfs-shaped directory (`<path>/etc/os-release`).
///
/// Returns `None` when the file is absent, unreadable, or lacks the
/// `VERSION_CODENAME=` key. Empty values are also treated as absent —
/// some distros set `VERSION_CODENAME=""` during rolling-release cycles
/// and that carries no useful meaning for our `distro=` qualifier.
pub fn read_version_codename(os_release_path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(os_release_path).ok()?;
    parse_version_codename(&text)
}

/// Read `os-release` at an explicit path and pluck out the raw `ID=` value
/// (e.g. `rhel`, `rocky`, `fedora`, `amzn`, `centos`, `ol`, `almalinux`,
/// `opensuse-leap`, `sles`, `debian`, `ubuntu`, `alpine`). Callers use this
/// to drive distro-specific branching — the primary consumer is the rpm
/// reader, which converts the ID into a PURL vendor segment via
/// [`super::package_db::rpm_vendor_from_id`].
///
/// Returns `None` when the file is absent, unreadable, or lacks the
/// `ID=` key. Empty values are also treated as absent. The returned
/// string preserves the raw casing from the file; per the os-release
/// spec (`man os-release`), IDs are already lowercase-only.
pub fn read_id(os_release_path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(os_release_path).ok()?;
    parse_id(&text)
}

/// Read `os-release` at an explicit path and pluck out the `VERSION_ID=`
/// value (e.g. Alpine's `3.20.9`, Debian's `12`, RHEL's `9.3`). Used to
/// stamp `distro=alpine-<VERSION_ID>` onto apk PURLs per the PURL spec.
///
/// Returns `None` when the file is absent, unreadable, or the key is
/// missing / empty.
pub fn read_version_id(os_release_path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(os_release_path).ok()?;
    parse_version_id(&text)
}

/// Read the trace host's own `/etc/os-release` on Linux, returning the
/// codename if present. Non-Linux always returns `None`. Equivalent to
/// the helper that used to live in `attestation::builder`.
pub fn detect_host_codename() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        read_version_codename(Path::new("/etc/os-release"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Extract the distro codename from the raw contents of an os-release
/// file. Prefers `VERSION_CODENAME=` (set by Debian, Ubuntu ≥20.04,
/// derivatives) and falls back to `UBUNTU_CODENAME=` when the first key
/// is absent — some older Ubuntu images set only that. Handles the
/// three common value shapes:
///
/// ```text
/// VERSION_CODENAME=bookworm
/// VERSION_CODENAME="bookworm"
/// VERSION_CODENAME='bookworm'
/// ```
fn parse_version_codename(text: &str) -> Option<String> {
    let mut ubuntu_fallback: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("VERSION_CODENAME=") {
            let trimmed = rest.trim().trim_matches('"').trim_matches('\'');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        } else if ubuntu_fallback.is_none() {
            if let Some(rest) = line.strip_prefix("UBUNTU_CODENAME=") {
                let trimmed = rest.trim().trim_matches('"').trim_matches('\'');
                if !trimmed.is_empty() {
                    ubuntu_fallback = Some(trimmed.to_string());
                }
            }
        }
    }
    ubuntu_fallback
}

/// Extract the `VERSION_ID=` value from os-release contents. Handles
/// the same three value shapes as [`parse_version_codename`] (bare /
/// double quoted / single quoted).
fn parse_version_id(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("VERSION_ID=") {
            let trimmed = rest.trim().trim_matches('"').trim_matches('\'');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Extract the raw `ID=` value from os-release contents. Handles the
/// same three value shapes as [`parse_version_codename`] (bare / double
/// quoted / single quoted).
fn parse_id(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ID=") {
            let trimmed = rest.trim().trim_matches('"').trim_matches('\'');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_value() {
        let text = "NAME=Debian\nVERSION_CODENAME=bookworm\nID=debian\n";
        assert_eq!(parse_version_codename(text), Some("bookworm".to_string()));
    }

    #[test]
    fn parses_double_quoted_value() {
        let text = r#"VERSION_CODENAME="jammy""#;
        assert_eq!(parse_version_codename(text), Some("jammy".to_string()));
    }

    #[test]
    fn parses_single_quoted_value() {
        let text = "VERSION_CODENAME='trixie'";
        assert_eq!(parse_version_codename(text), Some("trixie".to_string()));
    }

    #[test]
    fn empty_value_is_none() {
        let text = "VERSION_CODENAME=\"\"\n";
        assert_eq!(parse_version_codename(text), None);
    }

    #[test]
    fn missing_key_is_none() {
        let text = "NAME=Alpine\nID=alpine\nVERSION_ID=3.19\n";
        assert_eq!(parse_version_codename(text), None);
    }

    #[test]
    fn ignores_leading_whitespace() {
        // Some os-release files have blank-ish lines; tolerate them.
        let text = "\n   VERSION_CODENAME=noble\n";
        assert_eq!(parse_version_codename(text), Some("noble".to_string()));
    }

    #[test]
    fn reads_from_a_real_file_via_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("os-release");
        std::fs::write(&path, "VERSION_CODENAME=bullseye\n").unwrap();
        assert_eq!(read_version_codename(&path), Some("bullseye".to_string()));
    }

    #[test]
    fn missing_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist");
        assert_eq!(read_version_codename(&path), None);
    }

    #[test]
    fn falls_back_to_ubuntu_codename_when_version_codename_absent() {
        // Early Ubuntu and some derivatives only set UBUNTU_CODENAME=.
        let text = "NAME=Ubuntu\nID=ubuntu\nUBUNTU_CODENAME=noble\n";
        assert_eq!(parse_version_codename(text), Some("noble".to_string()));
    }

    #[test]
    fn parses_version_id_alpine() {
        let text = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.9\n";
        assert_eq!(parse_version_id(text), Some("3.20.9".to_string()));
    }

    #[test]
    fn parses_version_id_quoted() {
        let text = "VERSION_ID=\"12\"\n";
        assert_eq!(parse_version_id(text), Some("12".to_string()));
    }

    #[test]
    fn version_id_missing_is_none() {
        let text = "ID=alpine\n";
        assert_eq!(parse_version_id(text), None);
    }

    #[test]
    fn version_id_empty_is_none() {
        let text = "VERSION_ID=\"\"\n";
        assert_eq!(parse_version_id(text), None);
    }

    #[test]
    fn read_version_id_from_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("os-release");
        std::fs::write(&path, "ID=alpine\nVERSION_ID=3.20.9\n").unwrap();
        assert_eq!(read_version_id(&path), Some("3.20.9".to_string()));
    }

    #[test]
    fn version_codename_wins_over_ubuntu_codename() {
        // Modern Ubuntu sets both — VERSION_CODENAME is the canonical
        // spec key and should take precedence, even when it appears
        // second in the file.
        let text = "UBUNTU_CODENAME=jammy\nVERSION_CODENAME=jammy\n";
        assert_eq!(parse_version_codename(text), Some("jammy".to_string()));

        // Same thing, reversed: earlier UBUNTU_CODENAME still loses.
        let text2 = "VERSION_CODENAME=noble\nUBUNTU_CODENAME=noble\n";
        assert_eq!(parse_version_codename(text2), Some("noble".to_string()));
    }

    #[test]
    fn empty_version_codename_allows_ubuntu_fallback() {
        // If VERSION_CODENAME="" (rolling-release style) and
        // UBUNTU_CODENAME is set, use the fallback rather than giving
        // up entirely.
        let text = "VERSION_CODENAME=\"\"\nUBUNTU_CODENAME=devel\n";
        assert_eq!(parse_version_codename(text), Some("devel".to_string()));
    }

    // --- ID= parser (milestone 003 T010) -------------------------------

    #[test]
    fn id_rhel() {
        let text = "NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nVERSION_ID=\"9.4\"\n";
        assert_eq!(parse_id(text), Some("rhel".to_string()));
    }

    #[test]
    fn id_rocky() {
        let text = "NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"9.3\"\n";
        assert_eq!(parse_id(text), Some("rocky".to_string()));
    }

    #[test]
    fn id_fedora_bare() {
        let text = "NAME=Fedora\nID=fedora\nVERSION_ID=40\n";
        assert_eq!(parse_id(text), Some("fedora".to_string()));
    }

    #[test]
    fn id_amazon_linux() {
        // AL2023 and AL2 both ship ID="amzn".
        let text = "NAME=\"Amazon Linux\"\nID=\"amzn\"\nVERSION_ID=\"2023\"\n";
        assert_eq!(parse_id(text), Some("amzn".to_string()));
    }

    #[test]
    fn id_centos_stream() {
        let text = "NAME=\"CentOS Stream\"\nID=\"centos\"\nVERSION_ID=\"9\"\n";
        assert_eq!(parse_id(text), Some("centos".to_string()));
    }

    #[test]
    fn id_oracle_linux() {
        let text = "NAME=\"Oracle Linux Server\"\nID=\"ol\"\nVERSION_ID=\"9.4\"\n";
        assert_eq!(parse_id(text), Some("ol".to_string()));
    }

    #[test]
    fn id_almalinux() {
        let text = "NAME=\"AlmaLinux\"\nID=\"almalinux\"\nVERSION_ID=\"9.4\"\n";
        assert_eq!(parse_id(text), Some("almalinux".to_string()));
    }

    #[test]
    fn id_opensuse_leap() {
        // openSUSE uses a hyphenated ID — make sure we preserve it verbatim.
        let text = "NAME=\"openSUSE Leap\"\nID=\"opensuse-leap\"\nVERSION_ID=\"15.5\"\n";
        assert_eq!(parse_id(text), Some("opensuse-leap".to_string()));
    }

    #[test]
    fn id_sles() {
        let text = "NAME=\"SLES\"\nID=\"sles\"\nVERSION_ID=\"15.5\"\n";
        assert_eq!(parse_id(text), Some("sles".to_string()));
    }

    #[test]
    fn id_missing_returns_none() {
        let text = "NAME=ExoticDistro\nVERSION_ID=1.0\n";
        assert_eq!(parse_id(text), None);
    }

    #[test]
    fn id_empty_returns_none() {
        let text = "ID=\"\"\n";
        assert_eq!(parse_id(text), None);
    }

    #[test]
    fn id_reads_from_a_real_file_via_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("os-release");
        std::fs::write(&path, "ID=rocky\n").expect("write");
        assert_eq!(read_id(&path), Some("rocky".to_string()));
    }

    #[test]
    fn id_missing_file_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist");
        assert_eq!(read_id(&path), None);
    }

    #[test]
    fn id_does_not_match_version_id() {
        // VERSION_ID="9" should NOT satisfy the ID= lookup.
        let text = "VERSION_ID=\"9\"\n";
        assert_eq!(parse_id(text), None);
    }

    // --- rootfs-aware readers (conformance bug 1) ----------------------

    #[test]
    fn rootfs_reader_prefers_etc_os_release() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::fs::create_dir_all(rootfs.join("usr/lib")).unwrap();
        std::fs::write(rootfs.join("etc/os-release"), "ID=ubuntu\nVERSION_ID=24.04\n").unwrap();
        // Conflicting usr/lib/os-release — should be ignored because
        // /etc takes precedence per spec.
        std::fs::write(rootfs.join("usr/lib/os-release"), "ID=debian\nVERSION_ID=12\n").unwrap();
        assert_eq!(read_id_from_rootfs(rootfs), Some("ubuntu".to_string()));
        assert_eq!(read_version_id_from_rootfs(rootfs), Some("24.04".to_string()));
    }

    #[test]
    fn rootfs_reader_falls_back_to_usr_lib_when_etc_absent() {
        // Exact scenario from Ubuntu 24.04 images where /etc/os-release
        // is a symlink into /usr/lib/os-release and the symlink ends up
        // dangling after tar extraction: only the target file is
        // present. Before this fix, read_id returned None and the
        // caller fell back to "debian" namespace.
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();
        std::fs::create_dir_all(rootfs.join("usr/lib")).unwrap();
        std::fs::write(rootfs.join("usr/lib/os-release"), "ID=ubuntu\nVERSION_ID=24.04\n").unwrap();
        assert_eq!(read_id_from_rootfs(rootfs), Some("ubuntu".to_string()));
        assert_eq!(read_version_id_from_rootfs(rootfs), Some("24.04".to_string()));
    }

    #[test]
    fn rootfs_reader_returns_none_when_neither_path_present() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_id_from_rootfs(dir.path()), None);
        assert_eq!(read_version_id_from_rootfs(dir.path()), None);
    }

    #[test]
    fn rootfs_reader_follows_symlink_when_target_present() {
        // Happy-path: symlink is intact, target is present. The OS
        // resolves it for us via std::fs::read_to_string.
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::fs::create_dir_all(rootfs.join("usr/lib")).unwrap();
        std::fs::write(rootfs.join("usr/lib/os-release"), "ID=ubuntu\nVERSION_ID=24.04\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("../usr/lib/os-release", rootfs.join("etc/os-release")).unwrap();
        #[cfg(not(unix))]
        return;
        assert_eq!(read_id_from_rootfs(rootfs), Some("ubuntu".to_string()));
    }
}
