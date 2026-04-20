//! Shared `/etc/os-release` reader.
//!
//! Two call sites want the distro codename: the build-time attestation
//! builder (which reads the trace host's own os-release via the fixed
//! path `/etc/os-release`), and the scan pipeline (which reads it out
//! of an extracted container image rootfs or a --path root). Same
//! parsing rules in both cases — one small helper in one place.

use std::path::Path;

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
}
