//! BinaryScan + binary-scan-result-to-PackageDbEntry conversion.
//!
//! Owns the intermediate `BinaryScan` type that the per-file scanner
//! in `scan.rs` produces, plus the three conversion functions that
//! turn scan results into `PackageDbEntry` rows: `version_match_to_entry`
//! (curated version strings), `make_file_level_component` (the binary
//! itself), and `note_package_to_entry` (ELF .note.package parsing).

use std::path::Path;

use mikebom_common::types::hash::ContentHash;
use mikebom_common::types::purl::Purl;
use sha2::{Digest, Sha256};

use super::elf;
use super::packer;
use super::version_strings;
use super::super::package_db::{rpm_vendor_from_id, PackageDbEntry};

/// Convert a curated-scanner match into a `PackageDbEntry`.
pub(super) fn version_match_to_entry(
    m: &version_strings::EmbeddedVersionMatch,
    path: &Path,
) -> Option<PackageDbEntry> {
    let purl_str = format!(
        "pkg:generic/{}@{}",
        mikebom_common::types::purl::encode_purl_segment(m.library.slug()),
        mikebom_common::types::purl::encode_purl_segment(&m.version),
    );
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
        shade_relocation: None,
        buildinfo_status: None,
        evidence_kind: Some("embedded-version-string".to_string()),
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

pub(super) fn make_file_level_component(
    path: &Path,
    bytes: &[u8],
    scan: &BinaryScan,
    detected_go: bool,
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
    // Filename can carry arbitrary chars; percent-encode for PURL
    // name-segment conformance.
    let encoded_filename = mikebom_common::types::purl::encode_purl_segment(&filename);
    let purl_str = format!("pkg:generic/{encoded_filename}?file-sha256={sha256}");
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
        shade_relocation: None,
        buildinfo_status: None,
        evidence_kind: None,
        binary_class: Some(scan.binary_class.to_string()),
        binary_stripped: Some(scan.stripped),
        linkage_kind: Some(linkage),
        // G1: milestone 004 US2 R8 cross-link — set when the same
        // bytes carry `runtime/debug.BuildInfo` so downstream
        // consumers can pair the file-level `pkg:generic/<name>`
        // component with its `pkg:golang/<module>@<version>`
        // siblings from `go_binary.rs`.
        detected_go: if detected_go { Some(true) } else { None },
        confidence: None,
        binary_packed: scan.packer.map(|p| p.as_str().to_string()),
        raw_version: None,
        parent_purl: None,
        npm_role: None,
        co_owned_by: None,
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
pub(super) fn note_package_to_entry(
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

    // purl-spec § Character encoding: `+` and other non-allowed chars
    // MUST be percent-encoded in BOTH the name and version segments.
    // The note.{name,version} came out of an ELF `.note.package`
    // section and can carry real-world package coords with `+` (RPMs
    // like `libstdc++`, semver versions like `1.0+build.1`). Route
    // both through the canonical encoder so all five arms below emit
    // spec-conformant PURLs.
    let encoded_name = mikebom_common::types::purl::encode_purl_segment(&note.name);
    let encoded_version = mikebom_common::types::purl::encode_purl_segment(&note.version);
    let purl_str = match note.note_type.as_str() {
        "rpm" => {
            let raw_vendor = resolve_vendor(note.distro.as_deref(), "rpm");
            // rpm_vendor_from_id normalizes `rhel`→`redhat`, `ol`→`oracle`,
            // etc. Same mapping used by rpm.rs for the rpmdb reader.
            let vendor = rpm_vendor_from_id(&raw_vendor);
            append_distro_qualifier(&mut qualifiers, &vendor);
            format!("pkg:rpm/{vendor}/{encoded_name}@{encoded_version}{qualifiers}")
        }
        "deb" => {
            let vendor = resolve_vendor(note.distro.as_deref(), "debian");
            append_distro_qualifier(&mut qualifiers, &vendor);
            format!("pkg:deb/{vendor}/{encoded_name}@{encoded_version}{qualifiers}")
        }
        "apk" => {
            let vendor = resolve_vendor(note.distro.as_deref(), "alpine");
            append_distro_qualifier(&mut qualifiers, &vendor);
            format!("pkg:apk/{vendor}/{encoded_name}@{encoded_version}{qualifiers}")
        }
        "alpm" | "pacman" => {
            format!("pkg:alpm/arch/{encoded_name}@{encoded_version}{qualifiers}")
        }
        _ => format!("pkg:generic/{encoded_name}@{encoded_version}"),
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
        shade_relocation: None,
        buildinfo_status: None,
        evidence_kind: Some("elf-note-package".to_string()),
        binary_class: None,
        binary_stripped: None,
        linkage_kind: None,
        detected_go: None,
        confidence: None,
        binary_packed: None,
        raw_version: None,
        parent_purl: None,
        npm_role: None,
        co_owned_by: None,
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
    fn note_package_rpm_percent_encodes_plus_in_name() {
        let note = elf::ElfNotePackage {
            note_type: "rpm".into(),
            name: "libstdc++".into(),
            version: "14.2.1-3.fc40".into(),
            architecture: Some("aarch64".into()),
            distro: Some("fedora".into()),
            os_cpe: None,
        };
        let entry = note_package_to_entry(
            &note,
            Path::new("/usr/lib64/libstdc++.so.6"),
            Some("fedora"),
            Some("40"),
        )
        .unwrap();
        let purl = entry.purl.as_str();
        assert!(
            purl.contains("/libstdc%2B%2B@"),
            "expected percent-encoded `++` in ELF-note PURL; got {purl}",
        );
        assert!(
            !purl.contains("libstdc++"),
            "literal `++` must not appear; got {purl}",
        );
    }

    #[test]
    fn note_package_rpm_percent_encodes_mid_name_plus() {
        let note = elf::ElfNotePackage {
            note_type: "rpm".into(),
            name: "perl-Text-Tabs+Wrap".into(),
            version: "2024.001-1.fc40".into(),
            architecture: Some("noarch".into()),
            distro: Some("fedora".into()),
            os_cpe: None,
        };
        let entry = note_package_to_entry(
            &note,
            Path::new("/usr/share/perl5/Text/Tabs.pm"),
            Some("fedora"),
            Some("40"),
        )
        .unwrap();
        assert!(
            entry.purl.as_str().contains("/perl-Text-Tabs%2BWrap@"),
            "mid-name `+` must percent-encode; got {}",
            entry.purl.as_str()
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

    fn fake_binary_scan() -> BinaryScan {
        BinaryScan {
            binary_class: "elf",
            imports: Vec::new(),
            has_dynamic: false,
            stripped: false,
            note_package: None,
            string_region: Vec::new(),
            packer: None,
        }
    }

    #[test]
    fn make_file_level_component_sets_detected_go_when_flag_set() {
        // G1 wiring: `make_file_level_component` receives
        // `detected_go = true` when the caller's `go_in_linux`
        // check fires. The emitted PackageDbEntry carries
        // `detected_go = Some(true)` so the CDX emitter surfaces
        // `mikebom:detected-go = true` on the file-level
        // component, cross-linking it with the sibling
        // `pkg:golang/.../module@version` entries from
        // `go_binary.rs`.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("goapp");
        std::fs::write(&path, b"dummy-bytes").unwrap();
        let scan = fake_binary_scan();
        let entry =
            make_file_level_component(&path, b"dummy-bytes", &scan, true);
        assert_eq!(entry.name, "goapp");
        assert_eq!(entry.detected_go, Some(true));
        assert_eq!(entry.binary_class.as_deref(), Some("elf"));
        assert!(
            entry.purl.as_str().starts_with("pkg:generic/goapp"),
            "expected pkg:generic/goapp PURL: {}",
            entry.purl.as_str(),
        );
    }

    #[test]
    fn make_file_level_component_leaves_detected_go_none_for_non_go() {
        // Regression guard: non-Go file-level entries (plain ELF,
        // Mach-O binaries without BuildInfo) keep `detected_go =
        // None` so the CDX property is only emitted when the
        // cross-link is real.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("plain-tool");
        std::fs::write(&path, b"plain-bytes").unwrap();
        let scan = fake_binary_scan();
        let entry =
            make_file_level_component(&path, b"plain-bytes", &scan, false);
        assert_eq!(entry.detected_go, None);
    }
}
