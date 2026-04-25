//! ELF binary parsing — `DT_NEEDED` dynamic-linkage extraction,
//! `.note.package` distro self-identification parsing (systemd
//! Packaging Metadata Notes format per research R4), and read-only
//! string-section extraction for the curated version-string scanner.
//!
//! Milestone 004 US2 tasks T027, T032, T033, T037.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Defense-in-depth cap on a single binary's size. 500 MB covers every
/// realistic server ELF while keeping memory-resident parsing bounded.
pub const MAX_BINARY_SIZE_BYTES: u64 = 500 * 1024 * 1024;

/// Minimum binary size worth parsing — anything smaller than 1 KB
/// is a shell script or a placeholder, not an ELF.
pub const MIN_BINARY_SIZE_BYTES: u64 = 1024;

/// Cap on concatenated read-only string-section bytes. Larger
/// `.rodata` gets truncated silently (the parent `BinaryFileComponent`
/// carries `mikebom:binary-parse-limit = "string-region-cap"` in that
/// case — plumbed by the caller).
/// Parsed `.note.package` payload (systemd FDO Packaging Metadata
/// Notes schema — research R4). Fields align with the published spec.
/// `os_cpe` is populated by serde from the JSON payload but not yet
/// consumed by mikebom code; preserved for spec fidelity.
#[allow(dead_code)]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ElfNotePackage {
    #[serde(rename = "type")]
    pub note_type: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub distro: Option<String>,
    #[serde(default, rename = "osCpe")]
    pub os_cpe: Option<String>,
}

/// Parse a `.note.package` section blob. Format (per spec):
///
/// ```text
///   namesz (4 bytes, LE) | descsz (4 bytes, LE) | type (4 bytes, LE)
///   name (padded to 4-byte alignment)  — typically "FDO\0"
///   desc (padded to 4-byte alignment)  — JSON payload
/// ```
fn parse_note_package(data: &[u8]) -> Option<ElfNotePackage> {
    if data.len() < 12 {
        return None;
    }
    let namesz = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let descsz = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
    let _ntype = u32::from_le_bytes(data[8..12].try_into().ok()?);

    let name_start = 12;
    let name_end = name_start + namesz;
    if name_end > data.len() {
        return None;
    }

    // Align to 4 bytes for desc start.
    let desc_start = (name_end + 3) & !3;
    let desc_end = desc_start + descsz;
    if desc_end > data.len() {
        return None;
    }

    let desc = &data[desc_start..desc_end];
    // Trim any trailing NUL padding.
    let desc_trimmed_end = desc
        .iter()
        .rposition(|b| *b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    serde_json::from_slice::<ElfNotePackage>(&desc[..desc_trimmed_end]).ok()
}

/// Public wrapper around the internal note-package parser so
/// `binary/mod.rs`'s cross-format dispatcher can call it without
/// exposing the private parser name.
pub fn parse_note_package_public(data: &[u8]) -> Option<ElfNotePackage> {
    parse_note_package(data)
}

/// Produce the parent-binary path for `evidence.occurrences[]` —
/// purposely absolute so cross-scan diffs are stable.
#[allow(dead_code)]
pub fn absolute_path(rootfs: &Path, rel: &Path) -> PathBuf {
    if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        rootfs.join(rel)
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn parse_note_package_minimal() {
        // Construct a .note.package payload:
        //   name = "FDO\0" (4 bytes, namesz=4)
        //   desc = '{"type":"rpm","name":"curl","version":"8.2.1","distro":"Fedora"}'
        let payload = br#"{"type":"rpm","name":"curl","version":"8.2.1","distro":"Fedora","architecture":"x86_64"}"#;
        let name = b"FDO\0";
        let descsz = payload.len() as u32;
        let namesz = name.len() as u32;
        let mut note = Vec::new();
        note.extend_from_slice(&namesz.to_le_bytes());
        note.extend_from_slice(&descsz.to_le_bytes());
        note.extend_from_slice(&0xcafe_1a7e_u32.to_le_bytes()); // type
        note.extend_from_slice(name);
        // name already 4-byte aligned — no padding needed
        note.extend_from_slice(payload);
        // pad desc to 4-byte boundary
        while note.len() % 4 != 0 {
            note.push(0);
        }

        let parsed = parse_note_package(&note).unwrap();
        assert_eq!(parsed.note_type, "rpm");
        assert_eq!(parsed.name, "curl");
        assert_eq!(parsed.version, "8.2.1");
        assert_eq!(parsed.distro.as_deref(), Some("Fedora"));
        assert_eq!(parsed.architecture.as_deref(), Some("x86_64"));
    }

    #[test]
    fn parse_note_package_missing_required_field_returns_none() {
        // Payload missing "version".
        let payload = br#"{"type":"rpm","name":"curl"}"#;
        let name = b"FDO\0";
        let mut note = Vec::new();
        note.extend_from_slice(&(name.len() as u32).to_le_bytes());
        note.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        note.extend_from_slice(&0u32.to_le_bytes());
        note.extend_from_slice(name);
        note.extend_from_slice(payload);
        while note.len() % 4 != 0 {
            note.push(0);
        }
        assert!(parse_note_package(&note).is_none());
    }

    #[test]
    fn parse_note_package_alpm_variant() {
        let payload =
            br#"{"type":"alpm","name":"bash","version":"5.2.015-1","distro":"Arch Linux"}"#;
        let name = b"FDO\0";
        let mut note = Vec::new();
        note.extend_from_slice(&(name.len() as u32).to_le_bytes());
        note.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        note.extend_from_slice(&0u32.to_le_bytes());
        note.extend_from_slice(name);
        note.extend_from_slice(payload);
        while note.len() % 4 != 0 {
            note.push(0);
        }
        let parsed = parse_note_package(&note).unwrap();
        assert_eq!(parsed.note_type, "alpm");
        assert_eq!(parsed.name, "bash");
        assert_eq!(parsed.distro.as_deref(), Some("Arch Linux"));
    }

    #[test]
    fn parse_note_package_truncated_returns_none() {
        // Header promises 100 bytes of desc; only 4 available.
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes());
        note.extend_from_slice(&100u32.to_le_bytes());
        note.extend_from_slice(&0u32.to_le_bytes());
        note.extend_from_slice(b"FDO\0");
        note.extend_from_slice(b"x\0\0\0");
        assert!(parse_note_package(&note).is_none());
    }
}
