//! ELF binary parsing — `DT_NEEDED` dynamic-linkage extraction,
//! `.note.package` distro self-identification parsing (systemd
//! Packaging Metadata Notes format per research R4), and read-only
//! string-section extraction for the curated version-string scanner.
//!
//! Milestone 004 US2 tasks T027, T032, T033, T037.

use std::path::{Path, PathBuf};

use object::{Object, ObjectSection};
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
pub const MAX_STRING_REGION_BYTES: usize = 16 * 1024 * 1024;

/// Output of a successful ELF scan. Mirrors `ElfBinary` in
/// `data-model.md` but trims fields we don't yet use to keep the
/// surface manageable.
#[derive(Clone, Debug, Default)]
pub struct ElfScan {
    /// `DT_NEEDED` entries, soname strings. Deduped within this binary
    /// (cross-binary dedup happens in `linkage.rs`).
    pub needed: Vec<String>,
    /// Systemd `.note.package` payload, when present and parseable.
    pub note_package: Option<ElfNotePackage>,
    /// Concatenated bytes of `.rodata` + `.data.rel.ro` (capped at
    /// `MAX_STRING_REGION_BYTES`). Fed to the curated version-string
    /// scanner.
    pub string_region: Vec<u8>,
    /// True when `.symtab` / `.dynsym` AND `.note.package` are both
    /// absent — intrinsic "stripped" signal for the file-level
    /// component.
    pub stripped: bool,
    /// True when ANY loadable PT_DYNAMIC segment is present. Drives
    /// the `linkage_kind = "dynamic"` vs `"static"` decision.
    pub has_dynamic: bool,
}

/// Parsed `.note.package` payload (systemd FDO Packaging Metadata
/// Notes schema — research R4). Fields align with the published spec.
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

/// Parse an ELF binary from bytes. Returns `None` if the input isn't
/// an ELF or parsing fails in a way that prevents useful output. Never
/// panics — all errors are swallowed into `None` with a WARN log.
pub fn parse(path: &Path, bytes: &[u8]) -> Option<ElfScan> {
    let file = match object::read::File::parse(bytes) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "skipping ELF parse");
            return None;
        }
    };
    if !matches!(file.format(), object::BinaryFormat::Elf) {
        return None;
    }

    let mut out = ElfScan::default();

    // `.dynamic` section presence is the authoritative signal that
    // this is a dynamically-linked ELF.
    out.has_dynamic = file.section_by_name(".dynamic").is_some();

    // Extract DT_NEEDED via object's `imports()` API.
    out.needed = extract_dt_needed(&file);

    // Extract .note.package JSON payload.
    if let Some(section) = file.section_by_name(".note.package") {
        if let Ok(data) = section.data() {
            out.note_package = parse_note_package(data);
        }
    }

    // Extract read-only string region (`.rodata` + `.data.rel.ro`).
    for name in [".rodata", ".data.rel.ro"] {
        if let Some(section) = file.section_by_name(name) {
            if let Ok(data) = section.data() {
                let room = MAX_STRING_REGION_BYTES.saturating_sub(out.string_region.len());
                let take = data.len().min(room);
                out.string_region.extend_from_slice(&data[..take]);
                if take < data.len() {
                    break; // cap hit — don't keep reading
                }
            }
        }
    }

    // Stripped = no symbol tables AND no .note.package to identify
    // the file. This is the "we have no evidence" flag per FR-027.
    let has_symtab = file.section_by_name(".symtab").is_some()
        || file.section_by_name(".dynsym").is_some();
    out.stripped = !has_symtab && out.note_package.is_none();

    Some(out)
}

/// Extract `DT_NEEDED` entries via `object::read::File::imports()`.
/// For ELF, `import.library()` is the soname (e.g. `libc.so.6`). We
/// dedupe within this binary by string — cross-binary dedup happens
/// in `linkage.rs`. Returns `None` on failure; caller treats as empty.
fn extract_dt_needed(file: &object::read::File<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let imports = match file.imports() {
        Ok(i) => i,
        Err(e) => {
            tracing::debug!(error = %e, "ELF imports() failed; treating as empty");
            return out;
        }
    };
    for imp in imports {
        let lib = imp.library();
        if lib.is_empty() {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(lib) {
            if seen.insert(s.to_string()) {
                out.push(s.to_string());
            }
        }
    }
    out
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

    #[test]
    fn parse_non_elf_returns_none() {
        let bytes = b"this is not an ELF binary, just text";
        assert!(parse(Path::new("/tmp/notelf"), bytes).is_none());
    }
}
