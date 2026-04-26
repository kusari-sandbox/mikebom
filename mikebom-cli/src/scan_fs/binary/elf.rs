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

/// `.gnu_debuglink` section payload — a filename pointing at a
/// stripped-debug sibling file plus a CRC32 of that target's contents.
/// See the binutils manual section "MiscOptions" for the layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebuglinkEntry {
    /// NUL-terminated filename (typically `<basename>.debug`).
    pub file: String,
    /// Little-endian CRC32 of the referenced .debug file's contents.
    pub crc32: u32,
}

/// Parse a `.note.gnu.build-id` section blob. Same wire-format as
/// `.note.package` (namesz/descsz/type/name/desc), but the desc
/// payload is the raw build-id bytes — typically 20 bytes of SHA-1
/// (the gcc/clang default), rarely 16 bytes of MD5.
///
/// Returns the build-id as lowercase hex. None on parse failure or
/// empty desc (binary built with `-Wl,--build-id=none`).
#[allow(dead_code)]
pub fn parse_gnu_build_id(data: &[u8]) -> Option<String> {
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

    // Align desc start to a 4-byte boundary (note format requirement).
    let desc_start = (name_end + 3) & !3;
    let desc_end = desc_start + descsz;
    if desc_end > data.len() || descsz == 0 {
        return None;
    }

    let mut hex = String::with_capacity(descsz * 2);
    for byte in &data[desc_start..desc_end] {
        // SAFETY: writing hex to a String can't fail.
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", byte);
    }
    Some(hex)
}

/// Parse a `.gnu_debuglink` section blob. Layout:
///
/// ```text
///   filename (NUL-terminated)
///   0–3 bytes of NUL padding to a 4-byte boundary
///   crc32 (4 bytes, little-endian)
/// ```
///
/// Returns None on absent NUL terminator, non-UTF-8 filename, or
/// truncated CRC32.
#[allow(dead_code)]
pub fn parse_debuglink(data: &[u8]) -> Option<DebuglinkEntry> {
    let nul_pos = data.iter().position(|&b| b == 0)?;
    let file = std::str::from_utf8(&data[..nul_pos]).ok()?.to_string();
    let after_nul = nul_pos + 1;
    // Align to a 4-byte boundary for the CRC32.
    let crc_start = (after_nul + 3) & !3;
    if crc_start + 4 > data.len() {
        return None;
    }
    let crc32 = u32::from_le_bytes(data[crc_start..crc_start + 4].try_into().ok()?);
    Some(DebuglinkEntry { file, crc32 })
}

/// Walk the `.dynamic` section's `Dyn` entries and collect every
/// path string referenced by a `DT_RPATH` (0x0F) or `DT_RUNPATH`
/// (0x1D) entry. Each Dyn's `d_val` is an offset into `.dynstr`;
/// the resolved string is `:`-separated path list per the dynamic
/// loader convention.
///
/// Word size + endianness must be supplied by the caller (decoded
/// from the ELF file header's `e_ident[EI_CLASS]` byte and
/// `e_ident[EI_DATA]` byte respectively). Stops at `DT_NULL` (0)
/// per the dynamic-array termination rule.
///
/// Returns deduplicated paths preserving discovery order. Does NOT
/// expand `$ORIGIN`, `$LIB`, `$PLATFORM` — those substitutions are
/// runtime-context-dependent and are recorded raw per spec
/// clarification.
#[allow(dead_code)]
pub fn extract_runpath_entries(
    dynamic: &[u8],
    dynstr: &[u8],
    is_64bit: bool,
    little_endian: bool,
) -> Vec<String> {
    const DT_NULL: u64 = 0;
    const DT_RPATH: u64 = 15;
    const DT_RUNPATH: u64 = 29;

    let entry_size = if is_64bit { 16 } else { 8 };
    let mut paths: Vec<String> = Vec::new();

    for chunk in dynamic.chunks_exact(entry_size) {
        let (d_tag, d_val): (u64, u64) = if is_64bit {
            let Ok(tag_b): Result<[u8; 8], _> = chunk[0..8].try_into() else {
                continue;
            };
            let Ok(val_b): Result<[u8; 8], _> = chunk[8..16].try_into() else {
                continue;
            };
            if little_endian {
                (u64::from_le_bytes(tag_b), u64::from_le_bytes(val_b))
            } else {
                (u64::from_be_bytes(tag_b), u64::from_be_bytes(val_b))
            }
        } else {
            let Ok(tag_b): Result<[u8; 4], _> = chunk[0..4].try_into() else {
                continue;
            };
            let Ok(val_b): Result<[u8; 4], _> = chunk[4..8].try_into() else {
                continue;
            };
            let (t, v) = if little_endian {
                (u32::from_le_bytes(tag_b), u32::from_le_bytes(val_b))
            } else {
                (u32::from_be_bytes(tag_b), u32::from_be_bytes(val_b))
            };
            (t as u64, v as u64)
        };

        if d_tag == DT_NULL {
            break;
        }
        if d_tag != DT_RPATH && d_tag != DT_RUNPATH {
            continue;
        }

        let offset = d_val as usize;
        if offset >= dynstr.len() {
            continue;
        }
        let end = dynstr[offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| offset + p)
            .unwrap_or(dynstr.len());
        let path_str = match std::str::from_utf8(&dynstr[offset..end]) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for path in path_str.split(':') {
            let trimmed = path.trim();
            if !trimmed.is_empty() && !paths.iter().any(|p| p == trimmed) {
                paths.push(trimmed.to_string());
            }
        }
    }
    paths
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

    /// Helper: build a `.note.gnu.build-id` section blob with the given
    /// description bytes. namesz=4 ("GNU\0"), type=NT_GNU_BUILD_ID (3).
    fn build_gnu_build_id_note(desc: &[u8]) -> Vec<u8> {
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes()); // namesz
        note.extend_from_slice(&(desc.len() as u32).to_le_bytes()); // descsz
        note.extend_from_slice(&3u32.to_le_bytes()); // NT_GNU_BUILD_ID
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(desc);
        // Pad desc to 4-byte boundary (caller-side expectation).
        while note.len() % 4 != 0 {
            note.push(0);
        }
        note
    }

    #[test]
    fn parse_gnu_build_id_sha1() {
        // 20-byte SHA-1 build-id (gcc/clang default).
        let desc = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x02, 0x03, 0x04,
        ];
        let note = build_gnu_build_id_note(&desc);
        assert_eq!(
            parse_gnu_build_id(&note).as_deref(),
            Some("00112233445566778899aabbccddeeff01020304"),
        );
    }

    #[test]
    fn parse_gnu_build_id_md5() {
        // 16-byte MD5 build-id (rare but spec-allowed).
        let desc = [
            0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0,
        ];
        let note = build_gnu_build_id_note(&desc);
        assert_eq!(
            parse_gnu_build_id(&note).as_deref(),
            Some("deadbeeffeedface123456789abcdef0"),
        );
    }

    #[test]
    fn parse_gnu_build_id_empty_desc_returns_none() {
        // build-id=none yields a note with descsz=0 — treat as absent.
        let note = build_gnu_build_id_note(&[]);
        assert!(parse_gnu_build_id(&note).is_none());
    }

    #[test]
    fn parse_gnu_build_id_truncated_returns_none() {
        // Header claims 20 bytes of desc; only 4 supplied.
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes());
        note.extend_from_slice(&20u32.to_le_bytes());
        note.extend_from_slice(&3u32.to_le_bytes());
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(parse_gnu_build_id(&note).is_none());
    }

    #[test]
    fn parse_debuglink_full() {
        // Filename "foo.debug" (9 bytes + NUL = 10), pad to 12, then
        // CRC32 = 0xdeadbeef.
        let mut data = Vec::new();
        data.extend_from_slice(b"foo.debug\0");
        // Pad to 4-byte boundary (10 → 12).
        data.extend_from_slice(&[0u8, 0u8]);
        data.extend_from_slice(&0xdeadbeef_u32.to_le_bytes());
        let entry = parse_debuglink(&data).unwrap();
        assert_eq!(entry.file, "foo.debug");
        assert_eq!(entry.crc32, 0xdeadbeef);
    }

    #[test]
    fn parse_debuglink_no_padding_needed() {
        // Filename "abc\0" is exactly 4 bytes — no padding before CRC.
        let mut data = Vec::new();
        data.extend_from_slice(b"abc\0");
        data.extend_from_slice(&0x12345678_u32.to_le_bytes());
        let entry = parse_debuglink(&data).unwrap();
        assert_eq!(entry.file, "abc");
        assert_eq!(entry.crc32, 0x12345678);
    }

    #[test]
    fn parse_debuglink_missing_nul_returns_none() {
        let data = b"no-nul-here";
        assert!(parse_debuglink(data).is_none());
    }

    #[test]
    fn parse_debuglink_truncated_crc_returns_none() {
        let mut data = Vec::new();
        data.extend_from_slice(b"foo\0");
        data.extend_from_slice(&[0u8, 0u8]); // only 2 bytes of CRC, not 4
        assert!(parse_debuglink(&data).is_none());
    }

    /// Helper: build a 64-bit little-endian Dyn array. Each entry is
    /// 16 bytes (d_tag i64 LE + d_val u64 LE).
    fn build_dyn64_le(entries: &[(u64, u64)]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(tag, val) in entries {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out
    }

    #[test]
    fn extract_runpath_entries_single_runpath() {
        // dynstr layout: NUL @ 0 (sentinel empty string), then
        // "$ORIGIN/../lib:/opt/vendor/lib\0" starting at offset 1.
        let mut dynstr = vec![0u8];
        let path = b"$ORIGIN/../lib:/opt/vendor/lib\0";
        let path_offset = dynstr.len() as u64;
        dynstr.extend_from_slice(path);

        let dynamic = build_dyn64_le(&[
            (29, path_offset), // DT_RUNPATH
            (0, 0),            // DT_NULL
        ]);

        let paths = extract_runpath_entries(&dynamic, &dynstr, true, true);
        assert_eq!(
            paths,
            vec![
                "$ORIGIN/../lib".to_string(),
                "/opt/vendor/lib".to_string(),
            ]
        );
    }

    #[test]
    fn extract_runpath_entries_dedupes_across_rpath_and_runpath() {
        // Both DT_RPATH and DT_RUNPATH point at the same path.
        let mut dynstr = vec![0u8];
        let path = b"/usr/local/lib\0";
        let path_offset = dynstr.len() as u64;
        dynstr.extend_from_slice(path);

        let dynamic = build_dyn64_le(&[
            (15, path_offset), // DT_RPATH
            (29, path_offset), // DT_RUNPATH
            (0, 0),
        ]);

        let paths = extract_runpath_entries(&dynamic, &dynstr, true, true);
        assert_eq!(paths, vec!["/usr/local/lib".to_string()]);
    }

    #[test]
    fn extract_runpath_entries_no_rpath_returns_empty() {
        // Only DT_NEEDED (1) entries — no RPATH/RUNPATH.
        let mut dynstr = vec![0u8];
        let path = b"libc.so.6\0";
        let path_offset = dynstr.len() as u64;
        dynstr.extend_from_slice(path);

        let dynamic = build_dyn64_le(&[
            (1, path_offset), // DT_NEEDED
            (0, 0),
        ]);

        let paths = extract_runpath_entries(&dynamic, &dynstr, true, true);
        assert!(paths.is_empty());
    }

    #[test]
    fn extract_runpath_entries_stops_at_dt_null() {
        // Two RPATH entries — the second is after a DT_NULL sentinel
        // and should NOT be observed (matches loader behavior).
        let mut dynstr = vec![0u8];
        let p1 = b"/first\0";
        let off1 = dynstr.len() as u64;
        dynstr.extend_from_slice(p1);
        let p2 = b"/second\0";
        let off2 = dynstr.len() as u64;
        dynstr.extend_from_slice(p2);

        let dynamic = build_dyn64_le(&[
            (15, off1), // DT_RPATH
            (0, 0),     // DT_NULL — array terminates here
            (15, off2), // DT_RPATH (after null — should be ignored)
        ]);

        let paths = extract_runpath_entries(&dynamic, &dynstr, true, true);
        assert_eq!(paths, vec!["/first".to_string()]);
    }

    #[test]
    fn extract_runpath_entries_32bit_be() {
        // 32-bit big-endian — least-common combo, exercises the
        // alternate decode path.
        let mut dynstr = vec![0u8];
        let path = b"/be/path\0";
        let path_offset = dynstr.len() as u32;
        dynstr.extend_from_slice(path);

        let mut dynamic = Vec::new();
        // d_tag = DT_RUNPATH (29), d_val = path_offset; both BE u32.
        dynamic.extend_from_slice(&29u32.to_be_bytes());
        dynamic.extend_from_slice(&path_offset.to_be_bytes());
        // DT_NULL terminator.
        dynamic.extend_from_slice(&0u32.to_be_bytes());
        dynamic.extend_from_slice(&0u32.to_be_bytes());

        let paths = extract_runpath_entries(&dynamic, &dynstr, false, false);
        assert_eq!(paths, vec!["/be/path".to_string()]);
    }
}
