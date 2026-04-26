//! Single-file binary scanner — ELF / Mach-O / fat-Mach-O / PE.
//!
//! Reads the file bytes, identifies the format via the `object` crate,
//! and produces a `BinaryScan` (defined in `entry.rs`) holding the
//! cross-format common fields plus ELF-specific note-package data.

use std::path::Path;

use object::ObjectSection;

use super::elf;
use super::entry::BinaryScan;
use super::packer;

/// Quick probe: does this ELF carry Go BuildInfo? Used by the Linux-
/// rootfs Go-suppression rule — when Go BuildInfo succeeds, the Go
/// modules emitted by `package_db::go_binary` carry the container
/// content; the file-level binary component is redundant noise.
///
/// Lightweight byte-scan for the BuildInfo magic prefix `\xff Go buildinf:`
/// — avoids re-parsing the binary. Same magic the `go_binary` reader
/// looks for (source: Go stdlib `debug/buildinfo`).
pub(super) fn is_go_binary(bytes: &[u8]) -> bool {
    // Scan the first 64 MB — BuildInfo lives in the `.go.buildinfo`
    // section, which the Go linker places AFTER the text/data
    // sections. Real-world offsets commonly exceed the old 2 MB
    // probe cap: a 6 MB Go binary puts BuildInfo around 3.9 MB; a
    // larger service binary can push it past 10 MB. 64 MB covers
    // virtually all Go binaries while keeping bounded worst-case
    // cost on pathological non-Go files. The probe is a
    // `windows().any()` scan which modern rustc/LLVM optimizes
    // aggressively — measurable cost on a 64 MB file is tens of
    // milliseconds, acceptable for the correctness win.
    //
    // For comparison, `go_binary.rs::detect_is_go` first does a
    // section-name lookup via the object crate (fast, precise), then
    // falls back to memmem over the entire file (up to 500 MB). This
    // cheaper byte-scan covers the common case without pulling in
    // ELF parsing here.
    const PROBE: usize = 64 * 1024 * 1024;
    let end = bytes.len().min(PROBE);
    bytes[..end]
        .windows(14)
        .any(|w| w == b"\xff Go buildinf:")
}


pub(super) fn scan_binary(path: &Path, bytes: &[u8]) -> Option<BinaryScan> {
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

    // Milestone 023 — three more ELF identity signals (NT_GNU_BUILD_ID,
    // DT_RPATH/DT_RUNPATH, .gnu_debuglink) using the same byte-slice
    // contract as parse_note_package_public. Non-ELF leaves all three
    // at their default values.
    let (build_id, runpath, debuglink) = if class == "elf" {
        let build_id = file
            .section_by_name_bytes(b".note.gnu.build-id")
            .and_then(|s| s.data().ok())
            .and_then(elf::parse_gnu_build_id);
        let debuglink = file
            .section_by_name_bytes(b".gnu_debuglink")
            .and_then(|s| s.data().ok())
            .and_then(elf::parse_debuglink);
        let runpath = match (
            file.section_by_name_bytes(b".dynamic").and_then(|s| s.data().ok()),
            file.section_by_name_bytes(b".dynstr").and_then(|s| s.data().ok()),
        ) {
            (Some(dynamic), Some(dynstr)) => {
                // Detect ELF class + endianness from the file header's
                // e_ident bytes (offsets 4 and 5). Both are bounds-
                // checked here defensively; `object::read::File::parse`
                // succeeded above so the bytes are present, but the
                // upstream contract isn't carried in the type system.
                let is_64bit = bytes.get(4).copied() == Some(2);
                let little_endian = bytes.get(5).copied() != Some(2);
                elf::extract_runpath_entries(dynamic, dynstr, is_64bit, little_endian)
            }
            _ => Vec::new(),
        };
        (build_id, runpath, debuglink)
    } else {
        (None, Vec::new(), None)
    };

    // Milestone 024 — Mach-O identity signals (LC_UUID, LC_RPATH,
    // min-OS version) extracted via byte-level parsers in macho.rs.
    // ELF / PE leave all three at default values. Note: this is the
    // non-fat path; the fat-Mach-O path (`scan_fat_macho` below) calls
    // the same parsers against the first slice's bytes.
    let (macho_uuid, macho_rpath, macho_min_os) = if class == "macho" {
        (
            super::macho::parse_lc_uuid(bytes),
            super::macho::parse_lc_rpath(bytes),
            super::macho::parse_min_os_version(bytes),
        )
    } else {
        (None, Vec::new(), None)
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
        build_id,
        runpath,
        debuglink,
        macho_uuid,
        macho_rpath,
        macho_min_os,
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

    // Milestone 024 — fat Mach-O identity: use the first slice's bytes
    // for LC_UUID / LC_RPATH / min-OS. Per spec edge case "fat-slice UUID
    // divergence", arch-specific UUIDs are intentionally collapsed to the
    // first slice; consumers needing per-slice identity should fall back
    // to `otool -l <slice>`.
    let first_slice = slice_datas.first().copied().unwrap_or(&[][..]);
    let macho_uuid = super::macho::parse_lc_uuid(first_slice);
    let macho_rpath = super::macho::parse_lc_rpath(first_slice);
    let macho_min_os = super::macho::parse_min_os_version(first_slice);

    Some(BinaryScan {
        binary_class: "macho",
        imports,
        has_dynamic,
        stripped,
        note_package: None, // Mach-O doesn't carry .note.package
        build_id: None,     // milestone 023 — ELF-only fields stay default
        runpath: Vec::new(),
        debuglink: None,
        macho_uuid,
        macho_rpath,
        macho_min_os,
        string_region,
        packer: packer::detect(bytes),
    })
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

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
    fn is_go_binary_detects_magic_past_old_2mb_cap() {
        // Regression guard: the old 2 MB probe window missed real
        // Go binaries where BuildInfo lives past that offset
        // (common for Go binaries ≥5 MB). Probe cap is now 64 MB.
        let mut bytes = vec![0u8; 5 * 1024 * 1024];
        bytes[3_900_000..3_900_014].copy_from_slice(b"\xff Go buildinf:");
        assert!(is_go_binary(&bytes));
    }

    #[test]
    fn is_go_binary_bounded_probe_at_64mb() {
        // Magic past the 64 MB probe window should NOT match —
        // defense against scanning huge non-Go files completely.
        // 64 MB = 67,108,864 bytes; place magic at 68 MB so it's
        // clearly outside the window.
        let mut bytes = vec![0u8; 70 * 1024 * 1024];
        bytes[68 * 1024 * 1024..68 * 1024 * 1024 + 14]
            .copy_from_slice(b"\xff Go buildinf:");
        assert!(!is_go_binary(&bytes));
    }
}

