//! PE binary identity parsers — CodeView pdb-id, IMAGE_FILE_HEADER
//! machine type, and IMAGE_OPTIONAL_HEADER subsystem (milestone 028).
//!
//! Completes the binary-identity trifecta started by milestones 023
//! (ELF NT_GNU_BUILD_ID + DT_RPATH/RUNPATH + .gnu_debuglink) and 024
//! (Mach-O LC_UUID + LC_RPATH + min-OS). Three signals:
//!
//! - **PDB-id (CodeView GUID + Age)**: the canonical PE binary
//!   identity, analog of NT_GNU_BUILD_ID / LC_UUID. Microsoft
//!   toolchains write a CodeView Type-2 record into the
//!   `IMAGE_DIRECTORY_ENTRY_DEBUG` directory carrying a 16-byte GUID
//!   plus a u32 Age plus the original PDB filename. The pair
//!   `<guid-hex>:<age>` is what symbol servers (Microsoft Symbol
//!   Server, Mozilla / Chromium symbol stores), WinDbg, drmingw,
//!   and crash-dump analyzers use to locate matching `.pdb` files.
//! - **Machine type**: IMAGE_FILE_HEADER.Machine — the binary's
//!   target architecture (`amd64`, `i386`, `arm64`, etc.).
//! - **Subsystem**: IMAGE_OPTIONAL_HEADER.Subsystem — runtime
//!   context (`console`, `windows-gui`, `efi-application`, etc.).
//!
//! Unlike 023/024 which needed byte-level parsing, this module leans
//! on `object` 0.36's typed PE accessors: `PeFile::pdb_info()` returns
//! `Result<Option<CodeView>>` directly, and the `ImageNtHeaders` trait
//! provides `file_header()` + `optional_header()`. The wrapper fns
//! are generic over the trait so the body is shared between PE32
//! and PE32+; the call site picks `PeFile32` vs `PeFile64` by reading
//! `IMAGE_OPTIONAL_HEADER.Magic` (`0x10B` vs `0x20B`).
//!
//! Each parser returns `Option<String>` defensively and never panics.

#![allow(dead_code)] // wired in commit 2 (028/wire-up-bag)

use object::pe;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile, PeFile32, PeFile64};
use object::Object;

/// PE32 magic — `IMAGE_NT_OPTIONAL_HDR32_MAGIC`.
const PE32_MAGIC: u16 = 0x10B;
/// PE32+ magic — `IMAGE_NT_OPTIONAL_HDR64_MAGIC`.
const PE32_PLUS_MAGIC: u16 = 0x20B;

/// Result tuple from the unified entry point: pdb-id / machine /
/// subsystem, in struct-field order matching `BinaryScan`.
pub type PeIdentity = (Option<String>, Option<String>, Option<String>);

/// Parse PE bytes and return all three identity signals. Returns
/// `(None, None, None)` for malformed bytes; individual fields may be
/// `None` even on a valid PE if the source data is absent (e.g. a
/// stripped `.exe` with no `IMAGE_DEBUG_DIRECTORY` entry has no
/// pdb-id, but still has machine + subsystem).
///
/// Bit-width dispatch reads `IMAGE_OPTIONAL_HEADER.Magic` (canonical
/// PE32 vs PE32+ discriminator) per spec edge case "32-bit vs 64-bit
/// PE". Both arms call into the same generic-over-`ImageNtHeaders`
/// helpers below.
pub fn parse_pe_identity(bytes: &[u8]) -> PeIdentity {
    match detect_pe_magic(bytes) {
        Some(PE32_MAGIC) => match PeFile32::parse(bytes) {
            Ok(file) => (
                parse_pdb_id(&file),
                parse_machine_type(&file),
                parse_subsystem(&file),
            ),
            Err(_) => (None, None, None),
        },
        Some(PE32_PLUS_MAGIC) => match PeFile64::parse(bytes) {
            Ok(file) => (
                parse_pdb_id(&file),
                parse_machine_type(&file),
                parse_subsystem(&file),
            ),
            Err(_) => (None, None, None),
        },
        _ => (None, None, None),
    }
}

/// Read the PE optional-header `Magic` u16 to discriminate PE32 vs
/// PE32+. Walks the standard PE layout: `e_lfanew` (DOS header offset
/// 0x3C, u32 LE) points to the NT headers, which start with a 4-byte
/// `PE\0\0` signature, then a 20-byte `IMAGE_FILE_HEADER`, then the
/// `IMAGE_OPTIONAL_HEADER` whose first u16 is `Magic`.
fn detect_pe_magic(bytes: &[u8]) -> Option<u16> {
    // DOS signature `MZ` at offset 0.
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes.get(0x3C..0x40)?.try_into().ok()?) as usize;
    // PE\0\0 signature.
    if bytes.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    // 20-byte IMAGE_FILE_HEADER follows; IMAGE_OPTIONAL_HEADER's first
    // u16 is Magic.
    let magic_offset = e_lfanew + 4 + 20;
    let magic_bytes: [u8; 2] = bytes.get(magic_offset..magic_offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(magic_bytes))
}

/// Hex-encode + age-format the CodeView Type-2 record into the
/// `<guid-hex-lowercase>:<age>` form used by symbol servers (32 hex
/// chars + colon + decimal age). `None` for binaries without a
/// CodeView record (stripped, NB10 / Type-1 PDBs, resource-only DLLs).
pub fn parse_pdb_id<'a, Pe: ImageNtHeaders>(file: &PeFile<'a, Pe, &'a [u8]>) -> Option<String> {
    let codeview = file.pdb_info().ok().flatten()?;
    let guid_hex = codeview
        .guid()
        .iter()
        .fold(String::with_capacity(32), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });
    Some(format!("{guid_hex}:{}", codeview.age()))
}

/// Decode `IMAGE_FILE_HEADER.Machine` into a stable lowercase name.
/// Always returns `Some(...)` for a parseable PE — unknown values map
/// to `"unknown"` per spec edge case.
pub fn parse_machine_type<'a, Pe: ImageNtHeaders>(
    file: &PeFile<'a, Pe, &'a [u8]>,
) -> Option<String> {
    let value = file.nt_headers().file_header().machine.get(object::LittleEndian);
    Some(machine_to_str(value).to_string())
}

/// Decode `IMAGE_OPTIONAL_HEADER.Subsystem` into a stable lowercase
/// name. Always returns `Some(...)` for a parseable PE — unknown
/// values map to `"unknown"` per spec edge case.
pub fn parse_subsystem<'a, Pe: ImageNtHeaders>(
    file: &PeFile<'a, Pe, &'a [u8]>,
) -> Option<String> {
    let value = file.nt_headers().optional_header().subsystem();
    Some(subsystem_to_str(value).to_string())
}

fn machine_to_str(value: u16) -> &'static str {
    match value {
        pe::IMAGE_FILE_MACHINE_I386 => "i386",
        pe::IMAGE_FILE_MACHINE_AMD64 => "amd64",
        pe::IMAGE_FILE_MACHINE_IA64 => "ia64",
        pe::IMAGE_FILE_MACHINE_ARM => "arm",
        pe::IMAGE_FILE_MACHINE_ARMNT => "armnt",
        pe::IMAGE_FILE_MACHINE_ARM64 => "arm64",
        pe::IMAGE_FILE_MACHINE_RISCV32 => "riscv32",
        pe::IMAGE_FILE_MACHINE_RISCV64 => "riscv64",
        _ => "unknown",
    }
}

fn subsystem_to_str(value: u16) -> &'static str {
    match value {
        pe::IMAGE_SUBSYSTEM_NATIVE => "native",
        pe::IMAGE_SUBSYSTEM_WINDOWS_GUI => "windows-gui",
        // Microsoft toolchain idiom: WINDOWS_CUI is the CLI subsystem,
        // colloquially "console". Match user-facing terminology.
        pe::IMAGE_SUBSYSTEM_WINDOWS_CUI => "console",
        pe::IMAGE_SUBSYSTEM_OS2_CUI => "os2-cui",
        pe::IMAGE_SUBSYSTEM_POSIX_CUI => "posix-cui",
        pe::IMAGE_SUBSYSTEM_NATIVE_WINDOWS => "native-windows",
        pe::IMAGE_SUBSYSTEM_WINDOWS_CE_GUI => "windows-ce-gui",
        pe::IMAGE_SUBSYSTEM_EFI_APPLICATION => "efi-application",
        pe::IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER => "efi-boot-service",
        pe::IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER => "efi-runtime-driver",
        pe::IMAGE_SUBSYSTEM_EFI_ROM => "efi-rom",
        pe::IMAGE_SUBSYSTEM_XBOX => "xbox",
        pe::IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION => "windows-boot-application",
        _ => "unknown",
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    /// Build a minimal valid PE image suitable for `PeFile{32,64}::parse`.
    /// Layout: MZ stub (0x40) → `PE\0\0` → IMAGE_FILE_HEADER (20) →
    /// IMAGE_OPTIONAL_HEADER → ONE IMAGE_SECTION_HEADER (40) → optional
    /// IMAGE_DEBUG_DIRECTORY entry + CodeView record inside the section's
    /// raw data. The single section is required so `pdb_info()` can
    /// resolve the data-directory RVA through the section table.
    fn build_minimal_pe(
        is_64bit: bool,
        machine: u16,
        subsystem: u16,
        codeview: Option<(&[u8; 16], u32, &str)>,
    ) -> Vec<u8> {
        let optional_header_size = if is_64bit { 240usize } else { 224 };
        let cv_data = codeview.map(|(guid, age, path)| {
            // RSDS signature + 16-byte GUID + 4-byte LE age + NUL-
            // terminated UTF-8 PDB path.
            let mut buf = Vec::with_capacity(24 + path.len() + 1);
            buf.extend_from_slice(b"RSDS");
            buf.extend_from_slice(guid);
            buf.extend_from_slice(&age.to_le_bytes());
            buf.extend_from_slice(path.as_bytes());
            buf.push(0);
            buf
        });

        let debug_dir_size = 28usize;
        let section_payload_size = match cv_data.as_ref() {
            Some(cv) => debug_dir_size + cv.len(),
            None => 0,
        };
        let has_section = section_payload_size > 0;
        let num_sections: u16 = if has_section { 1 } else { 0 };

        // Pre-compute offsets.
        let mz_size = 0x40usize;
        let nt_offset = mz_size; // e_lfanew = 0x40
        let pe_sig_size = 4usize;
        let file_header_size = 20usize;
        let section_header_size = 40usize;
        let headers_end =
            nt_offset + pe_sig_size + file_header_size + optional_header_size + (num_sections as usize) * section_header_size;
        // PE FileAlignment = 0x200 (512). Section raw data starts at the
        // first 0x200-aligned offset ≥ headers_end.
        let section_raw_offset = (headers_end + 0x1FF) & !0x1FF;
        // SectionAlignment = 0x1000; pick a small constant RVA.
        let section_rva: u32 = 0x1000;
        // CodeView blob lives right after the IMAGE_DEBUG_DIRECTORY entry.
        let cv_file_offset = section_raw_offset + debug_dir_size;
        let cv_rva = section_rva + debug_dir_size as u32;

        // ---- MZ header (0x40 bytes) ----
        let mut img = vec![0u8; mz_size];
        img[0..2].copy_from_slice(b"MZ");
        img[0x3C..0x40].copy_from_slice(&(nt_offset as u32).to_le_bytes());

        // ---- PE\0\0 signature ----
        img.extend_from_slice(b"PE\0\0");

        // ---- IMAGE_FILE_HEADER (20 bytes) ----
        img.extend_from_slice(&machine.to_le_bytes()); // Machine
        img.extend_from_slice(&num_sections.to_le_bytes()); // NumberOfSections
        img.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        img.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        img.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        img.extend_from_slice(&(optional_header_size as u16).to_le_bytes()); // SizeOfOptionalHeader
        img.extend_from_slice(&0u16.to_le_bytes()); // Characteristics

        // ---- IMAGE_OPTIONAL_HEADER ----
        let opt_start = img.len();
        let magic: u16 = if is_64bit { PE32_PLUS_MAGIC } else { PE32_MAGIC };
        img.extend_from_slice(&magic.to_le_bytes()); // Magic
        img.push(0); // MajorLinkerVersion
        img.push(0); // MinorLinkerVersion
        img.extend_from_slice(&0u32.to_le_bytes()); // SizeOfCode
        img.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
        img.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
        img.extend_from_slice(&0u32.to_le_bytes()); // AddressOfEntryPoint
        img.extend_from_slice(&0u32.to_le_bytes()); // BaseOfCode
        if !is_64bit {
            img.extend_from_slice(&0u32.to_le_bytes()); // BaseOfData (PE32 only)
        }
        if is_64bit {
            img.extend_from_slice(&0u64.to_le_bytes()); // ImageBase (u64 in PE32+)
        } else {
            img.extend_from_slice(&0u32.to_le_bytes()); // ImageBase (u32 in PE32)
        }
        img.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        img.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        img.extend_from_slice(&0u16.to_le_bytes()); // MajorOperatingSystemVersion
        img.extend_from_slice(&0u16.to_le_bytes()); // MinorOperatingSystemVersion
        img.extend_from_slice(&0u16.to_le_bytes()); // MajorImageVersion
        img.extend_from_slice(&0u16.to_le_bytes()); // MinorImageVersion
        img.extend_from_slice(&5u16.to_le_bytes()); // MajorSubsystemVersion
        img.extend_from_slice(&0u16.to_le_bytes()); // MinorSubsystemVersion
        img.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        img.extend_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        img.extend_from_slice(&(section_raw_offset as u32).to_le_bytes()); // SizeOfHeaders
        img.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        img.extend_from_slice(&subsystem.to_le_bytes()); // Subsystem
        img.extend_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
        // SizeOf{Stack,Heap}Reserve+Commit — 4×u32 in PE32, 4×u64 in PE32+.
        if is_64bit {
            for _ in 0..4 {
                img.extend_from_slice(&0u64.to_le_bytes());
            }
        } else {
            for _ in 0..4 {
                img.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        img.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        // NumberOfRvaAndSizes — must be 16 for the 16 standard data
        // directories (incl. IMAGE_DIRECTORY_ENTRY_DEBUG at index 6).
        img.extend_from_slice(&16u32.to_le_bytes());
        // 16 IMAGE_DATA_DIRECTORY entries (8 bytes each: VirtualAddress
        // u32 + Size u32). Index 6 = DEBUG; populated only when CodeView.
        for i in 0..16u32 {
            if i == 6 && has_section {
                img.extend_from_slice(&section_rva.to_le_bytes());
                img.extend_from_slice(&(debug_dir_size as u32).to_le_bytes());
            } else {
                img.extend_from_slice(&0u32.to_le_bytes());
                img.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        debug_assert_eq!(img.len() - opt_start, optional_header_size);

        // ---- IMAGE_SECTION_HEADER (40 bytes) — only when payload exists ----
        if has_section {
            let mut name = [0u8; 8];
            name[..6].copy_from_slice(b".debug");
            img.extend_from_slice(&name); // Name (8)
            img.extend_from_slice(&(section_payload_size as u32).to_le_bytes()); // VirtualSize
            img.extend_from_slice(&section_rva.to_le_bytes()); // VirtualAddress
            img.extend_from_slice(&(section_payload_size as u32).to_le_bytes()); // SizeOfRawData
            img.extend_from_slice(&(section_raw_offset as u32).to_le_bytes()); // PointerToRawData
            img.extend_from_slice(&0u32.to_le_bytes()); // PointerToRelocations
            img.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
            img.extend_from_slice(&0u16.to_le_bytes()); // NumberOfRelocations
            img.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
            img.extend_from_slice(&0x40000040u32.to_le_bytes()); // Characteristics: INITIALIZED_DATA | READ
        }

        // Pad up to FileAlignment so the section data starts at the
        // recorded PointerToRawData.
        if img.len() < section_raw_offset {
            img.resize(section_raw_offset, 0);
        }

        // ---- IMAGE_DEBUG_DIRECTORY entry (28 bytes, at start of section) ----
        if let Some(cv) = cv_data.as_ref() {
            img.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
            img.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
            img.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
            img.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
            img.extend_from_slice(&pe::IMAGE_DEBUG_TYPE_CODEVIEW.to_le_bytes()); // Type
            img.extend_from_slice(&(cv.len() as u32).to_le_bytes()); // SizeOfData
            img.extend_from_slice(&cv_rva.to_le_bytes()); // AddressOfRawData (RVA)
            img.extend_from_slice(&(cv_file_offset as u32).to_le_bytes()); // PointerToRawData (file offset)
            img.extend_from_slice(cv);
        }

        img
    }

    #[test]
    fn machine_to_str_known_values() {
        assert_eq!(machine_to_str(pe::IMAGE_FILE_MACHINE_AMD64), "amd64");
        assert_eq!(machine_to_str(pe::IMAGE_FILE_MACHINE_I386), "i386");
        assert_eq!(machine_to_str(pe::IMAGE_FILE_MACHINE_ARM64), "arm64");
        assert_eq!(machine_to_str(pe::IMAGE_FILE_MACHINE_ARMNT), "armnt");
    }

    #[test]
    fn machine_to_str_unknown_returns_unknown() {
        assert_eq!(machine_to_str(0xDEAD), "unknown");
        assert_eq!(machine_to_str(pe::IMAGE_FILE_MACHINE_UNKNOWN), "unknown");
    }

    #[test]
    fn subsystem_to_str_known_values() {
        assert_eq!(subsystem_to_str(pe::IMAGE_SUBSYSTEM_WINDOWS_CUI), "console");
        assert_eq!(subsystem_to_str(pe::IMAGE_SUBSYSTEM_WINDOWS_GUI), "windows-gui");
        assert_eq!(
            subsystem_to_str(pe::IMAGE_SUBSYSTEM_EFI_APPLICATION),
            "efi-application"
        );
        assert_eq!(subsystem_to_str(pe::IMAGE_SUBSYSTEM_NATIVE), "native");
    }

    #[test]
    fn subsystem_to_str_unknown_returns_unknown() {
        assert_eq!(subsystem_to_str(0xDEAD), "unknown");
        assert_eq!(subsystem_to_str(0), "unknown");
    }

    #[test]
    fn detect_pe_magic_returns_pe32_plus_for_64bit_image() {
        let img = build_minimal_pe(
            true,
            pe::IMAGE_FILE_MACHINE_AMD64,
            pe::IMAGE_SUBSYSTEM_WINDOWS_CUI,
            None,
        );
        assert_eq!(detect_pe_magic(&img), Some(PE32_PLUS_MAGIC));
    }

    #[test]
    fn detect_pe_magic_returns_pe32_for_32bit_image() {
        let img = build_minimal_pe(
            false,
            pe::IMAGE_FILE_MACHINE_I386,
            pe::IMAGE_SUBSYSTEM_WINDOWS_GUI,
            None,
        );
        assert_eq!(detect_pe_magic(&img), Some(PE32_MAGIC));
    }

    #[test]
    fn detect_pe_magic_rejects_non_pe_bytes() {
        assert_eq!(detect_pe_magic(b"garbage"), None);
        assert_eq!(detect_pe_magic(&[0u8; 0x100]), None); // No MZ
    }

    #[test]
    fn parse_pe_identity_64bit_with_codeview() {
        let guid: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let img = build_minimal_pe(
            true,
            pe::IMAGE_FILE_MACHINE_AMD64,
            pe::IMAGE_SUBSYSTEM_WINDOWS_CUI,
            Some((&guid, 7, "C:\\src\\foo.pdb")),
        );
        let (pdb, machine, subsys) = parse_pe_identity(&img);
        assert_eq!(
            pdb.as_deref(),
            Some("0123456789abcdeffedcba9876543210:7"),
            "pdb-id should be <guid-hex-lowercase>:<age>"
        );
        assert_eq!(machine.as_deref(), Some("amd64"));
        assert_eq!(subsys.as_deref(), Some("console"));
    }

    #[test]
    fn parse_pe_identity_32bit_without_codeview() {
        let img = build_minimal_pe(
            false,
            pe::IMAGE_FILE_MACHINE_I386,
            pe::IMAGE_SUBSYSTEM_WINDOWS_GUI,
            None,
        );
        let (pdb, machine, subsys) = parse_pe_identity(&img);
        assert_eq!(pdb, None, "no CodeView record → no pdb-id annotation");
        assert_eq!(machine.as_deref(), Some("i386"));
        assert_eq!(subsys.as_deref(), Some("windows-gui"));
    }

    #[test]
    fn parse_pe_identity_arm64_efi_application() {
        let img = build_minimal_pe(
            true,
            pe::IMAGE_FILE_MACHINE_ARM64,
            pe::IMAGE_SUBSYSTEM_EFI_APPLICATION,
            None,
        );
        let (_, machine, subsys) = parse_pe_identity(&img);
        assert_eq!(machine.as_deref(), Some("arm64"));
        assert_eq!(subsys.as_deref(), Some("efi-application"));
    }

    #[test]
    fn parse_pe_identity_unknown_machine_emits_unknown() {
        let img = build_minimal_pe(
            true,
            0xDEAD, // unknown machine type
            pe::IMAGE_SUBSYSTEM_WINDOWS_CUI,
            None,
        );
        let (_, machine, _) = parse_pe_identity(&img);
        assert_eq!(machine.as_deref(), Some("unknown"));
    }

    #[test]
    fn parse_pe_identity_returns_all_none_for_garbage_bytes() {
        let result = parse_pe_identity(b"this is not a PE binary at all");
        assert_eq!(result, (None, None, None));
    }
}
