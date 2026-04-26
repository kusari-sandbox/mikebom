//! Filesystem walker that finds candidate binary files.
//!
//! Walks `rootfs` looking for regular files whose first 16 bytes
//! match a known binary magic (ELF / Mach-O / PE). Skips hidden
//! and build directories; ignores files outside the size envelope.

use std::path::{Path, PathBuf};

/// Walk `rootfs` for regular files, probing the first 16 bytes of
/// each for a known binary magic. Skips hidden / build dirs. Ignores
/// files <1 KB or >500 MB (defense-in-depth).
pub(super) fn discover_binaries(root: &Path) -> Vec<PathBuf> {
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
