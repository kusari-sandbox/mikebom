//! Packer-signature detection. Milestone 004 US2 T031 / research R7.
//!
//! Packed binaries compress their original IMPORT table / DT_NEEDED
//! data and re-inflate at load time, which means static scanners see
//! an artificially sparse linkage list. Detecting packing tells the
//! consumer "the linkage you see here is not the linkage the binary
//! will have at runtime" — surfaced via `mikebom:binary-packed`.
//!
//! v1 detects UPX only (the dominant format). Other packers (ASProtect,
//! PECompact, VMProtect, Themida) are deliberately out of scope —
//! each adds signature maintenance burden for marginal coverage, and
//! UPX alone covers the long tail of test-environment-packed binaries.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackerKind {
    Upx,
}

impl PackerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PackerKind::Upx => "upx",
        }
    }
}

/// Probe a binary for a known packer signature.
///
/// ELF UPX: magic string `UPX!` typically appears in the first 2 KB
/// (inside the UPX-inserted stub).
///
/// PE UPX: UPX renames the `.text` section to `UPX0` / `UPX1`. The
/// section-name check is done by the caller via the `object` crate;
/// this byte-probe catches unprocessed PE bytes with the same
/// signature.
///
/// Mach-O UPX: the same `UPX!` ASCII marker shows up in the first
/// several KB.
pub fn detect(bytes: &[u8]) -> Option<PackerKind> {
    if has_upx_signature(bytes) {
        return Some(PackerKind::Upx);
    }
    None
}

fn has_upx_signature(bytes: &[u8]) -> bool {
    // Scan the first 4 KB for the ASCII marker. UPX places its stub
    // very early in the file; scanning more than a few KB pays off
    // almost never.
    const PROBE_WINDOW: usize = 4096;
    let probe_end = bytes.len().min(PROBE_WINDOW);
    memmem_short(&bytes[..probe_end], b"UPX!")
        || memmem_short(&bytes[..probe_end], b"UPX0")
        || memmem_short(&bytes[..probe_end], b"UPX1")
}

/// Tiny memmem implementation — `bytes.windows(needle.len()).any(...)`
/// inlined. Avoids pulling in the `memchr` crate.
fn memmem_short(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() || needle.is_empty() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn detects_upx_bang_marker() {
        let mut bytes = vec![0u8; 100];
        bytes.extend_from_slice(b"some padding UPX! more padding");
        assert_eq!(detect(&bytes), Some(PackerKind::Upx));
    }

    #[test]
    fn detects_pe_upx_section_name() {
        let mut bytes = vec![0u8; 512];
        // UPX0 / UPX1 section names appear in the PE section table
        // which lives in the first few KB of the file.
        bytes[512 - 4..].copy_from_slice(b"UPX0");
        assert_eq!(detect(&bytes), Some(PackerKind::Upx));
    }

    #[test]
    fn unpacked_binary_returns_none() {
        // 4 KB of mixed bytes with no UPX markers.
        let mut bytes = vec![0x7Fu8; 4096];
        bytes[0..4].copy_from_slice(b"\x7FELF");
        bytes[100..108].copy_from_slice(b"libc.so.");
        assert_eq!(detect(&bytes), None);
    }

    #[test]
    fn marker_past_probe_window_not_matched() {
        // `UPX!` at offset > 4096 should NOT match (bounded probe).
        let mut bytes = vec![0u8; 5000];
        bytes[4500..4504].copy_from_slice(b"UPX!");
        assert_eq!(detect(&bytes), None);
    }

    #[test]
    fn empty_input_returns_none() {
        assert_eq!(detect(&[]), None);
    }

    #[test]
    fn as_str_returns_canonical_slug() {
        assert_eq!(PackerKind::Upx.as_str(), "upx");
    }
}
