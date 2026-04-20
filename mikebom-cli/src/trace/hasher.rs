//! SHA-256 content hashing utilities.
//!
//! Provides userspace SHA-256 hashing for content verification and
//! attestation. Used to compute content hashes for downloaded artifacts
//! and file operations when the in-kernel hash is unavailable or needs
//! verification.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Compute the SHA-256 hash of `data` and return it as a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = sha256_bytes(data);
    hex_encode(&hash)
}

/// Compute the SHA-256 hash of `data` and return the raw 32-byte digest.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Encode a byte slice as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize]);
        s.push(HEX_CHARS[(b & 0x0f) as usize]);
    }
    s
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Stream-hash a file on disk. Reads in 64 KiB chunks so memory usage is
/// bounded regardless of file size. Returns the lowercase hex digest.
///
/// Refuses to open files larger than `max_bytes` — callers should set a
/// sane cap (256 MB is plenty for package artifacts) so an accidental
/// match against a gigabyte log doesn't stall trace post-processing.
pub fn sha256_file_hex(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "file {} exceeds size cap {} bytes (actual: {})",
                path.display(),
                max_bytes,
                meta.len()
            ),
        ));
    }
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let result = hasher.finalize();
    Ok(hex_encode(&result))
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    /// NIST test vector: SHA-256 of empty string.
    #[test]
    fn sha256_empty() {
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// NIST test vector: SHA-256 of "abc".
    #[test]
    fn sha256_abc() {
        let hash = sha256_hex(b"abc");
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// NIST test vector: SHA-256 of the 448-bit message.
    #[test]
    fn sha256_448bit() {
        let hash = sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            hash,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// Verify the raw bytes output matches the hex output.
    #[test]
    fn sha256_bytes_matches_hex() {
        let data = b"mikebom attestation test";
        let hex = sha256_hex(data);
        let bytes = sha256_bytes(data);

        // Re-encode bytes as hex and compare.
        let hex_from_bytes = hex_encode(&bytes);
        assert_eq!(hex, hex_from_bytes);
        assert_eq!(hex.len(), 64);
    }

    /// Verify determinism: same input always produces same output.
    #[test]
    fn sha256_deterministic() {
        let data = b"reproducible builds matter";
        let h1 = sha256_hex(data);
        let h2 = sha256_hex(data);
        assert_eq!(h1, h2);
    }

    /// Different inputs produce different hashes.
    #[test]
    fn sha256_different_inputs() {
        let h1 = sha256_hex(b"input one");
        let h2 = sha256_hex(b"input two");
        assert_ne!(h1, h2);
    }

    /// SHA-256 of a single zero byte.
    #[test]
    fn sha256_single_zero_byte() {
        let hash = sha256_hex(&[0x00]);
        assert_eq!(
            hash,
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    #[test]
    fn sha256_file_hex_matches_in_memory() {
        // File with contents "abc" should yield the NIST "abc" vector.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("abc.bin");
        std::fs::write(&path, b"abc").expect("write");
        let got = sha256_file_hex(&path, 1024).expect("hash");
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_file_hex_streams_across_chunks() {
        // 128 KiB file of 0xAA bytes forces the 64 KiB read loop to iterate.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("big.bin");
        let data = vec![0xAAu8; 128 * 1024];
        std::fs::write(&path, &data).expect("write");
        let from_file = sha256_file_hex(&path, 1 << 20).expect("hash");
        let from_mem = sha256_hex(&data);
        assert_eq!(from_file, from_mem);
    }

    #[test]
    fn sha256_file_hex_rejects_oversized_input() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("too_big.bin");
        std::fs::write(&path, vec![0u8; 2048]).expect("write");
        let result = sha256_file_hex(&path, 1024);
        assert!(result.is_err(), "expected size-cap rejection");
    }
}
