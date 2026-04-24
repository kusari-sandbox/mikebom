//! SPDX identifier newtype (milestone 010, T018).
//!
//! SPDX 2.3 §3.2 mandates `SPDXRef-[A-Za-z0-9.-]+`. [`SpdxId`] is the
//! only legal way to produce one of these strings inside mikebom, so
//! a raw `String` that happens to look like an SPDXID cannot be
//! passed anywhere an SPDXID is expected (Constitution Principle IV).
//!
//! Derivation (data-model.md §3.1, research.md R7):
//! ```text
//! SPDXRef-Package-<base32(SHA-256(canonical_purl))[..16]>
//! ```
//! Base32 ("RFC 4648, no padding") is chosen over hex because it
//! keeps the ID shorter at the same collision resistance. Every
//! character in the RFC-4648 alphabet `[A-Z2-7]` is in the SPDX-legal
//! set. The 16-char prefix covers 80 bits of hash — ~1 collision
//! expected at ~1 trillion components, far beyond any realistic SBOM.

use data_encoding::BASE32_NOPAD;
use mikebom_common::types::purl::Purl;
use sha2::{Digest, Sha256};

/// An SPDX 2.3 element identifier (`SPDXID` values and the fields
/// that reference them). Serializes as a bare string per the spec.
///
/// Only two constructors are exposed: [`SpdxId::for_purl`] for a
/// component derived from a PURL, and [`SpdxId::document`] for the
/// spec-mandated document-level identifier. Any other need routes
/// through those two so the SPDXID space stays derivable from scan
/// content alone (FR-006, FR-020).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct SpdxId(String);

/// Length of the base32-encoded SHA-256 prefix used in Package IDs.
/// 16 chars × 5 bits = 80 bits of entropy. See module docs.
const PURL_HASH_PREFIX_LEN: usize = 16;

impl SpdxId {
    /// Derive the SPDX ID for a resolved component from its PURL.
    ///
    /// Deterministic: identical PURL → identical SPDXID on every
    /// machine, every run. The canonical PURL form (as returned by
    /// `Purl::as_str`) is what gets hashed — so qualifier ordering,
    /// URL-escaping, and case normalization already happened upstream
    /// in `mikebom_common::types::purl`, and we inherit their invariants.
    pub fn for_purl(purl: &Purl) -> Self {
        let canonical = purl.as_str();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let digest = hasher.finalize();
        let encoded = BASE32_NOPAD.encode(&digest);
        let prefix = &encoded[..PURL_HASH_PREFIX_LEN];
        SpdxId(format!("SPDXRef-Package-{prefix}"))
    }

    /// The SPDX-spec-required document-level identifier.
    /// Always returns the literal string `SPDXRef-DOCUMENT`.
    pub fn document() -> Self {
        SpdxId("SPDXRef-DOCUMENT".to_string())
    }

    /// Construct a synthetic-root SPDXID when the scan has no single
    /// natural root (see `document.rs::build_document`'s synthesize-root
    /// branch). The caller is responsible for deriving `hash_prefix`
    /// from stable scan content so the resulting ID is deterministic
    /// — this constructor only enforces the literal-prefix shape.
    pub fn synthetic_root(hash_prefix: &str) -> Self {
        debug_assert!(
            hash_prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'),
            "synthetic-root hash_prefix {hash_prefix:?} contains non-SPDX chars",
        );
        SpdxId(format!("SPDXRef-DocumentRoot-{hash_prefix}"))
    }

    /// Borrow the underlying string. Used by the relationship builder
    /// to reference an ID without cloning.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn document_id_is_spec_literal() {
        assert_eq!(SpdxId::document().as_str(), "SPDXRef-DOCUMENT");
    }

    #[test]
    fn for_purl_is_deterministic() {
        let purl = Purl::new("pkg:cargo/serde@1.0.197").unwrap();
        let a = SpdxId::for_purl(&purl);
        let b = SpdxId::for_purl(&purl);
        assert_eq!(a, b, "same PURL must yield same SpdxId");
    }

    #[test]
    fn for_purl_starts_with_spdxref_package() {
        let purl = Purl::new("pkg:npm/left-pad@1.3.0").unwrap();
        let id = SpdxId::for_purl(&purl);
        assert!(
            id.as_str().starts_with("SPDXRef-Package-"),
            "got {}",
            id.as_str()
        );
    }

    #[test]
    fn for_purl_has_expected_length() {
        // "SPDXRef-Package-" (16) + 16-char hash prefix = 32 chars.
        let purl = Purl::new("pkg:cargo/serde@1.0.197").unwrap();
        let id = SpdxId::for_purl(&purl);
        assert_eq!(id.as_str().len(), 32, "got {}", id.as_str());
    }

    #[test]
    fn for_purl_character_set_is_spdx_legal() {
        // SPDX 2.3 §3.2: `SPDXRef-[A-Za-z0-9.-]+`. Our output is
        // `SPDXRef-Package-` followed by BASE32_NOPAD alphabet
        // `[A-Z2-7]` — strictly inside the legal set.
        let purls = [
            "pkg:cargo/serde@1.0.197",
            "pkg:npm/@scope/name@2.0.0",
            "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=bookworm",
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
        ];
        for p in purls {
            let id = SpdxId::for_purl(&Purl::new(p).unwrap());
            for c in id.as_str().chars() {
                assert!(
                    c.is_ascii_alphanumeric() || c == '.' || c == '-',
                    "char {c:?} in {} is not SPDX-legal",
                    id.as_str()
                );
            }
        }
    }

    #[test]
    fn different_purls_produce_different_ids() {
        let a = SpdxId::for_purl(&Purl::new("pkg:cargo/serde@1.0.197").unwrap());
        let b = SpdxId::for_purl(&Purl::new("pkg:cargo/serde@1.0.198").unwrap());
        assert_ne!(a, b, "different PURLs must produce different SpdxIds");
    }

    #[test]
    fn uniqueness_across_10k_synthetic_purls() {
        // Cheap collision stress: 10 000 synthetic PURLs must all
        // map to distinct SPDXIDs. 80 bits of entropy makes a
        // collision in this population astronomically unlikely
        // (~3 × 10⁻¹⁶), so a failure here is a bug in the derivation
        // (e.g. a truncated hash), not random bad luck.
        let mut set = std::collections::HashSet::new();
        for i in 0..10_000 {
            let p = Purl::new(&format!("pkg:cargo/fake-{i}@0.0.{i}")).unwrap();
            let id = SpdxId::for_purl(&p);
            assert!(
                set.insert(id.clone()),
                "collision at i={i}: {} already seen",
                id.as_str()
            );
        }
    }

    #[test]
    fn transparent_serde_emits_bare_string() {
        let id = SpdxId::for_purl(&Purl::new("pkg:cargo/x@1").unwrap());
        let json = serde_json::to_string(&id).unwrap();
        // Bare string, not `{"SpdxId": "..."}` or similar.
        assert!(json.starts_with('"') && json.ends_with('"'), "got {json}");
        assert!(json.contains("SPDXRef-Package-"));
    }
}
