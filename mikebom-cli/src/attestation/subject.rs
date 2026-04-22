//! Subject resolution — feature 006 US3.
//!
//! Replaces the legacy synthetic `"build-output"` descriptor with real
//! artifact-name + SHA-256 descriptors auto-detected from the trace +
//! artifact-dir walk. The resolver runs in a fixed precedence ladder
//! (operator override → artifact-dir walk → suffix match → magic-byte
//! detection → synthetic fallback) — documented in
//! `specs/006-sbomit-suite/data-model.md`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use mikebom_common::attestation::statement::ResourceDescriptor;

/// A resolved subject entry. Serializes into an in-toto
/// `ResourceDescriptor` per `contracts/attestation-envelope.md`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject {
    /// A real on-disk artifact with a content hash.
    Artifact {
        name: String,
        digest: ContentHash,
    },
    /// A synthetic placeholder emitted when no recognizable artifact is
    /// produced by the traced build. Uses a `synthetic` digest-algorithm
    /// key so verifiers can distinguish it from real content hashes.
    Synthetic {
        /// `synthetic:<short-summary>` — prefix preserved into wire.
        command_summary: String,
        /// Hex-encoded SHA-256 of the canonicalized command + trace
        /// start timestamp. Deterministic across identical traces.
        synthetic_digest: String,
    },
}

impl Subject {
    /// Build the wire `ResourceDescriptor` — name + digest-map entry.
    pub fn to_resource_descriptor(&self) -> ResourceDescriptor {
        match self {
            Self::Artifact { name, digest } => {
                let mut digest_map = BTreeMap::new();
                digest_map.insert("sha256".to_string(), digest.sha256_hex.clone());
                ResourceDescriptor {
                    name: name.clone(),
                    digest: digest_map,
                }
            }
            Self::Synthetic {
                command_summary,
                synthetic_digest,
            } => {
                let mut digest_map = BTreeMap::new();
                digest_map.insert("synthetic".to_string(), synthetic_digest.clone());
                ResourceDescriptor {
                    name: command_summary.clone(),
                    digest: digest_map,
                }
            }
        }
    }
}

/// A content hash for a real artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentHash {
    pub sha256_hex: String,
}

/// Configuration for the resolver. Populated from CLI flags +
/// `AggregatedTrace` context.
#[derive(Clone, Debug, Default)]
pub struct SubjectResolver {
    /// Explicit operator overrides via `--subject`. When non-empty,
    /// auto-detection is suppressed entirely.
    pub operator_subjects: Vec<PathBuf>,
    /// Paths to scan for artifacts (CWD + `--artifact-dir`).
    pub artifact_dirs: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_subject_serializes_with_sha256_digest() {
        let sub = Subject::Artifact {
            name: "ripgrep".to_string(),
            digest: ContentHash {
                sha256_hex: "abc123".to_string(),
            },
        };
        let rd = sub.to_resource_descriptor();
        assert_eq!(rd.name, "ripgrep");
        assert_eq!(rd.digest.get("sha256").unwrap(), "abc123");
        assert!(!rd.digest.contains_key("synthetic"));
    }

    #[test]
    fn synthetic_subject_serializes_with_synthetic_digest() {
        let sub = Subject::Synthetic {
            command_summary: "synthetic:cargo-test-abc1234".to_string(),
            synthetic_digest: "9a3f6c7b".to_string(),
        };
        let rd = sub.to_resource_descriptor();
        assert_eq!(rd.name, "synthetic:cargo-test-abc1234");
        assert_eq!(rd.digest.get("synthetic").unwrap(), "9a3f6c7b");
        assert!(!rd.digest.contains_key("sha256"));
    }

    #[test]
    fn subject_resolver_default_is_empty() {
        let resolver = SubjectResolver::default();
        assert!(resolver.operator_subjects.is_empty());
        assert!(resolver.artifact_dirs.is_empty());
    }
}
