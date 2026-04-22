//! Subject resolution — feature 006 US3.
//!
//! Replaces the legacy synthetic `"build-output"` descriptor with real
//! artifact-name + SHA-256 descriptors auto-detected from the trace +
//! artifact-dir walk. The resolver runs in a fixed precedence ladder
//! documented in `specs/006-sbomit-suite/data-model.md`:
//!
//! 1. **Operator override** — any `--subject` paths win; auto-detection
//!    is suppressed entirely (FR-009).
//! 2. **Artifact-dir walk** — scan declared `--artifact-dir` paths for
//!    files whose mtime is newer than trace-start.
//! 3. **Suffix-list match** — recognized archive extensions (`.whl`,
//!    `.crate`, `.tar.gz`, …) hash + include.
//! 4. **Magic-byte detection** — ELF / Mach-O / PE heads identified by
//!    their signature bytes regardless of extension.
//! 5. **Synthetic fallback** — when nothing above hits, emit a single
//!    `synthetic:<cmd>-<hash>` descriptor so strict in-toto parsers
//!    don't choke on an empty subject array (Q5).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

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
    /// Minimum mtime for artifact-dir walks. Files older than this
    /// aren't considered build output. Pre-trace files pre-exist.
    pub mtime_floor: Option<std::time::SystemTime>,
    /// The command being traced — used for synthetic-fallback summary.
    pub command: String,
    /// Trace start as RFC 3339 — used in the synthetic digest input.
    pub trace_start_rfc3339: String,
}

/// Common package / build-output suffixes that are unambiguous enough to
/// treat as "build artifact" without a magic-byte probe.
const ARTIFACT_SUFFIXES: &[&str] = &[
    ".whl",
    ".tar.gz",
    ".tgz",
    ".crate",
    ".gem",
    ".jar",
    ".war",
    ".ear",
    ".apk",
    ".deb",
    ".rpm",
    ".zip",
    ".pyz",
    ".tar",
    ".bz2",
    ".xz",
    ".dylib",
    ".so",
    ".a",
    ".dll",
    ".exe",
    ".pkg",
    ".dmg",
    ".msi",
    ".nupkg",
    ".pypirc",
];

impl SubjectResolver {
    /// Execute the precedence ladder and return one-or-more resolved
    /// subjects. Always non-empty per R2 (strict in-toto parsers).
    pub fn resolve(&self) -> Vec<Subject> {
        // 1. Operator override.
        if !self.operator_subjects.is_empty() {
            return self
                .operator_subjects
                .iter()
                .map(|p| {
                    self.artifact_from_path(p)
                        .unwrap_or_else(|_| self.synthetic_fallback())
                })
                .collect();
        }

        // 2–4. Artifact-dir walk + suffix + magic.
        let mut found: Vec<Subject> = Vec::new();
        for dir in &self.artifact_dirs {
            if let Ok(mut hits) = self.scan_dir(dir) {
                found.append(&mut hits);
            }
        }
        // Dedupe by artifact name (path).
        found.sort_by(|a, b| name_of(a).cmp(name_of(b)));
        found.dedup_by(|a, b| name_of(a) == name_of(b));

        if !found.is_empty() {
            return found;
        }

        // 5. Synthetic fallback.
        vec![self.synthetic_fallback()]
    }

    fn artifact_from_path(&self, path: &Path) -> Result<Subject, std::io::Error> {
        let hash = sha256_hex_of_file(path)?;
        Ok(Subject::Artifact {
            name: path.to_string_lossy().into_owned(),
            digest: ContentHash { sha256_hex: hash },
        })
    }

    fn scan_dir(&self, dir: &Path) -> Result<Vec<Subject>, std::io::Error> {
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            // mtime-floor check (if the resolver cares).
            if let Some(floor) = self.mtime_floor {
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let mtime = match meta.modified() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if mtime < floor {
                    continue;
                }
            }
            // Suffix OR magic-byte match gates inclusion.
            let matches_suffix = matches_artifact_suffix(&path);
            let matches_magic = matches_suffix || detect_magic_bytes(&path).unwrap_or(false);
            if matches_suffix || matches_magic {
                if let Ok(subject) = self.artifact_from_path(&path) {
                    out.push(subject);
                }
            }
        }
        Ok(out)
    }

    fn synthetic_fallback(&self) -> Subject {
        let (summary, digest) = synthetic_descriptor(&self.command, &self.trace_start_rfc3339);
        tracing::warn!(
            command = %self.command,
            "no recognized build artifact detected — emitting synthetic subject; \
            downstream verifier binding is degraded"
        );
        Subject::Synthetic {
            command_summary: summary,
            synthetic_digest: digest,
        }
    }
}

fn name_of(s: &Subject) -> &str {
    match s {
        Subject::Artifact { name, .. } => name,
        Subject::Synthetic {
            command_summary, ..
        } => command_summary,
    }
}

fn matches_artifact_suffix(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    ARTIFACT_SUFFIXES.iter().any(|suf| name.ends_with(suf))
}

/// Read the first 8 bytes of `path` and classify as ELF / Mach-O / PE.
/// Returns `Ok(false)` for unrecognized signatures (including text
/// files), `Err` only on IO errors.
pub fn detect_magic_bytes(path: &Path) -> Result<bool, std::io::Error> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; 8];
    let n = f.read(&mut buf)?;
    if n < 4 {
        return Ok(false);
    }
    Ok(is_elf(&buf[..n]) || is_mach_o(&buf[..n]) || is_pe(&buf[..n]))
}

fn is_elf(buf: &[u8]) -> bool {
    buf.len() >= 4 && &buf[..4] == b"\x7FELF"
}

fn is_mach_o(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    // 32-bit big-endian: CEFAEDFE / FEEDFACE; 64-bit: CFFAEDFE / FEEDFACF.
    // Fat (multi-arch): CAFEBABE / BEBAFECA.
    matches!(
        &buf[..4],
        [0xFE, 0xED, 0xFA, 0xCE] // 32-bit BE
            | [0xFE, 0xED, 0xFA, 0xCF] // 64-bit BE
            | [0xCE, 0xFA, 0xED, 0xFE] // 32-bit LE
            | [0xCF, 0xFA, 0xED, 0xFE] // 64-bit LE
            | [0xCA, 0xFE, 0xBA, 0xBE] // fat BE
            | [0xBE, 0xBA, 0xFE, 0xCA] // fat LE
    )
}

fn is_pe(buf: &[u8]) -> bool {
    buf.len() >= 2 && &buf[..2] == b"MZ"
}

fn sha256_hex_of_file(path: &Path) -> Result<String, std::io::Error> {
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

/// Compute the synthetic subject descriptor per Q5:
/// - `command_summary = "synthetic:" + argv0 + "-" + short-hash`
/// - `synthetic_digest = SHA-256(command + "|" + trace_start_rfc3339)`
pub fn synthetic_descriptor(command: &str, trace_start_rfc3339: &str) -> (String, String) {
    let mut hasher = Sha256::new();
    hasher.update(command.as_bytes());
    hasher.update(b"|");
    hasher.update(trace_start_rfc3339.as_bytes());
    let digest_hex = hex_encode(&hasher.finalize());
    let argv0 = command
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("unknown");
    let short = &digest_hex[..digest_hex.len().min(8)];
    (format!("synthetic:{argv0}-{short}"), digest_hex)
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use std::io::Write;

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
            command_summary: "synthetic:cargo-abc1234".to_string(),
            synthetic_digest: "9a3f6c7b".to_string(),
        };
        let rd = sub.to_resource_descriptor();
        assert_eq!(rd.name, "synthetic:cargo-abc1234");
        assert_eq!(rd.digest.get("synthetic").unwrap(), "9a3f6c7b");
        assert!(!rd.digest.contains_key("sha256"));
    }

    #[test]
    fn subject_resolver_default_is_empty() {
        let resolver = SubjectResolver::default();
        assert!(resolver.operator_subjects.is_empty());
        assert!(resolver.artifact_dirs.is_empty());
    }

    #[test]
    fn detect_magic_elf_signature() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.as_file().write_all(b"\x7FELF\x02\x01\x01\x00garbage").unwrap();
        assert!(detect_magic_bytes(tmp.path()).unwrap());
    }

    #[test]
    fn detect_magic_mach_o_64_le() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.as_file().write_all(b"\xCF\xFA\xED\xFE\x00\x00\x00\x00").unwrap();
        assert!(detect_magic_bytes(tmp.path()).unwrap());
    }

    #[test]
    fn detect_magic_mach_o_fat_be() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.as_file().write_all(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x00").unwrap();
        assert!(detect_magic_bytes(tmp.path()).unwrap());
    }

    #[test]
    fn detect_magic_pe_mz_signature() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.as_file().write_all(b"MZ\x90\x00\x00\x00\x00\x00").unwrap();
        assert!(detect_magic_bytes(tmp.path()).unwrap());
    }

    #[test]
    fn detect_magic_rejects_text_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.as_file().write_all(b"# just some text\n").unwrap();
        assert!(!detect_magic_bytes(tmp.path()).unwrap());
    }

    #[test]
    fn synthetic_digest_is_deterministic() {
        let (s1, d1) = synthetic_descriptor("cargo install ripgrep", "2026-04-22T00:00:00Z");
        let (s2, d2) = synthetic_descriptor("cargo install ripgrep", "2026-04-22T00:00:00Z");
        assert_eq!(s1, s2);
        assert_eq!(d1, d2);
    }

    #[test]
    fn synthetic_digest_differs_on_different_inputs() {
        let (_, d1) = synthetic_descriptor("cargo install ripgrep", "2026-04-22T00:00:00Z");
        let (_, d2) = synthetic_descriptor("cargo install ripgrep", "2026-04-22T00:00:01Z");
        assert_ne!(d1, d2);
    }

    #[test]
    fn synthetic_summary_extracts_basename_of_argv0() {
        let (summary, _) = synthetic_descriptor("/usr/bin/cargo install ripgrep", "2026");
        assert!(summary.starts_with("synthetic:cargo-"));
    }

    #[test]
    fn suffix_match_recognizes_wheels_and_crates() {
        assert!(matches_artifact_suffix(Path::new("foo-1.0-py3-none-any.whl")));
        assert!(matches_artifact_suffix(Path::new("bar-0.1.0.crate")));
        assert!(matches_artifact_suffix(Path::new("baz.tar.gz")));
        assert!(!matches_artifact_suffix(Path::new("README.md")));
    }

    #[test]
    fn operator_override_suppresses_auto_detection() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"fixture-content").unwrap();
        let resolver = SubjectResolver {
            operator_subjects: vec![tmp.path().to_path_buf()],
            artifact_dirs: vec![std::env::current_dir().unwrap()],
            mtime_floor: None,
            command: "cargo build".to_string(),
            trace_start_rfc3339: "2026-04-22T00:00:00Z".to_string(),
        };
        let subjects = resolver.resolve();
        assert_eq!(subjects.len(), 1);
        match &subjects[0] {
            Subject::Artifact { name, .. } => {
                assert!(name.ends_with(tmp.path().file_name().unwrap().to_str().unwrap()))
            }
            _ => panic!("expected Artifact, got synthetic"),
        }
    }

    #[test]
    fn empty_artifact_dirs_produce_synthetic_subject() {
        let resolver = SubjectResolver {
            operator_subjects: vec![],
            artifact_dirs: vec![],
            mtime_floor: None,
            command: "cargo test".to_string(),
            trace_start_rfc3339: "2026-04-22T00:00:00Z".to_string(),
        };
        let subjects = resolver.resolve();
        assert_eq!(subjects.len(), 1);
        match &subjects[0] {
            Subject::Synthetic {
                command_summary, ..
            } => assert!(command_summary.starts_with("synthetic:cargo-")),
            _ => panic!("expected Synthetic"),
        }
    }

    #[test]
    fn artifact_dir_walk_picks_up_matching_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        let whl_path = tmp.path().join("sample-1.0-py3-none-any.whl");
        std::fs::write(&whl_path, b"wheel bytes").unwrap();
        std::fs::write(tmp.path().join("README.md"), b"text").unwrap();

        let resolver = SubjectResolver {
            operator_subjects: vec![],
            artifact_dirs: vec![tmp.path().to_path_buf()],
            mtime_floor: None,
            command: "pip wheel .".to_string(),
            trace_start_rfc3339: "2026-04-22T00:00:00Z".to_string(),
        };
        let subjects = resolver.resolve();
        assert_eq!(subjects.len(), 1);
        match &subjects[0] {
            Subject::Artifact { name, .. } => assert!(name.contains("sample-1.0")),
            _ => panic!("expected Artifact"),
        }
    }

    #[test]
    fn artifact_dir_walk_picks_up_elf_binary_without_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("mybin");
        std::fs::write(&bin, b"\x7FELF\x02\x01\x01\x00body").unwrap();

        let resolver = SubjectResolver {
            operator_subjects: vec![],
            artifact_dirs: vec![tmp.path().to_path_buf()],
            mtime_floor: None,
            command: "cargo install".to_string(),
            trace_start_rfc3339: "2026-04-22T00:00:00Z".to_string(),
        };
        let subjects = resolver.resolve();
        assert_eq!(subjects.len(), 1);
        match &subjects[0] {
            Subject::Artifact { name, .. } => assert!(name.ends_with("mybin")),
            _ => panic!("expected Artifact"),
        }
    }

    #[test]
    fn artifact_dir_walk_handles_multiple_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.whl"), b"one").unwrap();
        std::fs::write(tmp.path().join("b.tar.gz"), b"two").unwrap();
        std::fs::write(tmp.path().join("c.txt"), b"ignored").unwrap();

        let resolver = SubjectResolver {
            operator_subjects: vec![],
            artifact_dirs: vec![tmp.path().to_path_buf()],
            mtime_floor: None,
            command: "python -m build".to_string(),
            trace_start_rfc3339: "2026-04-22T00:00:00Z".to_string(),
        };
        let subjects = resolver.resolve();
        assert_eq!(subjects.len(), 2, "should pick up .whl + .tar.gz");
        for s in &subjects {
            let rd = s.to_resource_descriptor();
            assert!(rd.digest.contains_key("sha256"));
        }
    }
}
