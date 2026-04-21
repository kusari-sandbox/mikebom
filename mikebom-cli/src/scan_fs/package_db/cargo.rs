//! Read Cargo/Rust package metadata from `Cargo.lock`.
//!
//! Supported formats (FR-040, R9):
//!
//! - **v3** (Cargo ≥ 1.53): `[[package]]` blocks with `name`, `version`,
//!   `source`, `checksum`, `dependencies`.
//! - **v4** (Cargo ≥ 1.78): same shape, but the `[metadata]` table is
//!   gone — checksums live on the `[[package]]` entries themselves.
//!
//! Fail-closed formats:
//!
//! - **v1** (Cargo 1.x pre-dates the `version = N` header; the lockfile
//!   has a top-level `[root]` table instead). Returns
//!   [`CargoError::LockfileUnsupportedVersion`] with `version = 1`.
//! - **v2** (Cargo 1.x early Stable): Returns the same error with
//!   `version = 2`. Users regenerate via `cargo generate-lockfile` on
//!   any Rust ≥ 1.53.
//!
//! Source-kind classification (R10):
//! - `source = "registry+https://..."` → registry crate. Gets SHA-256
//!   `ContentHash` from `checksum`.
//! - `source = "git+https://..."` → git coord. `source_type = "git"`.
//! - `source = "path+file://..."` → workspace-local. `source_type =
//!   "path"`.
//! - `source` absent → the entry IS the workspace root. `source_type =
//!   "workspace"` (no component emitted at read time; left to the
//!   caller to decide whether to publish).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use mikebom_common::types::hash::ContentHash;
use mikebom_common::types::purl::Purl;

use super::PackageDbEntry;

/// Errors the cargo reader can raise. Only `LockfileUnsupportedVersion`
/// is fatal (FR-040 + CLI contract, mirroring the npm v1 refusal).
#[derive(Debug, thiserror::Error)]
pub enum CargoError {
    #[error("Cargo.lock v1/v2 not supported; regenerate with cargo ≥1.53")]
    LockfileUnsupportedVersion { path: PathBuf, version: u64 },
}

const MAX_PROJECT_ROOT_DEPTH: usize = 6;

// ---------------------------------------------------------------------------
// Cargo.lock shape (serde deserialization)
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct CargoLock {
    #[serde(default)]
    version: Option<u64>,
    #[serde(default)]
    package: Vec<CargoPackage>,
}

#[derive(Debug, serde::Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

/// Classification of a `[[package]]` entry's `source = "..."` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    /// `registry+https://github.com/rust-lang/crates.io-index` (crates.io)
    /// or any alternate registry — the normal case.
    Registry,
    /// `git+https://...` — source-kind property `"git"`.
    Git,
    /// `path+file://...` — workspace-local, source-kind property `"path"`.
    Path,
    /// No `source =` key → the entry IS the workspace root (or a
    /// workspace-member that doesn't declare a source). Source-kind
    /// property `"workspace"`; no SHA-256 hash available.
    Workspace,
}

fn classify_source(source: Option<&str>) -> SourceKind {
    match source {
        None => SourceKind::Workspace,
        Some(s) if s.starts_with("registry+") => SourceKind::Registry,
        Some(s) if s.starts_with("git+") => SourceKind::Git,
        Some(s) if s.starts_with("path+") => SourceKind::Path,
        Some(_) => SourceKind::Registry, // unknown scheme; treat as registry
    }
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

fn build_cargo_purl(name: &str, version: &str) -> Option<Purl> {
    Purl::new(&format!("pkg:cargo/{name}@{version}")).ok()
}

fn package_to_entry(pkg: &CargoPackage, source_path: &str) -> Option<PackageDbEntry> {
    let purl = build_cargo_purl(&pkg.name, &pkg.version)?;
    let kind = classify_source(pkg.source.as_deref());
    let source_type = match kind {
        SourceKind::Registry => None,
        SourceKind::Git => Some("git".to_string()),
        SourceKind::Path => Some("path".to_string()),
        SourceKind::Workspace => Some("workspace".to_string()),
    };
    // Registry crates carry a SHA-256 checksum. Git / path / workspace
    // entries do not — leave licenses/hashes empty for them.
    let licenses = Vec::new();
    // Dependencies are encoded as `<name>` or `<name> <version>` or
    // `<name> <version> (registry+...)`. Take just the name.
    let depends: Vec<String> = pkg
        .dependencies
        .iter()
        .map(|d| {
            d.split_whitespace()
                .next()
                .unwrap_or(d)
                .to_string()
        })
        .collect();
    // Registry crates have an accessible `~/.cargo/registry/src/...`
    // Cargo.toml carrying `authors = [...]` that the lockfile
    // doesn't. Offline-safe: miss → None.
    let maintainer = if matches!(kind, SourceKind::Registry) {
        registry_cache_authors(&pkg.name, &pkg.version)
    } else {
        None
    };
    Some(PackageDbEntry {
        purl,
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        arch: None,
        source_path: source_path.to_string(),
        depends,
        maintainer,
        licenses,
        is_dev: None,
        requirement_range: None,
        source_type,
        buildinfo_status: None,
        evidence_kind: None,
        binary_class: None,
        binary_stripped: None,
        linkage_kind: None,
        detected_go: None,
        confidence: None,
        binary_packed: None,
        raw_version: None,
        npm_role: None,
        hashes: Vec::new(),
        sbom_tier: Some("source".to_string()),
    })
}

/// Build a `ContentHash` from a `checksum = "..."` hex string. Cargo
/// always emits SHA-256 so we hard-code the algorithm. Returns `None`
/// when the value isn't a valid SHA-256 hex.
pub(crate) fn checksum_to_content_hash(hex: &str) -> Option<ContentHash> {
    ContentHash::sha256(hex).ok()
}

/// Read `~/.cargo/registry/src/index.crates.io-*/<crate>-<version>/Cargo.toml`
/// and extract `package.authors`. Returns the joined author string
/// when found, `None` otherwise. Offline-safe: missing cache, missing
/// crate, missing authors, or malformed TOML all map to `None`.
///
/// The cache dir has a hash suffix that varies per registry
/// (`index.crates.io-6f17d22bba15001f` is today's crates.io); glob
/// `src/` and probe each candidate. Cost: one `read_dir` + a handful
/// of `is_dir()` probes per crate — negligible next to the lockfile
/// walk.
fn registry_cache_authors(name: &str, version: &str) -> Option<String> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    let src_root = std::path::PathBuf::from(home).join(".cargo/registry/src");
    let Ok(read_dir) = std::fs::read_dir(&src_root) else {
        return None;
    };
    let crate_dirname = format!("{name}-{version}");
    for entry in read_dir.flatten() {
        let registry_dir = entry.path();
        if !registry_dir.is_dir() {
            continue;
        }
        let cargo_toml = registry_dir.join(&crate_dirname).join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&cargo_toml) {
            if let Some(authors) = parse_authors_from_cargo_toml(&text) {
                return Some(authors);
            }
        }
    }
    None
}

/// Extract `package.authors = [...]` from a Cargo.toml body. Returns
/// the authors joined with `", "`. Uses the `toml` crate (already a
/// workspace dep) for robust parsing — handles multi-line arrays,
/// quoting, escapes, and TOML structure edge cases the lockfile
/// parser doesn't need to care about.
fn parse_authors_from_cargo_toml(text: &str) -> Option<String> {
    let parsed: toml::Value = toml::from_str(text).ok()?;
    let authors = parsed
        .get("package")?
        .get("authors")?
        .as_array()?;
    let joined: Vec<String> = authors
        .iter()
        .filter_map(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if joined.is_empty() {
        None
    } else {
        Some(joined.join(", "))
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Parse one `Cargo.lock` file. Emits typed error for v1/v2; otherwise
/// returns the flattened entry list for v3/v4.
fn parse_lockfile(path: &Path) -> Result<Vec<PackageDbEntry>, CargoError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Ok(Vec::new()),
    };
    let doc: CargoLock = match toml::from_str(&text) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "Cargo.lock parse failed — emitting zero cargo components",
            );
            return Ok(Vec::new());
        }
    };
    // Absent version field → pre-v3 (v1 or v2). Cargo never wrote a
    // `version = ` key before v3; its absence IS the signal.
    match doc.version {
        None => {
            // Could be v1 (has `[root]`) or v2 (has `[[package]]` but no
            // version). Both refuse per FR-040.
            let version_hint = if text.contains("[root]") { 1 } else { 2 };
            return Err(CargoError::LockfileUnsupportedVersion {
                path: path.to_path_buf(),
                version: version_hint,
            });
        }
        Some(v) if v < 3 => {
            return Err(CargoError::LockfileUnsupportedVersion {
                path: path.to_path_buf(),
                version: v,
            });
        }
        _ => {}
    }
    let source_path = path.to_string_lossy().into_owned();
    let mut out: Vec<PackageDbEntry> = Vec::new();
    for pkg in &doc.package {
        // Conformance bug 2 fix: skip workspace-root / path-only
        // entries. A Cargo.lock `[[package]]` with no `source` field
        // IS the scanned project (or a workspace member), not a
        // dependency. Emitting it produces a self-referential FP like
        // `pkg:cargo/my-app@0.1.0` in the SBOM. Mirrors npm.rs's
        // path_key == "" skip at parse_package_lock.
        //
        // Trade-off: path dependencies (`path = "../foo"` in Cargo.toml)
        // also have `source = None` and will be dropped. Same behavior
        // as npm (which skips `link: true` workspace entries).
        // Revisit via `--include-path-deps` if a real use case appears.
        if pkg.source.is_none() {
            tracing::debug!(
                name = %pkg.name,
                version = %pkg.version,
                "skipping cargo workspace-root/path entry (source absent)",
            );
            continue;
        }
        if let Some(mut entry) = package_to_entry(pkg, &source_path) {
            // Attach SHA-256 ContentHash to registry crates only.
            // Git / path entries don't carry a checksum in the lockfile.
            if classify_source(pkg.source.as_deref()) == SourceKind::Registry {
                if let Some(ref checksum) = pkg.checksum {
                    if let Some(hash) = checksum_to_content_hash(checksum) {
                        entry.hashes.push(hash);
                    }
                }
            }
            entry.source_path = source_path.clone();
            out.push(entry);
        }
    }
    Ok(out)
}

/// Public entry point — walks `rootfs` for `Cargo.lock` files, parses
/// each, and returns the flattened entry list. v1/v2 at any root
/// short-circuits with the typed error.
pub fn read(rootfs: &Path, _include_dev: bool) -> Result<Vec<PackageDbEntry>, CargoError> {
    let mut out: Vec<PackageDbEntry> = Vec::new();
    let mut seen_purls: HashSet<String> = HashSet::new();
    for lock_path in find_cargo_lockfiles(rootfs) {
        let entries = parse_lockfile(&lock_path)?;
        for entry in entries {
            let purl_key = entry.purl.as_str().to_string();
            if seen_purls.insert(purl_key) {
                out.push(entry);
            }
        }
    }
    if !out.is_empty() {
        tracing::info!(
            rootfs = %rootfs.display(),
            entries = out.len(),
            "parsed Cargo lockfiles",
        );
    }
    Ok(out)
}

fn find_cargo_lockfiles(rootfs: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_for_cargo_lockfiles(rootfs, 0, &mut out);
    out
}

fn walk_for_cargo_lockfiles(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let lock = dir.join("Cargo.lock");
    if lock.is_file() {
        out.push(lock);
    }
    if depth >= MAX_PROJECT_ROOT_DEPTH {
        return;
    }
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if should_skip_descent(name) {
            continue;
        }
        walk_for_cargo_lockfiles(&path, depth + 1, out);
    }
}

fn should_skip_descent(name: &str) -> bool {
    if name.starts_with('.') {
        return true;
    }
    matches!(
        name,
        "target" | "vendor" | "node_modules" | "dist" | "__pycache__"
    )
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn parse_authors_from_cargo_toml_joins_array() {
        let text = r#"
[package]
name = "serde"
version = "1.0.197"
authors = ["Erick Tryzelaar <erick.tryzelaar@gmail.com>", "David Tolnay <dtolnay@gmail.com>"]
edition = "2021"
"#;
        assert_eq!(
            parse_authors_from_cargo_toml(text).as_deref(),
            Some(
                "Erick Tryzelaar <erick.tryzelaar@gmail.com>, David Tolnay <dtolnay@gmail.com>",
            ),
        );
    }

    #[test]
    fn parse_authors_handles_single_author() {
        let text = r#"
[package]
name = "tiny"
authors = ["Solo Dev"]
"#;
        assert_eq!(
            parse_authors_from_cargo_toml(text).as_deref(),
            Some("Solo Dev"),
        );
    }

    #[test]
    fn parse_authors_returns_none_when_field_missing() {
        let text = r#"
[package]
name = "noauth"
version = "0.1"
"#;
        assert!(parse_authors_from_cargo_toml(text).is_none());
    }

    #[test]
    fn parse_authors_returns_none_on_empty_array() {
        let text = r#"
[package]
authors = []
"#;
        assert!(parse_authors_from_cargo_toml(text).is_none());
    }

    #[test]
    fn parse_authors_tolerates_malformed_toml() {
        assert!(parse_authors_from_cargo_toml("not valid =@ toml").is_none());
    }

    #[test]
    fn lockfile_unsupported_version_display_matches_contract() {
        let err = CargoError::LockfileUnsupportedVersion {
            path: PathBuf::from("/tmp/Cargo.lock"),
            version: 2,
        };
        assert_eq!(
            err.to_string(),
            "Cargo.lock v1/v2 not supported; regenerate with cargo ≥1.53"
        );
    }

    fn write_lockfile(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("Cargo.lock");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn parses_v3_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let body = r#"
version = 3

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3fb1c753d2daa1c9a31c65b0c2e1b8b3f6eafbbaa32a9c0b48da3b0b4e2b92d7"
dependencies = ["serde_derive"]

[[package]]
name = "serde_derive"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000001"
"#;
        let path = write_lockfile(dir.path(), body);
        let entries = parse_lockfile(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.name == "serde"));
        let serde = entries.iter().find(|e| e.name == "serde").unwrap();
        assert_eq!(serde.depends, vec!["serde_derive".to_string()]);
        assert_eq!(serde.sbom_tier.as_deref(), Some("source"));
        assert_eq!(serde.source_type, None); // registry source
    }

    #[test]
    fn parses_v4_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let body = r#"
version = 4

[[package]]
name = "anyhow"
version = "1.0.80"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "5ad32ce52e4161730f7098c077cd2ed6229b5804ccf99e5366be1ab72a98b4e1"
"#;
        let path = write_lockfile(dir.path(), body);
        let entries = parse_lockfile(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "anyhow");
    }

    #[test]
    fn git_source_gets_source_type_property() {
        let dir = tempfile::tempdir().unwrap();
        let body = r#"
version = 3

[[package]]
name = "my-fork"
version = "0.1.0"
source = "git+https://github.com/me/my-fork?branch=main#abc123"
"#;
        let path = write_lockfile(dir.path(), body);
        let entries = parse_lockfile(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_type.as_deref(), Some("git"));
    }

    #[test]
    fn v1_lockfile_refused_with_contract_error() {
        let dir = tempfile::tempdir().unwrap();
        // v1 lockfiles have [root] and no version = field.
        let body = r#"
[root]
name = "app"
version = "0.1.0"
dependencies = []
"#;
        let path = write_lockfile(dir.path(), body);
        match parse_lockfile(&path) {
            Err(CargoError::LockfileUnsupportedVersion { version, .. }) => {
                assert_eq!(version, 1);
            }
            other => panic!("expected v1 refusal, got {other:?}"),
        }
    }

    #[test]
    fn v2_lockfile_refused_with_contract_error() {
        let dir = tempfile::tempdir().unwrap();
        // v2 lockfiles have [[package]] but no version = key.
        let body = r#"
[[package]]
name = "x"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
"#;
        let path = write_lockfile(dir.path(), body);
        match parse_lockfile(&path) {
            Err(CargoError::LockfileUnsupportedVersion { version, .. }) => {
                assert_eq!(version, 2);
            }
            other => panic!("expected v2 refusal, got {other:?}"),
        }
    }

    #[test]
    fn source_classification() {
        assert_eq!(classify_source(None), SourceKind::Workspace);
        assert_eq!(
            classify_source(Some("registry+https://x")),
            SourceKind::Registry
        );
        assert_eq!(
            classify_source(Some("git+https://github.com/x/y")),
            SourceKind::Git
        );
        assert_eq!(
            classify_source(Some("path+file:///absolute/path")),
            SourceKind::Path
        );
    }

    #[test]
    fn read_walks_nested_workspace() {
        // Verifies the walker descends into subdirectories to find
        // Cargo.lock. Uses a registry dep alongside the workspace root
        // so the registry dep's presence confirms the walk succeeded
        // (the workspace root is filtered by design — see
        // parse_lockfile_skips_workspace_root).
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("services").join("api");
        std::fs::create_dir_all(&sub).unwrap();
        let body = r#"
version = 3

[[package]]
name = "api-crate"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9e8eabd0c76a9f2678a5e1a5c0c7b8b8c99999999999999999999999999999999"
"#;
        std::fs::write(sub.join("Cargo.lock"), body).unwrap();
        let entries = read(dir.path(), false).unwrap();
        // Walk found the nested Cargo.lock and emitted the registry dep.
        assert!(entries.iter().any(|e| e.name == "serde"));
        // Workspace root is filtered.
        assert!(!entries.iter().any(|e| e.name == "api-crate"));
    }

    #[test]
    fn parse_lockfile_skips_workspace_root() {
        // A Cargo.lock with a workspace root (no source) and one registry
        // dep should yield only the registry dep. The root is the
        // scanned project itself — emitting it as a component produces
        // a self-referential FP. Matches npm.rs's path_key == "" skip.
        let dir = tempfile::tempdir().unwrap();
        let body = r#"
version = 3

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
"#;
        std::fs::write(dir.path().join("Cargo.lock"), body).unwrap();
        let entries = read(dir.path(), false).unwrap();
        assert_eq!(entries.len(), 1, "expected 1 entry, got {entries:?}");
        assert_eq!(entries[0].name, "serde");
    }

    #[test]
    fn parse_lockfile_skips_all_workspace_members() {
        // Multi-crate workspace: all members have source = None and
        // should all be filtered, leaving only registry deps.
        let dir = tempfile::tempdir().unwrap();
        let body = r#"
version = 3

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "my-lib"
version = "0.1.0"

[[package]]
name = "my-cli"
version = "0.1.0"

[[package]]
name = "anyhow"
version = "1.0.80"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393"
"#;
        std::fs::write(dir.path().join("Cargo.lock"), body).unwrap();
        let entries = read(dir.path(), false).unwrap();
        assert_eq!(entries.len(), 1, "only the registry dep should remain");
        assert_eq!(entries[0].name, "anyhow");
    }

    #[test]
    fn read_empty_rootfs_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path(), false).unwrap().is_empty());
    }

    #[test]
    fn read_v1_propagates_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.lock"),
            "[root]\nname = \"x\"\nversion = \"0.1.0\"\ndependencies = []\n",
        )
        .unwrap();
        assert!(matches!(
            read(dir.path(), false),
            Err(CargoError::LockfileUnsupportedVersion { version: 1, .. })
        ));
    }
}