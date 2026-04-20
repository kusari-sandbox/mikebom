//! Read Node.js package metadata from a scanned filesystem.
//!
//! Three layered sources in order of authority (per spec FR-006..FR-010
//! and research.md R4 / R5 / R8):
//!
//! 1. **Lockfile**: `package-lock.json` (v2/v3) or `pnpm-lock.yaml` (v6+).
//!    Confidence 0.85. Tier is `source` when no populated `node_modules/`
//!    is observed; `deployed` when both lockfile AND node_modules exist
//!    and agree (lockfile mirrors installed state). v1 lockfiles are
//!    refused with an actionable error per FR-006.
//! 2. **Flat `node_modules/` walk**: when no lockfile is present.
//!    Confidence 0.85, tier `deployed`.
//! 3. **Root `package.json` fallback** (FR-007a): when neither lockfile
//!    nor `node_modules/` is present, parse the root manifest's
//!    `dependencies` (and `devDependencies` when `--include-dev` is set).
//!    Confidence 0.70, tier `design`.
//!
//! Drift rule (research R8): when a lockfile and `node_modules/` disagree
//! on a package's version, `node_modules/` wins — the installed reality
//! trumps the locked declaration. Symmetrical with the Python venv rule.
//!
//! v1 lockfile refusal: when `package-lock.json` declares
//! `"lockfileVersion": 1`, the reader returns
//! [`NpmError::LockfileV1Unsupported`]. The CLI wraps it as a non-zero
//! exit with the stderr message documented in
//! `contracts/cli-interface.md`.

use std::path::{Path, PathBuf};

use mikebom_common::types::hash::ContentHash;
use mikebom_common::types::purl::{encode_purl_segment, Purl};

use super::PackageDbEntry;

/// Errors the npm reader can raise. Only `LockfileV1Unsupported` is
/// fatal (FR-006 + CLI contract); the rest are soft failures that the
/// dispatcher logs and swallows.
#[derive(Debug, thiserror::Error)]
pub enum NpmError {
    #[error("package-lock.json v1 not supported; regenerate with npm ≥7")]
    LockfileV1Unsupported { path: PathBuf },
}

/// Public entry point. Walks the scan root for npm package sources and
/// emits one `PackageDbEntry` per unique package identity. Returns
/// `Err(LockfileV1Unsupported)` when any candidate project root contains
/// a v1 lockfile; callers convert that to a non-zero exit.
///
/// For directory scans the sole candidate is `rootfs` itself. For image
/// scans (rootfs = extracted container filesystem), this additionally
/// probes the common image layouts where npm projects live — global
/// `/usr/lib/node_modules/`, `/app/`, `/usr/src/app/`, `/opt/*/`,
/// `/srv/*/` — so the reader finds node_modules trees that don't sit
/// at the rootfs root. See FR-010 of the 002 spec.
pub fn read(
    rootfs: &Path,
    include_dev: bool,
    scan_mode: crate::scan_fs::ScanMode,
) -> Result<Vec<PackageDbEntry>, NpmError> {
    let mut entries: Vec<PackageDbEntry> = Vec::new();
    let mut seen_purls: std::collections::HashSet<String> = std::collections::HashSet::new();

    for project_root in candidate_project_roots(rootfs) {
        // Detect v1 first — fail closed before emitting anything partial.
        let pkg_lock = project_root.join("package-lock.json");
        if pkg_lock.is_file() {
            if let Ok(text) = std::fs::read_to_string(&pkg_lock) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                    let lockfile_version = parsed
                        .get("lockfileVersion")
                        .and_then(|v| v.as_u64());
                    if lockfile_version == Some(1) {
                        return Err(NpmError::LockfileV1Unsupported { path: pkg_lock });
                    }
                }
            }
        }

        let mut project_entries: Vec<PackageDbEntry> = Vec::new();

        // Tier A: lockfile (authoritative).
        if let Some(lockfile_entries) = read_package_lock(&project_root, include_dev) {
            project_entries.extend(lockfile_entries);
        } else if let Some(pnpm_entries) = read_pnpm_lock(&project_root, include_dev) {
            project_entries.extend(pnpm_entries);
        }

        // Tier B: flat node_modules walk (fires when the lockfile didn't
        // produce anything — typical for images where the lockfile has
        // been stripped at build time but the installed tree remains).
        if project_entries.is_empty() {
            if let Some(nm_entries) = read_node_modules(&project_root, scan_mode) {
                project_entries.extend(nm_entries);
            }
        }

        // Tier C: root package.json fallback (FR-007a).
        if project_entries.is_empty() {
            if let Some(fb_entries) = read_root_package_json(&project_root, include_dev) {
                project_entries.extend(fb_entries);
            }
        }

        for entry in project_entries {
            let purl_key = entry.purl.as_str().to_string();
            if seen_purls.insert(purl_key) {
                entries.push(entry);
            }
        }
    }

    Ok(entries)
}

/// Max depth for the recursive project-root search. Chosen to cover
/// realistic monorepos (`repo/packages/foo/apps/admin/` = 4 levels)
/// without running away into deep source trees. The walk is cheap
/// because it terminates at `node_modules/` and VCS/build directories.
const MAX_PROJECT_ROOT_DEPTH: usize = 6;

/// Enumerate every directory under `rootfs` that looks like an npm
/// project. Always includes `rootfs` itself so the single-project
/// case stays identical to before. Recurses up to
/// `MAX_PROJECT_ROOT_DEPTH` levels, stopping at directories that
/// cannot contain a project (installed trees, VCS / build outputs,
/// language-specific caches).
///
/// Handles three layouts with one mechanism:
/// - **Single project**: `rootfs` has the signals, descendants don't.
/// - **Container image**: `/usr/src/app/`, `/app/sub/`, `/srv/foo/`,
///   `/usr/lib/node_modules/<pkg>/` are all discovered without a
///   hard-coded path list — each is just a directory with npm signals.
/// - **Monorepo / multi-app dir**: every `package.json` under
///   `services/*`, `packages/*`, `apps/*`, etc. becomes its own root,
///   so per-workspace-package deps surface even when the root carries
///   a single hoisted `node_modules/`.
///
/// Dedup by PURL in `read()` handles the common case where a root
/// lockfile and a sub-package `package.json` reference the same dep.
fn candidate_project_roots(rootfs: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut visited: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    walk_for_project_roots(rootfs, 0, &mut out, &mut visited);
    out
}

fn walk_for_project_roots(
    dir: &Path,
    depth: usize,
    out: &mut Vec<PathBuf>,
    visited: &mut std::collections::HashSet<PathBuf>,
) {
    // Guard against symlink loops and duplicate enumeration. Use the
    // canonical path when it's available; fall back to `dir` as-is so
    // a missing dir doesn't silently swallow the scan.
    let key = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if !visited.insert(key) {
        return;
    }

    if has_npm_signal(dir) {
        out.push(dir.to_path_buf());
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
        walk_for_project_roots(&path, depth + 1, out, visited);
    }
}

/// Directory names we refuse to descend into when looking for project
/// roots. Split into three reasons:
///
/// 1. **Installed-tree subtrees** — `node_modules/` is an installed
///    dependency graph. Its own `package.json`s are already handled by
///    the parent project's `node_modules/` walker; descending would
///    produce N² false-positive "project roots". Same for `vendor/`
///    and the classic `bower_components/`.
/// 2. **Hidden / VCS / tooling dirs** — `.git/`, `.hg/`, `.svn/`, and
///    any dotfile dir. Never a project root; always just noise.
/// 3. **Build outputs and language caches** — `target/` (Rust + Maven),
///    `dist/`, `build/`, `out/`, `coverage/`, `.next/`, `.nuxt/`,
///    `__pycache__/`, `.venv/`, `venv/`. Won't contain upstream-project
///    metadata worth re-reading.
fn should_skip_descent(name: &str) -> bool {
    // Dotfiles (includes .git, .svn, .next, .venv, .cache, etc.).
    if name.starts_with('.') {
        return true;
    }
    matches!(
        name,
        "node_modules"
            | "bower_components"
            | "vendor"
            | "target"
            | "dist"
            | "build"
            | "out"
            | "coverage"
            | "__pycache__"
            | "venv"
    )
}

/// True when `dir` holds any of the four npm project signals. Used to
/// tag walk hits as project roots.
fn has_npm_signal(dir: &Path) -> bool {
    dir.join("package-lock.json").is_file()
        || dir.join("pnpm-lock.yaml").is_file()
        || dir.join("node_modules").is_dir()
        || dir.join("package.json").is_file()
}

// -----------------------------------------------------------------------
// NpmIntegrity — SRI base64 → hex decoder
// -----------------------------------------------------------------------

/// A decoded SRI integrity string from an npm lockfile. The lockfile
/// stores values like `sha512-<base64>`; we keep the algorithm name and
/// convert the base64 payload to lowercase hex so it matches
/// `ContentHash.value`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NpmIntegrity {
    pub algorithm: String,
    pub hex: String,
}

impl NpmIntegrity {
    /// Decode an SRI string. Returns None for anything that doesn't
    /// match the `alg-<base64>` shape or whose algorithm we don't
    /// recognise.
    pub(crate) fn parse(sri: &str) -> Option<Self> {
        let (alg, b64) = sri.split_once('-')?;
        let alg_upper = match alg.to_ascii_lowercase().as_str() {
            "sha512" => "SHA-512",
            "sha384" => "SHA-384",
            "sha256" => "SHA-256",
            "sha1" => "SHA-1",
            _ => return None,
        };
        let decoded = base64_decode(b64)?;
        let hex = decoded
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        Some(Self {
            algorithm: alg_upper.to_string(),
            hex,
        })
    }

    /// Convert to a `ContentHash`. Currently only SHA-256 maps through
    /// cleanly because that is the only public `ContentHash` constructor.
    /// Other algorithms (SHA-512 common in npm, SHA-384, SHA-1) return
    /// None pending a shared multi-algorithm constructor (tracked as
    /// TODO-NEW-1 `--hash-algorithm`).
    pub(crate) fn to_content_hash(&self) -> Option<ContentHash> {
        match self.algorithm.as_str() {
            "SHA-256" => ContentHash::sha256(&self.hex).ok(),
            _ => None,
        }
    }
}

/// Tiny base64 decoder used by [`NpmIntegrity::parse`]. The `base64`
/// crate is already a workspace dep but importing in this hot path
/// adds compile-time to something we can write in ~20 lines. Uses the
/// standard alphabet per RFC 4648.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(input.as_bytes()).ok()
}

// -----------------------------------------------------------------------
// Tier A: package-lock.json v2/v3 parser
// -----------------------------------------------------------------------

fn read_package_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>> {
    let path = rootfs.join("package-lock.json");
    let text = std::fs::read_to_string(&path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&text).ok()?;
    let source_path = path.to_string_lossy().into_owned();
    let out = parse_package_lock(&parsed, &source_path, include_dev);
    if out.is_empty() { None } else { Some(out) }
}

/// Parse a deserialised `package-lock.json` v2/v3 document. Iterates
/// the top-level `packages` object; skips the root entry (`""`) and
/// any workspace sub-roots (detected via `link: true`).
pub(crate) fn parse_package_lock(
    root: &serde_json::Value,
    source_path: &str,
    include_dev: bool,
) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();
    let Some(packages) = root.get("packages").and_then(|v| v.as_object()) else {
        return out;
    };

    // Sorted for determinism.
    let mut keys: Vec<&String> = packages.keys().collect();
    keys.sort();

    for path_key in keys {
        if path_key.is_empty() {
            // Root project entry — skip.
            continue;
        }
        let entry = &packages[path_key];
        let Some(tbl) = entry.as_object() else { continue };

        // Workspace link — symlink to a sibling workspace, not a
        // published package. Skip.
        if tbl.get("link").and_then(|v| v.as_bool()) == Some(true) {
            continue;
        }

        // `dev: true` / `optional: true` propagate through the nested
        // tree. Filter at source before the caller's dedup pass.
        let is_dev = tbl
            .get("dev")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let is_optional = tbl
            .get("optional")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !include_dev && (is_dev || is_optional) {
            continue;
        }

        // Version is required.
        let version = tbl
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if version.is_empty() {
            continue;
        }

        // Name is either declared in the entry or derived from the
        // path key: last `node_modules/<scope>?/<name>` segment.
        let name = tbl
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| derive_name_from_path_key(path_key));
        if name.is_empty() {
            continue;
        }

        let Some(purl) = build_npm_purl(&name, &version) else {
            continue;
        };

        let hashes = tbl
            .get("integrity")
            .and_then(|v| v.as_str())
            .and_then(NpmIntegrity::parse)
            .and_then(|i| i.to_content_hash())
            .map(|h| vec![h])
            .unwrap_or_default();

        let depends = tbl
            .get("dependencies")
            .and_then(|v| v.as_object())
            .map(|deps| deps.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        out.push(PackageDbEntry {
            purl,
            name,
            version,
            arch: None,
            source_path: source_path.to_string(),
            depends,
            maintainer: None,
            licenses: tbl
                .get("license")
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    mikebom_common::types::license::SpdxExpression::try_canonical(s.trim()).ok()
                })
                .into_iter()
                .collect(),
            is_dev: Some(is_dev),
            requirement_range: None,
            source_type: None,
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
            sbom_tier: Some("source".to_string()),
        });
        // Hashes collected but not yet wired through PackageDbEntry;
        // mirrors the pip.rs pattern until a shared content-hash channel
        // exists (tracked as TODO-NEW-1 --hash-algorithm work).
        let _ = hashes;
    }

    out
}

/// Derive a package name from a `packages` path key like
/// `node_modules/foo` or `node_modules/@scope/bar` or deeply nested
/// `node_modules/foo/node_modules/bar`. The real name is always the
/// segment (or scope+segment) that follows the LAST `node_modules/`.
fn derive_name_from_path_key(key: &str) -> String {
    let idx = match key.rfind("node_modules/") {
        Some(i) => i + "node_modules/".len(),
        None => return String::new(),
    };
    let tail = &key[idx..];
    // Scoped: "@scope/name" — two segments.
    if tail.starts_with('@') {
        let parts: Vec<&str> = tail.splitn(3, '/').collect();
        if parts.len() >= 2 {
            return format!("{}/{}", parts[0], parts[1]);
        }
    }
    // Unscoped: single segment.
    tail.split('/').next().unwrap_or("").to_string()
}

/// Build a canonical npm PURL. Scoped names (`@scope/name`) get the
/// `@` percent-encoded per the packageurl reference impl:
/// `pkg:npm/%40<scope>/<name>@<version>`.
fn build_npm_purl(name: &str, version: &str) -> Option<Purl> {
    let purl_str = if let Some(rest) = name.strip_prefix('@') {
        let (scope, bare_name) = rest.split_once('/')?;
        format!(
            "pkg:npm/%40{}/{}@{}",
            encode_purl_segment(scope),
            encode_purl_segment(bare_name),
            encode_purl_segment(version),
        )
    } else {
        format!(
            "pkg:npm/{}@{}",
            encode_purl_segment(name),
            encode_purl_segment(version),
        )
    };
    Purl::new(&purl_str).ok()
}

// -----------------------------------------------------------------------
// Tier A: pnpm-lock.yaml parser (v6 / v7 / v9)
// -----------------------------------------------------------------------

fn read_pnpm_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>> {
    let path = rootfs.join("pnpm-lock.yaml");
    let text = std::fs::read_to_string(&path).ok()?;
    let parsed: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    let source_path = path.to_string_lossy().into_owned();
    let out = parse_pnpm_lock(&parsed, &source_path, include_dev);
    if out.is_empty() { None } else { Some(out) }
}

/// Parse a deserialised `pnpm-lock.yaml` document. Handles v6/v7/v9
/// dialects per research.md R5.
pub(crate) fn parse_pnpm_lock(
    root: &serde_yaml::Value,
    source_path: &str,
    include_dev: bool,
) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();

    // v6/v7 put per-package info under `packages:` keyed by "/<name>@<version>"
    // (or "/@scope/name@version").
    // v9 splits: `snapshots:` carries resolved versions, `packages:` carries
    // registry metadata. Merge on key.
    let Some(packages) = root.get("packages").and_then(|v| v.as_mapping()) else {
        return out;
    };

    let mut keys: Vec<String> = packages
        .keys()
        .filter_map(|k| k.as_str().map(|s| s.to_string()))
        .collect();
    keys.sort();

    for key in keys {
        let Some(entry) = packages.get(serde_yaml::Value::String(key.clone())) else {
            continue;
        };
        let Some(tbl) = entry.as_mapping() else { continue };

        // v6/v7 key form: "/foo@1.0.0" or "/@scope/name@1.0.0"
        // v9 key form: "foo@1.0.0" (no leading slash)
        let stripped = key.strip_prefix('/').unwrap_or(&key);
        let (name, version) = parse_pnpm_key(stripped).unwrap_or_default();
        if name.is_empty() || version.is_empty() {
            continue;
        }

        let is_dev = tbl
            .get(serde_yaml::Value::String("dev".to_string()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !include_dev && is_dev {
            continue;
        }

        let Some(purl) = build_npm_purl(&name, &version) else {
            continue;
        };

        let hashes = tbl
            .get(serde_yaml::Value::String("resolution".to_string()))
            .and_then(|res| res.as_mapping())
            .and_then(|m| m.get(serde_yaml::Value::String("integrity".to_string())))
            .and_then(|v| v.as_str())
            .and_then(NpmIntegrity::parse)
            .and_then(|i| i.to_content_hash())
            .map(|h| vec![h])
            .unwrap_or_default();

        // Per-package `dependencies:` mapping. pnpm writes this as a
        // YAML mapping of `name: version-spec` pairs; we only need
        // the keys so the dep-graph edges can be built in scan_fs.
        // Peer-dep suffixes on pnpm v9 (`react@18.0.0(react-dom@...)`)
        // are stripped via `parse_pnpm_key` elsewhere; the `dependencies:`
        // values themselves are plain semver strings.
        let depends: Vec<String> = tbl
            .get(serde_yaml::Value::String("dependencies".to_string()))
            .and_then(|v| v.as_mapping())
            .map(|m| {
                m.keys()
                    .filter_map(|k| k.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        out.push(PackageDbEntry {
            purl,
            name,
            version,
            arch: None,
            source_path: source_path.to_string(),
            depends,
            maintainer: None,
            licenses: Vec::new(),
            is_dev: Some(is_dev),
            requirement_range: None,
            source_type: None,
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
            sbom_tier: Some("source".to_string()),
        });
        let _ = hashes;
    }

    out
}

/// Parse a pnpm package key — `<name>@<version>` or
/// `@<scope>/<name>@<version>` — into (name, version). The last `@`
/// is the version separator; everything before it is the name.
fn parse_pnpm_key(key: &str) -> Option<(String, String)> {
    // Strip any parenthesised peer-dep suffix (e.g. "(react@18.0.0)").
    let key = key.split('(').next().unwrap_or(key);
    // Find the LAST '@' that's after position 0 (position 0 is the
    // scope prefix for @scope/name).
    let search_start = if key.starts_with('@') { 1 } else { 0 };
    let at_idx = key[search_start..].rfind('@').map(|i| i + search_start)?;
    let name = key[..at_idx].to_string();
    let version = key[at_idx + 1..].to_string();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

// -----------------------------------------------------------------------
// Tier B: flat node_modules walk
// -----------------------------------------------------------------------

fn read_node_modules(
    rootfs: &Path,
    scan_mode: crate::scan_fs::ScanMode,
) -> Option<Vec<PackageDbEntry>> {
    let nm = rootfs.join("node_modules");
    if !nm.is_dir() {
        return None;
    }
    let mut out = Vec::new();
    walk_node_modules(&nm, &mut out, scan_mode, false);
    if out.is_empty() { None } else { Some(out) }
}

/// Feature 005 US1 — detect paths inside npm's own internal package
/// tree (`**/node_modules/npm/node_modules/**`). When a component's
/// source path matches this glob, npm itself is the owner — not the
/// application being scanned.
///
/// Match rule: the path must contain the component sequence
/// `node_modules` → `npm` → `node_modules` anywhere, with `npm` as a
/// directory whose immediate parent is named `node_modules`. This is
/// the canonical layout npm v7+ installs.
pub(crate) fn is_npm_internal_path(path: &Path) -> bool {
    let comps: Vec<&str> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();
    // Find any window [a, b, c] where a == "node_modules" && b == "npm" && c == "node_modules".
    comps
        .windows(3)
        .any(|w| w[0] == "node_modules" && w[1] == "npm" && w[2] == "node_modules")
}

fn walk_node_modules(
    nm: &Path,
    out: &mut Vec<PackageDbEntry>,
    scan_mode: crate::scan_fs::ScanMode,
    in_npm_internals: bool,
) {
    let Ok(rd) = std::fs::read_dir(nm) else { return };
    let mut children: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    children.sort();
    let parent_name = nm.file_name().and_then(|s| s.to_str()).unwrap_or("");
    for child in children {
        let name_os = child.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name_os.starts_with('.') {
            continue;
        }
        // Feature 005 US1: an `npm` directory whose parent is
        // `node_modules` is the root of npm's own bundled package tree.
        // In --path mode the operator is scanning an application tree, so
        // its own tooling is out of scope — skip entirely. In --image
        // mode the target is the whole filesystem, so we emit the
        // internals but tag each with `npm_role=internal` so downstream
        // consumers can filter or classify them.
        let is_npm_self_root = parent_name == "node_modules" && name_os == "npm";
        if is_npm_self_root && scan_mode == crate::scan_fs::ScanMode::Path {
            continue;
        }
        if name_os.starts_with('@') {
            // Scoped directory — recurse one level to find the actual
            // packages under it. Propagates `in_npm_internals` so scoped
            // deps under npm's own tree stay tagged.
            walk_node_modules(&child, out, scan_mode, in_npm_internals);
            continue;
        }
        if !child.is_dir() {
            continue;
        }
        let pkg_json = child.join("package.json");
        let Ok(text) = std::fs::read_to_string(&pkg_json) else { continue };
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let Some(name) = parsed.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = parsed.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(purl) = build_npm_purl(name, version) else { continue };
        let license = parsed
            .get("license")
            .and_then(|v| v.as_str())
            .and_then(|s| {
                mikebom_common::types::license::SpdxExpression::try_canonical(s.trim()).ok()
            })
            .into_iter()
            .collect();
        let depends = parsed
            .get("dependencies")
            .and_then(|v| v.as_object())
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();
        // Feature 005 US1: tag entries emitted from inside npm's own
        // bundled tree with `npm_role=internal`. `in_npm_internals` is
        // set by the caller for everything under the `npm` self-root;
        // `is_npm_self_root` catches the npm package itself on the
        // entry it emits directly (the `package.json` at the root).
        let npm_role = if in_npm_internals || is_npm_self_root {
            Some("internal".to_string())
        } else {
            None
        };
        out.push(PackageDbEntry {
            purl,
            name: name.to_string(),
            version: version.to_string(),
            arch: None,
            source_path: pkg_json.to_string_lossy().into_owned(),
            depends,
            maintainer: None,
            licenses: license,
            is_dev: None, // flat walk can't recover dev scope
            requirement_range: None,
            source_type: None,
            buildinfo_status: None,
            evidence_kind: None,
            binary_class: None,
            binary_stripped: None,
            linkage_kind: None,
            detected_go: None,
            confidence: None,
            binary_packed: None,
            raw_version: None,
            npm_role,
            sbom_tier: Some("deployed".to_string()),
        });

        // Feature 005 US1: in --image mode, after emitting the `npm`
        // package itself, also descend into its private `node_modules/`
        // to surface the bundled dep graph (~200 entries on a typical
        // node base image). Those entries inherit `in_npm_internals =
        // true` so they get tagged correctly.
        if is_npm_self_root && scan_mode == crate::scan_fs::ScanMode::Image {
            let nested = child.join("node_modules");
            if nested.is_dir() {
                walk_node_modules(&nested, out, scan_mode, true);
            }
        }
    }
}

// -----------------------------------------------------------------------
// Tier C: root package.json fallback (FR-007a)
// -----------------------------------------------------------------------

fn read_root_package_json(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>> {
    let path = rootfs.join("package.json");
    if !path.is_file() {
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&text).ok()?;
    let source_path = path.to_string_lossy().into_owned();
    let out = parse_root_package_json(&parsed, &source_path, include_dev);
    if out.is_empty() { None } else { Some(out) }
}

/// Parse `dependencies` (always) + `devDependencies` (when include_dev).
/// Each key becomes a design-tier component with the range spec in
/// `requirement_range` and `source_type` set for non-registry sources.
pub(crate) fn parse_root_package_json(
    root: &serde_json::Value,
    source_path: &str,
    include_dev: bool,
) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();
    for (section, is_dev) in [("dependencies", false), ("devDependencies", true)] {
        if is_dev && !include_dev {
            continue;
        }
        let Some(obj) = root.get(section).and_then(|v| v.as_object()) else {
            continue;
        };
        let mut names: Vec<&String> = obj.keys().collect();
        names.sort();
        for name in names {
            let range = obj[name].as_str().unwrap_or("").to_string();
            let source_type = classify_npm_source(&range);
            // Empty version for range-specs (spec FR-007a).
            let Some(purl) = build_npm_purl(name, "") else {
                continue;
            };
            out.push(PackageDbEntry {
                purl,
                name: name.to_string(),
                version: String::new(),
                arch: None,
                source_path: source_path.to_string(),
                depends: Vec::new(),
                maintainer: None,
                licenses: Vec::new(),
                is_dev: Some(is_dev),
                requirement_range: Some(range),
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
                sbom_tier: Some("design".to_string()),
            });
        }
    }
    out
}

/// Classify an npm dependency-range spec as `local` / `git` / `url` /
/// registry. Returns None for normal semver registry entries
/// (no property emission).
fn classify_npm_source(range: &str) -> Option<String> {
    if range.starts_with("file:") || range.starts_with('.') || range.starts_with('/') {
        Some("local".to_string())
    } else if range.starts_with("git+") || range.starts_with("git://") {
        Some("git".to_string())
    } else if range.starts_with("http://") || range.starts_with("https://") {
        Some("url".to_string())
    } else {
        None
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    // --- NpmIntegrity SRI decoder tests ---

    #[test]
    fn integrity_decodes_sha512() {
        // base64("hello world") = "aGVsbG8gd29ybGQ=" — but for SRI we
        // use a real sha512 so test values are deterministic.
        let sri = "sha512-MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx+7fIK+4qg9hvLABzzXAIaFMqoD6YFUYaCQPkMInyGdz6TQEsE7bPdCg==";
        let decoded = NpmIntegrity::parse(sri).expect("parses");
        assert_eq!(decoded.algorithm, "SHA-512");
        assert_eq!(decoded.hex.len(), 128); // 512 bits = 128 hex chars
    }

    #[test]
    fn integrity_decodes_sha384_and_sha256() {
        assert_eq!(
            NpmIntegrity::parse("sha384-AAAA").map(|i| i.algorithm),
            Some("SHA-384".to_string())
        );
        assert_eq!(
            NpmIntegrity::parse("sha256-AAAA").map(|i| i.algorithm),
            Some("SHA-256".to_string())
        );
    }

    #[test]
    fn integrity_rejects_malformed_input() {
        assert!(NpmIntegrity::parse("").is_none());
        assert!(NpmIntegrity::parse("sha512").is_none());
        assert!(NpmIntegrity::parse("unknown-AAAA").is_none());
        assert!(NpmIntegrity::parse("sha512-!!!invalid base64!!!").is_none());
    }

    #[test]
    fn integrity_round_trips_to_content_hash() {
        let sri = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        let decoded = NpmIntegrity::parse(sri).expect("parses");
        let hash = decoded.to_content_hash().expect("converts");
        // 32 bytes = 64 hex chars for SHA-256.
        assert_eq!(hash.value.as_str().len(), 64);
    }

    // --- PURL build tests ---

    #[test]
    fn build_npm_purl_unscoped() {
        let p = build_npm_purl("lodash", "4.17.21").expect("builds");
        assert_eq!(p.as_str(), "pkg:npm/lodash@4.17.21");
    }

    #[test]
    fn build_npm_purl_scoped_encodes_at() {
        let p = build_npm_purl("@angular/core", "16.0.0").expect("builds");
        assert_eq!(p.as_str(), "pkg:npm/%40angular/core@16.0.0");
    }

    #[test]
    fn build_npm_purl_empty_version_is_permitted_for_design_tier() {
        // Design-tier root-package.json fallback entries have no resolved
        // version yet — they carry the range spec as a property. The PURL
        // must still be constructible.
        let p = build_npm_purl("foo", "").expect("empty-version permitted");
        assert_eq!(p.as_str(), "pkg:npm/foo@");
    }

    // --- derive_name_from_path_key tests ---

    #[test]
    fn derive_name_handles_flat_and_scoped_and_nested() {
        assert_eq!(derive_name_from_path_key("node_modules/foo"), "foo");
        assert_eq!(
            derive_name_from_path_key("node_modules/@scope/bar"),
            "@scope/bar"
        );
        assert_eq!(
            derive_name_from_path_key("node_modules/foo/node_modules/bar"),
            "bar"
        );
        assert_eq!(
            derive_name_from_path_key("node_modules/foo/node_modules/@scope/baz"),
            "@scope/baz"
        );
    }

    // --- package-lock.json v2/v3 parser tests ---

    #[test]
    fn package_lock_v3_basic() {
        let src = serde_json::json!({
            "name": "myapp",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "myapp", "version": "0.1.0" },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "integrity": "sha512-MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx+7fIK+4qg9hvLABzzXAIaFMqoD6YFUYaCQPkMInyGdz6TQEsE7bPdCg==",
                    "license": "MIT"
                },
                "node_modules/eslint": {
                    "version": "8.0.0",
                    "dev": true
                }
            }
        });
        let out = parse_package_lock(&src, "/package-lock.json", false);
        assert_eq!(out.len(), 1, "dev entry filtered by default");
        assert_eq!(out[0].name, "lodash");
        assert_eq!(out[0].version, "4.17.21");
        assert_eq!(out[0].sbom_tier.as_deref(), Some("source"));
        assert_eq!(out[0].is_dev, Some(false));
        // Hash extraction is covered by `integrity_round_trips_to_content_hash`;
        // once PackageDbEntry gains a hashes field we re-assert here.
    }

    #[test]
    fn package_lock_v3_include_dev_surfaces_dev_packages() {
        let src = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/eslint": { "version": "8.0.0", "dev": true }
            }
        });
        let out = parse_package_lock(&src, "/package-lock.json", true);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].is_dev, Some(true));
    }

    #[test]
    fn package_lock_skips_workspace_link_entries() {
        let src = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/my-workspace": { "resolved": "../my-workspace", "link": true }
            }
        });
        let out = parse_package_lock(&src, "/package-lock.json", true);
        assert!(out.is_empty());
    }

    #[test]
    fn package_lock_scoped_package_emits_encoded_purl() {
        let src = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/@angular/core": { "version": "16.0.0", "license": "MIT" }
            }
        });
        let out = parse_package_lock(&src, "/package-lock.json", false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].purl.as_str(), "pkg:npm/%40angular/core@16.0.0");
    }

    #[test]
    fn package_lock_skips_optional_by_default() {
        let src = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/fsevents": { "version": "2.3.0", "optional": true }
            }
        });
        let out_default = parse_package_lock(&src, "/p.json", false);
        assert!(out_default.is_empty());
        let out_all = parse_package_lock(&src, "/p.json", true);
        assert_eq!(out_all.len(), 1);
    }

    // --- pnpm-lock.yaml parser tests ---

    #[test]
    fn pnpm_lock_v6_style_parses() {
        let yaml = r#"
lockfileVersion: '6.0'
packages:
  /lodash@4.17.21:
    resolution:
      integrity: sha512-MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx+7fIK+4qg9hvLABzzXAIaFMqoD6YFUYaCQPkMInyGdz6TQEsE7bPdCg==
    dev: false
  /eslint@8.0.0:
    dev: true
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let out = parse_pnpm_lock(&parsed, "/pnpm-lock.yaml", false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "lodash");
        assert_eq!(out[0].version, "4.17.21");
    }

    #[test]
    fn pnpm_lock_scoped_package_parses() {
        let yaml = r#"
lockfileVersion: '6.0'
packages:
  /@angular/core@16.0.0:
    resolution: {}
    dev: false
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let out = parse_pnpm_lock(&parsed, "/pnpm-lock.yaml", false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "@angular/core");
        assert_eq!(out[0].version, "16.0.0");
        assert_eq!(out[0].purl.as_str(), "pkg:npm/%40angular/core@16.0.0");
    }

    #[test]
    fn pnpm_key_parser_handles_peer_suffix() {
        // v9 adds peer-dep suffixes: `react-dom@18.0.0(react@18.0.0)`.
        let (name, version) = parse_pnpm_key("react-dom@18.0.0(react@18.0.0)").unwrap();
        assert_eq!(name, "react-dom");
        assert_eq!(version, "18.0.0");
    }

    // --- root package.json fallback tests ---

    #[test]
    fn root_pkgjson_fallback_emits_design_tier_deps_only_by_default() {
        let src = serde_json::json!({
            "name": "myapp",
            "version": "0.1.0",
            "dependencies": { "requests": "^1.0", "foo": "*" },
            "devDependencies": { "jest": "^29.0" }
        });
        let out = parse_root_package_json(&src, "/package.json", false);
        assert_eq!(out.len(), 2);
        for c in &out {
            assert_eq!(c.sbom_tier.as_deref(), Some("design"));
            assert!(c.requirement_range.is_some());
            assert!(c.version.is_empty());
        }
    }

    #[test]
    fn root_pkgjson_fallback_include_dev_adds_devdeps() {
        let src = serde_json::json!({
            "dependencies": { "foo": "^1.0" },
            "devDependencies": { "jest": "^29.0" }
        });
        let out = parse_root_package_json(&src, "/package.json", true);
        assert_eq!(out.len(), 2);
        let jest = out.iter().find(|c| c.name == "jest").unwrap();
        assert_eq!(jest.is_dev, Some(true));
    }

    #[test]
    fn root_pkgjson_classifies_non_registry_sources() {
        let src = serde_json::json!({
            "dependencies": {
                "local-pkg": "file:./lib",
                "git-pkg": "git+https://github.com/foo/bar.git",
                "url-pkg": "https://example.com/pkg.tgz",
                "registry-pkg": "^1.0.0"
            }
        });
        let out = parse_root_package_json(&src, "/package.json", false);
        let source_types: std::collections::HashMap<String, Option<String>> = out
            .into_iter()
            .map(|c| (c.name, c.source_type))
            .collect();
        assert_eq!(source_types["local-pkg"].as_deref(), Some("local"));
        assert_eq!(source_types["git-pkg"].as_deref(), Some("git"));
        assert_eq!(source_types["url-pkg"].as_deref(), Some("url"));
        assert!(source_types["registry-pkg"].is_none());
    }

    // --- v1 refusal tests ---

    #[test]
    fn v1_lockfile_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"old","lockfileVersion":1,"dependencies":{}}"#,
        )
        .unwrap();
        let err = read(dir.path(), false, crate::scan_fs::ScanMode::Path).unwrap_err();
        assert!(
            matches!(err, NpmError::LockfileV1Unsupported { .. }),
            "got {err:?}"
        );
        // Error message matches the contract.
        assert_eq!(
            err.to_string(),
            "package-lock.json v1 not supported; regenerate with npm ≥7"
        );
    }

    #[test]
    fn v2_and_v3_lockfiles_do_not_trigger_refusal() {
        for v in [2, 3] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("package-lock.json"),
                format!(r#"{{"lockfileVersion":{v},"packages":{{}}}}"#),
            )
            .unwrap();
            let res = read(dir.path(), false, crate::scan_fs::ScanMode::Path);
            assert!(res.is_ok(), "v{v} lockfile should parse without refusal");
        }
    }

    // --- end-to-end via read() ---

    #[test]
    fn reads_package_lock_over_pnpm_when_both_exist() {
        // If both files are present, package-lock.json wins (tier A
        // dispatch order in read()).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '6.0'\npackages:\n  /b@2.0.0:\n    dev: false\n",
        )
        .unwrap();
        let out = read(dir.path(), false, crate::scan_fs::ScanMode::Path).unwrap();
        assert!(out.iter().any(|e| e.name == "a"));
        assert!(
            !out.iter().any(|e| e.name == "b"),
            "pnpm lockfile should be ignored when package-lock is present"
        );
    }

    #[test]
    fn falls_back_to_node_modules_walk_when_no_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("node_modules/foo");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{"name":"foo","version":"1.2.3","license":"MIT"}"#,
        )
        .unwrap();
        let out = read(dir.path(), false, crate::scan_fs::ScanMode::Path).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "foo");
        assert_eq!(out[0].sbom_tier.as_deref(), Some("deployed"));
    }

    #[test]
    fn image_mode_discovers_node_modules_under_usr_src_app() {
        // Simulate a rootfs from a `node:*` image: installed tree lives
        // at /usr/src/app/node_modules/, no lockfile present.
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("usr/src/app");
        let nm = app.join("node_modules");
        let express = nm.join("express");
        std::fs::create_dir_all(&express).unwrap();
        std::fs::write(
            express.join("package.json"),
            r#"{"name":"express","version":"4.18.2","license":"MIT"}"#,
        )
        .unwrap();
        let out = read(dir.path(), false, crate::scan_fs::ScanMode::Path).unwrap();
        assert_eq!(out.len(), 1, "expected 1 entry from image-mode walk");
        assert_eq!(out[0].name, "express");
        assert_eq!(out[0].sbom_tier.as_deref(), Some("deployed"));
    }

    #[test]
    fn image_mode_discovers_global_npm_installs() {
        // Global installs live at /usr/lib/node_modules/ — typically a
        // single `npm`/`corepack`/similar tree on node base images.
        // Feature 005 US1: the npm self-root emits in --image mode and
        // carries `npm_role=internal`. --path mode is exercised in a
        // separate test that asserts zero emission.
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("usr/lib/node_modules/npm");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::write(
            global.join("package.json"),
            r#"{"name":"npm","version":"10.2.4","license":"Artistic-2.0"}"#,
        )
        .unwrap();
        let out = read(dir.path(), false, crate::scan_fs::ScanMode::Image).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "npm");
        assert_eq!(out[0].npm_role.as_deref(), Some("internal"));
    }

    #[test]
    fn monorepo_layout_discovers_each_workspace_package() {
        // Arbitrary layout — no image convention assumed. Root has a
        // lockfile (tier A fires there) and each service has only a
        // package.json (tier C design-tier fallback fires).
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Root: lockfile with one prod dep so tier A produces output.
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"monorepo","version":"0.0.0","workspaces":["services/*"]}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/shared-lib":{"version":"1.0.0"}}}"#,
        )
        .unwrap();

        // Sub-packages: package.json only, declaring unique deps.
        for (svc, dep) in [("api", "fastify"), ("web", "next"), ("worker", "bull")] {
            let svc_dir = root.join("services").join(svc);
            std::fs::create_dir_all(&svc_dir).unwrap();
            std::fs::write(
                svc_dir.join("package.json"),
                format!(
                    r#"{{"name":"@monorepo/{svc}","version":"0.0.0","dependencies":{{"{dep}":"^1.0"}}}}"#
                ),
            )
            .unwrap();
        }

        let out = read(root, false, crate::scan_fs::ScanMode::Path).unwrap();
        // Expect: 1 lockfile entry (shared-lib) + 3 design-tier deps
        // (fastify, next, bull). Each sub-package's own design-tier
        // entry for its own name is allowed but the names are distinct
        // PURLs so no dedup collision.
        let names: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"shared-lib"), "root lockfile: got {names:?}");
        assert!(names.contains(&"fastify"), "services/api: got {names:?}");
        assert!(names.contains(&"next"), "services/web: got {names:?}");
        assert!(names.contains(&"bull"), "services/worker: got {names:?}");
    }

    #[test]
    fn walk_skips_node_modules_subtrees() {
        // Deliberately plant a package.json *inside* a node_modules/ —
        // this is a dependency's manifest, not a project root. The
        // descent must skip node_modules so it doesn't get picked up.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("project")).unwrap();
        std::fs::write(
            root.join("project/package.json"),
            r#"{"name":"project","version":"0.0.0"}"#,
        )
        .unwrap();
        let nested = root.join("project/node_modules/some-dep");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("package.json"),
            r#"{"name":"some-dep","version":"2.0.0","dependencies":{"should-not-resurface":"*"}}"#,
        )
        .unwrap();

        let out = read(root, false, crate::scan_fs::ScanMode::Path).unwrap();
        assert!(
            !out.iter().any(|e| e.name == "should-not-resurface"),
            "descent into node_modules must not create bogus project roots"
        );
    }

    #[test]
    fn image_mode_deduplicates_purls_across_project_roots() {
        // When the same package appears in two discovered roots, the
        // reader emits it once.
        let dir = tempfile::tempdir().unwrap();
        for loc in ["app", "usr/src/app"] {
            let nm = dir.path().join(loc).join("node_modules/lodash");
            std::fs::create_dir_all(&nm).unwrap();
            std::fs::write(
                nm.join("package.json"),
                r#"{"name":"lodash","version":"4.17.21","license":"MIT"}"#,
            )
            .unwrap();
        }
        let out = read(dir.path(), false, crate::scan_fs::ScanMode::Path).unwrap();
        assert_eq!(out.len(), 1, "duplicate PURLs must be deduped");
        assert_eq!(out[0].name, "lodash");
    }

    #[test]
    fn root_pkgjson_fallback_fires_only_when_no_lockfile_no_nm() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"lodash":"^4.0"}}"#,
        )
        .unwrap();
        let out = read(dir.path(), false, crate::scan_fs::ScanMode::Path).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "lodash");
        assert_eq!(out[0].sbom_tier.as_deref(), Some("design"));
    }

    // ---- Feature 005 US1 --------------------------------------------------

    #[test]
    fn is_npm_internal_path_matches_canonical_glob() {
        use std::path::Path;
        // T017 — the canonical npm v7+ bundled tree layout. All these
        // paths contain a `node_modules → npm → node_modules` segment
        // run, which is the shape `is_npm_internal_path` matches.
        let cases_true: &[&str] = &[
            "usr/lib/node_modules/npm/node_modules/foo",
            "usr/local/lib/node_modules/npm/node_modules/@scope/bar",
            "opt/node/lib/node_modules/npm/node_modules/baz",
            // Nested — npm vendored inside an app's own tree (rare but
            // happens when a bundler ships a self-contained CLI).
            "app/node_modules/foo/node_modules/npm/node_modules/inner",
        ];
        for p in cases_true {
            assert!(
                is_npm_internal_path(Path::new(p)),
                "expected true for {}",
                p
            );
        }
        // README-style files directly under node_modules/npm (not inside
        // a further node_modules segment) are NOT internals — they're
        // metadata on the npm package itself.
        assert!(!is_npm_internal_path(Path::new("node_modules/npm/README.md")));
    }

    #[test]
    fn is_npm_internal_path_rejects_false_positives() {
        use std::path::Path;
        // T018 — paths that LOOK similar but don't match the required
        // three-segment `node_modules → npm → node_modules` sequence.
        let cases_false: &[&str] = &[
            "some/node_modules/foo",
            "etc/node_modules/something",
            // Directory name must be EXACTLY `npm`, not `npm-stuff` etc.
            "foo/npm-stuff/node_modules/bar",
            // `npm` directly under a non-`node_modules` parent isn't
            // the self-root.
            "usr/share/npm/node_modules/foo",
        ];
        for p in cases_false {
            assert!(
                !is_npm_internal_path(Path::new(p)),
                "expected false for {}",
                p
            );
        }
    }

    #[test]
    fn path_mode_excludes_npm_internals_from_read() {
        // T019 — the npm-internals tree must not contribute entries in
        // --path mode; the operator is scanning an application and
        // npm's own bundled deps are scanner tooling, not app deps.
        let dir = tempfile::tempdir().unwrap();
        let nested = dir
            .path()
            .join("usr/lib/node_modules/npm/node_modules/@npmcli/arborist");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("package.json"),
            r#"{"name":"@npmcli/arborist","version":"7.0.0"}"#,
        )
        .unwrap();
        // npm itself also has a package.json — that's part of the
        // self-root detection path.
        let npm_root = dir.path().join("usr/lib/node_modules/npm");
        std::fs::write(
            npm_root.join("package.json"),
            r#"{"name":"npm","version":"10.2.4"}"#,
        )
        .unwrap();
        let out = read(dir.path(), false, crate::scan_fs::ScanMode::Path).unwrap();
        assert!(
            out.iter().all(|e| e.name != "@npmcli/arborist"),
            "arborist should not appear in --path-mode output; got {:?}",
            out.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        assert!(
            out.iter().all(|e| e.name != "npm"),
            "npm self-root should not appear in --path-mode output"
        );
    }

    #[test]
    fn image_mode_includes_npm_internals_with_role() {
        // T020 — same fixture as T019, inverse mode. In --image mode
        // the internals ARE emitted and each carries
        // `npm_role = Some("internal")`.
        let dir = tempfile::tempdir().unwrap();
        let nested = dir
            .path()
            .join("usr/lib/node_modules/npm/node_modules/@npmcli/arborist");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("package.json"),
            r#"{"name":"@npmcli/arborist","version":"7.0.0"}"#,
        )
        .unwrap();
        let npm_root = dir.path().join("usr/lib/node_modules/npm");
        std::fs::write(
            npm_root.join("package.json"),
            r#"{"name":"npm","version":"10.2.4"}"#,
        )
        .unwrap();
        let out = read(dir.path(), false, crate::scan_fs::ScanMode::Image).unwrap();
        let arborist = out
            .iter()
            .find(|e| e.name == "@npmcli/arborist")
            .expect("arborist entry expected in --image mode");
        assert_eq!(arborist.npm_role.as_deref(), Some("internal"));
        let npm = out.iter().find(|e| e.name == "npm").expect("npm self-root expected");
        assert_eq!(npm.npm_role.as_deref(), Some("internal"));
    }
}