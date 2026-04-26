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
        if let Some(lockfile_entries) = package_lock::read_package_lock(&project_root, include_dev) {
            project_entries.extend(lockfile_entries);
        } else if let Some(pnpm_entries) = pnpm_lock::read_pnpm_lock(&project_root, include_dev) {
            project_entries.extend(pnpm_entries);
        }

        // Post-Tier-A author enrichment: lockfiles (v2/v3 and
        // pnpm-lock.yaml) don't carry per-package author, but when a
        // `node_modules/` tree is present alongside (typical
        // post-`npm install`), the installed `package.json` does.
        // Walk the tree and overlay `maintainer` onto matching
        // components by PURL. This is additive — it doesn't change
        // versions or add components beyond what the lockfile
        // declared.
        if !project_entries.is_empty() {
            enrich::enrich_entries_with_installed_authors(&project_root, &mut project_entries);
        }

        // Tier B: flat node_modules walk (fires when the lockfile didn't
        // produce anything — typical for images where the lockfile has
        // been stripped at build time but the installed tree remains).
        if project_entries.is_empty() {
            if let Some(nm_entries) = walk::read_node_modules(&project_root, scan_mode) {
                project_entries.extend(nm_entries);
            }
        }

        // Tier C: root package.json fallback (FR-007a).
        if project_entries.is_empty() {
            if let Some(fb_entries) = walk::read_root_package_json(&project_root, include_dev) {
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
    use super::project_roots::{
        should_skip_default_descent, walk_for_project_roots, WalkConfig,
    };
    walk_for_project_roots(
        rootfs,
        &WalkConfig {
            max_depth: MAX_PROJECT_ROOT_DEPTH,
            is_project_root: &has_npm_signal,
            should_skip: &should_skip_default_descent,
        },
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
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        Some(Self {
            algorithm: alg_upper.to_string(),
            hex,
        })
    }

    /// Convert to a `ContentHash`. Maps the SRI algorithm to mikebom's
    /// `HashAlgorithm` enum and validates hex length via the shared
    /// `with_algorithm` constructor. SHA-512 and SHA-256 are by far
    /// the dominant algorithms in npm lockfiles; SHA-384 and SHA-1
    /// also pass through.
    pub(crate) fn to_content_hash(&self) -> Option<ContentHash> {
        use mikebom_common::types::hash::HashAlgorithm;
        let alg = match self.algorithm.as_str() {
            "SHA-256" => HashAlgorithm::Sha256,
            "SHA-512" => HashAlgorithm::Sha512,
            "SHA-1" => HashAlgorithm::Sha1,
            // SHA-384 isn't in HashAlgorithm yet; defer.
            _ => return None,
        };
        ContentHash::with_algorithm(alg, &self.hex).ok()
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


// ========================================================================
// Module structure (milestone 018 / US2)
// ========================================================================
//
// npm/ split layout:
//   - package_lock.rs — package-lock.json v2/v3 parser
//   - pnpm_lock.rs    — pnpm-lock.yaml parser
//   - walk.rs         — node_modules walker + read_root_package_json + classifier
//   - enrich.rs       — author backfill from installed package.json files
//
// This file (mod.rs) hosts the orchestrator (pub fn read), error type
// (NpmError), project-root walker, integrity-string parser, base64 helper,
// and the cross-section build_npm_purl helper (used by every parser).
mod enrich;
mod package_lock;
mod pnpm_lock;
mod walk;

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

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
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
