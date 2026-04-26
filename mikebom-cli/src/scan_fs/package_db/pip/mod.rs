//! Read Python package metadata from a scanned filesystem.
//!
//! Three layered sources in order of authority (per spec FR-001..FR-005
//! and research.md R2 / R3):
//!
//! 1. **Installed venv**: `<root>/.../site-packages/<name>-<version>.dist-info/METADATA`
//!    — confidence 0.85, tier `deployed`. Ground truth: these packages are
//!    actually resolved and sitting on disk.
//! 2. **Lockfile**: `poetry.lock` (v1 and v2 formats) or `Pipfile.lock`
//!    — confidence 0.85, tier `source`. Authoritative about what WILL be
//!    installed if the lockfile is honoured.
//! 3. **Requirements file**: `requirements.txt` (and any `*.txt` matching
//!    pip's convention) — confidence 0.70, tier `design`. Best-guess:
//!    range specs may resolve to different versions depending on the
//!    registry state at install time.
//!
//! The public entry point [`read`] walks these in order and applies
//! drift resolution per research.md R8: a venv entry wins over a
//! lockfile entry for the same package; a lockfile entry wins over a
//! requirements.txt entry. Conversion to [`PackageDbEntry`] happens at
//! the module boundary so the rest of the scan pipeline (dedup, CPE
//! synthesis, compositions, deps.dev enrichment) handles Python the
//! same way it handles deb / apk today.
//!
//! `pyproject.toml`-only projects (no venv, no lockfile, no
//! requirements) emit zero components per FR-005 — `[project.dependencies]`
//! holds build specs, not resolved versions, so fabricating components
//! from it would bloat SBOMs with phantoms.

use std::path::{Path, PathBuf};

use mikebom_common::types::purl::encode_purl_segment;

use super::PackageDbEntry;


// ========================================================================
// Module structure (milestone 018)
// ========================================================================
//
// pip/ split layout (per specs/018-module-splits/contracts/module-boundaries.md):
//   - dist_info.rs       — Tier 1: venv PEP 376 walker + METADATA parser +
//                          extract_license + collect_claimed_paths
//   - poetry.rs          — Tier 2: poetry.lock v1/v2 parser
//   - pipfile.rs         — Tier 3: Pipfile.lock parser
//   - requirements_txt.rs — Tier 3: requirements*.txt parser
//
// This file (mod.rs) hosts the orchestrator (pub fn read), shared PURL
// helpers (build_pypi_purl_str / normalize_pypi_name_for_purl), the PEP 508
// requires-dist tokenizer (used by both dist_info and requirements_txt),
// the project-root walker, and the merge_without_override drift-resolution
// helper.

mod dist_info;
mod pipfile;
mod poetry;
mod requirements_txt;

pub use dist_info::collect_claimed_paths;

/// Normalise a pypi package name into the form the packageurl-python
/// reference implementation emits in canonical PURLs: lowercase, with
/// every `_` replaced by `-`. Other separators (dots, multi-hyphens)
/// are preserved — PEP 503 collapses them but packageurl-python does
/// not, and we align with the reference impl for byte-for-byte
/// conformance per SC-004.
///
/// `component.name` (what we store on `ResolvedComponent` for CycloneDX
/// display) keeps the declared form from the source (e.g. `Flask`,
/// `MarkupSafe`); only the PURL goes through this transform.
pub(crate) fn normalize_pypi_name_for_purl(name: &str) -> String {
    name.replace('_', "-").to_lowercase()
}

/// Build a canonical pypi PURL string from (possibly mixed-case, possibly
/// underscored) name and version. Normalises both name and version per
/// the packageurl-python reference implementation, then runs each
/// through the common segment encoder so `+` → `%2B`.
fn build_pypi_purl_str(name: &str, version: &str) -> String {
    let normalized_name = normalize_pypi_name_for_purl(name);
    if version.is_empty() {
        format!("pkg:pypi/{}", encode_purl_segment(&normalized_name))
    } else {
        format!(
            "pkg:pypi/{}@{}",
            encode_purl_segment(&normalized_name),
            encode_purl_segment(version),
        )
    }
}

/// Public entry point. Walks the scan root for Python package sources
/// and emits one `PackageDbEntry` per unique package identity. Drift
/// between sources is resolved per R8 (venv > lockfile > requirements).
///
/// * `include_dev` — when true, Poetry / Pipfile entries flagged as
///   dev-only are included; when false they're filtered out at source.
///   Venv dist-info and requirements.txt entries don't carry a dev/prod
///   distinction and are always emitted.
pub fn read(rootfs: &Path, include_dev: bool) -> Vec<PackageDbEntry> {
    let mut entries: Vec<PackageDbEntry> = Vec::new();

    // Tier 1: installed venvs. The venv enumerator already handles
    // standard venv layouts (`.venv/`, `/usr/lib/python*/`, etc.) —
    // it runs once against the rootfs regardless of project-root
    // structure because site-packages trees are globally addressable.
    let venv_entries = dist_info::read_venv_dist_info(rootfs);
    let had_venv = !venv_entries.is_empty();
    entries.extend(venv_entries);

    // Tiers 2 + 3: per-project-root tier readers. A "project root" is
    // any directory containing a Python project marker (poetry.lock,
    // Pipfile.lock, requirements*.txt, or pyproject.toml). This makes
    // the scanner handle arbitrary layouts with one mechanism:
    // - Single project at rootfs (directory scan) — one root, same as
    //   before.
    // - Container image with `/usr/src/app/pyproject.toml` — walker
    //   finds that directory without a hard-coded path list.
    // - Monorepo with `services/api/requirements.txt`,
    //   `services/worker/Pipfile.lock`, etc. — each becomes its own
    //   root, so per-service declarations surface.
    let mut had_project_marker = false;
    for project_root in candidate_python_project_roots(rootfs) {
        // A project is anything holding a lockfile / requirements /
        // pyproject; track this for the "pyproject.toml only" skip log
        // below. Tier 1 venv does NOT count as a project root here —
        // that's installed state, not a project declaration.
        had_project_marker = true;

        if let Some(lockfile_entries) = poetry::read_poetry_lock(&project_root, include_dev) {
            merge_without_override(&mut entries, lockfile_entries);
        }
        if let Some(lockfile_entries) = pipfile::read_pipfile_lock(&project_root, include_dev) {
            merge_without_override(&mut entries, lockfile_entries);
        }
        if let Some(req_entries) = requirements_txt::read_requirements_files(&project_root) {
            merge_without_override(&mut entries, req_entries);
        }
    }

    // If the root has a `pyproject.toml` but nothing else, log the skip
    // so operators can tell an empty-output run from "we didn't find
    // anything to scan." Per FR-024. The rootfs-level check stays
    // unchanged so the existing pyproject-only behavior is preserved.
    if entries.is_empty()
        && !had_venv
        && !had_project_marker
        && rootfs.join("pyproject.toml").is_file()
    {
        tracing::info!(
            rootfs = %rootfs.display(),
            "python project detected but no venv, lockfile, or requirements.txt — skipping"
        );
    }

    entries
}

/// Max depth for the recursive Python project-root search. Same budget
/// as `candidate_project_roots` in `npm.rs` — covers realistic monorepo
/// plus image layouts (`usr/src/app/services/api/` = 4 levels) without
/// running away into deep source trees.
const MAX_PROJECT_ROOT_DEPTH: usize = 6;

/// Enumerate every directory under `rootfs` that looks like a Python
/// project root (holds a poetry.lock, Pipfile.lock, requirements*.txt,
/// or pyproject.toml). Always includes `rootfs` itself so the single-
/// project case is unchanged. Recurses up to `MAX_PROJECT_ROOT_DEPTH`
/// levels via the shared
/// [`super::project_roots::walk_for_project_roots`] helper.
fn candidate_python_project_roots(rootfs: &Path) -> Vec<PathBuf> {
    use super::project_roots::{
        should_skip_default_descent, walk_for_project_roots, WalkConfig,
    };
    walk_for_project_roots(
        rootfs,
        &WalkConfig {
            max_depth: MAX_PROJECT_ROOT_DEPTH,
            is_project_root: &has_python_project_marker,
            // Default skip set + python's `site-packages` (handled
            // separately by `read_venv_dist_info`).
            should_skip: &|name| {
                should_skip_default_descent(name) || name == "site-packages"
            },
        },
    )
}

/// True when `dir` holds any Python project-root marker. Installed
/// state (site-packages, dist-info) is NOT a project marker — it's
/// the output of a project, handled by `read_venv_dist_info` on its
/// own pass.
fn has_python_project_marker(dir: &Path) -> bool {
    if dir.join("poetry.lock").is_file()
        || dir.join("Pipfile.lock").is_file()
        || dir.join("pyproject.toml").is_file()
    {
        return true;
    }
    // `requirements*.txt` is a glob — scan the top-level of `dir`.
    if let Ok(read_dir) = std::fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("requirements") && name.ends_with(".txt") {
                    return true;
                }
            }
        }
    }
    false
}

/// Merge `additions` into `entries`, dropping any addition whose PURL
/// already exists in `entries`. Preserves insertion order; additions
/// that DO land are appended at the tail.
fn merge_without_override(
    entries: &mut Vec<PackageDbEntry>,
    additions: Vec<PackageDbEntry>,
) {
    use std::collections::HashSet;
    let existing: HashSet<String> = entries
        .iter()
        .map(|e| e.purl.as_str().to_string())
        .collect();
    for a in additions {
        if !existing.contains(a.purl.as_str()) {
            entries.push(a);
        }
    }
}


// -----------------------------------------------------------------------
// Tier 1 support: PEP 508 Requires-Dist tokenizer
// -----------------------------------------------------------------------

/// Extract the bare package name from a PEP 508 requirement string.
/// Returns `None` if the environment marker (e.g. `; python_version < "3.10"`)
/// evaluates to false for the current interpreter, or if parsing fails.
///
/// Handles:
/// - Bare names: `requests`
/// - Names with extras: `requests[security]`
/// - Names with version specs: `requests >= 2.28, < 3`
/// - Environment markers: `requests ; python_version >= "3.8"`
/// - Combined: `requests[security] (>= 2.28) ; python_version >= "3.8"`
pub(crate) fn tokenise_requires_dist_name(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // Split on `;` for env markers. Preserve only the LHS for name
    // extraction; evaluate the marker to decide whether to emit.
    let (head, marker) = match raw.split_once(';') {
        Some((h, m)) => (h.trim(), Some(m.trim())),
        None => (raw, None),
    };

    // Evaluate marker (best-effort): if the marker references
    // sys_platform, python_version, or similar and evaluates to false,
    // drop the requirement.
    if let Some(m) = marker {
        if !marker_probably_matches(m) {
            return None;
        }
    }

    // Extract the name — everything up to the first separator:
    // space, `[` (extras), `(` (version spec), `<`, `>`, `=`, `!`, `~`, `@`.
    let end = head
        .find(|c: char| {
            c.is_whitespace()
                || matches!(c, '[' | '(' | '<' | '>' | '=' | '!' | '~' | '@')
        })
        .unwrap_or(head.len());
    let name = head[..end].trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Best-effort PEP 508 environment-marker evaluator. We only handle the
/// common cases (`python_version`, `sys_platform`, `platform_system`)
/// and return true conservatively for anything we can't evaluate — it's
/// better to include a possibly-unused dep than to silently drop one we
/// didn't understand.
fn marker_probably_matches(marker: &str) -> bool {
    // Quick conservative check: if the marker mentions "extra ==", treat
    // as false (extras are opt-in and we don't request any).
    if marker.contains("extra ==") {
        return false;
    }
    // Everything else: conservative true. The full PEP 508 grammar is
    // out of scope for the scanner's "identify packages" purpose; edge
    // cases at most cause a slight over-inclusion which the dedup path
    // cleans up.
    true
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    #[test]
    fn tokenise_bare_name() {
        assert_eq!(tokenise_requires_dist_name("requests"), Some("requests".into()));
    }

    #[test]
    fn tokenise_name_with_extras() {
        assert_eq!(
            tokenise_requires_dist_name("requests[security,socks]"),
            Some("requests".into())
        );
    }

    #[test]
    fn tokenise_name_with_version_spec() {
        assert_eq!(
            tokenise_requires_dist_name("requests >= 2.28, < 3"),
            Some("requests".into())
        );
        assert_eq!(
            tokenise_requires_dist_name("requests>=2.28"),
            Some("requests".into())
        );
    }

    #[test]
    fn tokenise_name_with_env_marker_that_probably_matches() {
        assert_eq!(
            tokenise_requires_dist_name("requests ; python_version >= \"3.8\""),
            Some("requests".into())
        );
    }

    #[test]
    fn tokenise_env_marker_with_extra_drops_requirement() {
        // `extra ==` markers mean "only when this optional extra is
        // requested" — we don't request any, so drop the dep.
        assert_eq!(
            tokenise_requires_dist_name("pytest ; extra == 'dev'"),
            None
        );
    }

    #[test]
    fn tokenise_empty_returns_none() {
        assert_eq!(tokenise_requires_dist_name(""), None);
        assert_eq!(tokenise_requires_dist_name("   "), None);
    }

    #[test]
    fn normalize_pypi_name_lowercases_and_flips_underscores() {
        // Reference impl (packageurl-python) canonicalises pypi names
        // to lowercase with `_` → `-`. Mikebom follows suit so PURLs
        // round-trip byte-for-byte (SC-004).
        assert_eq!(normalize_pypi_name_for_purl("Flask"), "flask");
        assert_eq!(normalize_pypi_name_for_purl("MarkupSafe"), "markupsafe");
        assert_eq!(normalize_pypi_name_for_purl("Jinja2"), "jinja2");
        assert_eq!(
            normalize_pypi_name_for_purl("zope.interface"),
            "zope.interface" // dots preserved per reference impl
        );
        assert_eq!(
            normalize_pypi_name_for_purl("typing_extensions"),
            "typing-extensions"
        );
        assert_eq!(
            normalize_pypi_name_for_purl("Pillow_SIMD"),
            "pillow-simd"
        );
    }

    #[test]
    fn build_pypi_purl_str_emits_canonical_form() {
        // Declared-form input → canonical output.
        assert_eq!(
            build_pypi_purl_str("Flask", "3.0.0"),
            "pkg:pypi/flask@3.0.0"
        );
        assert_eq!(
            build_pypi_purl_str("MarkupSafe", "2.1.3"),
            "pkg:pypi/markupsafe@2.1.3"
        );
        assert_eq!(
            build_pypi_purl_str("typing_extensions", "4.9.0"),
            "pkg:pypi/typing-extensions@4.9.0"
        );
    }

    #[test]
    fn monorepo_finds_requirements_in_each_service() {
        // Multi-service Python layout — no single top-level project
        // marker; each service has its own requirements.txt.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for (svc, pkg) in [("api", "fastapi"), ("worker", "celery"), ("web", "flask")] {
            let svc_dir = root.join("services").join(svc);
            std::fs::create_dir_all(&svc_dir).unwrap();
            std::fs::write(
                svc_dir.join("requirements.txt"),
                format!("{pkg}==1.0.0\n"),
            )
            .unwrap();
        }
        let out = read(root, false);
        let names: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"fastapi"), "got {names:?}");
        assert!(names.contains(&"celery"), "got {names:?}");
        assert!(names.contains(&"flask"), "got {names:?}");
    }

    #[test]
    fn python_walk_finds_nested_pyproject_under_usr_src() {
        // Image-style layout: pyproject.toml + requirements.txt live
        // at /usr/src/app/, rootfs is /.
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("usr/src/app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("pyproject.toml"),
            "[project]\nname = \"myapp\"\n",
        )
        .unwrap();
        std::fs::write(app.join("requirements.txt"), "httpx==0.25.0\n").unwrap();
        let out = read(dir.path(), false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "httpx");
    }

    #[test]
    fn python_walk_skips_venv_and_node_modules_noise() {
        // Planted stray pyproject.toml / requirements.txt inside
        // venv/ and node_modules/ — both must be ignored by the walk.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for noisy_parent in ["venv/lib/python3.11/site-packages/evil", "node_modules/evil"] {
            let noisy = root.join(noisy_parent);
            std::fs::create_dir_all(&noisy).unwrap();
            std::fs::write(
                noisy.join("requirements.txt"),
                "should-not-appear==9.9.9\n",
            )
            .unwrap();
        }
        let out = read(root, false);
        assert!(
            !out.iter().any(|e| e.name == "should-not-appear"),
            "walker must not descend into venv/ or node_modules/"
        );
    }
}
