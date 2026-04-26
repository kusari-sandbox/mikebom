//! Shared project-root walker used by ecosystem readers that scan
//! arbitrary filesystem layouts (single project, container image,
//! monorepo, etc.) for ecosystem-specific project markers.
//!
//! pip and npm both use this today via per-ecosystem closures; future
//! readers (cargo workspace member discovery, gem multi-app, …) can
//! drop in the same way without re-implementing the symlink-safe
//! canonicalize-then-recurse machinery.
//!
//! Pre-shared, both readers carried a near-identical
//! `walk_for_*_roots` recursive function plus a per-ecosystem skip
//! predicate. The skip predicates also overlapped almost entirely —
//! they all want to skip installed-tree subtrees, hidden / VCS /
//! tooling dirs, and common build/cache outputs. The
//! [`should_skip_default_descent`] helper centralises that set;
//! each reader's closure can compose it with ecosystem-specific
//! additions (pip's `site-packages` for example).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Per-call configuration for [`walk_for_project_roots`].
pub(crate) struct WalkConfig<'a> {
    /// Max recursion depth. Readers typically pass `6` — enough for
    /// realistic monorepo + image layouts (`/usr/src/app/services/api/` =
    /// 4 levels) without running away into deep source trees.
    pub max_depth: usize,
    /// Predicate that returns true when `dir` looks like a project
    /// root for this ecosystem (e.g. has `pyproject.toml`, has
    /// `package.json`, etc.). The walker pushes `dir` to the output
    /// list when this returns true, but still recurses into
    /// children — a parent project + nested workspace package both
    /// qualify in their own right.
    pub is_project_root: &'a dyn Fn(&Path) -> bool,
    /// Predicate that returns true when the walker should NOT descend
    /// into a directory named `name`. Compose [`should_skip_default_descent`]
    /// with ecosystem-specific additions.
    pub should_skip: &'a dyn Fn(&str) -> bool,
}

/// Find every directory under `rootfs` (depth-limited) that
/// `cfg.is_project_root` accepts. Always includes `rootfs` itself
/// when it qualifies.
///
/// Symlink-safe via a canonicalize-keyed visited set; tolerant of
/// unreadable dirs (silently skips, rather than erroring out — a
/// scan of a partially-restricted filesystem still produces what
/// it can).
pub(crate) fn walk_for_project_roots(rootfs: &Path, cfg: &WalkConfig) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    walk_inner(rootfs, 0, cfg, &mut out, &mut visited);
    out
}

fn walk_inner(
    dir: &Path,
    depth: usize,
    cfg: &WalkConfig,
    out: &mut Vec<PathBuf>,
    visited: &mut HashSet<PathBuf>,
) {
    // Guard against symlink loops and duplicate enumeration. Use the
    // canonical path when available; fall back to `dir` as-is so a
    // missing dir doesn't silently swallow the scan.
    let key = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if !visited.insert(key) {
        return;
    }

    if (cfg.is_project_root)(dir) {
        out.push(dir.to_path_buf());
    }

    if depth >= cfg.max_depth {
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
        if (cfg.should_skip)(name) {
            continue;
        }
        walk_inner(&path, depth + 1, cfg, out, visited);
    }
}

/// Default skip-set: directory names that no ecosystem should
/// descend into when looking for project roots. Three reasons:
///
/// 1. **Installed-tree subtrees** — `node_modules/`, `vendor/`,
///    `bower_components/`. Their own manifests are already handled
///    by their parent project's installed-tree walker; descending
///    would produce N² false-positive "project roots".
/// 2. **Hidden / VCS / tooling dirs** — anything starting with `.`
///    (`.git/`, `.next/`, `.venv/`, `.cache/`, …). Never a project
///    root; always just noise.
/// 3. **Build outputs and language caches** — `target/` (Rust +
///    Maven), `dist/`, `build/`, `out/`, `coverage/`,
///    `__pycache__/`, `venv/`. Won't contain upstream-project
///    metadata worth re-reading.
///
/// Ecosystem-specific additions compose with this — e.g., pip
/// additionally skips `site-packages/` because its venv-walker
/// handles dist-info on a separate pass.
pub(crate) fn should_skip_default_descent(name: &str) -> bool {
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
