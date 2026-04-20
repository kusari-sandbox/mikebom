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

use mikebom_common::types::license::SpdxExpression;
use mikebom_common::types::purl::{encode_purl_segment, Purl};

use super::PackageDbEntry;

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
    let venv_entries = read_venv_dist_info(rootfs);
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

        if let Some(lockfile_entries) = read_poetry_lock(&project_root, include_dev) {
            merge_without_override(&mut entries, lockfile_entries);
        }
        if let Some(lockfile_entries) = read_pipfile_lock(&project_root, include_dev) {
            merge_without_override(&mut entries, lockfile_entries);
        }
        if let Some(req_entries) = read_requirements_files(&project_root) {
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
/// + image layouts (`usr/src/app/services/api/` = 4 levels) without
/// running away into deep source trees.
const MAX_PROJECT_ROOT_DEPTH: usize = 6;

/// Enumerate every directory under `rootfs` that looks like a Python
/// project root (holds a poetry.lock, Pipfile.lock, requirements*.txt,
/// or pyproject.toml). Always includes `rootfs` itself so the single-
/// project case is unchanged. Recurses up to `MAX_PROJECT_ROOT_DEPTH`
/// levels, pruning installed-tree / VCS / cache directories so the
/// walk stays bounded on real-world trees.
///
/// Mirrors the npm walk: symlink-loop safe, skips dotfiles, skips
/// known heavy subtrees (`node_modules/`, `target/`, `dist/`, `venv/`,
/// `__pycache__/`, etc.).
fn candidate_python_project_roots(rootfs: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut visited: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    walk_for_python_roots(rootfs, 0, &mut out, &mut visited);
    out
}

fn walk_for_python_roots(
    dir: &Path,
    depth: usize,
    out: &mut Vec<PathBuf>,
    visited: &mut std::collections::HashSet<PathBuf>,
) {
    let key = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if !visited.insert(key) {
        return;
    }

    if has_python_project_marker(dir) {
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
        if should_skip_python_descent(name) {
            continue;
        }
        walk_for_python_roots(&path, depth + 1, out, visited);
    }
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

/// Directory names the Python walker refuses to descend into. Mirrors
/// the npm walker's skip set plus Python-specific caches (`venv/`,
/// `.venv/` via the dotfile rule, `__pycache__/`, `.tox/`, `.nox/`,
/// `.pytest_cache/` via the dotfile rule).
fn should_skip_python_descent(name: &str) -> bool {
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
            | "site-packages"
    )
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
// Tier 1: venv dist-info walker
// -----------------------------------------------------------------------

/// Iterate every dist-info `RECORD` file under every candidate
/// site-packages directory and insert each listed file (rootfs-joined
/// absolute path) into `claimed`. Milestone 004 post-ship fix for the
/// binary-walker double-counting of pip-installed cpython extensions.
///
/// RECORD format (PEP 376 / PEP 627): CSV where column 0 is the file
/// path relative to site-packages (forward slashes). We ignore the
/// remaining columns (hash + size — not needed for claim tracking).
///
/// No-op when no site-packages exists. Malformed CSV lines are
/// tolerated (partial claims, not scan failure).
pub fn collect_claimed_paths(
    rootfs: &Path,
    claimed: &mut std::collections::HashSet<std::path::PathBuf>,
    #[cfg(unix)] claimed_inodes: &mut std::collections::HashSet<(u64, u64)>,
) {
    for site_packages in candidate_site_packages_roots(rootfs) {
        if !site_packages.is_dir() {
            continue;
        }
        let Ok(read_dir) = std::fs::read_dir(&site_packages) else {
            continue;
        };
        for entry in read_dir.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("dist-info") {
                continue;
            }
            let record = p.join("RECORD");
            let Ok(content) = std::fs::read_to_string(&record) else {
                continue;
            };
            for line in content.lines() {
                // First field = path relative to site-packages.
                let Some(rel) = line.split(',').next() else {
                    continue;
                };
                let rel = rel.trim();
                if rel.is_empty() {
                    continue;
                }
                // Resolve path: site-packages + rel. Some RECORD
                // entries use `../` to escape for shared data
                // (`../../../bin/jq` etc.) — preserve that form.
                let abs = site_packages.join(rel);
                super::insert_claim_with_canonical(
                    claimed,
                    #[cfg(unix)]
                    claimed_inodes,
                    abs,
                );
            }
        }
    }
}

/// Walk candidate `site-packages/` locations under `rootfs` and parse
/// every `<name>-<version>.dist-info/METADATA` we find.
fn read_venv_dist_info(rootfs: &Path) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();
    for root in candidate_site_packages_roots(rootfs) {
        if !root.is_dir() {
            continue;
        }
        let Ok(read_dir) = std::fs::read_dir(&root) else {
            continue;
        };
        let mut names: Vec<PathBuf> = read_dir
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|ext| ext == "dist-info")
            })
            .collect();
        names.sort(); // determinism
        for dist_info in names {
            if let Some(entry) = parse_dist_info_dir(&dist_info) {
                out.push(entry);
            }
        }
    }
    out
}

/// Enumerate likely `site-packages/` locations. Covers:
/// - `<root>/.venv/lib/python*/site-packages/`
/// - `<root>/venv/lib/python*/site-packages/`
/// - `<root>/usr/lib/python*/dist-packages/` (Debian system python)
/// - `<root>/usr/lib/python*/site-packages/`
/// - `<root>/usr/local/lib/python*/site-packages/`
/// - `<root>/opt/app/.venv/lib/python*/site-packages/`
fn candidate_site_packages_roots(rootfs: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for venv in [".venv", "venv"] {
        out.extend(find_site_packages_under(&rootfs.join(venv).join("lib")));
    }
    for sys in ["usr/lib", "usr/local/lib", "opt/app/.venv/lib"] {
        out.extend(find_site_packages_under(&rootfs.join(sys)));
    }
    out
}

/// `<base>/python3.X/site-packages/` OR `<base>/python3.X/dist-packages/`.
/// Glob-equivalent for `python*/site-packages/` and `python*/dist-packages/`.
fn find_site_packages_under(base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !base.is_dir() {
        return out;
    }
    let Ok(read_dir) = std::fs::read_dir(base) else {
        return out;
    };
    for entry in read_dir.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.starts_with("python") {
            continue;
        }
        for leaf in ["site-packages", "dist-packages"] {
            let candidate = entry.path().join(leaf);
            if candidate.is_dir() {
                out.push(candidate);
            }
        }
    }
    out
}

/// Parse one `<name>-<version>.dist-info/` directory. Returns None if
/// the METADATA file is absent or unreadable.
fn parse_dist_info_dir(dist_info: &Path) -> Option<PackageDbEntry> {
    let metadata_path = dist_info.join("METADATA");
    let bytes = std::fs::read(&metadata_path).ok()?;
    let parsed = parse_metadata_bytes(&bytes);
    parsed.into_package_db_entry(metadata_path.to_string_lossy().into_owned())
}

// -----------------------------------------------------------------------
// Tier 1 support: PipDistInfoEntry + METADATA parser
// -----------------------------------------------------------------------

/// Parsed content of a single `dist-info/METADATA` file. Intermediate
/// representation; converted to [`PackageDbEntry`] at the module
/// boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PipDistInfoEntry {
    pub name: String,
    pub version: String,
    pub license_expression: Option<String>, // PEP 639 `License-Expression:`
    pub license_raw: Option<String>,        // legacy `License:`
    pub classifiers: Vec<String>,           // `Classifier: License :: ...`
    pub requires_dist: Vec<String>,         // raw PEP 508 strings
    pub author: Option<String>,
    pub author_email: Option<String>,
}

impl PipDistInfoEntry {
    /// Convert to the scan-pipeline's `PackageDbEntry` shape.
    fn into_package_db_entry(self, source_path: String) -> Option<PackageDbEntry> {
        if self.name.is_empty() || self.version.is_empty() {
            return None;
        }
        let purl_str = build_pypi_purl_str(&self.name, &self.version);
        let purl = Purl::new(&purl_str).ok()?;

        // Author / Author-email concatenated into supplier text.
        let supplier = match (&self.author, &self.author_email) {
            (Some(n), Some(e)) if !e.is_empty() => Some(format!("{n} <{e}>")),
            (Some(n), _) => Some(n.clone()),
            (None, Some(e)) if !e.is_empty() => Some(e.clone()),
            _ => None,
        };

        // Depends: bare names from Requires-Dist (PEP 508 tokenised).
        let depends = self
            .requires_dist
            .iter()
            .filter_map(|raw| tokenise_requires_dist_name(raw))
            .collect();

        let licenses = extract_license(&self);

        Some(PackageDbEntry {
            purl,
            name: self.name,
            version: self.version,
            arch: None,
            source_path,
            depends,
            maintainer: supplier,
            licenses,
            is_dev: None, // venv dist-info doesn't carry a dev/prod marker
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
            sbom_tier: Some("deployed".to_string()),
        })
    }
}

// -----------------------------------------------------------------------
// Tier 1 support: license precedence ladder (PEP 639 → legacy → classifier)
// -----------------------------------------------------------------------

/// Resolve license(s) from a `PipDistInfoEntry` per research.md R2.
/// Precedence: `License-Expression:` (PEP 639) → `License:` (legacy
/// free-form, passed through the copyright-shorthand normaliser) →
/// `Classifier: License ::` trove list. Returns at most one SPDX
/// expression from the first tier that produces a canonicalisable
/// value; empty Vec when nothing resolves.
pub(crate) fn extract_license(entry: &PipDistInfoEntry) -> Vec<SpdxExpression> {
    // Tier 1: PEP 639 — authoritative, SPDX by construction.
    if let Some(ref raw) = entry.license_expression {
        if let Ok(spdx) = SpdxExpression::try_canonical(raw.trim()) {
            return vec![spdx];
        }
    }
    // Tier 2: legacy `License:` free-form. Try canonical first.
    if let Some(ref raw) = entry.license_raw {
        let cleaned = raw.trim();
        if !cleaned.is_empty() {
            if let Ok(spdx) = SpdxExpression::try_canonical(cleaned) {
                return vec![spdx];
            }
        }
    }
    // Tier 3: classifier trove → SPDX lookup.
    for c in &entry.classifiers {
        if let Some(spdx) = classifier_to_spdx(c) {
            if let Ok(expr) = SpdxExpression::try_canonical(spdx) {
                return vec![expr];
            }
        }
    }
    Vec::new()
}

/// Map a `Classifier: License :: ...` trove string to the closest
/// canonical SPDX identifier. Table covers >95% of real-world PyPI
/// packages per research R2. Unknown classifiers return None.
pub(crate) fn classifier_to_spdx(classifier: &str) -> Option<&'static str> {
    // Classifiers look like "License :: OSI Approved :: MIT License".
    // Care about the last segment only.
    let last = classifier.rsplit("::").next()?.trim();
    Some(match last {
        "MIT License" => "MIT",
        "Apache Software License" => "Apache-2.0",
        "BSD License" => "BSD-3-Clause",
        "BSD 3-Clause" | "BSD 3-Clause License" => "BSD-3-Clause",
        "BSD 2-Clause" | "BSD 2-Clause License" => "BSD-2-Clause",
        "Mozilla Public License 2.0 (MPL 2.0)" => "MPL-2.0",
        "ISC License (ISCL)" => "ISC",
        "zlib/libpng License" => "Zlib",
        "Python Software Foundation License" => "Python-2.0",
        "GNU General Public License v2 (GPLv2)" => "GPL-2.0-only",
        "GNU General Public License v2 or later (GPLv2+)" => "GPL-2.0-or-later",
        "GNU General Public License v3 (GPLv3)" => "GPL-3.0-only",
        "GNU General Public License v3 or later (GPLv3+)" => "GPL-3.0-or-later",
        "GNU Lesser General Public License v2 (LGPLv2)" => "LGPL-2.0-only",
        "GNU Lesser General Public License v2 or later (LGPLv2+)" => "LGPL-2.0-or-later",
        "GNU Lesser General Public License v3 (LGPLv3)" => "LGPL-3.0-only",
        "GNU Lesser General Public License v3 or later (LGPLv3+)" => "LGPL-3.0-or-later",
        "GNU Affero General Public License v3" => "AGPL-3.0-only",
        "GNU Affero General Public License v3 or later (AGPLv3+)" => "AGPL-3.0-or-later",
        "Artistic License" => "Artistic-2.0",
        "The Unlicense (Unlicense)" => "Unlicense",
        _ => return None,
    })
}

/// Parse a METADATA file body. Tolerates non-UTF-8 by falling back to
/// lossy decoding (consistent with `copyright.rs` convention).
pub(crate) fn parse_metadata_bytes(bytes: &[u8]) -> PipDistInfoEntry {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    };
    parse_metadata_text(&text)
}

/// Parse METADATA as RFC-822-style stanzas with continuation-line
/// support: a line starting with a space/tab continues the previous
/// key's value. Multiple occurrences of the same key collect into a
/// list (e.g. `Classifier:` appears many times).
pub(crate) fn parse_metadata_text(text: &str) -> PipDistInfoEntry {
    let mut out = PipDistInfoEntry::default();

    // Only the header block matters; stop at the first blank line
    // which separates headers from the payload (description / README).
    let mut current_key: Option<String> = None;
    let mut current_value = String::new();

    let flush = |key_opt: &mut Option<String>, value: &mut String, out: &mut PipDistInfoEntry| {
        if let Some(key) = key_opt.take() {
            let v = std::mem::take(value).trim().to_string();
            match key.as_str() {
                "Name" => out.name = v,
                "Version" => out.version = v,
                "License" => {
                    if !v.is_empty() {
                        out.license_raw = Some(v);
                    }
                }
                "License-Expression" => {
                    if !v.is_empty() {
                        out.license_expression = Some(v);
                    }
                }
                "Classifier" => {
                    if !v.is_empty() {
                        out.classifiers.push(v);
                    }
                }
                "Requires-Dist" => {
                    if !v.is_empty() {
                        out.requires_dist.push(v);
                    }
                }
                "Author" => {
                    if !v.is_empty() {
                        out.author = Some(v);
                    }
                }
                "Author-email" => {
                    if !v.is_empty() {
                        out.author_email = Some(v);
                    }
                }
                _ => {}
            }
        }
    };

    for line in text.lines() {
        if line.is_empty() {
            // End of headers; stop parsing.
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line — append to current value with a space.
            if current_key.is_some() {
                if !current_value.is_empty() {
                    current_value.push(' ');
                }
                current_value.push_str(line.trim());
            }
            continue;
        }
        // Fresh header.
        flush(&mut current_key, &mut current_value, &mut out);
        if let Some(idx) = line.find(':') {
            let (key, rest) = line.split_at(idx);
            current_key = Some(key.to_string());
            current_value = rest[1..].trim().to_string();
        }
    }
    flush(&mut current_key, &mut current_value, &mut out);
    out
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

// -----------------------------------------------------------------------
// Tier 2: Poetry lockfile (v1 + v2)
// -----------------------------------------------------------------------

/// Read `<rootfs>/poetry.lock` if present. Returns None when absent or
/// unparseable. Dispatches on the top-level `[metadata] lock-version`
/// field to handle both v1 (`"1.1"` / `"1.2"`) and v2 (`"2.0"` / `"2.1"`)
/// shapes.
fn read_poetry_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>> {
    let path = rootfs.join("poetry.lock");
    let text = std::fs::read_to_string(&path).ok()?;
    let parsed: toml::Value = match toml::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(path = %path.display(), error = %e, "poetry.lock parse failed");
            return None;
        }
    };
    let source_path = path.to_string_lossy().into_owned();
    Some(parse_poetry_lock(&parsed, &source_path, include_dev))
}

/// Parse an already-deserialised `poetry.lock` TOML document.
/// Public-in-module for unit testing.
pub(crate) fn parse_poetry_lock(
    root: &toml::Value,
    source_path: &str,
    include_dev: bool,
) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();

    // [[package]] array-of-tables.
    let Some(packages) = root.get("package").and_then(|v| v.as_array()) else {
        return out;
    };

    for pkg in packages {
        let Some(tbl) = pkg.as_table() else {
            continue;
        };
        let name = tbl.get("name").and_then(|v| v.as_str()).unwrap_or("").trim();
        let version = tbl.get("version").and_then(|v| v.as_str()).unwrap_or("").trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }

        // Dev detection:
        // v1: `category = "main"` (prod) / `"dev"` (dev)
        // v2+: `groups = ["main", ...]` — prod if "main" is present.
        let is_dev = poetry_is_dev(tbl);

        // Honour the dev filter at source.
        if is_dev == Some(true) && !include_dev {
            continue;
        }

        // Nested dependencies table — keys are the dep names.
        let depends = tbl
            .get("dependencies")
            .and_then(|v| v.as_table())
            .map(|t| t.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        // Per-package hashes from `[[package.files]]`.
        let hashes = tbl
            .get("files")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| f.as_table()?.get("hash")?.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let purl_str = build_pypi_purl_str(name, version);
        let Ok(purl) = Purl::new(&purl_str) else {
            continue;
        };

        out.push(PackageDbEntry {
            purl,
            name: name.to_string(),
            version: version.to_string(),
            arch: None,
            source_path: source_path.to_string(),
            depends,
            maintainer: None,
            licenses: Vec::new(),
            is_dev,
            requirement_range: None,
            source_type: None,
            // Lockfile entries are pre-build declarations of what WILL
            // be installed, not what IS installed. Tier = "source" per
            // research.md R13.
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
        // `hashes` currently collected but not wired into ContentHash;
        // hash propagation from lockfiles is a follow-up (would need
        // SRI-style string parsing like npm integrity). The variable
        // is held in-scope as documentation of the intent.
        let _ = hashes;
    }

    out
}

/// Determine the dev-flag for a `poetry.lock` `[[package]]` entry.
/// Handles both lock-version dialects.
fn poetry_is_dev(tbl: &toml::value::Table) -> Option<bool> {
    // v1: `category = "main" | "dev"`
    if let Some(cat) = tbl.get("category").and_then(|v| v.as_str()) {
        return Some(cat == "dev");
    }
    // v2+: `groups = [...]` — prod iff "main" appears.
    if let Some(arr) = tbl.get("groups").and_then(|v| v.as_array()) {
        let has_main = arr
            .iter()
            .any(|g| g.as_str().is_some_and(|s| s == "main"));
        return Some(!has_main);
    }
    // No dev/prod info in the entry — preserve None so downstream
    // dedup treats it as "source didn't assert a scope."
    None
}

// -----------------------------------------------------------------------
// Tier 2: Pipfile.lock
// -----------------------------------------------------------------------

/// Read `<rootfs>/Pipfile.lock` if present. JSON-structured with two
/// top-level package maps: `default` (prod) and `develop` (dev).
fn read_pipfile_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>> {
    let path = rootfs.join("Pipfile.lock");
    let text = std::fs::read_to_string(&path).ok()?;
    let parsed: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(path = %path.display(), error = %e, "Pipfile.lock parse failed");
            return None;
        }
    };
    let source_path = path.to_string_lossy().into_owned();
    Some(parse_pipfile_lock(&parsed, &source_path, include_dev))
}

/// Parse an already-deserialised `Pipfile.lock` JSON document.
/// Public-in-module for unit testing.
pub(crate) fn parse_pipfile_lock(
    root: &serde_json::Value,
    source_path: &str,
    include_dev: bool,
) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();

    for (section, is_dev) in [("default", false), ("develop", true)] {
        if is_dev && !include_dev {
            continue;
        }
        let Some(packages) = root.get(section).and_then(|v| v.as_object()) else {
            continue;
        };
        // Sort keys for deterministic output (serde_json objects don't
        // preserve insertion order across builds / platforms).
        let mut names: Vec<&String> = packages.keys().collect();
        names.sort();
        for name in names {
            let entry = &packages[name];
            let version_raw = entry
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            // Pipfile.lock versions usually start with "==" — strip.
            let version = version_raw.trim_start_matches("==").trim();
            if version.is_empty() {
                continue;
            }

            let purl_str = build_pypi_purl_str(name, version);
            let Ok(purl) = Purl::new(&purl_str) else {
                continue;
            };

            out.push(PackageDbEntry {
                purl,
                name: name.clone(),
                version: version.to_string(),
                arch: None,
                source_path: source_path.to_string(),
                depends: Vec::new(), // Pipfile.lock doesn't expose the dep graph
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
        }
    }

    out
}

// -----------------------------------------------------------------------
// Tier 3: requirements.txt (design tier)
// -----------------------------------------------------------------------

/// Read the project's `requirements.txt` (and any `requirements*.txt`
/// siblings at the root). Pipe the contents through
/// [`parse_requirements_file_text`] and convert to `PackageDbEntry`.
fn read_requirements_files(rootfs: &Path) -> Option<Vec<PackageDbEntry>> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(rootfs) else {
        return None;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.starts_with("requirements") && n.ends_with(".txt"))
        })
        .collect();
    paths.sort();
    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let source_path = path.to_string_lossy().into_owned();
        let parsed = parse_requirements_file_text(&text);
        for entry in parsed {
            if let Some(pdb) = entry.into_package_db_entry(&source_path) {
                out.push(pdb);
            }
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// One line from a `requirements.txt`-style file, normalised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequirementsTxtEntry {
    pub name: String,
    /// Only populated for exactly-pinned (`==`) requirements. For
    /// ranges / unpinned / URL refs, left empty.
    pub version: String,
    /// Original raw line (including operators, extras, hash flags).
    /// Emitted as `mikebom:requirement-range` on the component.
    pub range_spec: String,
    /// Non-registry source kind: `"url"` for `https://...`, `"local"`
    /// for `file:...`, `"git"` for `git+...`. None for registry-named
    /// requirements.
    pub source_type: Option<String>,
}

impl RequirementsTxtEntry {
    fn into_package_db_entry(self, source_path: &str) -> Option<PackageDbEntry> {
        if self.name.is_empty() {
            return None;
        }
        // PURL for empty version: `pkg:pypi/<name>` (no @). packageurl
        // crate accepts this.
        let purl_str = build_pypi_purl_str(&self.name, &self.version);
        let purl = Purl::new(&purl_str).ok()?;
        Some(PackageDbEntry {
            purl,
            name: self.name,
            version: self.version,
            arch: None,
            source_path: source_path.to_string(),
            depends: Vec::new(),
            maintainer: None,
            licenses: Vec::new(),
            is_dev: None,
            requirement_range: Some(self.range_spec),
            source_type: self.source_type,
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
        })
    }
}

/// Parse raw `requirements.txt` text. Tolerates:
/// - `# comments` (full-line or trailing).
/// - Blank lines.
/// - `-r <other.txt>` includes (ignored this milestone; follow-up to recurse).
/// - `--hash=sha256:...` flags on their own line or trailing.
/// - URL refs (`https://...`, `git+...`, `file:...`).
/// - Pinned (`==`) and ranged (`>=`, `<`, `~=`, `!=`) requirements.
pub(crate) fn parse_requirements_file_text(text: &str) -> Vec<RequirementsTxtEntry> {
    let mut out = Vec::new();
    // Deal with line continuations: a trailing backslash joins to the
    // next line. Common in pinned-with-hash blocks.
    let joined = text.replace("\\\n", " ");
    for raw in joined.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // Strip full-line comments.
        if line.starts_with('#') {
            continue;
        }
        // Strip trailing comments (but only when clearly after a space).
        let line = match line.split_once(" #") {
            Some((before, _)) => before.trim(),
            None => line,
        };
        // Skip `-r`, `-c`, `--index-url`, etc. lines — meta-commands.
        if line.starts_with('-') {
            continue;
        }

        if let Some(entry) = parse_requirements_line(line) {
            out.push(entry);
        }
    }
    out
}

/// Parse a single non-blank, non-comment, non-meta requirements line.
fn parse_requirements_line(line: &str) -> Option<RequirementsTxtEntry> {
    // Strip any trailing `--hash=sha256:...` flags (can repeat).
    let body = line.splitn(2, "--hash").next().unwrap_or(line).trim();

    // URL-style sources.
    if body.starts_with("git+") {
        // e.g. `git+https://github.com/foo/bar.git@rev#egg=bar`
        let name = egg_fragment(body).unwrap_or_else(|| "unknown".to_string());
        return Some(RequirementsTxtEntry {
            name,
            version: String::new(),
            range_spec: body.to_string(),
            source_type: Some("git".to_string()),
        });
    }
    if body.starts_with("http://") || body.starts_with("https://") {
        let name = egg_fragment(body).unwrap_or_else(|| "unknown".to_string());
        return Some(RequirementsTxtEntry {
            name,
            version: String::new(),
            range_spec: body.to_string(),
            source_type: Some("url".to_string()),
        });
    }
    if body.starts_with("file:") || body.starts_with('.') || body.starts_with('/') {
        let name = egg_fragment(body).unwrap_or_else(|| "unknown".to_string());
        return Some(RequirementsTxtEntry {
            name,
            version: String::new(),
            range_spec: body.to_string(),
            source_type: Some("local".to_string()),
        });
    }

    // Registry-style: `name[extras] OP version, OP version; marker`.
    // Reuse the PEP 508 tokeniser for the name; detect `==` for pinning.
    let name = tokenise_requires_dist_name(body)?;

    // Look for a single `==` pin to populate `version`.
    let version = pinned_version_from(body).unwrap_or_default();

    Some(RequirementsTxtEntry {
        name,
        version,
        range_spec: body.to_string(),
        source_type: None,
    })
}

/// Extract `egg=<name>` from a URL-style requirement, if present.
fn egg_fragment(url: &str) -> Option<String> {
    let frag = url.split_once('#')?.1;
    for part in frag.split('&') {
        if let Some(value) = part.strip_prefix("egg=") {
            let clean = value.split('[').next().unwrap_or(value);
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }
    }
    None
}

/// If the requirement has a single `==` pin (and no disjunction like
/// `==1.0 || ==2.0`, which pip doesn't support anyway), return that
/// version string. Returns None for ranges.
fn pinned_version_from(body: &str) -> Option<String> {
    // Drop any env marker first.
    let head = body.split_once(';').map(|x| x.0).unwrap_or(body);
    // Look for `==` as an exact operator. Ignore `!=` and `~=`.
    for part in head.split(',') {
        let p = part.trim();
        if let Some(rest) = p.strip_prefix("==") {
            return Some(rest.trim().to_string());
        }
        // `name == 1.0` form: find `==` after some whitespace.
        if let Some(idx) = p.find("==") {
            // Ensure it's an `==` operator, not a substring of `===` etc.
            let before = &p[..idx];
            let after = &p[idx + 2..];
            if !before.ends_with('=') && !after.starts_with('=') {
                return Some(after.trim().trim_start_matches(' ').to_string());
            }
        }
    }
    None
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use std::fs;

    fn make_venv_rootfs(
        packages: &[(&str, &str, &str)],
    ) -> tempfile::TempDir {
        // packages: [(name, version, metadata_body)]
        let dir = tempfile::tempdir().expect("tempdir");
        let sp = dir.path().join(".venv/lib/python3.12/site-packages");
        fs::create_dir_all(&sp).unwrap();
        for (name, version, body) in packages {
            let subdir = sp.join(format!("{name}-{version}.dist-info"));
            fs::create_dir_all(&subdir).unwrap();
            fs::write(subdir.join("METADATA"), body).unwrap();
        }
        dir
    }

    #[test]
    fn parse_metadata_single_package_basics() {
        let body = "\
Metadata-Version: 2.1
Name: requests
Version: 2.31.0
Summary: Python HTTP for Humans.
Home-page: https://requests.readthedocs.io
Author: Kenneth Reitz
Author-email: me@kennethreitz.org
License: Apache 2.0
Requires-Dist: charset-normalizer<4,>=2
Requires-Dist: idna<4,>=2.5
Requires-Dist: urllib3<3,>=1.21.1
Requires-Dist: certifi>=2017.4.17
Classifier: License :: OSI Approved :: Apache Software License
Classifier: Programming Language :: Python :: 3
";
        let e = parse_metadata_text(body);
        assert_eq!(e.name, "requests");
        assert_eq!(e.version, "2.31.0");
        assert_eq!(e.author.as_deref(), Some("Kenneth Reitz"));
        assert_eq!(e.author_email.as_deref(), Some("me@kennethreitz.org"));
        assert_eq!(e.license_raw.as_deref(), Some("Apache 2.0"));
        assert_eq!(e.requires_dist.len(), 4);
        assert_eq!(e.classifiers.len(), 2);
    }

    #[test]
    fn parse_metadata_with_continuation_lines() {
        let body = "\
Name: multiline-pkg
Version: 0.1.0
License: Some custom license
 that spans multiple lines
 with indentation.
";
        let e = parse_metadata_text(body);
        assert_eq!(e.name, "multiline-pkg");
        let raw = e.license_raw.expect("license present");
        assert!(raw.contains("Some custom license"));
        assert!(raw.contains("multiple lines"));
    }

    #[test]
    fn parse_metadata_pep_639_license_expression_wins() {
        let body = "\
Name: modern-pkg
Version: 2.0.0
License-Expression: Apache-2.0 OR MIT
License: legacy-free-form
";
        let e = parse_metadata_text(body);
        assert_eq!(e.license_expression.as_deref(), Some("Apache-2.0 OR MIT"));
        assert_eq!(e.license_raw.as_deref(), Some("legacy-free-form"));
    }

    #[test]
    fn parse_metadata_stops_at_first_blank_line() {
        let body = "\
Name: pkg
Version: 1.0

This is the description; it should NOT be parsed as a header.
License: Ignored
";
        let e = parse_metadata_text(body);
        assert_eq!(e.name, "pkg");
        assert!(e.license_raw.is_none());
    }

    #[test]
    fn parse_metadata_non_utf8_author_falls_back_losslessly() {
        // Mixed UTF-8 + an invalid byte in the author field.
        let mut body = b"Name: q\nVersion: 1.0\nAuthor: Jose \xE9 Surname\nLicense: MIT\n".to_vec();
        let _ = &mut body; // keep mutable reference simple
        let e = parse_metadata_bytes(&body);
        assert_eq!(e.name, "q");
        assert_eq!(e.license_raw.as_deref(), Some("MIT"));
        // Author present (lossy-decoded); we don't care about the exact bytes.
        assert!(e.author.is_some());
    }

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
    fn venv_walk_finds_packages_in_standard_location() {
        let dir = make_venv_rootfs(&[
            ("requests", "2.31.0", "Name: requests\nVersion: 2.31.0\nLicense: Apache 2.0\n"),
            ("urllib3", "2.0.7", "Name: urllib3\nVersion: 2.0.7\nLicense: MIT\n"),
        ]);
        let out = read(dir.path(), false);
        assert_eq!(out.len(), 2);
        // Deterministic alphabetical order by dist-info dir name.
        assert_eq!(out[0].name, "requests");
        assert_eq!(out[1].name, "urllib3");
        assert!(out
            .iter()
            .all(|e| e.sbom_tier.as_deref() == Some("deployed")));
    }

    #[test]
    fn pyproject_only_project_skips_with_log() {
        // Bare pyproject.toml; no venv, no lockfile, no requirements.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"myapp\"\nversion = \"0.1.0\"\ndependencies = [\"requests\"]\n",
        )
        .unwrap();
        let out = read(dir.path(), false);
        assert!(out.is_empty(), "pyproject-only project emits zero components");
    }

    // --- PURL canonicalisation (lowercase + _→-) ---

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
    fn dist_info_with_mixed_case_name_emits_lowercase_purl() {
        // Real-world dist-info carries the declared name (may be mixed
        // case). The PURL must canonicalise but `component.name` (via
        // the entry's `name` field) preserves the declared form.
        let dir = make_venv_rootfs(&[(
            "Flask",
            "3.0.0",
            "Name: Flask\nVersion: 3.0.0\nLicense: BSD-3-Clause\n",
        )]);
        let out = read(dir.path(), false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "Flask", "component.name keeps declared form");
        assert_eq!(
            out[0].purl.as_str(),
            "pkg:pypi/flask@3.0.0",
            "PURL must be lowercase per packageurl-python reference impl"
        );
    }

    // --- License precedence tests ---

    #[test]
    fn license_pep_639_expression_wins() {
        let mut e = PipDistInfoEntry::default();
        e.license_expression = Some("Apache-2.0 OR MIT".into());
        e.license_raw = Some("Apache 2.0".into());
        e.classifiers.push("License :: OSI Approved :: MIT License".into());
        let out = extract_license(&e);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_str(), "Apache-2.0 OR MIT");
    }

    #[test]
    fn license_legacy_raw_tried_when_pep_639_absent() {
        let mut e = PipDistInfoEntry::default();
        e.license_raw = Some("MIT".into());
        let out = extract_license(&e);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_str(), "MIT");
    }

    #[test]
    fn license_classifier_fallback_maps_to_spdx() {
        let mut e = PipDistInfoEntry::default();
        e.classifiers.push("License :: OSI Approved :: Apache Software License".into());
        let out = extract_license(&e);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_str(), "Apache-2.0");
    }

    #[test]
    fn license_all_tiers_empty_returns_empty() {
        let e = PipDistInfoEntry::default();
        assert!(extract_license(&e).is_empty());
    }

    #[test]
    fn classifier_lookup_covers_common_licenses() {
        assert_eq!(
            classifier_to_spdx("License :: OSI Approved :: MIT License"),
            Some("MIT")
        );
        assert_eq!(
            classifier_to_spdx("License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)"),
            Some("GPL-3.0-or-later")
        );
        assert_eq!(
            classifier_to_spdx("License :: OSI Approved :: BSD License"),
            Some("BSD-3-Clause")
        );
    }

    #[test]
    fn classifier_lookup_returns_none_for_unknown() {
        assert_eq!(classifier_to_spdx("License :: Other/Proprietary License"), None);
        assert_eq!(classifier_to_spdx("Topic :: Software Development"), None);
    }

    // --- Poetry lockfile tests ---

    #[test]
    fn poetry_lock_v1_category_dev_filtered_by_default() {
        let src = r#"
[[package]]
name = "requests"
version = "2.31.0"
description = "HTTP for Humans"
category = "main"
optional = false
python-versions = ">=3.7"

[[package]]
name = "pytest"
version = "7.4.0"
description = "testing framework"
category = "dev"
optional = false
python-versions = ">=3.7"

[metadata]
lock-version = "1.1"
"#;
        let parsed: toml::Value = toml::from_str(src).unwrap();
        let out = parse_poetry_lock(&parsed, "/poetry.lock", /*include_dev=*/ false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "requests");
        assert_eq!(out[0].is_dev, Some(false));
        assert_eq!(out[0].sbom_tier.as_deref(), Some("source"));
    }

    #[test]
    fn poetry_lock_v1_include_dev_surfaces_both() {
        let src = r#"
[[package]]
name = "requests"
version = "2.31.0"
category = "main"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"

[metadata]
lock-version = "1.1"
"#;
        let parsed: toml::Value = toml::from_str(src).unwrap();
        let out = parse_poetry_lock(&parsed, "/poetry.lock", true);
        assert_eq!(out.len(), 2);
        let pytest = out.iter().find(|e| e.name == "pytest").expect("pytest present");
        assert_eq!(pytest.is_dev, Some(true));
    }

    #[test]
    fn poetry_lock_v2_groups_main_marks_prod() {
        let src = r#"
[[package]]
name = "requests"
version = "2.31.0"
groups = ["main"]

[[package]]
name = "pytest"
version = "7.4.0"
groups = ["dev"]

[metadata]
lock-version = "2.0"
"#;
        let parsed: toml::Value = toml::from_str(src).unwrap();
        let out = parse_poetry_lock(&parsed, "/poetry.lock", true);
        assert_eq!(out.len(), 2);
        let req = out.iter().find(|e| e.name == "requests").unwrap();
        let pyt = out.iter().find(|e| e.name == "pytest").unwrap();
        assert_eq!(req.is_dev, Some(false));
        assert_eq!(pyt.is_dev, Some(true));
    }

    #[test]
    fn poetry_lock_dependencies_table_populates_depends() {
        let src = r#"
[[package]]
name = "requests"
version = "2.31.0"
category = "main"

[package.dependencies]
urllib3 = ">=1.21.1,<3"
certifi = ">=2017.4.17"

[metadata]
lock-version = "1.1"
"#;
        let parsed: toml::Value = toml::from_str(src).unwrap();
        let out = parse_poetry_lock(&parsed, "/poetry.lock", false);
        assert_eq!(out.len(), 1);
        let e = &out[0];
        assert!(e.depends.contains(&"urllib3".to_string()));
        assert!(e.depends.contains(&"certifi".to_string()));
    }

    // --- Pipfile.lock tests ---

    #[test]
    fn pipfile_lock_default_only_by_default() {
        let src = serde_json::json!({
            "_meta": { "hash": "abc" },
            "default": {
                "requests": { "version": "==2.31.0", "hashes": ["sha256:..."] }
            },
            "develop": {
                "pytest": { "version": "==7.4.0", "hashes": ["sha256:..."] }
            }
        });
        let out = parse_pipfile_lock(&src, "/Pipfile.lock", false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "requests");
        assert_eq!(out[0].version, "2.31.0"); // `==` prefix stripped
        assert_eq!(out[0].is_dev, Some(false));
    }

    #[test]
    fn pipfile_lock_include_dev_surfaces_develop() {
        let src = serde_json::json!({
            "default": {
                "requests": { "version": "==2.31.0" }
            },
            "develop": {
                "pytest": { "version": "==7.4.0" }
            }
        });
        let out = parse_pipfile_lock(&src, "/Pipfile.lock", true);
        assert_eq!(out.len(), 2);
        let pyt = out.iter().find(|e| e.name == "pytest").unwrap();
        assert_eq!(pyt.is_dev, Some(true));
        assert_eq!(pyt.sbom_tier.as_deref(), Some("source"));
    }

    #[test]
    fn pipfile_lock_skips_entries_without_version() {
        let src = serde_json::json!({
            "default": {
                "broken": { "markers": "python_version > '3'" }
            }
        });
        let out = parse_pipfile_lock(&src, "/Pipfile.lock", false);
        assert!(out.is_empty());
    }

    // --- requirements.txt tests ---

    #[test]
    fn requirements_txt_pinned_populates_version_and_range() {
        let entries = parse_requirements_file_text("requests==2.31.0\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "requests");
        assert_eq!(entries[0].version, "2.31.0");
        assert_eq!(entries[0].range_spec, "requests==2.31.0");
        assert!(entries[0].source_type.is_none());
    }

    #[test]
    fn requirements_txt_ranged_leaves_version_empty() {
        let entries = parse_requirements_file_text("requests>=2,<3\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "requests");
        assert!(entries[0].version.is_empty());
        assert_eq!(entries[0].range_spec, "requests>=2,<3");
    }

    #[test]
    fn requirements_txt_bare_name_empty_version() {
        let entries = parse_requirements_file_text("requests\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "requests");
        assert!(entries[0].version.is_empty());
    }

    #[test]
    fn requirements_txt_strips_comments_and_blank_lines() {
        let text = "\
# top comment
requests==2.31.0  # trailing comment
# another

urllib3>=2  # with space before hash
";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "requests");
        assert_eq!(entries[1].name, "urllib3");
    }

    #[test]
    fn requirements_txt_skips_meta_commands() {
        let text = "\
-r other.txt
--index-url https://pypi.org/simple/
requests==2.31.0
";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "requests");
    }

    #[test]
    fn requirements_txt_strips_hash_flags() {
        let text = "\
requests==2.31.0 --hash=sha256:abc123 --hash=sha256:def456
urllib3>=2 \\
    --hash=sha256:zzz
";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "requests");
        assert_eq!(entries[1].name, "urllib3");
    }

    #[test]
    fn requirements_txt_git_url_source_type() {
        let text = "git+https://github.com/psf/requests.git@main#egg=requests\n";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "requests");
        assert_eq!(entries[0].source_type.as_deref(), Some("git"));
        assert!(entries[0].version.is_empty());
    }

    #[test]
    fn requirements_txt_https_url_source_type() {
        let text = "https://example.com/pkg/foo-1.0.tar.gz#egg=foo\n";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "foo");
        assert_eq!(entries[0].source_type.as_deref(), Some("url"));
    }

    #[test]
    fn requirements_txt_file_ref_source_type() {
        let text = "file:./local/pkg#egg=local-pkg\n";
        let entries = parse_requirements_file_text(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "local-pkg");
        assert_eq!(entries[0].source_type.as_deref(), Some("local"));
    }

    #[test]
    fn requirements_txt_conversion_produces_design_tier() {
        let entry = RequirementsTxtEntry {
            name: "requests".into(),
            version: "2.31.0".into(),
            range_spec: "requests==2.31.0".into(),
            source_type: None,
        };
        let pdb = entry.into_package_db_entry("/req.txt").expect("converts");
        assert_eq!(pdb.sbom_tier.as_deref(), Some("design"));
        assert_eq!(pdb.requirement_range.as_deref(), Some("requests==2.31.0"));
    }

    #[test]
    fn requirements_txt_empty_version_purl_well_formed() {
        let entry = RequirementsTxtEntry {
            name: "requests".into(),
            version: String::new(),
            range_spec: "requests>=2".into(),
            source_type: None,
        };
        let pdb = entry.into_package_db_entry("/req.txt").expect("converts");
        // packageurl-rs accepts `pkg:pypi/<name>` without @version.
        assert!(pdb.purl.as_str().starts_with("pkg:pypi/requests"));
    }

    #[test]
    fn requires_dist_tokenisation_drives_depends() {
        let body = "\
Name: requests
Version: 2.31.0
Requires-Dist: urllib3 < 3, >= 1.21.1
Requires-Dist: certifi >= 2017.4.17
Requires-Dist: charset-normalizer < 4, >= 2
Requires-Dist: pytest ; extra == 'dev'
";
        let dir = make_venv_rootfs(&[("requests", "2.31.0", body)]);
        let out = read(dir.path(), false);
        assert_eq!(out.len(), 1);
        let e = &out[0];
        // extra-marker dep dropped, rest emitted.
        assert!(e.depends.contains(&"urllib3".to_string()));
        assert!(e.depends.contains(&"certifi".to_string()));
        assert!(e.depends.contains(&"charset-normalizer".to_string()));
        assert!(!e.depends.contains(&"pytest".to_string()));
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