//! Read Go source-tree package metadata from `go.mod` + `go.sum`.
//!
//! Source-tier (FR-012/R3): a `go.sum` declares the exact version + h1
//! hash for every module the build pulls in, direct or transitive. This
//! is authoritative enough to emit `sbom_tier = "source"` components.
//! `go.mod` layers a dependency graph on top (direct requires → main
//! module) plus `replace` / `exclude` directives that rewrite or drop
//! entries before conversion.
//!
//! Transitive dep-graph enrichment: `go.sum` doesn't encode module →
//! module edges, but the Go module cache does — each downloaded
//! module's own `go.mod` sits at
//! `<GOMODCACHE>/cache/download/<escaped>/@v/<version>.mod` and lists
//! its declared `require` block. When the cache is present (CI,
//! developer machines, build containers that haven't been cleaned),
//! the reader fetches each module's go.mod and populates `depends`
//! accordingly. Cache-absent scans (scratch images, stripped build
//! artefacts) still emit the root → direct-dep edges; transitive
//! nodes stay flat.
//!
//! Not in scope for this milestone: private module proxy lookup, module
//! cache file-hash verification, `vendor/` directory component
//! extraction. Those are follow-ups.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use mikebom_common::types::purl::{encode_purl_segment, Purl};

use super::PackageDbEntry;

/// Max depth for the recursive project-root search. Matches the npm
/// walker's budget — enough to cover monorepo shapes without running
/// away into source trees.
const MAX_PROJECT_ROOT_DEPTH: usize = 6;

// ---------------------------------------------------------------------------
// Module cache lookup — for transitive dep-graph reconstruction
// ---------------------------------------------------------------------------

/// Encode a Go module path for the filesystem layout the module cache
/// uses. Every uppercase letter `X` becomes `!x` — e.g.
/// `github.com/Azure/azure-sdk-for-go` → `github.com/!azure/azure-sdk-for-go`.
/// Non-ASCII characters and punctuation pass through unchanged (no
/// module path in the wild uses them outside ASCII identifiers).
pub(crate) fn escape_module_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 4);
    for ch in path.chars() {
        if ch.is_ascii_uppercase() {
            out.push('!');
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Candidate module-cache roots for a given scan. Populated once per
/// scan to avoid redundant I/O across N module lookups. Each entry is
/// expected to contain a `cache/download/...` subtree.
#[derive(Clone, Debug, Default)]
pub(crate) struct GoModCache {
    roots: Vec<PathBuf>,
}

impl GoModCache {
    /// Discover candidate cache roots in priority order:
    /// 1. `$GOMODCACHE` environment variable (honouring the user's
    ///    local Go setup when running `--path` scans).
    /// 2. `$HOME/go/pkg/mod` (default when GOMODCACHE isn't set).
    /// 3. `<rootfs>/root/go/pkg/mod` (conventional in container images
    ///    that bake the cache in).
    /// 4. `<rootfs>/go/pkg/mod`
    /// 5. `<rootfs>/home/*/go/pkg/mod` (multi-user images).
    /// 6. `<rootfs>/usr/local/go/pkg/mod`
    ///
    /// Each candidate is included only when its `cache/download`
    /// subdirectory actually exists. The order matters for deterministic
    /// resolution when multiple caches are present — earlier wins.
    pub(crate) fn discover(rootfs: &Path) -> Self {
        let mut roots: Vec<PathBuf> = Vec::new();
        let mut seen: HashSet<PathBuf> = HashSet::new();

        let mut try_add = |candidate: PathBuf, roots: &mut Vec<PathBuf>| {
            let canonical = std::fs::canonicalize(&candidate).unwrap_or(candidate.clone());
            if !seen.insert(canonical) {
                return;
            }
            if candidate.join("cache/download").is_dir() {
                roots.push(candidate);
            }
        };

        if let Ok(env) = std::env::var("GOMODCACHE") {
            if !env.is_empty() {
                try_add(PathBuf::from(&env), &mut roots);
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                try_add(PathBuf::from(&home).join("go/pkg/mod"), &mut roots);
            }
        }
        try_add(rootfs.join("root/go/pkg/mod"), &mut roots);
        try_add(rootfs.join("go/pkg/mod"), &mut roots);
        // Enumerate rootfs/home/<user>/go/pkg/mod — common on
        // multi-user container layouts.
        if let Ok(home_dir) = std::fs::read_dir(rootfs.join("home")) {
            for entry in home_dir.flatten() {
                let candidate = entry.path().join("go/pkg/mod");
                try_add(candidate, &mut roots);
            }
        }
        try_add(rootfs.join("usr/local/go/pkg/mod"), &mut roots);

        GoModCache { roots }
    }

    /// Read `<cache>/cache/download/<escaped>/@v/<version>.mod` and
    /// return its contents. Returns `None` when no cache root has the
    /// file. IO errors are swallowed and reported as `None` so a single
    /// unreadable module doesn't abort the broader scan.
    pub(crate) fn read_mod_file(&self, module: &str, version: &str) -> Option<String> {
        if self.roots.is_empty() {
            return None;
        }
        let escaped = escape_module_path(module);
        let relative = format!("cache/download/{escaped}/@v/{version}.mod");
        for root in &self.roots {
            let path = root.join(&relative);
            if let Ok(text) = std::fs::read_to_string(&path) {
                return Some(text);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// go.mod parser
// ---------------------------------------------------------------------------

/// One `require` line from a `go.mod`. `indirect` tracks the `// indirect`
/// trailing comment Go emits for transitively-needed modules that aren't
/// imported directly. We keep both so downstream consumers can choose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GoModRequire {
    pub path: String,
    pub version: String,
    pub indirect: bool,
}

/// Parsed `go.mod` contents. `replaces` maps `(old_path, old_version) →
/// (new_path, new_version)` — an `old_version` of `""` means "match any
/// version of old_path". `excludes` holds the set that must be filtered
/// out before PURL construction.
#[derive(Clone, Debug, Default)]
pub(crate) struct GoModDocument {
    pub module_path: Option<String>,
    pub go_version: Option<String>,
    pub requires: Vec<GoModRequire>,
    pub replaces: HashMap<(String, String), (String, String)>,
    pub excludes: HashSet<(String, String)>,
}

/// Parse a `go.mod` file body into a [`GoModDocument`]. The parser is
/// line-oriented and deliberately lenient: unknown directives and
/// malformed lines are skipped rather than rejecting the whole file.
/// This mirrors `go mod`'s own tolerance for files that were hand-edited
/// between runs.
pub(crate) fn parse_go_mod(text: &str) -> GoModDocument {
    let mut doc = GoModDocument::default();
    let mut lines = text.lines();

    while let Some(raw) = lines.next() {
        let stripped = strip_line_comment(raw);
        let line = stripped.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("module ") {
            doc.module_path = Some(rest.trim().trim_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("go ") {
            doc.go_version = Some(rest.trim().to_string());
        } else if line == "require (" {
            for raw_inner in lines.by_ref() {
                let inner_owned = strip_line_comment_preserving_indirect(raw_inner);
                let inner = inner_owned.trim();
                if inner == ")" {
                    break;
                }
                if inner.is_empty() {
                    continue;
                }
                if let Some(req) = parse_require_line(inner) {
                    doc.requires.push(req);
                }
            }
        } else if let Some(rest) = line.strip_prefix("require ") {
            if let Some(req) = parse_require_line(rest) {
                doc.requires.push(req);
            }
        } else if line == "replace (" {
            for raw_inner in lines.by_ref() {
                let inner_owned = strip_line_comment(raw_inner);
                let inner = inner_owned.trim();
                if inner == ")" {
                    break;
                }
                if inner.is_empty() {
                    continue;
                }
                if let Some((k, v)) = parse_replace_line(inner) {
                    doc.replaces.insert(k, v);
                }
            }
        } else if let Some(rest) = line.strip_prefix("replace ") {
            if let Some((k, v)) = parse_replace_line(rest) {
                doc.replaces.insert(k, v);
            }
        } else if line == "exclude (" {
            for raw_inner in lines.by_ref() {
                let inner_owned = strip_line_comment(raw_inner);
                let inner = inner_owned.trim();
                if inner == ")" {
                    break;
                }
                if inner.is_empty() {
                    continue;
                }
                if let Some(coord) = parse_module_version_pair(inner) {
                    doc.excludes.insert(coord);
                }
            }
        } else if let Some(rest) = line.strip_prefix("exclude ") {
            if let Some(coord) = parse_module_version_pair(rest) {
                doc.excludes.insert(coord);
            }
        }
        // else: unknown directive (`toolchain`, `retract`, ...) — skip.
    }

    doc
}

/// Strip `// ...` line comments, but preserve the `// indirect` marker
/// — callers inside `require` blocks need to see it to flag the entry.
fn strip_line_comment_preserving_indirect(line: &str) -> String {
    let trimmed_end = line.trim_end();
    if let Some(comment_start) = trimmed_end.find("//") {
        let (code, comment) = trimmed_end.split_at(comment_start);
        if comment.trim() == "// indirect" {
            return format!("{code} // indirect");
        }
        code.to_string()
    } else {
        trimmed_end.to_string()
    }
}

/// Strip `// ...` comments from a line. Used outside `require` blocks
/// where the `// indirect` marker isn't meaningful.
fn strip_line_comment(line: &str) -> String {
    if let Some(i) = line.find("//") {
        line[..i].to_string()
    } else {
        line.to_string()
    }
}

fn parse_require_line(rest: &str) -> Option<GoModRequire> {
    let indirect = rest.contains("// indirect");
    let without_comment = rest.split("//").next().unwrap_or("").trim();
    let mut parts = without_comment.split_whitespace();
    let path = parts.next()?.trim_matches('"').to_string();
    let version = parts.next()?.trim_matches('"').to_string();
    if path.is_empty() || version.is_empty() {
        return None;
    }
    Some(GoModRequire {
        path,
        version,
        indirect,
    })
}

/// Parse `old-path [old-version] => new-path [new-version]`. Returns
/// `((old_path, old_version_or_empty), (new_path, new_version_or_empty))`.
fn parse_replace_line(rest: &str) -> Option<((String, String), (String, String))> {
    let (lhs, rhs) = rest.split_once("=>")?;
    let lhs_parts: Vec<&str> = lhs.split_whitespace().collect();
    let rhs_parts: Vec<&str> = rhs.split_whitespace().collect();
    let (old_path, old_ver) = match lhs_parts.as_slice() {
        [path] => (path.to_string(), String::new()),
        [path, ver] => (path.to_string(), ver.to_string()),
        _ => return None,
    };
    let (new_path, new_ver) = match rhs_parts.as_slice() {
        [path] => (path.to_string(), String::new()),
        [path, ver] => (path.to_string(), ver.to_string()),
        _ => return None,
    };
    Some((
        (old_path.trim_matches('"').to_string(), old_ver.trim_matches('"').to_string()),
        (new_path.trim_matches('"').to_string(), new_ver.trim_matches('"').to_string()),
    ))
}

fn parse_module_version_pair(rest: &str) -> Option<(String, String)> {
    let mut parts = rest.split_whitespace();
    let path = parts.next()?.trim_matches('"').to_string();
    let version = parts.next()?.trim_matches('"').to_string();
    Some((path, version))
}

// ---------------------------------------------------------------------------
// go.sum parser
// ---------------------------------------------------------------------------

/// One line from a `go.sum`. `GoSum` tracks `<module> <version>/go.mod`
/// entries (integrity for the module's go.mod file); `Module` tracks
/// `<module> <version>` entries (integrity for the module zip). Only
/// `Module` entries become SBOM components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GoSumKind {
    Module,
    GoMod,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GoSumEntry {
    pub module: String,
    pub version: String,
    pub hash: String,
    pub kind: GoSumKind,
}

/// Parse a `go.sum` file body. Malformed lines produce `None` and are
/// skipped; valid lines return populated entries.
pub(crate) fn parse_go_sum(text: &str) -> Vec<GoSumEntry> {
    text.lines().filter_map(parse_go_sum_line).collect()
}

fn parse_go_sum_line(line: &str) -> Option<GoSumEntry> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.split_whitespace();
    let module = parts.next()?.to_string();
    let version_raw = parts.next()?.to_string();
    let hash = parts.next()?.to_string();
    let (version, kind) = if let Some(stripped) = version_raw.strip_suffix("/go.mod") {
        (stripped.to_string(), GoSumKind::GoMod)
    } else {
        (version_raw, GoSumKind::Module)
    };
    if !hash.starts_with("h1:") {
        return None;
    }
    Some(GoSumEntry {
        module,
        version,
        hash,
        kind,
    })
}

// ---------------------------------------------------------------------------
// GoModEntry → PackageDbEntry
// ---------------------------------------------------------------------------

/// Apply `replace` / `exclude` directives, then build the PURL. Returns
/// `None` when an entry is fully excluded.
fn apply_replace_and_exclude(
    module: &str,
    version: &str,
    replaces: &HashMap<(String, String), (String, String)>,
    excludes: &HashSet<(String, String)>,
) -> Option<(String, String)> {
    if excludes.contains(&(module.to_string(), version.to_string())) {
        return None;
    }
    // Prefer the exact (path, version) match; fall back to path-only
    // (versioned replace → "any version" replace).
    if let Some((new_path, new_ver)) =
        replaces.get(&(module.to_string(), version.to_string()))
    {
        let final_path = new_path.clone();
        let final_ver = if new_ver.is_empty() {
            version.to_string()
        } else {
            new_ver.clone()
        };
        // Skip replace targets that point at a local path (`./foo`,
        // `../bar`, `/abs/path`) — those aren't registry modules and
        // carry no PURL.
        if looks_like_local_path(&final_path) {
            return None;
        }
        return Some((final_path, final_ver));
    }
    if let Some((new_path, new_ver)) =
        replaces.get(&(module.to_string(), String::new()))
    {
        let final_path = new_path.clone();
        let final_ver = if new_ver.is_empty() {
            version.to_string()
        } else {
            new_ver.clone()
        };
        if looks_like_local_path(&final_path) {
            return None;
        }
        return Some((final_path, final_ver));
    }
    Some((module.to_string(), version.to_string()))
}

fn looks_like_local_path(p: &str) -> bool {
    p.starts_with("./") || p.starts_with("../") || p.starts_with('/')
}

/// Decode a go.sum `h1:<base64-sha256>` value into a `ContentHash`
/// tagged as SHA-256. The h1 prefix stands for "hash algorithm 1"
/// which is `dirhash.Hash1` — SHA-256 over a sorted newline-joined
/// manifest of per-file SHA-256 hashes (see
/// `golang.org/x/mod/sumdb/dirhash`). The value is a valid 32-byte
/// SHA-256 digest by construction, so emitting it on
/// `component.hashes` with `alg: SHA-256` is correct per CDX's
/// field semantics — the hash input is a manifest rather than a
/// tarball, but CDX doesn't constrain what was hashed.
fn h1_to_content_hash(
    h1: &str,
) -> Option<mikebom_common::types::hash::ContentHash> {
    use base64::Engine;
    use mikebom_common::types::hash::{ContentHash, HashAlgorithm};
    let b64 = h1.strip_prefix("h1:")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    ContentHash::with_algorithm(HashAlgorithm::Sha256, &hex).ok()
}

/// Build a `pkg:golang/<module>@<version>` PURL. `Purl::new` does the
/// spec-compliant encoding; module paths happen to already be lowercase
/// by convention and contain `/` which the packageurl spec treats as
/// subpath segments for `pkg:golang` specifically.
fn build_golang_purl(module: &str, version: &str) -> Option<Purl> {
    // purl-spec § Character encoding: Go versions like
    // `v1.2.3+incompatible` MUST encode `+` → `%2B`. Module path `/`
    // separators are spec-allowed and pass through unchanged via
    // encode_purl_segment.
    let s = format!(
        "pkg:golang/{}@{}",
        encode_purl_segment(module),
        encode_purl_segment(version),
    );
    Purl::new(&s).ok()
}

/// Convert a `GoModDocument` + its `go.sum` entries into `PackageDbEntry`
/// values. `source_path` is the go.sum path (used for evidence). The
/// main module (from go.mod) gets its own entry with a dep list;
/// transitive modules have their `depends` populated from the module
/// cache at `<GOMODCACHE>/cache/download/<escaped>/@v/<version>.mod`
/// when `cache` can resolve it — otherwise the transitive entry stays
/// edge-less.
pub(crate) fn build_entries_from_go_module(
    doc: &GoModDocument,
    sums: &[GoSumEntry],
    source_path: &str,
    cache: &GoModCache,
) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();
    let mut seen_purls: HashSet<String> = HashSet::new();

    // Intentionally NOT emitting the project's own go.mod module as a
    // component — it's the workspace root being scanned, not a
    // dependency consumed by it. This mirrors the cargo + npm + maven
    // workspace filters (see `scan_fs/package_db/maven.rs` comment
    // block for the full rationale). The project's declared `module X`
    // path has no upstream PURL (it's what we're producing the SBOM
    // FOR), so emitting it as a dependency is a false positive and
    // also drags down sbomqs licensing because we have no license
    // source for the project itself.

    // --- Transitive modules (from go.sum) -----------------------------------
    for entry in sums {
        if entry.kind != GoSumKind::Module {
            continue;
        }
        let Some((resolved_path, resolved_version)) = apply_replace_and_exclude(
            &entry.module,
            &entry.version,
            &doc.replaces,
            &doc.excludes,
        ) else {
            continue;
        };
        let Some(purl) = build_golang_purl(&resolved_path, &resolved_version) else {
            continue;
        };
        let purl_key = purl.as_str().to_string();
        if !seen_purls.insert(purl_key) {
            continue;
        }
        // Pull the module's own go.mod from the cache (when present)
        // and extract its direct `require` entries — these are the
        // transitive edges for this node. Unresolvable lookups produce
        // an empty `depends` vec; the scan_fs resolver drops dangling
        // targets so only modules actually observed in go.sum become
        // dependsOn edges.
        let depends = cache_lookup_depends(cache, &resolved_path, &resolved_version);
        // Attach the module's `h1:` dirhash as a SHA-256 component
        // hash. This isn't a tarball hash — it's SHA-256 over a
        // sorted manifest of per-file hashes (see
        // `golang.org/x/mod/sumdb/dirhash`) — but the bytes ARE a
        // valid 32-byte SHA-256 and CDX's `component.hashes[]`
        // accepts any SHA-256. sbomqs's `comp_with_strong_checksums`
        // scorer counts it; humans who care about the specific
        // semantic (tarball vs dirhash) see the disambiguating tier
        // marker (`mikebom:sbom-tier = source`).
        let hashes = h1_to_content_hash(&entry.hash).into_iter().collect();
        out.push(PackageDbEntry {
            purl,
            name: resolved_path,
            version: resolved_version,
            arch: None,
            source_path: source_path.to_string(),
            depends,
            maintainer: None,
            licenses: Vec::new(),
            is_dev: None,
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
            parent_purl: None,
            npm_role: None,
            co_owned_by: None,
            hashes,
            sbom_tier: Some("source".to_string()),
            shade_relocation: None,
        });
    }

    out
}

/// Fetch a module's own go.mod from `cache` and return its direct
/// `require`-d module names. Indirect entries are included (we can't
/// tell post-hoc which of the upstream module's deps ended up in the
/// current project's build graph — better to emit the full edge set
/// and let the scan-wide dedup drop dangling targets).
fn cache_lookup_depends(cache: &GoModCache, module: &str, version: &str) -> Vec<String> {
    let Some(text) = cache.read_mod_file(module, version) else {
        return Vec::new();
    };
    let upstream_doc = parse_go_mod(&text);
    upstream_doc
        .requires
        .into_iter()
        .map(|r| r.path)
        .collect()
}

// ---------------------------------------------------------------------------
// Public reader
// ---------------------------------------------------------------------------

/// Walk `rootfs` looking for Go project roots (any directory containing
/// both `go.mod` and `go.sum`) and convert each into SBOM entries. The
/// walk is bounded by [`MAX_PROJECT_ROOT_DEPTH`] and skips descents into
/// `vendor/`, `.git/`, `node_modules/`, `target/`, `dist/`, and
/// `__pycache__/` — the same shape the npm + pip readers use.
/// Cross-reader signals collected during Go source-tree scanning.
/// Consumed by the aggregation filters in `package_db::read_all`:
///
/// * `main_modules` — Go module paths declared as the project's own
///   `module` directive in any scanned go.mod. Feeds the G5 filter
///   (feature 007 US3): a project is never its own dependency.
/// * `production_imports` — Go module paths that are reachable from
///   at least one non-`_test.go` import anywhere in the scanned
///   source tree. Feeds the G4 filter (feature 007 US2): modules
///   only imported from `_test.go` files are test-scope transitives
///   and shouldn't surface as runtime dependencies.
#[derive(Debug, Default)]
pub struct GoScanSignals {
    pub main_modules: HashSet<String>,
    pub production_imports: HashSet<String>,
}

pub fn read(rootfs: &Path, _include_dev: bool) -> (Vec<PackageDbEntry>, GoScanSignals) {
    let mut out: Vec<PackageDbEntry> = Vec::new();
    let mut seen_purls: HashSet<String> = HashSet::new();
    let mut signals = GoScanSignals::default();
    // Discover module cache roots once per scan — N module lookups
    // would otherwise stat the same non-existent paths repeatedly.
    let cache = GoModCache::discover(rootfs);
    if !cache.roots.is_empty() {
        tracing::debug!(
            rootfs = %rootfs.display(),
            cache_roots = cache.roots.len(),
            "Go module cache discovered",
        );
    }

    // First pass: collect every project root's (doc, sums) so we can
    // build the union of known module paths BEFORE the import-scan
    // pass. The production-import filter (G4) needs to longest-
    // prefix-match import strings against this union.
    let project_roots = candidate_project_roots(rootfs);
    let mut parsed_roots: Vec<(PathBuf, GoModDocument, Vec<GoSumEntry>)> = Vec::new();
    let mut known_modules: Vec<String> = Vec::new();
    for project_root in &project_roots {
        let go_mod_path = project_root.join("go.mod");
        let go_sum_path = project_root.join("go.sum");
        if !go_mod_path.is_file() {
            continue;
        }
        let Ok(go_mod_text) = std::fs::read_to_string(&go_mod_path) else {
            continue;
        };
        let doc = parse_go_mod(&go_mod_text);
        let sums = if go_sum_path.is_file() {
            std::fs::read_to_string(&go_sum_path)
                .map(|s| parse_go_sum(&s))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        if let Some(ref main_path) = doc.module_path {
            signals.main_modules.insert(main_path.clone());
        }
        for req in &doc.requires {
            known_modules.push(req.path.clone());
        }
        for sum in &sums {
            if sum.kind == GoSumKind::Module {
                known_modules.push(sum.module.clone());
            }
        }
        parsed_roots.push((project_root.clone(), doc, sums));
    }
    // Longest-prefix match requires the longest path to be tried first.
    known_modules.sort_by_key(|m| std::cmp::Reverse(m.len()));
    known_modules.dedup();

    // Second pass: emit entries AND walk .go files for production
    // imports.
    for (project_root, doc, sums) in &parsed_roots {
        let go_sum_path = project_root.join("go.sum");
        let source_path = go_sum_path.to_string_lossy().into_owned();
        let entries = build_entries_from_go_module(doc, sums, &source_path, &cache);
        for entry in entries {
            let purl_key = entry.purl.as_str().to_string();
            if seen_purls.insert(purl_key) {
                out.push(entry);
            }
        }
        // Feature 007 US2: walk .go source files under this project
        // root (excluding `_test.go` files and test-adjacent subtrees)
        // and record every imported module path that matches a known
        // module in `known_modules`. Imports of stdlib or unknown
        // paths are silently ignored.
        collect_production_imports(
            project_root,
            0,
            &known_modules,
            &mut signals.production_imports,
        );
    }

    if !out.is_empty() {
        tracing::info!(
            rootfs = %rootfs.display(),
            modules = out.len(),
            production_imports = signals.production_imports.len(),
            main_modules = signals.main_modules.len(),
            "parsed Go source tree",
        );
    }
    (out, signals)
}

/// Walk a Go project root collecting production-scope imports. Skips
/// `_test.go` files (test-scope) and any directory `should_skip_descent`
/// says to skip. For each remaining `.go` file, extracts import paths
/// via [`extract_go_imports`] and longest-prefix-matches each one
/// against `known_modules`. Matches are inserted into `out`.
///
/// The `known_modules` slice MUST be sorted by length descending so
/// the first prefix match is the longest (e.g., import
/// `github.com/foo/bar/baz` correctly attributes to module
/// `github.com/foo/bar` when both `github.com/foo` and
/// `github.com/foo/bar` are known modules).
fn collect_production_imports(
    dir: &Path,
    depth: usize,
    known_modules: &[String],
    out: &mut HashSet<String>,
) {
    if depth >= MAX_PROJECT_ROOT_DEPTH {
        return;
    }
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            if should_skip_descent(&path) {
                continue;
            }
            collect_production_imports(&path, depth + 1, known_modules, out);
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with(".go") {
            continue;
        }
        if name.ends_with("_test.go") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        for import_path in extract_go_imports(&bytes) {
            for module in known_modules {
                if import_path == *module
                    || import_path.starts_with(&format!("{module}/"))
                {
                    out.insert(module.clone());
                    break;
                }
            }
        }
    }
}

/// Extract every `import "…"` or grouped `import ( … )` path from a Go
/// source file. Returns the raw import path strings (e.g.,
/// `"github.com/sirupsen/logrus"`). Hand-rolled byte scanner — Go's
/// import syntax is simple enough that we don't need a full parser
/// and an external crate is overkill for "find import strings."
pub(crate) fn extract_go_imports(bytes: &[u8]) -> Vec<String> {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut remaining = text;
    while let Some(idx) = remaining.find("import") {
        let after = &remaining[idx + "import".len()..];
        // "import" must be a keyword, not part of a longer identifier.
        let before_is_boundary = idx == 0
            || matches!(
                remaining.as_bytes().get(idx.wrapping_sub(1)),
                Some(c) if !c.is_ascii_alphanumeric() && *c != b'_'
            );
        let after_is_boundary = after
            .as_bytes()
            .first()
            .map(|c| !c.is_ascii_alphanumeric() && *c != b'_')
            .unwrap_or(false);
        if !before_is_boundary || !after_is_boundary {
            let Some(next) = remaining.get(idx + 1..) else {
                break;
            };
            remaining = next;
            continue;
        }
        let trimmed = after.trim_start();
        if let Some(rest) = trimmed.strip_prefix('(') {
            // Grouped block: consume up to matching ')'.
            if let Some(end_rel) = rest.find(')') {
                let block = &rest[..end_rel];
                for line in block.lines() {
                    if let Some(path) = parse_import_line(line) {
                        out.push(path);
                    }
                }
                remaining = &rest[end_rel + 1..];
            } else {
                break;
            }
        } else if let Some(path) = parse_import_line(trimmed) {
            // Single-line import. Advance past the line.
            out.push(path);
            let Some(nl) = trimmed.find('\n') else {
                break;
            };
            remaining = &trimmed[nl + 1..];
        } else {
            let Some(next) = remaining.get(idx + 1..) else {
                break;
            };
            remaining = next;
        }
    }
    out
}

/// Parse a single import line. Handles optional alias (`foo "path"`,
/// `. "path"`, `_ "path"`) and returns just the quoted path.
fn parse_import_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with("//") {
        return None;
    }
    let quote_start = line.find('"')?;
    let after = &line[quote_start + 1..];
    let quote_end = after.find('"')?;
    Some(after[..quote_end].to_string())
}

fn candidate_project_roots(rootfs: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    walk_for_go_roots(rootfs, 0, &mut out, &mut visited);
    out
}

fn walk_for_go_roots(
    dir: &Path,
    depth: usize,
    out: &mut Vec<PathBuf>,
    visited: &mut HashSet<PathBuf>,
) {
    let key = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if !visited.insert(key) {
        return;
    }

    if dir.join("go.mod").is_file() {
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
        if should_skip_descent(&path) {
            continue;
        }
        walk_for_go_roots(&path, depth + 1, out, visited);
    }
}

/// Skip descent into directories that can't legitimately hold a
/// project root — dev-time residue, build outputs, and language-
/// specific vendor trees. Also skips Go's module cache
/// (`.../go/pkg/mod/...`) wherever it appears in the rootfs: the
/// cache is populated at build time by `go mod download` and
/// shouldn't contribute components to the scanned-image SBOM.
/// (This is a typical signature of a multi-stage Docker build that
/// copied the builder's cache into the image.)
fn should_skip_descent(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return true;
    };
    if name.starts_with('.') {
        return true;
    }
    if matches!(
        name,
        "vendor" | "node_modules" | "target" | "dist" | "build" | "__pycache__"
    ) {
        return true;
    }
    // Go module cache: `.../go/pkg/mod/...` anywhere in the
    // rootfs. Each cached module ships its own `go.mod`, so without
    // this skip the walker treats every cached module as a project
    // root and emits its deps as components — 21 FPs on polyglot.
    //
    // Recognize the three-component signature `.../go/pkg/mod/...`
    // via a sliding-window check over path components. Catches
    // `$HOME/go/pkg/mod`, `/root/go/pkg/mod`, `/go/pkg/mod`,
    // `/workspace/go/pkg/mod`, etc. — any layout where Go's
    // standard `GOMODCACHE` convention applies.
    let components: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    for window in components.windows(3) {
        if window == ["go", "pkg", "mod"] {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    // --- go.mod parser -----------------------------------------------------

    #[test]
    fn parses_minimal_go_mod() {
        let src = "module example.com/app\n\ngo 1.22\n";
        let doc = parse_go_mod(src);
        assert_eq!(doc.module_path.as_deref(), Some("example.com/app"));
        assert_eq!(doc.go_version.as_deref(), Some("1.22"));
        assert!(doc.requires.is_empty());
    }

    #[test]
    fn parses_multi_require_block() {
        let src = r#"
module example.com/app

go 1.22

require (
    github.com/spf13/cobra v1.7.0
    github.com/sirupsen/logrus v1.9.0 // indirect
    gopkg.in/yaml.v3 v3.0.1
)
"#;
        let doc = parse_go_mod(src);
        assert_eq!(doc.requires.len(), 3);
        assert!(doc
            .requires
            .iter()
            .any(|r| r.path == "github.com/spf13/cobra" && r.version == "v1.7.0" && !r.indirect));
        assert!(doc
            .requires
            .iter()
            .any(|r| r.path == "github.com/sirupsen/logrus" && r.indirect));
    }

    #[test]
    fn parses_single_line_require() {
        let src = "module x\nrequire github.com/pkg/errors v0.9.1\n";
        let doc = parse_go_mod(src);
        assert_eq!(doc.requires.len(), 1);
        assert_eq!(doc.requires[0].path, "github.com/pkg/errors");
        assert_eq!(doc.requires[0].version, "v0.9.1");
    }

    #[test]
    fn parses_replace_directive() {
        let src = r#"
module x
replace github.com/old/lib v1.0.0 => github.com/new/lib v2.0.0
"#;
        let doc = parse_go_mod(src);
        let k = ("github.com/old/lib".to_string(), "v1.0.0".to_string());
        let v = doc.replaces.get(&k).unwrap();
        assert_eq!(v.0, "github.com/new/lib");
        assert_eq!(v.1, "v2.0.0");
    }

    #[test]
    fn parses_replace_without_old_version() {
        let src = "module x\nreplace github.com/old/lib => github.com/new/lib v2.0.0\n";
        let doc = parse_go_mod(src);
        let k = ("github.com/old/lib".to_string(), String::new());
        assert!(doc.replaces.contains_key(&k));
    }

    #[test]
    fn parses_exclude_directive() {
        let src = "module x\nexclude github.com/bad/lib v0.0.1\n";
        let doc = parse_go_mod(src);
        assert!(doc
            .excludes
            .contains(&("github.com/bad/lib".to_string(), "v0.0.1".to_string())));
    }

    #[test]
    fn line_comments_are_stripped() {
        let src = "module x // main module comment\ngo 1.22 // min version\n";
        let doc = parse_go_mod(src);
        assert_eq!(doc.module_path.as_deref(), Some("x"));
        assert_eq!(doc.go_version.as_deref(), Some("1.22"));
    }

    // --- go.sum parser -----------------------------------------------------

    #[test]
    fn parses_module_and_gomod_pair() {
        let src = "github.com/a/b v1.0.0 h1:abc=\ngithub.com/a/b v1.0.0/go.mod h1:def=\n";
        let sums = parse_go_sum(src);
        assert_eq!(sums.len(), 2);
        assert_eq!(sums[0].kind, GoSumKind::Module);
        assert_eq!(sums[1].kind, GoSumKind::GoMod);
    }

    #[test]
    fn parses_pseudo_version() {
        let src = "github.com/a/b v0.0.0-20240101000000-abcdef123456 h1:xyz=\n";
        let sums = parse_go_sum(src);
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].version, "v0.0.0-20240101000000-abcdef123456");
    }

    #[test]
    fn malformed_go_sum_lines_are_skipped() {
        let src = "garbage\nfoo bar\ngithub.com/x/y v1.0.0 h1:ok=\n";
        let sums = parse_go_sum(src);
        assert_eq!(sums.len(), 1);
    }

    #[test]
    fn go_sum_line_without_h1_prefix_is_skipped() {
        // Some odd tools emit `sha256:` — we only trust h1:.
        let src = "github.com/x/y v1.0.0 sha256:notvalid\n";
        assert!(parse_go_sum(src).is_empty());
    }

    // --- entry construction ------------------------------------------------

    #[test]
    fn entries_exclude_workspace_root() {
        // The project's own `module X` from go.mod is NOT emitted —
        // it's the scan target, not a dependency. Mirrors cargo/npm/
        // maven workspace-root filters.
        let doc = parse_go_mod(
            "module example.com/app\ngo 1.22\nrequire github.com/x/y v1.0.0\n",
        );
        // 32-byte SHA-256, base64-encoded — 44 chars incl. one `=`
        // pad. The literal chosen doesn't correspond to any real
        // module; the decoder only validates length + base64.
        let sums = parse_go_sum(
            "github.com/x/y v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
        );
        let entries = build_entries_from_go_module(&doc, &sums, "/p/go.sum", &GoModCache::default());
        assert_eq!(entries.len(), 1, "only the transitive dep surfaces");
        assert!(!entries.iter().any(|e| e.name == "example.com/app"));
        assert_eq!(entries[0].name, "github.com/x/y");
        assert_eq!(entries[0].sbom_tier.as_deref(), Some("source"));
    }

    #[test]
    fn h1_decode_yields_sha256_content_hash() {
        use mikebom_common::types::hash::HashAlgorithm;
        // `h1:` + base64 of 32 zero bytes = 42 `A`s plus `==` pad...
        // actually: base64(32 bytes) = ceil(32*8/6) = 44 chars with
        // one `=` pad (32 bytes = 256 bits; 256/6 = 42.67 → 43 non-
        // pad chars + 1 pad).
        let h1 = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let hash = h1_to_content_hash(h1).expect("valid h1 decodes");
        assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
        // 32 zero bytes = 64 zero hex chars.
        assert_eq!(hash.value.as_str(), "0".repeat(64));
    }

    #[test]
    fn h1_decode_rejects_missing_prefix() {
        let bad = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(h1_to_content_hash(bad).is_none());
    }

    #[test]
    fn h1_decode_rejects_wrong_length() {
        // 16 bytes of base64 — wrong size.
        let bad = "h1:AAAAAAAAAAAAAAAAAAAAAA==";
        assert!(h1_to_content_hash(bad).is_none());
    }

    #[test]
    fn build_entries_attaches_module_hash_from_go_sum() {
        use mikebom_common::types::hash::HashAlgorithm;
        let doc = parse_go_mod(
            "module example.com/app\ngo 1.22\nrequire github.com/x/y v1.0.0\n",
        );
        let sums = parse_go_sum(
            "github.com/x/y v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
        );
        let entries = build_entries_from_go_module(&doc, &sums, "/p/go.sum", &GoModCache::default());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hashes.len(), 1);
        assert_eq!(entries[0].hashes[0].algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn gomod_kind_sum_line_produces_no_component_even_with_hash() {
        // The `<module>/go.mod` sum line carries a hash too, but it
        // hashes go.mod (not the module) — we drop the whole entry
        // upstream so no component is constructed from it.
        let doc = parse_go_mod("module x\ngo 1.22\n");
        let sums = parse_go_sum(
            "github.com/x/y v1.0.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
        );
        let entries = build_entries_from_go_module(&doc, &sums, "/p/go.sum", &GoModCache::default());
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn replace_changes_purl() {
        let doc = parse_go_mod(
            "module x\ngo 1.22\nrequire github.com/old/lib v1.0.0\nreplace github.com/old/lib v1.0.0 => github.com/new/lib v2.0.0\n",
        );
        let sums = parse_go_sum("github.com/old/lib v1.0.0 h1:ok=\n");
        let entries = build_entries_from_go_module(&doc, &sums, "/go.sum", &GoModCache::default());
        let transitive = entries
            .iter()
            .find(|e| e.name == "github.com/new/lib")
            .expect("replacement applied");
        assert_eq!(transitive.version, "v2.0.0");
        assert_eq!(transitive.purl.as_str(), "pkg:golang/github.com/new/lib@v2.0.0");
    }

    #[test]
    fn exclude_filters_entry() {
        let doc = parse_go_mod(
            "module x\ngo 1.22\nexclude github.com/bad/lib v1.0.0\n",
        );
        let sums = parse_go_sum("github.com/bad/lib v1.0.0 h1:ok=\n");
        let entries = build_entries_from_go_module(&doc, &sums, "/go.sum", &GoModCache::default());
        assert!(entries.iter().all(|e| e.name != "github.com/bad/lib"));
    }

    #[test]
    fn replace_to_local_path_is_dropped() {
        let doc = parse_go_mod(
            "module x\ngo 1.22\nreplace github.com/old/lib v1.0.0 => ./vendor/local\n",
        );
        let sums = parse_go_sum("github.com/old/lib v1.0.0 h1:ok=\n");
        let entries = build_entries_from_go_module(&doc, &sums, "/go.sum", &GoModCache::default());
        // Only the main module should remain.
        assert!(entries.iter().all(|e| e.name != "github.com/old/lib"));
        assert!(entries.iter().all(|e| !e.name.starts_with("./")));
    }

    #[test]
    fn gomod_kind_entries_do_not_produce_components() {
        let doc = parse_go_mod("module x\ngo 1.22\n");
        let sums = parse_go_sum("github.com/x/y v1.0.0/go.mod h1:abc=\n");
        let entries = build_entries_from_go_module(&doc, &sums, "/go.sum", &GoModCache::default());
        // Workspace root (`x`) is suppressed, AND the `/go.mod` sum line
        // is `GoSumKind::GoMod` so it doesn't produce a transitive
        // component either. Net: zero entries.
        assert_eq!(entries.len(), 0);
    }

    // --- module cache walker ----------------------------------------------

    #[test]
    fn module_path_escaping_handles_capitals() {
        assert_eq!(escape_module_path("github.com/spf13/cobra"), "github.com/spf13/cobra");
        assert_eq!(
            escape_module_path("github.com/Azure/azure-sdk-for-go"),
            "github.com/!azure/azure-sdk-for-go",
        );
        assert_eq!(
            escape_module_path("github.com/ClickHouse/clickhouse-go"),
            "github.com/!click!house/clickhouse-go",
        );
        // Non-letter characters pass through unchanged.
        assert_eq!(escape_module_path("go.yaml.in/yaml/v3"), "go.yaml.in/yaml/v3");
    }

    fn write_mod_cache_entry(
        cache_root: &Path,
        module: &str,
        version: &str,
        body: &str,
    ) {
        let rel = format!(
            "cache/download/{}/@v/{}.mod",
            escape_module_path(module),
            version
        );
        let full = cache_root.join(&rel);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&full, body).unwrap();
    }

    #[test]
    fn cache_read_mod_file_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let cache_root = dir.path().join("go/pkg/mod");
        write_mod_cache_entry(
            &cache_root,
            "github.com/spf13/cobra",
            "v1.10.2",
            "module github.com/spf13/cobra\ngo 1.15\nrequire github.com/spf13/pflag v1.0.9\n",
        );
        // Wire the cache root in explicitly, bypassing env discovery.
        let cache = GoModCache {
            roots: vec![cache_root.clone()],
        };
        let text = cache
            .read_mod_file("github.com/spf13/cobra", "v1.10.2")
            .expect("cached .mod file readable");
        assert!(text.contains("github.com/spf13/pflag"));
    }

    #[test]
    fn entries_pull_transitive_deps_from_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache_root = dir.path().join("go/pkg/mod");
        // cobra depends on pflag in its own go.mod
        write_mod_cache_entry(
            &cache_root,
            "github.com/spf13/cobra",
            "v1.7.0",
            "module github.com/spf13/cobra\ngo 1.15\nrequire github.com/spf13/pflag v1.0.5 // indirect\n",
        );
        let doc = parse_go_mod(
            "module example.com/app\ngo 1.22\nrequire github.com/spf13/cobra v1.7.0\n",
        );
        let sums = parse_go_sum(
            "github.com/spf13/cobra v1.7.0 h1:ok=\ngithub.com/spf13/pflag v1.0.5 h1:ok=\n",
        );
        let cache = GoModCache {
            roots: vec![cache_root.clone()],
        };
        let entries = build_entries_from_go_module(&doc, &sums, "/p/go.sum", &cache);
        let cobra = entries
            .iter()
            .find(|e| e.name == "github.com/spf13/cobra")
            .expect("cobra entry present");
        assert_eq!(
            cobra.depends,
            vec!["github.com/spf13/pflag".to_string()],
            "cobra's cached go.mod declared pflag — expected edge populated",
        );
    }

    #[test]
    fn transitive_deps_empty_when_cache_missing() {
        // Same fixture as above but without any cache root registered —
        // the transitive entry should still emit with empty `depends`.
        let doc = parse_go_mod(
            "module example.com/app\ngo 1.22\nrequire github.com/spf13/cobra v1.7.0\n",
        );
        let sums = parse_go_sum("github.com/spf13/cobra v1.7.0 h1:ok=\n");
        let entries = build_entries_from_go_module(
            &doc,
            &sums,
            "/p/go.sum",
            &GoModCache::default(),
        );
        let cobra = entries
            .iter()
            .find(|e| e.name == "github.com/spf13/cobra")
            .expect("cobra entry present");
        assert!(cobra.depends.is_empty());
    }

    // --- reader ------------------------------------------------------------

    #[test]
    fn read_empty_rootfs_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let (entries, _signals) = read(dir.path(), false);
        assert!(entries.is_empty());
    }

    #[test]
    fn read_finds_nested_go_project() {
        let dir = tempfile::tempdir().unwrap();
        let svc = dir.path().join("services").join("api");
        std::fs::create_dir_all(&svc).unwrap();
        std::fs::write(
            svc.join("go.mod"),
            "module example.com/api\ngo 1.22\nrequire github.com/x/y v1.0.0\n",
        )
        .unwrap();
        std::fs::write(svc.join("go.sum"), "github.com/x/y v1.0.0 h1:ok=\n")
            .unwrap();
        let (entries, _) = read(dir.path(), false);
        // Workspace root (`example.com/api`) is NOT emitted; only the
        // transitive dep surfaces as a component.
        assert!(!entries.iter().any(|e| e.name == "example.com/api"));
        assert!(entries.iter().any(|e| e.name == "github.com/x/y"));
    }

    // --- Go module cache exclusion (M4) ---------------------------------

    fn write_go_project(root: &Path, module: &str, deps: &[(&str, &str)]) {
        std::fs::create_dir_all(root).unwrap();
        let mut go_mod = format!("module {module}\ngo 1.22\n");
        if !deps.is_empty() {
            go_mod.push_str("require (\n");
            for (path, version) in deps {
                go_mod.push_str(&format!("    {path} {version}\n"));
            }
            go_mod.push_str(")\n");
        }
        std::fs::write(root.join("go.mod"), go_mod).unwrap();
        let mut go_sum = String::new();
        for (path, version) in deps {
            go_sum.push_str(&format!("{path} {version} h1:fake=\n"));
        }
        std::fs::write(root.join("go.sum"), go_sum).unwrap();
    }

    #[test]
    fn walker_skips_root_go_pkg_mod_trees() {
        // Multi-stage Docker build pattern: build-stage `go mod
        // download` populates `/root/go/pkg/mod/`, which then gets
        // carried into the final image. Each cached module has its
        // own `go.mod` — the walker must NOT treat them as project
        // roots.
        let dir = tempfile::tempdir().unwrap();
        let cache =
            dir.path().join("root/go/pkg/mod/github.com/foo/bar@v1.0.0");
        write_go_project(&cache, "github.com/foo/bar", &[("github.com/x/y", "v2.0.0")]);
        let (entries, _) = read(dir.path(), false);
        assert!(
            entries.is_empty(),
            "walker must skip /root/go/pkg/mod cache tree: {entries:?}",
        );
    }

    #[test]
    fn walker_skips_home_user_go_pkg_mod() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            dir.path().join("home/alice/go/pkg/mod/github.com/foo/bar@v1.0.0");
        write_go_project(&cache, "github.com/foo/bar", &[("github.com/x/y", "v2.0.0")]);
        let (entries, _) = read(dir.path(), false);
        assert!(
            entries.is_empty(),
            "walker must skip $HOME/go/pkg/mod cache tree: {entries:?}",
        );
    }

    #[test]
    fn walker_still_finds_legitimate_project_roots() {
        // Control: a real project at `/app/go.mod` + `/app/go.sum`
        // still emits normally after M4.
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("app");
        write_go_project(&app, "example.com/app", &[("github.com/real/dep", "v1.2.3")]);
        let (entries, _) = read(dir.path(), false);
        assert!(
            entries.iter().any(|e| e.name == "github.com/real/dep"),
            "legitimate project root must still emit: {entries:?}",
        );
    }

    #[test]
    fn walker_skips_gopath_outside_standard_paths() {
        // Non-standard `GOPATH` layout — still matches the
        // `.../go/pkg/mod/...` path-component signature.
        let dir = tempfile::tempdir().unwrap();
        let cache = dir
            .path()
            .join("workspace/go/pkg/mod/github.com/foo/bar@v1.0.0");
        write_go_project(&cache, "github.com/foo/bar", &[("github.com/x/y", "v2.0.0")]);
        let (entries, _) = read(dir.path(), false);
        assert!(
            entries.is_empty(),
            "walker must skip /workspace/go/pkg/mod cache tree: {entries:?}",
        );
    }
}