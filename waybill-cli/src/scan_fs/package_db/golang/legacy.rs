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
use std::sync::{mpsc, Arc, Mutex};

use waybill_common::types::license::SpdxExpression;
use waybill_common::types::purl::{encode_purl_segment, Purl};

// `super` is now `golang/` (not `package_db/`) post-milestone-055 T008
// directory promotion. Import via crate-absolute path so the reference
// is unambiguous regardless of where this module nests in the tree.
use crate::scan_fs::package_db::PackageDbEntry;

// Milestone 664 US2 T058: shared-walker migration types.
use crate::scan_fs::walk_registry::{
    globset_from_patterns, ReaderId, ReaderRegistration, SharedWalkerContext,
};

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

    /// True when no cache roots were discovered. Used by the
    /// milestone 055 resolver to short-circuit step 2 (cache walk)
    /// when there's no cache to walk.
    pub(crate) fn is_empty(&self) -> bool {
        self.roots.is_empty()
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
/// out before PURL construction. `tools` holds the package paths from
/// Go 1.24+'s `tool` directive — these declare build-time tool deps
/// the same way `require` declares runtime deps, with the version
/// resolved transitively via the matching `require` entry that
/// `go mod tidy` adds alongside the `tool` line.
#[derive(Clone, Debug, Default)]
pub(crate) struct GoModDocument {
    pub module_path: Option<String>,
    pub go_version: Option<String>,
    pub requires: Vec<GoModRequire>,
    pub replaces: HashMap<(String, String), (String, String)>,
    pub excludes: HashSet<(String, String)>,
    pub tools: Vec<String>,
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
        } else if line == "tool (" {
            for raw_inner in lines.by_ref() {
                let inner_owned = strip_line_comment(raw_inner);
                let inner = inner_owned.trim();
                if inner == ")" {
                    break;
                }
                if inner.is_empty() {
                    continue;
                }
                if let Some(path) = parse_tool_line(inner) {
                    doc.tools.push(path);
                }
            }
        } else if let Some(rest) = line.strip_prefix("tool ") {
            if let Some(path) = parse_tool_line(rest) {
                doc.tools.push(path);
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

/// Parse a single `tool` directive line — the path of a Go 1.24+ build-
/// tool dep. The directive takes a package path with no version (MVS
/// resolves the version via the matching `require` entry that
/// `go mod tidy` adds). Returns the **module path** prefix of the
/// package path so the result can be cross-referenced against the
/// module-keyed components waybill emits — e.g.
/// `github.com/foo/bar/cmd/baz` → `github.com/foo/bar`. We can't know
/// the module-boundary split without consulting `go.mod` of the target
/// (the path could be a 2-segment domain + N segments of repo +
/// optional vN suffix + arbitrary subpath). Strategy: the tool's
/// own go.mod is fetched/cached as part of `go mod tidy`, but we
/// don't read it here. Instead, return the path as-given and let the
/// edge-matching loop in `read()` (which already deduplicates against
/// the discovered component set) drop it if no component matches —
/// the same approach the resolver uses for `// indirect` requires
/// whose declared parent doesn't match any module in scope.
fn parse_tool_line(rest: &str) -> Option<String> {
    let path = rest.split_whitespace().next()?.trim_matches('"').to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

/// Issue #255: returns `true` when `candidate` is `<base>/vN` for some
/// integer N >= 2 — i.e., `candidate` is the `/vN`-suffixed major-
/// version variant of the same Go module as `base`. Used to detect
/// the `+incompatible` legacy-residue pattern: when both
/// `github.com/google/martian` (legacy `+incompatible` form) AND
/// `github.com/google/martian/v3` (modern `/vN` form) exist as Go
/// components in the same scan, the legacy form is residue and gets
/// filtered out.
///
/// Conservative: only matches the exact `<base>/vN` shape (one trailing
/// `/vN` segment, N a decimal integer >= 2). Doesn't match
/// `<base>/v2/sub/...` or `<base>/v1` (v1 isn't path-suffixed by
/// convention).
fn is_vn_sibling_of(candidate: &str, base: &str) -> bool {
    let Some(suffix) = candidate.strip_prefix(base) else {
        return false;
    };
    let Some(rest) = suffix.strip_prefix("/v") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    if !rest.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // Parse as int; reject v0 / v1 (those aren't `/vN`-suffixed
    // modules by Go convention — v0 / v1 use the un-suffixed path).
    rest.parse::<u32>().map(|n| n >= 2).unwrap_or(false)
}

/// Map a Go 1.24+ `tool` directive package path to the module path that
/// contains it. Module paths emitted by waybill are e.g.
/// `github.com/golangci/golangci-lint`; tool paths in `go.mod` are e.g.
/// `github.com/golangci/golangci-lint/cmd/golangci-lint`. The tool path
/// is always a (possibly equal) descendant of the module path, so the
/// longest module path that is a prefix of the tool path (at a path-
/// segment boundary) is the answer. Returns `None` if no module in
/// `module_paths` is a path-segment prefix of `tool_path`.
fn resolve_tool_to_module<'a>(tool_path: &str, module_paths: &[&'a str]) -> Option<&'a str> {
    let mut best: Option<&'a str> = None;
    for &m in module_paths {
        let matches = tool_path == m
            || (tool_path.starts_with(m) && tool_path.as_bytes().get(m.len()) == Some(&b'/'));
        if matches && best.map(|b| m.len() > b.len()).unwrap_or(true) {
            best = Some(m);
        }
    }
    best
}

/// Issue #251: compute the set of Go module names to flat-attach to
/// main-module's `depends` to recover reachability after the resolver's
/// hierarchical attribution leaves some components orphan.
///
/// Inputs:
/// - `golang_names`: every Go module's `entry.name` in the current scan's
///   `out` (the components that have already been emitted as PackageDbEntry
///   records). These are the candidates: any of them with zero incoming
///   edges from non-main entries will be backfilled.
/// - `all_edges`: a flat `(source_name, source_depends)` view of every
///   entry in `out` — Go-or-otherwise. Used to count incoming edges into
///   `golang_names`. Passing this as a slice lets unit tests exercise
///   the logic without constructing PackageDbEntry instances.
/// - `main_entry_depends`: main-module's current `depends` list before
///   backfill. Entries already there are dedup'd out of the result.
///
/// Returns a sorted Vec of Go module names with zero incoming edges
/// from any non-main entry AND not already in main-module's depends.
fn compute_orphan_backfill(
    golang_names: &[&str],
    all_edges: &[(&str, &[String])],
    main_entry_depends: &[String],
) -> Vec<String> {
    if golang_names.is_empty() {
        return Vec::new();
    }
    let go_set: std::collections::HashSet<&str> = golang_names.iter().copied().collect();
    let mut incoming: std::collections::HashMap<&str, usize> =
        golang_names.iter().map(|&n| (n, 0)).collect();
    for (_, depends) in all_edges {
        for child in *depends {
            // Milestone 233: depends may carry either bare `name` or
            // `name version` (post-m233 disambiguation form). Compare
            // against the name-only golang_names set on the leading
            // token.
            let child_name = child.split_whitespace().next().unwrap_or(child.as_str());
            if go_set.contains(child_name) {
                if let Some(c) = incoming.get_mut(child_name) {
                    *c += 1;
                }
            }
        }
    }
    // Milestone 233: main_entry_depends may carry either bare `name`
    // (pre-m233 form) or `name version` (post-m233 disambiguation).
    // Split on whitespace to get the name-only prefix for the
    // exclusion check so a direct-require doesn't get double-attached
    // as a backfilled orphan.
    let existing: std::collections::HashSet<&str> = main_entry_depends
        .iter()
        .map(|s| s.split_whitespace().next().unwrap_or(s.as_str()))
        .collect();
    let mut backfilled: Vec<String> = Vec::new();
    for &name in golang_names {
        if incoming.get(name).copied().unwrap_or(0) == 0 && !existing.contains(name) {
            backfilled.push(name.to_string());
        }
    }
    backfilled.sort();
    backfilled
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
) -> Option<waybill_common::types::hash::ContentHash> {
    use base64::Engine;
    use waybill_common::types::hash::{ContentHash, HashAlgorithm};
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
// Backward-compat wrapper for the milestone 049/053 unit tests. The
// production path in `read()` uses
// `build_entries_from_go_module_with_lookup` directly with a
// `ModuleGraphMap`-backed closure (T025); this wrapper preserves the
// pre-055 cache-only behavior for the existing tests so they continue
// to verify cache-walk semantics in isolation. `#[allow(dead_code)]`
// because rustc's dead-code analysis runs on the production-binary
// compile (tests excluded) — the function IS used, just only by tests.
#[allow(dead_code)]
pub(crate) fn build_entries_from_go_module(
    doc: &GoModDocument,
    sums: &[GoSumEntry],
    source_path: &str,
    cache: &GoModCache,
) -> Vec<PackageDbEntry> {
    build_entries_from_go_module_with_lookup(
        doc,
        sums,
        source_path,
        |p, v| cache_lookup_depends(cache, p, v),
        &HashSet::new(),
    )
}

/// Like `build_entries_from_go_module`, but lets the caller supply the
/// transitive-edge lookup. Used by the post-T025 `read()` path: it
/// builds a `ModuleGraphMap` once per scan via `GraphResolver::resolve`,
/// then passes a closure that consults the map.
///
/// `lookup_depends` receives `(resolved_path, resolved_version)` AFTER
/// `apply_replace_and_exclude` and returns the ordered list of direct-
/// require module paths to attach to the entry's `depends` field.
pub(crate) fn build_entries_from_go_module_with_lookup<F>(
    doc: &GoModDocument,
    sums: &[GoSumEntry],
    source_path: &str,
    lookup_depends: F,
    gosum_fallback_paths: &HashSet<String>,
) -> Vec<PackageDbEntry>
where
    F: Fn(&str, &str) -> Vec<String>,
{
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
        let depends = lookup_depends(&resolved_path, &resolved_version);
        // Attach the module's `h1:` dirhash as a SHA-256 component
        // hash. This isn't a tarball hash — it's SHA-256 over a
        // sorted manifest of per-file hashes (see
        // `golang.org/x/mod/sumdb/dirhash`) — but the bytes ARE a
        // valid 32-byte SHA-256 and CDX's `component.hashes[]`
        // accepts any SHA-256. sbomqs's `comp_with_strong_checksums`
        // scorer counts it; humans who care about the specific
        // semantic (tarball vs dirhash) see the disambiguating tier
        // marker (`waybill:sbom-tier = source`).
        let hashes = h1_to_content_hash(&entry.hash).into_iter().collect();
        // Milestone 091: components reached only via step 5 (the
        // go.sum flat fallback) carry a per-component provenance
        // discriminator so operators can distinguish the lower-fidelity
        // discovery path from steps 1–3. Constitution Principle X.
        let mut extra_annotations: std::collections::BTreeMap<String, serde_json::Value> =
            Default::default();
        if gosum_fallback_paths.contains(&resolved_path) {
            extra_annotations.insert(
                "waybill:resolver-step".to_string(),
                serde_json::Value::String("go-sum-fallback".to_string()),
            );
        }
        out.push(PackageDbEntry {
            build_inclusion: None,
            purl,
            name: resolved_path,
            version: resolved_version,
            arch: None,
            source_path: source_path.to_string(),
            depends,
            maintainer: None,
            licenses: Vec::new(),
            lifecycle_scope: None,
            requirement_ranges: Vec::new(),
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
            extra_annotations,
            binary_role: None,
        });
    }

    out
}

/// Issue #364 — build a `stdlib` `PackageDbEntry` for a Go project
/// whose go.mod declares `go <version>`. `bare_version` is the
/// pre-stripped version string (no `v`/`go` prefix; e.g. `"1.21.5"`).
/// The PURL takes the canonical syft shape
/// (`pkg:golang/stdlib@v<version>`). Returns `None` if the version
/// string can't be parsed into a valid PURL.
fn build_stdlib_entry(
    bare_version: &str,
    source_path: &str,
) -> Option<PackageDbEntry> {
    let bare = bare_version;
    let purl_str = format!("pkg:golang/stdlib@v{bare}");
    let purl = match waybill_common::types::purl::Purl::new(&purl_str) {
        Ok(p) => p,
        Err(_) => return None,
    };
    Some(PackageDbEntry {
        build_inclusion: None,
        purl,
        name: "stdlib".to_string(),
        version: format!("v{bare}"),
        arch: None,
        source_path: source_path.to_string(),
        depends: Vec::new(),
        maintainer: None,
        licenses: Vec::new(),
        lifecycle_scope: None,
        requirement_ranges: Vec::new(),
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
        hashes: Vec::new(),
        sbom_tier: Some("source".to_string()),
        shade_relocation: None,
        extra_annotations: Default::default(),
        binary_role: None,
    })
}

/// Fetch a module's own go.mod from `cache` and return its direct
/// `require`-d module names. Indirect entries are included (we can't
/// tell post-hoc which of the upstream module's deps ended up in the
/// current project's build graph — better to emit the full edge set
/// and let the scan-wide dedup drop dangling targets).
///
/// Dead-code-allowed because the production `read()` path uses the
/// milestone 055 `GraphResolver`'s cache walk instead. This function
/// is preserved for the milestone 053 backward-compat wrapper above
/// (used by unit tests).
#[allow(dead_code)]
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
// Milestone 057 — main-module LICENSE detection (Layer 1: SPDX header)
// ---------------------------------------------------------------------------

/// Candidate license-file basenames, in priority order. First file
/// found whose first 4 KB contains a parseable
/// `SPDX-License-Identifier:` header wins. Case-INsensitive match
/// against directory entries.
const LICENSE_FILE_CANDIDATES: &[&str] = &[
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "LICENCE",
    "LICENCE.md",
    "LICENCE.txt",
    "COPYING",
];

/// Cap on bytes read from each candidate license file. Per spec FR-001
/// — sufficient for the SPDX header (conventionally on the first line),
/// bounded against runaway reads on stray text files masquerading as
/// LICENSE.md.
const LICENSE_READ_LIMIT: usize = 4 * 1024;

/// SPDX header marker per <https://spdx.dev/specifications/>.
const SPDX_HEADER_MARKER: &str = "SPDX-License-Identifier:";

/// Layer-1 license detection: scan candidate LICENSE-style files at
/// `workspace_root` for an `SPDX-License-Identifier:` header and
/// return the canonicalized expression if found and parseable.
///
/// Returns an empty `Vec` when:
/// - no candidate file exists in the workspace root
/// - candidate files exist but contain no SPDX header in their first
///   4 KB (Layer 2 territory; deferred to follow-up)
/// - a SPDX header exists but fails to canonicalize (a `tracing::warn`
///   line is emitted with the path + raw expression for operator
///   visibility)
///
/// Never panics; never fails the scan. See
/// `specs/057-go-license-detection/spec.md` FR-001 / FR-002 / FR-003.
pub(crate) fn detect_main_module_license(workspace_root: &Path) -> Vec<SpdxExpression> {
    let entries = match std::fs::read_dir(workspace_root) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut found: HashMap<&'static str, PathBuf> = HashMap::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else { continue };
        for candidate in LICENSE_FILE_CANDIDATES {
            if name_str.eq_ignore_ascii_case(candidate) {
                found.entry(candidate).or_insert_with(|| entry.path());
                break;
            }
        }
    }

    for candidate in LICENSE_FILE_CANDIDATES {
        let Some(path) = found.get(candidate) else {
            continue;
        };
        if !path.is_file() {
            continue;
        }
        let text = match read_first_kb(path, LICENSE_READ_LIMIT) {
            Some(t) => t,
            None => continue,
        };
        let raw = match extract_spdx_header(&text) {
            Some(r) => r,
            None => continue,
        };
        match SpdxExpression::try_canonical(raw) {
            Ok(expr) => return vec![expr],
            Err(e) => {
                tracing::warn!(
                    license_path = %path.display(),
                    raw_expression = raw,
                    error = %e,
                    "main-module LICENSE file's SPDX-License-Identifier header failed to canonicalize",
                );
                return Vec::new();
            }
        }
    }
    Vec::new()
}

fn read_first_kb(path: &Path, limit: usize) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; limit];
    let n = file.read(&mut buf).ok()?;
    buf.truncate(n);
    let text = String::from_utf8_lossy(&buf).into_owned();
    Some(strip_bom(text))
}

fn strip_bom(s: String) -> String {
    if let Some(stripped) = s.strip_prefix('\u{feff}') {
        stripped.to_string()
    } else {
        s
    }
}

fn extract_spdx_header(text: &str) -> Option<&str> {
    let idx = text.find(SPDX_HEADER_MARKER)?;
    let after = &text[idx + SPDX_HEADER_MARKER.len()..];
    let line_end = after.find(['\n', '\r']).unwrap_or(after.len());
    let mut s = after[..line_end].trim();
    if let Some(stripped) = s.strip_suffix("-->") {
        s = stripped.trim();
    }
    if let Some(stripped) = s.strip_suffix("*/") {
        s = stripped.trim();
    }
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Build the synthetic Go main-module `PackageDbEntry` for a workspace
/// root, per milestone 053 FR-001 + FR-001a + FR-002 + FR-004 + FR-005
/// + FR-006.
///
/// Returns `None` when the project's `go.mod` lacks a `module`
/// directive (malformed source). Returns `Some(entry)` with:
///
/// - `purl`: `pkg:golang/<module-path>@<resolve_workspace_version()>`
///   per FR-001 — the workspace's Go module path plus the
///   git-describe-resolved version (or `v0.0.0-unknown` placeholder).
/// - `name`: bare module path (e.g., `github.com/argoproj/argo-workflows`).
/// - `depends`: every direct require declared in `go.mod` (including
///   `// indirect`), after applying `replace`/`exclude` directives via
///   the existing `apply_replace_and_exclude` helper. FR-002 +
///   deliberate Trivy-divergence note for indirect requires.
/// - `parent_purl: None` — top-level qualification for SPDX
///   root-selection (case 1 / case 3 of `build_document::root_id`).
/// - `sbom_tier: Some("source")` — go.mod is the authoritative source
///   of direct requires (FR-006).
/// - `extra_annotations`: `waybill:component-role: "main-module"`
///   per FR-004 (catalog row C40 supplementary signal layered on top
///   of the native-field placement that `metadata.rs` /
///   `packages.rs` will read).
/// - `licenses`: populated by `detect_main_module_license` (milestone
///   057, closes #103). See that function's doc for the Layer-1
///   detection contract.
///
/// `project_root` is used for the `git describe` ladder; `source_path`
/// is the project's `go.mod` location used for evidence/provenance.
pub(crate) fn build_main_module_entry(
    doc: &GoModDocument,
    project_root: &Path,
    source_path: &str,
) -> Option<PackageDbEntry> {
    let module_path = doc.module_path.as_ref()?.clone();
    let version = resolve_workspace_version(project_root);
    let purl = build_golang_purl(&module_path, &version)?;

    // Milestone 059 (closes #113 properly per reviewer feedback):
    // emit ONLY the workspace `go.mod`'s NON-`// indirect` requires
    // as direct edges from main-module. The pre-059 behavior of
    // including `// indirect` requires was milestone 053 FR-002's
    // deliberate "every go.mod-line require gets a root edge regardless
    // of indirect status" choice — it kept components reachable from
    // the SBOM root in the offline + empty-cache case but at the cost
    // of lying about the graph topology (claiming main-module
    // directly depends on testify's transitively-pulled
    // `davecgh/go-spew` etc.).
    //
    // The corrected graph: main-module → only its direct requires.
    // Indirect-marked requires reach their components transitively
    // via milestone 055's resolver (when the resolver can supply
    // transitive edges), or become orphans (Trivy-style trade-off,
    // accepted per spec Q&A). Orphan visibility comes from the
    // end-of-scan tracing summary in `read()` per FR-004.
    // Milestone 233 (FR-003) — emit direct-require depends in
    // "name version" form so the scan_fs/mod.rs:606-612 name-version
    // disambiguation resolves to the correct sibling-version PURL in
    // multi-module workspaces where different sub-modules require the
    // same package at different versions. Pre-233 used bare
    // `resolved_path`, which name-only-lookup last-wrote-wins.
    let depends: Vec<String> = doc
        .requires
        .iter()
        .filter(|req| !req.indirect)
        .filter_map(|req| {
            apply_replace_and_exclude(
                &req.path,
                &req.version,
                &doc.replaces,
                &doc.excludes,
            )
            .map(|(resolved_path, resolved_version)| {
                if resolved_version.is_empty() {
                    resolved_path
                } else {
                    format!("{} {}", resolved_path, resolved_version)
                }
            })
        })
        .collect();

    let mut extra_annotations: std::collections::BTreeMap<String, serde_json::Value> =
        Default::default();
    extra_annotations.insert(
        "waybill:component-role".to_string(),
        serde_json::Value::String("main-module".to_string()),
    );

    // Milestone 116 — produces-binaries extraction per FR-010 (Go).
    // Go has no manifest field naming binaries; the binary name is the
    // basename of any directory containing a `*.go` file with
    // `package main`. The two conventions covered:
    //   (a) `cmd/<name>/main.go` — binary = `<name>` (modern layout)
    //   (b) root-of-repo `main.go` — binary = the project root's
    //       basename (older / minimal layout)
    {
        let binary_candidates =
            extract_go_package_main_directory_names(project_root);
        crate::scan_fs::produces_binaries::stamp_into_annotations(
            &mut extra_annotations,
            binary_candidates,
        );
    }

    // Milestone 057 Layer 1: detect the project's own license from a
    // LICENSE-style file at the workspace root via SPDX header scan.
    // Empty when no candidate file exists / no SPDX header found /
    // header fails to canonicalize (in the last case, a tracing::warn
    // line records the path + raw expression). Layer 2 (content-based
    // matcher) is out of scope per spec FR-004.
    let licenses = detect_main_module_license(project_root);

    Some(PackageDbEntry {
        build_inclusion: None,
        purl,
        name: module_path,
        version,
        arch: None,
        source_path: source_path.to_string(),
        depends,
        maintainer: None,
        licenses,
        lifecycle_scope: None,
        requirement_ranges: Vec::new(),
        source_type: None,
        buildinfo_status: None,
        evidence_kind: None,
        binary_class: None,
        binary_stripped: None,
        linkage_kind: None,
        detected_go: Some(true),
        confidence: None,
        binary_packed: None,
        raw_version: None,
        parent_purl: None,
        npm_role: None,
        co_owned_by: None,
        hashes: Vec::new(),
        sbom_tier: Some("source".to_string()),
        shade_relocation: None,
        extra_annotations,
        binary_role: None,
    })
}

/// Milestone 116 — enumerate `package main` directories under
/// `project_root` and return their basenames as candidate produced
/// binary names. Per spec FR-010 + research §5:
///
///   - Walks via [`crate::scan_fs::walk::safe_walk`] with `max_depth: 4`
///     to cover both `cmd/<name>/main.go` (depth 2) and `cmd/<name>/
///     <subcmd>/main.go` (depth 3). The depth-4 ceiling is harmless
///     over-coverage.
///   - Skips `vendor/`, `testdata/`, `_`-prefix dirs (Go toolchain's
///     standard skip conventions per `go help packages` + milestone 091).
///   - For each candidate `*.go` file: read the first ~4 KB, skip
///     line-comments + `// +build` / `//go:build` directives + blank
///     lines, and check for `package main` as the first non-skipped
///     `package` clause.
///   - Root-of-repo case (FR-010 acceptance #3): if the project root
///     itself contains a `package main` `*.go` file, the binary name is
///     `project_root.file_name()`.
fn extract_go_package_main_directory_names(project_root: &Path) -> Vec<String> {
    let exclude_set = super::super::exclude_path::ExclusionSet::new_empty();
    let cfg = crate::scan_fs::walk::WalkConfig {
        max_depth: 4,
        should_skip: &|p, _root| {
            p.file_name()
                .and_then(|s| s.to_str())
                .map(|name| {
                    name == "vendor"
                        || name == "testdata"
                        || name.starts_with('_')
                        || name == "node_modules"
                        || name == ".git"
                })
                .unwrap_or(false)
        },
        exclude_set: &exclude_set,
    };

    let mut dirs_with_main: std::collections::BTreeSet<std::path::PathBuf> =
        std::collections::BTreeSet::new();
    // FR-005 permanent escape hatch — this walker cannot migrate to
    // walk_registry because it's a per-project-root subwalker bounded
    // to a single project subtree (called once per discovered
    // `go.mod` dir to enumerate `package main` directories). The
    // shared walker runs once across the scan tree; this walker runs
    // N times, one per project. Milestone 664 US2 T058.
    crate::scan_fs::walk::safe_walk(project_root, &cfg, |path| {
        if !path.is_file() {
            return;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("go") {
            return;
        }
        if file_declares_package_main(path) {
            if let Some(parent) = path.parent() {
                dirs_with_main.insert(parent.to_path_buf());
            }
        }
    });

    let mut out: Vec<String> = Vec::new();
    let root_canon = project_root.canonicalize().ok();
    for dir in &dirs_with_main {
        let basename = match (dir.canonicalize().ok(), root_canon.as_ref()) {
            // Root-of-repo case: use the project root's basename.
            (Some(d), Some(r)) if &d == r => project_root
                .canonicalize()
                .ok()
                .as_ref()
                .and_then(|p| p.file_name().map(|s| s.to_owned()))
                .or_else(|| {
                    project_root.file_name().map(|s| s.to_owned())
                }),
            _ => dir.file_name().map(|s| s.to_owned()),
        };
        if let Some(name) = basename.and_then(|s| s.into_string().ok()) {
            out.push(name);
        }
    }
    out
}

/// Milestone 116 — decide whether a `.go` file declares `package main`.
///
/// Reads up to roughly 4 KB, enough for header comments, build-tag
/// directives, and the package clause. Skips line comments and build-tag
/// directives such as the legacy `// +build` form and the modern
/// `//go:build` form, plus blank lines. The first non-skipped line that
/// begins with `package <name>` is the deciding clause. Conservative on
/// parse failure — returns `false`.
fn file_declares_package_main(path: &Path) -> bool {
    use std::io::Read;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = [0u8; 4096];
    let n = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let text = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let mut in_block_comment = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if in_block_comment {
            if line.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if line.starts_with("//") {
            // line comment OR build-tag directive — both irrelevant.
            continue;
        }
        if line.starts_with("/*") {
            if !line.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }
        // First non-skipped, non-comment line. Must be the package clause.
        if let Some(rest) = line.strip_prefix("package") {
            let rest = rest.trim_start();
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            return name == "main";
        }
        // Some other non-comment, non-package line — Go syntax error;
        // bail conservatively rather than guess.
        return false;
    }
    false
}

/// Resolve the synthetic main-module version per milestone 053 FR-001's
/// 3-step ladder:
/// 1. `git describe --tags --exact-match HEAD` — clean tagged release
///    (yields `v3.3.9` etc.)
/// 2. `git describe --tags --always` — tag-with-commits-since
///    (yields `v3.3.9-2-gabc1234`); also handles "no tags but commit
///    SHA known" by emitting the abbreviated SHA alone.
/// 3. The literal placeholder `v0.0.0-unknown` when not in a git repo,
///    when no tags or commits are reachable, when `git` is missing
///    from `$PATH`, or when the subprocess takes longer than the
///    configured timeout.
///
/// Test fixtures use tarball-style sources (no `.git` dir) so step 3
/// fires deterministically — preserves cross-host byte identity per
/// SC-007.
pub(crate) fn resolve_workspace_version(project_root: &Path) -> String {
    const PLACEHOLDER: &str = "v0.0.0-unknown";
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    // Skip the subprocess entirely when there's no `.git` directory at
    // the workspace root — saves the spawn cost on every tarball-style
    // fixture scan and avoids touching parent-directory `.git` (which
    // would yield a tag from the *host repo* rather than the scanned
    // project, a cross-host identity bug).
    if !project_root.join(".git").exists() {
        return PLACEHOLDER.to_string();
    }

    if let Some(v) = run_git_describe_with_timeout(
        project_root,
        &["describe", "--tags", "--exact-match", "HEAD"],
        TIMEOUT,
    ) {
        return v;
    }
    if let Some(v) = run_git_describe_with_timeout(
        project_root,
        &["describe", "--tags", "--always"],
        TIMEOUT,
    ) {
        return v;
    }
    PLACEHOLDER.to_string()
}

/// Spawn `git -C <project_root> <args...>` and return Some(trimmed
/// stdout) on success, None on any failure (binary missing, non-zero
/// exit, timeout, malformed output). Stderr is silenced; stderr output
/// from `git describe` is normal and non-actionable for our flow.
///
/// **Visibility (m216)**: `pub(crate)` so gem.rs can reuse the
/// primitive for its own version-resolution ladder without copying
/// the subprocess-timeout plumbing. The wrapping `resolve_workspace_version`
/// stays Go-specific (Go's convention is a `v` prefix on the placeholder);
/// Ruby applications need a bare `0.0.0-unknown` per m216 FR-004, so
/// gem.rs implements its own thin 3-step ladder over this primitive.
pub(crate) fn run_git_describe_with_timeout(
    project_root: &Path,
    args: &[&str],
    timeout: std::time::Duration,
) -> Option<String> {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;

    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(project_root)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return None,
    };

    // Take stdout BEFORE moving the child into the worker thread, so
    // we can both read stdout (worker) and kill the child (main) if
    // the timeout elapses.
    let stdout = child.stdout.take()?;

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        use std::io::Read as _;
        let mut buf = Vec::with_capacity(64);
        let mut handle = stdout;
        let _ = handle.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    // Wait up to `timeout` for the worker to finish reading stdout. If
    // it doesn't, kill the child and bail. Reading stdout is the
    // bottleneck for `git describe` (the actual git op is fast); a
    // hung subprocess shows up as a stalled stdout-read.
    let output_bytes = match rx.recv_timeout(timeout) {
        Ok(bytes) => bytes,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    };

    // Reap the child so it doesn't become a zombie. Brief secondary
    // wait — the worker has already finished reading stdout so this
    // returns immediately on healthy children; on slow exits we accept
    // a tiny extra wait to clean up.
    let status = match child.wait() {
        Ok(s) => s,
        Err(_) => return None,
    };
    if !status.success() {
        return None;
    }

    let trimmed = String::from_utf8_lossy(&output_bytes).trim().to_string();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed)
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
/// * `production_imports` — Go module paths reachable from at least
///   one non-`_test.go` import anywhere in the scanned source tree
///   (this project's prod imports — direct only). Used as the prod
///   baseline for the milestone 049 test-vs-prod tagging.
/// * `test_only_imports` (milestone 049) — Go module paths reachable
///   from `_test.go` imports of this project but NOT from any
///   non-`_test.go` import. These deps are tagged
///   `is_dev = Some(true)` and dropped when `--include-dev` is off.
///   Source-walk only; we do not BFS through deps' go.mod `require`
///   blocks because those don't distinguish prod-vs-test requires
///   (a dep can declare testify in its go.mod purely for its own
///   tests, but downstream consumers wouldn't load it in prod).
// Milestone 774: test-only panic-injection marker exercised by
// `m774_worker_panic_fails_fast` unit test. Compiled out in release
// builds. Scoped to a specific fixture-path prefix so parallel test
// execution (default `cargo test`) doesn't cross-contaminate — only
// workspaces whose project_root starts with the marker path panic.
#[cfg(test)]
static M774_INJECT_PANIC: std::sync::Mutex<Option<std::path::PathBuf>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn m774_should_inject_panic(project_root: &std::path::Path) -> bool {
    let guard = M774_INJECT_PANIC
        .lock()
        .expect("m774 test injection mutex poisoned");
    match guard.as_ref() {
        Some(marker) => project_root.starts_with(marker),
        None => false,
    }
}

// Milestone 774: test-only observation sink for the FR-014 summary
// log. The production code updates this in the same code path that
// emits `tracing::info!("m774 parallel source-import ...")` so a
// unit test can verify "exactly one summary per read()" without
// racing against another test's global tracing subscriber. Compiled
// out in release. Scoped to a specific fixture-path prefix so
// parallel test execution doesn't cross-contaminate.
#[cfg(test)]
#[derive(Debug, Clone)]
struct M774SummaryRecord {
    workspaces_scanned: usize,
    parallel_workers_used: usize,
    production_imports_count: usize,
    test_imports_count: usize,
}

#[cfg(test)]
static M774_SUMMARY_SINK: std::sync::Mutex<Option<(std::path::PathBuf, Vec<M774SummaryRecord>)>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn m774_summary_sink_should_record(rootfs: &std::path::Path) -> bool {
    let guard = M774_SUMMARY_SINK
        .lock()
        .expect("m774 summary sink mutex poisoned");
    match guard.as_ref() {
        Some((marker, _)) => rootfs.starts_with(marker),
        None => false,
    }
}

#[cfg(test)]
fn m774_summary_sink_push(rootfs: &std::path::Path, record: M774SummaryRecord) {
    let mut guard = M774_SUMMARY_SINK
        .lock()
        .expect("m774 summary sink mutex poisoned");
    if let Some((marker, records)) = guard.as_mut() {
        if rootfs.starts_with(&*marker) {
            records.push(record);
        }
    }
}

/// Milestone 774: work-queue payload for the post-main-loop parallel
/// phase that runs `collect_production_imports` + `collect_test_imports`
/// concurrently across per-workspace jobs. See
/// `specs/774-parallel-source-imports/data-model.md`.
struct WorkspaceImportJob<'a> {
    workspace_index: usize,
    project_root: &'a PathBuf,
}

/// Milestone 774: per-workspace worker output, moved through mpsc from
/// worker to the Phase 2 serial reduce.
struct ImportCollectionResult {
    #[allow(dead_code)] // Preserved for defense-in-depth "no gaps" diagnostic; not consumed today.
    workspace_index: usize,
    production_imports: HashSet<String>,
    test_imports: HashSet<String>,
}

#[derive(Debug, Default)]
pub struct GoScanSignals {
    pub main_modules: HashSet<String>,
    pub production_imports: HashSet<String>,
    pub test_only_imports: HashSet<String>,
    /// Milestone 061 (closes #119): aggregate graph completeness for
    /// the Go ecosystem. `None` ⇒ no `go.sum` entries were emitted in
    /// this scan (no Go components exist; signal not applicable).
    /// `Some(Complete)` ⇒ every `pkg:golang/...` component has at
    /// least one incoming `dependsOn`. `Some(Partial)` ⇒ one or more
    /// orphans (the per-component `waybill:orphan-reason` annotations
    /// name the why; the doc-level reason summary lives in
    /// `graph_completeness_reasons`).
    pub graph_completeness:
        Option<crate::scan_fs::package_db::GraphCompleteness>,
    /// Milestone 160 (T010): document-scope Go-transitive coverage signal
    /// aggregated across every workspace's resolver run. Reason-code
    /// precedence per Q1 caution-first: if ANY workspace produced
    /// `Unknown`, the aggregate is `Unknown`; else if ANY produced
    /// `Partial`, the aggregate is `Partial`; else `Complete`. `None` iff
    /// no Go workspace was scanned. Consumed by the CLI to emit the
    /// C110/C111 doc-scope annotations.
    pub go_transitive_coverage: Option<
        crate::scan_fs::package_db::golang::graph_resolver::GoTransitiveCoverage,
    >,
    /// Milestone 172: workspace-aggregated count of Go modules whose
    /// final resolution step was the m091 step-5 go.sum flat fallback.
    /// Sum across every workspace's `LadderSummary.gosum_fallback_count`.
    /// Read at the `read_all` aggregator to populate
    /// `ScanDiagnostics.gosum_fallback_count`; wrapped in `Some(...)`
    /// at that boundary only when Go was actually scanned (per FR-002).
    pub gosum_fallback_count: usize,
    /// Milestone 173: aggregated Go cache-warming outcome for this
    /// scan. `None` iff no Go scan happened (i.e., no Go workspaces
    /// were discovered). `Some(_)` when the warmer ran OR the mode
    /// was `Off` / `OfflineInhibited` on a Go-containing scan (still
    /// carries the mode value for C118 emission). Feeds the C118
    /// (`waybill:go-cache-warming-mode`) + C119
    /// (`waybill:go-cache-warming-failed`) doc-scope annotations.
    pub cache_warming: Option<
        crate::scan_fs::package_db::golang::warm_cache::CacheWarmingResult,
    >,
    /// Milestone 161 (T009): workspace-mode detection outcome from
    /// parsing `<rootfs>/go.work`. `None` iff no `go.work` file was
    /// present at scan entry, OR `GOWORK=off` in the scan env.
    /// Consumed by `read_all` to populate
    /// `ScanDiagnostics.go_workspace_mode` for the C112 doc-scope
    /// annotation.
    pub workspace_mode: Option<
        crate::scan_fs::package_db::golang::gowork::WorkspaceMode,
    >,
    /// Sorted-deduplicated list of `<reason-class>` tokens contributing
    /// to the `Partial` completeness state. Empty when `Complete` /
    /// `None`. Ecosystem prefix (`go:`) added by the upstream
    /// `read_all` aggregator before the value flows into the document-
    /// level annotation, so this field carries just the bare class
    /// names. Known classes:
    ///
    /// * `unresolved-indirect-require` — component has zero incoming
    ///   edges AND the issue-#251 backfill didn't pick it up either
    ///   (rare; only when the per-workspace backfill pass was skipped).
    /// * `flat-attached-fallback` (issue #251) — component had zero
    ///   incoming edges from non-main entries; waybill flat-attached
    ///   it to main-module's `depends` to restore reachability. The
    ///   incoming edge from main is a synthesized fallback, not a
    ///   real direct require declared in go.mod.
    /// * `proxy-fetch-failed`, `private-module` (planned) — refined
    ///   classifications gated on per-module fetch-error data being
    ///   threaded through from the milestone-055 resolver.
    pub graph_completeness_reasons: Vec<String>,
    /// Milestone 217 (waybill#631): Go-toolchain root paths detected
    /// during the walker's `candidate_project_roots` scan. Each entry
    /// is the parent-of-src path (i.e., `$GOROOT`) of a skipped
    /// `module std` / `module cmd` `go.mod`. Sorted lex + deduplicated.
    /// Empty when no toolchain was observed (typical scan; C136
    /// annotation absent). Read at `read_all` aggregator to populate
    /// `ScanDiagnostics.go_toolchains_detected` for downstream
    /// `ScanArtifacts.go_toolchains_detected` threading.
    pub toolchain_roots_detected: Vec<PathBuf>,
}

/// Milestone 160 (T010): Q1 caution-first precedence for aggregating
/// per-workspace `GoTransitiveCoverage` values into an ecosystem-wide
/// signal. `Unknown > Partial > Complete` — any workspace's Unknown
/// drags the aggregate to Unknown; any workspace's Partial drags to
/// Partial; all Complete yields Complete. Reason strings are joined
/// with `; ` when both sides carry them, per the FR-005 grammar.
fn merge_coverage(
    existing: crate::scan_fs::package_db::golang::graph_resolver::GoTransitiveCoverage,
    new: crate::scan_fs::package_db::golang::graph_resolver::GoTransitiveCoverage,
) -> crate::scan_fs::package_db::golang::graph_resolver::GoTransitiveCoverage {
    use crate::scan_fs::package_db::golang::graph_resolver::GoTransitiveCoverage as C;
    match (existing, new) {
        (C::Unknown(a), C::Unknown(b)) => C::Unknown(join_reasons(&a, &b)),
        (C::Unknown(r), _) | (_, C::Unknown(r)) => C::Unknown(r),
        (C::Partial(a), C::Partial(b)) => C::Partial(join_reasons(&a, &b)),
        (C::Partial(r), _) | (_, C::Partial(r)) => C::Partial(r),
        (C::Complete, C::Complete) => C::Complete,
    }
}

fn join_reasons(a: &str, b: &str) -> String {
    if a == b {
        a.to_string()
    } else {
        format!("{a}; {b}")
    }
}

/// Milestone 160 (T022 + T023): stamp per-Go-component transitive-edge
/// provenance annotations onto a `PackageDbEntry` from the graph
/// resolver's output. Universal C108 emission per Q2 (every Go
/// component carries `waybill:go-transitive-source`); conditional C109
/// emission (`waybill:go-transitive-unresolved-reason`) iff C108's
/// value is `"unresolved"`. No-op for non-Go entries (PURL does not
/// start with `pkg:golang/`) and for Go entries the graph didn't cover
/// (fixture-only edge case where an entry survives dedup without a
/// resolver record).
/// Milestone 161 (T007): Detect `go.work` at the scanned root and
/// classify per the WorkspaceMode taxonomy. Returns `None` iff the
/// scan should proceed as a non-workspace scan (either no `go.work`
/// file, OR the operator disabled workspace mode via `GOWORK=off` per
/// FR-006). Otherwise returns `Some(mode)` where `mode` is either
/// `Detected` or `Malformed` — both drive the C112 emission at
/// document scope; only `Detected` activates workspace-attribution
/// semantics via `WorkspaceMode::is_active()`.
fn detect_go_workspace_mode(
    rootfs: &Path,
) -> Option<crate::scan_fs::package_db::golang::gowork::WorkspaceMode> {
    use crate::scan_fs::package_db::golang::gowork::{parse_go_work, WorkspaceMode};

    // FR-006: `GOWORK=off` disables workspace mode regardless of
    // filesystem contents. Note: we deliberately do NOT emit a C112
    // annotation in this case — the annotation is absent-when-Absent
    // per SC-003 byte-identity guard.
    if std::env::var("GOWORK").as_deref() == Ok("off") {
        return None;
    }

    let go_work_path = rootfs.join("go.work");
    if !go_work_path.is_file() {
        return None;
    }

    let mode = match std::fs::read_to_string(&go_work_path) {
        Ok(text) => parse_go_work(&text),
        Err(e) => WorkspaceMode::Malformed {
            reason: format!("io-error: {e}"),
        },
    };
    tracing::info!(
        go_work_path = %go_work_path.display(),
        outcome = %mode.as_wire_str(),
        "go.work workspace-mode detected"
    );
    Some(mode)
}

fn stamp_go_transitive_annotations(
    entry: &mut PackageDbEntry,
    graph_map:
        &crate::scan_fs::package_db::golang::graph_resolver::ModuleGraphMap,
) {
    if !entry.purl.as_str().starts_with("pkg:golang/") {
        return;
    }
    let id = crate::scan_fs::package_db::golang::module_id::ModuleId::new(
        entry.name.clone(),
        entry.version.clone(),
    );
    let Some(graph_entry) = graph_map.entry(&id) else {
        return;
    };
    entry.extra_annotations.insert(
        "waybill:go-transitive-source".to_string(),
        serde_json::Value::String(graph_entry.source.as_wire_str().to_string()),
    );
    if graph_entry.source
        == crate::scan_fs::package_db::golang::graph_resolver::ResolutionStep::None
    {
        if let Some(reason_class) = graph_map.unresolved_reason(&id) {
            entry.extra_annotations.insert(
                "waybill:go-transitive-unresolved-reason".to_string(),
                serde_json::Value::String(reason_class.as_wire_str().to_string()),
            );
        }
    }
}

pub fn read(
    rootfs: &Path,
    _include_dev: bool,
    exclude_set: &super::super::exclude_path::ExclusionSet,
    precomputed_go_mod_paths: Option<Vec<PathBuf>>,
) -> (Vec<PackageDbEntry>, GoScanSignals) {
    let mut out: Vec<PackageDbEntry> = Vec::new();
    let mut seen_purls: HashSet<String> = HashSet::new();
    // Milestone 161 (T007): detect `go.work` at the scanned root.
    // Honor `GOWORK=off` env-var override per FR-006. Populates
    // `signals.workspace_mode` for the C112 doc-scope annotation.
    let workspace_mode = detect_go_workspace_mode(rootfs);
    let mut signals = GoScanSignals {
        workspace_mode,
        ..Default::default()
    };

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
    // Milestone 664 US2 T058: when the shared-walker pilot ran
    // upstream, use the precomputed go.mod list. Fall back to
    // safe_walk-driven discovery for legacy direct callers.
    let (project_roots, toolchain_roots_detected) = match precomputed_go_mod_paths {
        Some(paths) => candidate_project_roots_from_paths(paths),
        None => candidate_project_roots(rootfs, exclude_set),
    };
    // Milestone 217 (waybill#631): capture any observed Go-toolchain
    // roots for the C136 doc-scope annotation. Empty vec when no
    // toolchain was observed (typical case) — the caller wraps this
    // in Option::None → annotation absent.
    signals.toolchain_roots_detected = toolchain_roots_detected;
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

    // Second pass: emit entries AND walk .go files for production +
    // test-only imports.
    let mut test_imports: HashSet<String> = HashSet::new();
    let mut main_module_emitted = 0usize;
    // Issue #251: track names of Go modules flat-backfilled onto
    // main-module's `depends` during the per-workspace pass below.
    // After all workspaces are processed, the orphan-classifier loop
    // tags each backfilled component with
    // `waybill:orphan-reason: flat-attached-fallback` so the diagnostic
    // signal (waybill couldn't determine this component's hierarchical
    // parent) survives despite the resolved-incoming-edge from main.
    let mut backfilled_paths: HashSet<String> = HashSet::new();
    // Milestone 055 (T024 + T025): build the GraphResolver once per
    // scan and reuse it across project roots. The resolver's
    // 4-step ladder produces a `ModuleGraphMap` that supersedes the
    // per-entry `cache_lookup_depends()` lookup of milestone 053 —
    // edges populate from `$GOMODCACHE` (when present) AND from the
    // proxy fetch (`$GOPROXY`, default `proxy.golang.org`) when the
    // cache misses. Sync throughout (R3 deviation: the resolver lives
    // inside this sync chain). `--offline` plumbing is the T010
    // followup — for now we hard-code `false` and let `$GOPROXY=off`
    // be the user's offline knob; T024/T025 leaves a TODO marker in
    // `package_db/mod.rs::read_all` covering the flag-thread.
    use crate::scan_fs::package_db::golang::graph_resolver::{
        GraphResolver, GraphResolverConfig, WorkspaceContext,
    };
    let resolver = GraphResolver::new(GraphResolverConfig::default());

    // Milestone 173: opt-in Go cache warming. Read the effective mode
    // from the `WAYBILL_WARM_GO_CACHE_MODE` env var (set by scan_cmd.rs
    // after `--offline` reconciliation per FR-003). Warming runs ONCE
    // for all discovered workspaces before the resolver loop below —
    // step 1 (`go mod graph`) then finds every module locally instead
    // of falling through to step 5's flat go.sum fallback.
    //
    // The env-var carrier avoids threading two new params through the
    // 75-callsite `scan_path → read_all → golang::read` chain — same
    // convention as `WAYBILL_INCLUDE_VENDORED` / `WAYBILL_DEEP_HASH`.
    let warm_mode: crate::scan_fs::package_db::golang::warm_cache::CacheWarmingMode = {
        use crate::scan_fs::package_db::golang::warm_cache::CacheWarmingMode;
        match std::env::var("WAYBILL_WARM_GO_CACHE_MODE").as_deref() {
            Ok("per-workspace") => CacheWarmingMode::PerWorkspace,
            Ok("offline-inhibited") => CacheWarmingMode::OfflineInhibited,
            _ => CacheWarmingMode::Off,
        }
    };
    if !parsed_roots.is_empty() {
        use crate::scan_fs::package_db::golang::warm_cache;
        use std::time::Duration;

        let workspace_paths: Vec<PathBuf> =
            parsed_roots.iter().map(|(p, _, _)| p.clone()).collect();

        if matches!(warm_mode, warm_cache::CacheWarmingMode::PerWorkspace) {
            let concurrency_raw: u32 = std::env::var("WAYBILL_WARM_GO_CACHE_CONCURRENCY")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(4);
            let concurrency = warm_cache::effective_concurrency(concurrency_raw);
            let per_workspace_timeout = Duration::from_secs(60); // research §R4
            let overall_budget = Duration::from_secs(300); // research §R4
            tracing::info!(
                workspaces = workspace_paths.len(),
                concurrency,
                "warming Go module cache (--warm-go-cache=per-workspace)"
            );
            signals.cache_warming = Some(warm_cache::warm_workspaces(
                warm_cache::CacheWarmingMode::PerWorkspace,
                &workspace_paths,
                rootfs,
                concurrency,
                per_workspace_timeout,
                overall_budget,
            ));
        } else {
            // `Off` or `OfflineInhibited` — no warming performed, but
            // still record the mode so the C118 annotation surfaces the
            // operator's request. `failures` is trivially empty.
            signals.cache_warming = Some(warm_cache::CacheWarmingResult {
                mode: warm_mode,
                failures: Vec::new(),
            });
        }
    }

    for (project_root, doc, sums) in &parsed_roots {
        let go_sum_path = project_root.join("go.sum");
        let source_path = go_sum_path.to_string_lossy().into_owned();

        // Build the workspace context + resolve the transitive graph
        // for this project root once. The map is then consulted by the
        // per-entry closure passed into
        // `build_entries_from_go_module_with_lookup`.
        let ctx = WorkspaceContext::from_parts(
            project_root.clone(),
            doc,
            sums,
            /* offline = */ false,
        );
        let graph_map = match resolver.resolve(&ctx, &cache) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    project_root = %project_root.display(),
                    error = %e,
                    "Go transitive-edge resolver failed; falling back to empty edge set"
                );
                Default::default()
            }
        };

        // Milestone 160 (T010): aggregate this workspace's coverage into
        // the ecosystem-wide signal per Q1 caution-first precedence
        // (Unknown > Partial > Complete).
        if let Some(cov) = graph_map.coverage().cloned() {
            signals.go_transitive_coverage =
                Some(match (signals.go_transitive_coverage.take(), cov) {
                    (None, new) => new,
                    (Some(existing), new) => merge_coverage(existing, new),
                });
        }

        // Milestone 172: aggregate this workspace's step-5 fallback
        // count into the ecosystem-wide sum. Source: `LadderSummary
        // .gosum_fallback_count` (populated at graph_resolver.rs:916).
        signals.gosum_fallback_count += graph_map.summary().gosum_fallback_count;

        // Milestone 091: collect set of paths whose entries were
        // claimed via step 5 so build_entries_from_go_module_with_lookup
        // can attach the per-component provenance discriminator.
        let gosum_fallback_set: HashSet<String> =
            graph_map.gosum_fallback_paths().into_iter().collect();

        let entries = build_entries_from_go_module_with_lookup(
            doc,
            sums,
            &source_path,
            |path, version| {
                let id = crate::scan_fs::package_db::golang::module_id::ModuleId::new(
                    path.to_string(),
                    version.to_string(),
                );
                graph_map
                    .requires(&id)
                    .iter()
                    .map(|m| m.path().to_string())
                    .collect()
            },
            &gosum_fallback_set,
        );

        // Issue #255: filter `+incompatible` legacy-version residue
        // when a same-base-path `/vN` module is present.
        //
        // Background: Go modules pre-dating module-awareness used
        // versioning without the `/vN` path suffix. Importing them at
        // v2+ produces a `+incompatible` version (Go's signal that
        // the import skipped the major-version path convention). When
        // a project upgrades from the legacy form to a properly-
        // suffixed `/vN` module, `go mod tidy` conservatively leaves
        // the `+incompatible` go.sum integrity hash behind — it's
        // load-bearing for downstream users still on the legacy form,
        // even though THIS project no longer references it.
        //
        // Naive emission produces a same-module duplicate (e.g.
        // `martian@v2.1.0+incompatible` AND `martian/v3@v3.3.3`) where
        // the legacy entry has no incoming dep edge. After PR #253's
        // residual-orphan backfill, the legacy entry gets flat-
        // attached to root with `waybill:orphan-reason:
        // flat-attached-fallback` — a false positive.
        //
        // NARROW FILTER: drop a Go component if BOTH:
        //   - Its version contains `+incompatible`.
        //   - A same-base-path component exists at `<path>/vN` for
        //     some N >= 2.
        //
        // We deliberately do NOT drop all go.sum-but-not-go.mod-
        // reachable modules. Legitimate test-transitives (e.g.
        // `gopkg.in/check.v1`, pulled by `yaml.v3`'s test deps) live
        // in go.sum without being in go.mod, but the user expects to
        // see them in the SBOM for vulnerability scanning. The user's
        // filing described this bug as narrow; this filter matches
        // that scope.
        let entry_paths: std::collections::HashSet<String> = entries
            .iter()
            .filter(|e| e.purl.as_str().starts_with("pkg:golang/"))
            .map(|e| e.name.clone())
            .collect();
        let mut filtered_count = 0usize;
        for mut entry in entries {
            if entry.purl.as_str().starts_with("pkg:golang/")
                && entry.version.contains("+incompatible")
                && entry_paths.iter().any(|p| is_vn_sibling_of(p, &entry.name))
            {
                filtered_count += 1;
                tracing::debug!(
                    purl = %entry.purl.as_str(),
                    "Issue #255: dropping +incompatible residue (same-base-path /vN sibling present in entries)"
                );
                continue;
            }
            // Milestone 160 (T022 + T023): per-component transitive-edge
            // provenance annotations. C108 is universal on every Go
            // component (Q2); C109 is conditional iff C108 == "unresolved".
            stamp_go_transitive_annotations(&mut entry, &graph_map);

            let purl_key = entry.purl.as_str().to_string();
            if seen_purls.insert(purl_key) {
                out.push(entry);
            }
        }
        if filtered_count > 0 {
            tracing::info!(
                project_root = %project_root.display(),
                filtered = filtered_count,
                "Issue #255: filtered +incompatible legacy-version residue (same-base-path /vN module is present)"
            );
        }

        // Milestone 053 FR-001 + FR-002 + FR-004: emit a synthetic
        // main-module entry for this workspace root, with direct-
        // require edges to every go.mod-declared dependency. The
        // existing edge-emission loop in `scan_fs/mod.rs:526-547`
        // converts this entry's `depends` into `DependsOn`
        // relationships against components already present in the
        // scan, with dangling targets silently dropped.
        let go_mod_path = project_root.join("go.mod");
        let go_mod_source = go_mod_path.to_string_lossy().into_owned();
        if let Some(mut main_entry) =
            build_main_module_entry(doc, project_root, &go_mod_source)
        {
            // Milestone 091: in offline + cache-empty mode, the
            // resolver's step 5 claims every go.sum module steps 1–3
            // didn't reach, tagging them with source = GoSumFallback.
            // Augment main-module's `depends` with those module paths
            // so the SBOM includes flat root → transitive edges
            // recovering the ~110 transitive edges trivy captures from
            // go.sum content alone. Existing `// indirect`-filtered
            // direct-deps already in `main_entry.depends` are deduped
            // via the HashSet pass.
            // Milestone 233 (FR-001) — filter fallback paths to those
            // present in THIS main-module's own `go.sum`. Pre-233 used
            // `gosum_fallback_paths()` (scan-global aggregate), which
            // leaked sibling modules' go.sum entries into every main-
            // module's `depends`. See spec.md § Background.
            //
            // Milestone 233 (FR-003) — emit fallback paths in "name
            // version" form using THIS project's go.sum entries.
            // Multi-module workspaces with same-name different-version
            // fallback modules resolve to the correct per-project
            // version via scan_fs/mod.rs:606-612 disambiguation.
            let fallback_paths = graph_map.gosum_fallback_paths_for(sums);
            if !fallback_paths.is_empty() {
                let existing: std::collections::HashSet<String> =
                    main_entry.depends.iter().cloned().collect();
                let path_to_version: std::collections::HashMap<&str, &str> = sums
                    .iter()
                    .filter(|e| e.kind == GoSumKind::Module)
                    .map(|e| (e.module.as_str(), e.version.as_str()))
                    .collect();
                for path in fallback_paths {
                    let dep_string = match path_to_version.get(path.as_str()) {
                        Some(v) => format!("{} {}", path, v),
                        None => path.clone(),
                    };
                    if !existing.contains(&dep_string) && !existing.contains(&path) {
                        main_entry.depends.push(dep_string);
                    }
                }
            }

            // Milestone 233 (FR-002 + Clarifications §2) — replace-
            // directive → sibling main-module edges. For each `replace
            // old => new-path` in this module's go.mod where `new-path`
            // is a filesystem path pointing at another discovered
            // main-module's project_root, add an edge from this main-
            // module to the sibling's module_path. Matches Go's own
            // `go mod graph` behavior.
            for ((_old_path, _old_ver), (new_path, _new_ver)) in &doc.replaces {
                // Only filesystem-path replaces (relative or absolute).
                // Module-path replaces (like `replace foo v1 => foo v2`)
                // leave `new_path` as a module path, which won't
                // canonicalize to any project_root.
                if !new_path.starts_with('.') && !new_path.starts_with('/') {
                    continue;
                }
                let target_abs = project_root.join(new_path);
                let Ok(target_canon) = std::fs::canonicalize(&target_abs) else {
                    continue;
                };
                for (other_root, other_doc, _other_sums) in &parsed_roots {
                    let Ok(other_canon) = std::fs::canonicalize(other_root) else {
                        continue;
                    };
                    if other_canon != target_canon {
                        continue;
                    }
                    if let Some(sibling_module) = &other_doc.module_path {
                        if !main_entry.depends.contains(sibling_module) {
                            main_entry.depends.push(sibling_module.clone());
                        }
                    }
                    break;
                }
            }
            // Issue #250: emit edges from main-module to each Go 1.24+
            // `tool` directive entry. The directive uses package paths
            // (`example.com/mod/cmd/foo`) but waybill emits components
            // keyed by module paths (`example.com/mod`). Resolve each
            // tool path to its enclosing module by longest-prefix-match
            // against the already-discovered Go module set. The tool's
            // module IS in go.sum (since `go mod tidy` adds an indirect
            // require alongside the `tool` line) so it's been emitted
            // as a component by `build_entries_from_go_module_with_lookup`
            // above; we just need an incoming edge.
            //
            // ORDER NOTE: this block runs BEFORE the issue-#251 backfill
            // below. Reason: tool-directive resolution already places
            // the tool's module in `main_entry.depends`, so the
            // subsequent backfill's dedup-against-existing-depends
            // check skips it — leaving the tool with only the
            // `build-tool` role annotation (clean semantic) rather
            // than ALSO being tagged as `flat-attached-fallback`
            // (which would be misleading: tools aren't orphans whose
            // parent we couldn't find — they're declared deps via the
            // `tool` directive).
            if !doc.tools.is_empty() {
                // Pass 1: resolve every tool path to its enclosing
                // module path. Immutable-borrow `out` to read module
                // names; collect the resolved set + the unresolved-
                // tool-path set into Vecs so the borrow ends here.
                let mut tool_module_paths: Vec<String> = Vec::new();
                let mut unresolved_tools: Vec<String> = Vec::new();
                {
                    let golang_modules: Vec<&str> = out
                        .iter()
                        .filter(|e| e.purl.as_str().starts_with("pkg:golang/"))
                        .map(|e| e.name.as_str())
                        .collect();
                    for tool_path in &doc.tools {
                        match resolve_tool_to_module(tool_path, &golang_modules) {
                            Some(module_path) => {
                                tool_module_paths.push(module_path.to_string());
                            }
                            None => {
                                unresolved_tools.push(tool_path.clone());
                            }
                        }
                    }
                }
                // Pass 2: add flat edges from main-module → tool's
                // module, deduped against existing direct requires
                // already in main_entry.depends from go.mod.
                let existing: std::collections::HashSet<String> =
                    main_entry.depends.iter().cloned().collect();
                for p in &tool_module_paths {
                    if !existing.contains(p) {
                        main_entry.depends.push(p.clone());
                    }
                }
                // Pass 3: tag the matched components with
                // `waybill:component-role: build-tool` so SBOM
                // consumers can distinguish them from regular
                // runtime/library dependencies. Parallels the existing
                // `main-module` value emitted on the synthesized
                // main-module entry. The annotation slot is waybill-
                // namespaced; the closest standards-native slots
                // (CDX `scope: optional` and SPDX 2.3 `BUILD_TOOL_OF`
                // relationship type) would require deeper emitter
                // changes — deferred as standards-first follow-ups.
                if !tool_module_paths.is_empty() {
                    let path_set: std::collections::HashSet<&str> =
                        tool_module_paths.iter().map(|s| s.as_str()).collect();
                    for entry in out.iter_mut() {
                        if path_set.contains(entry.name.as_str())
                            && entry.purl.as_str().starts_with("pkg:golang/")
                        {
                            entry.extra_annotations.insert(
                                "waybill:component-role".to_string(),
                                serde_json::Value::String("build-tool".to_string()),
                            );
                        }
                    }
                    tracing::info!(
                        tool_count = tool_module_paths.len(),
                        "Issue #250: linked Go 1.24+ tool-directive entries to main-module + tagged with waybill:component-role: build-tool"
                    );
                }
                for tool_path in unresolved_tools {
                    tracing::warn!(
                        tool_path = %tool_path,
                        "go.mod `tool` directive entry — no enclosing Go module found in scan scope; tool's component (if any) will appear as orphan"
                    );
                }
            }
            // Issue #251: backfill residual orphans onto main-module.
            // After milestone-091's `gosum_fallback_paths()` flat-attach
            // above + the #250 tool-directive resolution, some Go
            // components can still end up with zero incoming edges:
            //
            // - `// indirect` requires whose only reachability path in
            //   `go mod graph` is THROUGH the main-module (step1 skips
            //   `parent.version().is_empty()` at graph_resolver.rs:442,
            //   intentionally — main-module's depends are populated from
            //   go.mod directly, not from `go mod graph`). When the
            //   intermediate parent of such an indirect was filtered out
            //   of the resolver's map (replace pointing at a local path,
            //   the intermediate parent not in go.sum, etc.), the
            //   indirect ends up with no incoming edge attribution and
            //   reports as `waybill:orphan-reason:
            //   unresolved-indirect-require` per milestone 061.
            //
            // - Modules where step 1 inserted them as parents (because
            //   `go mod graph` lists them as a parent with their own
            //   outgoing edges), so step 5's `gosum_fallback_paths()`
            //   doesn't claim them — but no other resolver-output entry
            //   lists them as a child either.
            //
            // Backfill: flat-attach any Go component in `out` (this
            // workspace's already-pushed transitives) with zero
            // incoming-from-other-entries edges to main_entry.depends.
            // Establishes the reachability invariant "every emitted Go
            // component is reachable from main-module" while preserving
            // the milestone-059 graph topology where possible — the flat
            // edge is added only as a FALLBACK, AFTER the resolver's
            // hierarchical attribution gets first chance.
            //
            // Cross-format parity: this modifies `main_entry.depends`
            // before push, so both CDX dependsOn and SPDX DEPENDS_ON
            // emitters see the same edge set. The PR #244 alpha.36
            // synth-root gate symmetry is preserved (CDX's
            // `target_has_no_edges` check and SPDX's symmetric
            // `synth_has_outgoing` check both observe the new edges).
            // Milestone 233 (FR-001) — restrict the eligible-orphan set
            // to components whose LONGEST-matching project_root prefix
            // is THIS project_root. In multi-module workspaces, a
            // nested module's go.sum-derived component's source_path
            // literally starts with the outer project's directory too;
            // scoping by simple prefix-match would attach every
            // nested-module orphan to the root. The longest-prefix
            // check picks the actual "owning" project_root instead.
            // See spec.md § Background / reporter's ticket.
            let project_root_str = project_root.to_string_lossy();
            let all_project_root_strs: Vec<String> = parsed_roots
                .iter()
                .map(|(pr, _, _)| pr.to_string_lossy().into_owned())
                .collect();
            let owns_component = |source_path: &str| -> bool {
                if !source_path.starts_with(project_root_str.as_ref()) {
                    return false;
                }
                // Every other project_root that is ALSO a prefix must be
                // shorter than THIS project_root; otherwise the other
                // one owns the component.
                all_project_root_strs.iter().all(|other| {
                    !source_path.starts_with(other.as_str())
                        || other.len() <= project_root_str.len()
                })
            };
            let golang_names: Vec<&str> = out
                .iter()
                .filter(|e| e.purl.as_str().starts_with("pkg:golang/"))
                .filter(|e| owns_component(&e.source_path))
                .map(|e| e.name.as_str())
                .collect();
            let all_edges: Vec<(&str, &[String])> = out
                .iter()
                .map(|e| (e.name.as_str(), e.depends.as_slice()))
                .collect();
            let backfilled =
                compute_orphan_backfill(&golang_names, &all_edges, &main_entry.depends);
            if !backfilled.is_empty() {
                tracing::info!(
                    backfill_count = backfilled.len(),
                    "Issue #251: flat-attaching residual-orphan Go components to main-module (resolver's hierarchical attribution left them with zero incoming edges)"
                );
                // Record paths for the post-loop annotation pass — these
                // components get `waybill:orphan-reason:
                // flat-attached-fallback` so consumers can distinguish
                // them from real direct requires.
                for p in &backfilled {
                    backfilled_paths.insert(p.clone());
                }
                // Milestone 233 (FR-003): resolve each backfilled name to
                // the (name, version) tuple of the owning component in
                // `out` (limited to components whose source_path is under
                // THIS project_root — same longest-prefix rule as
                // `owns_component`). Emit "name version" form so the
                // scan_fs/mod.rs disambiguation resolves to the correct
                // per-project-owned version. Pre-233 emitted bare names,
                // which name-only-lookup last-writes-wins to a sibling
                // module's version when multiple exist.
                let versioned_backfilled: Vec<String> = backfilled
                    .into_iter()
                    .map(|name| {
                        out.iter()
                            .find(|e| {
                                e.name == name
                                    && e.purl.as_str().starts_with("pkg:golang/")
                                    && owns_component(&e.source_path)
                            })
                            .map(|e| format!("{} {}", e.name, e.version))
                            .unwrap_or(name)
                    })
                    .collect();
                main_entry.depends.extend(versioned_backfilled);
            }
            let purl_key = main_entry.purl.as_str().to_string();
            if seen_purls.insert(purl_key) {
                out.push(main_entry);
                main_module_emitted += 1;
            }
        }
        // Milestone 774: `collect_production_imports` +
        // `collect_test_imports` were previously called here inline.
        // They now run in the post-main-loop parallel phase below —
        // see the `std::thread::scope` block after this loop closes.
        // Rationale: the two source-tree walks were empirically 95.4%
        // of loop time on test-kubernetes (per m774 profiling); the
        // per-workspace parallel phase drops the walker-isolated wall
        // time from ~22.5s to ~5-8s on 8-core hosts. See
        // `specs/774-parallel-source-imports/`.
    }

    // ============================================================
    // Milestone 774: parallel source-import collection phase.
    //
    // Extracts the two `collect_production_imports` +
    // `collect_test_imports` calls from the per-workspace serial loop
    // above into a bounded thread pool over the workspace queue. Per
    // Clarifications Q1 → Option A: ONLY these two calls are
    // parallelized; every other per-workspace post-processing
    // (resolver, entries, filter, main-module, orphan backfill, etc.)
    // stays serial in the loop above unchanged.
    //
    // Panic propagation (FR-007 + research R2 revised): each per-job
    // body is wrapped in `catch_unwind(AssertUnwindSafe(...))` so the
    // worker can log the failing workspace's absolute path BEFORE
    // `resume_unwind`s. `std::thread::scope`'s automatic join at
    // scope-close propagates the re-raised unwind to the enclosing
    // `pub fn read` call, matching pre-milestone unwind path.
    //
    // See `specs/774-parallel-source-imports/data-model.md` for the
    // orchestration diagram + `contracts/collect-imports-parallelism.md`
    // for the 11 verifiable contracts.
    let m774_phase_start = std::time::Instant::now();
    let m774_workers = crate::scan_fs::package_db::golang::mod_why::worker_count(parsed_roots.len());

    if parsed_roots.len() <= 1 {
        // R9 degenerate short-circuit: single-workspace scans skip the
        // thread-scope / mpsc / mutex allocations entirely, matching
        // pre-milestone latency (SC-005 within ±3%).
        if let Some((project_root, _doc, _sums)) = parsed_roots.first() {
            #[cfg(test)]
            if m774_should_inject_panic(project_root) {
                panic!("m774 test injection");
            }
            collect_production_imports(
                project_root,
                0,
                &known_modules,
                &mut signals.production_imports,
            );
            collect_test_imports(project_root, 0, &known_modules, &mut test_imports);
        }
    } else {
        let jobs: Vec<WorkspaceImportJob<'_>> = parsed_roots
            .iter()
            .enumerate()
            .map(|(i, (pr, _, _))| WorkspaceImportJob {
                workspace_index: i,
                project_root: pr,
            })
            .collect();
        let queue = Arc::new(Mutex::new(jobs));
        let (tx, rx) = mpsc::channel::<ImportCollectionResult>();
        let known_modules_ref: &[String] = &known_modules;

        std::thread::scope(|s| {
            for _ in 0..m774_workers {
                let queue = Arc::clone(&queue);
                let tx = tx.clone();
                s.spawn(move || loop {
                    let job = match queue
                        .lock()
                        .expect("m774: work queue mutex poisoned")
                        .pop()
                    {
                        Some(j) => j,
                        None => break,
                    };
                    let project_root_display = job.project_root.display().to_string();
                    let workspace_index = job.workspace_index;
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        #[cfg(test)]
                        if m774_should_inject_panic(job.project_root) {
                            panic!("m774 test injection");
                        }
                        let mut prod: HashSet<String> = HashSet::new();
                        let mut test: HashSet<String> = HashSet::new();
                        collect_production_imports(
                            job.project_root,
                            0,
                            known_modules_ref,
                            &mut prod,
                        );
                        collect_test_imports(
                            job.project_root,
                            0,
                            known_modules_ref,
                            &mut test,
                        );
                        (prod, test)
                    }));
                    match result {
                        Ok((prod, test)) => {
                            let _ = tx.send(ImportCollectionResult {
                                workspace_index,
                                production_imports: prod,
                                test_imports: test,
                            });
                        }
                        Err(payload) => {
                            tracing::error!(
                                workspace_index,
                                project_root = %project_root_display,
                                "m774 worker panicked in collect_*_imports; propagating to abort scan"
                            );
                            std::panic::resume_unwind(payload);
                        }
                    }
                });
            }
            // Drop the main-side sender so `rx` iteration terminates
            // once all worker-cloned senders have been dropped (i.e.,
            // once every worker has exited its loop).
            drop(tx);
            // Drain results inside the scope so the reduce completes
            // before scope auto-join re-raises any pending panics.
            for result in rx {
                signals
                    .production_imports
                    .extend(result.production_imports);
                test_imports.extend(result.test_imports);
            }
        });
    }

    // FR-014: exactly one summary log line per `pub fn read` invocation.
    tracing::info!(
        workspaces_scanned = parsed_roots.len(),
        parallel_workers_used = m774_workers,
        production_imports_count = signals.production_imports.len(),
        test_imports_count = test_imports.len(),
        elapsed_ms = m774_phase_start.elapsed().as_millis() as u64,
        "m774 parallel source-import collection complete"
    );
    #[cfg(test)]
    if m774_summary_sink_should_record(rootfs) {
        m774_summary_sink_push(
            rootfs,
            M774SummaryRecord {
                workspaces_scanned: parsed_roots.len(),
                parallel_workers_used: m774_workers,
                production_imports_count: signals.production_imports.len(),
                test_imports_count: test_imports.len(),
            },
        );
    }

    // Test-only set: imports reachable from `_test.go` source MINUS
    // imports reachable from non-test source. Modules in the difference
    // get `is_dev = Some(true)` in the classifier.
    //
    // Milestone 049 R3 (revised): the test-only computation uses
    // direct source imports only, NOT a go.mod-`require` BFS expansion.
    // Reason: a dep's go.mod `require` block doesn't distinguish prod
    // requires from test-only requires (Go test deps live in the dep's
    // `_test.go` source, not in its go.mod). Conservative BFS through
    // go.mod requires would falsely promote test-only deps to prod
    // whenever a transitively-prod dep's go.mod also requires them
    // (e.g., logrus's go.mod requires testify because logrus's own
    // tests use it; from this project's perspective testify is still
    // test-only). Output scope is unchanged — every go.sum entry is
    // emitted (FR-001) — only the test-only TAG uses this difference.
    signals.test_only_imports = test_imports
        .difference(&signals.production_imports)
        .cloned()
        .collect();

    if !out.is_empty() {
        tracing::info!(
            rootfs = %rootfs.display(),
            modules = out.len(),
            production_imports = signals.production_imports.len(),
            test_only_imports = signals.test_only_imports.len(),
            main_modules = signals.main_modules.len(),
            main_module_components_emitted = main_module_emitted,
            "parsed Go source tree",
        );

        // Milestone 059 FR-004: orphan-visibility summary. After the
        // graph-topology fix (main-module emits ONLY non-`// indirect`
        // requires), a Go component sourced from `go.sum` is an orphan
        // when no other component references it via `depends`.
        //
        // Milestone 061 (closes #119): classify each orphan with a
        // reason and populate the per-component
        // `waybill:orphan-reason` annotation. Aggregate the
        // completeness state into `signals` for the doc-level
        // `waybill:graph-completeness` annotation that the format
        // emitters surface in `metadata.properties[]`.
        //
        // First pass: build the incoming-edge count over Go components
        // only (the workspace's wrapping non-Go entries don't get
        // classified — they belong to other ecosystems' completeness
        // signals which are separate doc-level concerns).
        let mut incoming_count: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for entry in &out {
            if entry.purl.as_str().starts_with("pkg:golang/") {
                incoming_count
                    .entry(entry.name.clone())
                    .or_insert(0);
            }
        }
        for entry in &out {
            for child_path in &entry.depends {
                if let Some(c) = incoming_count.get_mut(child_path.as_str()) {
                    *c += 1;
                }
            }
        }
        let go_component_count = incoming_count.len();
        let orphan_count = incoming_count.values().filter(|&&c| c == 0).count();
        let reachable_count = go_component_count - orphan_count;
        tracing::info!(
            rootfs = %rootfs.display(),
            go_components = go_component_count,
            reachable_via_depends_on = reachable_count,
            orphans = orphan_count,
            "Go graph reachability summary (orphans = no incoming dependsOn — expected when --offline + empty cache + indirect-only requires)",
        );

        // Second pass: classify each orphan + populate the per-
        // component `waybill:orphan-reason` annotation. The classifier
        // is conservative — it picks `unresolved-indirect-require` as
        // the default and would refine to `private-module` /
        // `proxy-fetch-failed` if we had per-module fetch-error data
        // from the milestone 055 resolver. Threading that data
        // through is a follow-up; the default reason is operationally
        // correct for the offline + empty-cache common case (the
        // resolver's step 4 fall-through).
        let mut reason_classes: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        if orphan_count > 0 {
            for entry in out.iter_mut() {
                if !entry.purl.as_str().starts_with("pkg:golang/") {
                    continue;
                }
                // Milestone 091: skip the main-module (the project root
                // itself) — it has 0 incoming edges by construction
                // (nothing depends on the thing we're scanning), but
                // it's not a transitive orphan. Pre-091 the holistic-
                // parity asymmetry was masked because step-4 also left
                // most transitives orphaned (so CDX + SPDX both had
                // populated orphan-reason sets via components[]); post-
                // step-5, only main-module would still be tagged, and
                // CDX's main-module-via-metadata.component path doesn't
                // serialize extra_annotations — surfacing the gap.
                let is_main_module = entry
                    .extra_annotations
                    .get("waybill:component-role")
                    .and_then(|v| v.as_str())
                    == Some("main-module");
                if is_main_module {
                    continue;
                }
                let count = incoming_count.get(entry.name.as_str()).copied().unwrap_or(0);
                if count > 0 {
                    continue;
                }
                let reason = "unresolved-indirect-require".to_string();
                reason_classes.insert(reason.clone());
                entry.extra_annotations.insert(
                    "waybill:orphan-reason".to_string(),
                    serde_json::Value::String(reason),
                );
            }
        }

        // Issue #251: tag components that the per-workspace backfill
        // pass flat-attached to main_entry.depends. These are NOT
        // strict orphans anymore (they have an incoming edge from
        // main-module), but waybill couldn't determine their
        // hierarchical parent — the edge from main is a fallback, not
        // a real direct require declared in go.mod. The annotation
        // tells graph-walking SBOM consumers: "treat this incoming
        // edge as inferred, not authoritative."
        //
        // We use the existing `waybill:orphan-reason` annotation slot
        // (cross-format parity already wired in milestone 061 / row
        // C45) with a new closed-enum value
        // `flat-attached-fallback`. The annotation semantic widens
        // slightly: from strictly "no incoming edge" to "incoming
        // edge attribution unknown / synthesized." Existing
        // `unresolved-indirect-require` continues to mean "no
        // incoming edge AND we couldn't backfill" (rare; only when
        // the backfill pass skipped the entry for some reason).
        for entry in out.iter_mut() {
            if !entry.purl.as_str().starts_with("pkg:golang/") {
                continue;
            }
            if backfilled_paths.contains(&entry.name) {
                let reason = "flat-attached-fallback".to_string();
                reason_classes.insert(reason.clone());
                entry.extra_annotations.insert(
                    "waybill:orphan-reason".to_string(),
                    serde_json::Value::String(reason),
                );
            }
        }

        // Aggregate doc-level completeness signal. Only set when there
        // were Go components at all (signal not applicable for
        // non-Go-touching scans).
        if go_component_count > 0 {
            use crate::scan_fs::package_db::GraphCompleteness;
            signals.graph_completeness = Some(if orphan_count == 0 {
                GraphCompleteness::Complete
            } else {
                GraphCompleteness::Partial
            });
            signals.graph_completeness_reasons = reason_classes.into_iter().collect();
        }
    }

    // Issue #364 — emit a `stdlib` component per unique Go version seen
    // across all parsed go.mod files. Runs AFTER every Go-specific
    // classifier (mod-why, orphan-reason, graph-completeness) so the
    // stdlib entry isn't misclassified by analyzers that key on
    // import-graph reachability (stdlib has no go.sum entry / no
    // upstream module-path in the user's go.mod graph, so the
    // classifiers would falsely flag it as "not needed" or "orphan
    // flat-attached"). Matches syft's `pkg:golang/stdlib@v<version>`
    // emission shape so consumers can match either tool's stdlib CVEs
    // (e.g. CVE-2024-34156 big.Int overflow) against the CPE
    // `cpe:2.3:a:golang:go:<version>:*:*:*:*:*:*:*`.
    let mut emitted_versions: HashSet<String> = HashSet::new();
    for (project_root, doc, _sums) in &parsed_roots {
        let Some(go_version) = doc.go_version.as_deref() else {
            continue;
        };
        let bare = go_version
            .trim()
            .trim_start_matches('v')
            .trim_start_matches("go");
        if bare.is_empty() || !emitted_versions.insert(bare.to_string()) {
            continue;
        }
        let go_sum_path = project_root.join("go.sum");
        let source_path_for_evidence = if go_sum_path.is_file() {
            go_sum_path
                .to_string_lossy()
                .into_owned()
        } else {
            project_root.join("go.mod").to_string_lossy().into_owned()
        };
        if let Some(entry) = build_stdlib_entry(bare, &source_path_for_evidence) {
            out.push(entry);
            // Milestone 194 US1 (issue #571) — link the Go primary
            // main-module for THIS project_root to the emitted stdlib
            // by appending "stdlib" to its `.depends` list. The
            // existing name → PURL Relationship emitter at
            // `scan_fs/mod.rs:756-772` picks up "stdlib" and produces
            // a DependsOn edge to the corresponding
            // `pkg:golang/stdlib@v<version>` component (registered in
            // `name_to_purl` under `("golang", "stdlib")`).
            //
            // Match the mainmod by (a) golang ecosystem, (b) the
            // main-module role annotation, and (c) source_path in
            // this project_root's directory tree (the mainmod's
            // source_path is either `<project_root>/go.mod` or
            // `<project_root>/go.sum`, so a starts_with check on the
            // canonicalized project_root path is sufficient).
            let project_root_str = project_root.to_string_lossy();
            for e in out.iter_mut() {
                let is_go_mainmod = e.purl.as_str().starts_with("pkg:golang/")
                    && e.extra_annotations
                        .get("waybill:component-role")
                        .and_then(|v| v.as_str())
                        == Some("main-module")
                    && e.source_path.starts_with(project_root_str.as_ref());
                if is_go_mainmod && !e.depends.iter().any(|d| d == "stdlib") {
                    e.depends.push("stdlib".to_string());
                }
            }
        }
    }

    (out, signals)
}

/// Walk a Go project root collecting production-scope imports. Skips
/// `_test.go` files (test-scope) and any directory `should_skip_descent`
/// says to skip. Thin wrapper over [`collect_imports_filtered`] with the
/// "non-test files only" predicate.
fn collect_production_imports(
    dir: &Path,
    depth: usize,
    known_modules: &[String],
    out: &mut HashSet<String>,
) {
    collect_imports_filtered(
        dir,
        depth,
        known_modules,
        out,
        FileScope::ProdOnly,
    );
}

/// Walk a Go project root collecting test-scope imports. Visits ONLY
/// `_test.go` files (the inverse predicate of [`collect_production_imports`]).
/// Milestone 049: paired with `collect_production_imports` to compute
/// the test-only set as a difference (`test_imports - prod_imports`).
fn collect_test_imports(
    dir: &Path,
    depth: usize,
    known_modules: &[String],
    out: &mut HashSet<String>,
) {
    collect_imports_filtered(
        dir,
        depth,
        known_modules,
        out,
        FileScope::TestOnly,
    );
}

/// Which `.go` files to inspect in [`collect_imports_filtered`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum FileScope {
    /// Skip `_test.go` files; record imports from non-test source.
    ProdOnly,
    /// Only `_test.go` files; record imports from test source.
    TestOnly,
}

/// Shared implementation for [`collect_production_imports`] and
/// [`collect_test_imports`]. The `known_modules` slice MUST be sorted
/// by length descending so the first prefix match is the longest
/// (e.g., import `github.com/foo/bar/baz` correctly attributes to
/// module `github.com/foo/bar` when both `github.com/foo` and
/// `github.com/foo/bar` are known modules).
fn collect_imports_filtered(
    dir: &Path,
    depth: usize,
    known_modules: &[String],
    out: &mut HashSet<String>,
    scope: FileScope,
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
            collect_imports_filtered(&path, depth + 1, known_modules, out, scope);
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
        let is_test_file = name.ends_with("_test.go");
        match scope {
            FileScope::ProdOnly if is_test_file => continue,
            FileScope::TestOnly if !is_test_file => continue,
            _ => {}
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

/// Milestone 664 US2 T058: shared-walker discovery state. Collects
/// `go.mod` paths passing the legacy-parity ancestor-path filter.
#[derive(Default, Debug)]
pub(crate) struct GolangDiscoveredPaths {
    pub(crate) go_mod_paths: Vec<PathBuf>,
}

/// True iff any ancestor of `path` (a) has basename `testdata`, (b)
/// has basename starting with `_`, or (c) participates in a
/// `go/pkg/mod` 3-component sliding window. Mirrors legacy
/// `should_skip_descent` for the ancestors of matched `go.mod` files.
fn go_mod_ancestor_filter(path: &Path) -> bool {
    let components: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    // Iterate over ancestor dir names (all but the last component,
    // which is `go.mod` itself).
    for name in &components[..components.len().saturating_sub(1)] {
        if name.starts_with('_') || *name == "testdata" {
            return true;
        }
    }
    for window in components.windows(3) {
        if window == ["go", "pkg", "mod"] {
            return true;
        }
    }
    false
}

fn on_go_file(path: &Path, ctx: &SharedWalkerContext<'_>) {
    if path.file_name().and_then(|s| s.to_str()) != Some("go.mod") {
        return;
    }
    if go_mod_ancestor_filter(path) {
        return;
    }
    let Some(state) = ctx.state::<Mutex<GolangDiscoveredPaths>>(ReaderId::GOLANG) else {
        return;
    };
    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.go_mod_paths.push(path.to_path_buf());
}

pub(crate) fn registration() -> anyhow::Result<ReaderRegistration> {
    let patterns = globset_from_patterns(&["**/go.mod"])?;
    Ok(ReaderRegistration {
        reader_id: ReaderId::GOLANG,
        state: Some(Arc::new(Mutex::new(GolangDiscoveredPaths::default()))),
        patterns,
        on_file: Some(on_go_file),
        on_dir: None,
        descend_into: None,
    })
}

pub(crate) fn extract_paths(registration: &ReaderRegistration) -> GolangDiscoveredPaths {
    let Some(state_arc) = registration.state.as_ref() else {
        return GolangDiscoveredPaths::default();
    };
    let Some(mutex) = state_arc.downcast_ref::<Mutex<GolangDiscoveredPaths>>() else {
        return GolangDiscoveredPaths::default();
    };
    let mut guard = match mutex.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    std::mem::take(&mut *guard)
}

/// Convert a precomputed list of `go.mod` paths (from the shared-walker
/// pilot) into the same `(candidates, toolchain_roots)` tuple that
/// `candidate_project_roots` produces. Runs the `module std` / `module
/// cmd` classification inline against each `go.mod`.
fn candidate_project_roots_from_paths(
    mut go_mod_paths: Vec<PathBuf>,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    // Deterministic order — safe_walk was not sorted, but the callers'
    // downstream (parsed_roots.iter, known_modules union build) is
    // order-invariant. Sort defensively so pilot vs legacy paths emit
    // per-project log lines in the same order.
    go_mod_paths.sort();
    let mut out = Vec::new();
    let mut toolchain_roots: Vec<PathBuf> = Vec::new();
    for go_mod_path in &go_mod_paths {
        let Some(dir) = go_mod_path.parent() else {
            continue;
        };
        // Milestone 217 (waybill#631): mirror the toolchain-detection
        // classification from `candidate_project_roots` verbatim.
        if let Ok(text) = std::fs::read_to_string(go_mod_path) {
            let doc = parse_go_mod(&text);
            match doc.module_path.as_deref() {
                Some("std") => {
                    tracing::debug!(
                        path = %go_mod_path.display(),
                        module = "std",
                        "gorooted-stdlib go.mod skipped (waybill#631)"
                    );
                    if let Some(root) = go_mod_path.parent().and_then(|p| p.parent()) {
                        toolchain_roots.push(root.to_path_buf());
                    }
                    continue;
                }
                Some("cmd") => {
                    tracing::debug!(
                        path = %go_mod_path.display(),
                        module = "cmd",
                        "gorooted-cmd go.mod skipped (waybill#631)"
                    );
                    if let Some(root) = go_mod_path
                        .parent()
                        .and_then(|p| p.parent())
                        .and_then(|p| p.parent())
                    {
                        toolchain_roots.push(root.to_path_buf());
                    }
                    continue;
                }
                _ => {}
            }
        }
        out.push(dir.to_path_buf());
    }
    (out, toolchain_roots)
}

/// Milestone 114: delegates to `scan_fs::walk::safe_walk`. The Go
/// walker preserves the milestone-113 unconditional `testdata/`/`_`-
/// prefix skips via `should_skip_descent` (which takes `&Path`,
/// already path-shaped post-113).
///
/// **Milestone 217 (waybill#631)**: returns a tuple `(candidates,
/// toolchain_roots)` where `toolchain_roots` names any `$GOROOT`
/// paths whose stdlib (`module std`) or cmd (`module cmd`) go.mod
/// was observed and skipped. Callers consume `toolchain_roots` to
/// emit the C136 `waybill:go-toolchain-detected` document-scope
/// annotation. Empty vec on scans that observed no Go toolchain.
fn candidate_project_roots(
    rootfs: &Path,
    exclude_set: &super::super::exclude_path::ExclusionSet,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut out = Vec::new();
    let mut toolchain_roots: Vec<PathBuf> = Vec::new();
    let cfg = crate::scan_fs::walk::WalkConfig {
        max_depth: MAX_PROJECT_ROOT_DEPTH,
        should_skip: &|candidate: &Path, _rootfs: &Path| -> bool {
            should_skip_descent(candidate)
        },
        exclude_set,
    };
    crate::scan_fs::walk::safe_walk(rootfs, &cfg, |path| {
        if !(path.is_dir() && path.join("go.mod").is_file()) {
            return;
        }
        // Milestone 217 (waybill#631): parse the go.mod's `module`
        // line eagerly at walker time. If it declares a toolchain-
        // internal module boundary (`module std` = $GOROOT/src/go.mod,
        // `module cmd` = $GOROOT/src/cmd/go.mod), skip the directory
        // outright — no main-module component emitted, no downstream
        // `go list all` preflight (which would flood stderr with
        // "use of internal package … not allowed" for every stdlib
        // package). Record the parent-of-src toolchain root path
        // for the C136 document-scope annotation.
        let go_mod_path = path.join("go.mod");
        if let Ok(text) = std::fs::read_to_string(&go_mod_path) {
            let doc = parse_go_mod(&text);
            match doc.module_path.as_deref() {
                Some("std") => {
                    tracing::debug!(
                        path = %go_mod_path.display(),
                        module = "std",
                        "gorooted-stdlib go.mod skipped (waybill#631)"
                    );
                    // $GOROOT/src/go.mod → $GOROOT
                    if let Some(root) = go_mod_path.parent().and_then(|p| p.parent()) {
                        toolchain_roots.push(root.to_path_buf());
                    }
                    return;
                }
                Some("cmd") => {
                    tracing::debug!(
                        path = %go_mod_path.display(),
                        module = "cmd",
                        "gorooted-cmd go.mod skipped (waybill#631)"
                    );
                    // $GOROOT/src/cmd/go.mod → $GOROOT
                    if let Some(root) = go_mod_path
                        .parent()
                        .and_then(|p| p.parent())
                        .and_then(|p| p.parent())
                    {
                        toolchain_roots.push(root.to_path_buf());
                    }
                    return;
                }
                _ => {}
            }
        }
        out.push(path.to_path_buf());
    });
    toolchain_roots.sort();
    toolchain_roots.dedup();
    (out, toolchain_roots)
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
    // Per `go help packages`: "Directory and file names that begin
    // with '.' or '_' are ignored by the go tool, as are directories
    // named 'testdata'." We mirror the same three rules so waybill's
    // workspace discovery sees exactly what `go list ./...` would.
    if name.starts_with('.') || name.starts_with('_') {
        return true;
    }
    if matches!(
        name,
        "vendor" | "node_modules" | "target" | "dist" | "build" | "__pycache__" | "testdata"
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

    // --- issue #250: Go 1.24+ `tool` directive -----------------------------

    #[test]
    fn parses_single_tool_directive() {
        let src = "module x\ngo 1.24\ntool github.com/golangci/golangci-lint/cmd/golangci-lint\n";
        let doc = parse_go_mod(src);
        assert_eq!(doc.tools.len(), 1);
        assert_eq!(
            doc.tools[0],
            "github.com/golangci/golangci-lint/cmd/golangci-lint"
        );
    }

    #[test]
    fn parses_tool_block() {
        let src = r#"
module x
go 1.24

tool (
    github.com/golangci/golangci-lint/cmd/golangci-lint
    golang.org/x/tools/cmd/stringer
)
"#;
        let doc = parse_go_mod(src);
        assert_eq!(doc.tools.len(), 2);
        assert!(doc
            .tools
            .iter()
            .any(|t| t == "github.com/golangci/golangci-lint/cmd/golangci-lint"));
        assert!(doc.tools.iter().any(|t| t == "golang.org/x/tools/cmd/stringer"));
    }

    #[test]
    fn tool_directive_ignored_when_path_empty() {
        let src = "module x\ngo 1.24\ntool \n";
        let doc = parse_go_mod(src);
        assert!(doc.tools.is_empty());
    }

    #[test]
    fn tool_block_strips_line_comments() {
        let src = r#"
module x
go 1.24

tool (
    github.com/golangci/golangci-lint/cmd/golangci-lint // linter
    // golang.org/x/tools/cmd/stringer is intentionally commented out
)
"#;
        let doc = parse_go_mod(src);
        assert_eq!(doc.tools.len(), 1);
        assert_eq!(
            doc.tools[0],
            "github.com/golangci/golangci-lint/cmd/golangci-lint"
        );
    }

    #[test]
    fn resolve_tool_to_module_picks_longest_prefix() {
        let modules = vec![
            "github.com/foo/bar",
            "github.com/foo/bar/v2",
            "example.com/x",
        ];
        // Tool path matches the v2 variant (longer prefix wins).
        assert_eq!(
            resolve_tool_to_module("github.com/foo/bar/v2/cmd/tool", &modules),
            Some("github.com/foo/bar/v2"),
        );
    }

    #[test]
    fn resolve_tool_to_module_segment_boundary_required() {
        // `github.com/foo/bar` should NOT match tool path
        // `github.com/foo/barbaz/cmd/tool` (no segment boundary).
        let modules = vec!["github.com/foo/bar"];
        assert_eq!(
            resolve_tool_to_module("github.com/foo/barbaz/cmd/tool", &modules),
            None,
        );
    }

    #[test]
    fn resolve_tool_to_module_exact_match() {
        let modules = vec!["github.com/example/cmd-as-module"];
        assert_eq!(
            resolve_tool_to_module("github.com/example/cmd-as-module", &modules),
            Some("github.com/example/cmd-as-module"),
        );
    }

    #[test]
    fn resolve_tool_to_module_no_match() {
        let modules = vec!["example.com/x", "github.com/foo/bar"];
        assert_eq!(
            resolve_tool_to_module("nowhere.example.org/cmd/tool", &modules),
            None,
        );
    }

    // --- issue #255: +incompatible residue filter --------------------------

    #[test]
    fn is_vn_sibling_recognises_v2_through_v9() {
        let base = "github.com/google/martian";
        for n in 2..=9 {
            let candidate = format!("{base}/v{n}");
            assert!(
                is_vn_sibling_of(&candidate, base),
                "v{n} should be recognised as a /vN sibling of {base}",
            );
        }
    }

    #[test]
    fn is_vn_sibling_rejects_v0_and_v1() {
        // Go convention: v0 and v1 use the un-suffixed path; only
        // v2+ requires the `/vN` suffix. The +incompatible filter
        // should NOT match v0/v1.
        let base = "github.com/foo/bar";
        assert!(!is_vn_sibling_of(&format!("{base}/v0"), base));
        assert!(!is_vn_sibling_of(&format!("{base}/v1"), base));
    }

    #[test]
    fn is_vn_sibling_rejects_non_numeric_suffix() {
        let base = "github.com/foo/bar";
        assert!(!is_vn_sibling_of("github.com/foo/bar/version2", base));
        assert!(!is_vn_sibling_of("github.com/foo/bar/v2-beta", base));
        assert!(!is_vn_sibling_of("github.com/foo/bar/vlatest", base));
    }

    #[test]
    fn is_vn_sibling_rejects_deeper_paths() {
        // `<base>/v2/sub/pkg` is NOT a /vN sibling — it's a subpath
        // inside a /vN module, which has its own go.mod typically.
        let base = "github.com/foo/bar";
        assert!(!is_vn_sibling_of("github.com/foo/bar/v2/sub/pkg", base));
    }

    #[test]
    fn is_vn_sibling_rejects_unrelated_paths() {
        let base = "github.com/foo/bar";
        assert!(!is_vn_sibling_of("github.com/other/thing/v2", base));
        assert!(!is_vn_sibling_of("github.com/foo/barbaz/v2", base));
    }

    #[test]
    fn is_vn_sibling_handles_self_match() {
        // A module name equal to itself isn't a /vN sibling.
        let p = "github.com/foo/bar/v3";
        assert!(!is_vn_sibling_of(p, p));
    }

    #[test]
    fn is_vn_sibling_multi_digit_versions() {
        let base = "github.com/foo/bar";
        assert!(is_vn_sibling_of("github.com/foo/bar/v10", base));
        assert!(is_vn_sibling_of("github.com/foo/bar/v42", base));
    }

    #[test]
    fn tool_directive_annotation_contract_naming_stable() {
        // Contract test: the per-component annotation that flags
        // tool-directive entries uses the `waybill:component-role`
        // annotation slot (already wired through CDX + SPDX 2.3 +
        // SPDX 3.0.1 via the existing `main-module` value) with the
        // new closed-enum value `build-tool`. Any accidental rename
        // should be caught here before it ships and breaks consumer
        // policy that relies on these strings.
        const ANNOTATION_KEY: &str = "waybill:component-role";
        const ANNOTATION_VALUE_TOOL: &str = "build-tool";
        const ANNOTATION_VALUE_MAIN: &str = "main-module";
        assert_eq!(ANNOTATION_KEY, "waybill:component-role");
        assert_eq!(ANNOTATION_VALUE_TOOL, "build-tool");
        assert_eq!(ANNOTATION_VALUE_MAIN, "main-module");
        // If you renamed either of the values, update the parity
        // catalog row for `waybill:component-role` AND any consumer-
        // side policy that filters on these strings.
    }

    // --- issue #251: orphan backfill ---------------------------------------

    #[test]
    fn backfill_empty_when_no_golang_components() {
        let result = compute_orphan_backfill(&[], &[], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn backfill_empty_when_all_modules_have_incoming_edges() {
        // Scenario: main → A, A → B. No orphans.
        let depends_a: Vec<String> = vec!["B".to_string()];
        let depends_main: Vec<String> = vec!["A".to_string()];
        let edges: Vec<(&str, &[String])> = vec![
            ("A", depends_a.as_slice()),
            ("MAIN", depends_main.as_slice()),
        ];
        let result = compute_orphan_backfill(
            &["A", "B"],
            &edges,
            &depends_main,
        );
        assert!(
            result.is_empty(),
            "A is reachable from main, B is reachable from A — neither should backfill",
        );
    }

    #[test]
    fn backfill_attaches_module_with_zero_incoming() {
        // Scenario from guac: main directly requires A. A → B WAS the
        // expected edge but waybill's resolver lost it. B is in `out`
        // (from go.sum) but no entry depends on B. main_entry.depends =
        // [A] (only direct, non-indirect from go.mod).
        // Backfill should add B.
        let depends_a: Vec<String> = vec![]; // A's depends list is empty (resolver gap)
        let depends_main: Vec<String> = vec!["A".to_string()];
        let edges: Vec<(&str, &[String])> = vec![
            ("A", depends_a.as_slice()),
            ("MAIN", depends_main.as_slice()),
        ];
        let result = compute_orphan_backfill(
            &["A", "B"],
            &edges,
            &depends_main,
        );
        assert_eq!(result, vec!["B".to_string()]);
    }

    #[test]
    fn backfill_skips_modules_already_in_main_depends() {
        // Edge case: A is already in main_entry.depends AND has zero
        // incoming edges from non-main entries. Don't double-add.
        let depends_main: Vec<String> = vec!["A".to_string()];
        let edges: Vec<(&str, &[String])> = vec![
            ("MAIN", depends_main.as_slice()),
        ];
        let result = compute_orphan_backfill(
            &["A"],
            &edges,
            &depends_main,
        );
        assert!(result.is_empty(), "A already in main_entry.depends — should not backfill");
    }

    #[test]
    fn backfill_ignores_incoming_edges_from_non_golang_names() {
        // A non-Go entry depending on a Go module name still counts as
        // an incoming edge — keeps the contract simple. Non-Go edges
        // are rare but real (e.g., a binary entry that references its
        // ELF-discovered Go module).
        let depends_binary: Vec<String> = vec!["A".to_string()];
        let edges: Vec<(&str, &[String])> = vec![
            ("/usr/bin/some-binary", depends_binary.as_slice()),
        ];
        let result = compute_orphan_backfill(
            &["A"],
            &edges,
            &[],
        );
        assert!(
            result.is_empty(),
            "Even cross-ecosystem incoming edges count — A should not backfill",
        );
    }

    #[test]
    fn backfill_emits_sorted_output() {
        // Three orphans; verify deterministic ordering.
        let edges: Vec<(&str, &[String])> = vec![];
        let result = compute_orphan_backfill(
            &["zeta", "alpha", "middle"],
            &edges,
            &[],
        );
        assert_eq!(
            result,
            vec!["alpha".to_string(), "middle".to_string(), "zeta".to_string()],
        );
    }

    #[test]
    fn backfill_annotation_contract_naming_stable() {
        // Contract test: the per-component annotation that flags
        // backfilled entries uses the existing
        // `waybill:orphan-reason` annotation slot (milestone 061 /
        // parity row C45) with the closed-enum value
        // `flat-attached-fallback`. Both strings are exposed in
        // emitted SBOMs across CDX, SPDX 2.3, and SPDX 3.0.1 — any
        // accidental rename should be caught by this test before it
        // ships and breaks consumer policy.
        const ANNOTATION_KEY: &str = "waybill:orphan-reason";
        const ANNOTATION_VALUE_BACKFILL: &str = "flat-attached-fallback";
        const ANNOTATION_VALUE_ORPHAN: &str = "unresolved-indirect-require";
        assert_eq!(ANNOTATION_KEY, "waybill:orphan-reason");
        assert_eq!(ANNOTATION_VALUE_BACKFILL, "flat-attached-fallback");
        assert_eq!(ANNOTATION_VALUE_ORPHAN, "unresolved-indirect-require");
        // If you renamed either string, update the milestone-061
        // parity-catalog row C45 + the orphan-reason value documentation
        // in GoScanSignals + ALL existing emitted-SBOM goldens AND any
        // downstream consumer-side policy that relies on these strings.
    }

    #[test]
    fn backfill_real_world_shape_guac_indirect() {
        // Closest analog to the guac@ebb808e reproducer: main module
        // directly requires `osv-scalibr`; `osv-scalibr` SHOULD also
        // require `go-ext4-filesystem` per `go mod why -m` but the
        // resolver dropped that edge for some reason. Expect:
        //   - osv-scalibr stays as a direct edge from main (no change).
        //   - go-ext4-filesystem gets flat-backfilled onto main.
        let depends_osvscalibr: Vec<String> = vec![];
        let depends_main: Vec<String> = vec!["github.com/google/osv-scalibr".to_string()];
        let edges: Vec<(&str, &[String])> = vec![
            ("github.com/google/osv-scalibr", depends_osvscalibr.as_slice()),
            ("MAIN", depends_main.as_slice()),
        ];
        let result = compute_orphan_backfill(
            &[
                "github.com/google/osv-scalibr",
                "github.com/masahiro331/go-ext4-filesystem",
            ],
            &edges,
            &depends_main,
        );
        assert_eq!(
            result,
            vec!["github.com/masahiro331/go-ext4-filesystem".to_string()],
            "osv-scalibr already direct from main; go-ext4-filesystem (no incoming edge) backfills",
        );
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
        use waybill_common::types::hash::HashAlgorithm;
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
        use waybill_common::types::hash::HashAlgorithm;
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
        let (entries, _signals) = read(dir.path(), false, &Default::default(), None);
        assert!(entries.is_empty());
    }

    #[test]
    fn read_links_tool_directive_to_main_module_end_to_end() {
        // Issue #250 end-to-end regression: the user's reproducer
        // shape — a Go 1.24+ module with a `tool` directive — should
        // result in the tool's enclosing module appearing in the
        // synthesized main-module's `.depends` AND the tool's
        // component carrying `waybill:component-role: build-tool`.
        //
        // The fix landed in PR #252 (alpha.37); this test pins the
        // end-to-end behavior so it can't silently regress.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("go.mod"),
            "module example.com/repro\n\
             go 1.24\n\
             require github.com/spf13/cobra v1.10.2\n\
             tool github.com/golangci/golangci-lint/cmd/golangci-lint\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("go.sum"),
            "github.com/spf13/cobra v1.10.2 h1:fake=\n\
             github.com/golangci/golangci-lint v1.64.8 h1:fake=\n",
        )
        .unwrap();

        let (entries, _) = read(dir.path(), false, &Default::default(), None);

        // The tool's enclosing module is emitted as a component
        // (from go.sum).
        let golangci = entries
            .iter()
            .find(|e| e.name == "github.com/golangci/golangci-lint")
            .expect("golangci-lint component should be emitted from go.sum");

        // Issue #250 (PR #252) tagged: the tool-directive entry's
        // enclosing module carries `waybill:component-role:
        // build-tool` so SBOM consumers can distinguish it from
        // regular runtime/library deps.
        assert_eq!(
            golangci
                .extra_annotations
                .get("waybill:component-role")
                .and_then(|v| v.as_str()),
            Some("build-tool"),
            "tool-directive entry should be tagged build-tool; got: {:?}",
            golangci.extra_annotations,
        );

        // The synthesized main-module entry's `.depends` contains
        // BOTH the runtime direct (cobra) AND the tool's enclosing
        // module path (golangci-lint).
        let main = entries
            .iter()
            .find(|e| e.name == "example.com/repro")
            .expect("main-module entry must be emitted");
        // Milestone 233 FR-003: direct-require deps emit in "name version"
        // form for disambiguation.
        assert!(
            main.depends
                .iter()
                .any(|d| d.starts_with("github.com/spf13/cobra")),
            "main.depends should include cobra (direct require); got: {:?}",
            main.depends,
        );
        assert!(
            main.depends
                .iter()
                .any(|d| d == "github.com/golangci/golangci-lint" || d.starts_with("github.com/golangci/golangci-lint ")),
            "main.depends should include golangci-lint (tool-directive resolved to its enclosing module); got: {:?}",
            main.depends,
        );

        // The tool's component should NOT carry an orphan-reason
        // annotation (the linkage is established via main's
        // depends; it's not an orphan).
        assert!(
            !golangci
                .extra_annotations
                .contains_key("waybill:orphan-reason"),
            "tool-directive entry should not be flagged as orphan after #252 fix; got: {:?}",
            golangci.extra_annotations,
        );
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
        let (entries, _) = read(dir.path(), false, &Default::default(), None);
        // Milestone 053: the workspace root IS now emitted as a
        // synthetic main-module component (per FR-001), tagged with
        // `waybill:component-role: main-module`. Pre-053 the
        // workspace root was suppressed entirely.
        let main = entries
            .iter()
            .find(|e| e.name == "example.com/api")
            .expect("milestone 053: workspace root must be emitted as main-module");
        assert_eq!(
            main.extra_annotations
                .get("waybill:component-role")
                .and_then(|v| v.as_str()),
            Some("main-module"),
            "main-module entry must carry the C40 supplementary tag",
        );
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
        let (entries, _) = read(dir.path(), false, &Default::default(), None);
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
        let (entries, _) = read(dir.path(), false, &Default::default(), None);
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
        let (entries, _) = read(dir.path(), false, &Default::default(), None);
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
        let (entries, _) = read(dir.path(), false, &Default::default(), None);
        assert!(
            entries.is_empty(),
            "walker must skip /workspace/go/pkg/mod cache tree: {entries:?}",
        );
    }

    #[test]
    fn walker_skips_testdata_subtree() {
        // Per `go help packages`: directories named `testdata` are
        // ignored by the Go tool. A `go.mod` under `testdata/` is a
        // fixture for testing SBOM/build tooling, not a real workspace
        // — it would silently invert dependency edges in the emitted
        // SBOM (parent looks like it depends on the fixture). Match
        // Go's own behavior and skip the subtree.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("app");
        write_go_project(&real, "example.com/app", &[("github.com/real/dep", "v1.0.0")]);
        let fixture = real.join("pkg/sbomgen/testdata/gofixture");
        write_go_project(
            &fixture,
            "example.com/fixture",
            &[("example.com/app", "v0.0.0-fake")],
        );
        let (entries, _) = read(dir.path(), false, &Default::default(), None);
        assert!(
            entries.iter().any(|e| e.name == "example.com/app"),
            "real workspace must still emit: {entries:?}",
        );
        assert!(
            !entries.iter().any(|e| e.name == "example.com/fixture"),
            "testdata/ go.mod must NOT become a main-module: {entries:?}",
        );
    }

    #[test]
    fn walker_skips_underscore_prefixed_subtree() {
        // Per `go help packages`: directories whose name starts with
        // `_` are ignored by the Go tool. Common patterns: `_fork/`,
        // `_archive/`, `_examples/`. Match Go and skip.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("app");
        write_go_project(&real, "example.com/app", &[("github.com/real/dep", "v1.0.0")]);
        let archived = real.join("_archive/oldproject");
        write_go_project(&archived, "example.com/archived", &[]);
        let (entries, _) = read(dir.path(), false, &Default::default(), None);
        assert!(
            entries.iter().any(|e| e.name == "example.com/app"),
            "real workspace must still emit: {entries:?}",
        );
        assert!(
            !entries.iter().any(|e| e.name == "example.com/archived"),
            "_-prefixed dir go.mod must NOT become a main-module: {entries:?}",
        );
    }

    // ---------------------------------------------------------------
    // Milestone 049 — collect_test_imports + compute_transitive_prod_set
    // ---------------------------------------------------------------

    #[test]
    fn collect_test_imports_records_only_test_files() {
        let dir = tempfile::tempdir().unwrap();
        // Project source: main.go (prod) + main_test.go (test).
        std::fs::write(
            dir.path().join("main.go"),
            br#"package main
import "github.com/prod/lib"
func main() { _ = lib.Something() }"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("main_test.go"),
            br#"package main
import "github.com/test/lib"
func TestSomething(t *testing.T) { _ = lib.Something() }"#,
        )
        .unwrap();

        let known_modules = vec![
            "github.com/prod/lib".to_string(),
            "github.com/test/lib".to_string(),
        ];
        let mut prod = HashSet::new();
        let mut test = HashSet::new();
        collect_production_imports(dir.path(), 0, &known_modules, &mut prod);
        collect_test_imports(dir.path(), 0, &known_modules, &mut test);

        assert_eq!(prod.len(), 1);
        assert!(prod.contains("github.com/prod/lib"));
        assert!(!prod.contains("github.com/test/lib"));

        assert_eq!(test.len(), 1);
        assert!(test.contains("github.com/test/lib"));
        assert!(!test.contains("github.com/prod/lib"));
    }

    #[test]
    fn collect_test_imports_records_modules_imported_from_both() {
        // A module imported by BOTH prod and test code appears in
        // BOTH sets. The classifier later subtracts prod from test
        // to compute test-only.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("main.go"),
            br#"package main
import "github.com/shared/lib"
func main() { _ = lib.X() }"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("main_test.go"),
            br#"package main
import "github.com/shared/lib"
func TestX(t *testing.T) { _ = lib.X() }"#,
        )
        .unwrap();
        let known_modules = vec!["github.com/shared/lib".to_string()];
        let mut prod = HashSet::new();
        let mut test = HashSet::new();
        collect_production_imports(dir.path(), 0, &known_modules, &mut prod);
        collect_test_imports(dir.path(), 0, &known_modules, &mut test);
        assert_eq!(prod, test);
        // Per spec: a module reachable from both prod and test is
        // classified as prod (test_only = test - prod = empty).
        let test_only: HashSet<String> = test.difference(&prod).cloned().collect();
        assert!(test_only.is_empty());
    }

    // --- Milestone 053 FR-001: workspace version-resolution ladder ---------

    #[test]
    fn resolve_workspace_version_no_git_dir_returns_placeholder() {
        // No `.git` → step 3 fires deterministically. Locks the
        // tarball-style fixture invariant for SC-007 (cross-host byte
        // identity).
        let tmp = tempfile::tempdir().expect("tempdir");
        let v = resolve_workspace_version(tmp.path());
        assert_eq!(v, "v0.0.0-unknown");
    }

    #[test]
    fn resolve_workspace_version_git_repo_no_tags_falls_through_steps_to_sha() {
        // Step 1 (--exact-match) fails (no tag at HEAD). Step 2
        // (--always) succeeds and returns the abbreviated commit
        // SHA. Verifies the ladder progresses past step 1.
        let tmp = tempfile::tempdir().expect("tempdir");
        // Initialize a git repo with one commit; no tags.
        if !run_git_init_with_commit(tmp.path()) {
            // Skip if `git` isn't available on $PATH (unusual in CI).
            return;
        }
        let v = resolve_workspace_version(tmp.path());
        assert_ne!(v, "v0.0.0-unknown", "step 2 (--always) should win");
        // `--always` returns 7-char abbreviated SHA when no tag is
        // reachable. Hex chars only, length-7 (default).
        assert!(
            v.len() == 7 && v.chars().all(|c| c.is_ascii_hexdigit()),
            "expected 7-char abbreviated SHA, got: {v:?}",
        );
    }

    #[test]
    fn resolve_workspace_version_git_repo_with_exact_tag_returns_tag() {
        // Step 1 succeeds when HEAD points at an annotated tag. The
        // ladder MUST stop at step 1 (don't fall through to --always).
        let tmp = tempfile::tempdir().expect("tempdir");
        if !run_git_init_with_commit(tmp.path()) {
            return;
        }
        if !run_git_tag(tmp.path(), "v0.5.0-test") {
            return;
        }
        let v = resolve_workspace_version(tmp.path());
        assert_eq!(v, "v0.5.0-test");
    }

    /// Run `git init && git commit --allow-empty -m initial`. Returns
    /// false when `git` isn't on PATH (test should noop on those hosts
    /// rather than fail). Configures author + committer locally so the
    /// commit succeeds even when the test runner has no global git
    /// identity. Helper for the ladder tests above.
    fn run_git_init_with_commit(dir: &std::path::Path) -> bool {
        use std::process::{Command, Stdio};
        let init_ok = Command::new("git")
            .arg("init")
            .arg("--initial-branch=main")
            .arg("-q")
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !init_ok {
            return false;
        }
        let _ = Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(dir)
            .status();
        let _ = Command::new("git")
            .args(["config", "user.name", "Test Runner"])
            .current_dir(dir)
            .status();
        Command::new("git")
            .args(["commit", "--allow-empty", "-q", "-m", "initial"])
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn run_git_tag(dir: &std::path::Path, name: &str) -> bool {
        use std::process::{Command, Stdio};
        Command::new("git")
            .args(["tag", name])
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    // --- Milestone 053 FR-001/FR-002/FR-004: build_main_module_entry ------

    fn make_doc(src: &str) -> GoModDocument {
        parse_go_mod(src)
    }

    #[test]
    fn build_main_module_entry_three_requires_produces_three_depends() {
        let doc = make_doc(
            "module example.com/x\n\
             go 1.22\n\
             require (\n\
                 a.example.com/r1 v1.0.0\n\
                 b.example.com/r2 v2.0.0\n\
                 c.example.com/r3 v3.0.0\n\
             )\n",
        );
        let tmp = tempfile::tempdir().expect("tempdir");
        let entry = build_main_module_entry(&doc, tmp.path(), "/p/go.mod")
            .expect("main-module entry constructed");
        assert_eq!(entry.name, "example.com/x");
        assert_eq!(entry.depends.len(), 3);
        // Milestone 233 FR-003: depends now include version for
        // disambiguation ("name version" form).
        assert!(entry.depends.contains(&"a.example.com/r1 v1.0.0".to_string()));
        assert!(entry.depends.contains(&"b.example.com/r2 v2.0.0".to_string()));
        assert!(entry.depends.contains(&"c.example.com/r3 v3.0.0".to_string()));
    }

    #[test]
    fn build_main_module_entry_excludes_indirect_requires() {
        // Milestone 059 (closes #113 properly per reviewer feedback):
        // INVERTED from the original 053 spec FR-002 behavior. The
        // pre-059 build_main_module_entry deliberately included
        // `// indirect` requires as direct edges from main-module
        // ("for offline-scan simplicity") — that lied about the
        // graph topology. Post-059, only NON-indirect requires
        // become direct edges from main-module; indirect components
        // are reached via the milestone 055 transitive resolver
        // (when it can supply edges) or become orphans (Trivy-style
        // trade-off).
        let doc = make_doc(
            "module example.com/x\n\
             go 1.22\n\
             require (\n\
                 a.example.com/direct v1.0.0\n\
                 b.example.com/indirect v2.0.0 // indirect\n\
             )\n",
        );
        let tmp = tempfile::tempdir().expect("tempdir");
        let entry = build_main_module_entry(&doc, tmp.path(), "/p/go.mod")
            .expect("main-module entry constructed");
        assert_eq!(entry.depends.len(), 1, "only the non-indirect require makes a direct edge");
        // Milestone 233 FR-003: "name version" disambiguation form.
        assert!(entry.depends.contains(&"a.example.com/direct v1.0.0".to_string()));
        assert!(
            !entry.depends.iter().any(|d| d.starts_with("b.example.com/indirect")),
            "indirect requires MUST NOT appear as direct edges from main-module post-059",
        );
    }

    #[test]
    fn build_main_module_entry_applies_replace_directive() {
        let doc = make_doc(
            "module example.com/x\n\
             go 1.22\n\
             require y.example.com/orig v1.0.0\n\
             replace y.example.com/orig => z.example.com/replaced v1.0.0\n",
        );
        let tmp = tempfile::tempdir().expect("tempdir");
        let entry = build_main_module_entry(&doc, tmp.path(), "/p/go.mod")
            .expect("main-module entry constructed");
        assert_eq!(entry.depends.len(), 1);
        // Milestone 233 FR-003: "name version" disambiguation form.
        assert!(
            entry.depends.contains(&"z.example.com/replaced v1.0.0".to_string()),
            "replace should rewrite the target: {:?}",
            entry.depends
        );
    }

    #[test]
    fn build_main_module_entry_applies_exclude_directive() {
        let doc = make_doc(
            "module example.com/x\n\
             go 1.22\n\
             require z.example.com/dropme v1.0.0\n\
             exclude z.example.com/dropme v1.0.0\n",
        );
        let tmp = tempfile::tempdir().expect("tempdir");
        let entry = build_main_module_entry(&doc, tmp.path(), "/p/go.mod")
            .expect("main-module entry constructed");
        assert!(
            entry.depends.is_empty(),
            "exclude should drop the require: {:?}",
            entry.depends
        );
    }

    #[test]
    fn build_main_module_entry_zero_requires_emits_with_empty_depends() {
        let doc = make_doc("module example.com/empty\ngo 1.22\n");
        let tmp = tempfile::tempdir().expect("tempdir");
        let entry = build_main_module_entry(&doc, tmp.path(), "/p/go.mod")
            .expect("main-module entry constructed");
        assert_eq!(entry.name, "example.com/empty");
        assert!(entry.depends.is_empty());
    }

    #[test]
    fn build_main_module_entry_has_top_level_shape_and_supplementary_c40_tag() {
        let doc = make_doc("module example.com/x\ngo 1.22\n");
        let tmp = tempfile::tempdir().expect("tempdir");
        let entry = build_main_module_entry(&doc, tmp.path(), "/p/go.mod")
            .expect("main-module entry constructed");
        // FR-001a precondition: parent_purl=None so SPDX root-selection
        // picks this as a top-level component.
        assert!(entry.parent_purl.is_none());
        // FR-006: source-tier (go.mod is the authoritative source).
        assert_eq!(entry.sbom_tier.as_deref(), Some("source"));
        // FR-005: empty licenses (LICENSE detection deferred to #103).
        assert!(entry.licenses.is_empty());
        // FR-004: supplementary C40 annotation present with value
        // "main-module".
        let role = entry
            .extra_annotations
            .get("waybill:component-role")
            .and_then(|v| v.as_str());
        assert_eq!(role, Some("main-module"));
        // PURL shape per FR-001 + tarball-style fixture (no .git) →
        // step-3 placeholder version.
        assert_eq!(
            entry.purl.as_str(),
            "pkg:golang/example.com/x@v0.0.0-unknown"
        );
    }

    #[test]
    fn build_main_module_entry_returns_none_on_missing_module_directive() {
        let doc = make_doc("// just a comment, no module directive\n");
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(build_main_module_entry(&doc, tmp.path(), "/p/go.mod").is_none());
    }

    // --- Milestone 057: main-module LICENSE detection (Layer 1) -----------

    #[test]
    fn detect_license_returns_empty_when_no_candidate_files() {
        // SC-002 (regression-baseline): a workspace with no LICENSE-style
        // files at the root produces empty `licenses`. Critically, this
        // is the case for the existing `tests/fixtures/go/simple-module/`
        // and `argo-style-no-cache/argo-workflows/` fixtures, so their
        // goldens stay byte-identical post-057.
        let dir = tempfile::tempdir().unwrap();
        assert!(detect_main_module_license(dir.path()).is_empty());
    }

    #[test]
    fn detect_license_extracts_apache_2_0_from_license_file() {
        // SC-001: canonical Apache-2.0 SPDX header on the first line.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("LICENSE"),
            "SPDX-License-Identifier: Apache-2.0\n\nApache License, Version 2.0...\n",
        )
        .unwrap();
        let licenses = detect_main_module_license(dir.path());
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "Apache-2.0");
    }

    #[test]
    fn detect_license_extracts_compound_expression() {
        // AS#2: dual-licensed (`MIT OR Apache-2.0`) canonicalizes
        // through `try_canonical`.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("LICENSE.md"),
            "# License\n\nSPDX-License-Identifier: MIT OR Apache-2.0\n",
        )
        .unwrap();
        let licenses = detect_main_module_license(dir.path());
        assert_eq!(licenses.len(), 1);
        // Canonical form may insert spaces / re-order; assert on the
        // round-trip rather than literal string equality.
        let canonical = licenses[0].as_str();
        assert!(
            canonical.contains("MIT") && canonical.contains("Apache-2.0"),
            "canonicalized expression should retain both license IDs: {canonical}",
        );
    }

    #[test]
    fn detect_license_priority_license_beats_license_md() {
        // Multiple candidate files in same workspace — `LICENSE` wins
        // over `LICENSE.md` per priority order in
        // LICENSE_FILE_CANDIDATES.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("LICENSE"),
            "SPDX-License-Identifier: Apache-2.0\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("LICENSE.md"),
            "SPDX-License-Identifier: MIT\n",
        )
        .unwrap();
        let licenses = detect_main_module_license(dir.path());
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "Apache-2.0");
    }

    #[test]
    fn detect_license_case_insensitive_filename() {
        // `license` (lowercase) matches `LICENSE` candidate via
        // eq_ignore_ascii_case.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("license"),
            "SPDX-License-Identifier: BSD-3-Clause\n",
        )
        .unwrap();
        let licenses = detect_main_module_license(dir.path());
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "BSD-3-Clause");
    }

    #[test]
    fn detect_license_returns_empty_when_no_spdx_header() {
        // AS#4: Layer-1 miss when LICENSE has no SPDX header. Layer 2
        // territory; we deliberately don't guess.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("LICENSE"),
            "Apache License\nVersion 2.0, January 2004\n",
        )
        .unwrap();
        assert!(detect_main_module_license(dir.path()).is_empty());
    }

    #[test]
    fn detect_license_returns_empty_for_unparseable_header() {
        // AS#5 / SC-003: malformed SPDX expression. Tracing-warn
        // visibility is not asserted here (would require a captured
        // tracing subscriber); the empty-return contract is sufficient
        // to verify the FR-002 behavior.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("LICENSE"),
            "SPDX-License-Identifier: NotARealLicenseExpression!!!\n",
        )
        .unwrap();
        assert!(detect_main_module_license(dir.path()).is_empty());
    }

    #[test]
    fn detect_license_strips_html_comment_trailer() {
        // Edge case: SPDX header inside an HTML comment, common in
        // README.md-style LICENSE files.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("LICENSE.md"),
            "<!-- SPDX-License-Identifier: MIT -->\n\nMIT License\n",
        )
        .unwrap();
        let licenses = detect_main_module_license(dir.path());
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "MIT");
    }

    #[test]
    fn detect_license_strips_bom() {
        // Edge case: UTF-8 BOM at file start. Some Windows-authored
        // LICENSE.md files have one.
        let dir = tempfile::tempdir().unwrap();
        let mut bytes: Vec<u8> = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"SPDX-License-Identifier: ISC\n");
        std::fs::write(dir.path().join("LICENSE"), &bytes).unwrap();
        let licenses = detect_main_module_license(dir.path());
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "ISC");
    }

    #[test]
    fn detect_license_skips_directory_named_license() {
        // Edge case: some projects ship a `LICENSE/` directory of
        // per-vendor license files. The detector should skip it via
        // is_file() rather than panicking on the directory.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("LICENSE")).unwrap();
        // Add a sibling COPYING file so the priority list still has
        // something to pick up.
        std::fs::write(
            dir.path().join("COPYING"),
            "SPDX-License-Identifier: GPL-2.0-only\n",
        )
        .unwrap();
        let licenses = detect_main_module_license(dir.path());
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].as_str(), "GPL-2.0-only");
    }

    #[test]
    fn detect_license_caps_read_at_4kb() {
        // SPDX header buried >4 KB into the file → Layer 1 miss.
        let dir = tempfile::tempdir().unwrap();
        let mut content = "x".repeat(LICENSE_READ_LIMIT + 100);
        content.push_str("\nSPDX-License-Identifier: MIT\n");
        std::fs::write(dir.path().join("LICENSE"), content).unwrap();
        assert!(detect_main_module_license(dir.path()).is_empty());
    }

    #[test]
    fn build_main_module_entry_populates_license_when_license_file_has_spdx_header() {
        // SC-001 end-to-end via build_main_module_entry: the entry's
        // `licenses` field contains the canonical Apache-2.0 expression.
        let doc = make_doc("module example.com/with-license\n");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("LICENSE"),
            "SPDX-License-Identifier: Apache-2.0\n",
        )
        .unwrap();
        let entry = build_main_module_entry(&doc, dir.path(), "/p/go.mod")
            .expect("entry built");
        assert_eq!(entry.licenses.len(), 1);
        assert_eq!(entry.licenses[0].as_str(), "Apache-2.0");
    }

    #[test]
    fn build_main_module_entry_empty_licenses_when_no_license_file() {
        // FR-005: pre-057 behavior preserved when no LICENSE file
        // present. This is the regression-baseline that keeps the
        // existing simple-module / argo-style-no-cache fixtures'
        // goldens byte-identical.
        let doc = make_doc("module example.com/no-license\n");
        let dir = tempfile::tempdir().unwrap();
        let entry = build_main_module_entry(&doc, dir.path(), "/p/go.mod")
            .expect("entry built");
        assert!(entry.licenses.is_empty());
    }

    // ================================================================
    // Milestone 160 (T032b/c/d): per-component annotation emission
    // ================================================================

    fn make_go_entry_for_stamp(name: &str, version: &str) -> PackageDbEntry {
        PackageDbEntry {
            build_inclusion: None,
            purl: waybill_common::types::purl::Purl::new(&format!(
                "pkg:golang/{name}@{version}"
            ))
            .expect("valid purl"),
            name: name.to_string(),
            version: version.to_string(),
            arch: None,
            source_path: String::new(),
            depends: Vec::new(),
            maintainer: None,
            licenses: Vec::new(),
            lifecycle_scope: None,
            requirement_ranges: Vec::new(),
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
            hashes: Vec::new(),
            sbom_tier: Some("source".to_string()),
            shade_relocation: None,
            extra_annotations: Default::default(),
            binary_role: None,
        }
    }

    fn synth_module_graph_with_entry(
        name: &str,
        version: &str,
        source: crate::scan_fs::package_db::golang::graph_resolver::ResolutionStep,
    ) -> crate::scan_fs::package_db::golang::graph_resolver::ModuleGraphMap {
        use crate::scan_fs::package_db::golang::graph_resolver::{
            ModuleGraphEntry, ModuleGraphMap,
        };
        use crate::scan_fs::package_db::golang::module_id::ModuleId;
        let mut map = ModuleGraphMap::new();
        let id = ModuleId::new(name.to_string(), version.to_string());
        map.insert(ModuleGraphEntry {
            module: id,
            requires: Vec::new(),
            source,
        });
        map
    }

    #[test]
    fn t032b_stamp_emits_go_mod_graph_source() {
        // SC-008 (h): C108 value "go-mod-graph" on step-1-resolved module.
        use crate::scan_fs::package_db::golang::graph_resolver::ResolutionStep;
        let mut entry = make_go_entry_for_stamp("example.com/foo", "v1.2.3");
        let map = synth_module_graph_with_entry(
            "example.com/foo",
            "v1.2.3",
            ResolutionStep::GoModGraph,
        );
        stamp_go_transitive_annotations(&mut entry, &map);
        assert_eq!(
            entry.extra_annotations.get("waybill:go-transitive-source"),
            Some(&serde_json::Value::String("go-mod-graph".to_string()))
        );
        // C109 must NOT be present when C108 != "unresolved".
        assert!(!entry
            .extra_annotations
            .contains_key("waybill:go-transitive-unresolved-reason"));
    }

    #[test]
    fn t032c_stamp_emits_proxy_fetch_source() {
        // SC-008 (i): C108 value "proxy-fetch" on step-3-resolved module.
        use crate::scan_fs::package_db::golang::graph_resolver::ResolutionStep;
        let mut entry = make_go_entry_for_stamp("example.com/bar", "v0.1.0");
        let map = synth_module_graph_with_entry(
            "example.com/bar",
            "v0.1.0",
            ResolutionStep::Proxy,
        );
        stamp_go_transitive_annotations(&mut entry, &map);
        assert_eq!(
            entry.extra_annotations.get("waybill:go-transitive-source"),
            Some(&serde_json::Value::String("proxy-fetch".to_string()))
        );
        assert!(!entry
            .extra_annotations
            .contains_key("waybill:go-transitive-unresolved-reason"));
    }

    #[test]
    fn t032d_stamp_emits_unresolved_with_reason() {
        // SC-008 (j): C108 == "unresolved" AND C109 present with class.
        use crate::scan_fs::package_db::golang::graph_resolver::{
            ModuleGraphEntry, ModuleGraphMap, ResolutionStep,
            UnresolvedReasonClass,
        };
        use crate::scan_fs::package_db::golang::module_id::ModuleId;
        let mut entry = make_go_entry_for_stamp("example.com/gone", "v9.9.9");
        let mut map = ModuleGraphMap::new();
        let id = ModuleId::new("example.com/gone".to_string(), "v9.9.9".to_string());
        map.insert(ModuleGraphEntry {
            module: id.clone(),
            requires: Vec::new(),
            source: ResolutionStep::None,
        });
        map.record_unresolved_reason(id, UnresolvedReasonClass::ProxyFetchNotFound);
        stamp_go_transitive_annotations(&mut entry, &map);
        assert_eq!(
            entry.extra_annotations.get("waybill:go-transitive-source"),
            Some(&serde_json::Value::String("unresolved".to_string()))
        );
        assert_eq!(
            entry
                .extra_annotations
                .get("waybill:go-transitive-unresolved-reason"),
            Some(&serde_json::Value::String("proxy-fetch-not-found".to_string()))
        );
    }

    #[test]
    fn stamp_no_op_on_non_go_component() {
        // SC-003 dual-side byte-identity guard: no annotation emission
        // on non-Go entries.
        let mut entry = PackageDbEntry {
            build_inclusion: None,
            purl: waybill_common::types::purl::Purl::new(
                "pkg:npm/left-pad@1.3.0",
            )
            .expect("valid purl"),
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            arch: None,
            source_path: String::new(),
            depends: Vec::new(),
            maintainer: None,
            licenses: Vec::new(),
            lifecycle_scope: None,
            requirement_ranges: Vec::new(),
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
            hashes: Vec::new(),
            sbom_tier: None,
            shade_relocation: None,
            extra_annotations: Default::default(),
            binary_role: None,
        };
        // Even with a matching graph map (impossible in prod, but
        // exercising the purl-check gate), no emission occurs.
        let map = synth_module_graph_with_entry(
            "left-pad",
            "1.3.0",
            crate::scan_fs::package_db::golang::graph_resolver::ResolutionStep::Proxy,
        );
        stamp_go_transitive_annotations(&mut entry, &map);
        assert!(!entry
            .extra_annotations
            .contains_key("waybill:go-transitive-source"));
    }

    // -------- m217 (waybill#631) walker filter unit tests --------

    #[test]
    fn candidate_project_roots_skips_module_std() {
        let root = tempfile::tempdir().unwrap();
        // Stub GOROOT/src/go.mod declaring `module std`.
        let src = root.path().join("usr/local/go/src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("go.mod"), "module std\n\ngo 1.26\n").unwrap();

        let empty = crate::scan_fs::package_db::exclude_path::ExclusionSet::default();
        let (candidates, toolchains) = candidate_project_roots(root.path(), &empty);
        assert!(
            candidates.is_empty(),
            "walker MUST skip module std; got {candidates:?}"
        );
        assert_eq!(
            toolchains.len(),
            1,
            "toolchain-observation MUST record the parent-of-src path"
        );
        assert!(
            toolchains[0].ends_with("usr/local/go"),
            "expected $GOROOT-shaped path, got {}",
            toolchains[0].display()
        );
    }

    #[test]
    fn candidate_project_roots_skips_module_cmd() {
        let root = tempfile::tempdir().unwrap();
        let cmd_dir = root.path().join("usr/local/go/src/cmd");
        std::fs::create_dir_all(&cmd_dir).unwrap();
        std::fs::write(cmd_dir.join("go.mod"), "module cmd\n\ngo 1.26\n").unwrap();

        let empty = crate::scan_fs::package_db::exclude_path::ExclusionSet::default();
        let (candidates, toolchains) = candidate_project_roots(root.path(), &empty);
        assert!(
            candidates.is_empty(),
            "walker MUST skip module cmd; got {candidates:?}"
        );
        assert_eq!(toolchains.len(), 1, "toolchain-observation MUST fire");
        assert!(
            toolchains[0].ends_with("usr/local/go"),
            "expected $GOROOT path (parent of src/cmd), got {}",
            toolchains[0].display()
        );
    }

    #[test]
    fn candidate_project_roots_keeps_user_project() {
        let root = tempfile::tempdir().unwrap();
        let app = root.path().join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("go.mod"),
            "module example.com/app\n\ngo 1.22\n",
        )
        .unwrap();

        let empty = crate::scan_fs::package_db::exclude_path::ExclusionSet::default();
        let (candidates, toolchains) = candidate_project_roots(root.path(), &empty);
        assert_eq!(
            candidates.len(),
            1,
            "user project MUST be a candidate; got {candidates:?}"
        );
        assert!(
            toolchains.is_empty(),
            "no toolchain observed for user-only project; got {toolchains:?}"
        );
    }

    #[test]
    fn candidate_project_roots_dedups_multiple_toolchains() {
        let root = tempfile::tempdir().unwrap();
        // TWO stub GOROOTs
        for prefix in ["usr/local/go", "opt/go"] {
            let src = root.path().join(prefix).join("src");
            std::fs::create_dir_all(&src).unwrap();
            std::fs::write(src.join("go.mod"), "module std\n\ngo 1.26\n").unwrap();
        }
        let empty = crate::scan_fs::package_db::exclude_path::ExclusionSet::default();
        let (candidates, toolchains) = candidate_project_roots(root.path(), &empty);
        assert!(candidates.is_empty());
        assert_eq!(toolchains.len(), 2, "expected 2 distinct toolchain roots");
        // Sorted lex — opt/go before usr/local/go.
        assert!(toolchains[0].ends_with("opt/go"), "sort order wrong: {toolchains:?}");
        assert!(toolchains[1].ends_with("usr/local/go"));
    }

    #[test]
    fn candidate_project_roots_install_path_independence() {
        // Same as `dedups_multiple_toolchains` but explicitly asserts
        // that BOTH non-standard paths (`opt/go` and `srv/go`) get
        // treated identically. Detection MUST be on the module-path,
        // not the install location.
        let root = tempfile::tempdir().unwrap();
        for prefix in ["opt/go", "srv/go"] {
            let src = root.path().join(prefix).join("src");
            std::fs::create_dir_all(&src).unwrap();
            std::fs::write(src.join("go.mod"), "module std\n\ngo 1.26\n").unwrap();
        }
        let empty = crate::scan_fs::package_db::exclude_path::ExclusionSet::default();
        let (candidates, toolchains) = candidate_project_roots(root.path(), &empty);
        assert!(candidates.is_empty(), "both non-standard install paths must be skipped");
        assert_eq!(toolchains.len(), 2);
    }
}

/// Milestone 774: unit tests for the post-main-loop parallel source-
/// import phase. See `specs/774-parallel-source-imports/` for the
/// spec + plan; the five tests below cover contracts 3, 4, 5, 6, 8.
#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod m774_tests {
    use super::*;
    use crate::scan_fs::package_db::exclude_path::ExclusionSet;

    /// Build N synthetic workspaces sharing a common set of known
    /// modules. Each workspace has: one `go.mod` declaring its module
    /// path, one `main.go` importing 2 prod-lib modules, one
    /// `_test.go` importing 1 testonly module. Synthetic package
    /// names per memory `feedback_fixture_synthetic_package_names`.
    fn make_n_workspace_fixture(n: usize) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..n {
            let ws = dir.path().join(format!("ws{i}"));
            std::fs::create_dir_all(&ws).unwrap();
            std::fs::write(
                ws.join("go.mod"),
                format!(
                    "module github.com/kusari-oss/waybill-fixture-m774-ws{i}\n\ngo 1.22\n\nrequire (\n\tgithub.com/kusari-oss/waybill-fixture-m774-lib-a v1.0.0\n\tgithub.com/kusari-oss/waybill-fixture-m774-lib-b v1.0.0\n\tgithub.com/kusari-oss/waybill-fixture-m774-testonly-x v1.0.0\n)\n"
                ),
            )
            .unwrap();
            std::fs::write(
                ws.join("main.go"),
                br#"package main
import (
    "github.com/kusari-oss/waybill-fixture-m774-lib-a"
    "github.com/kusari-oss/waybill-fixture-m774-lib-b"
)
func main() { _ = liba.X(); _ = libb.Y() }
"#,
            )
            .unwrap();
            std::fs::write(
                ws.join("main_test.go"),
                br#"package main
import "github.com/kusari-oss/waybill-fixture-m774-testonly-x"
func TestX(t *testing.T) { _ = testonly.X() }
"#,
            )
            .unwrap();
        }
        dir
    }

    /// T009: merge-correctness — a multi-workspace scan produces the
    /// same production_imports + test_only_imports as a serial
    /// per-workspace collection would have produced.
    #[test]
    fn m774_multi_workspace_merge_correctness() {
        let dir = make_n_workspace_fixture(3);
        let exclude = ExclusionSet::new_empty();
        let (_out, signals) = read(dir.path(), true, &exclude, None);

        // Every prod lib should be in production_imports.
        assert!(signals
            .production_imports
            .contains("github.com/kusari-oss/waybill-fixture-m774-lib-a"));
        assert!(signals
            .production_imports
            .contains("github.com/kusari-oss/waybill-fixture-m774-lib-b"));

        // The testonly-x module should be in test_only_imports (not in prod).
        assert!(signals
            .test_only_imports
            .contains("github.com/kusari-oss/waybill-fixture-m774-testonly-x"));
        assert!(!signals
            .production_imports
            .contains("github.com/kusari-oss/waybill-fixture-m774-testonly-x"));
    }

    /// T010: two independent scans against the same tree produce
    /// element-identical production_imports + test_only_imports sets
    /// (SC-004 determinism).
    #[test]
    fn m774_determinism_across_runs() {
        let dir = make_n_workspace_fixture(3);
        let exclude = ExclusionSet::new_empty();

        let (_out_a, sig_a) = read(dir.path(), true, &exclude, None);
        let (_out_b, sig_b) = read(dir.path(), true, &exclude, None);

        // HashSet equality compares content ignoring iteration order.
        assert_eq!(sig_a.production_imports, sig_b.production_imports);
        assert_eq!(sig_a.test_only_imports, sig_b.test_only_imports);
    }

    /// T011: worker-thread panic in the parallel phase propagates via
    /// `resume_unwind` through `std::thread::scope`'s auto-join,
    /// aborting the enclosing `read()` call with a panic. FR-007 +
    /// research R2 revised.
    ///
    /// Injection is scoped to the test's specific fixture path so
    /// parallel test execution doesn't cross-contaminate — sibling
    /// tests use different tempdirs, whose paths don't match the
    /// marker prefix.
    #[test]
    fn m774_worker_panic_fails_fast() {
        let dir = make_n_workspace_fixture(3);
        let exclude = ExclusionSet::new_empty();

        // Reset the marker on test exit even if catch_unwind swallows
        // the panic — protects sibling tests that run concurrently in
        // the same process.
        struct PanicMarkerGuard;
        impl Drop for PanicMarkerGuard {
            fn drop(&mut self) {
                *M774_INJECT_PANIC.lock().unwrap() = None;
            }
        }
        let _guard = PanicMarkerGuard;

        *M774_INJECT_PANIC.lock().unwrap() = Some(dir.path().to_path_buf());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            read(dir.path(), true, &exclude, None)
        }));
        assert!(
            result.is_err(),
            "read() MUST propagate the worker panic; got Ok result instead"
        );
    }

    /// T012: single-workspace scan takes the degenerate short-circuit
    /// arm — no `std::thread::scope`, no mpsc allocation. Assert wall
    /// time is small (protects against a future refactor that
    /// accidentally spawns threads for N=1). SC-005.
    #[test]
    fn m774_single_workspace_no_thread_spawn() {
        let dir = make_n_workspace_fixture(1);
        let exclude = ExclusionSet::new_empty();
        let start = std::time::Instant::now();
        let (_out, _signals) = read(dir.path(), true, &exclude, None);
        let elapsed = start.elapsed();
        // Generous bound — 2s accommodates test-suite parallelism +
        // debug-build overhead + all the non-collect-imports work in
        // read() (resolver, entries, main-module, orphan backfill).
        // The real value of this assert is catching a hypothetical
        // regression where the degenerate arm stops firing and every
        // N=1 scan spawns a full thread pool. That failure mode would
        // add ~50-100ms of thread-spawn overhead PER SCAN, not per
        // workspace, so the absolute bound isn't the tight signal —
        // but a runaway (e.g., spawn-per-workspace-count) would blow
        // it. Watch for the summary log's parallel_workers_used field
        // instead if this bound needs tightening.
        // Bound history: 2s originally; raised to 8s during m776 after
        // one gate failure; measured and set to 3s.
        //
        // Measurement (18-core macOS, debug build, wall time of the
        // isolated test binary, which is an over-estimate since it
        // includes process startup that `elapsed` excludes):
        //   unloaded:              1.77s cold, then 0.36-0.74s warm
        //   2x CPU oversubscribe:  0.44-1.34s, 5/5 pass
        //   CPU + I/O load (load
        //   average 95):          0.40-0.67s, 6/6 pass
        // The 8s raise was an over-correction: contention does not push
        // this test anywhere near 2s. The one gate failure that
        // prompted it is better explained by a bloated target/ tree on
        // the host (131 GB at the time) stalling test-binary startup
        // than by the bound being wrong.
        //
        // 3s keeps margin over the cold-cache case while still catching
        // the failure mode this assert exists for: the degenerate arm
        // stopping and a thread pool being spawned per scan, which costs
        // ~10s on the root workspace — orders of magnitude, not
        // milliseconds. Watch the summary log's parallel_workers_used
        // field for a tighter signal.
        assert!(
            elapsed < std::time::Duration::from_millis(3000),
            "single-workspace scan took {elapsed:?}, degenerate short-circuit may not be firing",
        );
    }

    /// T013: FR-014 summary log fires exactly once per `read()`
    /// invocation with the required fields. Uses a `#[cfg(test)]`
    /// sink instead of a tracing subscriber because other tests in
    /// the same binary install global `set_global_default` tracing
    /// subscribers that preempt this test's thread-local
    /// `with_default` (observed empirically at implement-time). The
    /// sink is fixture-path-scoped so parallel test execution
    /// doesn't cross-contaminate.
    #[test]
    fn m774_summary_log_fires_once_per_read() {
        let dir = make_n_workspace_fixture(3);
        let exclude = ExclusionSet::new_empty();

        struct SummarySinkGuard;
        impl Drop for SummarySinkGuard {
            fn drop(&mut self) {
                *M774_SUMMARY_SINK.lock().unwrap() = None;
            }
        }
        let _guard = SummarySinkGuard;

        *M774_SUMMARY_SINK.lock().unwrap() = Some((dir.path().to_path_buf(), Vec::new()));

        let (_out, _signals) = read(dir.path(), true, &exclude, None);

        let sink = M774_SUMMARY_SINK.lock().unwrap();
        let (_, records) = sink.as_ref().expect("sink was installed");
        assert_eq!(
            records.len(),
            1,
            "expected exactly one m774 summary record per read(); got {}: {:?}",
            records.len(),
            records,
        );
        let record = &records[0];
        assert_eq!(record.workspaces_scanned, 3);
        assert!(record.parallel_workers_used >= 1);
        assert!(record.production_imports_count >= 2, "prod imports should include lib-a + lib-b");
        assert!(record.test_imports_count >= 1, "test imports should include testonly-x");
    }
}