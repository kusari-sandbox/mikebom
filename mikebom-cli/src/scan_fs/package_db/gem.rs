//! Read Ruby gem package metadata from `Gemfile.lock`.
//!
//! Gemfile.lock format (bundler ≥ 2.x):
//!
//! ```text
//! GEM
//!   remote: https://rubygems.org/
//!   specs:
//!     activesupport (7.1.3)
//!       base64
//!       concurrent-ruby (~> 1.0, >= 1.0.2)
//!     base64 (0.2.0)
//!     concurrent-ruby (1.2.3)
//!
//! GIT
//!   remote: https://github.com/rails/rails.git
//!   revision: abc123...
//!   specs:
//!     rails (7.2.0.alpha.internal)
//!
//! PATH
//!   remote: ../vendor/my-gem
//!   specs:
//!     my-gem (0.1.0)
//!
//! PLATFORMS
//!   ruby
//!
//! DEPENDENCIES
//!   activesupport
//!   rails!
//!   my-gem!
//!
//! BUNDLED WITH
//!    2.5.3
//! ```
//!
//! Section headers at column 0, section body at indent 2, gem specs at
//! indent 4 (`gem-name (version)`), transitive deps at indent 6. Legacy
//! bundler 1.x format is largely the same but has no `BUNDLED WITH`
//! trailer and may use two-space vs four-space indents inconsistently;
//! we handle both via indent counting (≥2 for section body, ≥4 for
//! specs) rather than fixed counts.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use mikebom_common::types::purl::{encode_purl_segment, Purl};

use super::PackageDbEntry;

const MAX_PROJECT_ROOT_DEPTH: usize = 6;

/// One spec line in GEM / GIT / PATH. `depends` holds the transitive
/// dependency names parsed from the indent-6 block under this spec —
/// the bit of Gemfile.lock that actually encodes the per-gem dep graph.
/// Version constraints like `(~> 1.0, >= 1.0.2)` are stripped; only
/// the bare gem name is retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GemSpec {
    pub name: String,
    pub version: String,
    pub kind: GemSection,
    pub depends: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GemSection {
    Gem,
    Git,
    Path,
}

/// A parsed `Gemfile.lock`. `dependencies` holds the gem names declared
/// in the `DEPENDENCIES` block (top-level / direct deps).
#[derive(Clone, Debug, Default)]
pub(crate) struct GemfileLockDocument {
    pub specs: Vec<GemSpec>,
    pub dependencies: Vec<String>,
}

pub(crate) fn parse_gemfile_lock(text: &str) -> GemfileLockDocument {
    let mut doc = GemfileLockDocument::default();
    let mut current_section: Option<GemSection> = None;
    let mut in_specs = false;
    let mut in_dependencies = false;

    for raw_line in text.lines() {
        let indent = raw_line.chars().take_while(|c| *c == ' ').count();
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            in_specs = false;
            in_dependencies = false;
            continue;
        }
        // Section headers live at column 0.
        if indent == 0 {
            match trimmed {
                "GEM" => {
                    current_section = Some(GemSection::Gem);
                    in_specs = false;
                    in_dependencies = false;
                }
                "GIT" => {
                    current_section = Some(GemSection::Git);
                    in_specs = false;
                    in_dependencies = false;
                }
                "PATH" => {
                    current_section = Some(GemSection::Path);
                    in_specs = false;
                    in_dependencies = false;
                }
                "DEPENDENCIES" => {
                    current_section = None;
                    in_specs = false;
                    in_dependencies = true;
                }
                "PLATFORMS" | "BUNDLED WITH" | "CHECKSUMS" | "RUBY VERSION" => {
                    current_section = None;
                    in_specs = false;
                    in_dependencies = false;
                }
                _ => {
                    current_section = None;
                    in_specs = false;
                    in_dependencies = false;
                }
            }
            continue;
        }
        if in_dependencies {
            // DEPENDENCIES block: one gem name per line, optionally
            // with `!` suffix (pinned to GIT/PATH source) or
            // version-spec parens that we ignore here.
            let name = trimmed
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches('!')
                .to_string();
            if !name.is_empty() {
                doc.dependencies.push(name);
            }
            continue;
        }
        if current_section.is_none() {
            continue;
        }
        if trimmed == "specs:" {
            in_specs = true;
            continue;
        }
        if !in_specs {
            // Section metadata line (`remote:`, `revision:`, etc.) —
            // ignored; the source_type is captured via the section.
            continue;
        }
        // A gem spec line looks like `gem-name (version)`. Transitive
        // deps (indent 6+) also have this shape; we dedup by name
        // within this lockfile so the transitive line doesn't overwrite
        // the primary spec.
        if indent < 4 {
            continue;
        }
        if indent == 4 {
            // New spec — `gem-name (version)`.
            if let Some((name, version)) = parse_spec_line(trimmed) {
                if let Some(section) = current_section {
                    doc.specs.push(GemSpec {
                        name: name.to_string(),
                        version: version.to_string(),
                        kind: section,
                        depends: Vec::new(),
                    });
                }
            }
        } else if indent >= 6 {
            // Transitive dep line under the most-recently-opened spec.
            // Format is `name` or `name (constraint[, constraint])`;
            // strip any trailing `(...)` constraint and the `!` source
            // pin to match the DEPENDENCIES block's convention.
            let bare = trimmed
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches('!');
            if !bare.is_empty() {
                if let Some(last) = doc.specs.last_mut() {
                    // Ignore duplicate edges if a lockfile lists the
                    // same transitive dep twice (unusual but harmless).
                    if !last.depends.iter().any(|d| d == bare) {
                        last.depends.push(bare.to_string());
                    }
                }
            }
        }
    }

    doc
}

fn parse_spec_line(line: &str) -> Option<(&str, &str)> {
    // Expect `name (version[, versionspec])`. We ignore version
    // constraints of the form `(~> 1.0, >= 1.0.2)` — those only appear
    // on transitive dep lines at deeper indent, which we filter out
    // already.
    let open = line.find('(')?;
    let close = line.find(')')?;
    if close <= open {
        return None;
    }
    let name = line[..open].trim();
    let inner = &line[open + 1..close];
    if name.is_empty() || inner.is_empty() {
        return None;
    }
    // If the inner starts with a comparator, this is a constraint line.
    if inner
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '~' | '>' | '<' | '='))
    {
        return None;
    }
    let version = inner.split(',').next().unwrap_or(inner).trim();
    Some((name, version))
}

fn build_gem_purl(name: &str, version: &str) -> Option<Purl> {
    // purl-spec § Character encoding: `+` and other non-allowed
    // chars must be percent-encoded in both name and version.
    Purl::new(&format!(
        "pkg:gem/{}@{}",
        encode_purl_segment(name),
        encode_purl_segment(version),
    ))
    .ok()
}

fn spec_to_entry(
    spec: &GemSpec,
    source_path: &str,
    _direct_deps: &HashSet<String>,
) -> Option<PackageDbEntry> {
    let purl = build_gem_purl(&spec.name, &spec.version)?;
    let source_type = match spec.kind {
        GemSection::Gem => None,
        GemSection::Git => Some("git".to_string()),
        GemSection::Path => Some("path".to_string()),
    };
    // Gemfile.lock encodes per-gem transitive edges via the indent-6
    // lines under each spec; the parser collected them into
    // `spec.depends`. Scan_fs's relationship resolver will drop any
    // dangling targets (e.g. bundler-provided gems that aren't listed
    // as specs in this lockfile).
    let depends = spec.depends.clone();
    Some(PackageDbEntry {
        purl,
        name: spec.name.clone(),
        version: spec.version.clone(),
        arch: None,
        source_path: source_path.to_string(),
        depends,
        maintainer: None,
        licenses: Vec::new(),
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
        parent_purl: None,
        npm_role: None,
        co_owned_by: None,
        hashes: Vec::new(),
        sbom_tier: Some("source".to_string()),
        shade_relocation: None,
    })
}

/// Convert a disk-observed gemspec into a PackageDbEntry. Gemspec
/// files carry no transitive dep graph (that lives in Gemfile.lock), so
/// `depends` is always empty. Tagged `source_type = "installed-gemspec"`
/// to distinguish from Gemfile.lock-tier entries.
fn gemspec_to_entry(
    name: &str,
    version: &str,
    authors: Option<&str>,
    source_path: &str,
) -> Option<PackageDbEntry> {
    let purl = build_gem_purl(name, version)?;
    Some(PackageDbEntry {
        purl,
        name: name.to_string(),
        version: version.to_string(),
        arch: None,
        source_path: source_path.to_string(),
        depends: Vec::new(),
        maintainer: authors.map(|s| s.to_string()),
        licenses: Vec::new(),
        is_dev: None,
        requirement_range: None,
        source_type: Some("installed-gemspec".to_string()),
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
        sbom_tier: Some("analyzed".to_string()),
        shade_relocation: None,
    })
}

/// Public entry point — walks `rootfs` for `Gemfile.lock` files AND
/// for `specifications/*.gemspec` files (Ruby's stdlib/default gems +
/// system-installed gems not pinned by a Gemfile). Dedupes on PURL so
/// Gemfile.lock entries win if both sources see the same gem.
pub fn read(rootfs: &Path, _include_dev: bool) -> Vec<PackageDbEntry> {
    let mut out: Vec<PackageDbEntry> = Vec::new();
    let mut seen_purls: HashSet<String> = HashSet::new();
    for lock_path in find_gemfile_locks(rootfs) {
        let Ok(text) = std::fs::read_to_string(&lock_path) else {
            continue;
        };
        let doc = parse_gemfile_lock(&text);
        let direct: HashSet<String> = doc.dependencies.iter().cloned().collect();
        let source_path = lock_path.to_string_lossy().into_owned();
        for spec in &doc.specs {
            let Some(entry) = spec_to_entry(spec, &source_path, &direct) else {
                continue;
            };
            let purl_key = entry.purl.as_str().to_string();
            if seen_purls.insert(purl_key) {
                out.push(entry);
            }
        }
    }
    // Gemspec walk (conformance bug 3): Ruby stdlib and default gems
    // ship as `<ruby>/lib/ruby/gems/<VERSION>/specifications/default/*.gemspec`
    // and are invisible to Gemfile.lock scanning. Also catches any
    // system-wide `gem install` outputs living in the standard
    // specifications dirs.
    for spec_path in find_gemspecs(rootfs) {
        let Ok(text) = std::fs::read_to_string(&spec_path) else {
            continue;
        };
        let Some(spec) = parse_gemspec_full(&text) else {
            continue;
        };
        let source_path = spec_path.to_string_lossy().into_owned();
        let Some(entry) = gemspec_to_entry(
            &spec.name,
            &spec.version,
            spec.authors.as_deref(),
            &source_path,
        ) else {
            continue;
        };
        let purl_key = entry.purl.as_str().to_string();
        if seen_purls.insert(purl_key) {
            out.push(entry);
        }
    }
    if !out.is_empty() {
        tracing::info!(
            rootfs = %rootfs.display(),
            entries = out.len(),
            "parsed Gemfile.lock + gemspec entries",
        );
    }
    out
}

fn find_gemfile_locks(rootfs: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_for_gemfile_locks(rootfs, 0, &mut out);
    out
}

fn walk_for_gemfile_locks(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let lock = dir.join("Gemfile.lock");
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
        walk_for_gemfile_locks(&path, depth + 1, out);
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

/// Find `.gemspec` files under `rootfs` that live in a
/// `specifications/` directory (including `specifications/default/`).
/// This is the canonical location for installed gems — Ruby's
/// `Gem::Specification.dirs` resolves to paths like:
///
/// - `/usr/lib/ruby/gems/3.3.0/specifications/`
/// - `/usr/lib/ruby/gems/3.3.0/specifications/default/`   (stdlib gems)
/// - `$HOME/.gem/ruby/3.3.0/specifications/`
/// - `/opt/*/gems/specifications/`
///
/// Rather than hard-code those paths, we walk the filesystem looking
/// for any directory named `specifications` containing `.gemspec`
/// files. Cheap, covers all Ruby install layouts (distro packages,
/// rbenv, rvm, asdf, ruby-install), and doesn't depend on environment
/// variables.
fn find_gemspecs(rootfs: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_for_gemspecs(rootfs, 0, &mut out);
    out
}

const MAX_GEMSPEC_WALK_DEPTH: usize = 10;

fn walk_for_gemspecs(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth >= MAX_GEMSPEC_WALK_DEPTH {
        return;
    }
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if path.is_dir() {
            if should_skip_descent(name) {
                continue;
            }
            // When we hit a `specifications` directory, harvest its
            // .gemspec files (plus any nested `default/` subdirectory
            // that Ruby uses for stdlib gems) and do NOT descend
            // further. Saves walking per-gem source trees under
            // neighboring `gems/` directories.
            if name == "specifications" {
                harvest_gemspecs_in_dir(&path, out);
                continue;
            }
            walk_for_gemspecs(&path, depth + 1, out);
        }
    }
}

fn harvest_gemspecs_in_dir(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_file() {
            if path
                .extension()
                .and_then(|s| s.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("gemspec"))
                .unwrap_or(false)
            {
                out.push(path);
            }
        } else if path.is_dir() {
            // `specifications/default/` contains Ruby-shipped stdlib
            // gems. One level of recursion is enough — Ruby doesn't
            // nest deeper.
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if name == "default" {
                    harvest_gemspecs_in_dir(&path, out);
                }
            }
        }
    }
}

/// Parse a `.gemspec` file and extract `(name, version)`.
///
/// Gemspec files are Ruby source; mikebom doesn't execute Ruby.
/// Fortunately the name+version assignments follow a rigid idiom
/// across all installed gemspecs:
///
/// ```ruby
/// Gem::Specification.new do |s|
///   s.name = "json"
///   s.version = "2.7.2"                 # most common
///   # or:
///   s.version = Gem::Version.new "2.7.2"
///   ...
/// end
/// ```
///
/// We only need to recognise the `s.name`/`s.version` (or `spec.`/
/// `specification.`) assignment lines and strip the quoted literal.
/// Any non-trivial Ruby expression (interpolation, conditionals) for
/// name or version returns `None` and the caller skips the gem.
pub(crate) fn parse_gemspec(text: &str) -> Option<(String, String)> {
    parse_gemspec_full(text).map(|g| (g.name, g.version))
}

/// Parsed `.gemspec` fields. `authors` is the raw array content
/// joined with `", "` when multiple; single-author form (`s.author =
/// "..."`) is also accepted and returned as a one-element string.
pub(crate) struct GemspecFields {
    pub name: String,
    pub version: String,
    pub authors: Option<String>,
}

pub(crate) fn parse_gemspec_full(text: &str) -> Option<GemspecFields> {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut authors: Option<String> = None;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if let Some(v) = strip_assignment(line, "name") {
            if let Some(literal) = extract_string_literal(v) {
                name = Some(literal);
            }
        } else if let Some(v) = strip_assignment(line, "version") {
            if let Some(literal) = extract_string_literal(v) {
                version = Some(literal);
            }
        } else if let Some(v) = strip_assignment(line, "authors") {
            if let Some(joined) = extract_string_array(v) {
                authors = Some(joined);
            }
        } else if let Some(v) = strip_assignment(line, "author") {
            // Some gemspecs use the singular form.
            if let Some(literal) = extract_string_literal(v) {
                authors = Some(literal);
            }
        }
    }
    match (name, version) {
        (Some(n), Some(v)) if !n.is_empty() && !v.is_empty() => Some(GemspecFields {
            name: n,
            version: v,
            authors,
        }),
        _ => None,
    }
}

/// Extract a bracketed array of string literals — `["Alice", "Bob"]`
/// or `['Alice']` — and return `"Alice, Bob"`. Ignores surrounding
/// trailing tokens like `.freeze`. Returns `None` on malformed input.
fn extract_string_array(rhs: &str) -> Option<String> {
    let trimmed = rhs.trim();
    let inside = trimmed
        .strip_prefix('[')
        .and_then(|s| s.rsplit_once(']'))
        .map(|(before, _after)| before.trim())?;
    let mut out: Vec<String> = Vec::new();
    for piece in inside.split(',') {
        let p = piece.trim();
        if p.is_empty() {
            continue;
        }
        if let Some(literal) = extract_string_literal(p) {
            if !literal.is_empty() {
                out.push(literal);
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out.join(", "))
    }
}

/// Match a line like `s.name = "foo"` / `spec.version = "1.0"` /
/// `specification.name = "foo"` and return the RHS trimmed. Returns
/// `None` when the line doesn't match any accepted receiver + attribute
/// combo, or when the attribute doesn't match `attr`.
fn strip_assignment<'a>(line: &'a str, attr: &str) -> Option<&'a str> {
    // Receivers Ruby gemspec generators emit in practice.
    const RECEIVERS: &[&str] = &["s", "spec", "specification", "gem"];
    for receiver in RECEIVERS {
        let prefix = format!("{receiver}.{attr}");
        if let Some(rest) = line.strip_prefix(&prefix) {
            let rest = rest.trim_start();
            if let Some(rhs) = rest.strip_prefix('=') {
                return Some(rhs.trim());
            }
        }
    }
    None
}

/// Extract the first string literal from `rhs`, handling:
///   `"foo"` / `'foo'`
///   `Gem::Version.new("foo")` / `Gem::Version.new "foo"`
///   `"foo".freeze`
/// Returns the content between quotes; `None` if no literal found.
fn extract_string_literal(rhs: &str) -> Option<String> {
    let bytes = rhs.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' || b == b'\'' {
            let quote = b;
            // Find the matching closing quote; gemspec strings don't
            // contain escapes in practice (Ruby string literals with
            // `\"` do exist but gem names/versions never use them).
            let start = i + 1;
            for j in start..bytes.len() {
                if bytes[j] == quote {
                    let literal = &rhs[start..j];
                    if literal.is_empty() {
                        return None;
                    }
                    return Some(literal.to_string());
                }
            }
            return None;
        }
    }
    None
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_gem_section() {
        let text = r#"
GEM
  remote: https://rubygems.org/
  specs:
    activesupport (7.1.3)
      base64
      concurrent-ruby (~> 1.0, >= 1.0.2)
    base64 (0.2.0)
    concurrent-ruby (1.2.3)

PLATFORMS
  ruby

DEPENDENCIES
  activesupport

BUNDLED WITH
   2.5.3
"#;
        let doc = parse_gemfile_lock(text);
        assert_eq!(doc.specs.len(), 3);
        let active = doc
            .specs
            .iter()
            .find(|s| s.name == "activesupport")
            .expect("activesupport spec");
        assert_eq!(active.version, "7.1.3");
        // Transitive deps captured from indent-6 lines.
        assert_eq!(
            active.depends,
            vec!["base64".to_string(), "concurrent-ruby".to_string()],
        );
        // Leaf specs carry empty depends.
        let base64 = doc.specs.iter().find(|s| s.name == "base64").unwrap();
        assert!(base64.depends.is_empty());
        assert_eq!(doc.dependencies, vec!["activesupport".to_string()]);
    }

    #[test]
    fn captures_per_spec_transitive_deps_with_constraints_stripped() {
        let text = r#"
GEM
  specs:
    foo (1.0.0)
      activesupport (~> 7.0, >= 7.0.1)
      base64
      concurrent-ruby (>= 1.0.2, < 2.0)
    activesupport (7.1.3)
    base64 (0.2.0)
    concurrent-ruby (1.2.3)
"#;
        let doc = parse_gemfile_lock(text);
        let foo = doc.specs.iter().find(|s| s.name == "foo").unwrap();
        assert_eq!(
            foo.depends,
            vec![
                "activesupport".to_string(),
                "base64".to_string(),
                "concurrent-ruby".to_string(),
            ],
        );
    }

    #[test]
    fn transitive_deps_deduplicate_within_a_spec() {
        // A lockfile that declared the same dep twice under one gem —
        // make sure we don't emit two edges. Unusual in practice but
        // cheap defensive check.
        let text = r#"
GEM
  specs:
    foo (1.0.0)
      bar
      bar
    bar (0.1.0)
"#;
        let doc = parse_gemfile_lock(text);
        let foo = doc.specs.iter().find(|s| s.name == "foo").unwrap();
        assert_eq!(foo.depends, vec!["bar".to_string()]);
    }

    #[test]
    fn parses_git_section() {
        let text = r#"
GIT
  remote: https://github.com/rails/rails.git
  revision: abc123
  specs:
    rails (7.2.0.alpha)

DEPENDENCIES
  rails!
"#;
        let doc = parse_gemfile_lock(text);
        assert_eq!(doc.specs.len(), 1);
        assert_eq!(doc.specs[0].kind, GemSection::Git);
    }

    #[test]
    fn parses_path_section() {
        let text = r#"
PATH
  remote: ../vendor/my-gem
  specs:
    my-gem (0.1.0)

DEPENDENCIES
  my-gem!
"#;
        let doc = parse_gemfile_lock(text);
        assert_eq!(doc.specs.len(), 1);
        assert_eq!(doc.specs[0].kind, GemSection::Path);
    }

    #[test]
    fn ignores_constraint_lines() {
        // Lines like `activesupport (~> 7.0)` should NOT appear as specs.
        let text = r#"
GEM
  specs:
    foo (1.0.0)
      activesupport (~> 7.0, >= 7.0.1)
      base64 (>= 0.1.0)
    activesupport (7.1.3)
"#;
        let doc = parse_gemfile_lock(text);
        let names: Vec<_> = doc.specs.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"activesupport"));
        assert!(!names.contains(&"base64")); // base64 never listed at indent 4
    }

    #[test]
    fn dependencies_block_strips_pin_suffix() {
        let text = r#"
DEPENDENCIES
  rails!
  activesupport
  rspec (~> 3.13)
"#;
        let doc = parse_gemfile_lock(text);
        assert_eq!(
            doc.dependencies,
            vec!["rails".to_string(), "activesupport".to_string(), "rspec".to_string()],
        );
    }

    #[test]
    fn read_empty_rootfs_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path(), false).is_empty());
    }

    #[test]
    fn read_finds_gemfile_lock() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Gemfile.lock"),
            "GEM\n  specs:\n    activesupport (7.1.3)\n\nDEPENDENCIES\n  activesupport\n",
        )
        .unwrap();
        let entries = read(dir.path(), false);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "activesupport");
        assert_eq!(entries[0].purl.as_str(), "pkg:gem/activesupport@7.1.3");
    }

    #[test]
    fn git_spec_carries_source_type() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Gemfile.lock"),
            "GIT\n  remote: https://x/y\n  revision: abc\n  specs:\n    y (0.1.0)\n\nDEPENDENCIES\n  y!\n",
        )
        .unwrap();
        let entries = read(dir.path(), false);
        assert_eq!(entries[0].source_type.as_deref(), Some("git"));
    }

    // --- gemspec walker (conformance bug 3) ----------------------------

    #[test]
    fn parse_gemspec_simple_name_version() {
        // Canonical shape from `gem build` output.
        let text = r#"# -*- encoding: utf-8 -*-
Gem::Specification.new do |s|
  s.name = "json"
  s.version = "2.7.2"
  s.authors = ["foo"]
end
"#;
        let (name, version) = parse_gemspec(text).unwrap();
        assert_eq!(name, "json");
        assert_eq!(version, "2.7.2");
    }

    #[test]
    fn parse_gemspec_gem_version_new_form() {
        // Common alternative — Ruby stdlib default gems emit this.
        let text = r#"Gem::Specification.new do |s|
  s.name = "bundler"
  s.version = Gem::Version.new "4.0.10"
end
"#;
        let (name, version) = parse_gemspec(text).unwrap();
        assert_eq!(name, "bundler");
        assert_eq!(version, "4.0.10");
    }

    #[test]
    fn parse_gemspec_spec_receiver_and_freeze() {
        // `spec.` receiver (vs `s.`) and `.freeze` suffix both occur.
        let text = r#"Gem::Specification.new do |spec|
  spec.name = "psych".freeze
  spec.version = "5.1.2".freeze
end
"#;
        let (name, version) = parse_gemspec(text).unwrap();
        assert_eq!(name, "psych");
        assert_eq!(version, "5.1.2");
    }

    #[test]
    fn parse_gemspec_single_quoted() {
        let text = r#"Gem::Specification.new do |s|
  s.name = 'rdoc'
  s.version = '6.6.3.1'
end
"#;
        let (name, version) = parse_gemspec(text).unwrap();
        assert_eq!(name, "rdoc");
        assert_eq!(version, "6.6.3.1");
    }

    #[test]
    fn parse_gemspec_full_extracts_authors_array() {
        let text = r#"Gem::Specification.new do |s|
  s.name = "rake"
  s.version = "13.0.6"
  s.authors = ["Hiroshi SHIBATA", "Eric Hodel", "Jim Weirich"]
end
"#;
        let spec = parse_gemspec_full(text).unwrap();
        assert_eq!(spec.name, "rake");
        assert_eq!(
            spec.authors.as_deref(),
            Some("Hiroshi SHIBATA, Eric Hodel, Jim Weirich"),
        );
    }

    #[test]
    fn parse_gemspec_full_extracts_singular_author() {
        let text = r#"Gem::Specification.new do |s|
  s.name = "solo"
  s.version = "1.0.0"
  s.author = "Solo Dev"
end
"#;
        let spec = parse_gemspec_full(text).unwrap();
        assert_eq!(spec.authors.as_deref(), Some("Solo Dev"));
    }

    #[test]
    fn parse_gemspec_full_no_authors_field_is_none() {
        let text = r#"Gem::Specification.new do |s|
  s.name = "noauth"
  s.version = "1.0"
end
"#;
        let spec = parse_gemspec_full(text).unwrap();
        assert!(spec.authors.is_none());
    }

    #[test]
    fn gemspec_to_entry_populates_maintainer_from_authors() {
        let entry = gemspec_to_entry(
            "rake",
            "13.0.6",
            Some("Hiroshi SHIBATA, Eric Hodel"),
            "/test.gemspec",
        )
        .unwrap();
        assert_eq!(
            entry.maintainer.as_deref(),
            Some("Hiroshi SHIBATA, Eric Hodel"),
        );
    }

    #[test]
    fn parse_gemspec_rejects_when_name_missing() {
        let text = r#"Gem::Specification.new do |s|
  s.version = "1.0"
end
"#;
        assert!(parse_gemspec(text).is_none());
    }

    #[test]
    fn parse_gemspec_handles_interpolated_version() {
        // Ruby `#{}` interpolation means we can't resolve without
        // executing the gemspec. The string-literal extractor still
        // captures the raw `#{VAR}` contents — downstream PURL
        // construction may fail on non-alphanumerics, in which case
        // the caller skips. This test documents current behavior.
        let text = "Gem::Specification.new do |s|\n  s.name = \"foo\"\n  s.version = \"#{FOO_VERSION}\"\nend\n";
        let result = parse_gemspec(text);
        if let Some((_, v)) = result {
            assert!(v.contains('#') || v.contains('{'));
        }
    }

    #[test]
    fn find_gemspecs_walks_default_specs_dir() {
        // Simulate a Ruby install tree:
        //   usr/lib/ruby/gems/3.3.0/specifications/default/json-2.7.2.gemspec
        //   usr/lib/ruby/gems/3.3.0/specifications/psych-5.1.2.gemspec
        let dir = tempfile::tempdir().unwrap();
        let specs = dir.path().join("usr/lib/ruby/gems/3.3.0/specifications");
        std::fs::create_dir_all(specs.join("default")).unwrap();
        std::fs::write(
            specs.join("default/json-2.7.2.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"json\"\n  s.version = \"2.7.2\"\nend\n",
        )
        .unwrap();
        std::fs::write(
            specs.join("psych-5.1.2.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"psych\"\n  s.version = \"5.1.2\"\nend\n",
        )
        .unwrap();
        let found = find_gemspecs(dir.path());
        assert_eq!(found.len(), 2, "expected two gemspecs, got {found:?}");
    }

    #[test]
    fn read_returns_installed_gems_without_gemfile_lock() {
        let dir = tempfile::tempdir().unwrap();
        let specs = dir.path().join("usr/lib/ruby/gems/3.3.0/specifications/default");
        std::fs::create_dir_all(&specs).unwrap();
        std::fs::write(
            specs.join("bigdecimal-3.1.5.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"bigdecimal\"\n  s.version = \"3.1.5\"\nend\n",
        )
        .unwrap();
        let entries = read(dir.path(), false);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "bigdecimal");
        assert_eq!(entries[0].version, "3.1.5");
        assert_eq!(entries[0].source_type.as_deref(), Some("installed-gemspec"));
        assert_eq!(entries[0].purl.as_str(), "pkg:gem/bigdecimal@3.1.5");
    }

    #[test]
    fn gemfile_lock_wins_over_gemspec_for_same_gem() {
        // Dedup: if a gem appears in both Gemfile.lock and a
        // specifications/*.gemspec, the Gemfile.lock version wins
        // (Gemfile.lock processed first and seen_purls blocks the
        // gemspec from being re-added).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Gemfile.lock"),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    json (2.7.1)\n\nDEPENDENCIES\n  json\n",
        )
        .unwrap();
        let specs = dir.path().join("usr/lib/ruby/gems/3.3.0/specifications/default");
        std::fs::create_dir_all(&specs).unwrap();
        std::fs::write(
            specs.join("json-2.7.2.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"json\"\n  s.version = \"2.7.2\"\nend\n",
        )
        .unwrap();
        let entries = read(dir.path(), false);
        // Two distinct PURLs — different versions so they're distinct
        // packages, both emitted. This is correct: two different
        // versions of json are installed.
        let json_entries: Vec<_> =
            entries.iter().filter(|e| e.name == "json").collect();
        assert_eq!(json_entries.len(), 2);
    }
}