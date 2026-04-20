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

use mikebom_common::types::purl::Purl;

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
    Purl::new(&format!("pkg:gem/{name}@{version}")).ok()
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
        npm_role: None,
        sbom_tier: Some("source".to_string()),
    })
}

/// Public entry point — walks `rootfs` for `Gemfile.lock` files, parses
/// each, and returns the flattened entry list.
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
    if !out.is_empty() {
        tracing::info!(
            rootfs = %rootfs.display(),
            entries = out.len(),
            "parsed Gemfile.lock entries",
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
        assert!(!names.iter().any(|n| *n == "base64")); // base64 never listed at indent 4
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
}