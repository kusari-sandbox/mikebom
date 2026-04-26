//! node_modules flat walker + root package.json reader + npm-source classifier.

use std::path::{Path, PathBuf};


use super::super::PackageDbEntry;
use super::build_npm_purl;
use super::enrich::extract_author_string;

pub(super) fn read_node_modules(
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
///
/// Currently only exercised by unit tests; the npm walker handles the
/// internal-path filter inline today. Kept for the test surface.
#[allow(dead_code)]
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
        let maintainer = extract_author_string(&parsed);
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
            maintainer,
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
            parent_purl: None,
            npm_role,
            co_owned_by: None,
            hashes: Vec::new(),
            sbom_tier: Some("deployed".to_string()),
            shade_relocation: None,
            extra_annotations: Default::default(),
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

/// Overlay `maintainer` on lockfile-derived entries by reading the
/// corresponding installed `package.json` under the project's
/// `node_modules/`. Silent no-op when the tree isn't present; only
pub(super) fn read_root_package_json(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>> {
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
                parent_purl: None,
                npm_role: None,
                co_owned_by: None,
                hashes: Vec::new(),
                sbom_tier: Some("design".to_string()),
                shade_relocation: None,
                extra_annotations: Default::default(),
            });
        }
    }
    out
}

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
                "expected true for {p}"
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
                "expected false for {p}"
            );
        }
    }
}
