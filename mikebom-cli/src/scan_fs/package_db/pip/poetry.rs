//! Tier 2: poetry.lock parser (v1 and v2 formats).
//!
//! Dispatches on the top-level `[metadata] lock-version` field to
//! handle both v1 (`"1.1"` / `"1.2"`) and v2 (`"2.0"` / `"2.1"`)
//! shapes. Returns None when no `poetry.lock` exists or the file is
//! unparseable. Called from [`super::read`] after the venv tier.

use std::path::Path;

use mikebom_common::types::purl::Purl;

use super::super::PackageDbEntry;
use super::build_pypi_purl_str;

// -----------------------------------------------------------------------
// Tier 2: Poetry lockfile (v1 + v2)
// -----------------------------------------------------------------------

/// Read `<rootfs>/poetry.lock` if present. Returns None when absent or
/// unparseable. Dispatches on the top-level `[metadata] lock-version`
/// field to handle both v1 (`"1.1"` / `"1.2"`) and v2 (`"2.0"` / `"2.1"`)
/// shapes.
pub(super) fn read_poetry_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>> {
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
            parent_purl: None,
            npm_role: None,
            co_owned_by: None,
            hashes: Vec::new(),
            sbom_tier: Some("source".to_string()),
            shade_relocation: None,
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

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
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
}
