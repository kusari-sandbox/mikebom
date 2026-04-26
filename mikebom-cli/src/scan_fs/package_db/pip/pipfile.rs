//! Tier 3: Pipfile.lock parser (Pipenv).
//!
//! JSON-structured with two top-level package maps: `default` (prod)
//! and `develop` (dev). Returns None when no `Pipfile.lock` exists or
//! the file is unparseable.

use std::path::Path;

use mikebom_common::types::purl::Purl;

use super::super::PackageDbEntry;
use super::build_pypi_purl_str;

pub(super) fn read_pipfile_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>> {
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
                parent_purl: None,
                npm_role: None,
                co_owned_by: None,
                hashes: Vec::new(),
                sbom_tier: Some("source".to_string()),
                shade_relocation: None,
                extra_annotations: Default::default(),
            });
        }
    }

    out
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
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
}
