//! pnpm-lock.yaml parser.

use std::path::Path;


use super::super::PackageDbEntry;
use super::{build_npm_purl, NpmIntegrity};

pub(super) fn read_pnpm_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>> {
    let path = rootfs.join("pnpm-lock.yaml");
    let text = std::fs::read_to_string(&path).ok()?;
    let parsed: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    let source_path = path.to_string_lossy().into_owned();
    let out = parse_pnpm_lock(&parsed, &source_path, include_dev);
    if out.is_empty() { None } else { Some(out) }
}

/// Parse a deserialised `pnpm-lock.yaml` document. Handles v6/v7/v9
/// dialects per research.md R5.
pub(crate) fn parse_pnpm_lock(
    root: &serde_yaml::Value,
    source_path: &str,
    include_dev: bool,
) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();

    // v6/v7 put per-package info under `packages:` keyed by "/<name>@<version>"
    // (or "/@scope/name@version").
    // v9 splits: `snapshots:` carries resolved versions, `packages:` carries
    // registry metadata. Merge on key.
    let Some(packages) = root.get("packages").and_then(|v| v.as_mapping()) else {
        return out;
    };

    let mut keys: Vec<String> = packages
        .keys()
        .filter_map(|k| k.as_str().map(|s| s.to_string()))
        .collect();
    keys.sort();

    for key in keys {
        let Some(entry) = packages.get(serde_yaml::Value::String(key.clone())) else {
            continue;
        };
        let Some(tbl) = entry.as_mapping() else { continue };

        // v6/v7 key form: "/foo@1.0.0" or "/@scope/name@1.0.0"
        // v9 key form: "foo@1.0.0" (no leading slash)
        let stripped = key.strip_prefix('/').unwrap_or(&key);
        let (name, version) = parse_pnpm_key(stripped).unwrap_or_default();
        if name.is_empty() || version.is_empty() {
            continue;
        }

        let is_dev = tbl
            .get(serde_yaml::Value::String("dev".to_string()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !include_dev && is_dev {
            continue;
        }

        let Some(purl) = build_npm_purl(&name, &version) else {
            continue;
        };

        let hashes = tbl
            .get(serde_yaml::Value::String("resolution".to_string()))
            .and_then(|res| res.as_mapping())
            .and_then(|m| m.get(serde_yaml::Value::String("integrity".to_string())))
            .and_then(|v| v.as_str())
            .and_then(NpmIntegrity::parse)
            .and_then(|i| i.to_content_hash())
            .map(|h| vec![h])
            .unwrap_or_default();

        // Per-package `dependencies:` mapping. pnpm writes this as a
        // YAML mapping of `name: version-spec` pairs; we only need
        // the keys so the dep-graph edges can be built in scan_fs.
        // Peer-dep suffixes on pnpm v9 (`react@18.0.0(react-dom@...)`)
        // are stripped via `parse_pnpm_key` elsewhere; the `dependencies:`
        // values themselves are plain semver strings.
        let depends: Vec<String> = tbl
            .get(serde_yaml::Value::String("dependencies".to_string()))
            .and_then(|v| v.as_mapping())
            .map(|m| {
                m.keys()
                    .filter_map(|k| k.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        out.push(PackageDbEntry {
            purl,
            name,
            version,
            arch: None,
            source_path: source_path.to_string(),
            depends,
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
            hashes,
            sbom_tier: Some("source".to_string()),
            shade_relocation: None,
            extra_annotations: Default::default(),
        });
    }

    out
}

/// Parse a pnpm package key — `<name>@<version>` or
/// `@<scope>/<name>@<version>` — into (name, version). The last `@`
/// is the version separator; everything before it is the name.
fn parse_pnpm_key(key: &str) -> Option<(String, String)> {
    // Strip any parenthesised peer-dep suffix (e.g. "(react@18.0.0)").
    let key = key.split('(').next().unwrap_or(key);
    // Find the LAST '@' that's after position 0 (position 0 is the
    // scope prefix for @scope/name).
    let search_start = if key.starts_with('@') { 1 } else { 0 };
    let at_idx = key[search_start..].rfind('@').map(|i| i + search_start)?;
    let name = key[..at_idx].to_string();
    let version = key[at_idx + 1..].to_string();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

// -----------------------------------------------------------------------
// Tier B: flat node_modules walk
// -----------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    #[test]
    fn pnpm_lock_v6_style_parses() {
        let yaml = r#"
lockfileVersion: '6.0'
packages:
  /lodash@4.17.21:
    resolution:
      integrity: sha512-MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx+7fIK+4qg9hvLABzzXAIaFMqoD6YFUYaCQPkMInyGdz6TQEsE7bPdCg==
    dev: false
  /eslint@8.0.0:
    dev: true
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let out = parse_pnpm_lock(&parsed, "/pnpm-lock.yaml", false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "lodash");
        assert_eq!(out[0].version, "4.17.21");
    }

    #[test]
    fn pnpm_lock_scoped_package_parses() {
        let yaml = r#"
lockfileVersion: '6.0'
packages:
  /@angular/core@16.0.0:
    resolution: {}
    dev: false
"#;
        let parsed: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let out = parse_pnpm_lock(&parsed, "/pnpm-lock.yaml", false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "@angular/core");
        assert_eq!(out[0].version, "16.0.0");
        assert_eq!(out[0].purl.as_str(), "pkg:npm/%40angular/core@16.0.0");
    }

    #[test]
    fn pnpm_key_parser_handles_peer_suffix() {
        // v9 adds peer-dep suffixes: `react-dom@18.0.0(react@18.0.0)`.
        let (name, version) = parse_pnpm_key("react-dom@18.0.0(react@18.0.0)").unwrap();
        assert_eq!(name, "react-dom");
        assert_eq!(version, "18.0.0");
    }
}
