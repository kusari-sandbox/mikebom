//! package-lock.json v2/v3 parser.

use std::path::Path;


use super::super::PackageDbEntry;
use super::{build_npm_purl, NpmIntegrity};

pub(super) fn read_package_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>> {
    let path = rootfs.join("package-lock.json");
    let text = std::fs::read_to_string(&path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&text).ok()?;
    let source_path = path.to_string_lossy().into_owned();
    let out = parse_package_lock(&parsed, &source_path, include_dev);
    if out.is_empty() { None } else { Some(out) }
}

/// Parse a deserialised `package-lock.json` v2/v3 document. Iterates
/// the top-level `packages` object; skips the root entry (`""`) and
/// any workspace sub-roots (detected via `link: true`).
pub(crate) fn parse_package_lock(
    root: &serde_json::Value,
    source_path: &str,
    include_dev: bool,
) -> Vec<PackageDbEntry> {
    let mut out = Vec::new();
    let Some(packages) = root.get("packages").and_then(|v| v.as_object()) else {
        return out;
    };

    // Sorted for determinism.
    let mut keys: Vec<&String> = packages.keys().collect();
    keys.sort();

    for path_key in keys {
        if path_key.is_empty() {
            // Root project entry — skip.
            continue;
        }
        let entry = &packages[path_key];
        let Some(tbl) = entry.as_object() else { continue };

        // Workspace link — symlink to a sibling workspace, not a
        // published package. Skip.
        if tbl.get("link").and_then(|v| v.as_bool()) == Some(true) {
            continue;
        }

        // `dev: true` / `optional: true` propagate through the nested
        // tree. Filter at source before the caller's dedup pass.
        let is_dev = tbl
            .get("dev")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let is_optional = tbl
            .get("optional")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !include_dev && (is_dev || is_optional) {
            continue;
        }

        // Version is required.
        let version = tbl
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if version.is_empty() {
            continue;
        }

        // Name is either declared in the entry or derived from the
        // path key: last `node_modules/<scope>?/<name>` segment.
        let name = tbl
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| derive_name_from_path_key(path_key));
        if name.is_empty() {
            continue;
        }

        let Some(purl) = build_npm_purl(&name, &version) else {
            continue;
        };

        let hashes = tbl
            .get("integrity")
            .and_then(|v| v.as_str())
            .and_then(NpmIntegrity::parse)
            .and_then(|i| i.to_content_hash())
            .map(|h| vec![h])
            .unwrap_or_default();

        let depends = tbl
            .get("dependencies")
            .and_then(|v| v.as_object())
            .map(|deps| deps.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        out.push(PackageDbEntry {
            purl,
            name,
            version,
            arch: None,
            source_path: source_path.to_string(),
            depends,
            maintainer: None,
            licenses: tbl
                .get("license")
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    mikebom_common::types::license::SpdxExpression::try_canonical(s.trim()).ok()
                })
                .into_iter()
                .collect(),
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

/// Derive a package name from a `packages` path key like
/// `node_modules/foo` or `node_modules/@scope/bar` or deeply nested
/// `node_modules/foo/node_modules/bar`. The real name is always the
/// segment (or scope+segment) that follows the LAST `node_modules/`.
fn derive_name_from_path_key(key: &str) -> String {
    let idx = match key.rfind("node_modules/") {
        Some(i) => i + "node_modules/".len(),
        None => return String::new(),
    };
    let tail = &key[idx..];
    // Scoped: "@scope/name" — two segments.
    if tail.starts_with('@') {
        let parts: Vec<&str> = tail.splitn(3, '/').collect();
        if parts.len() >= 2 {
            return format!("{}/{}", parts[0], parts[1]);
        }
    }
    // Unscoped: single segment.
    tail.split('/').next().unwrap_or("").to_string()
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::super::{read, NpmError};
    use super::*;
    #[test]
    fn derive_name_handles_flat_and_scoped_and_nested() {
        assert_eq!(derive_name_from_path_key("node_modules/foo"), "foo");
        assert_eq!(
            derive_name_from_path_key("node_modules/@scope/bar"),
            "@scope/bar"
        );
        assert_eq!(
            derive_name_from_path_key("node_modules/foo/node_modules/bar"),
            "bar"
        );
        assert_eq!(
            derive_name_from_path_key("node_modules/foo/node_modules/@scope/baz"),
            "@scope/baz"
        );
    }

    #[test]
    fn package_lock_v3_basic() {
        let src = serde_json::json!({
            "name": "myapp",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "myapp", "version": "0.1.0" },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "integrity": "sha512-MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx+7fIK+4qg9hvLABzzXAIaFMqoD6YFUYaCQPkMInyGdz6TQEsE7bPdCg==",
                    "license": "MIT"
                },
                "node_modules/eslint": {
                    "version": "8.0.0",
                    "dev": true
                }
            }
        });
        let out = parse_package_lock(&src, "/package-lock.json", false);
        assert_eq!(out.len(), 1, "dev entry filtered by default");
        assert_eq!(out[0].name, "lodash");
        assert_eq!(out[0].version, "4.17.21");
        assert_eq!(out[0].sbom_tier.as_deref(), Some("source"));
        assert_eq!(out[0].is_dev, Some(false));
        // Hash extraction is covered by `integrity_round_trips_to_content_hash`;
        // once PackageDbEntry gains a hashes field we re-assert here.
    }

    #[test]
    fn package_lock_v3_include_dev_surfaces_dev_packages() {
        let src = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/eslint": { "version": "8.0.0", "dev": true }
            }
        });
        let out = parse_package_lock(&src, "/package-lock.json", true);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].is_dev, Some(true));
    }

    #[test]
    fn package_lock_skips_workspace_link_entries() {
        let src = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/my-workspace": { "resolved": "../my-workspace", "link": true }
            }
        });
        let out = parse_package_lock(&src, "/package-lock.json", true);
        assert!(out.is_empty());
    }

    #[test]
    fn package_lock_scoped_package_emits_encoded_purl() {
        let src = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/@angular/core": { "version": "16.0.0", "license": "MIT" }
            }
        });
        let out = parse_package_lock(&src, "/package-lock.json", false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].purl.as_str(), "pkg:npm/%40angular/core@16.0.0");
    }

    #[test]
    fn package_lock_skips_optional_by_default() {
        let src = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/fsevents": { "version": "2.3.0", "optional": true }
            }
        });
        let out_default = parse_package_lock(&src, "/p.json", false);
        assert!(out_default.is_empty());
        let out_all = parse_package_lock(&src, "/p.json", true);
        assert_eq!(out_all.len(), 1);
    }

    #[test]
    fn v1_lockfile_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name":"old","lockfileVersion":1,"dependencies":{}}"#,
        )
        .unwrap();
        let err = read(dir.path(), false, crate::scan_fs::ScanMode::Path).unwrap_err();
        assert!(
            matches!(err, NpmError::LockfileV1Unsupported { .. }),
            "got {err:?}"
        );
        // Error message matches the contract.
        assert_eq!(
            err.to_string(),
            "package-lock.json v1 not supported; regenerate with npm ≥7"
        );
    }

    #[test]
    fn v2_and_v3_lockfiles_do_not_trigger_refusal() {
        for v in [2, 3] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("package-lock.json"),
                format!(r#"{{"lockfileVersion":{v},"packages":{{}}}}"#),
            )
            .unwrap();
            let res = read(dir.path(), false, crate::scan_fs::ScanMode::Path);
            assert!(res.is_ok(), "v{v} lockfile should parse without refusal");
        }
    }
}
