//! Post-merge enrichment: backfill author fields from installed package.json files.

use std::path::Path;

use super::super::PackageDbEntry;

pub(super) fn enrich_entries_with_installed_authors(
    project_root: &Path,
    entries: &mut [PackageDbEntry],
) {
    let nm_root = project_root.join("node_modules");
    if !nm_root.is_dir() {
        return;
    }
    for entry in entries.iter_mut() {
        if entry.maintainer.is_some() {
            continue;
        }
        // `name` may be scoped (`@babel/core`) — that maps to the
        // on-disk directory `node_modules/@babel/core/package.json`.
        let pkg_json_path = nm_root.join(&entry.name).join("package.json");
        let Ok(bytes) = std::fs::read(&pkg_json_path) else {
            continue;
        };
        let Ok(parsed): Result<serde_json::Value, _> =
            serde_json::from_slice(&bytes)
        else {
            continue;
        };
        if let Some(maintainer) = extract_author_string(&parsed) {
            entry.maintainer = Some(maintainer);
        }
    }
}

/// Extract a single maintainer string from an installed
/// `package.json`. npm's `author` field can be a bare string
/// (`"Alice <a@x>"`) or an object (`{"name": "Alice", "email":
/// "a@x", "url": "https://alice.dev"}`). Falls back to the first
/// entry of `maintainers` when `author` is absent. Returns `None`
/// when neither field carries anything usable.
pub(super) fn extract_author_string(pkg_json: &serde_json::Value) -> Option<String> {
    pkg_json
        .get("author")
        .and_then(person_from_value)
        .or_else(|| {
            pkg_json
                .get("maintainers")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.iter().find_map(person_from_value))
        })
}

fn person_from_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
        }
        serde_json::Value::Object(obj) => {
            let name = obj
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())?;
            let email = obj
                .get("email")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            Some(match email {
                Some(email) => format!("{name} <{email}>"),
                None => name.to_string(),
            })
        }
        _ => None,
    }
}

// -----------------------------------------------------------------------
// Tier C: root package.json fallback (FR-007a)

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    #[test]
    fn extract_author_from_bare_string() {
        let pkg = serde_json::json!({
            "name": "logrus-ish",
            "author": "Alice Maintainer <alice@example.com>"
        });
        assert_eq!(
            extract_author_string(&pkg).as_deref(),
            Some("Alice Maintainer <alice@example.com>"),
        );
    }

    #[test]
    fn extract_author_from_object_with_email() {
        let pkg = serde_json::json!({
            "author": { "name": "Alice", "email": "alice@example.com", "url": "https://alice.dev" }
        });
        assert_eq!(
            extract_author_string(&pkg).as_deref(),
            Some("Alice <alice@example.com>"),
        );
    }

    #[test]
    fn extract_author_from_object_name_only() {
        let pkg = serde_json::json!({
            "author": { "name": "Alice" }
        });
        assert_eq!(extract_author_string(&pkg).as_deref(), Some("Alice"));
    }

    #[test]
    fn extract_author_falls_back_to_maintainers_array() {
        let pkg = serde_json::json!({
            "maintainers": [
                { "name": "Alice", "email": "alice@example.com" },
                { "name": "Bob" }
            ]
        });
        assert_eq!(
            extract_author_string(&pkg).as_deref(),
            Some("Alice <alice@example.com>"),
        );
    }

    #[test]
    fn extract_author_returns_none_when_both_missing() {
        let pkg = serde_json::json!({ "name": "anonymous" });
        assert!(extract_author_string(&pkg).is_none());
    }

    #[test]
    fn extract_author_ignores_empty_string() {
        let pkg = serde_json::json!({ "author": "   " });
        assert!(extract_author_string(&pkg).is_none());
    }
}
