//! PURL ecosystem → deps.dev system identifier mapping.
//!
//! deps.dev indexes six package ecosystems: cargo, npm, pypi, go,
//! maven, nuget. PURL's ecosystem field uses slightly different names
//! (`golang` vs `go`), and many common ecosystems (deb, apk, generic,
//! github) aren't covered at all. This module is the single source of
//! truth for the mapping so the enrichment pass can skip unsupported
//! ecosystems silently instead of making doomed API calls.

/// Return the deps.dev `system` identifier for a PURL ecosystem, or
/// `None` if deps.dev doesn't index that ecosystem.
pub fn deps_dev_system_for(ecosystem: &str) -> Option<&'static str> {
    match ecosystem {
        "cargo" => Some("cargo"),
        "npm" => Some("npm"),
        "pypi" => Some("pypi"),
        // PURL spec uses "golang"; deps.dev uses "go".
        "golang" | "go" => Some("go"),
        "maven" => Some("maven"),
        "nuget" => Some("nuget"),
        // Deliberately unsupported (deps.dev has no data):
        // "deb", "apk", "generic", "github", "gem", "docker"
        _ => None,
    }
}

/// Format the deps.dev `package name` field for a PURL-described
/// component. Different ecosystems compose the name from the PURL's
/// `namespace` and `name` fields differently:
///
/// - **Maven**: `"{groupId}:{artifactId}"`. The earlier license-lookup
///   path used just `name` (the artifactId), which produced
///   `com.google.guava:guava` → `guava` and consistently missed.
/// - **Go**: `"{namespace}/{name}"` — the full module path.
/// - **npm scoped**: `"@{namespace}/{name}"`.
/// - **Everything else**: `name` alone.
pub fn deps_dev_package_name(ecosystem: &str, namespace: Option<&str>, name: &str) -> String {
    match ecosystem {
        "maven" => match namespace {
            Some(g) if !g.is_empty() => format!("{g}:{name}"),
            _ => name.to_string(),
        },
        "golang" | "go" => match namespace {
            Some(ns) if !ns.is_empty() => format!("{ns}/{name}"),
            _ => name.to_string(),
        },
        "npm" => match namespace {
            Some(ns) if !ns.is_empty() => {
                let trimmed = ns.trim_start_matches('@');
                format!("@{trimmed}/{name}")
            }
            _ => name.to_string(),
        },
        _ => name.to_string(),
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn supported_ecosystems_map_to_deps_dev_systems() {
        assert_eq!(deps_dev_system_for("cargo"), Some("cargo"));
        assert_eq!(deps_dev_system_for("npm"), Some("npm"));
        assert_eq!(deps_dev_system_for("pypi"), Some("pypi"));
        assert_eq!(deps_dev_system_for("golang"), Some("go"));
        assert_eq!(deps_dev_system_for("go"), Some("go"));
        assert_eq!(deps_dev_system_for("maven"), Some("maven"));
        assert_eq!(deps_dev_system_for("nuget"), Some("nuget"));
    }

    #[test]
    fn unsupported_ecosystems_return_none() {
        assert_eq!(deps_dev_system_for("deb"), None);
        assert_eq!(deps_dev_system_for("apk"), None);
        assert_eq!(deps_dev_system_for("generic"), None);
        assert_eq!(deps_dev_system_for("github"), None);
        assert_eq!(deps_dev_system_for("gem"), None);
        assert_eq!(deps_dev_system_for("docker"), None);
        assert_eq!(deps_dev_system_for(""), None);
    }

    #[test]
    fn maven_name_is_group_artifact() {
        assert_eq!(
            deps_dev_package_name("maven", Some("com.google.guava"), "guava"),
            "com.google.guava:guava",
        );
    }

    #[test]
    fn go_name_is_module_path() {
        assert_eq!(
            deps_dev_package_name("golang", Some("github.com/spf13"), "cobra"),
            "github.com/spf13/cobra",
        );
    }

    #[test]
    fn npm_scoped_name_includes_at() {
        assert_eq!(
            deps_dev_package_name("npm", Some("angular"), "core"),
            "@angular/core",
        );
        assert_eq!(
            deps_dev_package_name("npm", Some("@types"), "node"),
            "@types/node",
        );
    }

    #[test]
    fn unscoped_ecosystems_use_bare_name() {
        assert_eq!(deps_dev_package_name("cargo", None, "serde"), "serde");
        assert_eq!(deps_dev_package_name("pypi", None, "requests"), "requests");
        assert_eq!(deps_dev_package_name("npm", None, "lodash"), "lodash");
    }

    #[test]
    fn missing_namespace_falls_back_to_bare_name() {
        assert_eq!(deps_dev_package_name("maven", None, "artifactOnly"), "artifactOnly");
        assert_eq!(deps_dev_package_name("maven", Some(""), "artifactOnly"), "artifactOnly");
    }
}
