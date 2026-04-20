//! Map hostnames to ecosystems as a last-resort heuristic.
//!
//! When URL pattern matching and hash resolution both fail, the hostname
//! alone can still indicate which ecosystem a download belongs to. This
//! is the lowest-confidence resolver and should only be used as a
//! fallback to establish a baseline ecosystem tag.

/// Attempt to map a hostname to a package ecosystem name.
///
/// Returns the ecosystem identifier (e.g., "cargo", "pypi", "npm") or
/// `None` if the hostname is not recognized.
pub fn resolve_hostname(hostname: &str) -> Option<&'static str> {
    let lower = hostname.to_ascii_lowercase();
    match lower.as_str() {
        // Cargo / crates.io
        "crates.io" | "static.crates.io" => Some("cargo"),

        // PyPI
        "pypi.org" | "files.pythonhosted.org" => Some("pypi"),

        // npm
        "registry.npmjs.org" => Some("npm"),

        // Go
        "proxy.golang.org" | "sum.golang.org" => Some("golang"),

        // Maven
        "repo1.maven.org" | "repo.maven.apache.org" | "central.maven.org" => Some("maven"),

        // RubyGems
        "rubygems.org" => Some("gem"),

        // Debian / Ubuntu
        "deb.debian.org" | "security.debian.org" | "archive.ubuntu.com"
        | "security.ubuntu.com" => Some("deb"),

        _ => None,
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn cargo_hostnames() {
        assert_eq!(resolve_hostname("crates.io"), Some("cargo"));
        assert_eq!(resolve_hostname("static.crates.io"), Some("cargo"));
    }

    #[test]
    fn pypi_hostnames() {
        assert_eq!(resolve_hostname("pypi.org"), Some("pypi"));
        assert_eq!(resolve_hostname("files.pythonhosted.org"), Some("pypi"));
    }

    #[test]
    fn npm_hostname() {
        assert_eq!(resolve_hostname("registry.npmjs.org"), Some("npm"));
    }

    #[test]
    fn golang_hostnames() {
        assert_eq!(resolve_hostname("proxy.golang.org"), Some("golang"));
        assert_eq!(resolve_hostname("sum.golang.org"), Some("golang"));
    }

    #[test]
    fn maven_hostnames() {
        assert_eq!(resolve_hostname("repo1.maven.org"), Some("maven"));
        assert_eq!(resolve_hostname("repo.maven.apache.org"), Some("maven"));
    }

    #[test]
    fn rubygems_hostname() {
        assert_eq!(resolve_hostname("rubygems.org"), Some("gem"));
    }

    #[test]
    fn deb_hostnames() {
        assert_eq!(resolve_hostname("deb.debian.org"), Some("deb"));
        assert_eq!(resolve_hostname("archive.ubuntu.com"), Some("deb"));
    }

    #[test]
    fn unknown_hostname_returns_none() {
        assert_eq!(resolve_hostname("example.com"), None);
        assert_eq!(resolve_hostname("github.com"), None);
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(resolve_hostname("Crates.IO"), Some("cargo"));
        assert_eq!(resolve_hostname("PYPI.ORG"), Some("pypi"));
    }
}
