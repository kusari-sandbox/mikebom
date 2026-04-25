use std::time::Duration;

use serde::Deserialize;

/// A result from querying deps.dev by content hash.
#[derive(Clone, Debug, Deserialize)]
pub struct QueryResult {
    pub system: String,
    pub name: String,
    pub version: String,
}

/// Version information from deps.dev GetVersion API.
#[derive(Clone, Debug, Deserialize)]
pub struct VersionInfo {
    pub licenses: Vec<String>,
    #[serde(default)]
    pub advisory_keys: Vec<String>,
    #[serde(default)]
    pub links: Vec<Link>,
}

/// A link associated with a package version.
#[derive(Clone, Debug, Deserialize)]
pub struct Link {
    pub label: String,
    pub url: String,
}

/// Response shape from the `:dependencies` endpoint. deps.dev returns
/// the full transitive tree from the queried coord — `nodes[0]` is
/// always the queried coord itself (`relation == "SELF"`), followed
/// by one entry per transitive dep (`relation == "DIRECT" |
/// "INDIRECT"`). `edges` references nodes by index.
#[derive(Clone, Debug, Deserialize)]
pub struct DependencyGraph {
    #[serde(default)]
    pub nodes: Vec<DependencyNode>,
    #[serde(default)]
    pub edges: Vec<DependencyEdge>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DependencyNode {
    #[serde(rename = "versionKey")]
    pub version_key: VersionKey,
    #[serde(default)]
    pub relation: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct VersionKey {
    /// Ecosystem tag, uppercase (e.g. `"MAVEN"`, `"CARGO"`). Returned
    /// uppercased regardless of request case.
    pub system: String,
    /// Package name. For Maven this is `"group:artifact"`.
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DependencyEdge {
    #[serde(rename = "fromNode")]
    pub from_node: usize,
    #[serde(rename = "toNode")]
    pub to_node: usize,
    #[serde(default)]
    pub requirement: String,
}

/// HTTP client for the deps.dev v3 API.
///
/// Provides hash-based package lookup and version metadata retrieval
/// for license, advisory, and supplier enrichment. `Clone` is cheap
/// because `reqwest::Client` is reference-counted internally.
#[derive(Clone)]
pub struct DepsDevClient {
    http: reqwest::Client,
    base_url: String,
    #[allow(dead_code)]
    timeout: Duration,
}

impl DepsDevClient {
    /// Create a new deps.dev API client with the given timeout per request.
    pub fn new(timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();

        Self {
            http,
            base_url: "https://api.deps.dev/v3".to_string(),
            timeout,
        }
    }

    /// Build the URL for a hash-based query.
    fn query_url(&self, hash_hex: &str) -> String {
        format!(
            "{}/query?hash.type=sha256&hash.value={}",
            self.base_url, hash_hex
        )
    }

    /// Build the URL for a GetVersion request.
    fn version_url(&self, system: &str, name: &str, version: &str) -> String {
        format!(
            "{}/systems/{}/packages/{}/versions/{}",
            self.base_url,
            url_encode(system),
            url_encode(name),
            url_encode(version),
        )
    }

    /// Query deps.dev for packages matching a content hash.
    pub async fn query_by_hash(&self, hash_hex: &str) -> anyhow::Result<Vec<QueryResult>> {
        let url = self.query_url(hash_hex);
        tracing::debug!(url = %url, "querying deps.dev by hash");

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "deps.dev query failed: HTTP {status} — {body}"
            );
        }

        let results: Vec<QueryResult> = response.json().await?;
        Ok(results)
    }

    /// Build the URL for a `:dependencies` request — the full
    /// transitive dep graph starting from this coord.
    fn dependencies_url(&self, system: &str, name: &str, version: &str) -> String {
        format!(
            "{}/systems/{}/packages/{}/versions/{}:dependencies",
            self.base_url,
            url_encode(system),
            url_encode(name),
            url_encode(version),
        )
    }

    /// Fetch the full transitive dependency graph for a coord. The
    /// returned `DependencyGraph` has one `SELF` node (the queried
    /// coord) plus every transitive dep reachable from it, along with
    /// the `from → to` edges between them. Used by the post-scan
    /// enrichment pass to fill in deps that weren't reconstructable
    /// from local JARs or the M2 cache (typically because a shade
    /// plugin stripped `META-INF/maven/` or the user hasn't run
    /// `mvn install` to populate their local cache).
    ///
    /// `system` must be lowercase (deps.dev accepts both but documents
    /// lowercase as canonical). `name` must be formatted appropriately
    /// for the ecosystem — Maven names are `group:artifact`.
    pub async fn get_dependency_graph(
        &self,
        system: &str,
        name: &str,
        version: &str,
    ) -> anyhow::Result<DependencyGraph> {
        let url = self.dependencies_url(system, name, version);
        tracing::debug!(url = %url, "querying deps.dev for dependency graph");

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "deps.dev GetDependencies failed: HTTP {status} — {body}"
            );
        }

        let graph: DependencyGraph = response.json().await?;
        Ok(graph)
    }

    /// Retrieve version metadata (licenses, advisories, links) for a package.
    pub async fn get_version(
        &self,
        system: &str,
        name: &str,
        version: &str,
    ) -> anyhow::Result<VersionInfo> {
        let url = self.version_url(system, name, version);
        tracing::debug!(url = %url, "querying deps.dev for version info");

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "deps.dev GetVersion failed: HTTP {status} — {body}"
            );
        }

        let info: VersionInfo = response.json().await?;
        Ok(info)
    }
}

/// Percent-encode a URL path segment.
///
/// Covers the characters deps.dev's package-name field actually uses in
/// practice across its ecosystems:
///   `:` → `%3A` — Maven coord separator (`group:artifact`).
///   `/` → `%2F` — Go module paths (`github.com/spf13/cobra`).
///   `@` → `%40` — npm scoped packages (`@angular/core`).
///   `%`, space — defensive.
fn url_encode(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('/', "%2F")
        .replace('@', "%40")
        .replace(':', "%3A")
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn query_url_construction() {
        let client = DepsDevClient::new(Duration::from_secs(5));
        let url = client.query_url("abc123def456");
        assert_eq!(
            url,
            "https://api.deps.dev/v3/query?hash.type=sha256&hash.value=abc123def456"
        );
    }

    #[test]
    fn version_url_construction() {
        let client = DepsDevClient::new(Duration::from_secs(5));
        let url = client.version_url("cargo", "serde", "1.0.197");
        assert_eq!(
            url,
            "https://api.deps.dev/v3/systems/cargo/packages/serde/versions/1.0.197"
        );
    }

    #[test]
    fn version_url_encodes_special_chars() {
        let client = DepsDevClient::new(Duration::from_secs(5));
        let url = client.version_url("npm", "@angular/core", "16.0.0");
        assert!(url.contains("%40angular%2Fcore"));
    }
}
