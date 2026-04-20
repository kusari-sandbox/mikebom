use mikebom_common::types::license::SpdxExpression;
use mikebom_common::types::purl::Purl;

use super::deps_dev_client::DepsDevClient;

/// Resolve SPDX license expressions for a package via deps.dev GetVersion.
///
/// Queries the deps.dev API for the package identified by the given PURL
/// and returns any SPDX license expressions associated with it.
///
/// Currently a stub that returns an empty list. Will be wired to
/// `DepsDevClient::get_version` when the enrichment pipeline supports
/// async sources.
pub async fn resolve_licenses(
    _client: &DepsDevClient,
    _purl: &Purl,
) -> anyhow::Result<Vec<SpdxExpression>> {
    // TODO: Query client.get_version() using purl ecosystem/name/version,
    // then parse each license string into SpdxExpression.
    Ok(vec![])
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn stub_returns_empty() {
        let client = DepsDevClient::new(Duration::from_secs(5));
        let purl = Purl::new("pkg:cargo/serde@1.0.197").expect("valid purl");
        let licenses = resolve_licenses(&client, &purl)
            .await
            .expect("resolve licenses");
        assert!(licenses.is_empty());
    }
}
