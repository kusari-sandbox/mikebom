use mikebom_common::types::purl::Purl;

use super::deps_dev_client::DepsDevClient;

/// Resolve supplier metadata for a package via deps.dev.
///
/// Attempts to determine the supplier/publisher of a package by
/// inspecting the links and metadata returned by the deps.dev API.
///
/// Currently a stub that returns `None`. Will be wired to
/// `DepsDevClient::get_version` link data in a future phase.
pub async fn resolve_supplier(
    _client: &DepsDevClient,
    _purl: &Purl,
) -> anyhow::Result<Option<String>> {
    // TODO: Query client.get_version() for links,
    // then extract supplier from homepage or repository metadata.
    Ok(None)
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn stub_returns_none() {
        let client = DepsDevClient::new(Duration::from_secs(5));
        let purl = Purl::new("pkg:cargo/serde@1.0.197").expect("valid purl");
        let supplier = resolve_supplier(&client, &purl)
            .await
            .expect("resolve supplier");
        assert!(supplier.is_none());
    }
}
