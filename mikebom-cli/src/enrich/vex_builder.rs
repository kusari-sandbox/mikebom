use mikebom_common::resolution::AdvisoryRef;
use mikebom_common::types::purl::Purl;

use super::deps_dev_client::DepsDevClient;

/// Build VEX (Vulnerability Exploitability eXchange) entries for a package.
///
/// Queries the deps.dev API for advisories affecting the given package
/// and returns structured advisory references suitable for inclusion
/// in CycloneDX vulnerabilities or SPDX security annotations.
///
/// Currently a stub that returns an empty list. Will be wired to
/// `DepsDevClient::get_version` advisory data in a future phase.
pub async fn build_vex_entries(
    _client: &DepsDevClient,
    _purl: &Purl,
) -> anyhow::Result<Vec<AdvisoryRef>> {
    // TODO: Query client.get_version() for advisory_keys,
    // then construct AdvisoryRef for each.
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
        let entries = build_vex_entries(&client, &purl)
            .await
            .expect("build vex entries");
        assert!(entries.is_empty());
    }
}
