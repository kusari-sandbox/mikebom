//! HTTP client for the ClearlyDefined `/definitions/{...}` endpoint.
//!
//! Returns the curated `licensed.declared` SPDX expression — that's
//! mikebom's only consumer for this milestone. The richer payload
//! (per-file licenses, attributions, copyrights, tool scores) is not
//! parsed; if a future enrichment needs them, extend [`CdDefinition`].

use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

const DEFAULT_BASE_URL: &str = "https://api.clearlydefined.io";

/// Fields mikebom actually uses out of CD's `/definitions` payload.
/// Optional everywhere because CD returns 200 with a sparse body for
/// "we know about this package but have no curated data yet."
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CdDefinition {
    /// CD's curated SPDX expression for the package, taken from
    /// `licensed.declared`. `None` when the field is absent or empty.
    pub declared_license: Option<String>,
}

/// Async HTTP client.
///
/// Construction is cheap; reuse a single instance across many calls
/// to share the underlying connection pool. 5-second per-request
/// timeout keeps a slow CD instance from blocking the scan.
#[derive(Clone)]
pub struct ClearlyDefinedClient {
    http: reqwest::Client,
    base_url: String,
}

impl ClearlyDefinedClient {
    pub fn new(timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!(
                "mikebom/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/mikebom)"
            ))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            base_url: DEFAULT_BASE_URL.to_string(),
        }
    }

    /// Fetch the curated definition for one CD coord. Returns `Ok(None)`
    /// when CD answered 404 (CD doesn't have the package yet) so the
    /// caller can cache the miss; returns `Err` for transient failures
    /// (timeout, connection error, malformed JSON) so the caller can
    /// distinguish "definitively unknown" from "try again later."
    pub async fn get_definition(
        &self,
        coord_url_path: &str,
    ) -> Result<Option<CdDefinition>> {
        let url = format!("{}/definitions/{}", self.base_url, coord_url_path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("CD request failed: {url}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "CD returned non-success status {}: {}",
                resp.status(),
                url
            );
        }
        let body: CdResponse = resp
            .json()
            .await
            .with_context(|| format!("CD response JSON parse failed: {url}"))?;
        Ok(Some(body.into_definition()))
    }
}

/// Thin shape over CD's `/definitions/{...}` JSON. Only the fields we
/// actually consume.
#[derive(Debug, Deserialize)]
struct CdResponse {
    licensed: Option<CdLicensed>,
}

#[derive(Debug, Deserialize)]
struct CdLicensed {
    declared: Option<String>,
}

impl CdResponse {
    fn into_definition(self) -> CdDefinition {
        CdDefinition {
            declared_license: self
                .licensed
                .and_then(|l| l.declared)
                .filter(|s| !s.is_empty()),
        }
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn cd_response_with_declared_license_parses() {
        let body = serde_json::json!({
            "licensed": {
                "declared": "MIT"
            }
        });
        let parsed: CdResponse = serde_json::from_value(body).unwrap();
        let def = parsed.into_definition();
        assert_eq!(def.declared_license.as_deref(), Some("MIT"));
    }

    #[test]
    fn cd_response_with_empty_declared_normalizes_to_none() {
        let body = serde_json::json!({
            "licensed": {
                "declared": ""
            }
        });
        let parsed: CdResponse = serde_json::from_value(body).unwrap();
        assert!(parsed.into_definition().declared_license.is_none());
    }

    #[test]
    fn cd_response_with_no_licensed_block_yields_none() {
        let body = serde_json::json!({});
        let parsed: CdResponse = serde_json::from_value(body).unwrap();
        assert!(parsed.into_definition().declared_license.is_none());
    }

    #[test]
    fn cd_response_compound_expression_preserved() {
        let body = serde_json::json!({
            "licensed": {
                "declared": "MIT OR Apache-2.0"
            }
        });
        let parsed: CdResponse = serde_json::from_value(body).unwrap();
        assert_eq!(
            parsed.into_definition().declared_license.as_deref(),
            Some("MIT OR Apache-2.0")
        );
    }
}
