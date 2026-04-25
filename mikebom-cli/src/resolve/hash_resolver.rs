//! Resolve package identity by querying deps.dev with a SHA-256 content hash.
//!
//! Uses the deps.dev API v3alpha to look up packages by their content hash.
//! The hex-encoded SHA-256 hash is converted to base64 for the query parameter.

use std::time::Duration;

use anyhow::Context;
use serde::Deserialize;

use mikebom_common::types::hash::ContentHash;
use mikebom_common::types::purl::{encode_purl_segment, Purl};

/// Resolves package identity from SHA-256 content hashes via the deps.dev API.
pub struct HashResolver {
    client: reqwest::Client,
    base_url: String,
}

/// A single match result from a deps.dev hash query.
#[derive(Clone, Debug)]
pub struct HashMatch {
    pub purl: Purl,
    pub system: String,
    pub name: String,
    pub version: String,
}

// deps.dev API response structures.
#[derive(Debug, Deserialize)]
struct DepsDevQueryResponse {
    #[serde(default)]
    results: Vec<DepsDevResult>,
}

#[derive(Debug, Deserialize)]
struct DepsDevResult {
    #[serde(default)]
    version: Option<DepsDevVersion>,
}

#[derive(Debug, Deserialize)]
struct DepsDevVersion {
    #[serde(rename = "versionKey")]
    version_key: DepsDevVersionKey,
}

#[derive(Debug, Deserialize)]
struct DepsDevVersionKey {
    system: String,
    name: String,
    version: String,
}

impl HashResolver {
    /// Create a new hash resolver with the given timeout for API requests.
    pub fn new(timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: "https://api.deps.dev/v3alpha".to_string(),
        }
    }


    /// Build the API URL for a hash query.
    fn build_url(&self, hash: &ContentHash) -> anyhow::Result<String> {
        let hex_str = hash.value.as_str();
        let bytes = hex_to_bytes(hex_str)
            .context("failed to decode hex hash")?;

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

        Ok(format!(
            "{}/queryresults?hash.type=sha256&hash.value={}",
            self.base_url,
            urlencoding_encode(&b64),
        ))
    }

    /// Query deps.dev by SHA-256 hash to find matching packages.
    pub async fn resolve(&self, hash: &ContentHash) -> anyhow::Result<Vec<HashMatch>> {
        let url = self.build_url(hash)?;

        tracing::debug!("querying deps.dev: {url}");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("deps.dev request failed")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("deps.dev returned {status}: {body}");
        }

        let body: DepsDevQueryResponse = response
            .json()
            .await
            .context("failed to parse deps.dev response")?;

        let mut matches = Vec::new();
        for result in body.results {
            if let Some(version) = result.version {
                let vk = &version.version_key;
                let purl_str = system_to_purl(&vk.system, &vk.name, &vk.version);
                if let Some(purl_s) = purl_str {
                    if let Ok(purl) = Purl::new(&purl_s) {
                        matches.push(HashMatch {
                            purl,
                            system: vk.system.clone(),
                            name: vk.name.clone(),
                            version: vk.version.clone(),
                        });
                    }
                }
            }
        }

        Ok(matches)
    }

}

/// Convert a deps.dev system name to a PURL string.
fn system_to_purl(system: &str, name: &str, version: &str) -> Option<String> {
    // purl-spec § Character encoding: name + version are
    // percent-encoded strings. `+` (and other non-allowed chars)
    // must encode as `%2B` in both.
    let n = encode_purl_segment(name);
    let v = encode_purl_segment(version);
    match system.to_uppercase().as_str() {
        "CARGO" => Some(format!("pkg:cargo/{n}@{v}")),
        "NPM" => Some(format!("pkg:npm/{n}@{v}")),
        "GO" => Some(format!("pkg:golang/{n}@{v}")),
        "MAVEN" => {
            // deps.dev uses "groupId:artifactId" format.
            if let Some((group, artifact)) = name.split_once(':') {
                Some(format!(
                    "pkg:maven/{}/{}@{v}",
                    encode_purl_segment(group),
                    encode_purl_segment(artifact),
                ))
            } else {
                Some(format!("pkg:maven/{n}@{v}"))
            }
        }
        "PYPI" => Some(format!("pkg:pypi/{n}@{v}")),
        "NUGET" => Some(format!("pkg:nuget/{n}@{v}")),
        _ => None,
    }
}

/// Decode a hex string into bytes.
fn hex_to_bytes(hex: &str) -> anyhow::Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("hex string has odd length");
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .context("invalid hex character")?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Simple percent-encoding for URL query parameter values.
fn urlencoding_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 2);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                encoded.push(byte as char);
            }
            b' ' => encoded.push_str("%20"),
            b'+' => encoded.push_str("%2B"),
            b'/' => encoded.push_str("%2F"),
            b'=' => encoded.push_str("%3D"),
            _ => {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::types::hash::ContentHash;

    #[test]
    fn hex_to_bytes_valid() {
        let bytes = hex_to_bytes("3fb1c873").expect("valid hex");
        assert_eq!(bytes, vec![0x3f, 0xb1, 0xc8, 0x73]);
    }

    #[test]
    fn hex_to_bytes_odd_length_fails() {
        assert!(hex_to_bytes("abc").is_err());
    }

    #[test]
    fn build_url_constructs_valid_query() {
        let resolver = HashResolver::new(Duration::from_secs(10));
        let hash = ContentHash::sha256(
            "3fb1c873e1b9b056a4dc4c0c198b24c3ffa59243c322bfd971d2d5ef4f463ee1",
        )
        .expect("valid hash");

        let url = resolver.build_url(&hash).expect("should build URL");
        assert!(url.starts_with("https://api.deps.dev/v3alpha/queryresults"));
        assert!(url.contains("hash.type=sha256"));
        assert!(url.contains("hash.value="));
        // The base64 value should be percent-encoded and present.
        assert!(!url.contains(' '));
    }

    #[test]
    fn build_url_base64_encoding() {
        // Known hex → base64 conversion check.
        let resolver = HashResolver::new(Duration::from_secs(5));
        let hash = ContentHash::sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .expect("valid hash");

        let url = resolver.build_url(&hash).expect("should build URL");
        // The SHA-256 of empty string: hex → base64 is "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        // Percent-encoded: "47DEQpj8HBSa%2B%2FTImW%2B5JCeuQeRkm5NMpJWZG3hSuFU%3D"
        assert!(url.contains("47DEQpj8HBSa"));
    }

    #[test]
    fn system_to_purl_cargo() {
        let purl = system_to_purl("CARGO", "serde", "1.0.197");
        assert_eq!(purl, Some("pkg:cargo/serde@1.0.197".to_string()));
    }

    #[test]
    fn system_to_purl_maven_with_colon() {
        let purl = system_to_purl("MAVEN", "org.apache.commons:commons-lang3", "3.12.0");
        assert_eq!(
            purl,
            Some("pkg:maven/org.apache.commons/commons-lang3@3.12.0".to_string())
        );
    }

    #[test]
    fn system_to_purl_unknown_returns_none() {
        assert!(system_to_purl("UNKNOWN_SYSTEM", "foo", "1.0").is_none());
    }
}
