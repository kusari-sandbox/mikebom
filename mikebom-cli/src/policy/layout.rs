//! In-toto layout document types + starter-layout generator.
//!
//! Schema: the minimal subset of the in-toto v1 layout format that
//! satisfies single-step policies. Any in-toto-aware verifier
//! (`witness`, the in-toto reference Python impl) accepts these
//! without modification.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Layout {
    #[serde(rename = "_type")]
    pub layout_type: String,
    pub expires: String,
    pub readme: Option<String>,
    pub keys: BTreeMap<String, LayoutKey>,
    pub steps: Vec<LayoutStep>,
    pub inspect: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LayoutKey {
    pub keyid: String,
    pub keytype: String,
    pub scheme: String,
    pub keyval: KeyVal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyVal {
    pub public: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LayoutStep {
    #[serde(rename = "_type")]
    pub step_type: String,
    pub name: String,
    pub expected_materials: Vec<serde_json::Value>,
    pub expected_products: Vec<serde_json::Value>,
    pub pubkeys: Vec<String>,
    pub threshold: u32,
    pub expected_command: Vec<String>,
}

/// Parse `"6m"`, `"1y"`, `"18mo"`, `"2y"` into a `chrono::Duration`.
/// Defaults: `"m"` = 30 days, `"mo"` = 30 days, `"y"` = 365 days,
/// `"d"` = 1 day, `"w"` = 7 days.
pub fn parse_expires_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }

    // Split on the boundary between digits and letters.
    let split_at = s
        .char_indices()
        .find(|(_, c)| c.is_ascii_alphabetic())
        .map(|(i, _)| i)
        .ok_or_else(|| format!("no unit suffix in {s:?}"))?;
    let (num_str, unit) = s.split_at(split_at);
    let n: i64 = num_str
        .parse()
        .map_err(|e| format!("bad integer in {s:?}: {e}"))?;

    let days = match unit {
        "d" => n,
        "w" => n * 7,
        // "mo" and plain "m" both mean months — normalize to 30 days.
        "m" | "mo" | "mon" | "month" | "months" => n * 30,
        "y" | "yr" | "year" | "years" => n * 365,
        other => return Err(format!("unknown unit {other:?} in {s:?}")),
    };
    Ok(Duration::days(days))
}

/// Compute an in-toto-compatible keyid: SHA-256 hex of the
/// DER-encoded SubjectPublicKeyInfo. For a PEM-in PEM-out pipeline we
/// hash the canonical DER bytes extracted via `pem` + `x509_parser`.
pub fn keyid_from_pem(public_pem: &str) -> Result<String, String> {
    let parsed =
        pem::parse(public_pem.as_bytes()).map_err(|e| format!("PEM parse failed: {e}"))?;
    // For PUBLIC KEY PEM the body already IS DER SPKI.
    let der = parsed.contents();
    let mut hasher = Sha256::new();
    hasher.update(der);
    let mut out = String::with_capacity(64);
    for b in hasher.finalize() {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    Ok(out)
}

/// Build a minimal in-toto layout from an operator-supplied PEM public
/// key + step name + expiration duration.
pub fn generate_starter_layout(
    functionary_pem: &str,
    step_name: &str,
    expires_at: DateTime<Utc>,
    readme: Option<String>,
) -> Result<Layout, String> {
    let keyid = keyid_from_pem(functionary_pem)?;
    let mut keys = BTreeMap::new();
    keys.insert(
        keyid.clone(),
        LayoutKey {
            keyid: keyid.clone(),
            keytype: "ecdsa".to_string(),
            scheme: "ecdsa-sha2-nistp256".to_string(),
            keyval: KeyVal {
                public: functionary_pem.to_string(),
            },
        },
    );
    let steps = vec![LayoutStep {
        step_type: "step".to_string(),
        name: step_name.to_string(),
        expected_materials: vec![],
        expected_products: vec![],
        pubkeys: vec![keyid.clone()],
        threshold: 1,
        expected_command: vec![],
    }];
    Ok(Layout {
        layout_type: "layout".to_string(),
        expires: expires_at.to_rfc3339(),
        readme,
        keys,
        steps,
        inspect: vec![],
    })
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    const SAMPLE_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4fKL5mJmSeRmz44GDfLHsQCmXbFs\n\
HQ2Pk79bQ4b3B+Z3Vu3Bm1FBpYhXm5f+o0D9G8xB5Yh5Kq3vU1HnN7mBmw==\n\
-----END PUBLIC KEY-----\n";

    #[test]
    fn parse_expires_duration_handles_common_forms() {
        assert_eq!(parse_expires_duration("1y").unwrap().num_days(), 365);
        assert_eq!(parse_expires_duration("2y").unwrap().num_days(), 730);
        assert_eq!(parse_expires_duration("6m").unwrap().num_days(), 180);
        assert_eq!(parse_expires_duration("18mo").unwrap().num_days(), 540);
        assert_eq!(parse_expires_duration("30d").unwrap().num_days(), 30);
        assert_eq!(parse_expires_duration("52w").unwrap().num_days(), 364);
    }

    #[test]
    fn parse_expires_duration_rejects_invalid() {
        assert!(parse_expires_duration("").is_err());
        assert!(parse_expires_duration("y").is_err());
        assert!(parse_expires_duration("1").is_err());
        assert!(parse_expires_duration("1xyz").is_err());
    }

    #[test]
    fn keyid_from_pem_is_stable_sha256() {
        let id = keyid_from_pem(SAMPLE_PUB_PEM).unwrap();
        let id2 = keyid_from_pem(SAMPLE_PUB_PEM).unwrap();
        assert_eq!(id, id2);
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn keyid_from_pem_rejects_malformed_input() {
        assert!(keyid_from_pem("not a pem").is_err());
    }

    #[test]
    fn generate_starter_layout_produces_valid_in_toto_shape() {
        let expires = Utc::now() + Duration::days(365);
        let layout = generate_starter_layout(
            SAMPLE_PUB_PEM,
            "build-trace-capture",
            expires,
            Some("Test layout".to_string()),
        )
        .unwrap();

        assert_eq!(layout.layout_type, "layout");
        assert_eq!(layout.steps.len(), 1);
        assert_eq!(layout.steps[0].name, "build-trace-capture");
        assert_eq!(layout.steps[0].threshold, 1);
        assert_eq!(layout.keys.len(), 1);
        assert_eq!(layout.readme.as_deref(), Some("Test layout"));
    }

    #[test]
    fn generate_starter_layout_round_trips_through_json() {
        let expires = Utc::now() + Duration::days(365);
        let layout =
            generate_starter_layout(SAMPLE_PUB_PEM, "build", expires, None).unwrap();
        let json = serde_json::to_string(&layout).unwrap();
        let back: Layout = serde_json::from_str(&json).unwrap();
        assert_eq!(layout, back);
    }

    #[test]
    fn generate_starter_layout_bubbles_up_bad_pem() {
        let expires = Utc::now() + Duration::days(365);
        assert!(generate_starter_layout("garbage", "step", expires, None).is_err());
    }

    #[test]
    fn layout_serializes_with_expected_json_shape() {
        let expires = Utc::now() + Duration::days(365);
        let layout =
            generate_starter_layout(SAMPLE_PUB_PEM, "build", expires, None).unwrap();
        let json = serde_json::to_string(&layout).unwrap();
        assert!(json.contains("\"_type\":\"layout\""));
        assert!(json.contains("\"name\":\"build\""));
        assert!(json.contains("\"threshold\":1"));
        assert!(json.contains("\"expires\":"));
    }
}
