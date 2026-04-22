//! RFC 6902 JSON Patch applier + provenance recorder.
//!
//! Called from `mikebom sbom enrich` to apply operator-supplied patches
//! to a CycloneDX SBOM. Every patch is recorded under the SBOM's
//! top-level `properties[]` array as a `mikebom:enrichment-patch[N]`
//! entry carrying the author, timestamp, base-attestation SHA-256 (if
//! any), and op count. Downstream consumers walking the SBOM can tell
//! attested data from post-hoc enrichment via this property group.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum EnrichmentError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid JSON Patch (RFC 6902): {0}")]
    InvalidPatch(String),

    #[error("patch application failed: {0}")]
    PatchApply(String),
}

/// Per-patch provenance, embedded in the SBOM's properties after apply.
#[derive(Debug, Clone)]
pub struct EnrichmentPatch<'a> {
    /// RFC 6902 operations.
    pub operations: &'a Value,
    /// Recorded author identifier (email, name, "unknown").
    pub author: &'a str,
    /// Timestamp the enrichment was applied.
    pub timestamp: DateTime<Utc>,
    /// Optional SHA-256 hex of the base attestation file the SBOM was
    /// derived from; lets verifiers walk back to the attested source.
    pub base_attestation_sha256: Option<String>,
}

/// Compute a hex-encoded SHA-256 of a file.
pub fn attestation_sha256(path: &Path) -> Result<String, EnrichmentError> {
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    Ok(out)
}

/// Apply a JSON Patch to a mutable SBOM `Value`. On failure, `sbom` is
/// left at its partial state — callers needing atomicity should clone
/// before calling.
pub fn apply_patch(sbom: &mut Value, ops: &Value) -> Result<usize, EnrichmentError> {
    let patch: json_patch::Patch = serde_json::from_value(ops.clone())
        .map_err(|e| EnrichmentError::InvalidPatch(e.to_string()))?;
    let count = patch.0.len();
    json_patch::patch(sbom, &patch).map_err(|e| EnrichmentError::PatchApply(e.to_string()))?;
    Ok(count)
}

/// Append a `mikebom:enrichment-patch[N]` entry to the SBOM's top-level
/// `properties[]` array. If `properties` is absent, it's created.
pub fn append_provenance_property(
    sbom: &mut Value,
    patch_index: usize,
    patch: &EnrichmentPatch<'_>,
) -> Result<(), EnrichmentError> {
    let op_count = patch.operations.as_array().map(|a| a.len()).unwrap_or(0);
    let mut value_obj = serde_json::Map::new();
    value_obj.insert(
        "author".to_string(),
        Value::String(patch.author.to_string()),
    );
    value_obj.insert(
        "timestamp".to_string(),
        Value::String(
            patch
                .timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
    );
    value_obj.insert("op_count".to_string(), Value::Number(op_count.into()));
    if let Some(ref sha) = patch.base_attestation_sha256 {
        value_obj.insert("base_attestation".to_string(), Value::String(sha.clone()));
    }
    let value_json = Value::Object(value_obj).to_string();

    let property = serde_json::json!({
        "name": format!("mikebom:enrichment-patch[{patch_index}]"),
        "value": value_json,
    });

    // Ensure top-level "properties" array exists.
    let obj = sbom
        .as_object_mut()
        .ok_or_else(|| EnrichmentError::InvalidPatch("SBOM root is not an object".to_string()))?;
    let props = obj
        .entry("properties")
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = props
        .as_array_mut()
        .ok_or_else(|| EnrichmentError::InvalidPatch("properties is not an array".to_string()))?;
    arr.push(property);
    Ok(())
}

/// Full enrichment pipeline: apply patch(es) in order, record
/// provenance, return the mutated SBOM as an owned `Value`.
pub fn enrich(
    sbom_in: &Value,
    patches: &[EnrichmentPatch<'_>],
) -> Result<Value, EnrichmentError> {
    let mut sbom = sbom_in.clone();
    for (i, patch) in patches.iter().enumerate() {
        let _ops = apply_patch(&mut sbom, patch.operations)?;
        append_provenance_property(&mut sbom, i, patch)?;
    }
    Ok(sbom)
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_sbom() -> Value {
        json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "alpha", "version": "1.0.0"},
                {"type": "library", "name": "beta", "version": "2.0.0"},
                {"type": "library", "name": "gamma", "version": "3.0.0"}
            ]
        })
    }

    #[test]
    fn apply_add_operation_sets_field() {
        let mut sbom = sample_sbom();
        let ops = json!([
            {"op": "add", "path": "/components/0/supplier", "value": {"name": "Example"}}
        ]);
        let n = apply_patch(&mut sbom, &ops).unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            sbom["components"][0]["supplier"]["name"],
            json!("Example")
        );
    }

    #[test]
    fn apply_add_operation_appends_to_array() {
        let mut sbom = sample_sbom();
        let ops = json!([
            {"op": "add", "path": "/components/0/licenses", "value": []},
            {"op": "add", "path": "/components/0/licenses/-", "value": {"license": {"id": "Apache-2.0"}}}
        ]);
        apply_patch(&mut sbom, &ops).unwrap();
        assert_eq!(
            sbom["components"][0]["licenses"][0]["license"]["id"],
            json!("Apache-2.0")
        );
    }

    #[test]
    fn invalid_patch_is_reported() {
        let mut sbom = sample_sbom();
        let ops = json!([{"op": "wiggle", "path": "/components", "value": null}]);
        assert!(matches!(
            apply_patch(&mut sbom, &ops),
            Err(EnrichmentError::InvalidPatch(_))
        ));
    }

    #[test]
    fn test_op_failure_aborts_patch() {
        let mut sbom = sample_sbom();
        let ops = json!([
            {"op": "test", "path": "/components/0/name", "value": "NOT_ALPHA"},
            {"op": "add", "path": "/components/0/supplier", "value": {"name": "never-applied"}}
        ]);
        assert!(matches!(
            apply_patch(&mut sbom, &ops),
            Err(EnrichmentError::PatchApply(_))
        ));
        // Partial state: the test op may or may not roll back, so don't
        // assert on sbom contents here.
    }

    #[test]
    fn append_provenance_property_creates_properties_array() {
        let mut sbom = sample_sbom();
        let patch = EnrichmentPatch {
            operations: &json!([{"op": "add", "path": "/x", "value": 1}]),
            author: "security-team@example.com",
            timestamp: chrono::DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            base_attestation_sha256: Some("abc123".to_string()),
        };
        append_provenance_property(&mut sbom, 0, &patch).unwrap();
        let props = sbom["properties"].as_array().unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0]["name"], json!("mikebom:enrichment-patch[0]"));
        let value_str = props[0]["value"].as_str().unwrap();
        assert!(value_str.contains("security-team@example.com"));
        assert!(value_str.contains("\"base_attestation\":\"abc123\""));
    }

    #[test]
    fn enrich_applies_multiple_patches_in_order() {
        let sbom = sample_sbom();
        let p1_ops = json!([
            {"op": "add", "path": "/components/0/supplier", "value": {"name": "First"}}
        ]);
        let p2_ops = json!([
            {"op": "add", "path": "/components/0/supplier/contact", "value": "ops@example.com"}
        ]);
        let patches = vec![
            EnrichmentPatch {
                operations: &p1_ops,
                author: "alice",
                timestamp: Utc::now(),
                base_attestation_sha256: None,
            },
            EnrichmentPatch {
                operations: &p2_ops,
                author: "bob",
                timestamp: Utc::now(),
                base_attestation_sha256: None,
            },
        ];
        let out = enrich(&sbom, &patches).unwrap();
        assert_eq!(out["components"][0]["supplier"]["name"], json!("First"));
        assert_eq!(
            out["components"][0]["supplier"]["contact"],
            json!("ops@example.com")
        );
        let props = out["properties"].as_array().unwrap();
        assert_eq!(props.len(), 2);
        assert_eq!(
            props[0]["name"],
            json!("mikebom:enrichment-patch[0]")
        );
        assert_eq!(
            props[1]["name"],
            json!("mikebom:enrichment-patch[1]")
        );
    }

    #[test]
    fn attestation_sha256_matches_manual_hash() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"attestation-content").unwrap();
        let hex = attestation_sha256(tmp.path()).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"attestation-content");
        let mut expected = String::new();
        for b in hasher.finalize() {
            use std::fmt::Write;
            let _ = write!(expected, "{:02x}", b);
        }
        assert_eq!(hex, expected);
    }
}
