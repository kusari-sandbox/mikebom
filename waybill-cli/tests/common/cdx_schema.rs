//! Shared CycloneDX 1.6 schema validator for integration tests.
//!
//! Milestone 777 (FR-008) extracted this from the duplicated copies in
//! `sbom_user_metadata.rs` and `sbom_type_signaling.rs` so the signing
//! tests validate against the same schema rather than a third copy.
//!
//! # Why the JSF reference is NOT stubbed
//!
//! The CDX 1.6 schema reaches two external schemas by relative `$ref`:
//! `spdx.schema.json` (license-expression strings) and
//! `jsf-0.82.schema.json` (`#/definitions/signature`).
//!
//! Both were previously replaced with permissive stubs, on the premise
//! that waybill never emits signed BOMs. That premise was false —
//! `--sign-key` has emitted signed BOMs since milestone 221 — and the
//! `{}` stub meant *any* signature object validated. That is precisely
//! how the malformed `publicKey` this milestone fixes went unnoticed:
//! the placement defect lives in the CDX schema itself and would have
//! been caught, but the key-shape defect sits behind the stubbed `$ref`
//! and was invisible.
//!
//! The JSF schema is therefore vendored and served for real. The SPDX
//! stub is retained: it covers license-expression strings only, is
//! unrelated to signing, and the real SPDX license list would accept
//! the literal identifiers waybill emits anyway.

use std::path::PathBuf;
use std::sync::OnceLock;

pub fn cdx_schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schemas/cyclonedx-1.6.json")
}

pub fn jsf_schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schemas/jsf-0.82.schema.json")
}

/// Resolves the CDX 1.6 schema's two external references.
///
/// `jsf-0.82.schema.json` resolves to the vendored upstream document.
/// `spdx.schema.json` resolves to a permissive string stub (see module
/// docs for why that one stays a stub).
pub struct CdxRefRetriever;

impl jsonschema::Retrieve for CdxRefRetriever {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let s = uri.as_str();
        if s.ends_with("spdx.schema.json") {
            return Ok(serde_json::json!({"type": "string"}));
        }
        if s.ends_with("jsf-0.82.schema.json") {
            let raw = std::fs::read_to_string(jsf_schema_path())?;
            return Ok(serde_json::from_str(&raw)?);
        }
        Err(format!("unexpected external schema reference: {s}").into())
    }
}

/// CDX 1.6 validator with both external references resolved.
///
/// `should_validate_formats(true)` is set explicitly even though it is
/// already the default: `jsonschema` resolves that default by draft
/// (on for draft-04/06/07, off for 2020-12), and both schemas here are
/// draft-07. Stating it means a future schema-draft bump cannot
/// silently disable format assertion. It matters for signatures — JSF
/// types `signature.algorithm` as `oneOf[uri-format string, enum]`, and
/// without format assertion a valid `"ES256"` matches both branches and
/// fails `oneOf`.
pub fn cdx_validator() -> &'static jsonschema::Validator {
    static CELL: OnceLock<jsonschema::Validator> = OnceLock::new();
    CELL.get_or_init(|| {
        let raw = std::fs::read_to_string(cdx_schema_path()).expect("read CDX 1.6 schema");
        let schema: serde_json::Value = serde_json::from_str(&raw).expect("parse CDX schema");
        jsonschema::options()
            .with_retriever(CdxRefRetriever)
            .should_validate_formats(true)
            .build(&schema)
            .expect("compile CDX 1.6 schema")
    })
}

/// Validate a CDX document, returning every error as a printable list.
/// Empty vec == valid.
pub fn cdx_validation_errors(doc: &serde_json::Value) -> Vec<String> {
    cdx_validator()
        .iter_errors(doc)
        .map(|e| format!("{}: {e}", e.instance_path()))
        .collect()
}
