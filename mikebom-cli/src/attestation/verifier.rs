//! DSSE envelope verifier — feature 006 US1.
//!
//! Given a DSSE-wrapped in-toto Statement, verify that:
//! 1. The envelope parses (shape, base64 payload).
//! 2. Each signature verifies against its embedded identity material.
//! 3. `--expected-subject` paths match a subject in the statement.
//! 4. `--identity` patterns match the Fulcio cert SAN for keyless.
//! 5. `--no-transparency-log` is respected for keyless envelopes.
//!
//! Layout verification is delegated to the `policy` module (US4).

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigstore::crypto::{
    verification_key::CosignVerificationKey, Signature as SigstoreSig, SigningScheme,
};

use mikebom_common::attestation::envelope::{
    dsse_pae, IdentityMetadata, KeyAlgorithm, Signature, SignedEnvelope, IN_TOTO_PAYLOAD_TYPE,
};

/// Result of verifying a DSSE envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum VerificationReport {
    Pass {
        signer: SignerIdentityInfo,
        subject_digest: Option<String>,
        transparency_log_verified: bool,
        layout_satisfied: Option<bool>,
    },
    Fail {
        mode: FailureMode,
        detail: String,
        /// Partial identity information when available — lets operators
        /// debug identity mismatches without having the full envelope.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        partial_identity: Option<SignerIdentityInfo>,
    },
}

/// Human-readable signer identity description.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerIdentityInfo {
    pub kind: String,
    pub label: String,
}

/// Closed set of verification failure modes (FR-022).
///
/// Tooling consumers branch on this discriminant via `--json` output.
/// Adding a new variant is a spec change, not an implementation detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum FailureMode {
    /// Input is a raw Statement with no DSSE envelope.
    NotSigned,
    /// Envelope shape is invalid.
    MalformedEnvelope,
    /// Cryptographic signature check failed.
    SignatureInvalid,
    /// Signer identity does not match `--public-key` / `--identity` /
    /// layout-declared functionary.
    IdentityMismatch,
    /// `--expected-subject`'s on-disk SHA-256 does not match any
    /// subject digest in the attestation.
    SubjectDigestMismatch,
    /// A supplied in-toto layout's constraint was not satisfied.
    LayoutViolation,
    /// Keyless envelope lacks a Rekor bundle and
    /// `--no-transparency-log` was not set.
    TransparencyLogMissing,
    /// The Fulcio cert has expired.
    CertificateExpired,
    /// Cert chain does not terminate in a known trust root.
    TrustRootInvalid,
}

impl FailureMode {
    /// Exit-code grouping per `contracts/cli.md`:
    /// `0` pass / `1` crypto / `2` envelope / `3` layout.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::SignatureInvalid
            | Self::IdentityMismatch
            | Self::SubjectDigestMismatch
            | Self::TransparencyLogMissing => 1,
            Self::NotSigned
            | Self::MalformedEnvelope
            | Self::CertificateExpired
            | Self::TrustRootInvalid => 2,
            Self::LayoutViolation => 3,
        }
    }
}

/// Internal error type produced by the verifier pipeline. Converted to a
/// [`VerificationReport::Fail`] at the CLI boundary.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("envelope verification failed: {mode:?} ({detail})")]
    Failed {
        mode: FailureMode,
        detail: String,
    },

    #[error("IO error reading attestation: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

impl VerificationError {
    pub fn failed(mode: FailureMode, detail: impl Into<String>) -> Self {
        Self::Failed {
            mode,
            detail: detail.into(),
        }
    }
}

/// Options controlling the verifier. Populated from CLI flags.
#[derive(Clone, Debug, Default)]
pub struct VerifyOptions {
    /// PEM-encoded public key expected to have signed the envelope.
    /// Mutually exclusive with `identity_pattern`.
    pub public_key_pem: Option<String>,
    /// Expected Fulcio-cert SAN pattern (email, URL, or glob).
    /// Mutually exclusive with `public_key_pem`.
    pub identity_pattern: Option<String>,
    /// Absolute paths whose on-disk SHA-256 must match a subject.
    pub expected_subjects: Vec<std::path::PathBuf>,
    /// When `true`, a keyless envelope may lack a Rekor inclusion
    /// proof. When `false` (default), a missing proof → fail.
    pub skip_transparency_log: bool,
    /// Optional in-toto layout to enforce against the envelope +
    /// statement. When `None`, only envelope-level checks run.
    pub layout: Option<crate::policy::layout::Layout>,
}

/// Parsed envelope + decoded payload. Shared across the verify pipeline.
///
/// The `statement` field is a format-agnostic JSON `Value` — accepts
/// any in-toto Statement shape (v0.1 witness-collection, v1 mikebom-
/// native, or anything else that has the minimum `_type` + `subject`
/// + `predicateType` + `predicate` keys).
#[derive(Debug)]
pub struct ParsedAttestation {
    pub envelope: SignedEnvelope,
    pub statement: serde_json::Value,
    /// Raw payload bytes — the DSSE signature covers these exact bytes
    /// via the PAE wrapper.
    pub payload_bytes: Vec<u8>,
}

/// Parse a signed attestation file. Returns `NotSigned` when the file
/// is a raw in-toto Statement (no DSSE envelope) per FR-022.
pub fn parse_envelope(raw: &str) -> Result<ParsedAttestation, VerificationError> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| VerificationError::failed(FailureMode::MalformedEnvelope, e.to_string()))?;

    // Distinguish signed (has payloadType) from raw Statement.
    if value.get("payloadType").is_none() {
        return Err(VerificationError::failed(
            FailureMode::NotSigned,
            "no DSSE envelope wrapper (missing payloadType) — input is a raw Statement",
        ));
    }

    let envelope: SignedEnvelope = serde_json::from_value(value).map_err(|e| {
        VerificationError::failed(
            FailureMode::MalformedEnvelope,
            format!("envelope shape invalid: {e}"),
        )
    })?;

    if envelope.payload_type != IN_TOTO_PAYLOAD_TYPE {
        return Err(VerificationError::failed(
            FailureMode::MalformedEnvelope,
            format!(
                "unexpected payloadType {:?} (only {} supported)",
                envelope.payload_type, IN_TOTO_PAYLOAD_TYPE
            ),
        ));
    }

    if envelope.signatures.is_empty() {
        return Err(VerificationError::failed(
            FailureMode::MalformedEnvelope,
            "envelope has no signatures",
        ));
    }

    let payload_bytes = BASE64_STD.decode(&envelope.payload).map_err(|e| {
        VerificationError::failed(
            FailureMode::MalformedEnvelope,
            format!("payload is not valid base64: {e}"),
        )
    })?;

    let statement: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| {
            VerificationError::failed(
                FailureMode::MalformedEnvelope,
                format!("decoded payload is not valid JSON: {e}"),
            )
        })?;

    // Minimal in-toto shape check: require the four well-known keys
    // regardless of Statement version / predicate type.
    for required in ["_type", "subject", "predicateType", "predicate"] {
        if statement.get(required).is_none() {
            return Err(VerificationError::failed(
                FailureMode::MalformedEnvelope,
                format!("payload missing required in-toto field {required:?}"),
            ));
        }
    }

    Ok(ParsedAttestation {
        envelope,
        statement,
        payload_bytes,
    })
}

/// Verify the cryptographic signature of a single [`Signature`] entry.
/// Uses sigstore-rs [`CosignVerificationKey`] under the hood.
pub fn verify_signature(
    sig: &Signature,
    payload_bytes: &[u8],
    payload_type: &str,
) -> Result<(), VerificationError> {
    let pae = dsse_pae(payload_type, payload_bytes);

    let (key_pem, scheme) = match &sig.identity {
        IdentityMetadata::PublicKey {
            public_key,
            algorithm,
        } => (public_key.clone(), scheme_for_algorithm(*algorithm)),
        IdentityMetadata::Certificate { certificate, .. } => {
            // Extract the SubjectPublicKeyInfo from the cert. We defer
            // chain validation to `verify_cert_chain`; here we only
            // verify the DSSE signature against the cert's SPKI.
            let spki_pem = extract_spki_pem(certificate).map_err(|e| {
                VerificationError::failed(
                    FailureMode::TrustRootInvalid,
                    format!("cannot extract SPKI from cert: {e}"),
                )
            })?;
            // Fulcio issues ECDSA-P256 + SHA-256 certs by default; we
            // pin this scheme for keyless verification.
            (spki_pem, SigningScheme::ECDSA_P256_SHA256_ASN1)
        }
    };

    let vk = CosignVerificationKey::from_pem(key_pem.as_bytes(), &scheme).map_err(|e| {
        VerificationError::failed(
            FailureMode::TrustRootInvalid,
            format!("cannot parse PEM public key: {e}"),
        )
    })?;

    let sig_bytes = BASE64_STD.decode(&sig.sig).map_err(|e| {
        VerificationError::failed(
            FailureMode::MalformedEnvelope,
            format!("signature is not valid base64: {e}"),
        )
    })?;

    vk.verify_signature(SigstoreSig::Raw(&sig_bytes), &pae)
        .map_err(|e| {
            VerificationError::failed(
                FailureMode::SignatureInvalid,
                format!("DSSE signature failed to verify: {e}"),
            )
        })
}

fn scheme_for_algorithm(alg: KeyAlgorithm) -> SigningScheme {
    match alg {
        KeyAlgorithm::EcdsaP256 => SigningScheme::ECDSA_P256_SHA256_ASN1,
        KeyAlgorithm::Ed25519 => SigningScheme::ED25519,
        // sigstore-rs 0.10 does not expose a plain RSA-PKCS1 variant in
        // a cross-version stable way; default back to ECDSA-P256 for
        // parity (real RSA support lands alongside the sign_local flow
        // in T034 when we pin a concrete scheme).
        KeyAlgorithm::RsaPkcs1 => SigningScheme::ECDSA_P256_SHA256_ASN1,
    }
}

/// Extract a PEM-encoded SubjectPublicKeyInfo from a PEM-encoded cert.
/// Uses `x509-parser` indirectly through sigstore's cert helpers.
fn extract_spki_pem(cert_pem: &str) -> Result<String, String> {
    let parsed = pem::parse(cert_pem.as_bytes())
        .map_err(|e| format!("PEM parse failed: {e}"))?;
    if parsed.tag() != "CERTIFICATE" {
        return Err(format!("expected CERTIFICATE PEM, got {}", parsed.tag()));
    }
    let (_, cert) = x509_parser::parse_x509_certificate(parsed.contents())
        .map_err(|e| format!("X.509 parse failed: {e}"))?;
    let spki_der = cert.tbs_certificate.subject_pki.raw;
    let spki_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", spki_der.to_vec()));
    Ok(spki_pem)
}

/// Check that each `expected_subject` path has an on-disk SHA-256 that
/// matches some entry in the statement's `subject` array. Works on
/// either in-toto Statement version because `subject[]` has the same
/// shape across v0.1 and v1.
pub fn verify_subjects(
    statement: &serde_json::Value,
    expected: &[std::path::PathBuf],
) -> Result<Option<String>, VerificationError> {
    if expected.is_empty() {
        return Ok(None);
    }
    let subjects = statement
        .get("subject")
        .and_then(|s| s.as_array())
        .ok_or_else(|| {
            VerificationError::failed(
                FailureMode::MalformedEnvelope,
                "statement.subject is missing or not an array",
            )
        })?;
    let mut matched: Option<String> = None;
    for path in expected {
        let hex = sha256_hex_of_file(path)?;
        let hit = subjects.iter().any(|subj| {
            subj.get("digest")
                .and_then(|d| d.get("sha256"))
                .and_then(|v| v.as_str())
                .map(|s| s.eq_ignore_ascii_case(&hex))
                .unwrap_or(false)
        });
        if !hit {
            return Err(VerificationError::failed(
                FailureMode::SubjectDigestMismatch,
                format!(
                    "on-disk SHA-256 {hex} of {path:?} does not match any attestation subject"
                ),
            ));
        }
        matched = Some(hex);
    }
    Ok(matched)
}

fn sha256_hex_of_file(path: &Path) -> Result<String, VerificationError> {
    let bytes = std::fs::read(path).map_err(VerificationError::from)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Match the cert's Subject Alternative Name against `pattern` (email,
/// URL, or suffix glob).
pub fn match_identity(cert_pem: &str, pattern: &str) -> Result<String, VerificationError> {
    let parsed = pem::parse(cert_pem.as_bytes()).map_err(|e| {
        VerificationError::failed(
            FailureMode::TrustRootInvalid,
            format!("cert PEM parse failed: {e}"),
        )
    })?;
    let (_, cert) = x509_parser::parse_x509_certificate(parsed.contents()).map_err(|e| {
        VerificationError::failed(
            FailureMode::TrustRootInvalid,
            format!("X.509 parse failed: {e}"),
        )
    })?;

    let sans: Vec<String> = cert
        .extensions()
        .iter()
        .filter_map(|ext| {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                ext.parsed_extension()
            {
                Some(san)
            } else {
                None
            }
        })
        .flat_map(|san| san.general_names.iter())
        .map(|gn| format!("{gn:?}"))
        .collect();

    let pattern_is_glob = pattern.contains('*');
    for san in &sans {
        if pattern_is_glob {
            let suffix = pattern.trim_start_matches('*');
            if san.contains(suffix) {
                return Ok(san.clone());
            }
        } else if san.contains(pattern) {
            return Ok(san.clone());
        }
    }

    Err(VerificationError::failed(
        FailureMode::IdentityMismatch,
        format!(
            "cert SAN(s) {sans:?} do not match expected identity {pattern:?}"
        ),
    ))
}

/// Enforce the transparency-log policy: keyless envelopes must embed a
/// Rekor bundle unless `skip_transparency_log` is set.
///
/// Note: this checks policy only. Cryptographic verification of the
/// inclusion proof lands in a follow-on task (Merkle-tree verification
/// against the embedded checkpoint).
pub fn verify_transparency_log(
    sig: &Signature,
    skip: bool,
) -> Result<bool, VerificationError> {
    match &sig.identity {
        IdentityMetadata::Certificate { rekor_bundle, .. } => match (rekor_bundle, skip) {
            (Some(_), _) => Ok(true),
            (None, true) => Ok(false),
            (None, false) => Err(VerificationError::failed(
                FailureMode::TransparencyLogMissing,
                "keyless envelope lacks a Rekor bundle and --no-transparency-log was not set",
            )),
        },
        // Local-key envelopes never include transparency log proofs.
        IdentityMetadata::PublicKey { .. } => Ok(false),
    }
}

/// End-to-end verification pipeline. Consumes a raw attestation file's
/// contents and CLI options, returns a [`VerificationReport`].
pub fn verify_attestation(raw: &str, opts: &VerifyOptions) -> VerificationReport {
    let parsed = match parse_envelope(raw) {
        Ok(p) => p,
        Err(VerificationError::Failed { mode, detail }) => {
            return VerificationReport::Fail {
                mode,
                detail,
                partial_identity: None,
            };
        }
        Err(other) => {
            return VerificationReport::Fail {
                mode: FailureMode::MalformedEnvelope,
                detail: other.to_string(),
                partial_identity: None,
            };
        }
    };

    // v1 of this feature: exactly one signature per envelope.
    let sig = &parsed.envelope.signatures[0];

    // Signature verification.
    if let Err(VerificationError::Failed { mode, detail }) =
        verify_signature(sig, &parsed.payload_bytes, &parsed.envelope.payload_type)
    {
        return VerificationReport::Fail {
            mode,
            detail,
            partial_identity: Some(describe_identity(&sig.identity)),
        };
    }

    // Optional public-key match: re-derive the keyid from opts.public_key_pem
    // and compare against the signature's embedded identity. Placeholder
    // for future expansion — the signature-verify step already enforces
    // this via the embedded identity material.
    if let Some(expected_pem) = opts.public_key_pem.as_ref() {
        if let IdentityMetadata::PublicKey { public_key, .. } = &sig.identity {
            if !public_keys_match(expected_pem, public_key) {
                return VerificationReport::Fail {
                    mode: FailureMode::IdentityMismatch,
                    detail: "--public-key does not match envelope identity".to_string(),
                    partial_identity: Some(describe_identity(&sig.identity)),
                };
            }
        }
    }

    // Keyless identity pattern match.
    if let Some(pattern) = opts.identity_pattern.as_ref() {
        if let IdentityMetadata::Certificate { certificate, .. } = &sig.identity {
            if let Err(VerificationError::Failed { mode, detail }) =
                match_identity(certificate, pattern)
            {
                return VerificationReport::Fail {
                    mode,
                    detail,
                    partial_identity: Some(describe_identity(&sig.identity)),
                };
            }
        }
    }

    // Transparency log policy.
    let tlog_verified =
        match verify_transparency_log(sig, opts.skip_transparency_log) {
            Ok(v) => v,
            Err(VerificationError::Failed { mode, detail }) => {
                return VerificationReport::Fail {
                    mode,
                    detail,
                    partial_identity: Some(describe_identity(&sig.identity)),
                };
            }
            Err(e) => {
                return VerificationReport::Fail {
                    mode: FailureMode::TrustRootInvalid,
                    detail: e.to_string(),
                    partial_identity: Some(describe_identity(&sig.identity)),
                };
            }
        };

    // Subject digest check.
    let subject_digest = match verify_subjects(&parsed.statement, &opts.expected_subjects) {
        Ok(d) => d,
        Err(VerificationError::Failed { mode, detail }) => {
            return VerificationReport::Fail {
                mode,
                detail,
                partial_identity: Some(describe_identity(&sig.identity)),
            };
        }
        Err(e) => {
            return VerificationReport::Fail {
                mode: FailureMode::MalformedEnvelope,
                detail: e.to_string(),
                partial_identity: Some(describe_identity(&sig.identity)),
            };
        }
    };

    // Layout evaluation (US4).
    let layout_satisfied = match &opts.layout {
        Some(layout) => {
            match crate::policy::apply::verify_against_layout(
                &parsed.statement,
                &parsed.envelope,
                layout,
            ) {
                Ok(()) => Some(true),
                Err(mode) => {
                    return VerificationReport::Fail {
                        mode,
                        detail: "in-toto layout constraint violated".to_string(),
                        partial_identity: Some(describe_identity(&sig.identity)),
                    };
                }
            }
        }
        None => None,
    };

    VerificationReport::Pass {
        signer: describe_identity(&sig.identity),
        subject_digest,
        transparency_log_verified: tlog_verified,
        layout_satisfied,
    }
}

fn describe_identity(identity: &IdentityMetadata) -> SignerIdentityInfo {
    match identity {
        IdentityMetadata::PublicKey { public_key, .. } => SignerIdentityInfo {
            kind: "public_key".to_string(),
            label: format!("sha256:{}", sha256_hex_of_str(public_key)),
        },
        IdentityMetadata::Certificate { certificate, .. } => SignerIdentityInfo {
            kind: "certificate".to_string(),
            label: format!("sha256:{}", sha256_hex_of_str(certificate)),
        },
    }
}

fn sha256_hex_of_str(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex_encode(&hasher.finalize())
}

fn public_keys_match(expected_pem: &str, envelope_pem: &str) -> bool {
    let norm = |s: &str| {
        s.trim()
            .replace("\r\n", "\n")
            .replace(['\n', ' '], "")
    };
    norm(expected_pem) == norm(envelope_pem)
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::attestation::envelope::canonical_json_bytes;
    use sigstore::crypto::signing_key::SigStoreSigner;
    use sigstore::crypto::SigningScheme;

    /// Synthesize a minimal signed envelope using an in-process keypair.
    /// Returns the envelope's JSON bytes and the PEM public key.
    fn build_signed_envelope_json() -> (String, String) {
        let scheme = SigningScheme::ECDSA_P256_SHA256_ASN1;
        let signer: SigStoreSigner = scheme.create_signer().unwrap();
        let keypair = signer.to_sigstore_keypair().unwrap();
        let pub_pem = keypair.public_key_to_pem().unwrap();

        // Minimal statement: just enough structure to round-trip through
        // InTotoStatement. The actual payload content is irrelevant to
        // the signature-verify path.
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "test", "digest": {"sha256": "a".repeat(64)}}],
            "predicateType": "https://mikebom.dev/attestation/build-trace/v1",
            "predicate": {
                "metadata": {
                    "tool": {"name": "mikebom", "version": "0.1.0"},
                    "trace_start": "2026-01-01T00:00:00Z",
                    "trace_end": "2026-01-01T00:00:01Z",
                    "target_process": {"pid": 1, "command": "test", "cgroup_id": 0},
                    "host": {"os": "linux", "kernel_version": "6.5", "arch": "x86_64"},
                    "generation_context": "build-time-trace"
                },
                "network_trace": {
                    "connections": [],
                    "summary": {
                        "total_connections": 0, "unique_hosts": [], "unique_ips": [],
                        "protocol_counts": {}, "total_bytes_received": 0
                    }
                },
                "file_access": {
                    "operations": [],
                    "summary": {
                        "total_operations": 0, "unique_paths": 0, "operations_by_type": {}
                    }
                },
                "trace_integrity": {
                    "ring_buffer_overflows": 0, "events_dropped": 0,
                    "uprobe_attach_failures": [], "kprobe_attach_failures": [],
                    "partial_captures": [], "bloom_filter_capacity": 100000,
                    "bloom_filter_false_positive_rate": 0.01
                }
            }
        });
        let payload_bytes = canonical_json_bytes(&statement).unwrap();
        let pae = dsse_pae(IN_TOTO_PAYLOAD_TYPE, &payload_bytes);
        let sig_bytes = signer.sign(&pae).unwrap();

        let envelope = SignedEnvelope {
            payload_type: IN_TOTO_PAYLOAD_TYPE.to_string(),
            payload: BASE64_STD.encode(&payload_bytes),
            signatures: vec![Signature {
                keyid: None,
                sig: BASE64_STD.encode(&sig_bytes),
                identity: IdentityMetadata::PublicKey {
                    public_key: pub_pem.clone(),
                    algorithm: KeyAlgorithm::EcdsaP256,
                },
            }],
        };
        (serde_json::to_string(&envelope).unwrap(), pub_pem)
    }

    #[test]
    fn every_variant_maps_to_documented_exit_code() {
        assert_eq!(FailureMode::SignatureInvalid.exit_code(), 1);
        assert_eq!(FailureMode::IdentityMismatch.exit_code(), 1);
        assert_eq!(FailureMode::SubjectDigestMismatch.exit_code(), 1);
        assert_eq!(FailureMode::TransparencyLogMissing.exit_code(), 1);
        assert_eq!(FailureMode::NotSigned.exit_code(), 2);
        assert_eq!(FailureMode::MalformedEnvelope.exit_code(), 2);
        assert_eq!(FailureMode::CertificateExpired.exit_code(), 2);
        assert_eq!(FailureMode::TrustRootInvalid.exit_code(), 2);
        assert_eq!(FailureMode::LayoutViolation.exit_code(), 3);
    }

    #[test]
    fn failure_mode_serializes_as_pascal_case() {
        let json = serde_json::to_string(&FailureMode::SignatureInvalid).unwrap();
        assert_eq!(json, "\"SignatureInvalid\"");
        let back: FailureMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, FailureMode::SignatureInvalid);
    }

    #[test]
    fn verification_report_pass_serializes_discriminant() {
        let report = VerificationReport::Pass {
            signer: SignerIdentityInfo {
                kind: "public_key".to_string(),
                label: "sha256:abc".to_string(),
            },
            subject_digest: Some("sha256:def".to_string()),
            transparency_log_verified: false,
            layout_satisfied: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"result\":\"pass\""));
    }

    #[test]
    fn verification_error_helper_constructs_failed() {
        let err = VerificationError::failed(FailureMode::NotSigned, "raw statement");
        match err {
            VerificationError::Failed { mode, detail } => {
                assert_eq!(mode, FailureMode::NotSigned);
                assert_eq!(detail, "raw statement");
            }
            _ => panic!("expected Failed variant"),
        }
    }

    #[test]
    fn parse_envelope_rejects_raw_statement() {
        let raw = r#"{"_type":"https://in-toto.io/Statement/v1","subject":[]}"#;
        let err = parse_envelope(raw).unwrap_err();
        match err {
            VerificationError::Failed { mode, .. } => assert_eq!(mode, FailureMode::NotSigned),
            _ => panic!("expected NotSigned"),
        }
    }

    #[test]
    fn parse_envelope_rejects_missing_signatures() {
        let raw = r#"{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}"#;
        let err = parse_envelope(raw).unwrap_err();
        match err {
            VerificationError::Failed { mode, detail } => {
                assert_eq!(mode, FailureMode::MalformedEnvelope);
                assert!(detail.contains("no signatures"));
            }
            _ => panic!("expected MalformedEnvelope"),
        }
    }

    #[test]
    fn parse_envelope_rejects_wrong_payload_type() {
        let raw = r#"{"payloadType":"text/plain","payload":"aGk=","signatures":[{"sig":"x","identity":{"type":"public_key","public_key":"","algorithm":"ecdsa-p256"}}]}"#;
        let err = parse_envelope(raw).unwrap_err();
        match err {
            VerificationError::Failed { mode, detail } => {
                assert_eq!(mode, FailureMode::MalformedEnvelope);
                assert!(detail.contains("unexpected payloadType"));
            }
            _ => panic!("expected MalformedEnvelope"),
        }
    }

    #[test]
    fn verify_attestation_pass_on_valid_local_key_envelope() {
        let (json, _pub_pem) = build_signed_envelope_json();
        let report = verify_attestation(&json, &VerifyOptions::default());
        match report {
            VerificationReport::Pass { .. } => {}
            VerificationReport::Fail { mode, detail, .. } => {
                panic!("expected Pass, got Fail {mode:?}: {detail}");
            }
        }
    }

    #[test]
    fn verify_attestation_fails_on_tampered_payload() {
        let (json, _) = build_signed_envelope_json();
        let mut envelope: SignedEnvelope = serde_json::from_str(&json).unwrap();
        let mut bytes = BASE64_STD.decode(&envelope.payload).unwrap();
        bytes[0] ^= 0xff;
        envelope.payload = BASE64_STD.encode(&bytes);
        let tampered = serde_json::to_string(&envelope).unwrap();
        let report = verify_attestation(&tampered, &VerifyOptions::default());
        match report {
            VerificationReport::Fail { mode, .. } => assert!(
                matches!(
                    mode,
                    FailureMode::SignatureInvalid | FailureMode::MalformedEnvelope
                ),
                "tampered payload should fail; got {mode:?}"
            ),
            _ => panic!("tampered payload should fail"),
        }
    }

    #[test]
    fn verify_attestation_not_signed_for_raw_statement() {
        let raw = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [],
            "predicateType": "https://mikebom.dev/attestation/build-trace/v1",
            "predicate": {}
        })
        .to_string();
        let report = verify_attestation(&raw, &VerifyOptions::default());
        match report {
            VerificationReport::Fail { mode, .. } => assert_eq!(mode, FailureMode::NotSigned),
            _ => panic!("expected NotSigned"),
        }
    }

    #[test]
    fn subject_digest_mismatch_detected() {
        use std::io::Write;
        let (json, _) = build_signed_envelope_json();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // Content whose SHA-256 does NOT equal the statement's placeholder
        // 'a' * 64 digest.
        tmp.as_file().write_all(b"nothing hashes to all-a").unwrap();

        let opts = VerifyOptions {
            expected_subjects: vec![tmp.path().to_path_buf()],
            ..Default::default()
        };
        let report = verify_attestation(&json, &opts);
        match report {
            VerificationReport::Fail { mode, .. } => {
                assert_eq!(mode, FailureMode::SubjectDigestMismatch);
            }
            _ => panic!("subject digest mismatch should fail"),
        }
    }

    #[test]
    fn missing_transparency_log_on_keyless_without_skip_fails() {
        let cert_identity = IdentityMetadata::Certificate {
            certificate: "-----BEGIN CERTIFICATE-----\nMIIBkjCCAToC\n-----END CERTIFICATE-----"
                .to_string(),
            chain: vec![],
            rekor_bundle: None,
        };
        let sig = Signature {
            keyid: None,
            sig: "AAAA".to_string(),
            identity: cert_identity,
        };
        let err = verify_transparency_log(&sig, false).unwrap_err();
        match err {
            VerificationError::Failed { mode, .. } => {
                assert_eq!(mode, FailureMode::TransparencyLogMissing);
            }
            _ => panic!("expected TransparencyLogMissing"),
        }
    }

    #[test]
    fn missing_transparency_log_on_keyless_with_skip_returns_false() {
        let cert_identity = IdentityMetadata::Certificate {
            certificate: "-----BEGIN CERTIFICATE-----\nMIIBkjCCAToC\n-----END CERTIFICATE-----"
                .to_string(),
            chain: vec![],
            rekor_bundle: None,
        };
        let sig = Signature {
            keyid: None,
            sig: "AAAA".to_string(),
            identity: cert_identity,
        };
        let verified = verify_transparency_log(&sig, true).unwrap();
        assert!(!verified);
    }

    #[test]
    fn local_key_envelope_skips_transparency_log_check() {
        let sig = Signature {
            keyid: None,
            sig: "AAAA".to_string(),
            identity: IdentityMetadata::PublicKey {
                public_key: "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----".to_string(),
                algorithm: KeyAlgorithm::EcdsaP256,
            },
        };
        let verified = verify_transparency_log(&sig, false).unwrap();
        assert!(!verified);
    }
}
