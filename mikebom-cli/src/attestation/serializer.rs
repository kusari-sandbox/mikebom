//! JSON serialization/deserialization for in-toto attestations.

// `read_attestation` is invoked cross-platform from `cli/generate.rs`,
// but `write_*` and `to_json` are only invoked from
// `cli/scan.rs::execute_scan` (Linux-only). Allow dead_code on
// non-Linux to keep the cross-platform clippy clean.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::Path;

use mikebom_common::attestation::statement::InTotoStatement;
use mikebom_common::attestation::witness::WitnessStatement;
use serde::Serialize;

use crate::attestation::signer::{self, SigningIdentity};

/// Serialize an attestation to a JSON file (unsigned, legacy shape).
///
/// Preserved for callers that don't yet thread a `SigningIdentity`
/// through. New code should prefer [`write_attestation_signed`] which
/// wraps the statement in a DSSE envelope when a signing identity is
/// configured.
pub fn write_attestation(stmt: &InTotoStatement, path: &Path) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(stmt)?;
    std::fs::write(path, json)?;
    tracing::info!("Attestation written to {}", path.display());
    Ok(())
}

/// Serialize an attestation, wrapping in a DSSE envelope when an active
/// signing identity is configured. Hard-fails on signing errors per
/// FR-006a: no file is written if signing fails.
pub fn write_attestation_signed(
    stmt: &InTotoStatement,
    path: &Path,
    identity: &SigningIdentity,
) -> anyhow::Result<()> {
    match signer::sign(stmt, identity)? {
        Some(envelope) => {
            let json = serde_json::to_string_pretty(&envelope)?;
            std::fs::write(path, json)?;
            tracing::info!("Signed attestation written to {}", path.display());
        }
        None => {
            // No signing requested — emit legacy raw shape + warning
            // per FR-004. Downstream verifiers that can't match the
            // raw shape should branch on the `NotSigned` FailureMode.
            tracing::warn!(
                "Attestation emitted without a signing identity — downstream \
                verification will report NotSigned. Pass --signing-key <PATH> \
                or --keyless to produce a DSSE envelope."
            );
            write_attestation(stmt, path)?;
        }
    }
    Ok(())
}

/// Serialize a witness-compatible attestation Statement v0.1, signing
/// through the same DSSE envelope flow as the mikebom-native path.
///
/// The envelope's `payloadType` stays `application/vnd.in-toto+json`
/// regardless of Statement version — `go-witness`, `sbomit`, and any
/// DSSE-aware verifier parse either version transparently.
pub fn write_witness_attestation_signed(
    stmt: &WitnessStatement,
    path: &Path,
    identity: &SigningIdentity,
) -> anyhow::Result<()> {
    write_signable(stmt, path, identity, "witness-v0.1")
}

/// Shared sign-or-raw flow parametric on the Statement type.
fn write_signable<T: Serialize>(
    stmt: &T,
    path: &Path,
    identity: &SigningIdentity,
    label: &str,
) -> anyhow::Result<()> {
    match identity {
        SigningIdentity::None => {
            tracing::warn!(
                format = label,
                "Attestation emitted without a signing identity — downstream \
                verification will report NotSigned. Pass --signing-key <PATH> \
                or --keyless to produce a DSSE envelope."
            );
            let json = serde_json::to_string_pretty(stmt)?;
            std::fs::write(path, json)?;
            tracing::info!("Attestation ({label}) written to {}", path.display());
            Ok(())
        }
        SigningIdentity::LocalKey { .. } | SigningIdentity::Keyless { .. } => {
            // Canonicalize + sign the bytes directly. We can't route
            // through `signer::sign` which takes `&InTotoStatement`, so
            // run the equivalent pipeline inline.
            use base64::{engine::general_purpose::STANDARD as B64, Engine};
            use mikebom_common::attestation::envelope::{
                canonical_json_bytes, dsse_pae, IdentityMetadata, KeyAlgorithm, Signature,
                SignedEnvelope, IN_TOTO_PAYLOAD_TYPE,
            };
            use signer::SigningError;

            let payload_bytes = canonical_json_bytes(stmt)
                .map_err(|e| anyhow::anyhow!("canonical JSON failed: {e}"))?;
            let pae = dsse_pae(IN_TOTO_PAYLOAD_TYPE, &payload_bytes);

            // Local-key path only for now; keyless reuses the same
            // typed error as the mikebom-v1 path.
            let SigningIdentity::LocalKey {
                path: key_path,
                passphrase_env,
            } = identity
            else {
                return Err(anyhow::anyhow!(SigningError::OidcTokenError {
                    detail:
                        "keyless witness-format signing not yet implemented — use --signing-key"
                            .to_string(),
                }));
            };
            let keypair = signer::load_local_signer(key_path, passphrase_env.as_deref())?;
            let scheme = sigstore::crypto::SigningScheme::ECDSA_P256_SHA256_ASN1;
            let sstore_signer = keypair
                .to_sigstore_signer(&scheme)
                .map_err(|e| anyhow::anyhow!("build signer: {e}"))?;
            let sig_bytes = sstore_signer
                .sign(&pae)
                .map_err(|e| anyhow::anyhow!("local sign: {e}"))?;
            let public_key_pem = keypair
                .public_key_to_pem()
                .map_err(|e| anyhow::anyhow!("export pub key: {e}"))?;

            let envelope = SignedEnvelope {
                payload_type: IN_TOTO_PAYLOAD_TYPE.to_string(),
                payload: B64.encode(&payload_bytes),
                signatures: vec![Signature {
                    keyid: None,
                    sig: B64.encode(&sig_bytes),
                    identity: IdentityMetadata::PublicKey {
                        public_key: public_key_pem,
                        algorithm: KeyAlgorithm::EcdsaP256,
                    },
                }],
            };
            std::fs::write(path, serde_json::to_string_pretty(&envelope)?)?;
            tracing::info!(
                "Signed attestation ({label}) written to {}",
                path.display()
            );
            Ok(())
        }
    }
}

/// Read an attestation from a JSON file.
pub fn read_attestation(path: &Path) -> anyhow::Result<InTotoStatement> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read attestation file {}: {}", path.display(), e))?;
    let stmt: InTotoStatement = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("failed to parse attestation JSON: {e}"))?;
    Ok(stmt)
}

/// Serialize an attestation to a JSON string.
pub fn to_json(stmt: &InTotoStatement) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(stmt)?)
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn round_trip_via_fixture() {
        let fixture = include_str!("../../../tests/fixtures/sample-attestation.json");
        let stmt: InTotoStatement =
            serde_json::from_str(fixture).expect("fixture should parse");

        assert_eq!(stmt.statement_type, InTotoStatement::STATEMENT_TYPE);
        assert_eq!(stmt.predicate_type, InTotoStatement::PREDICATE_TYPE);
        assert_eq!(stmt.predicate.metadata.tool.name, "mikebom");
        assert_eq!(stmt.predicate.network_trace.connections.len(), 3);
        assert_eq!(stmt.predicate.file_access.operations.len(), 2);
        assert_eq!(stmt.predicate.trace_integrity.ring_buffer_overflows, 0);

        // Re-serialize and parse again
        let json = to_json(&stmt).expect("should serialize");
        let stmt2: InTotoStatement =
            serde_json::from_str(&json).expect("re-serialized should parse");
        assert_eq!(stmt.predicate.network_trace.connections.len(),
                   stmt2.predicate.network_trace.connections.len());
    }

    #[test]
    fn write_and_read_file() {
        let fixture = include_str!("../../../tests/fixtures/sample-attestation.json");
        let stmt: InTotoStatement =
            serde_json::from_str(fixture).expect("fixture should parse");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.attestation.json");

        write_attestation(&stmt, &path).expect("should write");
        let read_back = read_attestation(&path).expect("should read");

        assert_eq!(stmt.statement_type, read_back.statement_type);
        assert_eq!(
            stmt.predicate.network_trace.connections.len(),
            read_back.predicate.network_trace.connections.len()
        );
    }
}
