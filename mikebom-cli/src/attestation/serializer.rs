//! JSON serialization/deserialization for in-toto attestations.

use std::path::Path;

use mikebom_common::attestation::statement::InTotoStatement;

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

/// Read an attestation from a JSON file.
pub fn read_attestation(path: &Path) -> anyhow::Result<InTotoStatement> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read attestation file {}: {}", path.display(), e))?;
    let stmt: InTotoStatement = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("failed to parse attestation JSON: {}", e))?;
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
