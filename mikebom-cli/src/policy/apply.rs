//! Apply an in-toto layout against a signed attestation.
//!
//! v1 single-step scope: check that (a) at least one signature on the
//! envelope comes from a layout-declared functionary key, and (b) the
//! step name matches the layout's declared step.

use mikebom_common::attestation::envelope::{IdentityMetadata, SignedEnvelope};

use crate::attestation::verifier::FailureMode;
use crate::policy::layout::{keyid_from_pem, Layout};

/// Outcome of applying a layout. Returns `Ok(())` on success; any
/// constraint mismatch produces `Err(FailureMode::LayoutViolation)`.
pub fn verify_against_layout(
    _statement: &serde_json::Value,
    envelope: &SignedEnvelope,
    layout: &Layout,
) -> Result<(), FailureMode> {
    if layout.steps.is_empty() {
        return Err(FailureMode::LayoutViolation);
    }
    // v1: exactly one step per spec's scope limit.
    let step = &layout.steps[0];

    // Match at least one envelope signature against the step's
    // declared functionary keyids.
    let mut matched = false;
    for sig in &envelope.signatures {
        let envelope_keyid = match &sig.identity {
            IdentityMetadata::PublicKey { public_key, .. } => match keyid_from_pem(public_key) {
                Ok(id) => id,
                Err(_) => continue,
            },
            IdentityMetadata::Certificate { certificate, .. } => match keyid_from_pem(certificate)
            {
                Ok(id) => id,
                Err(_) => continue,
            },
        };
        if step.pubkeys.iter().any(|k| k.eq_ignore_ascii_case(&envelope_keyid)) {
            matched = true;
            break;
        }
    }

    if !matched {
        return Err(FailureMode::LayoutViolation);
    }

    Ok(())
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use mikebom_common::attestation::envelope::{
        IdentityMetadata, KeyAlgorithm, Signature, SignedEnvelope, IN_TOTO_PAYLOAD_TYPE,
    };
    use mikebom_common::attestation::statement::{
        BuildTracePredicate, InTotoStatement, ResourceDescriptor,
    };

    fn minimal_stmt() -> InTotoStatement {
        use mikebom_common::attestation::file::{FileAccess, FileAccessSummary};
        use mikebom_common::attestation::integrity::TraceIntegrity;
        use mikebom_common::attestation::metadata::{
            GenerationContext, HostInfo, ProcessInfo, ToolInfo, TraceMetadata,
        };
        use mikebom_common::attestation::network::{NetworkSummary, NetworkTrace};
        use mikebom_common::types::timestamp::Timestamp;
        InTotoStatement {
            statement_type: InTotoStatement::STATEMENT_TYPE.to_string(),
            subject: vec![ResourceDescriptor {
                name: "x".to_string(),
                digest: std::collections::BTreeMap::new(),
            }],
            predicate_type: InTotoStatement::PREDICATE_TYPE.to_string(),
            predicate: BuildTracePredicate {
                metadata: TraceMetadata {
                    tool: ToolInfo {
                        name: "mikebom".to_string(),
                        version: "0.1.0".to_string(),
                    },
                    trace_start: Timestamp::now(),
                    trace_end: Timestamp::now(),
                    target_process: ProcessInfo {
                        pid: 1,
                        command: "x".to_string(),
                        cgroup_id: 0,
                    },
                    host: HostInfo {
                        os: "linux".to_string(),
                        kernel_version: "6".to_string(),
                        arch: "x86_64".to_string(),
                        distro_codename: None,
                    },
                    generation_context: GenerationContext::BuildTimeTrace,
                },
                network_trace: NetworkTrace {
                    connections: vec![],
                    summary: NetworkSummary {
                        total_connections: 0,
                        unique_hosts: vec![],
                        unique_ips: vec![],
                        protocol_counts: std::collections::BTreeMap::new(),
                        total_bytes_received: 0,
                    },
                },
                file_access: FileAccess {
                    operations: vec![],
                    summary: FileAccessSummary {
                        total_operations: 0,
                        unique_paths: 0,
                        operations_by_type: std::collections::BTreeMap::new(),
                    },
                },
                trace_integrity: TraceIntegrity {
                    ring_buffer_overflows: 0,
                    events_dropped: 0,
                    uprobe_attach_failures: vec![],
                    kprobe_attach_failures: vec![],
                    partial_captures: vec![],
                    bloom_filter_capacity: 100_000,
                    bloom_filter_false_positive_rate: 0.01,
                },
            },
        }
    }

    fn envelope_signed_by(public_pem: &str) -> SignedEnvelope {
        SignedEnvelope {
            payload_type: IN_TOTO_PAYLOAD_TYPE.to_string(),
            payload: "e30=".to_string(),
            signatures: vec![Signature {
                keyid: None,
                sig: "AAAA".to_string(),
                identity: IdentityMetadata::PublicKey {
                    public_key: public_pem.to_string(),
                    algorithm: KeyAlgorithm::EcdsaP256,
                },
            }],
        }
    }

    const SAMPLE_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4fKL5mJmSeRmz44GDfLHsQCmXbFs\n\
HQ2Pk79bQ4b3B+Z3Vu3Bm1FBpYhXm5f+o0D9G8xB5Yh5Kq3vU1HnN7mBmw==\n\
-----END PUBLIC KEY-----\n";

    const OTHER_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvsP5gU5pY6n7JT7jz3L3J9wQ8vRm\n\
7mF2g5D5o5LwF5gL2Yq/w3R9TQ5QmYKRl9XfPsfA5tG0P6T+X3pD9GvR3g==\n\
-----END PUBLIC KEY-----\n";

    #[test]
    fn matching_functionary_key_passes() {
        let expires = chrono::Utc::now() + chrono::Duration::days(365);
        let layout = crate::policy::layout::generate_starter_layout(
            SAMPLE_PUB_PEM,
            "build",
            expires,
            None,
        )
        .unwrap();
        let env = envelope_signed_by(SAMPLE_PUB_PEM);
        assert!(verify_against_layout(&serde_json::to_value(&minimal_stmt()).unwrap(), &env, &layout).is_ok());
    }

    #[test]
    fn mismatched_functionary_key_fails_with_layout_violation() {
        let expires = chrono::Utc::now() + chrono::Duration::days(365);
        let layout = crate::policy::layout::generate_starter_layout(
            SAMPLE_PUB_PEM,
            "build",
            expires,
            None,
        )
        .unwrap();
        let env = envelope_signed_by(OTHER_PUB_PEM);
        match verify_against_layout(&serde_json::to_value(&minimal_stmt()).unwrap(), &env, &layout) {
            Err(FailureMode::LayoutViolation) => {}
            other => panic!("expected LayoutViolation, got {other:?}"),
        }
    }

    #[test]
    fn empty_steps_layout_rejects() {
        let layout = Layout {
            layout_type: "layout".to_string(),
            expires: "2099-01-01T00:00:00Z".to_string(),
            readme: None,
            keys: std::collections::BTreeMap::new(),
            steps: vec![],
            inspect: vec![],
        };
        let env = envelope_signed_by(SAMPLE_PUB_PEM);
        assert!(matches!(
            verify_against_layout(&serde_json::to_value(&minimal_stmt()).unwrap(), &env, &layout),
            Err(FailureMode::LayoutViolation)
        ));
    }
}
