//! Integration tests for `mikebom policy init` + `mikebom sbom verify
//! --layout` — feature 006 US4.

#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::io::Write;
use std::path::Path;
use std::process::Command;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;

use mikebom_common::attestation::envelope::{
    canonical_json_bytes, dsse_pae, IdentityMetadata, KeyAlgorithm, Signature, SignedEnvelope,
    IN_TOTO_PAYLOAD_TYPE,
};
use mikebom_common::attestation::file::{FileAccess, FileAccessSummary};
use mikebom_common::attestation::integrity::TraceIntegrity;
use mikebom_common::attestation::metadata::{
    GenerationContext, HostInfo, ProcessInfo, ToolInfo, TraceMetadata,
};
use mikebom_common::attestation::network::{NetworkSummary, NetworkTrace};
use mikebom_common::attestation::statement::{
    BuildTracePredicate, InTotoStatement, ResourceDescriptor,
};
use mikebom_common::types::timestamp::Timestamp;
use sigstore::crypto::SigningScheme;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mikebom")
}

fn minimal_statement() -> InTotoStatement {
    let mut digest = std::collections::BTreeMap::new();
    digest.insert("sha256".to_string(), "a".repeat(64));
    InTotoStatement {
        statement_type: InTotoStatement::STATEMENT_TYPE.to_string(),
        subject: vec![ResourceDescriptor {
            name: "layout-integration".to_string(),
            digest,
        }],
        predicate_type: InTotoStatement::PREDICATE_TYPE.to_string(),
        predicate: BuildTracePredicate {
            metadata: TraceMetadata {
                tool: ToolInfo {
                    name: "mikebom".to_string(),
                    version: "0.1.0-test".to_string(),
                },
                trace_start: Timestamp::now(),
                trace_end: Timestamp::now(),
                target_process: ProcessInfo {
                    pid: 1,
                    command: "test".to_string(),
                    cgroup_id: 0,
                },
                host: HostInfo {
                    os: "linux".to_string(),
                    kernel_version: "6.5".to_string(),
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

/// Produce an (envelope_path, public_key_pem_path, signing_keypair).
/// Using a fresh keypair each call keeps tests isolated.
struct Keyed {
    envelope_path: std::path::PathBuf,
    pub_key_path: std::path::PathBuf,
    _tmp: tempfile::TempDir,
}

fn signed_envelope_with_fresh_key(dir: &Path) -> Keyed {
    let scheme = SigningScheme::ECDSA_P256_SHA256_ASN1;
    let signer = scheme.create_signer().unwrap();
    let keypair = signer.to_sigstore_keypair().unwrap();
    let public_pem = keypair.public_key_to_pem().unwrap();
    let statement = minimal_statement();
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
                public_key: public_pem.clone(),
                algorithm: KeyAlgorithm::EcdsaP256,
            },
        }],
    };
    let envelope_path = dir.join("attest.dsse.json");
    let pub_key_path = dir.join("signer.pub");
    std::fs::write(&envelope_path, serde_json::to_string(&envelope).unwrap()).unwrap();
    std::fs::write(&pub_key_path, public_pem).unwrap();
    Keyed {
        envelope_path,
        pub_key_path,
        _tmp: tempfile::TempDir::new_in(".").unwrap_or_else(|_| tempfile::tempdir().unwrap()),
    }
}

#[test]
fn policy_init_produces_valid_layout_json() {
    let tmp = tempfile::tempdir().unwrap();
    // Generate a signing keypair to use as the functionary.
    let signed = signed_envelope_with_fresh_key(tmp.path());
    let layout_path = tmp.path().join("layout.json");

    let out = Command::new(bin())
        .args([
            "policy",
            "init",
            "--functionary-key",
            signed.pub_key_path.to_str().unwrap(),
            "--output",
            layout_path.to_str().unwrap(),
            "--step-name",
            "build-integration-test",
        ])
        .output()
        .expect("policy init should run");
    assert!(
        out.status.success(),
        "policy init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let body = std::fs::read_to_string(&layout_path).unwrap();
    assert!(body.contains("\"_type\": \"layout\""));
    assert!(body.contains("\"build-integration-test\""));
    let _ = signed.envelope_path;
}

#[test]
fn verify_with_matching_layout_passes() {
    let tmp = tempfile::tempdir().unwrap();
    let signed = signed_envelope_with_fresh_key(tmp.path());
    let layout_path = tmp.path().join("layout.json");

    // Generate layout bound to the same functionary key.
    let gen = Command::new(bin())
        .args([
            "policy",
            "init",
            "--functionary-key",
            signed.pub_key_path.to_str().unwrap(),
            "--output",
            layout_path.to_str().unwrap(),
        ])
        .output()
        .expect("policy init should run");
    assert!(gen.status.success());

    // Verify with the layout — should pass.
    let v = Command::new(bin())
        .args([
            "sbom",
            "verify",
            signed.envelope_path.to_str().unwrap(),
            "--layout",
            layout_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("verify should run");
    let code = v.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&v.stdout);
    assert_eq!(code, 0, "matching layout should pass; stdout={stdout}");
    assert!(stdout.contains("\"layout_satisfied\": true"));
}

#[test]
fn verify_with_mismatched_layout_fails_exit_three() {
    let tmp = tempfile::tempdir().unwrap();
    // Envelope signed by key A.
    let signed = signed_envelope_with_fresh_key(tmp.path());
    // Layout built from key B (different from A).
    let other_dir = tempfile::tempdir().unwrap();
    let other = signed_envelope_with_fresh_key(other_dir.path());
    let layout_path = tmp.path().join("mismatch.layout.json");

    let gen = Command::new(bin())
        .args([
            "policy",
            "init",
            "--functionary-key",
            other.pub_key_path.to_str().unwrap(),
            "--output",
            layout_path.to_str().unwrap(),
        ])
        .output()
        .expect("policy init should run");
    assert!(gen.status.success());

    let v = Command::new(bin())
        .args([
            "sbom",
            "verify",
            signed.envelope_path.to_str().unwrap(),
            "--layout",
            layout_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("verify should run");
    let code = v.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&v.stdout);
    assert_eq!(code, 3, "layout violation should exit 3; stdout={stdout}");
    assert!(stdout.contains("\"mode\": \"LayoutViolation\""));
}

#[test]
fn policy_init_rejects_invalid_expires_format() {
    let tmp = tempfile::tempdir().unwrap();
    let signed = signed_envelope_with_fresh_key(tmp.path());
    let layout_path = tmp.path().join("layout.json");

    let mut f = tempfile::NamedTempFile::new_in(tmp.path()).unwrap();
    f.write_all(b"placeholder").unwrap();

    let out = Command::new(bin())
        .args([
            "policy",
            "init",
            "--functionary-key",
            signed.pub_key_path.to_str().unwrap(),
            "--output",
            layout_path.to_str().unwrap(),
            "--expires",
            "garbage",
        ])
        .output()
        .expect("policy init should run");
    assert!(!out.status.success(), "garbage --expires should fail");
}
