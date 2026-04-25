//! Integration tests for the witness-v0.1 attestation format.
//!
//! Confirms that:
//! 1. mikebom can produce a signed witness-compatible envelope end-to-end
//!    (in-process — no Linux/eBPF needed)
//! 2. `mikebom sbom verify` consumes the resulting envelope
//! 3. The wire shape matches go-witness + the Vyom-Yadav network-trace
//!    attestor JSON schema (key naming, required fields)

#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::process::Command;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use mikebom_common::attestation::envelope::{
    canonical_json_bytes, dsse_pae, IdentityMetadata, KeyAlgorithm, Signature, SignedEnvelope,
    IN_TOTO_PAYLOAD_TYPE,
};
use mikebom_common::attestation::witness::{
    self, Collection, CollectionEntry, CommandRunAttestation, DigestSet, MaterialAttestation,
    NetworkConfig, NetworkSummary, NetworkTrace, NetworkTraceAttestation, PayloadConfig, Product,
    ProductAttestation, WitnessStatement, WitnessSubject,
};
use sigstore::crypto::SigningScheme;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mikebom")
}

fn sample_witness_statement() -> WitnessStatement {
    let mut material: MaterialAttestation = std::collections::BTreeMap::new();
    material.insert(
        "src/main.rs".to_string(),
        witness::sha256_digest("a".repeat(64)),
    );
    material.insert(
        "Cargo.toml".to_string(),
        witness::sha256_digest("b".repeat(64)),
    );

    let cmd = CommandRunAttestation {
        cmd: vec![
            "cargo".to_string(),
            "install".to_string(),
            "ripgrep".to_string(),
        ],
        stdout: String::new(),
        stderr: String::new(),
        exitcode: 0,
        processes: vec![],
    };

    let mut products: ProductAttestation = std::collections::BTreeMap::new();
    products.insert(
        "target/release/ripgrep".to_string(),
        Product {
            mime_type: "application/x-executable".to_string(),
            digest: witness::sha256_digest("c".repeat(64)),
        },
    );

    let network = NetworkTraceAttestation {
        network_trace: NetworkTrace {
            start_time: chrono::Utc::now(),
            end_time: chrono::Utc::now(),
            connections: vec![],
            summary: NetworkSummary {
                total_connections: 0,
                protocol_counts: std::collections::BTreeMap::new(),
                unique_hosts: vec![],
                unique_ips: vec![],
                total_bytes_sent: 0,
                total_bytes_received: 0,
            },
            config: NetworkConfig {
                observe_pids: vec![],
                observe_cgroups: vec![],
                observe_commands: vec![],
                observe_child_tree: true,
                proxy_port: 0,
                proxy_bind_ipv4: String::new(),
                payload: PayloadConfig::default(),
            },
        },
    };

    let now = chrono::Utc::now();
    WitnessStatement {
        statement_type: witness::STATEMENT_TYPE_V01.to_string(),
        subject: vec![WitnessSubject {
            name: "target/release/ripgrep".to_string(),
            digest: witness::sha256_digest("c".repeat(64)),
        }],
        predicate_type: witness::COLLECTION_PREDICATE_TYPE.to_string(),
        predicate: Collection {
            name: "cargo-install".to_string(),
            attestations: vec![
                CollectionEntry {
                    attestor_type: witness::MATERIAL_TYPE.to_string(),
                    attestation: serde_json::to_value(&material).unwrap(),
                    starttime: now,
                    endtime: now,
                },
                CollectionEntry {
                    attestor_type: witness::COMMAND_RUN_TYPE.to_string(),
                    attestation: serde_json::to_value(&cmd).unwrap(),
                    starttime: now,
                    endtime: now,
                },
                CollectionEntry {
                    attestor_type: witness::PRODUCT_TYPE.to_string(),
                    attestation: serde_json::to_value(&products).unwrap(),
                    starttime: now,
                    endtime: now,
                },
                CollectionEntry {
                    attestor_type: witness::NETWORK_TRACE_TYPE.to_string(),
                    attestation: serde_json::to_value(&network).unwrap(),
                    starttime: now,
                    endtime: now,
                },
            ],
        },
    }
}

fn sign_witness(stmt: &WitnessStatement) -> SignedEnvelope {
    let scheme = SigningScheme::ECDSA_P256_SHA256_ASN1;
    let signer = scheme.create_signer().unwrap();
    let keypair = signer.to_sigstore_keypair().unwrap();
    let public_pem = keypair.public_key_to_pem().unwrap();
    let payload = canonical_json_bytes(stmt).unwrap();
    let pae = dsse_pae(IN_TOTO_PAYLOAD_TYPE, &payload);
    let sig_bytes = signer.sign(&pae).unwrap();
    SignedEnvelope {
        payload_type: IN_TOTO_PAYLOAD_TYPE.to_string(),
        payload: B64.encode(&payload),
        signatures: vec![Signature {
            keyid: None,
            sig: B64.encode(&sig_bytes),
            identity: IdentityMetadata::PublicKey {
                public_key: public_pem,
                algorithm: KeyAlgorithm::EcdsaP256,
            },
        }],
    }
}

#[test]
fn cli_verifies_signed_witness_envelope() {
    let stmt = sample_witness_statement();
    let envelope = sign_witness(&stmt);

    let tmp = tempfile::tempdir().unwrap();
    let env_path = tmp.path().join("witness.dsse.json");
    std::fs::write(&env_path, serde_json::to_string(&envelope).unwrap()).unwrap();

    let out = Command::new(bin())
        .args([
            "sbom",
            "verify",
            env_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("mikebom should run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        code, 0,
        "witness envelope should verify; stdout={stdout}; stderr={stderr}"
    );
    assert!(stdout.contains("\"result\": \"pass\""));
}

#[test]
fn envelope_payload_decodes_to_statement_v01_with_collection_predicate() {
    let stmt = sample_witness_statement();
    let envelope = sign_witness(&stmt);
    let payload = B64.decode(&envelope.payload).unwrap();
    let decoded: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(decoded["_type"], "https://in-toto.io/Statement/v0.1");
    assert_eq!(
        decoded["predicateType"],
        "https://witness.testifysec.com/attestation-collection/v0.1"
    );
    let attestations = decoded["predicate"]["attestations"].as_array().unwrap();
    let types: Vec<&str> = attestations
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"https://witness.dev/attestations/material/v0.1"));
    assert!(types.contains(&"https://witness.dev/attestations/command-run/v0.1"));
    assert!(types.contains(&"https://witness.dev/attestations/product/v0.1"));
    assert!(types.contains(&"https://witness.dev/attestations/network-trace/v0.1"));

    // Collection entries use one-word `starttime` / `endtime`.
    let entry0 = &attestations[0];
    assert!(entry0.get("starttime").is_some());
    assert!(entry0.get("endtime").is_some());
    assert!(entry0.get("start_time").is_none());
    assert!(entry0.get("end_time").is_none());

    // The inner network-trace payload uses underscored `start_time` /
    // `end_time` per the Vyom-Yadav fork wire format.
    let nt_entry = attestations
        .iter()
        .find(|e| e["type"] == "https://witness.dev/attestations/network-trace/v0.1")
        .unwrap();
    let nt_body = &nt_entry["attestation"]["network_trace"];
    assert!(nt_body.get("start_time").is_some(), "network_trace.start_time missing");
    assert!(nt_body.get("end_time").is_some(), "network_trace.end_time missing");
}

#[test]
fn digestset_values_are_flat_algo_to_hex_maps() {
    // Regression fence: go-witness' DigestSet JSON is
    // {"sha256": "abc..."} — not a nested object with "algorithm"/"value"
    // keys. Make sure our serialization matches.
    let stmt = sample_witness_statement();
    let material_entry = stmt
        .predicate
        .attestations
        .iter()
        .find(|e| e.attestor_type == witness::MATERIAL_TYPE)
        .unwrap();
    let m = material_entry.attestation.as_object().unwrap();
    for (_, digest) in m {
        let digest_obj = digest.as_object().unwrap();
        // Key must be algorithm string; value must be hex string.
        for (alg, hex) in digest_obj {
            assert!(
                matches!(alg.as_str(), "sha256" | "sha1" | "sha512" | "md5"),
                "unexpected algorithm {alg}"
            );
            assert!(hex.is_string(), "digest value must be hex string, got {hex:?}");
        }
    }
}

#[test]
fn product_entry_has_mime_type_and_nested_digest() {
    let stmt = sample_witness_statement();
    let product_entry = stmt
        .predicate
        .attestations
        .iter()
        .find(|e| e.attestor_type == witness::PRODUCT_TYPE)
        .unwrap();
    let products = product_entry.attestation.as_object().unwrap();
    let (_, entry) = products.iter().next().unwrap();
    assert!(entry["mime_type"].is_string());
    assert!(entry["digest"].is_object());
}

#[test]
fn tampered_witness_payload_fails_verify() {
    let stmt = sample_witness_statement();
    let mut envelope = sign_witness(&stmt);
    // Mutate one byte of the payload.
    let mut payload = B64.decode(&envelope.payload).unwrap();
    payload[0] ^= 0xff;
    envelope.payload = B64.encode(&payload);

    let tmp = tempfile::tempdir().unwrap();
    let env_path = tmp.path().join("tampered.dsse.json");
    std::fs::write(&env_path, serde_json::to_string(&envelope).unwrap()).unwrap();

    let out = Command::new(bin())
        .args(["sbom", "verify", env_path.to_str().unwrap(), "--json"])
        .output()
        .expect("mikebom should run");
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 1 || code == 2,
        "tampered witness envelope should fail; got {code}"
    );
}

/// Non-test helper in the tests file — silences an unused-import lint
/// when DigestSet is used elsewhere but not here.
#[allow(dead_code)]
fn _uses(_: DigestSet) {}
