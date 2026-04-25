//! DSSE envelope types + canonical-JSON / PAE helpers for feature 006.
//!
//! Feature 006 (SBOMit compliance suite) wraps the existing
//! [`super::statement::InTotoStatement`] in a DSSE envelope when a signing
//! identity is configured. The envelope carries one signature per identity
//! plus enough identity material (PEM key or Fulcio cert chain + optional
//! Rekor inclusion proof) for a downstream verifier to operate without any
//! out-of-band trust configuration.
//!
//! See `specs/006-sbomit-suite/contracts/attestation-envelope.md` for the
//! wire format and `data-model.md` for the full type model.
//!
//! The canonicalization helpers in this module produce byte-identical
//! output across runs so repeated signing of the same logical statement
//! yields byte-identical envelope bytes (FR-006: determinism).

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The DSSE payload type for in-toto v1 statements.
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Top-level DSSE envelope. Wraps a base64-encoded payload (the in-toto
/// Statement) with one or more signatures.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<Signature>,
}

/// A single signature inside a [`SignedEnvelope`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    /// Optional signature identifier — SHA-256 of the PEM public key or
    /// the DER-encoded Fulcio certificate. Verifiers may use it to pick
    /// the right key from a multi-signer envelope.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub keyid: Option<String>,
    /// Base64-encoded raw signature bytes.
    pub sig: String,
    pub identity: IdentityMetadata,
}

/// Identity metadata per FR-005: everything a verifier needs in-envelope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IdentityMetadata {
    /// Keyless flow: Fulcio-issued cert + chain + optional Rekor bundle.
    Certificate {
        /// PEM-encoded Fulcio cert.
        certificate: String,
        /// Any intermediate certs. Empty for sigstore public-good.
        #[serde(default)]
        chain: Vec<String>,
        /// Inclusion proof from the Rekor transparency log.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        rekor_bundle: Option<RekorBundle>,
    },
    /// Local-key flow: PEM verifying key + algorithm identifier.
    PublicKey {
        public_key: String,
        algorithm: KeyAlgorithm,
    },
}

/// Rekor inclusion proof embedded in a keyless envelope. Enables offline
/// verification of transparency-log inclusion.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RekorBundle {
    pub log_index: u64,
    pub log_id: String,
    pub integrated_time: i64,
    pub signed_entry_timestamp: String,
    pub inclusion_proof: InclusionProof,
}

/// Cryptographic inclusion proof against a Rekor checkpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub log_index: u64,
    pub tree_size: u64,
    pub root_hash: String,
    pub hashes: Vec<String>,
    pub checkpoint: String,
}

/// Signature algorithms accepted for local-key signing. Keyless flows
/// never use this — the cert's SPKI carries the algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAlgorithm {
    EcdsaP256,
    Ed25519,
    RsaPkcs1,
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::EcdsaP256 => "ecdsa-p256",
            Self::Ed25519 => "ed25519",
            Self::RsaPkcs1 => "rsa-pkcs1",
        };
        f.write_str(s)
    }
}

impl FromStr for KeyAlgorithm {
    type Err = UnknownKeyAlgorithm;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ecdsa-p256" => Ok(Self::EcdsaP256),
            "ed25519" => Ok(Self::Ed25519),
            "rsa-pkcs1" => Ok(Self::RsaPkcs1),
            other => Err(UnknownKeyAlgorithm(other.to_string())),
        }
    }
}

/// Error type for unrecognized [`KeyAlgorithm`] strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKeyAlgorithm(pub String);

impl fmt::Display for UnknownKeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown key algorithm: {} (accepted: ecdsa-p256, ed25519, rsa-pkcs1)",
            self.0
        )
    }
}

impl std::error::Error for UnknownKeyAlgorithm {}

/// Errors produced by envelope canonicalization.
#[derive(Debug, thiserror::Error)]
pub enum SerializationError {
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Serialize `t` to canonical JSON bytes — deterministic across runs.
///
/// Canonicalization rules (FR-006):
/// 1. Round-trip through `serde_json::Value` to get `serde_json::Map`
///    entries, then re-serialize with keys in sorted (BTreeMap) order.
/// 2. No whitespace between tokens (serde_json default compact mode).
/// 3. Floats use the default `serde_json` ryu representation.
pub fn canonical_json_bytes<T: Serialize>(t: &T) -> Result<Vec<u8>, SerializationError> {
    let value = serde_json::to_value(t)?;
    let sorted = sort_value(value);
    Ok(serde_json::to_vec(&sorted)?)
}

fn sort_value(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> =
                map.into_iter().map(|(k, v)| (k, sort_value(v))).collect();
            let mut out = serde_json::Map::with_capacity(sorted.len());
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_value).collect()),
        other => other,
    }
}

/// DSSE Pre-Authenticated Encoding per the DSSE v1 spec.
///
/// The encoding is `"DSSEv1 " + len(payload_type) + " " + payload_type + " " + len(payload) + " " + payload` where `len` is ASCII decimal. Signers sign — and verifiers verify — these exact bytes.
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let pt_bytes = payload_type.as_bytes();
    let mut out = Vec::with_capacity(
        7 + 20 + pt_bytes.len() + 20 + payload.len() + 4,
    );
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(pt_bytes.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(pt_bytes);
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> SignedEnvelope {
        SignedEnvelope {
            payload_type: IN_TOTO_PAYLOAD_TYPE.to_string(),
            payload: "eyJoZWxsbyI6IndvcmxkIn0".to_string(),
            signatures: vec![Signature {
                keyid: Some("sha256:abc".to_string()),
                sig: "MEUCIQ...".to_string(),
                identity: IdentityMetadata::PublicKey {
                    public_key: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
                        .to_string(),
                    algorithm: KeyAlgorithm::EcdsaP256,
                },
            }],
        }
    }

    #[test]
    fn envelope_round_trip() {
        let env = sample_envelope();
        let json = serde_json::to_string(&env).expect("serialize");
        let back: SignedEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(env, back);
    }

    #[test]
    fn identity_tagged_with_type_discriminant() {
        let env = sample_envelope();
        let json = serde_json::to_string(&env).expect("serialize");
        assert!(json.contains("\"type\":\"public_key\""));
    }

    #[test]
    fn certificate_variant_round_trips_with_rekor_bundle() {
        let identity = IdentityMetadata::Certificate {
            certificate: "-----BEGIN CERTIFICATE-----\n...".to_string(),
            chain: vec![],
            rekor_bundle: Some(RekorBundle {
                log_index: 123,
                log_id: "sha256:abc".to_string(),
                integrated_time: 1_700_000_000,
                signed_entry_timestamp: "MEY...".to_string(),
                inclusion_proof: InclusionProof {
                    log_index: 123,
                    tree_size: 1_000_000,
                    root_hash: "sha256:root".to_string(),
                    hashes: vec!["sha256:h1".to_string()],
                    checkpoint: "sigstore/1".to_string(),
                },
            }),
        };
        let json = serde_json::to_string(&identity).expect("serialize");
        let back: IdentityMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(identity, back);
    }

    #[test]
    fn key_algorithm_round_trips_via_fromstr_display() {
        for alg in [
            KeyAlgorithm::EcdsaP256,
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::RsaPkcs1,
        ] {
            let s = alg.to_string();
            let parsed: KeyAlgorithm = s.parse().expect("parse own display output");
            assert_eq!(alg, parsed);
        }
    }

    #[test]
    fn key_algorithm_rejects_unknown() {
        let err = "blake3-p256".parse::<KeyAlgorithm>().unwrap_err();
        assert!(err.to_string().contains("blake3-p256"));
    }

    #[test]
    fn key_algorithm_serde_kebab_case() {
        let alg = KeyAlgorithm::EcdsaP256;
        let json = serde_json::to_string(&alg).expect("serialize");
        assert_eq!(json, "\"ecdsa-p256\"");
        let back: KeyAlgorithm = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(alg, back);
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let mut a: BTreeMap<String, i32> = BTreeMap::new();
        a.insert("b".to_string(), 2);
        a.insert("a".to_string(), 1);
        a.insert("c".to_string(), 3);

        let bytes1 = canonical_json_bytes(&a).expect("canonicalize");
        let bytes2 = canonical_json_bytes(&a).expect("canonicalize");
        assert_eq!(bytes1, bytes2);

        let s = String::from_utf8(bytes1).expect("utf8");
        let pos_a = s.find("\"a\"").expect("a present");
        let pos_b = s.find("\"b\"").expect("b present");
        let pos_c = s.find("\"c\"").expect("c present");
        assert!(pos_a < pos_b && pos_b < pos_c, "keys sorted: {s}");
    }

    #[test]
    fn canonical_json_sorts_nested_keys() {
        let nested = serde_json::json!({
            "outer": { "z": 1, "a": 2, "m": { "y": 0, "b": 9 } }
        });
        let bytes = canonical_json_bytes(&nested).expect("canonicalize");
        let s = String::from_utf8(bytes).expect("utf8");
        let pos_a = s.find("\"a\"").expect("a present");
        let pos_m = s.find("\"m\"").expect("m present");
        let pos_z = s.find("\"z\"").expect("z present");
        assert!(pos_a < pos_m && pos_m < pos_z);
        let pos_b = s.find("\"b\":9").expect("b:9 present");
        let pos_y = s.find("\"y\":0").expect("y:0 present");
        assert!(pos_b < pos_y);
    }

    #[test]
    fn dsse_pae_matches_spec_example() {
        // DSSE v1 spec reference: the PAE of payload type "http://example.com/HelloWorld"
        // over payload "hello world" is the byte string:
        //   "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        let pae = dsse_pae("http://example.com/HelloWorld", b"hello world");
        assert_eq!(
            pae,
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
    }

    #[test]
    fn dsse_pae_empty_payload() {
        let pae = dsse_pae("application/vnd.in-toto+json", b"");
        assert_eq!(pae, b"DSSEv1 28 application/vnd.in-toto+json 0 ".to_vec());
    }
}
