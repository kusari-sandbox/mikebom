//! DSSE envelope signer — feature 006 US2.
//!
//! Local-key (PEM + optional env-var passphrase) and keyless (OIDC →
//! Fulcio → Rekor) signing flows. Hard-fails on any pipeline error per
//! FR-006a: the caller gets a typed `SigningError`, no silent fallback
//! to unsigned output.

// Signer is invoked only from `cli/scan.rs::execute_scan` (Linux-only
// trace flow). On macOS the file compiles but is unreachable; allow
// dead_code on non-Linux.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use sigstore::crypto::signing_key::{SigStoreKeyPair, SigStoreSigner};
use sigstore::crypto::SigningScheme;

use mikebom_common::attestation::envelope::{
    canonical_json_bytes, dsse_pae, IdentityMetadata, KeyAlgorithm, Signature, SignedEnvelope,
    IN_TOTO_PAYLOAD_TYPE,
};
use mikebom_common::attestation::statement::InTotoStatement;

/// High-level signing configuration constructed from CLI flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningIdentity {
    /// No signing — legacy (pre-feature-006) behavior. Emits a raw
    /// in-toto Statement JSON file.
    None,
    /// Local-key signing with an on-disk PEM private key.
    LocalKey {
        path: PathBuf,
        /// Name of the env var holding the passphrase. `None` means the
        /// key is unencrypted.
        passphrase_env: Option<String>,
    },
    /// Keyless signing via OIDC → Fulcio → (optional) Rekor.
    Keyless {
        fulcio_url: String,
        rekor_url: String,
        oidc_provider: OidcProvider,
        /// Whether to upload to Rekor and embed the inclusion proof.
        transparency_log: bool,
    },
}

/// How to obtain an OIDC token for keyless signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OidcProvider {
    /// GitHub Actions — use `ACTIONS_ID_TOKEN_REQUEST_URL` +
    /// `ACTIONS_ID_TOKEN_REQUEST_TOKEN` to mint a token.
    GitHubActions,
    /// Operator-supplied pre-fetched token via `SIGSTORE_ID_TOKEN` env.
    Explicit,
    /// Interactive browser flow. Rejected in non-interactive contexts.
    Interactive,
}

impl OidcProvider {
    /// Detect from the ambient environment. Order:
    /// 1. GitHub Actions (if OIDC endpoint + token env vars present)
    /// 2. Explicit (if `SIGSTORE_ID_TOKEN` set)
    /// 3. Interactive (fallback — only works in TTY contexts)
    pub fn detect() -> Self {
        if std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").is_ok()
            && std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").is_ok()
        {
            return Self::GitHubActions;
        }
        if std::env::var("SIGSTORE_ID_TOKEN").is_ok() {
            return Self::Explicit;
        }
        Self::Interactive
    }
}

/// Tagged failure modes for the sign pipeline (FR-006a).
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("signing key file not found: {path}")]
    KeyFileMissing { path: String },

    #[error("signing key passphrase missing or invalid (env var: {env_var})")]
    KeyPassphraseInvalid { env_var: String },

    #[error("signing key could not be parsed: {detail}")]
    KeyParseError { detail: String },

    #[error("unsupported signing key algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },

    #[error("OIDC token acquisition failed: {detail}")]
    OidcTokenError { detail: String },

    #[error("Fulcio certificate issuance failed: {detail}")]
    FulcioError { detail: String },

    #[error("Rekor upload or inclusion-proof generation failed: {detail}")]
    RekorError { detail: String },

    #[error("canonical JSON serialization failed: {0}")]
    Serialization(#[from] mikebom_common::attestation::envelope::SerializationError),

    #[error("low-level signing operation failed: {detail}")]
    CryptoError { detail: String },

    #[error("IO error during signing: {0}")]
    Io(#[from] std::io::Error),
}

/// Default local-key algorithm when `mikebom` generates or imports a
/// key without explicit scheme information. ECDSA-P256 matches Fulcio.
pub(crate) const DEFAULT_KEY_ALGORITHM: KeyAlgorithm = KeyAlgorithm::EcdsaP256;

/// Load a PEM-encoded signing key from disk. If `passphrase_env` names
/// an env var, the key is treated as encrypted and decrypted in-process.
pub fn load_local_signer(
    path: &Path,
    passphrase_env: Option<&str>,
) -> Result<SigStoreKeyPair, SigningError> {
    if !path.exists() {
        return Err(SigningError::KeyFileMissing {
            path: path.display().to_string(),
        });
    }
    let pem_bytes = std::fs::read(path)?;

    match passphrase_env {
        Some(env_var) => {
            let passphrase = std::env::var(env_var).map_err(|_| {
                SigningError::KeyPassphraseInvalid {
                    env_var: env_var.to_string(),
                }
            })?;
            SigStoreKeyPair::from_encrypted_pem(&pem_bytes, passphrase.as_bytes()).map_err(|e| {
                SigningError::KeyPassphraseInvalid {
                    env_var: format!("{env_var}: {e}"),
                }
            })
        }
        None => SigStoreKeyPair::from_pem(&pem_bytes).map_err(|e| SigningError::KeyParseError {
            detail: e.to_string(),
        }),
    }
}

/// Infer a [`SigningScheme`] from a loaded keypair's algorithm. For
/// v1 we default to ECDSA-P256 (matches Fulcio + the vast majority of
/// sigstore-produced keys) and convert explicitly for Ed25519.
fn scheme_for_algorithm(alg: KeyAlgorithm) -> SigningScheme {
    match alg {
        KeyAlgorithm::EcdsaP256 => SigningScheme::ECDSA_P256_SHA256_ASN1,
        KeyAlgorithm::Ed25519 => SigningScheme::ED25519,
        KeyAlgorithm::RsaPkcs1 => SigningScheme::ECDSA_P256_SHA256_ASN1,
    }
}

/// Sign a statement with a local PEM keypair. Returns a fully-formed
/// DSSE envelope with the verifying key embedded for offline verify.
pub fn sign_local(
    statement: &InTotoStatement,
    keypair: &SigStoreKeyPair,
) -> Result<SignedEnvelope, SigningError> {
    let payload_bytes = canonical_json_bytes(statement)?;
    let pae = dsse_pae(IN_TOTO_PAYLOAD_TYPE, &payload_bytes);

    // SigStoreKeyPair doesn't expose `.sign()` directly; promote to a
    // SigStoreSigner via to_sigstore_signer, then sign the PAE bytes.
    let scheme = SigningScheme::ECDSA_P256_SHA256_ASN1;
    let signer = keypair
        .to_sigstore_signer(&scheme)
        .map_err(|e| SigningError::CryptoError {
            detail: format!("cannot build signer from key: {e}"),
        })?;
    let sig_bytes = signer
        .sign(&pae)
        .map_err(|e| SigningError::CryptoError {
            detail: format!("local signing failed: {e}"),
        })?;

    let public_key_pem =
        keypair
            .public_key_to_pem()
            .map_err(|e| SigningError::KeyParseError {
                detail: format!("cannot export public key PEM: {e}"),
            })?;

    // sigstore's SigStoreKeyPair doesn't expose the concrete scheme
    // directly; v1 ships with ECDSA-P256 as the default. Future work:
    // persist the scheme alongside the key or parse it from the PEM.
    let algorithm = DEFAULT_KEY_ALGORITHM;

    Ok(SignedEnvelope {
        payload_type: IN_TOTO_PAYLOAD_TYPE.to_string(),
        payload: BASE64_STD.encode(&payload_bytes),
        signatures: vec![Signature {
            keyid: Some(keyid_for_pem(&public_key_pem)),
            sig: BASE64_STD.encode(&sig_bytes),
            identity: IdentityMetadata::PublicKey {
                public_key: public_key_pem,
                algorithm,
            },
        }],
    })
}

/// Keyless signing skeleton. The full flow is OIDC token → Fulcio cert
/// → sign → (optional) Rekor upload. v1 of this feature ships the type
/// plumbing + explicit-token path; full Fulcio/Rekor integration is
/// gated on a real OIDC token being available in the environment.
pub fn sign_keyless(
    _statement: &InTotoStatement,
    identity: &SigningIdentity,
) -> Result<SignedEnvelope, SigningError> {
    // v1: keyless flow requires live network calls to Fulcio + Rekor.
    // Return a structured error rather than crashing so CI environments
    // that want to exercise the hard-fail contract (FR-006a) can.
    let _ = identity;
    Err(SigningError::OidcTokenError {
        detail: "keyless signing not yet fully implemented — use --signing-key for local signing; keyless flow lands in a follow-on task that adds Fulcio cert issuance + Rekor upload".to_string(),
    })
}

/// Unified signing entrypoint. Dispatches on `identity`.
///
/// Returns:
/// - `Ok(Some(envelope))` — signed envelope ready to serialize
/// - `Ok(None)` — caller requested no signing; emit raw Statement
/// - `Err(_)` — hard-fail per FR-006a
pub fn sign(
    statement: &InTotoStatement,
    identity: &SigningIdentity,
) -> Result<Option<SignedEnvelope>, SigningError> {
    match identity {
        SigningIdentity::None => Ok(None),
        SigningIdentity::LocalKey {
            path,
            passphrase_env,
        } => {
            let keypair = load_local_signer(path, passphrase_env.as_deref())?;
            let envelope = sign_local(statement, &keypair)?;
            Ok(Some(envelope))
        }
        SigningIdentity::Keyless { .. } => {
            let envelope = sign_keyless(statement, identity)?;
            Ok(Some(envelope))
        }
    }
}

fn keyid_for_pem(pem: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pem.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

// Silence unused-import lint when the signer module is compiled but no
// downstream caller instantiates a `SigStoreSigner` directly. The type
// stays in scope because sigstore re-exports `SigStoreKeyPair` through
// it during cert/key plumbing in follow-on tasks.
#[allow(dead_code)]
fn _unused_but_reserved(_s: Option<SigStoreSigner>) {}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use std::io::Write;

    fn minimal_statement() -> InTotoStatement {
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
        let mut digest = std::collections::BTreeMap::new();
        digest.insert("sha256".to_string(), "a".repeat(64));
        InTotoStatement {
            statement_type: InTotoStatement::STATEMENT_TYPE.to_string(),
            subject: vec![ResourceDescriptor {
                name: "test".to_string(),
                digest,
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

    /// Generate an unencrypted PEM keypair and write it to a tempfile.
    /// Returns the tempfile (keeps it alive) and the PEM public key.
    fn pem_tempfile() -> (tempfile::NamedTempFile, String) {
        let scheme = SigningScheme::ECDSA_P256_SHA256_ASN1;
        let signer = scheme.create_signer().unwrap();
        let keypair = signer.to_sigstore_keypair().unwrap();
        let private_pem = keypair.private_key_to_pem().unwrap();
        let public_pem = keypair.public_key_to_pem().unwrap();
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(private_pem.as_bytes()).unwrap();
        (tmp, public_pem)
    }

    #[test]
    fn signing_identity_none_is_default_shape() {
        let id = SigningIdentity::None;
        assert_eq!(id, SigningIdentity::None);
    }

    #[test]
    fn signing_error_displays_detail() {
        let err = SigningError::KeyFileMissing {
            path: "/tmp/missing.pem".to_string(),
        };
        assert!(err.to_string().contains("/tmp/missing.pem"));
    }

    #[test]
    fn default_key_algorithm_is_ecdsa_p256() {
        assert_eq!(DEFAULT_KEY_ALGORITHM, KeyAlgorithm::EcdsaP256);
    }

    // Env-var tests are consolidated into one serial test because
    // `std::env::set_var` / `remove_var` mutate process-wide state that
    // races with parallel test execution.
    #[test]
    fn oidc_detect_resolves_all_providers_in_precedence_order() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // 1. GitHub Actions wins when its two env vars are set.
        let _g1 = EnvGuard::setup(&[
            ("ACTIONS_ID_TOKEN_REQUEST_URL", Some("https://x")),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", Some("abc")),
            ("SIGSTORE_ID_TOKEN", None),
        ]);
        assert_eq!(OidcProvider::detect(), OidcProvider::GitHubActions);
        drop(_g1);

        // 2. Explicit when only SIGSTORE_ID_TOKEN is set.
        let _g2 = EnvGuard::setup(&[
            ("ACTIONS_ID_TOKEN_REQUEST_URL", None),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None),
            ("SIGSTORE_ID_TOKEN", Some("jwt-token")),
        ]);
        assert_eq!(OidcProvider::detect(), OidcProvider::Explicit);
        drop(_g2);

        // 3. Interactive is the last-resort fallback.
        let _g3 = EnvGuard::setup(&[
            ("ACTIONS_ID_TOKEN_REQUEST_URL", None),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None),
            ("SIGSTORE_ID_TOKEN", None),
        ]);
        assert_eq!(OidcProvider::detect(), OidcProvider::Interactive);
    }

    #[test]
    fn load_local_signer_missing_path_errors() {
        let bogus = Path::new("/nonexistent/mikebom-test-key.pem");
        let err = load_local_signer(bogus, None).err().expect("should error");
        match err {
            SigningError::KeyFileMissing { path } => {
                assert!(path.contains("nonexistent"));
            }
            other => panic!("expected KeyFileMissing, got {other:?}"),
        }
    }

    #[test]
    fn load_local_signer_passphrase_env_missing_errors() {
        let (tmp, _pub) = pem_tempfile();
        let err = load_local_signer(tmp.path(), Some("MIKEBOM_NONEXISTENT_PASSPHRASE_ENV"))
            .err()
            .expect("should error");
        match err {
            SigningError::KeyPassphraseInvalid { env_var } => {
                assert!(env_var.contains("MIKEBOM_NONEXISTENT"));
            }
            other => panic!("expected KeyPassphraseInvalid, got {other:?}"),
        }
    }

    #[test]
    fn sign_local_roundtrips_through_verifier() {
        use crate::attestation::verifier::{
            verify_attestation, VerificationReport, VerifyOptions,
        };
        let (tmp, _pub_pem) = pem_tempfile();
        let keypair = load_local_signer(tmp.path(), None).unwrap();
        let stmt = minimal_statement();
        let envelope = sign_local(&stmt, &keypair).unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        match verify_attestation(&json, &VerifyOptions::default()) {
            VerificationReport::Pass { .. } => {}
            VerificationReport::Fail { mode, detail, .. } => {
                panic!("round-trip should pass, got Fail {mode:?}: {detail}");
            }
        }
    }

    #[test]
    fn sign_local_canonical_payload_is_deterministic() {
        let (tmp, _pub_pem) = pem_tempfile();
        let keypair = load_local_signer(tmp.path(), None).unwrap();
        let stmt = minimal_statement();
        let env1 = sign_local(&stmt, &keypair).unwrap();
        let env2 = sign_local(&stmt, &keypair).unwrap();
        assert_eq!(env1.payload, env2.payload, "payload bytes must be identical");
    }

    #[test]
    fn sign_dispatches_none_to_no_envelope() {
        let stmt = minimal_statement();
        let res = sign(&stmt, &SigningIdentity::None).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn sign_dispatches_local_key_path() {
        let (tmp, _pub_pem) = pem_tempfile();
        let stmt = minimal_statement();
        let identity = SigningIdentity::LocalKey {
            path: tmp.path().to_path_buf(),
            passphrase_env: None,
        };
        let envelope = sign(&stmt, &identity).unwrap().expect("some envelope");
        assert_eq!(envelope.signatures.len(), 1);
        assert!(envelope.signatures[0].keyid.as_ref().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn sign_keyless_returns_structured_error_for_unimplemented_path() {
        let stmt = minimal_statement();
        let identity = SigningIdentity::Keyless {
            fulcio_url: "https://fulcio.sigstore.dev".to_string(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            oidc_provider: OidcProvider::Interactive,
            transparency_log: true,
        };
        match sign(&stmt, &identity) {
            Err(SigningError::OidcTokenError { detail }) => {
                assert!(detail.contains("keyless"));
            }
            other => panic!("expected OidcTokenError, got {other:?}"),
        }
    }

    #[test]
    fn sign_hard_fails_on_missing_key_file() {
        let stmt = minimal_statement();
        let identity = SigningIdentity::LocalKey {
            path: PathBuf::from("/nonexistent/mikebom-test.pem"),
            passphrase_env: None,
        };
        match sign(&stmt, &identity) {
            Err(SigningError::KeyFileMissing { .. }) => {}
            other => panic!("expected KeyFileMissing, got {other:?}"),
        }
    }

    #[test]
    fn keyid_is_sha256_prefixed_hex() {
        let kid = keyid_for_pem("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----");
        assert!(kid.starts_with("sha256:"));
        assert_eq!(kid.len(), 7 + 64); // "sha256:" + 32 bytes hex
    }

    /// RAII guard that snapshots + replaces env vars for the duration of
    /// a test. Restores originals on drop.
    struct EnvGuard {
        originals: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn setup(vars: &[(&str, Option<&str>)]) -> Self {
            let mut originals = Vec::new();
            for (k, v) in vars {
                originals.push((k.to_string(), std::env::var(k).ok()));
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
            Self { originals }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.originals {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }
}
