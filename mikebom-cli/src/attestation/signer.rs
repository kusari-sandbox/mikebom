//! DSSE envelope signer — feature 006 US2.
//!
//! This module carries the signing-identity types + a typed error enum.
//! The real local-key / keyless sign flows land in Phase 4 (T031-T035);
//! this file ships the scaffolding that CLI argument parsing and the
//! unified sign entrypoint in [`serializer`](super::serializer) plug into.

use std::path::PathBuf;

use mikebom_common::attestation::envelope::KeyAlgorithm;

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

/// Unused-for-now tracking constant: the default algorithm we advertise
/// when we generate a PEM key internally. Reserved for the local-key
/// `sign_local` flow that lands in T031–T034.
pub(crate) const DEFAULT_KEY_ALGORITHM: KeyAlgorithm = KeyAlgorithm::EcdsaP256;

#[cfg(test)]
mod tests {
    use super::*;

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
}
