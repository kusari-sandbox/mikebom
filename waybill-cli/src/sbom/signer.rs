//! Feature 221 US2a — SBOM-envelope-level signing.
//!
//! Extends the milestone-006 attestation-envelope signing primitives
//! (`crate::attestation::signer`, `waybill_common::attestation::envelope`)
//! to cover SBOM documents themselves rather than in-toto statements.
//!
//! Two emission paths:
//! - **CycloneDX**: sign in-place. The signature JSON object lands at
//!   the document root (`$.signature`) — the slot CDX 1.6 actually
//!   defines for a document-level enveloped signature. Milestone 777
//!   moved it there: it previously sat at `metadata.signature`, which
//!   the schema rejects outright, since `metadata` is
//!   `additionalProperties: false` and declares no `signature`
//!   property. Uses the JSF (JSON Signature Format,
//!   draft-cyberphone-jsf-00) empty-value trick: canonicalize with
//!   `value = ""`, sign the canonical bytes, fill the actual
//!   base64url signature back into `value`.
//! - **SPDX 2.3 / SPDX 3**: emit a companion DSSE envelope alongside
//!   the primary artifact at `<output>.sig.json`. Neither SPDX
//!   version has a native in-document envelope-signature slot.
//!
//! **Scope of this file** (US2a): static-key path only
//! (`SigningMode::StaticKey`). Sigstore keyless (`SigningMode::Keyless`)
//! is US2b — completing the m006 `sign_keyless()` scaffold with real
//! Fulcio/Rekor calls is deferred to a follow-up session.
//!
//! **Fail-close** per FR-009a: every fallible operation returns a
//! typed `SbomSigningError`; the CLI layer at `scan_cmd.rs` maps
//! this to exit code 1 with the offending output file unlinked
//! (matches cosign / gpg / notary conventions — no silent unsigned
//! fallback).

#![allow(dead_code)] // Some helpers land ahead of their US2b consumers.

use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
// CycloneDX/JSF signature values use the base64url alphabet without
// padding (JSF defers the binary representation to JWA / RFC 7518).
// BASE64_STD above stays in use for the DSSE sidecar, whose envelope
// format mandates the standard alphabet — do not merge these two.
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use serde::Serialize;
use sigstore::crypto::signing_key::SigStoreKeyPair;
use sigstore::crypto::SigningScheme;
use thiserror::Error;

use waybill_common::attestation::envelope::{
    canonical_json_bytes, dsse_pae, IdentityMetadata, KeyAlgorithm, Signature, SignedEnvelope,
};

use crate::attestation::signer::{load_local_signer, SigningError};

/// The DSSE `payloadType` used for SBOM sidecars. Not an in-toto
/// statement; we use a distinct type URI so downstream tooling can
/// tell an SBOM signature apart from an attestation signature.
pub const SBOM_DSSE_PAYLOAD_TYPE: &str = "application/vnd.waybill.sbom+json";

/// High-level signing configuration, mirrors the CLI parse result.
/// Constructed once at CLI parse time and consumed by the emit path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningMode {
    /// Neither `--sign` nor `--sign-key` set (the default). Emit is
    /// byte-identical to pre-m221 output per FR-009.
    Unsigned,
    /// `--sign-key <PATH>` — static key material (PEM file). US2a.
    StaticKey {
        key_ref: PathBuf,
        /// Env var holding the passphrase for encrypted keys.
        /// Defaults to `WAYBILL_SIGN_KEY_PASSPHRASE` when the operator
        /// omitted `--sign-key-passphrase-env`.
        passphrase_env: String,
    },
    /// `--sign` — Sigstore keyless (US2b, milestone 222). OIDC token
    /// acquisition is late-bound per FR-008 (resolved at signing time,
    /// not CLI parse time). Endpoints are env-var-overridable via
    /// `WAYBILL_FULCIO_URL` / `WAYBILL_REKOR_URL` /
    /// `WAYBILL_REKOR_TIMEOUT_SECS`.
    Keyless {
        fulcio_url: String,
        rekor_url: String,
        rekor_timeout: std::time::Duration,
    },
}

impl SigningMode {
    /// True when a signature should be produced. Cheap check that
    /// avoids the CLI layer having to reason about specific variants.
    pub fn is_enabled(&self) -> bool {
        !matches!(self, SigningMode::Unsigned)
    }
}

/// The output of `sign_sbom_bytes`. Two shapes today; US2b will add
/// `Keyless(SigstoreBundle)`.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum SbomSignatureEnvelope {
    /// JSF (JSON Signature Format) object — the CDX-native shape,
    /// destined for the root `signature` slot of an emitted CDX
    /// document.
    StaticKeyJsf(JsfSignature),
    // Reserved for US2b:
    // Keyless(SigstoreBundle),
}

/// Return type for `sign_sbom_bytes_to_sidecar`. SPDX outputs get a
/// separate on-disk sidecar (SPDX has no in-document signature slot);
/// the shape depends on the `SigningMode` variant.
///
/// Milestone 222 US2b — extends the m221 US2a `SignedEnvelope`-only
/// return to accommodate the Sigstore keyless flow's `Bundle` output.
#[derive(Debug)]
pub enum Sidecar {
    /// DSSE envelope wrapping the SPDX bytes as payload — m221 US2a
    /// static-key flow. Sidecar filename `.sig.json`.
    Dsse(SignedEnvelope),
    /// Sigstore Bundle — m222 US2b keyless flow. Sidecar filename
    /// `.sig.bundle.json` per FR-004.
    SigstoreBundle(Box<sigstore::bundle::Bundle>),
}

impl Sidecar {
    /// Serialize the sidecar's inner payload to pretty JSON bytes ready
    /// to write to disk. Both DSSE + Bundle serialize via serde_json.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        match self {
            Sidecar::Dsse(envelope) => serde_json::to_vec_pretty(envelope),
            Sidecar::SigstoreBundle(bundle) => serde_json::to_vec_pretty(bundle.as_ref()),
        }
    }

    /// Filename suffix appended to the primary SPDX output path. DSSE
    /// gets `.sig.json`; Sigstore Bundle gets `.sig.bundle.json` per
    /// FR-004.
    pub fn sidecar_suffix(&self) -> &'static str {
        match self {
            Sidecar::Dsse(_) => ".sig.json",
            Sidecar::SigstoreBundle(_) => ".sig.bundle.json",
        }
    }

    /// Human-readable variant name for INFO log messages.
    pub fn kind_label(&self) -> &'static str {
        match self {
            Sidecar::Dsse(_) => "DSSE",
            Sidecar::SigstoreBundle(_) => "Sigstore Bundle",
        }
    }
}

/// A JSF (JSON Signature Format, draft-cyberphone-jsf-00) signature
/// object. Wire shape follows the CycloneDX 1.6 `signature` schema.
///
/// For US2a we ship a minimal but conformant shape. Fields:
/// - `algorithm`: JWS-style algorithm identifier (`"ES256"` for
///   ECDSA-P256, `"EdDSA"` for Ed25519).
/// - `publicKey`: JWK-shaped public key so verifiers can validate
///   offline without out-of-band key distribution.
/// - `value`: base64url-encoded signature bytes.
#[derive(Clone, Debug, Serialize)]
pub struct JsfSignature {
    pub algorithm: String,
    #[serde(rename = "publicKey")]
    pub public_key: JsfPublicKey,
    /// Base64url-encoded signature bytes. During canonicalization for
    /// signing, this MUST be `""` (empty string) per JSF §4.3 to
    /// preserve determinism.
    pub value: String,
}

/// JWK public key material, per JSON Signature Format.
///
/// Milestone 777 landed the JWK parameter split that milestone 221
/// deferred. The previous shape (`{ pem, algorithmHint }`) is not
/// merely unconventional but schema-invalid: JSF's elliptic-curve
/// branch is `additionalProperties: false` and requires exactly
/// `kty`, `crv`, `x`, `y`, so both former fields were rejected.
///
/// Only P-256 is produced; see `resolve_signing_key`. The PEM form is
/// dropped rather than relocated — the JWK carries the same key
/// material, and preserving the PEM under a vendor-prefixed property
/// would violate the standards-native-first rule (Constitution
/// Principle V).
#[derive(Clone, Debug, Serialize)]
pub struct JsfPublicKey {
    /// Key type. `"EC"` for the supported curve.
    pub kty: &'static str,
    /// Curve name. `"P-256"`.
    pub crv: &'static str,
    /// EC point X coordinate, base64url without padding (RFC 7518 §6.2.1).
    pub x: String,
    /// EC point Y coordinate, base64url without padding.
    pub y: String,
}

impl SigningMode {
    /// The sidecar suffix this mode will produce, knowable *before*
    /// signing runs.
    ///
    /// Milestone 778 needs this because the CycloneDX document records
    /// where its companion artifact lives, and that reference must be
    /// part of the content that gets signed (FR-013). Deriving the name
    /// from the resulting [`Sidecar`] would be too late — the document
    /// is already signed by then. Returns `None` for `Unsigned`, which
    /// produces no sidecar at all.
    ///
    /// Kept adjacent to [`Sidecar::sidecar_suffix`] so the two cannot
    /// drift silently; the write path cross-checks them.
    pub fn sidecar_suffix(&self) -> Option<&'static str> {
        match self {
            SigningMode::Unsigned => None,
            SigningMode::StaticKey { .. } => Some(".sig.json"),
            SigningMode::Keyless { .. } => Some(".sig.bundle.json"),
        }
    }
}

/// Tagged failure modes for the SBOM-signing pipeline. Every variant
/// is user-actionable; the CLI diagnostic surfaces the enum variant
/// name so operators know exactly which subsystem failed.
#[derive(Debug, Error)]
pub enum SbomSigningError {
    #[error("could not load signing key: {0}")]
    KeyLoadFailed(#[from] SigningError),

    #[error(
        "unsupported signing key type: {algorithm}. CycloneDX signing \
         supports ECDSA P-256 only; the signature format requires a \
         key-type-specific public-key representation, and emitting one \
         that does not match the key in use would produce a document \
         that misdescribes its own signature. Re-run with a P-256 key."
    )]
    AlgorithmUnsupported { algorithm: String },

    #[error("low-level signing operation failed: {detail}")]
    SignFailed { detail: String },

    #[error("canonical JSON serialization failed: {0}")]
    Serialization(#[from] waybill_common::attestation::envelope::SerializationError),

    #[error("serde_json error while constructing signature envelope: {0}")]
    JsonEncoding(#[from] serde_json::Error),

    #[error("cannot export public key PEM for signature envelope: {detail}")]
    PublicKeyExportFailed { detail: String },

    #[error(
        "unsupported operation: {operation} \
         (US2a covers static-key JSF/DSSE only; keyless is US2b)"
    )]
    NotImplemented { operation: String },
}

// ---------------------------------------------------------------------------
// Top-level signing entrypoints
// ---------------------------------------------------------------------------

/// Remove any pre-existing signature before re-signing (FR-006).
///
/// Clears the conformant root slot *and* the pre-milestone-777
/// `metadata.signature` location. Clearing the legacy slot matters
/// because a document signed by an older waybill carries its signature
/// there; leaving it would produce a document with two conflicting
/// signature claims, one of them in a slot the schema rejects.
fn strip_existing_signature(doc: &mut serde_json::Value) {
    if let Some(root) = doc.as_object_mut() {
        root.remove("signature");
    }
    if let Some(meta) = doc.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        meta.remove("signature");
    }
}

/// Sign the CycloneDX document's root `signature` slot **in place**.
///
/// Reads the root `signature` slot, sets its `value` to `""`,
/// canonicalizes the entire document via `canonical_json_bytes`, signs
/// the canonical bytes with the key referenced by `mode`, and writes
/// the actual base64 signature back into `value`.
///
/// When `mode == SigningMode::Unsigned`, this is a no-op — the passed
/// `Value` is returned unchanged, guaranteeing FR-009 byte-identity.
pub fn sign_cdx_document_in_place(
    doc: &mut serde_json::Value,
    mode: &SigningMode,
) -> Result<(), SbomSigningError> {
    if !mode.is_enabled() {
        return Ok(());
    }

    // Milestone 777 US3 (FR-014) — the Sigstore keyless path cannot
    // currently produce a conformant CycloneDX signature, so it is
    // refused here as well as at the CLI.
    //
    // The keyless flow embeds a whole Sigstore bundle as the signature
    // payload. That is not a JSON Signature Format `signer` object, so
    // relocating it to the conformant root slot would be strictly worse
    // than leaving it where it was: the schema does validate the root
    // slot, and a bundle there fails it. Expressing the bundle through
    // JSF's certificate-path and key-identifier properties may be
    // possible, but determining that requires exercising the path
    // against a live signing identity and is tracked as follow-up work.
    //
    // Refusing in the library as well as the CLI keeps FR-001/FR-002
    // unconditionally true for every document this function returns,
    // rather than true only for callers who happen to route through the
    // CLI guard.
    //
    // Milestone 778 note: this guard STAYS. m778 gives keyless CycloneDX
    // a working path, but that path is a detached sidecar — it routes
    // around this function rather than through it. This remains the
    // *in-document* signer, and keyless still has no conformant
    // in-document form, so refusing here is still correct for any caller
    // that reaches it directly.
    if matches!(mode, SigningMode::Keyless { .. }) {
        return Err(SbomSigningError::NotImplemented {
            operation: "Sigstore keyless signing of CycloneDX documents \
                        (the bundle payload has no conformant JSON Signature \
                        Format representation; use --sign-key for CycloneDX, \
                        or keyless with an SPDX format, which signs to a \
                        detached sidecar)"
                .to_string(),
        });
    }

    let keypair = load_key(mode)?;
    // Derived from the key material, never assumed (FR-007, FR-019).
    let resolved = resolve_signing_key(&keypair)?;

    // Re-signing must not leave residue in either slot (FR-006).
    strip_existing_signature(doc);

    // JSF empty-value trick: populate the root signature slot with the
    // fully-shaped envelope EXCEPT `value = ""`, canonicalize, sign,
    // then fill the real base64url value in.
    let placeholder = JsfSignature {
        algorithm: resolved.jwa_alg.to_string(),
        public_key: resolved.public_key.clone(),
        value: String::new(),
    };

    // Insert the placeholder at the document root. CDX 1.6 declares
    // `signature` there; `metadata` is `additionalProperties: false`
    // and rejects it (milestone 777).
    let placeholder_json = serde_json::to_value(&placeholder)?;
    let root = doc
        .as_object_mut()
        .ok_or_else(|| SbomSigningError::SignFailed {
            detail: "CDX document root is not a JSON object; cannot insert signature slot"
                .to_string(),
        })?;
    root.insert("signature".to_string(), placeholder_json);

    let canonical = canonical_json_bytes(doc)?;
    let signer = keypair
        .to_sigstore_signer(&resolved.scheme)
        .map_err(|e| SbomSigningError::SignFailed {
            detail: format!("cannot build signer from key: {e}"),
        })?;
    let sig_bytes = signer.sign(&canonical).map_err(|e| SbomSigningError::SignFailed {
        detail: format!("signature computation failed: {e}"),
    })?;
    // base64url per JSF/JWA — NOT BASE64_STD, which the DSSE sidecar
    // below still requires.
    let sig_b64 = BASE64_URL.encode(&sig_bytes);

    // Fill in the real value.
    let root = doc
        .as_object_mut()
        .expect("document root object still present");
    let sig = root
        .get_mut("signature")
        .and_then(|s| s.as_object_mut())
        .expect("signature inserted above still present");
    sig.insert("value".to_string(), serde_json::Value::String(sig_b64));

    Ok(())
}

/// Produce a signature sidecar for the given emitted-SBOM bytes.
/// Returns `Ok(None)` when `mode == Unsigned` (no sidecar file written).
///
/// **Format-neutral.** Despite its original SPDX-only name (renamed in
/// milestone 778), nothing here is SPDX-specific: the caller hands over
/// whatever bytes it just wrote and gets back a detached signature over
/// exactly those bytes. Both the SPDX formats and — as of milestone 778
/// — the keyless CycloneDX path use it.
///
/// The payload is the caller's bytes verbatim. Do NOT canonicalize
/// before calling: a detached signature is verified against the file as
/// it sits on disk, so any transformation here would force every
/// verifier to reproduce it first. That is the distinction from
/// `sign_cdx_document_in_place`, which signs a canonical form because
/// its signature lives *inside* the document it covers.
///
/// - `SigningMode::StaticKey{..}` → `Sidecar::Dsse(SignedEnvelope)`
///   with `payloadType = SBOM_DSSE_PAYLOAD_TYPE`.
/// - `SigningMode::Keyless{..}` → `Sidecar::SigstoreBundle(Bundle)`
///   with the raw SPDX bytes as the signed payload (detached; the
///   SPDX doc on disk equals the signed bytes byte-for-byte per the
///   `contracts/keyless-signing-flow.md` CDX/SPDX contract split).
///
/// Milestone 222 US2b renamed the entry from `sign_spdx_bytes_to_dsse`
/// to reflect the Sidecar shape shift; a thin backwards-compatible
/// alias is preserved for the m221 US2a call site until the CLI
/// migrates to the new return type.
pub fn sign_sbom_bytes_to_sidecar(
    sbom_bytes: &[u8],
    mode: &SigningMode,
) -> Result<Option<Sidecar>, SbomSigningError> {
    if !mode.is_enabled() {
        return Ok(None);
    }

    // Milestone 222 US2b — Sigstore keyless dispatch.
    if let SigningMode::Keyless {
        fulcio_url,
        rekor_url,
        rekor_timeout,
    } = mode
    {
        let success = crate::attestation::signer::sign_keyless_sbom(
            sbom_bytes,
            fulcio_url,
            rekor_url,
            *rekor_timeout,
        )
        .map_err(|e| SbomSigningError::SignFailed {
            detail: format!("Sigstore keyless sign failed: {e}"),
        })?;
        return Ok(Some(Sidecar::SigstoreBundle(Box::new(success.bundle))));
    }

    let keypair = load_key(mode)?;
    // The DSSE sidecar path is deliberately untouched by milestone 777
    // (FR-013): SPDX has no in-document signature slot, and the DSSE
    // envelope format mandates standard-alphabet base64 for its payload
    // and signature. `scheme` is what `signing_scheme_for` returned for
    // the hardcoded P-256 algorithm before that helper was removed, and
    // `algorithm` still rides in the envelope's identity metadata — both
    // preserved verbatim so the emitted sidecar is byte-identical.
    let algorithm = KeyAlgorithm::EcdsaP256;
    let scheme = SigningScheme::ECDSA_P256_SHA256_ASN1;
    let public_key_pem = export_public_key_pem(&keypair)?;

    let pae = dsse_pae(SBOM_DSSE_PAYLOAD_TYPE, sbom_bytes);
    let signer = keypair
        .to_sigstore_signer(&scheme)
        .map_err(|e| SbomSigningError::SignFailed {
            detail: format!("cannot build signer from key: {e}"),
        })?;
    let sig_bytes = signer.sign(&pae).map_err(|e| SbomSigningError::SignFailed {
        detail: format!("signature computation failed: {e}"),
    })?;

    Ok(Some(Sidecar::Dsse(SignedEnvelope {
        payload_type: SBOM_DSSE_PAYLOAD_TYPE.to_string(),
        payload: BASE64_STD.encode(sbom_bytes),
        signatures: vec![Signature {
            keyid: None,
            sig: BASE64_STD.encode(&sig_bytes),
            identity: IdentityMetadata::PublicKey {
                public_key: public_key_pem,
                algorithm,
            },
        }],
    })))
}

/// Milestone 221 US2a legacy alias — returns just the DSSE envelope,
/// or `Err(NotImplemented)` for the m222 US2b Keyless variant (that
/// path must go through `sign_sbom_bytes_to_sidecar` for the correct
/// Bundle return type). Kept during the m222 transition; delete once
/// the CLI's SPDX sidecar-writer is fully on `Sidecar`.
pub fn sign_spdx_bytes_to_dsse(
    spdx_bytes: &[u8],
    mode: &SigningMode,
) -> Result<Option<SignedEnvelope>, SbomSigningError> {
    match sign_sbom_bytes_to_sidecar(spdx_bytes, mode)? {
        None => Ok(None),
        Some(Sidecar::Dsse(env)) => Ok(Some(env)),
        Some(Sidecar::SigstoreBundle(_)) => Err(SbomSigningError::NotImplemented {
            operation: "sign_spdx_bytes_to_dsse called with SigningMode::Keyless — \
                        Sigstore keyless signing produces a Bundle sidecar, not DSSE. \
                        Callers must migrate to sign_sbom_bytes_to_sidecar."
                .to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_key(mode: &SigningMode) -> Result<SigStoreKeyPair, SbomSigningError> {
    match mode {
        SigningMode::Unsigned => Err(SbomSigningError::NotImplemented {
            operation: "load_key called on Unsigned mode".to_string(),
        }),
        SigningMode::StaticKey {
            key_ref,
            passphrase_env,
        } => {
            let passphrase_env_ref = if std::env::var(passphrase_env).is_ok() {
                Some(passphrase_env.as_str())
            } else {
                None
            };
            let keypair = load_local_signer(key_ref, passphrase_env_ref)?;
            Ok(keypair)
        }
        SigningMode::Keyless { .. } => Err(SbomSigningError::NotImplemented {
            operation: "load_key called on Keyless mode — keyless sign path does not load \
                        a local key; it uses an ephemeral Fulcio-issued cert. Callers must \
                        dispatch on SigningMode::Keyless before reaching load_key."
                .to_string(),
        }),
    }
}

/// Everything the CycloneDX signing path needs about the operator's
/// key, derived from the key itself rather than assumed.
struct ResolvedSigningKey {
    scheme: SigningScheme,
    /// JWA identifier (RFC 7518) that JSF's `algorithm` enum accepts.
    jwa_alg: &'static str,
    public_key: JsfPublicKey,
}

/// Determine the key type from the supplied key material and produce
/// the matching signing scheme, declared algorithm, and JWK.
///
/// Milestone 777 (FR-007, FR-019). Before this, the algorithm was
/// hardcoded to `ES256` regardless of the key supplied, and the
/// mapping helpers it replaced could label an RSA key `RS256` while
/// signing it with an ECDSA scheme. Deriving all three from one match
/// makes that disagreement unrepresentable rather than merely
/// unreached.
///
/// P-256 only, deliberately. JSF requires a key-type-specific public
/// key representation, and its `algorithm` enum further requires
/// explicit `Ed*` names rather than the generic `"EdDSA"` the old
/// mapping emitted — so the other arms were not merely unimplemented,
/// they were wrong. Refusing is the honest behaviour.
fn resolve_signing_key(
    keypair: &SigStoreKeyPair,
) -> Result<ResolvedSigningKey, SbomSigningError> {
    use sigstore::crypto::signing_key::ecdsa::ECDSAKeys;

    match keypair {
        SigStoreKeyPair::ECDSA(ECDSAKeys::P256(_)) => {
            let der = keypair.public_key_to_der().map_err(|e| {
                SbomSigningError::PublicKeyExportFailed {
                    detail: format!("cannot export SubjectPublicKeyInfo DER: {e}"),
                }
            })?;
            Ok(ResolvedSigningKey {
                scheme: SigningScheme::ECDSA_P256_SHA256_ASN1,
                jwa_alg: "ES256",
                public_key: p256_jwk_from_spki(&der)?,
            })
        }
        SigStoreKeyPair::ECDSA(ECDSAKeys::P384(_)) => {
            Err(SbomSigningError::AlgorithmUnsupported {
                algorithm: "ECDSA P-384".to_string(),
            })
        }
        SigStoreKeyPair::ED25519(_) => Err(SbomSigningError::AlgorithmUnsupported {
            algorithm: "Ed25519".to_string(),
        }),
        SigStoreKeyPair::RSA(_) => Err(SbomSigningError::AlgorithmUnsupported {
            algorithm: "RSA".to_string(),
        }),
    }
}

/// Build a JSF/JWK public key from a P-256 SubjectPublicKeyInfo DER.
///
/// The SPKI's subject public key is an uncompressed EC point —
/// `0x04 || X(32) || Y(32)` — and `x`/`y` are those halves encoded
/// base64url without padding per RFC 7518 §6.2.1.
fn p256_jwk_from_spki(der: &[u8]) -> Result<JsfPublicKey, SbomSigningError> {
    use x509_parser::prelude::FromDer;

    let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(der).map_err(|e| {
        SbomSigningError::PublicKeyExportFailed {
            detail: format!("cannot parse SubjectPublicKeyInfo: {e}"),
        }
    })?;

    let point: &[u8] = &spki.subject_public_key.data;
    // 1 tag byte + two 32-byte coordinates.
    if point.len() != 65 || point[0] != 0x04 {
        return Err(SbomSigningError::PublicKeyExportFailed {
            detail: format!(
                "expected a 65-byte uncompressed P-256 point (0x04 || X || Y), \
                 got {} byte(s) starting with 0x{:02x}",
                point.len(),
                point.first().copied().unwrap_or(0)
            ),
        });
    }

    Ok(JsfPublicKey {
        kty: "EC",
        crv: "P-256",
        x: BASE64_URL.encode(&point[1..33]),
        y: BASE64_URL.encode(&point[33..65]),
    })
}

fn export_public_key_pem(keypair: &SigStoreKeyPair) -> Result<String, SbomSigningError> {
    keypair
        .public_key_to_pem()
        .map_err(|e| SbomSigningError::PublicKeyExportFailed {
            detail: e.to_string(),
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;
    use serde_json::json;
    use sigstore::crypto::signing_key::SigStoreKeyPair;
    use sigstore::crypto::SigningScheme;
    use tempfile::NamedTempFile;

    /// Generate an ephemeral P-256 keypair, write its PEM to a
    /// tempfile, and return both the tempfile (private-key PEM on
    /// disk) and the loaded `SigStoreKeyPair` for downstream
    /// verification with the same key material.
    fn ephemeral_p256_pem_file() -> (NamedTempFile, SigStoreKeyPair) {
        let scheme = SigningScheme::ECDSA_P256_SHA256_ASN1;
        let signer = scheme.create_signer().expect("create_signer");
        let keypair = signer.to_sigstore_keypair().expect("to_sigstore_keypair");
        let pem = keypair.private_key_to_pem().expect("private_key_to_pem");
        let f = NamedTempFile::new().expect("tempfile");
        std::fs::write(f.path(), pem).expect("write pem");
        (f, keypair)
    }

    #[test]
    fn signing_mode_is_enabled_reflects_variant_m221() {
        assert!(!SigningMode::Unsigned.is_enabled());
        assert!(SigningMode::StaticKey {
            key_ref: PathBuf::from("/tmp/x.pem"),
            passphrase_env: "WAYBILL_SIGN_KEY_PASSPHRASE".to_string(),
        }
        .is_enabled());
    }

    #[test]
    fn signing_mode_keyless_is_enabled_m222() {
        let mode = SigningMode::Keyless {
            fulcio_url: "https://fulcio.sigstore.dev".to_string(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            rekor_timeout: std::time::Duration::from_secs(30),
        };
        assert!(mode.is_enabled());
    }

    #[test]
    fn load_key_rejects_keyless_mode_m222() {
        let mode = SigningMode::Keyless {
            fulcio_url: "https://fulcio.sigstore.dev".to_string(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            rekor_timeout: std::time::Duration::from_secs(30),
        };
        match load_key(&mode) {
            Err(SbomSigningError::NotImplemented { .. }) => {}
            Err(other) => panic!("expected NotImplemented, got {other:?}"),
            Ok(_) => panic!("expected keyless mode to not go through load_key"),
        }
    }

    #[test]
    fn sign_cdx_document_in_place_noop_when_unsigned_m221() {
        let mut doc = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"timestamp": "2026-07-29T00:00:00Z"},
        });
        let baseline = doc.clone();
        sign_cdx_document_in_place(&mut doc, &SigningMode::Unsigned)
            .expect("no-op signing returns Ok");
        assert_eq!(doc, baseline, "Unsigned mode MUST leave document byte-identical");
        assert!(
            doc.get("metadata").and_then(|m| m.get("signature")).is_none(),
            "no signature slot should be inserted in Unsigned mode"
        );
    }

    #[test]
    fn sign_cdx_document_in_place_populates_signature_slot_m221() {
        let (pem_file, _keypair) = ephemeral_p256_pem_file();
        let mut doc = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"timestamp": "2026-07-29T00:00:00Z"},
            "components": [],
        });
        let mode = SigningMode::StaticKey {
            key_ref: pem_file.path().to_path_buf(),
            passphrase_env: "WAYBILL_UNSET_TEST_ENV_M221".to_string(),
        };
        sign_cdx_document_in_place(&mut doc, &mode).expect("static-key sign");

        // Milestone 777: the signature lives at the document root, and
        // the public key is a JWK. Both were previously asserted in
        // their schema-invalid forms by this very test.
        assert!(
            doc.pointer("/metadata/signature").is_none(),
            "signature MUST NOT be written under metadata (FR-002)"
        );
        let sig = doc.pointer("/signature").expect("root signature slot exists");
        assert_eq!(sig["algorithm"], "ES256");
        let pk = &sig["publicKey"];
        assert_eq!(pk["kty"], "EC", "JSF requires a JWK key type (FR-003)");
        assert_eq!(pk["crv"], "P-256");
        assert!(
            pk["x"].as_str().is_some_and(|v| !v.is_empty())
                && pk["y"].as_str().is_some_and(|v| !v.is_empty()),
            "EC coordinates must be present (FR-003)"
        );
        assert!(
            pk.get("pem").is_none() && pk.get("algorithmHint").is_none(),
            "JSF's EC branch forbids additional properties (FR-003)"
        );
        let value = sig["value"].as_str().unwrap();
        assert!(!value.is_empty(), "signature value must be non-empty");
        assert!(
            !value.contains('+') && !value.contains('/') && !value.contains('='),
            "signature value must use the base64url alphabet without padding (FR-020)"
        );
    }

    /// Milestone 777 replaced `sign_cdx_document_in_place_rejects_missing_metadata_m221`.
    ///
    /// That test asserted signing FAILS on a document with no
    /// `metadata` object — a requirement that existed only because the
    /// signature was being inserted into `metadata`. The signature now
    /// goes at the document root, so `metadata` is irrelevant to
    /// signing and the old expectation is obsolete rather than merely
    /// relocated. Pinning the new behaviour so the dependency cannot
    /// creep back.
    #[test]
    fn sign_cdx_document_in_place_no_longer_requires_metadata_m777() {
        let (pem_file, _keypair) = ephemeral_p256_pem_file();
        let mut doc = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [],
        });
        let mode = SigningMode::StaticKey {
            key_ref: pem_file.path().to_path_buf(),
            passphrase_env: "WAYBILL_UNSET_TEST_ENV_M221".to_string(),
        };
        sign_cdx_document_in_place(&mut doc, &mode)
            .expect("signing must not depend on a metadata object");
        assert!(
            doc.pointer("/signature").is_some(),
            "signature lands at the root regardless of metadata"
        );
    }

    #[test]
    fn sign_spdx_bytes_to_dsse_noop_when_unsigned_m221() {
        let result = sign_spdx_bytes_to_dsse(b"any", &SigningMode::Unsigned)
            .expect("no-op returns Ok");
        assert!(result.is_none(), "Unsigned mode returns None");
    }

    #[test]
    fn sign_spdx_bytes_to_dsse_wraps_payload_m221() {
        let (pem_file, _keypair) = ephemeral_p256_pem_file();
        let mode = SigningMode::StaticKey {
            key_ref: pem_file.path().to_path_buf(),
            passphrase_env: "WAYBILL_UNSET_TEST_ENV_M221".to_string(),
        };
        let payload = br#"{"spdxVersion":"SPDX-2.3"}"#.to_vec();
        let env = sign_spdx_bytes_to_dsse(&payload, &mode)
            .expect("sign ok")
            .expect("envelope present");

        assert_eq!(env.payload_type, SBOM_DSSE_PAYLOAD_TYPE);
        let decoded = BASE64_STD.decode(&env.payload).expect("base64 decode");
        assert_eq!(decoded, payload);
        assert_eq!(env.signatures.len(), 1);
        assert!(!env.signatures[0].sig.is_empty());
    }

    #[test]
    fn sign_cdx_signature_verifies_with_matching_pubkey_m221() {
        use sigstore::crypto::verification_key::CosignVerificationKey;
        use sigstore::crypto::Signature as SigstoreSig;

        // Full round-trip: sign a CDX doc, extract the signature
        // value, reset the slot to "", recanonicalize, and verify
        // against the ephemeral pubkey.
        let (pem_file, keypair) = ephemeral_p256_pem_file();
        let mut doc = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"timestamp": "2026-07-29T00:00:00Z"},
            "components": [{"name": "example", "type": "library"}],
        });
        let mode = SigningMode::StaticKey {
            key_ref: pem_file.path().to_path_buf(),
            passphrase_env: "WAYBILL_UNSET_TEST_ENV_M221".to_string(),
        };
        sign_cdx_document_in_place(&mut doc, &mode).expect("sign ok");

        let sig_b64 = doc
            .pointer("/signature/value")
            .and_then(|v| v.as_str())
            .expect("signature value populated")
            .to_string();
        // base64url on the CycloneDX side (FR-020). The DSSE sidecar
        // test below still decodes with BASE64_STD — the two paths use
        // different alphabets on purpose and must not be unified.
        let sig_bytes = BASE64_URL.decode(&sig_b64).expect("base64url decode");

        // Reset value → recanonicalize (matches sign-side JCS input).
        let root = doc.as_object_mut().unwrap();
        let sig = root.get_mut("signature").unwrap().as_object_mut().unwrap();
        sig.insert("value".to_string(), json!(""));
        let canonical = canonical_json_bytes(&doc).expect("canonicalize");

        let pubkey_pem = keypair.public_key_to_pem().expect("pub pem");
        let vk = CosignVerificationKey::from_pem(
            pubkey_pem.as_bytes(),
            &SigningScheme::ECDSA_P256_SHA256_ASN1,
        )
        .expect("verification key");
        vk.verify_signature(SigstoreSig::Raw(&sig_bytes), &canonical)
            .expect("signature must verify against matching pubkey");

        // Mutation of any byte in the canonical payload must flip verify.
        let mut mutated = canonical.clone();
        // Flip a byte in the middle of the payload to avoid altering
        // structural JSON like `{}` at the boundaries.
        let mid = mutated.len() / 2;
        mutated[mid] ^= 0x01;
        assert!(
            vk.verify_signature(SigstoreSig::Raw(&sig_bytes), &mutated).is_err(),
            "mutation of signed bytes MUST cause verify to fail"
        );
    }
}
