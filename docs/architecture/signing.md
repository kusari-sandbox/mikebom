# DSSE Signing & Verification

Feature 006 (SBOMit compliance suite) added end-to-end signing and
verification of mikebom-produced attestations using
[sigstore-rs](https://github.com/sigstore/sigstore-rs). All envelopes
are DSSE-wrapped and carry enough identity material in-line for a
downstream verifier to operate without any out-of-band trust
configuration.

## Layers

### `mikebom_common::attestation::envelope`

The shared types + DSSE PAE / canonical-JSON helpers. Consumed by
both the CLI signer and verifier, plus any external Rust tool that
wants to interop with mikebom's envelope shape.

- `SignedEnvelope` — top-level DSSE shape: `payloadType`, base64
  `payload`, `signatures[]`
- `Signature` — per-signature `keyid`, `sig`, `IdentityMetadata`
- `IdentityMetadata::{Certificate, PublicKey}` — keyless (Fulcio cert
  + chain + optional Rekor bundle) vs. local-key (PEM + algorithm)
- `KeyAlgorithm::{EcdsaP256, Ed25519, RsaPkcs1}`
- `canonical_json_bytes()` — deterministic key-ordered JSON
- `dsse_pae()` — DSSE v1 Pre-Authenticated Encoding

### `mikebom-cli::attestation::signer`

- `SigningIdentity::{None, LocalKey, Keyless}`
- `OidcProvider::{GitHubActions, Explicit, Interactive}` + `detect()`
- `load_local_signer(path, passphrase_env)` — PEM → `SigStoreKeyPair`
- `sign_local(stmt, keypair)` — canonical payload + PAE + sign
- `sign_keyless(stmt, identity)` — scaffolded; full Fulcio/Rekor
  integration is a follow-on task
- `sign(stmt, identity)` — unified entrypoint; `Ok(None)` = unsigned

### `mikebom-cli::attestation::verifier`

- `parse_envelope()` — separates `NotSigned` / `MalformedEnvelope`
- `verify_signature()` — sigstore-rs `CosignVerificationKey` + DSSE PAE
- `verify_subjects()` — SHA-256 of on-disk bytes vs. subject digests
- `match_identity()` — x509 SAN match for keyless envelopes
- `verify_transparency_log()` — Rekor bundle presence check
- `FailureMode` (closed set of 9 variants) → exit codes 1/2/3

### `mikebom-cli::policy`

In-toto layout support.

- `layout::generate_starter_layout()` — minimal single-step layout
- `apply::verify_against_layout()` — functionary-keyid check

### `mikebom-cli::sbom::mutator`

RFC 6902 JSON Patch applier + provenance recorder for `sbom enrich`.

## Envelope shape

See [`specs/006-sbomit-suite/contracts/attestation-envelope.md`](../../specs/006-sbomit-suite/contracts/attestation-envelope.md)
for the full schema + synthetic-subject handling + determinism rules.

## Sigstore defaults

- Fulcio: `https://fulcio.sigstore.dev`
- Rekor: `https://rekor.sigstore.dev`

Overridable via `--fulcio-url` / `--rekor-url` for private sigstore
instances.

## Constitution Principle I audit

sigstore-rs 0.10 chosen over 0.13+ because the latter force-depends on
`aws-lc-rs` via the `cert` feature, violating the
"pure Rust, zero C" principle. With 0.10 + rustls-tls features we stay
C-clean on Linux targets (`cargo tree -p mikebom --target
x86_64-unknown-linux-gnu -e normal` confirms zero `openssl-sys`,
`libz-sys`, `aws-lc-rs`, `native-tls` hits).
