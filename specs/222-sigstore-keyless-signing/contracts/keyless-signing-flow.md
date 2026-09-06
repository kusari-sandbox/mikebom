# Contract: Keyless signing end-to-end flow (feature 222 US2b)

> **SUPERSEDED IN PART BY MILESTONE 777.** The CDX-embedded Bundle
> canonical-bytes contract described below no longer applies: keyless
> signing of CycloneDX output is refused as of m777, because a Sigstore
> Bundle has no conformant JSON Signature Format representation and the
> emitted document failed CycloneDX 1.6 schema validation. The SPDX
> sidecar contract in this document is unaffected and remains current.
> See `specs/777-cdx-signature-conformance/`.


**Consumer surface**: `waybill-cli/src/attestation/signer.rs::sign_keyless_sbom`
**Called from**: `waybill-cli/src/sbom/signer.rs::sign_cdx_document_in_place`
+ `sign_spdx_bytes_to_dsse` (Keyless branch of the `SigningMode` match)

Documents the exact sequence for `--sign`, timing constraints, and
the interface between waybill and sigstore-rs 0.11.

---

## Preconditions

Before `sign_keyless_sbom()` is called:

1. CLI parse has completed. `SigningMode::Keyless{fulcio_url,
   rekor_url, rekor_timeout}` is constructed from `--sign` +
   `WAYBILL_FULCIO_URL` / `WAYBILL_REKOR_URL` /
   `WAYBILL_REKOR_TIMEOUT_SECS` env-var overrides.
2. m221 FR-008a rejection of `--sign + --output -` has already
   fired if applicable — this function only runs when `--output`
   is a durable path.
3. Scan has completed; caller holds the emit-ready canonical bytes
   of the SBOM document (CDX with `metadata.signature.value = ""`
   placeholder OR raw SPDX bytes).

## Signature

```rust
pub fn sign_keyless_sbom(
    canonical_bytes: &[u8],
    mode: &SigningMode,
    // Only the Keyless variant is valid; other variants panic (indicates caller bug).
) -> Result<KeylessSignSuccess, SigningError>
```

**Return value**: `KeylessSignSuccess` from `data-model.md`
containing the Bundle + the three FR-016 log fields.

## Sequence

Per Q3 clarification, FR-008 (late-bound OIDC), and R2/R3/R4 in
research.md:

```text
Step 1: OIDC token acquisition (LATE-BOUND per FR-008)
├── provider = OidcProvider::detect()
├── token = resolve_identity_token(&provider)?  // per oidc-provider-dispatch.md
├── if !token.in_validity_period() { return Err(OidcTokenError) }
└── oidc_provider_label = match provider {
        GitHubActions => "github-actions-ambient",
        Explicit      => "explicit-env",
        Interactive   => unreachable via resolve_identity_token; already Err'd
    }

Step 2: SigningContext construction (per R1-alt — vendored CTFE keys)
├── fulcio = FulcioClient::new(
│     Url::parse(fulcio_url).map_err(...)?,
│     TokenProvider::from(oidc_token.clone()),
│ )
├── rekor_cfg = RekorConfiguration::default()  // rekor.sigstore.dev
│     if rekor_url != "https://rekor.sigstore.dev" {
│         rekor_cfg.base_path = rekor_url.to_string();
│     }
├── ctfe_keyring = sigstore_trust_root::ctfe_keyring(rekor_url)?
│     // See waybill-cli/src/attestation/sigstore_trust_root.rs.
│     // Dispatches on rekor_url: sigstage.dev => STAGE_CTFE, else PROD_CTFE.
│     // DER SPKI parsed by sigstore::crypto::Keyring::new().
├── ctx = SigningContext::new(fulcio, rekor_cfg, ctfe_keyring)
│     // NOT ::production() — that requires sigstore-trust-root feature
│     // which transitively pulls aws-lc-rs (violates Constitution
│     // Principle I). See research.md §R1 for the audit result.
└── If any step fails → return Err(SigningError::CryptoError { detail: ... })
    (URL parse error, DER parse error, or Keyring construction error).

Step 3: Signing session + Fulcio cert issuance
├── session = ctx.blocking_signer(token)?
│     // Session::new internally posts the OIDC token to Fulcio and
│     // receives a short-lived (~10 min) x509 cert. Any HTTP failure
│     // or Fulcio-side rejection surfaces here.
├── fulcio_cert_subject = session
│     .fulcio_cert_chain()  // or equivalent accessor per sigstore-rs 0.11
│     .leaf()
│     .subject_alternative_name()
│     .first()
│     .ok_or(CryptoError { detail: "Fulcio cert has no SAN" })?
│     .to_string()
└── If session build fails → return Err(SigningError::FulcioError)

Step 4: Sign + Rekor upload
├── With rekor timeout wrapper (R4):
│     let (tx, rx) = std::sync::mpsc::channel();
│     std::thread::spawn(move || {
│         tx.send(session.sign(std::io::Cursor::new(canonical_bytes)))
│     });
│     let artifact = rx
│         .recv_timeout(rekor_timeout)
│         .map_err(|_| RekorError { detail: "sign timed out after {secs}s (Rekor inclusion-proof wait)" })?
│         .map_err(|e| classify_sign_error(e))?;  // maps sigstore-rs error class to SigningError variant
├── session.sign(...) internally:
│     ├── Generates ephemeral P-256 keypair.
│     ├── Signs canonical_bytes with the keypair.
│     ├── Uploads {cert, signature} to Rekor as a `hashedrekord` entry.
│     ├── Waits for Rekor inclusion-proof.
│     └── Returns SigningArtifact with the full Bundle payload.

Step 5: Extract Rekor log-index from Bundle
├── bundle = artifact.to_bundle();
├── rekor_log_index = bundle
│     .verification_material
│     .tlog_entries
│     .first()
│     .ok_or(RekorError { detail: "Bundle missing tlog_entries after successful sign — contract violation" })?
│     .log_index
│     // Rekor log-index is 1-based per Rekor API spec.
│     as u64;
└── If log_index == 0 → return Err(RekorError { detail: "log-index 0 is invalid (Rekor uses 1-based indexing)" })

Step 6: FR-016 INFO logging
├── tracing::info!(
│     rekor_log_index,
│     fulcio_cert_subject = %fulcio_cert_subject,
│     oidc_provider = oidc_provider_label,
│     "SBOM signed via Sigstore keyless"
│ );
└── Structured fields via tracing's field syntax — SREs can filter
    logs by any of the three fields.

Step 7: Return success
└── Ok(KeylessSignSuccess {
        bundle,
        rekor_log_index,
        fulcio_cert_subject,
        oidc_provider: oidc_provider_label,
    })
```

## Wire format guarantees

- **Bundle content-type**:
  `application/vnd.dev.sigstore.bundle+json;version=0.3` (per
  Sigstore Bundle spec v0.3, `sigstore::bundle::Bundle`'s
  `mediaType` field). Verified during T036-equivalent test by
  parsing the emitted output and asserting the field.
- **Bundle contents**:
  - `verificationMaterial.x509CertificateChain.certificates`:
    Fulcio leaf cert + intermediates (per FR-014).
  - `verificationMaterial.tlogEntries`: Rekor entry with
    `logIndex`, `integratedTime`, `logID`, `inclusionProof.hashes`.
  - `messageSignature.messageDigest.algorithm`: `SHA2_256`.
  - `messageSignature.messageDigest.digest`: base64 sha256 of
    canonical_bytes.
  - `messageSignature.signature`: base64 ECDSA signature.

sigstore-rs's `Bundle::to_bundle()` produces this shape verbatim;
consumers verifying with `cosign verify-blob --bundle <output>` see
the same wire format.

### CDX-embedded Bundle: canonical-bytes contract

**Decision**: For CDX outputs, waybill signs the canonical bytes of
the emitted document WITHOUT the `metadata.signature` slot populated,
then inserts the resulting Sigstore Bundle at `metadata.signature`
after signing. Verifiers reproduce the signed bytes by:

1. Parsing the received CDX JSON.
2. Extracting the `metadata.signature` Bundle object.
3. Removing the `metadata.signature` key from the parsed document
   (NOT setting `.value = ""` — remove the field entirely).
4. Re-serializing to canonical JSON (RFC 8785 JCS, matching m221's
   `canonical_json_bytes` helper at
   `waybill-common/src/attestation/envelope.rs`).
5. Verifying the Bundle's `messageSignature` against those bytes.

**Rationale**: Sigstore Bundle signs raw payload bytes; unlike JSF
(m221 US2a static-key), the Bundle envelope has no `.value` slot
that can be temporarily emptied and re-filled during
canonicalization. The "sign document-without-signature, embed
Bundle" convention is what SLSA provenance envelopes and in-toto
attestation Bundles use for the same slot-shape.

**Alternatives rejected**:
- **Sidecar-only for CDX (like SPDX)**: violates FR-003 (native
  in-document signature slot required).
- **Embed Bundle in `metadata.properties[waybill:sigstore-bundle]`
  instead of `metadata.signature`**: sidesteps the recursion issue
  but forfeits the CDX-native slot benefit and would trigger the
  m071 parity-extractor gate for a new `waybill:*` annotation
  (avoided per Q3).
- **JSF-style empty-value trick for the Bundle**: doesn't apply —
  Bundle isn't a value-slot, it's a full envelope.

**Implementation contract**:
- `sign_cdx_document_in_place()` (Keyless arm at T021) MUST:
  1. Serialize CDX to canonical bytes WITHOUT any
     `metadata.signature` field.
  2. Call `sign_keyless_sbom(canonical_bytes, ...)` — sigstore-rs
     signs those exact bytes.
  3. Insert the returned `Bundle` at `metadata.signature` in the
     mutated document.
  4. Emit the mutated document to disk.

- SPDX 2.3 + SPDX 3 do NOT face this problem — the Bundle sidecar
  is fully detached; the SPDX doc-on-disk equals the signed
  payload byte-for-byte.

- Integration test T024 MUST verify the round-trip works end-to-end
  against a real signed CDX (assert extraction + strip + re-canon +
  verify all produce Ok).

## Fail-close cleanup (m221 FR-009a inheritance)

Every `Err(SigningError::*)` return from this function propagates
back through `sign_cdx_document_in_place` /
`sign_spdx_bytes_to_dsse` to the CLI dispatch layer, which:

1. Unlinks any partial `--output <path>` file.
2. Logs `tracing::error!` with the specific `SigningError::*`
   variant name.
3. Returns `ExitCode::FAILURE` (non-zero exit).

**No silent unsigned fallback ever**. If Fulcio is down, Rekor is
down, OIDC provider rejects the token, network is partitioned, etc.
— the operator gets a non-zero exit + a diagnostic naming the
specific subsystem that failed. Existing test
`us2a_signing_failure_cleans_up_output_file` at
`waybill-cli/tests/cisa_2026_signing.rs` establishes the pattern;
US2b adds equivalent coverage for the Keyless mode (subprocess
run with `--sign` and unreachable Fulcio URL → assert non-zero
exit + no output file).

## Error → variant mapping

sigstore-rs 0.11's error types classify into our `SigningError`
variants via a `classify_sign_error()` helper:

| sigstore-rs error class | Maps to | Rationale |
|-------------------------|---------|-----------|
| `SigstoreError::FulcioClientError(_)` | `FulcioError` | Fulcio HTTP or cert-issuance failure. |
| `SigstoreError::RekorError(_)` | `RekorError` | Rekor HTTP or inclusion-proof failure. |
| `SigstoreError::PublicKeyOrCertificateError(_)` | `CryptoError` | Local ephemeral keypair or cert-parse failure. |
| `SigstoreError::IdentityTokenError(_)` | `OidcTokenError` | JWT parse or claim validation. |
| Timeout via `mpsc::RecvTimeoutError` | `RekorError` | Wrapper timeout per R4/FR-007. |
| Anything else | `CryptoError` | Generic "signing failed" catch-all with `detail:` preserving the sigstore-rs error string. |

## Non-goals for US2b

- **Interactive browser flow**: deferred per Q1. `Interactive`
  provider returns fail-close before reaching this function.
- **Verify command**: US2b ships sign-only; verify is handled by
  `cosign verify-blob --bundle` externally. Follow-up
  `waybill sbom verify --bundle <path>` is a v2 nice-to-have.
- **Rekor entry caching**: bundle contents are the SBOM's Rekor
  proof; no separate cache maintained.
- **Bundle signing without Rekor**: not supported. FR-007 makes
  Rekor mandatory; operators wanting a Rekor-free signature use
  `--sign-key <PEM>` (m221 US2a).
