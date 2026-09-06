# Phase 0 Research: CycloneDX Signature Conformance

**Feature**: 777-cdx-signature-conformance
**Date**: 2026-09-05

All findings below were verified against source in this workspace or
against upstream schema documents, not inferred. Each records what was
checked so a reviewer can re-run it.

---

## R1 — Will the Rust gate reproduce the spurious `algorithm` failure seen during investigation?

**Decision**: No configuration needed. The gate can validate signed
documents with the default validator options.

**Rationale**: The spec's Context records that validating a conformant
JSF signature with Python's validator produces a spurious `oneOf`
failure on `signature.algorithm`, because JSON Schema Draft 7 does not
assert `format` by default and `"ES256"` therefore satisfies both the
`format: uri` branch and the enum branch. This raised the risk that the
Rust gate would reject correct output.

It will not. `jsonschema` 0.46.2 resolves its format-assertion default
by draft:

```rust
// jsonschema-0.46.2/src/compiler.rs:325
pub(crate) fn validates_formats_by_default(&self) -> bool {
    self.config.validate_formats().unwrap_or(matches!(
        self.draft,
        Draft::Draft4 | Draft::Draft6 | Draft::Draft7
    ))
}
```

Both relevant schemas declare draft-07 (`cyclonedx-1.6.json` and
`jsf-0.82.schema.json`), so format assertion is **on by default**. The
spec's assumption "Format assertion must be explicitly enabled in the
gate" is true of the Python investigation harness but not of the Rust
gate; no `should_validate_formats(true)` call is required, though adding
one is harmless and self-documenting.

**Alternatives considered**: Explicitly setting `should_validate_formats(true)`
— recommended anyway as an intent marker, since the default is
draft-dependent and a future schema bump to a 2020-12 draft would
silently flip it off.

---

## R2 — Does the existing schema harness actually catch the two defects?

**Decision**: It catches Defect 1 but **not** Defect 2. The harness must
stop stubbing the JSF schema before it can gate the signing path.

**Rationale**: The existing CDX validator installs a retriever that
replaces both external `$ref` targets with permissive stubs
(`waybill-cli/tests/sbom_user_metadata.rs`, `CdxStubRetriever`):

```rust
if s.ends_with("jsf-0.82.schema.json") {
    // jsf-0.82 is referenced via `#/definitions/signature` for
    // optional BOM signing. Waybill never emits signed BOMs so
    // the slot is structurally absent. Provide an inner
    // `definitions/signature` that's permissive (`{}`) so the
    // JSON-pointer dereference resolves.
    return Ok(serde_json::json!({ "definitions": { "signature": {} } }));
}
```

Two consequences:

1. The stub's stated premise — *"Waybill never emits signed BOMs"* — is
   false. `--sign-key` emits signed BOMs today. The comment records the
   same mistaken belief that produced Defect 1.
2. Because `definitions/signature` resolves to `{}`, **any** signature
   object validates. Pointing this harness at a signed document would
   catch the metadata placement (that constraint lives in the CDX schema
   itself, not behind the `$ref`) but would silently pass a malformed
   `publicKey`.

So FR-008 requires vendoring the real `jsf-0.82.schema.json` alongside
the existing CDX schema and serving it from the retriever. The SPDX stub
can remain as-is; it is unrelated to signing.

**Alternatives considered**: Enabling the crate's `resolve-http` feature
to fetch the JSF schema at test time — rejected: the workspace sets
`default-features = false` deliberately, and a network-dependent gate is
strictly worse than a vendored file.

---

## R3 — How is the JWK derived, and does it need new dependencies?

**Decision**: Derive `kty`/`crv`/`x`/`y` from the exported
SubjectPublicKeyInfo DER. **Zero new Cargo dependencies.**

**Rationale**: `SigStoreKeyPair` already exposes
`public_key_to_der() -> Result<Vec<u8>>` (SPKI DER) alongside the
`public_key_to_pem()` the current code uses. For a P-256 key the SPKI
subject-public-key bit string is the uncompressed EC point
`0x04 || X(32 bytes) || Y(32 bytes)`; `x` and `y` are those two halves
base64url-encoded without padding, per RFC 7518 §6.2.1.

`x509-parser = "0.16"` and `pem = "3"` are already direct dependencies of
`waybill-cli` (promoted during m089), and either can reach the SPKI bit
string without additions.

**Alternatives considered**:
- Using the `p256` crate's `EncodedPoint` directly — it is present
  transitively via sigstore and would be the most type-safe route, but
  it would need promoting to a direct dependency. Held as a fallback if
  SPKI handling proves awkward.
- Re-parsing the PEM the code already produces — strictly worse than
  asking for DER directly.

---

## R4 — How is the key type determined, and how expensive is FR-007?

**Decision**: Match on the existing enum. FR-007 and FR-019 are cheap
and structural, not analytical.

**Rationale**: The key type is already modelled as a sum type in the
signing library:

```rust
pub enum SigStoreKeyPair { ECDSA(ECDSAKeys), ED25519(..), RSA(..) }
pub enum ECDSAKeys { P256(..), P384(..) }
```

So "determine the key's actual type" (FR-007) is a match on
`SigStoreKeyPair`, and curve discrimination is a match on `ECDSAKeys`.
Accepting only `ECDSA(P256)` and refusing every other arm satisfies
FR-007 exactly, and deriving the declared algorithm from the same match
satisfies FR-019 by construction.

This also isolates the latent hazard the spec records. Today
`waybill-cli/src/sbom/signer.rs:276` hardcodes
`let algorithm = KeyAlgorithm::EcdsaP256;`, and the helper table maps
`RsaPkcs1` to an ECDSA signing scheme while labelling it `RS256`. Both
become unreachable once the algorithm is derived from a match that
rejects non-P256 arms; the dead `KeyAlgorithm` mapping helpers should be
narrowed rather than left as traps.

---

## R5 — Where does the keyless refusal belong so no file is written?

**Decision**: Reject at argument-validation time, before the scan runs.
The existing fail-close cleanup remains as a safety net.

**Rationale**: Two existing mechanisms make this cheap.

1. **Precedent for early rejection.** The CLI already rejects
   `--sign`/`--sign-key` combined with `--output -` at parse time
   (m221 FR-008a). The keyless-plus-CycloneDX combination is knowable
   from the same argument set (`args.sign` and the requested format
   list), so it belongs in the same place. Failing before the scan means
   the operator is not made to wait for a full scan before being told
   the request cannot be satisfied.
2. **Existing fail-close cleanup.** `scan_cmd.rs` maintains a cleanup
   tracker whose stated contract is: *"Every file we write goes into
   this list; on any signing failure we unlink each one before
   propagating the error, so consumers never see a partial `--output
   <path>` file."* This already satisfies FR-015 and the
   multiple-formats edge case even if a refusal were to fire later.

Rejecting early is therefore the primary route, with the cleanup tracker
as defence in depth rather than the mechanism being relied upon.

**Alternatives considered**: Raising the refusal inside
`sign_cdx_document_in_place` — simpler to locate but wastes a full scan
before failing, and produces a worse operator experience for a condition
knowable from the arguments alone.

---

## R6 — What existing assertions and documents encode the old shape?

**Decision**: Six code assertions and one operator-facing document.

**Rationale**: Enumerated by grep; each must move to the conformant
shape under FR-009, FR-010, and FR-018.

| Location | What it pins |
|----------|--------------|
| `signer.rs:552` | asserts no signature under `metadata` for the unsigned case |
| `signer.rs:572` | reads `/metadata/signature` |
| `signer.rs:574` | asserts `publicKey.pem` contains a PEM header |
| `signer.rs:648` | reads `/metadata/signature/value` |
| `signer.rs:657` | mutates the signature object under `metadata` |
| `cisa_2026_signing.rs:107,158,262,571` | four pointer assertions on `/metadata/signature` |
| `signer.rs:9` (module doc) | asserts the metadata slot is "native CDX 1.6" |
| `docs/cisa-2026-coverage.md:37` + Appendix B | states `metadata.signature` for both signing paths and gives `jq .metadata.signature signed.cdx.json` as the verification recipe |

The CISA matrix row is the largest documentation change: it describes
the slot three times, prescribes a verification command against it, and
claims both signing paths ship. Under this feature the keyless path
stops producing CycloneDX output at all, so the row's CycloneDX column
needs both a location correction and a scope correction.

---

## Summary of dependency impact

**Zero new Cargo dependencies.** One new vendored test fixture
(`jsf-0.82.schema.json`, ~4 KB) alongside the existing schema fixtures.
