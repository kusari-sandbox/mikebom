# Quickstart: Keyless CycloneDX Signing

**Feature**: 778-keyless-cdx-sidecar

Two paths through this document. Most of the feature can be checked
**without** a signing identity; three things cannot. They are separated
so the identity-dependent work can be deferred without blocking the
rest.

---

## Part A — verifiable without a signing identity

### A1. Confirm the starting behaviour

Before the change, keyless CycloneDX is refused:

```sh
waybill --offline sbom scan --path mini --format cyclonedx-json \
        --sign --output out.cdx.json ; echo "exit=$?"
```

Expect a non-zero exit naming `--sign-key` as the alternative, and no
`out.cdx.json`. After the change, this command reaches the signing
attempt instead of being refused up front — it will still fail without
an identity, but the failure moves.

### A2. Confirm SPDX keyless is untouched

```sh
waybill --offline sbom scan --path mini --format spdx-2.3-json \
        --sign --output out.spdx.json
```

Its behaviour must be identical before and after. This is the control
for FR-010: it shares the signer being generalized.

### A3. Confirm static-key CycloneDX is untouched

```sh
waybill --offline sbom scan --path mini --format cyclonedx-json \
        --sign-key key.pk8.pem --output signed.cdx.json
jq '{root_sig: has("signature"), refs: (.externalReferences // [] | length)}' signed.cdx.json
```

Expect `root_sig: true` and **no** signature reference — the static-key
path keeps its in-document signature and gains nothing from this
feature.

### A4. Confirm unsigned byte-identity

Run the golden-file suite. Zero golden files may change (FR-011,
SC-004). Any churn means the change leaked outside the keyless path.

### A5. Confirm the reference's form, once emitting

Given a keyless-signed document, its reference must resolve after the
pair is moved:

```sh
mkdir elsewhere && cp signed.cdx.json signed.cdx.json.sig.bundle.json elsewhere/
cd elsewhere
jq -r '.externalReferences[] | select(.type=="attestation") | .url' signed.cdx.json
# must name a file that exists HERE, with no directory component
```

This is SC-009, and it is the check that distinguishes a relative name
from an absolute path that merely looked fine on the emitting host.

---

## Part B — requires a live signing identity

Nothing in Part B can be faked. Attempting to stub it produces a test
that passes while proving nothing.

### B1. End-to-end verification

```sh
export SIGSTORE_ID_TOKEN=$(cosign login --identity-token)
waybill sbom scan --path mini --format cyclonedx-json \
        --sign --output signed.cdx.json

cosign verify-blob \
    --bundle signed.cdx.json.sig.bundle.json \
    --certificate-identity '<your OIDC subject>' \
    --certificate-oidc-issuer '<your OIDC issuer>' \
    signed.cdx.json
```

### B2. Tamper detection

Alter any byte of `signed.cdx.json` and re-run B1's verify. It must
fail.

### B3. The retargeted keyless tests

```sh
WAYBILL_TEST_KEYLESS=1 cargo +stable test --test cisa_2026_signing
```

---

## Traps

**Do not canonicalize before signing.** The in-document signer in the
same file canonicalizes with `value = ""`, and reaching for that by
analogy is the single most likely way to get this wrong. The companion
artifact signs the bytes as written — that is what lets `cosign
verify-blob` work against the file with no preprocessing.

**Do not add a checksum to the reference.** The external reference
accepts hashes, and adding one looks like free tamper-detection. It is
circular: the artifact signs the document, so the document cannot
contain the artifact's hash.

**Do not inject the reference in the builder.** The builder does not
know the output path the reference must name. It belongs at the write
boundary, where the target is known and where the parse-modify-reserialize
pattern already exists.

**Do not remove the in-document signer's keyless refusal.** It stays
correct — keyless has no conformant in-document form. What changes is
that the CLI stops routing to it.
