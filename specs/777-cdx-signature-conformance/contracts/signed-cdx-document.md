# Contract: Signed CycloneDX Document

**Feature**: 777-cdx-signature-conformance
**Surface**: the emitted `cyclonedx-json` artifact when signing is enabled
**Consumers**: CycloneDX conformance validators, signature-aware SBOM
scoring tools, any consumer performing offline signature verification

---

## C1 — Signature placement

A signed document carries its signature at the document root.

```jsonc
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": { /* ... no `signature` property ... */ },
  "components": [ /* ... */ ],
  "signature": {
    "algorithm": "ES256",
    "publicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
    "value": "<base64url signature bytes, unpadded>"
  }
}
```

**Guarantees**

- `$.signature` is present when signing succeeded.
- `$.metadata.signature` is absent, always.
- The document validates against the unmodified upstream CycloneDX 1.6
  schema with the JSF schema resolved to its real definition.
- `$.signature.value` uses the base64url alphabet without padding, per
  the signature format's JWA binary-representation rule. This is not
  enforceable by schema validation (the field is typed as a plain
  string), so it is a contract obligation rather than a checked one.
  The detached SPDX sidecar is unaffected and keeps the standard
  alphabet its envelope format requires.

**Breaking-change notice**: consumers reading `$.metadata.signature`
find nothing after this change. That location was never valid; a
conforming consumer reads `$.signature`.

---

## C2 — Public key encoding

`$.signature.publicKey` is a JWK carrying exactly the parameters JSF
mandates for the key type.

For the supported key type (EC P-256):

| Field | Value |
|-------|-------|
| `kty` | `"EC"` |
| `crv` | `"P-256"` |
| `x` | base64url (unpadded) of the 32-byte X coordinate |
| `y` | base64url (unpadded) of the 32-byte Y coordinate |

**Guarantees**

- No `pem` or `algorithmHint` property is present; the JSF EC branch
  forbids additional properties.
- The coordinates belong to the key that produced `$.signature.value`.
- `$.signature.algorithm` is derived from this key, so the declared
  algorithm and the signing scheme cannot disagree.

---

## C3 — Verification contract

Verification is performed over a canonicalization of the document with
`$.signature.value` set to the empty string, per JSF §4.3.

**Guarantees**

- Verification succeeds against `$.signature.publicKey` for an
  unmodified document.
- Verification fails if any byte of document content outside the
  signature is altered.

**Consumer recipe** (replaces the previous `jq .metadata.signature`
recipe in the CISA coverage document):

```sh
jq .signature signed.cdx.json
```

---

## C4 — CLI refusal contract

| Invocation | Outcome |
|------------|---------|
| `--sign-key <path>` with a P-256 key, CycloneDX output | succeeds; document satisfies C1–C3 |
| `--sign-key <path>` with any non-P-256 key | exits non-zero, error names the unsupported key type, no output file |
| `--sign` (keyless), CycloneDX output requested | exits non-zero, error states the keyless path cannot produce a conformant CycloneDX signature and names `--sign-key` as the alternative, no output file |
| `--sign` (keyless), SPDX output only | succeeds, unchanged |
| no signing flag | succeeds; output byte-identical to pre-change |

**Guarantees**

- Refusals are decided from arguments before scanning where the
  condition is knowable from arguments alone, so no partial output can
  exist.
- A refusal never leaves a file on disk, including when several output
  formats were requested in one invocation.

---

## C5 — Unaffected surfaces

- Unsigned CycloneDX output: byte-identical.
- SPDX 2.3 and SPDX 3 signing: unchanged. Both use detached sidecars
  with no in-document signature slot, and neither is touched.
- The Sigstore bundle sidecar shapes: unchanged.
