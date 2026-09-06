# Phase 1 Data Model: CycloneDX Signature Conformance

**Feature**: 777-cdx-signature-conformance
**Date**: 2026-09-05

This feature changes the shape and placement of one emitted structure
and narrows one input domain. No persistent state, no storage, no
schema migration.

---

## E1 — Document signature (emitted)

The enveloped signature covering a canonicalized form of the emitted
CycloneDX document.

**Placement**

| | Before | After |
|---|---|---|
| JSON pointer | `/metadata/signature` | `/signature` |
| Schema status | rejected (`metadata` is `additionalProperties: false`) | accepted (declared at document root) |

**Fields** (JSF `definitions/signer`; required set is `algorithm` + `value`)

| Field | Type | Constraint |
|-------|------|-----------|
| `algorithm` | string | JWA identifier derived from the key actually used (FR-019). `ES256` for the only supported key type. |
| `publicKey` | object | JWK; see E2. |
| `value` | string | base64url-encoded signature bytes. Empty string during canonicalization, per JSF §4.3. |

**Invariants**

- INV-1: exactly one signature location is populated in an emitted
  document; the metadata slot is never populated (FR-002).
- INV-2: `algorithm` is derived from the key, never assumed (FR-019).
- INV-3: `value` is empty during the canonicalization that produces the
  bytes to be signed, and populated afterwards. Relocating the slot
  changes which bytes are covered but not this ordering.
- INV-4: re-signing a previously signed document removes the prior
  signature from the conformant location, leaving no residue in the
  previously used location (FR-006).

---

## E2 — Public key material (emitted)

Published inside the signature so consumers verify without out-of-band
key distribution.

**Shape change**

| | Before | After |
|---|---|---|
| Representation | `{ algorithmHint: string, pem: string }` | JWK |
| Schema status | rejected — JSF's EC branch is `additionalProperties: false` and requires `kty`/`crv`/`x`/`y` | accepted |

**Fields for the supported key type**

| Field | Value |
|-------|-------|
| `kty` | `"EC"` |
| `crv` | `"P-256"` |
| `x` | base64url, unpadded, 32 bytes decoded |
| `y` | base64url, unpadded, 32 bytes decoded |

**Invariants**

- INV-5: no property outside the JSF EC parameter set appears; the PEM
  and the algorithm hint are dropped rather than relocated (see spec
  Assumptions).
- INV-6: `x` and `y` are the coordinates of the same key that produced
  `value`, sourced from that key's exported SubjectPublicKeyInfo.

---

## E3 — Signing key type (input domain, narrowed)

Not emitted; determines whether the operation proceeds.

**Domain**

| Key type | Before | After |
|----------|--------|-------|
| ECDSA P-256 | accepted; algorithm hardcoded to match | accepted; algorithm derived |
| ECDSA P-384 | reached signing with a P-256 label | refused (FR-007) |
| Ed25519 | behaviour unestablished | refused (FR-007) |
| RSA | mapped to an ECDSA scheme while labelled `RS256` | refused (FR-007) |

**State transition**

```
supplied key ─► determine type
                   ├─ ECDSA P-256 ─► derive algorithm ─► sign ─► emit
                   └─ anything else ─► refuse (named type, non-zero exit, no output)
```

**Invariants**

- INV-7: the type is determined from the key material, never assumed.
- INV-8: a refusal produces no output file.

---

## E4 — Conformance gate (test-time)

| Aspect | Before | After |
|--------|--------|-------|
| Documents validated | unsigned only | unsigned **and** signed |
| JSF `$ref` | permissive stub (`{}`) | real vendored `jsf-0.82.schema.json` |
| Defect 1 detectable | yes (unexercised — no signed input) | yes |
| Defect 2 detectable | **no** (stub accepts anything) | yes |

- INV-9: the gate resolves the JSF reference to the real schema; a
  permissive stub silently disables half the gate's purpose (R2).

---

## E5 — Signing-mode / format combination (input validation)

| Signing mode | CycloneDX requested | SPDX only |
|---|---|---|
| Unsigned | proceed | proceed |
| Static key | proceed | proceed |
| Keyless | **refuse** (FR-014, FR-015) | proceed (FR-016) |

- INV-10: the refusal is decided from arguments alone, before scanning,
  so no partial output can exist (R5).
