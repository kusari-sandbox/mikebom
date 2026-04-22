# Contract: Signed attestation envelope

JSON schema and example for the DSSE envelope mikebom emits when a
signing identity is configured. Accepted as input by `mikebom sbom
verify` and by any other SBOMit-compliant verifier.

---

## Envelope format

```jsonc
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64(canonical_json(InTotoStatement))>",
  "signatures": [
    {
      "keyid": "<optional: public-key fingerprint or cert digest>",
      "sig": "<base64(signature_bytes)>",
      "identity": { "type": "certificate" | "public_key", "..." }
    }
  ]
}
```

The **payload** field holds a base64 encoding of the canonical JSON
of an in-toto Statement v1 — the same shape mikebom emits today, just
base64-wrapped inside the envelope so the DSSE signature covers
exactly the bytes downstream verifiers reconstruct.

The **signatures** array has one entry per signing identity. v1 of
this feature produces exactly one signature; multi-signer flows are
not in scope (see `plan.md` out-of-scope: multi-step layouts).

---

## Signature identity — keyless

When signing was done keyless (Fulcio + OIDC):

```jsonc
{
  "keyid": "sha256:3a7bd3e2...",
  "sig": "MEQCIH...",
  "identity": {
    "type": "certificate",
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "chain": [],
    "rekor_bundle": {
      "log_index": 123456789,
      "log_id": "sha256:c0d23d6a...",
      "integrated_time": 1713700000,
      "signed_entry_timestamp": "MEYCIQ...",
      "inclusion_proof": {
        "log_index": 123456789,
        "tree_size": 987654321,
        "root_hash": "sha256:...",
        "hashes": ["sha256:...", "sha256:..."],
        "checkpoint": "sigstore/1000..."
      }
    }
  }
}
```

- `certificate` is the PEM-encoded Fulcio-issued ephemeral
  certificate. Its Subject Alternative Name carries the OIDC
  identity (email, GitHub workflow URL, etc.) that signed.
- `chain` holds any intermediate certs. For sigstore's public-good
  Fulcio instance this is usually empty because Fulcio's root cert
  is in the well-known trust root.
- `rekor_bundle` is present when `--no-transparency-log` was NOT
  passed. It carries the Rekor log inclusion proof enabling offline
  verification without a live Rekor query.

When `--no-transparency-log` was set, `rekor_bundle` is `null`. The
envelope remains valid but verifiers that require transparency-log
proof will emit `VerificationReport::Fail { mode:
TransparencyLogMissing }`.

---

## Signature identity — local key

When signing was done with a local PEM key:

```jsonc
{
  "keyid": "sha256:9d6a...",
  "sig": "MEQCIH...",
  "identity": {
    "type": "public_key",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "algorithm": "ecdsa-p256"
  }
}
```

- `public_key` is the PEM-encoded verifying key derived from the
  private key used for signing. Always embedded so verifiers don't
  need out-of-band key distribution.
- `algorithm` enum: `ecdsa-p256` | `ed25519` | `rsa-pkcs1`. Other
  algorithms rejected at parse time.
- No Rekor bundle — local-key signing does not include transparency
  log proof.

---

## Payload shape (unchanged)

The base64-decoded payload is the existing in-toto Statement v1:

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "ripgrep", "digest": { "sha256": "5f2ab..." } }
  ],
  "predicateType": "https://mikebom.dev/attestation/build-trace/v1",
  "predicate": {
    "metadata": { "tool": {"name":"mikebom","version":"0.1.0-alpha.4"}, "...": "..." },
    "network_trace": { "connections": ["..."], "...": "..." },
    "file_access": { "operations": ["..."], "...": "..." },
    "trace_integrity": { "ring_buffer_overflows": 0, "...": "..." }
  }
}
```

No schema change to the Statement itself. Changes are only:
1. `subject` now carries real artifacts and their SHA-256 digests
   (instead of today's synthetic `"build-output"` sentinel), or
   a synthetic entry per clarification Q5.
2. The Statement is base64-encoded inside a DSSE envelope when
   signed, unchanged-and-raw when unsigned.

---

## Synthetic subject shape (when no artifact detected)

Per clarification Q5:

```jsonc
{
  "name": "synthetic:cargo-test-abc1234",
  "digest": {
    "synthetic": "9a3f6c7b1e2d..."  // SHA-256 of trace command + start timestamp
  }
}
```

- `name`: `synthetic:` prefix plus a short command-derived summary.
- `digest.synthetic`: the non-real algorithm key signals to every
  verifier that this is NOT a content hash. Value is deterministic
  (reproducible across identical traces).

This shape is the **only** subject-entry shape when no artifact is
detected. Subject array is never empty (that would break strict
in-toto parsers per R2 analysis).

---

## Unsigned payload — backwards compatibility

Invocations with no signing identity emit a raw Statement v1 JSON
file, not a DSSE envelope. Shape identical to pre-feature output:

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [ ... ],
  "predicateType": "https://mikebom.dev/attestation/build-trace/v1",
  "predicate": { ... }
}
```

Distinguishing signed vs. unsigned for a verifier: signed files have
a top-level `payloadType` key; unsigned files do not. `mikebom sbom
verify` reports `FailureMode::NotSigned` when handed an unsigned
file — a legitimate outcome that CI tooling can branch on.

---

## Determinism

Per FR-006, the base64-encoded `payload` must be byte-identical
across re-runs of a reproducible build. Canonicalization rules:

1. The inner Statement JSON is serialized with deterministic key
   ordering (alphabetical at every level, matches `serde_json` with
   `BTreeMap`).
2. Floating-point numbers use exact representation where
   applicable; no `NaN` / `Infinity` in any predicate field (not
   produced by existing code).
3. Timestamp strings use RFC 3339 UTC (`2026-04-21T...Z`) — already
   the case today.

Signatures themselves may vary (e.g., ECDSA's random nonce), but
the signed bytes are deterministic.

---

## Verifier acceptance criteria

Any verifier claiming SBOMit compliance should:

1. Parse the envelope per the DSSE spec.
2. For each signature, reconstruct the PAE (Pre-Authenticated
   Encoding) over `payloadType || payload || context` and verify
   the signature against the declared key / certificate.
3. If `identity.certificate` is present, walk the cert chain to a
   known trust root (Fulcio's for sigstore-public-good, or a
   configured custom root).
4. If `identity.rekor_bundle` is present, verify the inclusion
   proof against the Rekor log's current root (or the checkpoint
   embedded in the bundle).
5. Decode `payload`, parse the in-toto Statement, and optionally
   verify each `subject.digest` against on-disk artifact SHA-256.
6. Optionally apply an in-toto layout against the statement.

All six steps are implemented in `mikebom sbom verify`. External
verifiers can pick-and-choose based on their policy.
