# Contract: CLI surface

New and modified commands + flags for the SBOMit compliance suite.
Every flag follows the existing noun-verb pattern: `mikebom <noun>
<verb> [flags]`. Global flags (`--offline`, `--include-dev`,
`--include-legacy-rpmdb`) continue to work.

---

## `mikebom trace capture` — new flags

```
--signing-key <PATH>
    Path to a PEM-encoded private key for local-key signing.
    Mutually exclusive with --keyless.

--signing-key-passphrase-env <NAME>
    Name of the environment variable holding the passphrase for an
    encrypted --signing-key. Has no effect on unencrypted keys.
    No interactive prompt is used (CI-friendly).

--keyless
    Use keyless signing: OIDC → Fulcio → (optional) Rekor. Mutually
    exclusive with --signing-key.

--fulcio-url <URL>
    Override the Fulcio certificate-issuance URL. Default:
    https://fulcio.sigstore.dev.

--rekor-url <URL>
    Override the Rekor transparency-log URL. Default:
    https://rekor.sigstore.dev.

--no-transparency-log
    Skip Rekor upload + inclusion-proof embedding. Keyless mode
    only; with this flag the emitted envelope carries the Fulcio
    cert alone. A warning is logged about the reduced verifier
    support.

--subject <PATH>
    Explicit subject artifact path. Repeatable: pass multiple to
    record multiple subjects. Overrides auto-detection — when set,
    mikebom does NOT scan for artifacts.

--require-signing
    Fail the command if no signing identity was configured. By
    default, missing identity emits unsigned + warning; this flag
    flips that to a hard error. Useful in CI policies.
```

## `mikebom trace run` — same flag additions

All of the above, plus the flags pass transparently into the
composed `trace capture` + `sbom generate` pipeline. No new
`sbom generate` flags are surfaced at the `run` level beyond the
signing flags (existing flags untouched).

## `mikebom sbom generate` — new flags

```
--subject <PATH>
    Explicit subject artifact path. Same semantics as
    `trace capture --subject` but applied when generating an SBOM
    from an already-captured attestation.
```

Existing `--enrich`, `--lockfile`, `--deps-dev-timeout`, and
`--skip-purl-validation` flags are unchanged.

## `mikebom sbom verify <attestation>` — NEW subcommand

**Purpose**: validate a signed attestation end-to-end. Accepts
mikebom-produced envelopes AND envelopes from any other
SBOMit-compliant tool (per FR-023) as long as the shape matches.

```
Usage: mikebom sbom verify <ATTESTATION> [flags]

Arguments:
  <ATTESTATION>  Path to a signed (.json / .dsse) attestation file.

Flags:
  --layout <PATH>
      Verify against an in-toto layout. When omitted, only
      envelope-level checks run (signature, subject digest).

  --public-key <PATH>
      Path to a PEM-encoded public key expected to have signed
      the attestation. Mutually exclusive with --identity. Use
      for local-key-signed attestations.

  --identity <PATTERN>
      Expected signer identity (email, URL, or glob pattern) for
      keyless-signed attestations. Matched against the Fulcio
      certificate's Subject Alternative Name.

  --expected-subject <PATH>
      Verify the on-disk SHA-256 of PATH matches one of the
      attestation's subjects. Repeatable.

  --no-transparency-log
      Don't require a Rekor inclusion proof in the envelope.
      Default is to require one for keyless-signed envelopes.

  --fulcio-url / --rekor-url  (same defaults as trace capture)

  --json
      Emit a structured verification report to stdout instead of
      a human message.
```

**Exit codes**:
- `0`: `VerificationReport::Pass`.
- `1`: `VerificationReport::Fail` with `mode = SignatureInvalid`,
  `IdentityMismatch`, `SubjectDigestMismatch`, `TransparencyLogMissing`.
- `2`: `Fail` with `mode = MalformedEnvelope`, `NotSigned`,
  `TrustRootInvalid`, `CertificateExpired`.
- `3`: `Fail` with `mode = LayoutViolation`.

Non-zero exit codes are grouped so CI policies can distinguish
"crypto invalid" from "policy failed" from "envelope malformed".

**Output**:
- Human mode (default): a one-liner status + bullet list of
  findings.
- `--json` mode: full `VerificationReport` serialized.

## `mikebom policy init` — NEW subcommand

**Purpose**: generate a starter in-toto layout for the operator's
signing identity.

```
Usage: mikebom policy init [flags]

Flags:
  --output <PATH>
      Where to write the layout. Default: ./layout.json.

  --functionary-key <PATH>
      PEM-encoded public key of the expected signer. Required.

  --step-name <NAME>
      Single step the layout expects. Default: "build-trace-capture".

  --expires <DURATION>
      How long the layout is valid. Default: 1y.
      Format: "6m", "1y", "18mo", "2y".

  --readme <TEXT>
      Optional human-readable description embedded in the layout.
```

**Output**: a well-formed in-toto layout JSON file at `--output`.
See `research.md` R2 for the exact schema mikebom emits.

## `mikebom sbom enrich <sbom>` — reprise of existing stub (P3)

Today this is a stubbed `bail!("enrich command not yet implemented
— see Phase 6 (US4)")` command. This feature implements it.

```
Usage: mikebom sbom enrich <SBOM> [flags]

Arguments:
  <SBOM>  CycloneDX JSON to enrich in-place.

Flags:
  --patch <PATH>
      Path to an RFC 6902 JSON patch file. Repeatable: patches
      are applied in order (later operations see earlier ones).

  --author <STRING>
      Recorded author of the enrichment for provenance metadata.
      Defaults to "unknown" with a warning.

  --base-attestation <PATH>
      Optional path to the attestation this SBOM was derived from.
      The enriched SBOM will embed the attestation's SHA-256 in
      its property group so verifiers can walk back.

  --output <PATH>
      Where to write the enriched SBOM. Default: overwrite <SBOM>.
```

Existing `--skip-vex`, `--skip-licenses`, `--skip-supplier`, and
`--vex-overrides` flags stay as no-ops for now (they were on the
stub signature); they can be implemented in a later feature.

---

## Backwards compatibility

- Zero-flag invocations of `mikebom trace run / capture / sbom
  generate` continue to produce the same output shape they
  produce today (unsigned JSON attestation, synthetic subject if
  no `--subject` supplied).
- Existing `mikebom.attestation.json` files from pre-feature
  versions remain consumable by `sbom generate` and the new
  `sbom verify` (the latter reports `NotSigned` as the failure
  mode, which is expected for legacy files — it does not crash).
- All new flags are additive; no existing flag semantics change.

---

## Error-exit-code contract

Summary of exit codes across the new and modified commands:

| Command | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `trace capture` | success | signing failure (when `--require-signing`) | user / arg error | n/a |
| `trace run` | success | signing failure (when `--require-signing`) | user / arg error | n/a |
| `sbom generate` | success | subject override mismatch | user / arg error | n/a |
| `sbom verify` | Pass | crypto fail | envelope fail | layout fail |
| `policy init` | success | — | user / arg error | — |
| `sbom enrich` | success | patch apply error | user / arg error | — |

Every non-zero exit maps to a distinguishable `FailureMode` in the
`--json` output for tooling integration.
