# Quickstart — SBOMit compliance suite

Five short recipes covering the P1 user stories end-to-end. Run
them on an already-installed mikebom (`cargo build --release` or
one of the pre-release tarballs) on a Linux host for trace-mode
recipes, any host for verify / policy / enrich.

---

## Recipe 1 — Sign a build with a local key

**Scenario**: air-gapped developer wants signed attestations without
OIDC. Generate a local key, trace a build, verify the result.

```bash
# 1. Generate a PEM key (one-time). Standard OpenSSL-style; any
#    external toolchain works — mikebom reads the PEM file.
openssl ecparam -genkey -name prime256v1 -out signing.key
openssl ec -in signing.key -pubout -out signing.pub
chmod 600 signing.key  # OS permissions are your threat model

# 2. Trace a build with local-key signing.
mikebom trace run \
  --signing-key ./signing.key \
  --sbom-output ripgrep.cdx.json \
  --attestation-output ripgrep.attestation.dsse.json \
  -- cargo install ripgrep

# Produces:
#   ripgrep.attestation.dsse.json — DSSE envelope with one local-key
#                                    signature; subject points at the
#                                    real ripgrep binary with SHA-256
#   ripgrep.cdx.json              — CycloneDX 1.6 SBOM

# 3. Verify the attestation using the public key.
mikebom sbom verify ripgrep.attestation.dsse.json \
  --public-key ./signing.pub \
  --expected-subject "$(command -v ripgrep)"

# Expected output: "PASS — verified with local key <fingerprint>,
# subject digest matches on-disk binary."
```

**For an encrypted key**, set the passphrase via an env var and name
the var in `--signing-key-passphrase-env`:

```bash
openssl ec -in signing.key -aes256 -out signing.enc.key  # encrypts

MIKEBOM_KEY_PASS='correct horse battery staple' mikebom trace run \
  --signing-key ./signing.enc.key \
  --signing-key-passphrase-env MIKEBOM_KEY_PASS \
  -- cargo install ripgrep
```

Note: no interactive prompt, by design (works identically in CI and
container entrypoints).

---

## Recipe 2 — Sign in GitHub Actions with keyless identity

**Scenario**: CI-friendly signing — no operator-supplied private
keys. Uses GitHub's OIDC token to get a short-lived Fulcio cert, and
uploads to Rekor for downstream transparency-log verification.

```yaml
# .github/workflows/release.yml (snippet)
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write    # required for OIDC token issuance
      contents: read
    steps:
      - uses: actions/checkout@v6
      - name: Build + sign + attest
        run: |
          mikebom trace run \
            --keyless \
            --sbom-output release.cdx.json \
            --attestation-output release.attestation.dsse.json \
            -- cargo install --path .

      - name: Upload attestation
        uses: actions/upload-artifact@v5
        with:
          name: release-attestation
          path: |
            release.attestation.dsse.json
            release.cdx.json
```

`mikebom` auto-detects the `ACTIONS_ID_TOKEN_REQUEST_URL` +
`ACTIONS_ID_TOKEN_REQUEST_TOKEN` env vars GitHub Actions injects,
mints an OIDC token, exchanges it at Fulcio for a signing cert,
signs the canonical DSSE payload, and uploads the entry to Rekor.
The resulting envelope carries a Rekor inclusion proof so
downstream verifiers can verify without a live Rekor query.

**Private sigstore instance**: add `--fulcio-url` and `--rekor-url`.

**Skip Rekor** (e.g., restricted-network CI): add
`--no-transparency-log`. The envelope is still valid but carries
no Rekor proof; verifiers that require one will report
`TransparencyLogMissing` — opt-in only.

---

## Recipe 3 — Verify an attestation from another SBOMit-compliant tool

**Scenario**: you receive a signed attestation produced by `witness`
or another SBOMit-aware tool. mikebom can verify it as long as the
envelope is DSSE-shaped.

```bash
mikebom sbom verify received.attestation.dsse.json \
  --identity 'signer@example.com' \
  --expected-subject ./their-binary

# Reports each step: envelope parsed, signature verified, identity
# matched, subject digest matched.
```

The `--identity` matcher accepts:
- An exact email: `user@example.com`
- A GitHub Actions workflow URL:
  `https://github.com/<org>/<repo>/.github/workflows/release.yml@refs/heads/main`
- A glob: `*.example.com` (suffix match on the cert SAN)

Failures report a specific `FailureMode`:

```text
FAIL — SignatureInvalid
  detail: DSSE envelope signature validation failed
  partial_identity: Some(certificate with SAN "bob@example.com")
```

---

## Recipe 4 — Override subject detection

**Scenario**: the traced build produces multiple outputs and you only
want a specific one in the subject, or auto-detection got it wrong.

```bash
# Auto-detection would pick up every .whl in dist/ by default; force
# just the primary wheel.
mikebom trace run \
  --signing-key ./signing.key \
  --subject ./dist/myapp-1.0.0-py3-none-any.whl \
  --attestation-output attest.dsse.json \
  -- python -m build

# The attestation's `subject` array will contain exactly the one file.
```

You can pass `--subject` multiple times to record multiple subjects
explicitly:

```bash
mikebom trace run \
  --signing-key ./signing.key \
  --subject ./dist/myapp-1.0.0-py3-none-any.whl \
  --subject ./dist/myapp-1.0.0.tar.gz \
  -- python -m build
```

When `--subject` is supplied, auto-detection is suppressed
entirely — mikebom signs exactly what you told it to.

---

## Recipe 5 — Generate + apply a layout

**Scenario**: organization-wide policy — "every build of production
artifacts must carry a mikebom attestation signed by the CI
functionary key."

```bash
# 1. Generate a starter layout that references a specific public key.
mikebom policy init \
  --functionary-key ci.pub \
  --step-name build-trace-capture \
  --output prod-release.layout.json

# 2. Capture a build and sign it (either recipe 1 or 2).
mikebom trace run --signing-key ci.key -- cargo install ripgrep

# 3. Verify the attestation passes the layout.
mikebom sbom verify mikebom.attestation.dsse.json \
  --layout prod-release.layout.json

# Pass: the signature is from the expected functionary key and the
# step name matches the layout's declared step.

# Fail example: signed by the wrong key.
mikebom sbom verify other.attestation.dsse.json --layout prod-release.layout.json
# → FAIL (exit 3) — LayoutViolation
#   detail: no signature on attestation from layout-declared
#           functionary (expected keyid sha256:9d6a..., got sha256:3f11...)
```

The generated layout is a well-formed in-toto layout; any
in-toto-compatible verifier (witness, the in-toto-verify Python
reference) can evaluate it, not just mikebom.

---

## Recipe 6 — Enrich a generated SBOM (P3)

**Scenario**: your organization wants to add a custom supplier
annotation to one component of a generated SBOM, recorded as a
patch with provenance metadata.

```bash
# 1. Generate the SBOM (standard recipe).
mikebom sbom scan --path ~/.cargo/registry/cache --output cargo.cdx.json

# 2. Write a JSON patch that adds a supplier to one component.
cat > add-supplier.patch.json <<'EOF'
[
  {
    "op": "add",
    "path": "/components/3/supplier",
    "value": { "name": "Example Corp Security Team" }
  }
]
EOF

# 3. Apply the patch and record authorship.
mikebom sbom enrich cargo.cdx.json \
  --patch ./add-supplier.patch.json \
  --author "security-team@example.com" \
  --base-attestation ./mikebom.attestation.dsse.json

# The enriched cargo.cdx.json now includes a property group
# recording:
#   - The author ("security-team@example.com")
#   - The patch timestamp
#   - The base attestation's SHA-256 (so a verifier can walk back)
```

Downstream consumers walking the enriched SBOM can see — via the
`mikebom:enrichment-patch[N]` property group — which fields came
from the original attested trace and which were added by
post-hoc enrichment.

---

## Troubleshooting

**`Fulcio certificate issuance failed: 401 Unauthorized`** — your CI
environment doesn't have `id-token: write` permission, or the OIDC
provider isn't reachable. Check the workflow permissions stanza.

**`Rekor upload failed: timeout`** — the transparency log is
unreachable. Retry, or pass `--no-transparency-log` for a
non-transparent but still-signed envelope. Logged warning makes
this visible in CI.

**`signing failed: hard-fail per FR-006a`** — mikebom will NOT
silently fall back to unsigned. Fix the signing environment first.
If you need unsigned output for some reason, remove the
`--signing-key` / `--keyless` flags entirely.

**`SignatureInvalid` on verify of a known-good attestation** — check
that the envelope file wasn't re-formatted by an editor. DSSE
signatures cover the exact byte sequence of the payload field; any
re-serialization breaks validation.

**`SubjectDigestMismatch`** — the on-disk artifact has been modified
since the attestation was produced. Re-run the build or verify
against the exact artifact the attestation was produced for.

**`NotSigned` on legacy attestations** — pre-feature attestation
files carry no DSSE envelope; verify will report `NotSigned` as
the failure mode. Expected for legacy files; they still process
through `sbom generate` identically to before.
