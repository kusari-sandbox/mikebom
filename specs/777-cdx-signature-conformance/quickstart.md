# Quickstart: Verifying CycloneDX Signature Conformance

**Feature**: 777-cdx-signature-conformance

How to reproduce the defects before the change and confirm the fix
after. Every step here was executed during investigation; the "before"
outputs are what was actually observed, not predictions.

---

## 1. Generate a throwaway signing key

Never reuse a real key for this. Scratch directory only.

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ec.pem
openssl pkcs8 -topk8 -nocrypt -in ec.pem -out key.pk8.pem
```

## 2. Produce a signed document

Use a tiny synthetic fixture, not a real project.

```sh
mkdir -p mini
printf '{"name":"waybill-fixture-sig","version":"1.0.0","dependencies":{}}\n' > mini/package.json

waybill --offline sbom scan \
  --path mini \
  --format cyclonedx-json \
  --sign-key key.pk8.pem \
  --output signed.cdx.json
```

Note the flag order: `--offline` is a global flag and precedes
`sbom scan`; the format id is `cyclonedx-json`, not `cyclonedx`.

## 3. Observe where the signature lands

```sh
jq '{spec: .specVersion,
     root_sig: (has("signature")),
     meta_sig: (.metadata | has("signature"))}' signed.cdx.json
```

**Before**: `root_sig: false`, `meta_sig: true`
**After**: `root_sig: true`, `meta_sig: false`

## 4. Validate against the real schema

The vendored schema at
`waybill-cli/tests/fixtures/schemas/cyclonedx-1.6.json` needs two
external references resolved: `spdx.schema.json` and
`jsf-0.82.schema.json`. **The JSF reference must resolve to the real
schema** — the pre-existing test retriever stubs it with `{}`, which
accepts any signature object and would hide the public-key defect
entirely.

Expected progression:

| Document state | Result |
|---|---|
| Before the change | INVALID — `metadata`: additional properties not allowed (`signature`) |
| Signature relocated only | INVALID — `signature.publicKey`: missing `kty`/`crv`/`x`/`y`; `algorithmHint`, `pem` unexpected |
| Relocated **and** JWK | VALID |

## 5. A trap worth knowing about

If you validate with a tool that does **not** assert `format` (Python's
`jsonschema` without a `FormatChecker`, for instance), you will also see
a `oneOf` failure on `signature.algorithm`. That is a validator
artifact, not a defect: JSF types `algorithm` as
`oneOf[uri-format string, enum]`, and without format assertion `"ES256"`
satisfies both branches. A hand-built, fully conformant signature
reproduces it.

The Rust gate is not affected — `jsonschema` 0.46 asserts formats by
default for draft-04/06/07, and both schemas are draft-07. Do not
"fix" a conformant signature in response to this message.

## 6. Confirm the signature still verifies

```sh
# unmodified document → verification succeeds
# any content byte altered outside the signature → verification fails
```

Relocating the slot changes which bytes the signature covers, so this
check is the one that proves the canonicalization ordering survived the
move. It is not optional.

## 7. Confirm the refusals

```sh
# keyless + CycloneDX → non-zero exit, no file written
waybill --offline sbom scan --path mini --format cyclonedx-json \
        --sign --output out.cdx.json ; echo "exit=$?" ; ls out.cdx.json

# keyless + SPDX only → still succeeds
waybill --offline sbom scan --path mini --format spdx-2.3-json \
        --sign --output out.spdx.json

# non-P-256 key → non-zero exit naming the key type
openssl genpkey -algorithm ed25519 -out ed.pem
waybill --offline sbom scan --path mini --format cyclonedx-json \
        --sign-key ed.pem --output out.cdx.json ; echo "exit=$?"
```

## 8. Clean up

```sh
shred -u ec.pem key.pk8.pem ed.pem 2>/dev/null || rm -f ec.pem key.pk8.pem ed.pem
```
