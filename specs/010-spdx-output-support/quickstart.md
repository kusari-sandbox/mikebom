# Quickstart — SPDX Output Support

**Feature**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md) | **Date**: 2026-04-23

This guide shows the user-facing surface introduced by milestone 010. Cross-references for implementers: see plan.md (architecture), research.md (technology choices), data-model.md (internal types), contracts/cli-format-flag.md (the authoritative CLI contract).

## TL;DR

```bash
# Existing behavior — unchanged. CycloneDX 1.6 JSON.
mikebom sbom scan --path .

# Produce SPDX 2.3 JSON instead.
mikebom sbom scan --path . --format spdx-2.3-json

# Produce both, in one scan (no rescan, no duplicate work).
mikebom sbom scan --path . --format cyclonedx-json,spdx-2.3-json

# Override per-format output paths.
mikebom sbom scan --path . \
    --format cyclonedx-json,spdx-2.3-json \
    --output cyclonedx-json=/tmp/cdx.json \
    --output spdx-2.3-json=/srv/sbom/spdx.json

# Try the experimental SPDX 3.0.1 stub (npm coverage only).
mikebom sbom scan --path ./my-npm-app --format spdx-3-json-experimental
```

## What you get

| Format | Default filename | Status | Notes |
|--------|------------------|--------|-------|
| `cyclonedx-json` | `mikebom.cdx.json` | Stable (unchanged) | CycloneDX 1.6 JSON. Default when no `--format` is passed. Output is byte-identical to pre-milestone for any given scan. |
| `spdx-2.3-json` | `mikebom.spdx.json` | **New, stable** | SPDX 2.3 JSON. Validates clean against the official LF SPDX 2.3 JSON schema. Co-emits `mikebom.openvex.json` next to it when the scan produces VEX statements. |
| `spdx-3-json-experimental` | `mikebom.spdx3-experimental.json` | **Experimental** | SPDX 3.0.1 JSON-LD. Single-ecosystem coverage (npm). The output's creator field, the file name, and `--help` all label it experimental. |
| OpenVEX 0.2.0 sidecar | `mikebom.openvex.json` | **New, stable** | Written automatically next to an SPDX file when VEX statements exist. Override path with `--output openvex=<path>`. |

## Producing both formats from one scan

```bash
mikebom sbom scan --path . --format cyclonedx-json,spdx-2.3-json
```

This runs the scan once and emits two files (or three, if VEX is present). Compared with running `mikebom sbom scan` twice (once per format), this is **at least 30% faster** on representative image-scan fixtures because deep-hash and layer-walk work happens once instead of twice (success criterion SC-009).

The CycloneDX bytes are identical to what `mikebom sbom scan --format cyclonedx-json` would produce alone. The SPDX bytes are identical to what `mikebom sbom scan --format spdx-2.3-json` would produce alone. Multi-format mode is purely a performance optimization on the scan; the serializers are unchanged.

## Reading the SPDX file alongside the CycloneDX file

Every component in the CycloneDX file appears as exactly one SPDX `Package` in the SPDX file, matched by PURL. The data-placement map at [`docs/reference/sbom-format-mapping.md`](../../../docs/reference/sbom-format-mapping.md) (canonical home; mirrored under `contracts/` in this milestone for review) lists, for every emitted field, where it lives in CycloneDX and where it lives in SPDX 2.3 (and SPDX 3).

Mikebom-specific data with no native SPDX 2.3 home (the `mikebom:*` properties, evidence, compositions) is preserved as SPDX `annotations[]` on either the document or the relevant Package, with a JSON envelope conforming to [`contracts/mikebom-annotation.schema.json`](./contracts/mikebom-annotation.schema.json):

```json
{
  "schema": "mikebom-annotation/v1",
  "field": "mikebom:evidence-kind",
  "value": "instrumentation"
}
```

Tools that ignore SPDX annotations see a clean, fully-conformant SPDX document. Tools that read them recover full mikebom fidelity.

## OpenVEX sidecar

When the scan produces VEX statements (CycloneDX `vulnerabilities[]`), an OpenVEX 0.2.0 JSON sidecar is written next to the SPDX file:

```text
.
├── mikebom.spdx.json
└── mikebom.openvex.json
```

The SPDX document references the sidecar via `externalDocumentRefs[]`:

```json
"externalDocumentRefs": [
  {
    "externalDocumentId": "DocumentRef-OpenVEX",
    "spdxDocument": "./mikebom.openvex.json",
    "checksum": { "algorithm": "SHA256", "checksumValue": "<sha256 of sidecar bytes>" }
  }
]
```

When no VEX statements exist for the scan, no sidecar is created.

## Validating the output yourself

```bash
# SPDX 2.3
pyspdxtools-validate mikebom.spdx.json
# or any official LF SPDX validator

# OpenVEX (any JSON Schema validator + OpenVEX 0.2.0 schema from openvex/spec)
jsonschema -i mikebom.openvex.json openvex.schema.json

# SPDX 3.0.1 (when using the experimental stub)
jsonschema -i mikebom.spdx3-experimental.json spdx-3.0.1.json
```

Mikebom's own CI validates produced output against the same schemas using `jsonschema = "0.46"` in pure Rust — see plan.md → Testing.

## Determinism

Re-running the same scan against the same target produces byte-identical output (modulo SPDX `created` and `documentNamespace`, both of which are derived from a single shared timestamp / scan-fingerprint per invocation). This means SBOMs can be checked into source control, diffed across builds, and compared across machines without false-positive churn.

## Backward compatibility

- Calling `mikebom sbom scan` with no `--format` continues to produce a single `mikebom.cdx.json` exactly as before.
- The CycloneDX output for any given scan is byte-identical to the pre-milestone output, enforced by a regression test on pinned fixtures.
- No existing flags change meaning.

## Common errors

| Error | Cause | Fix |
|-------|-------|-----|
| `error: unknown format identifier 'spdx-3-json'` | Forgot the `-experimental` suffix on the SPDX 3 stub. | Use `spdx-3-json-experimental`. |
| `error: --output for format 'spdx-2.3-json' but that format was not requested` | Passed `--output spdx-2.3-json=...` without listing it in `--format`. | Add `spdx-2.3-json` to `--format`. |
| `error: output path collision: 'cyclonedx-json' and 'spdx-2.3-json' both write to '/tmp/sbom.json'` | Two `--output` overrides resolved to the same path. | Use distinct paths per format. |

## Where the stub stops (SPDX 3)

The SPDX 3 stub (`spdx-3-json-experimental`) covers npm components only and emits a minimal subset of SPDX 3.0.1 elements (Document, CreationInfo, Package, Relationship). It is intended to exercise the format-dispatch architecture in real code, not to be a production SBOM. The data-placement map's SPDX 3 column lists `defer until SPDX 3 profile X stabilizes` for fields that depend on profiles still maturing in SPDX 3.x. A follow-up milestone will expand coverage; see plan.md complexity tracking for the constitution-amendment recommendation.
