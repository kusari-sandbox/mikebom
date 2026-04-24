# Contract — `mikebom sbom scan --format` flag

**Owner**: milestone 010 | **References**: spec FR-001, FR-003, FR-004, FR-004a, FR-004b, FR-019a, FR-019b | research R10

This document is the contract between the CLI surface and the format-dispatch layer (`SerializerRegistry`). Implementation MUST honor it; tests SHOULD assert against it.

## Flag

```
--format <FMT>[,<FMT>...]    [repeatable]
```

Accepted forms:

| Form | Equivalent to | Notes |
|------|---------------|-------|
| `--format cyclonedx-json` | (current behavior) | Unchanged from pre-milestone. Default if `--format` is omitted. |
| `--format spdx-2.3-json` | new | Single SPDX 2.3 emission. |
| `--format cyclonedx-json,spdx-2.3-json` | repeated `--format` below | Comma-separated list. |
| `--format cyclonedx-json --format spdx-2.3-json` | comma-separated above | Repeated occurrences. |
| `--format spdx-2.3-json --format spdx-2.3-json` | `--format spdx-2.3-json` | Duplicates de-duplicated silently (FR-004). |
| `--format spdx-3-json-experimental` | new, opt-in | Activates the FR-019a/b stub. Visibly labeled experimental in `--help` and in produced output. |

Behavior with no `--format` flag: unchanged from pre-milestone (CycloneDX JSON only, default filename). FR-004b.

## Recognized format identifiers

| Identifier | Stable? | Default filename | Notes |
|------------|---------|------------------|-------|
| `cyclonedx-json` | Stable | `mikebom.cdx.json` | CycloneDX 1.6 JSON. Pre-milestone default; preserved byte-identically (FR-022, SC-006). |
| `spdx-2.3-json` | Stable | `mikebom.spdx.json` | SPDX 2.3 JSON. New in this milestone. May co-emit `mikebom.openvex.json` next to it when the scan produces VEX statements (FR-016a). |
| `spdx-3-json-experimental` | **Experimental** | `mikebom.spdx3-experimental.json` | SPDX 3.0.1 JSON-LD stub. One-ecosystem (npm) coverage; opt-in only; surfaces "experimental" label in CLI `--help` and in the produced document's `creationInfo.creators` / `tooling` field. FR-019a, FR-019b. |

Identifiers are case-sensitive. Unknown identifiers exit non-zero with a clear error listing all registered identifiers.

## Per-format output overrides

```
--output <FMT>=<PATH>    [repeatable]
```

Examples:

```
mikebom sbom scan --path . \
    --format cyclonedx-json,spdx-2.3-json \
    --output cyclonedx-json=/tmp/cdx.json \
    --output spdx-2.3-json=/srv/sbom/spdx.json
```

Rules:

- An override applies only to the format whose identifier appears on the LHS.
- An override for a format that wasn't requested via `--format` is a hard error.
- The OpenVEX sidecar path is derived from the SPDX file's parent directory by default. To override the sidecar location, use `--output openvex=/path/to/openvex.json` (the OpenVEX sidecar is treated as a pseudo-format for override purposes only — it cannot be requested directly via `--format` and its presence is gated on whether the scan produces VEX statements).
- Default filename collisions are impossible by design (each registered format has a distinct default filename).
- Override-induced collisions (two formats overridden to the same path) MUST exit non-zero before any scan work is performed.

## CLI help output requirements (FR-019b)

`mikebom sbom scan --help` MUST:

1. List all registered format identifiers under `--format`'s help text.
2. Annotate `spdx-3-json-experimental` with the literal token `[EXPERIMENTAL]` in the help line.
3. Not silently accept any alias (e.g., `spdx-3-json` without the `-experimental` suffix MUST exit non-zero with "did you mean `spdx-3-json-experimental`?").

## Determinism

Per FR-020 / SC-007 / data-model.md §8, all serializers receive a single `OutputConfig.created` timestamp shared across the invocation. Multiple formats emitted from one scan therefore share a `created`/`metadata.timestamp` value byte-for-byte; running the same scan twice yields byte-identical output (modulo `created` and `documentNamespace`).
