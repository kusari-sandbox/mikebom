# Contract: SPDX 3.0.1 Emitter (`spdx-3-json`)

**Branch**: `011-spdx-3-full-support` | **Date**: 2026-04-24 | **Plan**: [plan.md](../plan.md) | **Data model**: [data-model.md](../data-model.md)

This document is the public contract the SPDX 3.0.1 emitter makes to its callers — the CLI dispatch layer (`mikebom-cli/src/cli/scan_cmd.rs`), the integration test suite under `mikebom-cli/tests/`, and any future programmatic embedder of the `mikebom_cli::generate` API.

The contract is **format-version-agnostic** above the JSON-LD shape: callers pass `ScanArtifacts` + `OutputConfig` and receive `Vec<EmittedArtifact>`. The same shape the SPDX 2.3 emitter offers; SPDX 3 plugs into the existing `SbomSerializer` trait without trait changes.

## 1. Identity

| Field | Value |
|-------|-------|
| Format identifier (stable) | `spdx-3-json` |
| Format identifier (deprecated alias, accepted through milestone 012) | `spdx-3-json-experimental` |
| Default output filename | `mikebom.spdx3.json` |
| Format-dispatch struct | `mikebom_cli::generate::spdx::Spdx3JsonSerializer` |
| Alias-dispatch struct | `mikebom_cli::generate::spdx::Spdx3JsonExperimentalSerializer` (delegates to `Spdx3JsonSerializer::serialize` and emits a stderr deprecation notice — see §4) |

## 2. Input

```rust
fn serialize(
    &self,
    scan: &ScanArtifacts<'_>,
    cfg: &OutputConfig,
) -> anyhow::Result<Vec<EmittedArtifact>>;
```

`ScanArtifacts` and `OutputConfig` are unchanged from milestone 010. The SPDX 3 path adds **no required fields** to either — every signal it consumes is already populated by the existing scan pipeline.

## 3. Output guarantees

The returned `Vec<EmittedArtifact>` always contains the SPDX 3 document at `mikebom.spdx3.json` (or the user-overridden path from `OutputConfig.overrides`). It additionally contains the OpenVEX sidecar at `mikebom.openvex.json` (default name) when the scan produced advisories, matching the milestone-010 SPDX 2.3 ↔ OpenVEX co-emit shape exactly.

| # | Guarantee | Enforced by |
|---|-----------|-------------|
| G1 | Output validates against the bundled SPDX 3.0.1 JSON-LD schema (`mikebom-cli/tests/fixtures/spdx3-3.0.1.schema.json`) with zero warnings and zero errors. | `tests/spdx3_schema_validation.rs` (FR-016, SC-002) |
| G2 | Two runs of `serialize` against the same `ScanArtifacts` + `OutputConfig` produce byte-identical document bytes. | `tests/spdx3_determinism.rs` (FR-015, SC-006) |
| G3 | For every CycloneDX `components[].purl` (top-level or nested via the milestone-010 walk), exactly one SPDX 3 `software_Package` carries that PURL (in `software_packageUrl` *and* in an `ExternalIdentifier[purl]` entry). Component count parity with the CycloneDX serializer for the same scan. | `tests/spdx3_cdx_parity.rs` (FR-005, SC-003) |
| G4 | For every matched (CDX↔SPDX 3) Package pair, version and checksum-set parity holds byte-for-byte. CDX `alg` strings (`SHA-256`, …) normalize to SPDX 3's `algorithm` enum form (`SHA256`, …) via the same `normalize_alg` rule the SPDX 2.3 parity test uses. | `tests/spdx3_cdx_parity.rs` (FR-006, SC-003) |
| G5 | Every `mikebom:*` field reachable in the SPDX 2.3 output for a fixture is reachable in the SPDX 3 output for the same fixture, by field name and value. The reachability path is either a native SPDX 3 property binding (per `data-model.md`) or an `Annotation` element whose `statement` decodes to the milestone-010 `MikebomAnnotationCommentV1` envelope. | `tests/spdx3_annotation_fidelity.rs` (FR-011, SC-005) |
| G6 | The `SpdxDocument` element's `externalRef[]` carries exactly one entry of `externalRefType: "securityAdvisory"` whose `locator` resolves to the OpenVEX sidecar's emitted path — when and only when the scan produced advisories. | `tests/openvex_sidecar.rs` (extended for SPDX 3) (FR-013, FR-014) |
| G7 | Single invocation of `--format cyclonedx-json,spdx-2.3-json,spdx-3-json` completes in ≤75% wall-clock of three sequential single-format invocations against the same target (CI gate; spec target ≤70%). | `tests/triple_format_perf.rs` (FR-004, SC-007) |
| G8 | Output for a user who passes only `--format cyclonedx-json` is byte-identical to milestone 010's CycloneDX output for the same scan. (No SPDX 3 work runs when SPDX 3 is not requested.) | `tests/cdx_regression.rs` (already exists; the milestone-011 changes are emit-side, no shared code path mutated) (SC-009) |
| G9 | `sbomqs score` ranks the SPDX 3 output ≥ the CycloneDX output on every NTIA-minimum native feature both formats express. | `tests/sbomqs_parity.rs` (extended) (SC-001) |
| G10 | Every row in `docs/reference/sbom-format-mapping.md` has a non-placeholder SPDX 3 column entry. | `tests/sbom_format_mapping_coverage.rs` (already enforces three columns; the SPDX 3 column gains real entries replacing the milestone-010 `defer until …` placeholders) (SC-004, SC-010) |

## 4. Alias-path deprecation behavior

When the user invokes `Spdx3JsonExperimentalSerializer` (via `--format spdx-3-json-experimental`), the implementation:

1. Calls `Spdx3JsonSerializer::serialize` and returns its `Vec<EmittedArtifact>` **unchanged**. The bytes are byte-identical to the stable identifier's output for the same scan: same default filename `mikebom.spdx3.json`, same document content, no comment-property differences. (Per research.md §R6: the alias is a deprecation track, not an experimental emitter; constitution V's experimental-labeling clause does not apply.)
2. Returns `experimental() = false` on the trait. The deprecation signal is carried by the help-text annotation (rendered separately by the CLI surface based on identifier name) and the stderr notice — not by the trait's `experimental()` flag, which would conflate "deprecated lifecycle" with "preview-quality output."
3. Emits the FR-002 deprecation notice to stderr exactly once per invocation. Notice text per `research.md` §R2 (two lines: deprecation directive + shape-change advisory). Suppressed when `MIKEBOM_NO_DEPRECATION_NOTICE=1` is set, so CI logs of pipelines on a controlled migration don't drown in repeated warnings.

The format-dispatch test (`tests/format_dispatch.rs`) asserts:
- Both identifiers are accepted by the CLI parser.
- Both identifiers produce a `Vec<EmittedArtifact>` whose first element's path is `mikebom.spdx3.json` (no `-experimental` suffix).
- The bytes of the two outputs are **byte-identical** for the same scan input.
- The alias prints the deprecation notice to stderr; the stable identifier does not.

## 5. Annotation envelope contract (carried over from milestone 010)

The `MikebomAnnotationCommentV1` envelope shape is **unchanged**:

```json
{ "schema": "mikebom-annotation/v1", "field": "<mikebom:field-name>", "value": <original-value> }
```

In SPDX 2.3 this envelope lives in `annotations[].comment` (a string field). In SPDX 3 it lives in `Annotation.statement` (also a string field). The envelope JSON bytes are byte-identical across the two format versions for the same `(subject, field, value)` tuple. No envelope-version bump.

This sameness is the load-bearing property the annotation-fidelity test relies on: it can decode an SPDX 2.3 annotation comment and an SPDX 3 Annotation statement with one `serde_json::from_str::<MikebomAnnotationCommentV1>` call each and compare results.

## 6. Strict-match rule (Q2)

For each `mikebom:*` field, the emitter chooses native vs. Annotation per the table in [data-model.md](../data-model.md). Borderline rows (C8, C16, C18, C19) are resolved per [research.md](../research.md) §R5 and locked into [docs/reference/sbom-format-mapping.md](../../../docs/reference/sbom-format-mapping.md).

The choice is **not** dynamic — there is no "if this Package's data fits a native field, use it; otherwise fall back" runtime decision. Every row is decided at the mapping-doc level and the emitter always emits the chosen shape, full stop. This is what makes the strict-match rule reviewable and what makes the annotation-fidelity test deterministic.

## 7. Failure modes

| Condition | Behavior |
|-----------|----------|
| Non-canonicalizable license expression | Emit the `simplelicensing_LicenseExpression` element with the raw string verbatim, attach an `Annotation[mikebom:license-canonicalization-failed]` to the LicenseExpression element. (Matches the SPDX 2.3 path's non-fatal-fallback behavior, FR-008.) |
| PURL-less component | Emit the Package using a synthesized PURL the way the SPDX 2.3 path does (`pkg:generic/<target>@0.0.0` for the synthetic root, or fail-out per the milestone-010 contract for non-root components). |
| Empty scan (zero components) | Emit a structurally valid document containing the synthesized root Package only, matching the SPDX 2.3 path. |
| OpenVEX serialization error | Bubble up via `anyhow::Result::Err`. Do not emit a partial SPDX 3 document. (Matches SPDX 2.3 fail-closed behavior.) |
| Schema-validation failure (in tests) | Test fails with the schema validator's diagnostic output. CI gate is hard. |
