# Implementation Plan: CycloneDX Signature Conformance

**Branch**: `777-cdx-signature-conformance` | **Date**: 2026-09-05 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/777-cdx-signature-conformance/spec.md`

## Summary

Signed CycloneDX output is schema-invalid today: the signature is written
to `metadata.signature` (a slot CycloneDX forbids, since `metadata` is
`additionalProperties: false`) and its `publicKey` is a PEM blob where
JSON Signature Format requires a JWK. Both defects were verified against
the upstream schema; fixing both — and only both — yields a valid
document.

The approach is narrow and additive-free: move the signature to the
document root, derive the JWK from the key material already available
via `public_key_to_der()`, derive the declared algorithm from a match on
the key type (refusing anything but EC P-256), and refuse the keyless
path for CycloneDX output rather than emit output known to be invalid.
The gate is closed by pointing the existing schema harness at a signed
document — which additionally requires vendoring the real JSF schema,
because the harness currently stubs it with a permissive `{}` that would
hide the public-key defect.

**Zero new Cargo dependencies.** One new vendored test fixture.

## Technical Context

**Language/Version**: Rust stable (workspace toolchain inherited from milestones 001–776; no nightly)
**Primary Dependencies**: Existing only — `sigstore` 0.11 (kusari-sandbox fork; `SigStoreKeyPair::public_key_to_der`), `x509-parser` 0.16 and `pem` 3 (already direct deps of `waybill-cli`; SPKI handling), `serde`/`serde_json`, `base64`-equivalent encoding via existing `data-encoding`, `clap` (argument validation), `tracing`, `anyhow`/`thiserror`. Dev/test: existing `jsonschema` 0.46. **Zero new Cargo dependencies** (see research R3).
**Storage**: N/A — the signature is emitted into the output document; no caches, no persistence.
**Testing**: `cargo +stable test --workspace` plus `cargo +stable clippy --workspace --all-targets`, per the mandatory pre-PR gate. New coverage lands in `waybill-cli/src/sbom/signer.rs` unit tests and `waybill-cli/tests/cisa_2026_signing.rs`, with schema validation extended from the existing harness.
**Target Platform**: All supported hosts (Linux, macOS, Windows). Signing is user-space and platform-independent; no eBPF surface touched.
**Project Type**: CLI / library — single Rust workspace, three crates.
**Performance Goals**: N/A. Signing is one operation over one in-memory document; the change adds a key-material decode measured in microseconds.
**Constraints**: Unsigned output must be byte-identical (FR-012); SPDX signing untouched (FR-013); no new dependencies; the gate must not depend on network access.
**Scale/Scope**: One signing module, one CLI validation site, one test file, one vendored schema fixture, one operator-facing document.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design.*

| Principle | Assessment |
|-----------|-----------|
| **I. Pure Rust, Zero C** | PASS. No new dependencies; the SPKI decode uses crates already in the tree. No C, no scripting runtime. |
| **III. Fail Closed** | PASS, and strengthened. The principle's letter is scoped to eBPF tracing, but its rationale — that silently shipping a misleading artifact is worse than failing — is exactly this feature's posture: both the keyless path and unsupported key types refuse rather than emit invalid output. |
| **IV. Type-Driven Correctness** | PASS, and strengthened. Key-type handling moves from a hardcoded constant to a match on an existing sum type, making the label/scheme disagreement documented in research R4 unrepresentable rather than merely unreached. |
| **V. Specification Compliance** | **This feature exists to restore compliance.** Principle V requires CycloneDX 1.6 valid serialization; signed output currently violates it. The "standards-native fields take precedence" clause also governs the decision to drop the PEM rather than preserve it under a `waybill:` property. |
| **VII. Test Isolation** | PASS. Test keys are generated per-test into temp dirs; no shared fixture key material is committed. |
| **VIII. Completeness / IX. Accuracy / X. Transparency** | PASS. The feature removes an inaccuracy (a document claiming a signature consumers cannot find) and corrects the operator-facing coverage claim that documents the wrong slot. |

**No violations. Complexity Tracking section omitted — nothing to justify.**

Post-Phase-1 re-check: unchanged. The design adds no new abstraction, no
new crate, and no new configuration surface; the only new artifact is a
vendored schema fixture used by tests.

## Project Structure

### Documentation (this feature)

```text
specs/777-cdx-signature-conformance/
├── plan.md              # This file
├── spec.md              # Feature specification (19 FRs, 9 SCs, 3 stories)
├── research.md          # Phase 0 output — R1..R6
├── data-model.md        # Phase 1 output — E1..E5
├── quickstart.md        # Phase 1 output — reproduction + verification recipe
├── contracts/
│   └── signed-cdx-document.md
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 output (/speckit.tasks — NOT created here)
```

### Source Code (repository root)

```text
waybill-cli/
├── src/
│   ├── sbom/
│   │   └── signer.rs                     # US1: signature placement, JWK
│   │                                     #      derivation, key-type match,
│   │                                     #      algorithm derivation, module
│   │                                     #      doc correction
│   └── cli/
│       └── scan_cmd.rs                   # US3: keyless + CycloneDX refusal at
│                                         #      argument-validation time
└── tests/
    ├── cisa_2026_signing.rs              # US1/US2/US3: assertions moved to the
    │                                     #      conformant shape; refusal tests
    └── fixtures/schemas/
        ├── cyclonedx-1.6.json            # existing, unchanged
        └── jsf-0.82.schema.json          # NEW: real JSF schema, replaces the
                                          #      permissive test stub

docs/
└── cisa-2026-coverage.md                 # US1/US3: row 2 + Appendix B —
                                          #      slot correction and scope
                                          #      correction for the keyless path
```

**Structure Decision**: Single Rust workspace, existing three-crate
layout, unchanged. All production changes are confined to two files in
`waybill-cli` — the signing module and the CLI argument-validation site.
`waybill-common` is untouched: the signature shape is an emission
concern with no cross-crate type. Test changes are confined to one
integration test plus the signing module's own unit tests.

## Delivery Stages

Delivery follows the spec's story priorities. US1 is indivisible — the
two defects must be fixed together or the document remains invalid — so
it is not decomposed further at plan level.

Numbered independently of the task phases in `tasks.md` (which add a
setup and a foundational phase ahead of these, and a polish phase after).

| Stage | Story | Delivers |
|-------|-------|----------|
| 1 | US1 | Conformant signature: root placement, JWK public key, key-type match, derived algorithm |
| 2 | US2 | Gate closure: vendored JSF schema, signed-document validation, assertions moved off the old shape |
| 3 | US3 | Keyless refusal at argument-validation time; SPDX-only keyless still succeeds |
| 4 | — | Documentation: module doc, CISA coverage row 2 and Appendix B, follow-up issue for keyless conformance |

Stage 2 depends on Stage 1 only in the sense that the gate would fail
against pre-fix output — which is the point, and is how SC-003 is
demonstrated.

## Risks

| Risk | Mitigation |
|------|-----------|
| Relocating the slot changes the signed byte range, so a canonicalization mistake produces signatures that verify against nothing | Round-trip verification is an acceptance scenario (US1 #5/#6), not an afterthought; tamper-detection coverage must not regress (SC-005) |
| The gate passes while still being blind to the public-key defect | Research R2 identified the permissive JSF stub as the cause; SC-003 requires demonstrating failure on each defect reintroduced separately, which a stubbed gate cannot do |
| Golden-file churn from an unrelated emission change | Unsigned output is byte-identical by construction (FR-012); SC-004 asserts zero golden files change, which is a cheap early signal if something leaked |
| A blanket base64 change breaks SPDX signing | The same `BASE64_STD` alias encodes both the CycloneDX signature and the DSSE sidecar, and DSSE mandates the standard alphabet. T014 and T022 name the exact lines to change and the exact lines to leave alone; SC-010 checks both alphabets in one run |
| Keyless refusal breaks existing scripts | Intentional and recorded in spec Assumptions; the output those scripts produce today is invalid and reads as unsigned to conforming consumers |

## Notes on the local environment

`target/` was cleaned during the session preceding this plan, so the
first build on this branch is from scratch and the first pre-PR run will
be substantially slower than usual. This is expected and is not a
symptom of the change.
