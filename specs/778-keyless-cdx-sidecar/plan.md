# Implementation Plan: Keyless CycloneDX Signing via Detached Sidecar

**Branch**: `778-keyless-cdx-sidecar` | **Date**: 2026-09-06 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/778-keyless-cdx-sidecar/spec.md`

## Summary

Milestone 777 refused keyless signing for CycloneDX rather than emit a
document that was schema-invalid while advertising itself as signed.
This feature gives that operator a working path: the signature travels
beside the document as a detached bundle — the shape SPDX already uses
and the shape existing verification tooling already understands.

The work is mostly routing. The signer is byte-generic, the sidecar
path-derivation helper is target-generic, and the write boundary
already has a branch that writes a document then signs the bytes it
wrote. Keyless CycloneDX joins that branch. What is genuinely new is a
document-level reference naming the companion artifact, injected at the
write boundary because only there is the output path known.

**Zero new Cargo dependencies. No new production files.**

## Technical Context

**Language/Version**: Rust stable (workspace toolchain inherited from milestones 001–777; no nightly)
**Primary Dependencies**: Existing only — `sigstore` 0.11 (kusari-sandbox fork) for the keyless flow, `serde`/`serde_json` (document parse + re-serialize at the write boundary), `tracing` (FR-016 summary), `anyhow`/`thiserror`. Dev/test: existing `jsonschema` 0.46 plus milestone 777's shared CycloneDX validator at `waybill-cli/tests/common/cdx_schema.rs`. **Zero new Cargo dependencies** (research R1).
**Storage**: N/A — two files written per signed run; no caches, no persistence.
**Testing**: `cargo +stable clippy --workspace --all-targets` + `cargo +stable test --workspace`, per the mandatory pre-PR gate. Identity-dependent coverage runs only under `WAYBILL_TEST_KEYLESS=1` in its dedicated CI job.
**Target Platform**: All supported hosts. Signing is user-space; no eBPF surface touched.
**Project Type**: CLI / library — single Rust workspace, three crates.
**Performance Goals**: N/A. One additional file write and one parse/re-serialize per signed run.
**Constraints**: Unsigned output byte-identical (FR-011); static-key CycloneDX byte-identical to its post-777 form (SC-006); SPDX signing untouched (FR-010); no new dependencies.
**Scale/Scope**: One CLI write-boundary branch, one reference-injection helper, one signer rename, one test file, two documents.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design.*

| Principle | Assessment |
|-----------|-----------|
| **I. Pure Rust, Zero C** | PASS. No new dependencies. |
| **III. Fail Closed** | PASS. A signing failure leaves neither file (FR-008), reusing the existing fail-close cleanup. The feature also *removes* a refusal — but it replaces it with a working path, not with silent degradation, which is the distinction the principle's rationale draws. |
| **IV. Type-Driven Correctness** | PASS. The routing change is a match arm at the write boundary; the in-document signer keeps its keyless refusal so the invalid combination stays unrepresentable for any other caller. |
| **V. Specification Compliance** | PASS, and this is the feature's point. The emitted document stays schema-valid because the signature is no longer inside it (FR-003). The signature reference uses a standards-native external-reference type rather than a `waybill:` property, per the standards-native-first clause. |
| **VII. Test Isolation** | PASS. Identity-dependent tests stay behind the existing env-var gate so the default suite remains hermetic. |
| **IX. Accuracy / X. Transparency** | PASS. The document gains a truthful record that a signature exists and where. The spec explicitly declines to claim more than that — see the note on quality scorers. |

**No violations. Complexity Tracking section omitted — nothing to justify.**

Post-Phase-1 re-check: unchanged. One judgment call surfaced (R5, the
parity catalog row) and is carried as a scope decision below rather
than a constitution concern.

## Project Structure

### Documentation (this feature)

```text
specs/778-keyless-cdx-sidecar/
├── plan.md              # This file
├── spec.md              # 18 FRs, 10 SCs, 3 stories
├── research.md          # Phase 0 — R1..R7
├── data-model.md        # Phase 1 — E1..E4
├── quickstart.md        # Phase 1 — split into identity-free and identity-dependent halves
├── contracts/
│   └── keyless-cdx-sidecar.md
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 output (/speckit.tasks — NOT created here)
```

### Source Code (repository root)

```text
waybill-cli/
├── src/
│   ├── sbom/
│   │   └── signer.rs          # rename the byte-generic sidecar signer off its
│   │                          # SPDX-specific name; keyless in-document refusal
│   │                          # stays untouched
│   └── cli/
│       └── scan_cmd.rs        # remove the m777 keyless+CDX refusal; route
│                              # keyless CDX to the sidecar branch; inject the
│                              # signature reference before writing; FR-016 summary
└── tests/
    └── cisa_2026_signing.rs   # retarget 3 superseded tests; replace the
                               # refusal test; keep the SPDX-only control

docs/
└── cisa-2026-coverage.md      # row 2 + Appendix B — keyless CDX works again,
                               # in a new shape

specs/222-sigstore-keyless-signing/
└── contracts/keyless-signing-flow.md   # its m777 supersession banner is now
                                        # itself out of date
```

**Structure Decision**: Unchanged workspace layout. Production changes
are confined to two files in `waybill-cli`. `waybill-common` is
untouched — the signature reference is an emission concern with no
cross-crate type.

## Delivery Stages

Numbered independently of the task phases in `tasks.md`.

| Stage | Story | Delivers |
|-------|-------|----------|
| 1 | US1 | Keyless CycloneDX succeeds: document written, companion artifact beside it |
| 2 | US2 | The document records where its signature lives |
| 3 | US3 | The three superseded tests cover the new path |
| 4 | — | Documentation, and the parity-catalog decision below |

Stage 1 and Stage 2 are separable but should land together: a signed
document with no reference is indistinguishable from an unsigned one,
which is the gap US2 exists to close.

## Scope decision carried into tasks — RESOLVED

**Parity catalog row for the signature reference: NOT added.**

Research R5 established no gate requires one. Implementation surfaced
two further facts that turn a preference into a decision:

1. **The parity harness scans unsigned.** Its fixtures never carry a
   signature reference, because nothing in that path signs. A catalog
   row would therefore be evaluated against documents that structurally
   cannot contain the field it describes.
2. **`CdxOnly` rows are inert in the current gate.** The arm in
   `assert_holistic_parity` discards both SPDX sets and asserts nothing:
   `let _ = (&spdx23_set, &spdx3_set);`. So the row would add catalog
   prose and zero verification.

Adding it would mean documenting a mapping the gate cannot check, for a
field the gate's inputs never contain. The catalog's job is cross-format
mapping; a signature-location pointer that exists on one signing path in
one format is emission detail, and it is documented in this feature's
contract instead.

**Side observation, not fixed here**: `Directionality::CdxOnly`'s doc
comment in `waybill-cli/src/parity/extractors/common.rs` states the
check "asserts only that the CDX side is non-empty." The implementation
asserts nothing at all. That discrepancy predates this feature and
affects any existing `CdxOnly` row (C42 among them), which may be
weaker than its documentation implies. Worth a look independently of
this milestone.

## Risks

| Risk | Mitigation |
|------|-----------|
| Canonicalizing before signing by analogy with the in-document path in the same file, breaking `cosign verify-blob` | FR-004a states the requirement; research R2 and the quickstart both name it as the primary trap; the SPDX branch is the worked example to copy |
| The reference is added after signing, invalidating it | Injection happens at the write boundary before the write, and the written bytes are the signed bytes — ordering is structural, not conventional (R3) |
| A checksum is added to the reference | Circular by construction; recorded in the spec, data model, contract and quickstart because the idea is attractive until attempted |
| Acceptance blocked on identity availability | Quickstart splits identity-free from identity-dependent checks so the former can be completed and reviewed first (R7) |
| Generalizing the signer regresses SPDX | SPDX keyless is the control case, unchanged and covered by existing tests; SC-006 and FR-010 make the expectation explicit |

## Note on the environment

Acceptance of FR-004, FR-005 and FR-014 requires a live signing
identity. This is not a planning gap — it is the same constraint that
caused milestone 777 to defer this work rather than guess at it. Every
other requirement is verifiable without one, and the task ordering
should reflect that so progress is not gated on credentials.
