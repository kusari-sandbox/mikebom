# Tasks: Keyless CycloneDX Signing via Detached Sidecar

**Input**: Design documents from `/specs/778-keyless-cdx-sidecar/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Test tasks ARE included. FR-014 and SC-007 are explicitly test-shaped, and the project constitution makes the clippy + full-suite gate mandatory.

**Organization**: Grouped by user story. Within that, ordered so every task verifiable **without a signing identity** comes before the ones that need one (research R7) — progress must not be gated on credentials.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on incomplete work)
- **[Story]**: US1 / US2 / US3 per spec.md
- **🔑**: Requires a live signing identity — cannot be completed or verified without one
- Exact file paths on every task

## Path Conventions

Single Rust workspace. Production changes in `waybill-cli/src/`; tests in `waybill-cli/tests/`.

---

## Phase 1: Setup

**Purpose**: Establish the pre-change baseline so later claims are measured, not assumed.

- [X] T001 Record current behaviour of `--sign` with CycloneDX by running the `waybill --offline sbom scan --path <fixture> --format cyclonedx-json --sign --output out.cdx.json` invocation from `specs/778-keyless-cdx-sidecar/quickstart.md` §A1, confirming the non-zero exit and absent output file that milestone 777 introduced
- [X] T002 Record current behaviour of keyless SPDX by running quickstart §A2 against `waybill-cli/tests/cisa_2026_signing.rs`'s scan target — this is the control for FR-010 and must be identical after the change
- [X] T003 Record current static-key CycloneDX output by running `specs/778-keyless-cdx-sidecar/quickstart.md` §A3, capturing the emitted document so SC-006 byte-identity can be checked against it later

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Name the shared signer honestly before two formats depend on it. Research R1 found it byte-generic already; only its name says otherwise, and a stale name is what produced milestone 777's false "waybill never emits signed BOMs" comment.

**⚠️ BLOCKS US1.**

- [X] T004 Rename `sign_spdx_bytes_to_sidecar` in `waybill-cli/src/sbom/signer.rs:367` to a format-neutral name reflecting that it signs arbitrary emitted-SBOM bytes, updating its doc comment to state that it is used by both the SPDX and CycloneDX keyless paths
- [X] T005 Update the existing call site of the renamed function in `waybill-cli/src/cli/scan_cmd.rs` (SPDX sidecar branch, ~line 4558) and any test references, confirming SPDX behaviour is unchanged by compiling and running `cargo +stable test --test cisa_2026_signing`
- [X] T006 Confirm the keyless refusal inside `sign_cdx_document_in_place` in `waybill-cli/src/sbom/signer.rs` is left intact, adding a comment recording that it remains correct as the *in-document* signer's guard and that milestone 778 routes around it rather than removing it (research R4, data-model INV-10)

**Checkpoint**: SPDX signing still passes; the signer is honestly named; the in-document guard is documented as deliberate.

---

## Phase 3: User Story 1 — Keyless signing works for CycloneDX again (Priority: P1) 🎯 MVP

**Goal**: A keyless-signed CycloneDX run succeeds, writing a valid document and a companion signature artifact beside it.

**Independent Test**: Run quickstart §B1 with a signing identity — command succeeds, both files written, signature verifies. Without an identity, verify via T010/T011 that the refusal is gone and the run reaches the signing attempt rather than being rejected up front.

### Remove the refusal and route to the sidecar

- [X] T007 [US1] Remove the milestone-777 keyless+CycloneDX refusal block in `waybill-cli/src/cli/scan_cmd.rs` (~lines 2980-3005, the `anyhow::bail!` whose message begins "--sign (Sigstore keyless) cannot currently produce a conformant"), leaving the surrounding stdout-rejection and dispatch logic untouched (FR-001)
- [X] T008 [US1] Add a keyless-CycloneDX branch at the write boundary in `waybill-cli/src/cli/scan_cmd.rs` (~line 4519, alongside the existing `fmt == "cyclonedx-json"` signing case) that writes the document verbatim and then signs it to a companion artifact — mirroring the SPDX branch at ~line 4552, NOT the in-document branch. The existing CycloneDX case must remain and handle static keys only (FR-001, FR-002, data-model E3)
- [X] T009 [US1] Ensure the companion artifact is produced from the **exact bytes written to disk**, passing the same buffer to the signer in `waybill-cli/src/cli/scan_cmd.rs` that was passed to `write_bytes_to` (~line 4536), as the SPDX branch at ~line 4558 already does (FR-004a). Do NOT canonicalize — the in-document path's `canonical_json_bytes` treatment must not be applied here (research R2)
- [X] T010 [US1] Derive the companion artifact's path with the existing `sidecar_extension_for` helper in `waybill-cli/src/cli/scan_cmd.rs:5049` rather than a new rule, so CycloneDX inherits the SPDX naming convention by construction (FR-006)
- [X] T011 [US1] Register the companion artifact with the fail-close cleanup tracker in `waybill-cli/src/cli/scan_cmd.rs` alongside the document, so a signing failure leaves neither file (FR-008, SC-004, INV-3)

### Verify without an identity

- [X] T012 [US1] Replace `m777_keyless_with_cyclonedx_is_refused_and_writes_nothing` in `waybill-cli/tests/cisa_2026_signing.rs:179` with a test asserting the refusal is gone — that keyless + CycloneDX now reaches the signing attempt and fails for want of an identity rather than being rejected from the arguments alone
- [X] T013 [P] [US1] Confirm `m777_keyless_with_spdx_only_is_not_refused` in `waybill-cli/tests/cisa_2026_signing.rs:204` still passes unchanged — SPDX keyless must be unaffected (FR-010). Note: this does NOT satisfy SC-008, which requires both formats in one invocation — see T017
- [X] T014 [P] [US1] Add a test in `waybill-cli/tests/cisa_2026_signing.rs` asserting the static-key CycloneDX path is untouched: signature still inside the document, no companion artifact written, no signature reference present (FR-009, SC-006)

### Verify with an identity

- [ ] T015 🔑 [US1] Add a test in `waybill-cli/tests/cisa_2026_signing.rs`, gated behind `WAYBILL_TEST_KEYLESS=1`, asserting a keyless CycloneDX run writes both the document and the companion artifact, and that the document validates against the CycloneDX schema via `common::cdx_schema::cdx_validation_errors` with zero errors (FR-003, SC-001)
- [ ] T016 🔑 [US1] Add a test in `waybill-cli/tests/cisa_2026_signing.rs` asserting the companion artifact verifies against the document, and fails after any byte of the document is altered (FR-004, FR-005, SC-002, SC-003)
- [ ] T017 🔑 [US1] Add a test in `waybill-cli/tests/cisa_2026_signing.rs` asserting that a single keyless invocation requesting BOTH `cyclonedx-json` and `spdx-2.3-json` produces two companion artifacts, each named from its own document and each verifying against that document and not the other. This is the case FR-007 and SC-008 describe and the spec lists as an edge case; it is ordinary usage (one CI step emitting both formats) and is where a per-format artifact could most easily be mis-associated (FR-007, SC-008)

**Checkpoint**: US1 is independently deliverable. Keyless CycloneDX produces a verifiable artifact.

---

## Phase 4: User Story 2 — A CycloneDX document says where its signature is (Priority: P2)

**Goal**: The document records that a signature exists and names the companion artifact.

**Independent Test**: Quickstart §A5 — copy document and artifact to a different directory, resolve the reference relative to the document, confirm it locates the artifact. Needs no signing identity once the reference is being emitted.

- [X] T018 [US2] Add a helper in `waybill-cli/src/cli/scan_cmd.rs` that injects a document-level external reference of the attestation type into emitted CycloneDX bytes, taking the companion artifact's path and emitting only its **bare filename** with no directory component (FR-012, FR-012a, INV-5)
- [X] T019 [US2] Call the T018 helper at the write boundary in `waybill-cli/src/cli/scan_cmd.rs` **before** the document is written, so the reference is inside the bytes that get signed (FR-013, INV-6). Injection must not touch the builder — it does not know the output path (research R3)
- [X] T020 [US2] Confirm the reference carries no checksum of the companion artifact, adding a comment in `waybill-cli/src/cli/scan_cmd.rs` recording the circularity that makes one impossible (INV-7) — the artifact signs the document that would contain its hash
- [X] T021 [US2] Confirm the T018 helper in `waybill-cli/src/cli/scan_cmd.rs` is invoked only from the keyless CycloneDX branch, so unsigned and static-key output are unchanged (FR-011, INV-8), verified against the T003 baseline document
- [X] T022 [P] [US2] Add a test in `waybill-cli/tests/cisa_2026_signing.rs` asserting the emitted reference names a bare filename with no directory separator, and that resolving it relative to the document's directory locates the companion artifact after both files are moved elsewhere (SC-009)
- [X] T023 [P] [US2] Add a test in `waybill-cli/tests/cisa_2026_signing.rs` asserting a document carrying the reference still validates against the CycloneDX schema with zero errors (US2 acceptance scenario 3)
- [ ] T024 🔑 [US2] Add a test in `waybill-cli/tests/cisa_2026_signing.rs` verifying the signature validates on a document carrying the reference, proving the injection happens before signing rather than after (US2 acceptance scenario 5)

**Checkpoint**: A consumer holding only the document can tell a signature exists.

---

## Phase 5: User Story 3 — The superseded keyless tests cover the new path (Priority: P3)

**Goal**: Restore the regression coverage milestone 777 had to disable.

**Independent Test**: Run the keyless test set with an identity available; it exercises the sidecar path and passes. Without an identity, confirm no test in the suite asserts an in-document keyless signature.

- [ ] T025 🔑 [US3] Retarget `us2b_keyless_bundle_sign_and_verify` in `waybill-cli/tests/cisa_2026_signing.rs:690` from the removed in-document embedding to the companion-artifact path, and remove its SUPERSEDED ignore reason (FR-014)
- [ ] T026 🔑 [US3] Retarget `us2b_keyless_fr016_info_log_fields_m222` in `waybill-cli/tests/cisa_2026_signing.rs:756` to assert the diagnostic fields emitted on the sidecar path, and remove its SUPERSEDED ignore reason (FR-014)
- [ ] T027 🔑 [US3] Retarget `us2b_keyless_signature_covers_document_mutation_m222` in `waybill-cli/tests/cisa_2026_signing.rs:818` to detect tampering via the companion artifact, and remove its SUPERSEDED ignore reason (FR-014)
- [X] T028 [US3] Remove the "SUPERSEDED BY MILESTONE 777" banner comment above those three tests in `waybill-cli/tests/cisa_2026_signing.rs`, since the behaviour it describes as removed now exists again in a new shape
- [X] T029 [US3] Confirm `us2b_keyless_no_oidc_token_fails_close_m222` and `us2b_keyless_signing_failure_cleans_up_output_m222` remain on SPDX in `waybill-cli/tests/cisa_2026_signing.rs` — they exercise identity acquisition and cleanup, which are format-independent, and moving them back to CycloneDX would re-couple them for no gain (research R6)
- [X] T030 [US3] Grep `waybill-cli/` for any remaining assertion that keyless signing embeds a signature in a CycloneDX document and confirm zero hits outside historical spec documents (FR-014, SC-007)

---

## Phase 6: Polish & Cross-Cutting Concerns

- [X] T031 Add the FR-016 operator summary in `waybill-cli/src/cli/scan_cmd.rs` near the existing per-artifact log at ~line 4547, recording each signed format and its companion artifact's path (SC-010)
- [X] T032 [P] Update `docs/cisa-2026-coverage.md` row 2: the CycloneDX column currently states keyless is refused; it now produces a companion artifact. Correct both the behaviour claim and the scope claim added in milestone 777 (FR-015)
- [X] T033 [P] Update the keyless verification recipe in `docs/cisa-2026-coverage.md` Appendix B, which milestone 777 retargeted to SPDX, so it shows the CycloneDX path alongside it (FR-015)
- [X] T034 [P] Update the "SUPERSEDED IN PART BY MILESTONE 777" banner in `specs/222-sigstore-keyless-signing/contracts/keyless-signing-flow.md` — its CycloneDX contract is superseded again, this time by a working sidecar shape rather than a refusal
- [X] T035 Decide the parity-catalog question carried in `specs/778-keyless-cdx-sidecar/plan.md`: either add a `Directionality::CdxOnly` row for the signature reference to `docs/reference/sbom-format-mapping.md` plus a matching extractor in `waybill-cli/src/parity/extractors/mod.rs`, or record in the plan why the catalog stays scoped to parity-relevant fields. Not gate-forced either way (research R5)
- [X] T036 If T035 adds a row, document it against the existing C47 `attestation`-typed reference in `docs/reference/sbom-format-mapping.md` so a reader encountering two attestation references in one document can tell an identifier binding from a signature pointer (research R5)
- [X] T037 Verify unsigned output is byte-identical by running the full golden-file suite and confirming zero golden files change (FR-011, SC-005)
- [X] T038 Run the mandatory pre-PR gate — `cargo +stable clippy --workspace --all-targets` then `cargo +stable test --workspace --no-fail-fast` — and enumerate every `^---- .+ stdout ----` line before claiming green
- [ ] T039 🔑 Run the identity-gated suite with `WAYBILL_TEST_KEYLESS=1 cargo +stable test --test cisa_2026_signing` and confirm the three retargeted tests pass (SC-007)

---

## Dependencies & Execution Order

```
Phase 1 (Setup: T001-T003)
        │
        ▼
Phase 2 (Foundational: T004-T006)  ⚠️ BLOCKS US1
        │
        ├──────────────► Phase 3 (US1: T007-T016)  🎯 MVP
        │                        │
        │                        ▼
        │                Phase 4 (US2: T018-T024)  — needs US1's sidecar path to name
        │                        │
        │                        ▼
        │                Phase 5 (US3: T025-T030)  — needs the new path to test against
        │                                 │
        └─────────────────────────────────┴──► Phase 6 (Polish: T031-T039)
```

**Story independence**: US2 and US3 both depend on US1 — there is no companion artifact to point at or to test until it exists. This feature is more sequential than milestone 777, where US3 was genuinely independent.

**Within-story ordering**: T007→T008 (remove the refusal before adding the branch it blocked); T008→T009→T010→T011 (branch, then payload, then path, then cleanup); T018→T019 (helper before its call site).

## Identity-Gated Work

Seven tasks are marked 🔑 and cannot be completed without a live signing identity: T015, T016, T024, T025, T026, T027, T039. Everything else — 31 of 38 tasks — is completable and verifiable without one.

This split is the point of the ordering. Build and verify the identity-free set first; when an identity becomes available the only open questions are end-to-end verification and the three retargeted tests. Do not stub the identity-gated work: a stubbed keyless test passes while proving nothing, which is worse than an honestly skipped one.

## Parallel Execution Opportunities

- **Phase 3**: T013 and T014 are marked [P] — different test functions, no shared state.
- **Phase 4**: T022 and T023 are marked [P] — different test functions.
- **Phase 6 docs**: T032, T033, T034 are marked [P]. T032 and T033 touch the same file in different sections; sequence them if edits conflict.
- T008 through T011 all edit the same write-boundary region of `scan_cmd.rs` and must NOT be parallelized despite being conceptually separate.

## Implementation Strategy

**MVP = Phase 1 + Phase 2 + Phase 3 (US1).** That restores the capability. US2 and US3 add discoverability and regression coverage.

**Recommended sequencing given the identity constraint**: complete every non-🔑 task through Phase 4, run the gate, and open the work for review at that point. The identity-gated tasks are then a bounded, clearly-labelled remainder rather than a blocker on the whole milestone.

**Suggested first checkpoint**: stop after T006 and confirm SPDX signing still passes. The signer rename touches a function both formats will depend on; if SPDX breaks there, nothing downstream is trustworthy.
