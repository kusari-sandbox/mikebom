# Tasks: CycloneDX Signature Conformance

**Input**: Design documents from `/specs/777-cdx-signature-conformance/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Test tasks ARE included. US2 is entirely a test/gate story, and the
project constitution makes `cargo +stable test --workspace` +
`cargo +stable clippy --workspace --all-targets` a mandatory gate.

**Organization**: Grouped by user story so each is independently
implementable and testable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on incomplete work)
- **[Story]**: US1 / US2 / US3 per spec.md
- Exact file paths included in every task

## Path Conventions

Single Rust workspace, three crates. All production changes land in
`waybill-cli/src/`; tests in `waybill-cli/tests/` and in-module `#[cfg(test)]`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the pre-change baseline so every later claim is measured, not assumed.

- [X] T001 Rebuild the workspace from scratch (`target/` was cleaned) via `cargo +stable build --all-targets` at the repository root, and record the wall time so the first slow pre-PR run is not mistaken for a regression
- [X] T002 Reproduce both defects on the current code following `specs/777-cdx-signature-conformance/quickstart.md` steps 1–3, and record the observed `root_sig: false` / `meta_sig: true` result as the pre-change baseline

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The real JSF schema is required before ANY conformance claim can be verified — US1 acceptance scenario 1 depends on it as much as US2 does. Per research R2, the existing harness stubs this reference with a permissive `{}` that would silently accept a malformed public key.

**⚠️ BLOCKS US1 and US2.**

- [X] T003 Vendor the upstream `jsf-0.82.schema.json` (draft-07) to `waybill-cli/tests/fixtures/schemas/jsf-0.82.schema.json`, matching the provenance convention used by the adjacent `cyclonedx-1.6.json` fixture (FR-008)
- [X] T004 Replace the permissive `jsf-0.82.schema.json` stub in `CdxStubRetriever` in `waybill-cli/tests/sbom_user_metadata.rs` with a load of the vendored file, and delete the now-false comment claiming "Waybill never emits signed BOMs" (FR-008, research R2)
- [X] T005 Add an explicit `.should_validate_formats(true)` to the CDX validator builder in `waybill-cli/tests/sbom_user_metadata.rs` as an intent marker, with a comment recording that the draft-07 default already enables it (research R1) and that a future 2020-12 schema bump would silently disable it
- [X] T006 Extract the CDX validator construction from `waybill-cli/tests/sbom_user_metadata.rs` into a shared test helper reachable from `waybill-cli/tests/cisa_2026_signing.rs`, so the signing tests validate against the same schema rather than a second copy (FR-008)

**Checkpoint**: A signed document can now be validated against the real schema, and doing so should FAIL on the current code with the `metadata` additional-properties error. Confirm that failure before proceeding — it is the proof the gate has teeth.

---

## Phase 3: User Story 1 — Signed CycloneDX output passes conformance validation (Priority: P1) 🎯 MVP

**Goal**: A signed document validates cleanly against CycloneDX 1.6 and consumers find the signature where the specification says it will be.

**Independent Test**: Sign a fixture scan with a locally generated P-256 key and validate the emitted document against the vendored CycloneDX 1.6 schema with the real JSF reference resolved; expect zero errors.

### Key-type and algorithm derivation

- [X] T007 [US1] Add a key-type resolution function in `waybill-cli/src/sbom/signer.rs` that matches on `SigStoreKeyPair` (`ECDSA(ECDSAKeys::P256)` accepted; `ECDSA(P384)`, `ED25519`, `RSA` refused) and returns both the accepted curve and its JWA algorithm identifier, so the declared algorithm is derived rather than assumed (FR-007, FR-019)
- [X] T008 [US1] Add an `SbomSigningError` variant in `waybill-cli/src/sbom/signer.rs` for an unsupported signing key type, carrying the detected type name so the operator diagnostic can name it (FR-007)
- [X] T009 [US1] Replace the hardcoded `let algorithm = KeyAlgorithm::EcdsaP256;` at `waybill-cli/src/sbom/signer.rs:276` with a call to the T007 resolver, propagating the T008 error for unsupported types (FR-007, FR-019)
- [X] T010 [US1] Narrow or remove the now-unreachable non-P256 arms of `signing_scheme_for` and `jwa_alg` in `waybill-cli/src/sbom/signer.rs`, eliminating the mapping in which an RSA key is labelled `RS256` while signed with an ECDSA scheme (research R4)

### JWK public-key emission

- [X] T011 [US1] Replace the `JsfPublicKey` struct in `waybill-cli/src/sbom/signer.rs` with a JWK shape carrying `kty`, `crv`, `x`, `y`, and update its doc comment, which currently records the PEM form as a deferred "US2b enhancement" (FR-003)
- [X] T012 [US1] Add a JWK-derivation function in `waybill-cli/src/sbom/signer.rs` that takes the keypair's `public_key_to_der()` SubjectPublicKeyInfo, extracts the uncompressed EC point, and emits `x` and `y` as unpadded base64url halves per RFC 7518 §6.2.1 (research R3; use the already-direct `x509-parser` / `pem` deps, no new crates) (FR-003)
- [X] T013 [US1] Replace the `export_public_key_pem` call site in `waybill-cli/src/sbom/signer.rs` with the T012 derivation, dropping the PEM and algorithm hint rather than relocating them (spec Assumptions; the JSF EC branch forbids additional properties) (FR-003)
- [X] T014 [US1] Switch the CycloneDX signature value encoding at `waybill-cli/src/sbom/signer.rs:314` from the `STANDARD` base64 engine to `URL_SAFE_NO_PAD` (already used at `waybill-cli/src/attestation/signer.rs:935`, so no new dependency). **Do NOT change lines 388 and 391**, which encode the DSSE sidecar payload and signature and must stay on the standard alphabet — the DSSE envelope format mandates it, and changing them would break FR-013 (FR-020)

### Signature relocation

- [X] T015 [US1] Move the static-key placeholder insertion at `waybill-cli/src/sbom/signer.rs:303` from `metadata` to the document root, preserving the placeholder-then-canonicalize-then-fill ordering (FR-001, FR-002, INV-3)
- [X] T016 [US1] Move the post-signature value fill at `waybill-cli/src/sbom/signer.rs:317-325` to read and mutate the root signature object rather than the metadata one (FR-001, FR-002)
- [X] T017 [US1] Move the pre-signing signature removal at `waybill-cli/src/sbom/signer.rs:248` to target the root slot, so re-signing leaves no residue in the previously used location (FR-006, INV-4)
- [X] T018 [US1] Correct the module doc at `waybill-cli/src/sbom/signer.rs:9`, which asserts `metadata.signature` is "native CDX 1.6" — the belief that produced the defect (FR-010)

### Verification

- [X] T019 [US1] Update the in-module unit tests in `waybill-cli/src/sbom/signer.rs` (lines ~552, ~572, ~574, ~648, ~657) to assert the root location and the JWK shape instead of `/metadata/signature` and `publicKey.pem` (FR-009)
- [X] T020 [US1] Add a test in `waybill-cli/tests/cisa_2026_signing.rs` that signs a fixture and validates the result against the vendored CycloneDX 1.6 schema via the T006 helper, asserting zero errors (FR-004, FR-008, FR-017, SC-001)
- [X] T021 [US1] Add a test in `waybill-cli/tests/cisa_2026_signing.rs` asserting the signature round-trips: verification succeeds on the unmodified document and fails when a content byte outside the signature is altered (FR-005, SC-005) — this is the check that proves the canonicalization ordering survived relocation
- [X] T022 [US1] Update the CycloneDX-side signature decoder in the `waybill-cli/src/sbom/signer.rs` unit tests (~line 652) to base64url, leave the DSSE payload decoder (~line 620) on the standard alphabet, and assert both in the same test run so neither path can be changed without the other being checked (FR-020, FR-013, SC-010)
- [X] T023 [US1] Add a test in `waybill-cli/tests/cisa_2026_signing.rs` that a non-P-256 key is refused with an error naming the key type and no output file is produced (FR-007, SC-009)

**Checkpoint**: US1 is independently deliverable. Signed output is conformant; the remaining stories add gate coverage and operator honesty.

---

## Phase 4: User Story 2 — The conformance gap cannot silently reopen (Priority: P2)

**Goal**: Any change that makes signed output non-conformant fails the gate.

**Independent Test**: Reintroduce each defect in turn and confirm the gate fails with a message identifying the offending location; restore and confirm it passes.

- [X] T024 [US2] Add a mutation-style test note (or a documented manual procedure) in `waybill-cli/tests/cisa_2026_signing.rs` recording how to reintroduce each defect to prove the gate has teeth, following the m775 precedent of deliberately implementing the naive fix to verify test sensitivity (SC-003)
- [X] T025 [US2] Verify by deliberate reintroduction that placing the signature under `metadata` fails the gate: temporarily revert T015 in `waybill-cli/src/sbom/signer.rs`, run the T020 test in `waybill-cli/tests/cisa_2026_signing.rs`, confirm failure identifies the `metadata` location, then restore (SC-003)
- [X] T026 [US2] Verify by deliberate reintroduction that a `publicKey` lacking `kty` fails the gate: temporarily emit the pre-fix PEM shape in `waybill-cli/src/sbom/signer.rs`, run the T020 test in `waybill-cli/tests/cisa_2026_signing.rs`, confirm failure identifies the offending property, then restore. This specifically proves the T003/T004 de-stubbing worked — the pre-change stub in `waybill-cli/tests/sbom_user_metadata.rs` would have passed it (SC-003, research R2)
- [X] T027 [US2] Grep `waybill-cli/` for any remaining assertion on `/metadata/signature` or `publicKey.pem` and confirm zero hits outside historical spec documents (FR-009, SC-006)

**Checkpoint**: The defect class is now gated.

---

## Phase 5: User Story 3 — The keyless signing path refuses rather than emitting invalid output (Priority: P3)

**Goal**: waybill stops producing CycloneDX output it knows to be invalid, and names the conformant alternative.

**Independent Test**: Invoke the keyless path requesting CycloneDX output; confirm non-zero exit, no file written, and an error naming `--sign-key`.

- [X] T028 [US3] Add an argument-validation rejection in `waybill-cli/src/cli/scan_cmd.rs` for `--sign` combined with a requested `cyclonedx-json` format, sited alongside the existing parse-time rejection of `--sign` with `--output -` (research R5, FR-014)
- [X] T029 [US3] Ensure the T028 rejection in `waybill-cli/src/cli/scan_cmd.rs` fires before the scan begins (ahead of the signing-mode construction at ~line 4408), so no partial output can exist even when several formats are requested in one invocation (FR-015, INV-10; the existing m221 fail-close cleanup tracker remains as defence in depth)
- [X] T030 [US3] Confirm the T028 guard in `waybill-cli/src/cli/scan_cmd.rs` is scoped to the CycloneDX format only, so the keyless path still succeeds when only SPDX formats are requested — SPDX signing routes through `sign_spdx_bytes_to_sidecar` in `waybill-cli/src/sbom/signer.rs` and is untouched (FR-016, SC-008)
- [X] T031 [P] [US3] Add a test in `waybill-cli/tests/cisa_2026_signing.rs` asserting keyless + CycloneDX exits non-zero, writes no file, and names the static-key alternative in its error (SC-007)
- [X] T032 [P] [US3] Add a test in `waybill-cli/tests/cisa_2026_signing.rs` asserting keyless + SPDX-only still succeeds (SC-008)
- [X] T033 [US3] Update the four `/metadata/signature` pointer assertions in `waybill-cli/tests/cisa_2026_signing.rs` (lines 107, 158, 262, 571), including any keyless-path assertions that must now expect refusal rather than an emitted document (FR-009)

**Checkpoint**: All three stories complete.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [X] T034 [P] Update `docs/cisa-2026-coverage.md` row 2: correct the slot from `metadata.signature` to the document root in the CycloneDX column, and correct the scope claim — the keyless path no longer emits CycloneDX at all, so "both signing paths ship" is no longer accurate for that column (FR-011)
- [X] T035 [P] Update the verification recipe in `docs/cisa-2026-coverage.md` row 2 and Appendix B from `jq .metadata.signature signed.cdx.json` to `jq .signature signed.cdx.json` (FR-011, contract C3)
- [X] T036 [P] Record the keyless CycloneDX limitation in `docs/cisa-2026-coverage.md` (row 2 CycloneDX column) and open a follow-up GitHub issue for keyless conformance, referencing the unresolved question of whether a Sigstore bundle can be expressed through JSF's `certificatePath` / `keyId` properties (FR-018)
- [X] T037 Review `specs/222-sigstore-keyless-signing/contracts/keyless-signing-flow.md`, whose CDX-embedded canonical-bytes contract references `metadata.signature`, and record that m777 supersedes it for the CycloneDX path
- [X] T038 Verify unsigned output is byte-identical: run the full golden-file suite and confirm zero golden files change (FR-012, SC-004). Any churn here means the change leaked outside the signing path
- [X] T039 Run the mandatory pre-PR gate — `cargo +stable clippy --workspace --all-targets` then `cargo +stable test --workspace --no-fail-fast` — and enumerate every `^---- .+ stdout ----` line before claiming green. FR-013 (SPDX signing unchanged) is evidenced here by the pre-existing SPDX sidecar tests in `waybill-cli/tests/cisa_2026_signing.rs` (`us2a_spdx23_dsse_sidecar_written_and_verifies` and its SPDX 3 sibling), which must remain green
- [X] T040 Re-score a signed document with `sbomqs` (binary path overridable via `WAYBILL_SBOMQS_BIN`, per `docs/user-guide/configuration.md`) and confirm `sbom_signature` is now non-zero where it previously scored 0.0 (SC-002). SC-002 itself stays tool-agnostic; this task names the tool only so it is independently executable

---

## Open Scope Question (raised during task generation — NOT yet covered by any FR)

**The signature value's base64 alphabet.** `waybill-cli/src/sbom/signer.rs:33`
imports `STANDARD as BASE64_STD` and encodes the signature value with it,
while the same file's doc comment at line 152 states *"base64url-encoded
signature bytes"*, and JSF describes `value` as following the JWA
(RFC 7518) binary representation, which is base64url.

This does **not** fail schema validation — JSF types `value` as a plain
string with no `pattern` or `format` — so it is invisible to FR-004 and
to the gate this feature builds. But a conforming JSF verifier decoding
base64url would reject any signature whose standard-base64 encoding
happens to contain `+` or `/`, which is most of them.

No FR covers this. It is therefore **not** included in the task list
above. It needs an explicit ruling: add an FR and a task, or defer it to
the follow-up alongside the keyless work. Deciding to fix it would add
roughly one task in the same file already being modified by T015–T017.

A related observation, already covered: JSF's `algorithm` enum requires
explicit `Ed*` names rather than `"EdDSA"`, so the existing
`jwa_alg(Ed25519) => "EdDSA"` mapping would also have been invalid. T010
removes it.

---

## Dependencies & Execution Order

```
Phase 1 (Setup: T001-T002)
        │
        ▼
Phase 2 (Foundational: T003-T006)  ⚠️ BLOCKS US1 and US2
        │
        ├──────────────► Phase 3 (US1: T007-T023)  🎯 MVP
        │                        │
        │                        ▼
        │                Phase 4 (US2: T024-T027)  — needs US1 to pass; needs Phase 2 to have teeth
        │
        └──────────────► Phase 5 (US3: T028-T033)  — independent of US1/US2
                                 │
                                 ▼
                         Phase 6 (Polish: T034-T040)
```

**Story independence**: US3 touches only `scan_cmd.rs` plus its own
tests and can proceed in parallel with US1. US2 depends on US1 landing
(the gate would otherwise fail on known-bad output) and on Phase 2
(without the real JSF schema it cannot detect the public-key defect).

**Within-story ordering**: T007→T009 (resolver before its call site);
T011→T012→T013 (shape before derivation before call site);
T015→T016 (placement before fill). T017, T018 are independent of those
chains.

## Parallel Execution Opportunities

- **Phase 5 tests**: T031 and T032 are marked [P] — different test functions, no shared state.
- **Phase 6 docs**: T034, T035, T036 are marked [P] — T034/T035 touch the same file but different sections; sequence them if edit conflicts arise.
- **Across stories**: US3 (T028–T033) can run concurrently with US1 (T007–T023); they share no files.
- T010 and T011 both edit `signer.rs` and must NOT be parallelized despite being conceptually separate.

## Implementation Strategy

**MVP = Phase 1 + Phase 2 + Phase 3 (US1).** That delivers the entire
user-visible fix: conformant signed output. Phases 4–6 add gate
durability and operator honesty but are not required for the defect to
be resolved.

**Incremental delivery**: US1 alone is shippable. US3 is independently
shippable and could land first if the misleading-output problem is
judged more urgent than the invalid-output problem — though US1 is the
larger correctness win.

**Suggested first checkpoint**: stop after T006 and confirm the gate
fails on current code. If it passes, the schema de-stubbing did not take
effect and everything downstream would be validated against a permissive
schema.
