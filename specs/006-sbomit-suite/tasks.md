---
description: "Task list for feature 006-sbomit-suite"
---

# Tasks: SBOMit compliance suite

**Input**: Design documents from `/specs/006-sbomit-suite/`
**Prerequisites**: `plan.md` ✓, `spec.md` ✓, `research.md` ✓, `data-model.md` ✓, `contracts/cli.md` ✓, `contracts/attestation-envelope.md` ✓, `quickstart.md` ✓

**Tests**: Tests ARE included below — the existing mikebom codebase enforces test coverage as a constitutional norm (Principle VII). Unit tests stay inline in each module; integration tests land in `mikebom-cli/tests/`.

**Organization**: Tasks are grouped by user story. Each story can be implemented + tested independently. Within a story: types → core logic → CLI wiring → tests.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Maps to a user story from `spec.md` (US1…US5)
- Exact file paths included in every task description
- All paths are absolute from `/Users/mlieberman/Projects/mikebom/`

## Path conventions

- User-space crate: `mikebom-cli/src/**`
- Shared crate: `mikebom-common/src/**`
- Integration tests: `mikebom-cli/tests/**`

No new crates per Constitution Principle VI.

---

## Phase 1: Setup (shared infrastructure)

**Purpose**: Workspace dependency additions + dep audit before any new code lands.

- [X] T001 Add `sigstore = { version = "0.10", default-features = false, features = ["sigstore-trust-root", "cosign", "rekor", "bundle"] }` to `mikebom-cli/Cargo.toml` `[dependencies]`. Do NOT enable `native-tls` features — rely on the existing `rustls-tls` posture. See `specs/006-sbomit-suite/research.md` R1 for the feature-set rationale.
- [X] T002 Add `json-patch = "3"` to `mikebom-cli/Cargo.toml` `[dependencies]` (used only by the P3 enrichment work; deferred file impact is minimal but the dep belongs with the rest of this feature's dependency additions).
- [X] T003 [P] Add `base64 = "0.22"` to `mikebom-common/Cargo.toml` `[dependencies]` (already present in `mikebom-cli/Cargo.toml:21` — mirror to common for envelope serialization). Verify with `cargo tree -p mikebom-common`.
- [X] T004 **Constitution Principle I audit**: run `cargo tree -p mikebom -e normal` after T001–T003 and confirm zero new `-sys` crates that invoke a C compiler. Scan for `openssl-sys`, `libz-sys`, `native-tls`, `c-bindings`, `bindgen`. If any appear, return to T001 and narrow `sigstore` features further before proceeding.
- [X] T005 [P] Update `docs/architecture/attestations.md` "Known gaps" section to remove the "Attestation signing isn't wired yet" item (it will become done in Phase 4). Add a "v006 in progress" note. This is documentation-only and does not block anything.

---

## Phase 2: Foundational (blocking prerequisites)

**Purpose**: Shared types + error enums + module scaffolding that every user story below depends on. MUST complete before any `[US*]`-labelled task begins.

**⚠️ CRITICAL**: User stories 1–5 all depend on the `SignedEnvelope` + `Signature` + `IdentityMetadata` types landing first.

- [X] T006 Create `mikebom-common/src/attestation/envelope.rs` with `SignedEnvelope`, `Signature`, `IdentityMetadata` (enum: `Certificate` | `PublicKey`), `RekorBundle`, and `InclusionProof` types per `specs/006-sbomit-suite/data-model.md`. Derive `Serialize`, `Deserialize`, `Clone`, `Debug`, `PartialEq`. Unit tests for round-trip JSON serialization inline in a `#[cfg(test)] mod tests` block. (`KeyAlgorithm` enum is defined separately in T008.)
- [X] T007 Re-export `envelope` module from `mikebom-common/src/attestation/mod.rs` and `mikebom-common/src/lib.rs` so downstream crates can `use mikebom_common::attestation::envelope::SignedEnvelope`.
- [X] T008 [P] Define `KeyAlgorithm` enum (`EcdsaP256`, `Ed25519`, `RsaPkcs1`) with `FromStr` + `Display` + `Serialize`/`Deserialize` (via `#[serde(rename_all = "kebab-case")]`) in `mikebom-common/src/attestation/envelope.rs`. Unit tests for unknown-algorithm rejection.
- [X] T009 Create `mikebom-cli/src/attestation/signer.rs` skeleton with `SigningIdentity` enum (`None` | `LocalKey { path, passphrase_env }` | `Keyless { fulcio_url, rekor_url, oidc_provider, transparency_log }`) and `OidcProvider` enum (`GitHubActions` | `Explicit` | `Interactive`). Include the `SigningError` `thiserror` enum with all variants from `data-model.md`. No actual signing logic yet — types + error plumbing only.
- [X] T010 Create `mikebom-cli/src/attestation/verifier.rs` skeleton with `VerificationReport`, `FailureMode` (all 9 variants from `data-model.md`), and `SignerIdentityInfo` types. `VerificationError` `thiserror` enum. No verification logic yet.
- [X] T011 Create `mikebom-cli/src/attestation/subject.rs` skeleton with `Subject` enum (`Artifact { name, digest }` | `Synthetic { command_summary, synthetic_digest }`) and `SubjectResolver` struct (empty impl). Unit test for canonical JSON serialization of each variant.
- [X] T012 Add `pub mod signer; pub mod verifier; pub mod subject;` to `mikebom-cli/src/attestation/mod.rs`. Gate compilation by ensuring `cargo check --bin mikebom` passes before moving to Phase 3.
- [X] T013 [P] Canonical JSON helper: add `canonical_json_bytes<T: Serialize>(t: &T) -> Result<Vec<u8>, SerializationError>` to `mikebom-common/src/attestation/envelope.rs` that serializes with deterministic key ordering (use `BTreeMap` upstream or `serde_json::to_vec` with key sorting). Unit test for byte-level determinism across runs.
- [X] T014 [P] DSSE PAE (Pre-Authenticated Encoding) helper in `mikebom-common/src/attestation/envelope.rs`: `dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8>` per the DSSE spec (length-prefixed concatenation). Unit tests with the DSSE spec's reference test vectors.

**Checkpoint**: `cargo check --workspace` + `cargo test --workspace` both pass. User stories 1–5 unblocked.

---

## Phase 3: User Story 1 — Downstream verifier accepts mikebom attestations (P1) 🎯 MVP

**Goal**: Stand up `mikebom sbom verify` as a working subcommand that can validate DSSE-wrapped in-toto attestations against a public key, a Fulcio identity pattern, and optionally an in-toto layout. Independently testable against *externally* signed attestations (e.g., from `cosign`/`witness`) — doesn't require US2/US3 to be complete.

**Independent Test**: Hand a `cosign`-signed DSSE envelope to `mikebom sbom verify --public-key cosign.pub` and confirm it returns `Pass`; hand a tampered envelope and confirm `SignatureInvalid`.

### Tests for User Story 1

- [X] T015 [P] [US1] Unit tests for `FailureMode` → exit-code mapping in `mikebom-cli/src/cli/verify.rs::tests`: every `FailureMode` variant maps to the documented exit code per `contracts/cli.md`.
- [~] T016 [P] [US1] Integration test scaffold — tests are in-crate under `mikebom-cli/src/attestation/verifier.rs::tests` (not `mikebom-cli/tests/`) because `mikebom` is a binary crate without a lib target; shelling out to the binary is covered by the smoke test in the module-level docs. Synthesized envelopes cover valid-local-key, tampered-payload, raw-statement, and missing-field cases.

### Implementation for User Story 1

- [X] T017 [US1] Envelope parsing in `mikebom-cli/src/attestation/verifier.rs::parse_envelope`: validate top-level shape (`payloadType`, `payload`, `signatures[]` all required), base64-decode payload, deserialize into `InTotoStatement`. Returns `FailureMode::MalformedEnvelope` on shape errors, `FailureMode::NotSigned` when the file is a raw Statement (no envelope wrapper).
- [X] T018 [US1] Signature verification in `mikebom-cli/src/attestation/verifier.rs::verify_signature`: DSSE PAE computation (reuse T014 helper), then per-signature verify against either `IdentityMetadata::PublicKey` (local) or `IdentityMetadata::Certificate` (keyless). Uses sigstore-rs `CosignVerificationKey::from_pem` + `verify_signature` primitives (the `cosign::verify` surface wraps these internally). Returns `FailureMode::SignatureInvalid` on failed verify, `FailureMode::TrustRootInvalid` on bad cert chain.
- [X] T019 [US1] Subject digest check in `mikebom-cli/src/attestation/verifier.rs::verify_subjects`: for each `--expected-subject <PATH>` flag, hash the on-disk file with SHA-256 and compare against the attestation's subject digests. Returns `FailureMode::SubjectDigestMismatch` on mismatch.
- [X] T020 [US1] Identity matcher in `mikebom-cli/src/attestation/verifier.rs::match_identity`: extract the Fulcio cert's Subject Alternative Name(s) via `x509-parser` and match against the `--identity <PATTERN>` flag (exact email, GitHub workflow URL, or glob suffix). Returns `FailureMode::IdentityMismatch` on no match.
- [~] T021 [US1] Transparency-log policy check in `mikebom-cli/src/attestation/verifier.rs::verify_transparency_log`: enforces the presence rule (keyless envelope must carry a Rekor bundle unless `--no-transparency-log` set). Cryptographic inclusion-proof verification against the checkpoint is deferred to a follow-on task (Merkle-tree math lives outside the critical-path MVP).
- [X] T022 [US1] Created `mikebom-cli/src/cli/verify.rs` implementing the `sbom verify` subcommand per `contracts/cli.md` with all contracted flags. Layout check stubs to `layout_satisfied: None` for now (filled in by US4).
- [X] T023 [US1] Wired `sbom verify` as a NEW variant in `SbomSubcommand`; deleted the stubbed `validate` variant and `mikebom-cli/src/cli/validate.rs`. `attestation validate` (feature-001) untouched.
- [X] T024 [US1] Exit-code wiring: `main.rs` now returns `ExitCode`; `sbom verify` routes `FailureMode::exit_code()` all the way up. Verified end-to-end: legacy unsigned attestation now reports `NotSigned` with exit 2.
- [~] T025 [US1] Round-trip sign-then-verify test landed inline at `attestation::verifier::tests::verify_attestation_pass_on_valid_local_key_envelope` (not `tests/verify_dsse.rs` — integration tests can't cross the bin-crate boundary; see T016 note).
- [~] T026 [US1] Tampered-payload test landed inline at `attestation::verifier::tests::verify_attestation_fails_on_tampered_payload`.
- [X] T027 [US1] Raw-Statement `NotSigned` test landed inline at `attestation::verifier::tests::verify_attestation_not_signed_for_raw_statement`. Also covered by the CLI smoke test against the feature-001 `tests/fixtures/sample-attestation.json` (`mikebom sbom verify` returns exit 2 + `NotSigned`).

**Checkpoint**: `mikebom sbom verify` passes on externally produced signed envelopes and fails with distinguishable `FailureMode`s on tampered input. User Story 1 is fully testable.

---

## Phase 4: User Story 2 — Build operator produces signed, reproducible attestations (P1)

**Goal**: Plumb DSSE signing through `trace capture` / `trace run`. Both local-key (PEM + optional env-var passphrase) and keyless (OIDC → Fulcio → Rekor) flows. Hard-fail on any signing-pipeline error (Q3).

**Independent Test**: Run `mikebom trace run --signing-key signing.key -- echo hi` (or any tracable command) on Linux, obtain a signed DSSE envelope, and verify with US1's `sbom verify --public-key signing.pub`. Round-trip succeeds.

### Tests for User Story 2

- [ ] T028 [P] [US2] Unit test `mikebom-cli/src/attestation/signer.rs::tests::canonical_payload_is_deterministic`: for a fixed `InTotoStatement` input, produce the canonical payload twice and assert byte-identical output (FR-006).
- [ ] T029 [P] [US2] Unit test `mikebom-cli/src/attestation/signer.rs::tests::encrypted_pem_loads_with_passphrase_env`: generate an encrypted ECDSA-P256 PEM fixture, set the passphrase env var, load via `SigningIdentity::LocalKey`, assert success. Negative: wrong passphrase → `SigningError::KeyPassphraseInvalid`.
- [ ] T030 [P] [US2] Integration test scaffold `mikebom-cli/tests/sign_local_key.rs`: generates a test PEM keypair in a tempdir on test startup.

### Implementation for User Story 2

- [ ] T031 [US2] Local-key load helper in `mikebom-cli/src/attestation/signer.rs::load_local_signer`: reads a PEM file from `SigningIdentity::LocalKey.path`, optionally decrypts using the env-var-supplied passphrase, returns a `sigstore::KeyPair` (or equivalent `sigstore-rs` type). Maps errors to `SigningError::KeyFileMissing` / `KeyPassphraseInvalid`.
- [ ] T032 [US2] OIDC provider detection in `mikebom-cli/src/attestation/signer.rs::detect_oidc_provider`: reads env vars per `research.md` R4 (`ACTIONS_ID_TOKEN_REQUEST_URL` + `_TOKEN` → `GitHubActions`; `SIGSTORE_ID_TOKEN` → `Explicit`; otherwise → `Interactive`). Returns `OidcProvider`.
- [ ] T033 [US2] Keyless signing flow in `mikebom-cli/src/attestation/signer.rs::sign_keyless`: (a) obtain OIDC token per detected provider; (b) exchange for Fulcio cert via `sigstore::fulcio::FulcioClient`; (c) sign the DSSE payload with the ephemeral key; (d) if `transparency_log == true`, upload to Rekor and embed inclusion proof. Returns `SignedEnvelope`. Map each step's error to a distinct `SigningError` variant.
- [ ] T034 [US2] Local-key signing flow in `mikebom-cli/src/attestation/signer.rs::sign_local`: use the loaded keypair from T031, compute DSSE PAE (T014), sign, assemble `SignedEnvelope` with `IdentityMetadata::PublicKey` carrying the verifying PEM + `KeyAlgorithm`. Returns `SignedEnvelope`.
- [ ] T035 [US2] Unified sign entrypoint in `mikebom-cli/src/attestation/signer.rs::sign`: `fn sign(statement: &InTotoStatement, identity: &SigningIdentity) -> Result<SignedEnvelope, SigningError>`. Dispatches to `sign_local` or `sign_keyless` or returns an unsigned-sentinel marker for `SigningIdentity::None` (caller handles).
- [ ] T036 [US2] Edit `mikebom-cli/src/attestation/serializer.rs::write_attestation`: accept a `SigningIdentity`. When `None`, emit raw JSON Statement (preserves legacy shape, logs warning per FR-004). When non-`None`, call T035's `sign` and emit the resulting `SignedEnvelope` as JSON. Hard-fail semantics per FR-006a: any signing error → non-zero exit, no file written, optional `.partial` sidecar with raw trace events.
- [ ] T037 [US2] Extend `mikebom-cli/src/cli/scan.rs::ScanArgs` (the `trace capture` args struct) with `--signing-key <PATH>`, `--signing-key-passphrase-env <NAME>`, `--keyless`, `--fulcio-url <URL>`, `--rekor-url <URL>`, `--no-transparency-log`, `--require-signing` per `contracts/cli.md`. Construct a `SigningIdentity` from the flag combination (mutually-exclusive validation between `--signing-key` and `--keyless`).
- [ ] T038 [US2] Pass the constructed `SigningIdentity` through to `attestation::serializer::write_attestation` in `mikebom-cli/src/cli/scan.rs::execute_scan` (Linux-only). Hard-fail handling: if `write_attestation` returns `SigningError`, print a structured error to stderr and return `anyhow::Error` (kills the process with non-zero exit).
- [ ] T039 [US2] Mirror the same flag additions on `mikebom-cli/src/cli/run.rs::RunArgs` (the `trace run` wrapper). Thread them through to the composed `scan::execute` + `generate::execute` pipeline.
- [ ] T040 [US2] Integration test `mikebom-cli/tests/sign_local_key.rs::signs_with_local_pem_and_verifies`: generate PEM keypair → synthesize a minimal in-toto Statement → invoke `attestation::serializer::write_attestation` with `SigningIdentity::LocalKey` → read back the file → invoke `attestation::verifier::verify_envelope` with the public key → assert `VerificationReport::Pass`. End-to-end round-trip without CLI.
- [ ] T041 [US2] Integration test `mikebom-cli/tests/sign_local_key.rs::determinism`: sign the same statement + identity twice, assert the base64 `payload` field is byte-identical. (Signatures may differ for ECDSA due to nonce; PEM-based signing via `ed25519-dalek` would give us byte-identical sigs too, but ECDSA determinism is not required per FR-006's caveat.)
- [ ] T042 [US2] Integration test `mikebom-cli/tests/sign_local_key.rs::hard_fail_on_missing_key`: invoke with `--signing-key ./nonexistent.pem`, assert non-zero exit, no attestation file written.
- [ ] T043 [US2] Integration test `mikebom-cli/tests/sign_keyless.rs` (marked `#[ignore]` unless `SIGSTORE_ID_TOKEN` env var is set): keyless flow end-to-end against sigstore public-good Fulcio + Rekor. Gated per Principle VII (CI environments without OIDC tokens skip).

**Checkpoint**: `mikebom trace run --signing-key signing.key -- <cmd>` produces a signed DSSE envelope that round-trips through `mikebom sbom verify --public-key signing.pub`. Signing failures produce non-zero exit + no file.

---

## Phase 5: User Story 3 — Attestation subject resolves to real build artifact (P1)

**Goal**: Replace today's synthetic `"build-output"` subject with real artifact names + SHA-256 digests, auto-detected from the existing trace + artifact-dir walk. Operator `--subject` flag overrides auto-detection. Synthetic fallback per Q5.

**Independent Test**: Run `mikebom trace run -- cargo install ripgrep` (no signing flags) and inspect the attestation's `subject` field; the `ripgrep` binary's filename + real SHA-256 must appear. No dependency on US2 signing.

### Tests for User Story 3

- [ ] T044 [P] [US3] Unit tests in `mikebom-cli/src/attestation/subject.rs::tests` for `detect_magic_bytes`: pass raw ELF (`\x7FELF`), Mach-O (`\xCF\xFA\xED\xFE` 64-bit LE), PE (`MZ` + offset to `PE\0\0`) byte streams and non-binary data; assert true/false classifications.
- [ ] T045 [P] [US3] Unit test `mikebom-cli/src/attestation/subject.rs::tests::synthetic_digest_is_deterministic`: given a fixed command + trace-start timestamp, the synthetic digest hex output is identical across runs (FR-006).
- [ ] T046 [P] [US3] Unit test `mikebom-cli/src/attestation/subject.rs::tests::operator_override_suppresses_detection`: `SubjectResolver::resolve(…, operator_override=[path])` returns only the operator's paths; auto-detection does not run.

### Implementation for User Story 3

- [ ] T047 [US3] Magic-byte detection helper in `mikebom-cli/src/attestation/subject.rs::detect_magic_bytes`: reads first 8 bytes of a file, returns `true` if ELF / Mach-O (32/64, BE/LE variants) / PE signature. Reuse `object` crate if already pulled in, otherwise inline byte constants.
- [ ] T048 [US3] Resolver core in `mikebom-cli/src/attestation/subject.rs::SubjectResolver::resolve`: implements the precedence ladder from `data-model.md` (operator override → artifact-dir walk → suffix-list match → magic-byte detection → synthetic fallback). Uses existing `walker::walk_and_hash` for suffix-matched files; extends it with magic-byte fallback for suffix-less executables.
- [ ] T049 [US3] Canonical synthetic digest in `mikebom-cli/src/attestation/subject.rs::synthetic_digest`: SHA-256 hex of `canonical_bytes(command_argv || trace_start_rfc3339)`. Returns `(command_summary, synthetic_digest)` tuple where `command_summary = "synthetic:<truncated_argv0>-<short-hash>"`.
- [ ] T050 [US3] Wire `SubjectResolver::resolve` into `mikebom-cli/src/attestation/builder.rs::build_attestation`: replace the current hardcoded `ResourceDescriptor { name: "build-output", digest: BTreeMap::new() }` with a call to the resolver. Pass the captured `AggregatedTrace`, `trace_command`, `trace_start`, and operator-supplied `--subject` paths. Map each returned `Subject` to a `ResourceDescriptor`.
- [ ] T051 [US3] Serialize `Subject::Artifact` as `{ "name": "<path>", "digest": { "sha256": "<hex>" } }` and `Subject::Synthetic` as `{ "name": "synthetic:...", "digest": { "synthetic": "<hex>" } }` in the in-toto Statement per `contracts/attestation-envelope.md`.
- [ ] T052 [US3] Add `--subject <PATH>` (repeatable) flag to `mikebom-cli/src/cli/scan.rs::ScanArgs` and `mikebom-cli/src/cli/run.rs::RunArgs`. Also add to `mikebom-cli/src/cli/generate.rs::GenerateArgs` so post-hoc SBOM derivation can accept a subject override.
- [ ] T053 [US3] Thread operator-supplied `--subject` paths through to `attestation::builder::build_attestation`. When any `--subject` is passed, auto-detection is suppressed entirely per FR-009.
- [ ] T054 [US3] Warning log on synthetic-subject fallback in `mikebom-cli/src/attestation/subject.rs::SubjectResolver::resolve`: `tracing::warn!(command = %command, "no recognized build artifact detected — emitting synthetic subject; downstream verifier binding is degraded")` when the resolver falls through all branches.
- [ ] T055 [US3] Integration test `mikebom-cli/tests/subject_detection.rs::suffix_list_matches_wheel`: run a synthetic trace that produces a `.whl` file in `--artifact-dir`, assert the resulting attestation's subject contains that file with a SHA-256 digest matching the on-disk bytes.
- [ ] T056 [US3] Integration test `mikebom-cli/tests/subject_detection.rs::elf_magic_detects_bare_binary`: place an ELF binary (or craft minimal ELF header) in `--artifact-dir`, assert detection + SHA-256 in subject.
- [ ] T057 [US3] Integration test `mikebom-cli/tests/subject_detection.rs::operator_override_wins`: pass `--subject foo.txt`, assert the attestation contains exactly `foo.txt` even when the artifact-dir holds other recognized files.
- [ ] T058 [US3] Integration test `mikebom-cli/tests/subject_detection.rs::synthetic_fallback`: run a trace with no artifacts produced, assert the subject is `synthetic:...` with a `synthetic` digest algorithm key (not `sha256`).

**Checkpoint**: Real builds produce attestations whose `subject[]` list real artifact files with real SHA-256s. Combined with Phase 4, signed attestations bind to concrete artifacts end-to-end.

---

## Phase 6: User Story 4 — Layout author defines and enforces a build policy (P2)

**Goal**: `mikebom policy init` produces a starter in-toto layout; `mikebom sbom verify --layout` evaluates an attestation against a layout. Single-step layouts only (multi-step deferred per spec's Out of Scope).

**Independent Test**: `mikebom policy init --functionary-key signer.pub > layout.json; mikebom sbom verify attest.dsse.json --layout layout.json` passes for matching attestation; fails with `LayoutViolation` when signer-key mismatch.

### Tests for User Story 4

- [ ] T059 [P] [US4] Unit tests in `mikebom-cli/src/policy/layout.rs::tests`: `generate_minimal_layout` produces valid in-toto JSON (round-trips through `serde_json`); `parse_layout` rejects malformed schemas.
- [ ] T060 [P] [US4] Unit tests in `mikebom-cli/src/policy/apply.rs::tests`: `match_functionary_key` matches on keyid, rejects on mismatch; `match_step_name` matches declared step names.

### Implementation for User Story 4

- [ ] T061 [US4] Create `mikebom-cli/src/policy/mod.rs` with `pub mod layout; pub mod apply;`. Register in `mikebom-cli/src/main.rs`.
- [ ] T062 [US4] Implement `mikebom-cli/src/policy/layout.rs` with `Layout`, `LayoutKey`, `LayoutStep`, `KeyVal` types (derive Serialize/Deserialize) per `data-model.md`. Add `generate_starter_layout(functionary_pem: &str, step_name: &str, expires: DateTime<Utc>) -> Layout`.
- [ ] T063 [US4] Keyid derivation helper in `mikebom-cli/src/policy/layout.rs::keyid_from_pem`: compute a SHA-256 of the canonical DER-encoded key bytes; return hex. Consistent with sigstore keyid convention so mikebom-generated keyids match what external tools produce.
- [ ] T064 [US4] Expires parser in `mikebom-cli/src/policy/layout.rs::parse_expires_duration`: accepts "6m", "1y", "18mo", "2y" → `chrono::Duration`. Default 1 year when flag absent.
- [ ] T065 [US4] Implement `mikebom-cli/src/policy/apply.rs::verify_against_layout(statement: &InTotoStatement, envelope: &SignedEnvelope, layout: &Layout) -> Result<(), FailureMode>`: for each layout step, check that `envelope.signatures[*].keyid` matches a declared functionary key; match step name against predicate metadata; apply `expected_products` pattern against `statement.subject`. Return `FailureMode::LayoutViolation { step_name }` on any mismatch.
- [ ] T066 [US4] Create `mikebom-cli/src/cli/policy.rs` with `PolicyCommand` enum carrying a single `Init(PolicyInitArgs)` variant. Args: `--output <PATH>`, `--functionary-key <PATH>`, `--step-name <NAME>` (default "build-trace-capture"), `--expires <DURATION>` (default "1y"), `--readme <TEXT>`.
- [ ] T067 [US4] Wire `PolicyCommand` into the top-level `Cli::Commands` enum in `mikebom-cli/src/main.rs` so `mikebom policy init` dispatches.
- [ ] T068 [US4] Wire layout verification into `mikebom sbom verify --layout` handler in `mikebom-cli/src/cli/verify.rs`: when `--layout` is passed, load the file, call `policy::apply::verify_against_layout`, map result into the `VerificationReport`. Exit code 3 on `LayoutViolation` (per contract).
- [ ] T069 [US4] Integration test `mikebom-cli/tests/policy_layout.rs::init_produces_valid_layout`: invoke `mikebom policy init --functionary-key test.pub`, parse output JSON, assert it validates against a minimal in-toto layout schema check.
- [ ] T070 [US4] Integration test `mikebom-cli/tests/policy_layout.rs::matching_layout_passes_verify`: produce a layout from a known key, produce a signed attestation from the matching private key (use US2 plumbing), run verify with layout, assert Pass.
- [ ] T071 [US4] Integration test `mikebom-cli/tests/policy_layout.rs::mismatched_functionary_fails`: swap the key at verify time, assert `LayoutViolation` with the step-name in the failure detail.

**Checkpoint**: `policy init` + `sbom verify --layout` round-trips correctly for single-step policies. Mismatched functionaries report `LayoutViolation` with actionable detail.

---

## Phase 7: User Story 5 — Consumer enriches a derived SBOM without losing provenance (P3)

**Goal**: Replace the existing stubbed `sbom enrich` command with a working RFC 6902 JSON Patch applier that records per-patch provenance metadata in the enriched SBOM.

**Independent Test**: Generate any CycloneDX SBOM → apply a JSON patch that adds a `supplier` to a component → verify the enriched SBOM contains both the applied change AND a `mikebom:enrichment-patch[0]` property group carrying author + timestamp + base-attestation-ref.

### Tests for User Story 5

- [ ] T072 [P] [US5] Unit test in `mikebom-cli/src/sbom/mutator.rs::tests::apply_add_operation_appends_to_array`: apply `{"op":"add","path":"/components/0/licenses/-","value":{...}}` to a fixture SBOM, assert the license appears in the output.
- [ ] T073 [P] [US5] Unit test `mikebom-cli/src/sbom/mutator.rs::tests::test_op_failure_aborts`: RFC 6902 `test` operation with wrong value aborts the whole patch application (atomic semantics).

### Implementation for User Story 5

- [ ] T074 [US5] Create `mikebom-cli/src/sbom/mod.rs` (if not present) with `pub mod mutator;`.
- [ ] T075 [US5] Implement `mikebom-cli/src/sbom/mutator.rs::apply_patch`: wraps the `json-patch` crate. Input: mutable `serde_json::Value` (the SBOM) + an `EnrichmentPatch`. Apply operations in order; returns either the mutated SBOM or an `EnrichmentError` on any failed op.
- [ ] T076 [US5] Provenance emission helper in `mikebom-cli/src/sbom/mutator.rs::append_provenance_property`: adds a `mikebom:enrichment-patch[N]` entry to the SBOM's top-level `properties[]` array with JSON-encoded `{author, timestamp, base_attestation, op_count}` per `research.md` R3.
- [ ] T077 [US5] Base-attestation reference helper in `mikebom-cli/src/sbom/mutator.rs::attestation_sha256`: when `--base-attestation <PATH>` is provided, stream-hash the file with SHA-256 and embed the hex digest in the provenance property. Returns `None` when the flag is absent (provenance property omits `base_attestation`).
- [ ] T078 [US5] Replace the stubbed `mikebom-cli/src/cli/enrich.rs::execute` (currently `bail!("enrich command not yet implemented")`) with the real implementation: accept `--patch` (repeatable), `--author`, `--base-attestation`, `--output` flags; load SBOM, apply patches in order via T075, append provenance via T076–T077, write output.
- [ ] T079 [US5] Author default: when `--author` is absent, use `"unknown"` and emit `tracing::warn!("enrichment author not specified — downstream traceability degraded")`.
- [ ] T080 [US5] Integration test `mikebom-cli/tests/sbom_enrich.rs::adds_supplier_to_component`: generate a trivial SBOM fixture with one component, write a JSON patch that adds `/components/0/supplier`, run `mikebom sbom enrich`, assert the supplier appears AND the `mikebom:enrichment-patch[0]` property exists in the output.
- [ ] T081 [US5] Integration test `mikebom-cli/tests/sbom_enrich.rs::multiple_patches_apply_in_order`: two patches, the second operating on a field the first added; assert order dependence honored.
- [ ] T082 [US5] Integration test `mikebom-cli/tests/sbom_enrich.rs::base_attestation_ref_embedded`: pass `--base-attestation attest.dsse.json`, assert the provenance property contains the attestation's SHA-256.

**Checkpoint**: `mikebom sbom enrich` works end-to-end. Enriched SBOMs carry provenance metadata distinguishable from original attested data.

---

## Phase 8: Polish & cross-cutting concerns

**Purpose**: Documentation, CI regression fence, constitutional audit, quickstart validation.

- [ ] T083 [P] Update `docs/user-guide/cli-reference.md` with all new flags (`--signing-key`, `--keyless`, `--no-transparency-log`, `--subject`, `--require-signing`, `--fulcio-url`, `--rekor-url`) and new subcommands (`sbom verify`, `policy init`, `sbom enrich` — no longer stubbed). Cite `specs/006-sbomit-suite/contracts/cli.md` for exhaustive coverage.
- [ ] T084 [P] Update `docs/architecture/attestations.md` — remove the "Attestation signing isn't wired yet" deferred backlog entry; add a paragraph describing the DSSE envelope shape, link to `contracts/attestation-envelope.md`.
- [ ] T085 [P] Add a new `docs/architecture/signing.md` page covering the signer + verifier subsystems, the SigningIdentity enum, and the Fulcio/Rekor defaults. Link from `docs/index.md`.
- [ ] T086 Update `README.md` top-level examples: add a "Sign a build" snippet using a local key to the Quickstart section.
- [ ] T087 [P] Update `docs/design-notes.md` with a dated entry (2026-04-21+): "Feature 006 adds DSSE + Fulcio + Rekor signing, real artifact subjects, in-toto layout, and RFC 6902 SBOM enrichment. sigstore-rs dep audit: passed cargo-tree C-free check."
- [ ] T088 Run the full test suite: `cargo test --workspace`. Baseline after feature 005 was ~995 tests; new tests from this feature add ~30 unit + ~15 integration. All must pass.
- [ ] T089 Run `cargo clippy --workspace --all-targets` and verify no `clippy::unwrap_used` violations (Constitution Principle IV / Strict Boundary 4). Fix any that slipped into the new code.
- [ ] T090 **Constitution dep-tree audit (re-run of T004)**: `cargo tree -p mikebom -e normal | rg -i "libz-sys|openssl-sys|native-tls|bindgen|cc|c-bindings"` must return zero results. Blocks merge if fails.
- [ ] T091 Run each recipe in `specs/006-sbomit-suite/quickstart.md` end-to-end on a Linux host (recipe 2's GitHub Actions snippet validated by running the keyless flow locally with `SIGSTORE_ID_TOKEN` set). Update quickstart.md with any drift.
- [ ] T092 [P] Update `CLAUDE.md` (via `.specify/scripts/bash/update-agent-context.sh claude`) to reflect the finalized signing stack. Already run once during /speckit.plan; re-run after T083–T087 settle.
- [ ] T093 Cut `v0.1.0-alpha.4` release with the feature merged. Update `Cargo.toml` workspace version; push tag; verify the existing release.yml workflow (from feature 005) produces all three tarballs and they contain the new `sbom verify` / `policy init` subcommands per `mikebom --help`.

---

## Phase 9: Post-analyze additions (coverage gaps from `/speckit.analyze`)

**Purpose**: Close the five MEDIUM coverage gaps C1–C5 surfaced by the
analysis report. Each task is independently executable and fits into
its originally-numbered phase conceptually; they're numbered T094+ so
prior task IDs stay stable.

- [ ] T094 [US2] Integration test `mikebom-cli/tests/legacy_compat.rs::sbom_generate_accepts_pre_feature_attestation`: load a raw (unsigned) in-toto Statement v1 JSON fixture representing a pre-feature `.attestation.json` file, invoke `mikebom sbom generate <path>`, assert the CycloneDX output is structurally identical to the baseline captured before this feature's serializer changes. Closes FR-018 / SC-008 backwards-compat regression risk from T036.
- [ ] T095 [US1] Integration test `mikebom-cli/tests/verify_dsse.rs::subject_digest_mismatch_detected`: produce a signed attestation for a known artifact file (reuse fixture from T040); mutate one byte of the on-disk artifact AFTER signing; invoke `mikebom sbom verify --expected-subject <path>`; assert exit 1 + `FailureMode::SubjectDigestMismatch` in the `--json` report. Closes the missing test for this `FailureMode` variant (FR-022 + SC-007).
- [ ] T096 [US3] Integration test `mikebom-cli/tests/subject_detection.rs::multiple_artifacts_all_detected`: place both a `.whl` file AND a `.tar.gz` file in `--artifact-dir` during a synthetic trace; assert the resulting attestation's `subject` array contains BOTH files, each with its own SHA-256 digest matching on-disk bytes. Closes FR-008 coverage gap (multi-artifact subject list).
- [ ] T097 [P] Cross-tool interop smoke test `mikebom-cli/tests/interop_cosign.rs::verify_with_cosign_blob`: produce a mikebom-signed attestation via local-key signing; run `cosign verify-blob --key <pub>.pem --signature <sig> <payload>` against the DSSE envelope's signature + extracted payload; assert `cosign` exit 0. Gate the test with `#[ignore]` unless `cosign` is on `$PATH` (Principle VII gating pattern). Closes SC-001 interop gap — proves round-trip against a real SBOMit-adjacent verifier.
- [ ] T098 [P] Signing-overhead benchmark in `mikebom-cli/tests/sign_local_key.rs::bench_signing_overhead`: measure wall-clock time for the sign-envelope step (statement canonicalize + PAE + sign + envelope serialize) against the `demos/rust/` fixture baseline. Assert median over 5 runs is <2 seconds (SC-003 gate). Mark `#[ignore]` unless `MIKEBOM_RUN_BENCHMARKS=1` is set so normal `cargo test` stays fast.

**Checkpoint**: With T094–T098, every MEDIUM gap from the analyze
report is closed. Total task count: 98.

---

## Dependencies & execution order

### Phase-level dependencies

- **Phase 1 (Setup)** — no dependencies; can start immediately.
- **Phase 2 (Foundational)** — depends on Phase 1 (deps added). **Blocks every user story.**
- **Phase 3 (US1 — Verifier)** — depends on Phase 2.
- **Phase 4 (US2 — Signing)** — depends on Phase 2. Independent of US1 (different files, though both use the same types from Phase 2).
- **Phase 5 (US3 — Subject)** — depends on Phase 2. Independent of US1 and US2 (operates on the attestation *content*; the envelope layer is orthogonal).
- **Phase 6 (US4 — Layout)** — depends on Phase 3 (layout verification plugs into the verifier). Light dep on US2 for test fixtures (signed attestations to verify against).
- **Phase 7 (US5 — Enrichment)** — depends on Phase 2 (uses `SignedEnvelope` SHA-256 for base-attestation-ref) but independent of US1/US2/US3/US4 otherwise.
- **Phase 8 (Polish)** — depends on all desired user stories completing.

### Within each user story

- Types (models) before logic — e.g., `Layout` struct before `verify_against_layout`.
- Logic before CLI wiring — e.g., `verifier::verify_envelope` before `cli::verify::execute`.
- Unit tests alongside the module they test; integration tests after CLI wiring lands.

### Parallel opportunities

- Setup tasks T001–T003 can run in parallel ([P]).
- Phase 2 T008, T013, T014 have `[P]` — they touch independent helpers.
- Within each US phase, the `[P]`-tagged unit-test tasks can start immediately once the corresponding module skeleton exists.
- After Phase 2 checkpoint, all four `[US*]`-labelled phases (US1/US2/US3/US5) can be worked on in parallel by different developers. US4 waits for US1 + US2.

---

## Parallel execution example: User Story 1

```bash
# Once Phase 2 is complete, launch US1 test scaffolding in parallel:
Task: "T015 [P] [US1] FailureMode → exit code unit tests in mikebom-cli/src/cli/verify.rs::tests"
Task: "T016 [P] [US1] Integration test scaffold mikebom-cli/tests/verify_dsse.rs + fixtures"

# Then implementation tasks in sequence (shared file: verifier.rs):
Task: "T017 [US1] parse_envelope"
Task: "T018 [US1] verify_signature"
Task: "T019 [US1] verify_subject"
Task: "T020 [US1] match_identity"
Task: "T021 [US1] verify_rekor_bundle"

# Finally CLI wiring (separate file, can happen after T017-T021):
Task: "T022 [US1] cli/verify.rs subcommand"
Task: "T023 [US1] wire into SbomCommand"
Task: "T024 [US1] exit-code mapping"
```

---

## Implementation strategy

### MVP (User Story 1 + US2 subset)

1. Phase 1: Setup (T001–T005).
2. Phase 2: Foundational types (T006–T014).
3. Phase 3: US1 verifier, end-to-end against externally-signed envelopes (T015–T027).
4. **Demo**: `mikebom sbom verify` accepts `cosign`-signed output from any source.
5. Phase 4: US2 local-key signing end (T031, T034, T035, T036, T037, T038, T039, T040, T042). Skip keyless for MVP.
6. **Demo**: round-trip sign (local) → verify, single operator.

This MVP slice delivers the SBOMit compliance value proposition — downstream verifiers accept mikebom output — without requiring US3 subject resolution or keyless signing.

### Incremental delivery

- **Increment 1 (MVP)**: Setup + Foundational + US1 + US2 (local key) → verifiable signed attestations.
- **Increment 2**: US2 (keyless) → CI-friendly signing.
- **Increment 3**: US3 → real artifact subjects. Now downstream verifiers can bind attestations to specific binaries.
- **Increment 4**: US4 → policy layouts.
- **Increment 5**: US5 → SBOM enrichment.
- **Increment 6 (Polish)**: docs, dep audit, release.

### Parallel team strategy

With three developers after Phase 2:

- **Dev A**: US1 (Verifier) → US4 (Layout, builds on US1).
- **Dev B**: US2 (Signing) → helps with US4 test fixtures.
- **Dev C**: US3 (Subject) → US5 (Enrichment).

All three parallel streams merge cleanly in Phase 8 Polish.

---

## Notes

- Task count: **98 total** across 9 phases (Phase 9 added post-analyze to close coverage gaps).
- Tasks per user story: US1 = 14 (incl. 4 tests), US2 = 17 (incl. 4 tests), US3 = 16 (incl. 4 tests), US4 = 13 (incl. 2 tests), US5 = 11 (incl. 2 tests). Plus 2 `[P]` polish tasks (T097 + T098) not owned by any single story.
- Setup + Foundational + Polish: **25 tasks** (13 foundational, 5 setup, 11 polish — but note T092 / T088 / T090 are single-run audits, not heavy LOC).
- Every task has a concrete file path or verifiable command.
- Tests are inline unit tests (sitting alongside code) + integration tests in `mikebom-cli/tests/` per the existing project convention.
- Constitution audit runs twice: T004 after dep additions, T090 after all implementation.
- No new crates, no C dependencies, no `.unwrap()` in production — enforced by the existing `#![deny(clippy::unwrap_used)]` at crate root + T089 clippy sweep.
- Commit after each task or logical group. Keep the `006-sbomit-suite` branch coherent so the eventual merge is reviewable.

---

## Independent test criteria per story

| Story | How to independently verify |
|---|---|
| **US1** | Hand an externally-produced (cosign/witness) DSSE envelope to `mikebom sbom verify --public-key ...`; assert `Pass`. Mutate the payload; assert `SignatureInvalid`. Feeds zero dependence on mikebom producing signed output. |
| **US2** | Generate a PEM key pair, run `mikebom trace run --signing-key` against any traced command, use US1's verifier to confirm the signature. Independent from US3 since the subject can still be synthetic at this stage. |
| **US3** | Run `mikebom trace run` (no signing flags) against `cargo install ripgrep`; inspect the unsigned attestation's `subject[]` field; the ripgrep binary appears with its real SHA-256. No US1/US2 dependency. |
| **US4** | `mikebom policy init` produces valid in-toto JSON (verifiable with any in-toto-aware tool). Requires US1 for the full `sbom verify --layout` loop. |
| **US5** | `mikebom sbom enrich` applies a JSON patch to any CycloneDX SBOM (from mikebom or any other generator) and emits provenance metadata. Fully independent of US1–US4. |

---

## MVP scope recommendation

**User Story 1 + User Story 2 (local key only)** — delivers the core SBOMit compliance value: mikebom-produced attestations can be verified by any DSSE-aware tool, and operators can sign them with a simple local PEM key. Keyless + real-subject + layouts + enrichment all add value, but US1 + US2 (local) is the smallest coherent unit that solves the user's stated problem ("Let's add the full sbomit suite here, let's using sigstore's rust sdk if possible").

Subsequent increments (US3 → US4 → US5 → keyless) deepen the story without blocking the first useful release.
