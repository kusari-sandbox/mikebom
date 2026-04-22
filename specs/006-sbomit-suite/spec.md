# Feature Specification: SBOMit compliance suite

**Feature Branch**: `006-sbomit-suite`
**Created**: 2026-04-21
**Status**: Draft
**Input**: User description: "Let's add the full sbomit suite here, let's using sigstore's rust sdk if possible. Let's also use the right subject and everything"

## Clarifications

### Session 2026-04-21

- Q: Transparency log (Rekor) for keyless signing — required, optional-with-opt-out, or deferred? → A: Default-on Rekor upload + inclusion proof, with a `--no-transparency-log` flag to disable per invocation (matches `cosign` behavior).
- Q: Local-key handling — format, passphrase, HSM/KMS scope? → A: PEM files, with an optional passphrase supplied via environment variable (no interactive prompt — CI-friendly). HSM/KMS backends are out of scope for v1.
- Q: Signing-failure policy during a trace (OIDC / Fulcio / Rekor call fails mid-build)? → A: Hard fail — when signing was requested and fails, no attestation file is written and the command exits non-zero. The raw trace may be preserved in a `.partial` sidecar for diagnostics. Users who want graceful degradation opt in explicitly.
- Q: Subject artifact detection scope — what counts as a "recognizable artifact"? → A: Reuse the existing `ARTIFACT_SUFFIXES` list from `scan_fs/walker.rs` (`.deb`, `.crate`, `.whl`, `.jar`, `.gem`, `.apk`, `.rpm`, `.tar.gz`, …) AND detect compiled executables via ELF / Mach-O / PE magic bytes (covers `cargo install` / `go install` bare-binary outputs), AND honor explicit `--artifact-dir` paths for operator override. Intermediates (`.o`, `.rlib`), log files, and temp files are not subject candidates.
- Q: Synthetic-subject marker when no artifact is detected? → A: Emit `subject[].name = "synthetic:<command-summary>"` with `digest = { "synthetic": "<sha256-of-command-and-trace-start>" }`. The `synthetic` digest-algorithm name is not a real hash function, so no verifier will mistake the value for a content hash, while every in-toto parser still sees a well-formed subject with a digest map.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Downstream verifier accepts mikebom attestations (Priority: P1)

A security engineer running an SBOMit-aware verification tool (e.g. witness,
go-witness, a SLSA verifier, or a policy engine) receives a mikebom build-trace
attestation and a derived CycloneDX SBOM. They verify the attestation's
signature, confirm the subject resolves to the actual build artifact they
shipped, and run policy against the trace predicate — all without manual
translation or one-off tooling.

**Why this priority**: This is the core value of being SBOMit-compliant. Today
mikebom's attestations are "SBOMit-shaped but not SBOMit-compliant" — unsigned
JSON with a synthetic subject that downstream tooling can't bind to a real
artifact. Every other piece of this feature supports this end-user flow.

**Independent Test**: Cut a release of a test build (e.g. `cargo install
ripgrep`) with mikebom, hand the attestation to a stock `witness verify` or
equivalent SBOMit-compliant verifier, and confirm it validates signature,
subject digest, and predicate schema without mikebom-specific plugins.

**Acceptance Scenarios**:

1. **Given** a completed `mikebom trace run` that produced a signed attestation
   and SBOM, **When** a downstream verifier runs signature validation using
   only the public key or identity referenced in the attestation, **Then** the
   verifier reports a successful verification.
2. **Given** a built artifact on disk referenced in an attestation's subject,
   **When** the verifier computes the artifact's SHA-256 and compares it to
   the subject digest, **Then** the digests match.
3. **Given** a derived CycloneDX SBOM, **When** the verifier walks from the
   SBOM back to the attestation, **Then** every component in the SBOM can be
   traced to a network connection or file operation in the trace predicate.

---

### User Story 2 — Build operator produces signed, reproducible attestations (Priority: P1)

A platform engineer running mikebom in CI wants every build to emit a signed
attestation. They can plug in a signing identity (keyless via OIDC + Fulcio
for CI, or a local key file for air-gapped environments) without wiring
bespoke glue, and the resulting attestation is byte-identical across re-runs
when the build is reproducible.

**Why this priority**: Signing is the foundation every SBOMit primitive
depends on. An unsigned attestation can be tampered with in transit and gives
downstream consumers no way to verify the attestation author's identity.

**Independent Test**: Run `mikebom trace run` twice against the same
reproducible build with the same signing identity and confirm (a) both
attestations carry valid signatures that verify against the expected identity
and (b) the pre-signature canonical payloads are byte-identical.

**Acceptance Scenarios**:

1. **Given** a signing identity configured via CLI flag or environment,
   **When** `mikebom trace run` completes, **Then** the written attestation
   is wrapped in a signed envelope carrying at least one verifiable signature
   and clear identity metadata.
2. **Given** no signing identity is configured, **When** the user runs
   `mikebom trace run`, **Then** the tool emits an unsigned attestation and
   warns that the output is not SBOMit-verifiable — keeping backwards
   compatibility with today's behavior.
3. **Given** a configured keyless signing identity (OIDC provider + Fulcio),
   **When** the user runs in CI, **Then** the signing step completes without
   any operator-supplied private-key material.

---

### User Story 3 — Attestation subject resolves to the real build artifact (Priority: P1)

A compliance auditor reviewing a mikebom attestation for a released binary
sees the attestation's `subject` pointing directly at the released artifact's
filename and SHA-256 digest, not a placeholder. They can independently
recompute the digest from the binary on disk and confirm the attestation is
*about* that specific file, not a generic "build-output" sentinel.

**Why this priority**: Without a real subject, signature verification and
policy enforcement can't bind the attestation to anything meaningful.
Co-equal priority with signing — neither is useful without the other.

**Independent Test**: Trace a known build (`cargo install ripgrep`,
`pip install requests`, `npm install lodash`) and verify the attestation's
subject contains the artifact's filename and its SHA-256 hash, matching the
file on disk byte-for-byte.

**Acceptance Scenarios**:

1. **Given** a traced build that produces one or more recognized build
   artifacts (compiled binary, `.whl`, `.tgz`, `.crate`, JAR, etc.), **When**
   the attestation is written, **Then** the `subject` array contains one
   entry per artifact with its real filename and SHA-256 digest.
2. **Given** a traced build that produces no recognizable build artifact
   (e.g. a test run that doesn't emit a file), **When** the attestation is
   written, **Then** the subject carries a clearly-marked synthetic entry
   (not a digest-less fake) and a warning is logged so operators know the
   attestation's binding is degraded.
3. **Given** the user passes an explicit `--subject` flag pointing at one or
   more files, **When** the trace completes, **Then** the attestation uses
   those files as the subject, overriding auto-detection.

---

### User Story 4 — Layout author defines and enforces a build policy (Priority: P2)

A security architect defines an in-toto layout for their organization: "every
build of a production service must carry a mikebom build-trace attestation,
signed by the CI functionary key, with a predicate indicating the build
completed within policy constraints." They apply this layout at verification
time and it either passes or produces a clear, actionable failure.

**Why this priority**: Layouts are how SBOMit scales beyond individual
artifacts to organizational policy. A build-only feature is valuable on its
own, so this is P2 rather than P1. But without a layout story, the full
SBOMit loop is incomplete.

**Independent Test**: Write a minimal layout that expects one step
("build-trace-capture") signed by a specific functionary. Pass a
mikebom-signed attestation through layout verification and confirm it
passes; deliberately break one constraint and confirm the verifier reports
the specific violation.

**Acceptance Scenarios**:

1. **Given** a user wants to generate a starter layout, **When** they invoke
   a `mikebom policy init` command, **Then** a valid in-toto layout is
   written that references the current signing identity and defines a single
   build-trace step.
2. **Given** a layout with a "build-trace-capture" step and a mikebom-signed
   attestation, **When** a standard in-toto verifier applies the layout,
   **Then** the verification succeeds.
3. **Given** a layout requiring a specific functionary key and an
   attestation signed by a different key, **When** the verifier runs,
   **Then** it fails with a message identifying the functionary mismatch.

---

### User Story 5 — Consumer enriches a derived SBOM without losing provenance (Priority: P3)

A package maintainer receives a mikebom-generated CycloneDX SBOM and wants to
add organization-specific metadata — custom properties, additional suppliers,
triage status on a vulnerability — without destroying the link between the
SBOM and the original attestation. They apply the enrichment as a recorded
patch, and downstream consumers can still trace every component back to the
original attestation, plus see the enrichment's author and timestamp.

**Why this priority**: Enrichment is important for real deployments but
narrower than signing/subject/layout. P3 because the core loop works without
it for the initial rollout.

**Independent Test**: Generate a mikebom SBOM, apply a JSON patch via the
enrichment mechanism (e.g. add a `supplier` to one component), and verify
(a) the patched SBOM still references the original attestation, (b) the
patch itself is recorded with author and timestamp metadata, and (c) a
verifier can distinguish original-attested data from enrichment.

**Acceptance Scenarios**:

1. **Given** a generated SBOM and a JSON-patch file, **When** the user
   applies the patch via a mikebom subcommand, **Then** the output SBOM
   reflects the patch and carries metadata recording which patches were
   applied.
2. **Given** an enriched SBOM, **When** a verifier walks its provenance
   chain, **Then** the verifier can distinguish which fields came from the
   original attested trace vs. which came from post-hoc enrichment.

---

### Edge Cases

- **Air-gapped signing**: operators without internet access can't reach
  Fulcio. The tool must support a local-key signing path that produces a
  valid DSSE envelope with the same structure — just a different identity
  story.
- **Transparency log unreachable during keyless signing**: when the
  default Rekor upload fails (network outage, log-service down), mikebom
  must distinguish this failure from Fulcio-cert-issuance failures and
  give operators a clear next step (retry, or explicit opt-out via
  `--no-transparency-log` with a visible security-posture warning).
- **Trace produced no subject artifact**: a trace of a test-only command
  (e.g. `cargo test`) or a process that doesn't produce a file artifact
  still needs a valid attestation shape; what goes in `subject` must be
  explicitly marked as synthetic, not silently faked.
- **Multiple build artifacts**: some builds produce several outputs (a wheel
  AND a source distribution, a `.deb` AND a `.deb.sig`). The subject must
  be a list, not a single file.
- **Signature verification failure in the field**: a downstream verifier
  receives an attestation whose signature doesn't validate. mikebom's
  tooling must produce a clear failure message that distinguishes "not
  signed" from "signed by unexpected identity" from "envelope malformed".
- **Signing-pipeline failure during a trace**: OIDC token issuance,
  Fulcio cert request, Rekor upload, or key load fails mid-build. The
  trace command hard-fails (non-zero exit, no attestation written); a
  `.partial` sidecar may capture raw trace events for diagnostics. No
  silent fallback to an unsigned attestation.
- **Legacy unsigned attestations**: users with existing `.attestation.json`
  files from pre-feature mikebom invocations must still be able to derive
  SBOMs from them; the signing requirement is on new attestations only.
- **Layout with no matching attestation**: a verifier runs a layout against
  an environment where no attestation is present. Failure must be clear,
  not silent.
- **Enrichment patches that conflict**: two independent patches modify the
  same field. Application must be deterministic and the conflict visible.
- **Subject digest mismatch between attestation time and verify time**: the
  artifact on disk has been modified since the attestation was produced.
  The verifier must flag this prominently.

## Requirements *(mandatory)*

### Functional Requirements

#### FR block — Signed attestation envelope

- **FR-001**: mikebom MUST be able to emit attestations wrapped in a
  standard signed-envelope format recognized by the SBOMit ecosystem (DSSE),
  such that stock SBOMit-compliant verifiers can validate the signature
  without mikebom-specific tooling.
- **FR-002**: Users MUST be able to sign an attestation using a local
  private-key file in PEM format, specifying the key via a CLI flag or
  environment variable, for air-gapped and local-development workflows.
  Encrypted (passphrase-protected) PEM files MUST be supported; the
  passphrase is supplied via an environment variable (no interactive
  prompt) so the flow works uniformly across local shells, CI runners,
  and container entrypoints. Unencrypted PEM files are accepted and
  rely on OS-level file permissions.
- **FR-003**: Users MUST be able to sign an attestation using a keyless
  identity flow (OIDC-bound certificate issued by a transparency-log-backed
  certificate authority) for CI environments, with no operator-supplied
  private keys. The keyless flow MUST upload the signing event to a
  transparency log and embed the inclusion proof in the signed envelope
  by default, with a `--no-transparency-log` flag to disable per
  invocation for restricted-network environments.
- **FR-004**: When no signing identity is configured, mikebom MUST emit an
  unsigned attestation (preserving today's behavior) and log a prominent
  warning that the output is not SBOMit-verifiable.
- **FR-005**: Signed attestations MUST include all identity metadata a
  downstream verifier needs in-envelope:
  - **Keyless flow**: the complete Fulcio-issued x509 certificate
    (PEM-encoded) plus any intermediate certificates needed to terminate
    the chain at a known trust root.
  - **Local-key flow**: the PEM-encoded verifying public key and its
    `KeyAlgorithm` (`ecdsa-p256` | `ed25519` | `rsa-pkcs1`).
  In both cases, no out-of-band material (key registries, cert
  truststores, manual identity lookups) is required for signature
  validation.
- **FR-006**: The signing step MUST be deterministic: re-signing the same
  canonical payload with the same identity MUST NOT change the payload
  bytes (signatures may vary where the signing algorithm is non-
  deterministic).
- **FR-006a**: When signing is requested and any signing-pipeline step
  fails (OIDC token issuance, Fulcio certificate request, Rekor upload
  if enabled, private-key load, signature computation), mikebom MUST
  hard-fail: no signed attestation file is written and the command
  exits non-zero. A `.partial` sidecar containing the raw trace events
  MAY be written so operators can diagnose without losing the captured
  data. Silent fallback to an unsigned attestation is prohibited — if
  the operator asked for signing, a missing signature is an error.

#### FR block — Subject resolution

- **FR-007**: For each traced build command that produces a recognizable
  artifact, mikebom MUST detect that artifact and include it in the
  attestation's `subject` with the artifact's filename and SHA-256
  digest. "Recognizable" means any of:
  (a) a file with a known package-artifact suffix from the existing
      `ARTIFACT_SUFFIXES` list in `scan_fs/walker.rs` (`.deb`, `.crate`,
      `.whl`, `.jar`, `.gem`, `.apk`, `.rpm`, `.tar.gz`, …);
  (b) a compiled executable identified by ELF / Mach-O / PE magic bytes
      at the file's head (covers `cargo install`, `go install`, and
      similar bare-binary outputs with no extension);
  (c) any file that lands inside an operator-supplied `--artifact-dir`
      during the trace window.
  Intermediates (`.o`, `.rlib`, staging tarballs), log files, and temp
  files MUST NOT be treated as subjects even when they're written
  during the trace.
- **FR-008**: When a traced build produces multiple artifacts, the
  attestation's `subject` MUST be a list containing every recognized
  artifact, each with its own digest.
- **FR-009**: Users MUST be able to override auto-detected subjects via an
  explicit CLI flag pointing at one or more files, for cases where
  auto-detection is wrong or absent.
- **FR-010**: When no recognizable artifact is produced, the attestation's
  subject MUST contain a single synthetic entry with:
  - `name` prefixed `synthetic:` followed by a short command-derived
    summary (e.g. `synthetic:cargo-test-abc123`).
  - `digest` using a `synthetic` algorithm key whose value is the
    SHA-256 of a canonical concatenation of the traced command and the
    trace-start timestamp (reproducible for identical traces).
  The non-real `synthetic` algorithm name signals to downstream
  verifiers that the value is not a content hash, while keeping the
  subject structurally valid for strict in-toto parsers. A warning
  MUST be logged so operators see the degraded-binding posture.
- **FR-011**: Subject digests MUST be computed from the actual bytes on
  disk at attestation-creation time; they MUST NOT be inferred from trace
  events alone.

#### FR block — In-toto layout

- **FR-012**: mikebom MUST be able to generate a starter in-toto layout
  that references the current signing identity and declares a single
  build-trace step, giving users a working policy baseline.
- **FR-013**: Layouts generated by mikebom MUST conform to the in-toto
  layout specification such that unmodified third-party verifiers
  (e.g. in-toto, witness) can evaluate them.
- **FR-014**: mikebom MUST be able to verify an attestation against a
  supplied layout, producing either a pass result or a failure message
  that identifies the specific constraint violated.

#### FR block — SBOM mutation / enrichment

- **FR-015**: Users MUST be able to apply a structured enrichment (e.g.
  JSON patch) to a mikebom-derived SBOM, producing an enriched SBOM that
  preserves the link to the original attestation.
- **FR-016**: Enriched SBOMs MUST record metadata about each applied
  patch: the patch's author or source, timestamp, and a reference to the
  original attestation.
- **FR-017**: Downstream consumers MUST be able to distinguish data in
  the enriched SBOM that came from the original attested trace from data
  introduced by enrichment.

#### FR block — Backwards compatibility + migration

- **FR-018**: Existing mikebom attestation files from pre-feature
  versions (unsigned, synthetic subject) MUST continue to be processable
  by the current `sbom generate` command; the feature does not orphan
  existing attestations.
- **FR-019**: Invoking mikebom without any new flags MUST continue to
  produce a valid (if not SBOMit-compliant) attestation — the new
  behavior is opt-in by default so existing pipelines don't break.
- **FR-020**: The documented upgrade path from unsigned to signed
  attestations MUST be adding a single category of new flag — either
  `--signing-key <PATH>` for local-key signing or `--keyless` for CI
  keyless signing — to an otherwise-unchanged invocation. No
  restructuring of existing commands, output paths, or attestation/SBOM
  filenames is required to opt in.

#### FR block — Verification tooling

- **FR-021**: mikebom MUST provide a verification subcommand that, given
  an attestation and optional policy/layout, reports whether the
  attestation is valid and every constraint is satisfied.
- **FR-022**: Verification failures MUST emit a named failure mode
  drawn from this closed set:
  - `NotSigned` — input is a raw Statement with no DSSE envelope.
  - `MalformedEnvelope` — envelope shape is invalid (missing
    `payloadType` / `signatures`, non-base64 payload, etc.).
  - `SignatureInvalid` — cryptographic signature check failed.
  - `IdentityMismatch` — signer identity does not match
    `--public-key` / `--identity` / layout-declared functionary.
  - `SubjectDigestMismatch` — an `--expected-subject`'s on-disk
    SHA-256 does not match the attestation's subject digest.
  - `LayoutViolation` — a supplied in-toto layout's constraint was
    not satisfied (detail includes the violating step name).
  - `TransparencyLogMissing` — a keyless envelope lacks a Rekor
    inclusion proof and `--no-transparency-log` was not set.
  - `CertificateExpired` — the Fulcio cert has expired.
  - `TrustRootInvalid` — the cert chain does not terminate in a known
    trust root.
  Tooling consumers rely on this exact set to branch on outcomes;
  adding a new mode is a spec change, not an implementation detail.
- **FR-023**: The verification subcommand MUST accept attestations
  produced by other SBOMit-compliant tools (not just mikebom's own
  output), within the limits of shared schema.

### Key Entities

- **Signed Attestation Envelope**: the outer structure wrapping the
  in-toto Statement. Carries the canonical payload, one or more
  signatures, and per-signature identity information. Consumed by any
  SBOMit-compliant verifier.
- **Subject**: the resource(s) the attestation is about. A list of
  artifact descriptors — each with name and digest — pointing at actual
  build outputs. Replaces today's synthetic "build-output" sentinel.
  When no real artifact is detectable, a single synthetic descriptor
  is emitted with a distinct `synthetic` digest-algorithm marker so
  downstream verifiers can't mistake it for a content hash.
- **Signing Identity**: the author proof for an attestation. Either a
  long-lived key (file-based) or a short-lived certificate bound to an
  external identity (OIDC-based keyless).
- **Layout**: signed policy document declaring which steps are expected,
  which functionaries may sign them, and what connects them. Consumed
  at verification time.
- **Enrichment Patch**: a structured modification to a derived SBOM,
  recorded with author and timestamp metadata so its provenance is
  distinguishable from the original attestation data.
- **Verification Report**: the output of running a verifier against an
  attestation (optionally with a layout). Distinguishes pass from each
  concrete failure mode.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A standard SBOMit-compliant verifier (reference tool
  selected at implementation time) can validate a mikebom-signed
  attestation end-to-end — signature, subject, and predicate schema —
  without any mikebom-specific plugins or glue code.
- **SC-002**: 95% of traced builds of supported tool commands
  (`cargo install`, `cargo build`, `pip install`, `npm install`, `go
  install`, `apt-get install`) produce an attestation whose subject
  contains at least one real artifact with a SHA-256 digest that matches
  the on-disk bytes.
- **SC-003**: Signing adds no more than 2 seconds of overhead to a
  typical build-trace capture (measured on the existing demo fixtures).
- **SC-004**: A user can produce a signed attestation with a local key
  in under 3 CLI-flag additions to their current `mikebom trace run`
  invocation.
- **SC-005**: A user can produce a keyless-signed attestation in a
  supported CI environment with zero operator-supplied private keys.
- **SC-006**: The starter layout generated by `mikebom policy init`
  passes verification against the first attestation the user produces
  after initialization, with no manual edits.
- **SC-007**: Verification failure messages identify the specific
  failing constraint (signature / identity / subject / layout /
  envelope) in 100% of cases; no generic "verification failed"
  messages.
- **SC-008**: Existing pre-feature attestation files continue to
  process successfully through `sbom generate` — zero-regression
  migration.
- **SC-009**: Enriched SBOMs allow a downstream consumer to
  programmatically separate original-attested fields from
  enrichment-introduced fields in every case.

## Assumptions

- **Signing SDK availability**: a Rust SDK for the target signing
  ecosystem (sigstore) exists, is actively maintained, and can produce
  DSSE envelopes; no custom cryptographic implementation is required.
- **SBOMit spec maturity**: the SBOMit v0.1.0 specification is the
  current baseline. Some sections are incomplete ("TODO" markers);
  where the spec is silent, the witness/go-witness reference
  implementations define the de-facto behavior.
- **In-toto envelope compatibility**: the DSSE envelope format is
  compatible with in-toto Statement v1 payloads, which mikebom
  already emits.
- **Artifact detection heuristics**: the subject-resolution logic
  reuses the existing `ARTIFACT_SUFFIXES` list from
  `mikebom-cli/src/scan_fs/walker.rs` plus ELF/Mach-O/PE magic-byte
  detection for compiled-executable outputs, plus operator-supplied
  `--artifact-dir` paths. No new build-tool integrations are added.
- **Air-gapped signing story**: local-key signing is sufficient for
  air-gapped environments; certificate-based keyless signing requires
  network access. Local keys are PEM-encoded; passphrase-protected
  PEMs are unlocked via environment variable (never interactive
  prompt), so the same signing command works in shells, CI, and
  container entrypoints.
- **Layout scope**: initial layouts are single-step (build-trace-only).
  Multi-step workflows (separate build + test + publish steps, each
  signed) are a future extension.
- **Patch semantics**: enrichment uses a well-known JSON patch format
  (RFC 6902 or JSON Merge Patch). Choice between the two is a
  planning-time decision based on the target SBOM format's
  expressiveness needs.
- **Constitutional compliance**: no C dependencies introduced (Rust-
  native sigstore SDK); no unwrap in production code; attestation
  predicate keeps its existing URI to avoid breaking consumers.
- **Backwards compatibility**: every new behavior is opt-in via new
  flags; existing invocations remain functional and produce the same
  output shape they produce today.
- **Verification scope**: mikebom's verifier subcommand focuses on
  mikebom-produced or mikebom-schema-compatible attestations. Full
  multi-attestor in-toto verification (many steps, many functionaries)
  is out of scope for the initial implementation and may be left to
  external tools (witness, in-toto-verify).
- **CI provider coverage for keyless**: initial keyless signing
  support targets GitHub Actions' OIDC token flow (the most common
  CI path). Other providers (GitLab CI, CircleCI, Buildkite) can be
  added incrementally.

## Out of Scope

- **SBOMit specification contributions**: any gaps in the SBOMit
  v0.1.0 spec itself are worked around via reference-implementation
  behavior; we do not propose spec changes in this feature.
- **Alternative signing ecosystems**: GPG, X.509-only, or non-DSSE
  signature schemes are not in scope. If the target signing Rust SDK
  proves unusable, the fallback is documented during planning, not
  open-ended design.
- **HSM / KMS / PKCS#11 signing backends**: not in v1. Pluggable
  signer backends (AWS KMS, GCP KMS, YubiKey, etc.) are a future
  extension; local-key signing in v1 is PEM-file-only.
- **Multi-step layouts**: beyond a single build-trace-capture step.
- **Transparency-log ingestion beyond signing**: we use transparency-
  log-backed signing as part of the keyless flow, but do not build
  custom log-querying tooling.
- **Retroactive signing**: converting existing unsigned attestations
  into signed ones is a future enhancement; the initial work signs
  at attestation-creation time only.
- **SBOM format-specific enrichment beyond CycloneDX**: SPDX-specific
  enrichment workflows are a future extension.
