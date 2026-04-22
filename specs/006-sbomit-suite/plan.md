# Implementation Plan: SBOMit compliance suite

**Branch**: `006-sbomit-suite` | **Date**: 2026-04-21 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/006-sbomit-suite/spec.md`

## Summary

Make mikebom's build-trace attestations verifiable by any SBOMit-compliant
tool. Five user stories, three of them P1: (1) downstream verifiers accept
mikebom output end-to-end; (2) build operators get signed attestations via
both local-key (PEM + optional env-var passphrase) and keyless
(OIDC→Fulcio→Rekor) flows; (3) the attestation subject points at real build
artifacts with real SHA-256 digests instead of today's `"build-output"`
sentinel. Two add-ons: P2 in-toto layout generation + verification, and P3
recorded-provenance SBOM enrichment via JSON patches.

Technical approach: wrap the existing `InTotoStatement` JSON in a **DSSE
envelope**, sign it via **sigstore's Rust SDK** (`sigstore-rs`), add a
**Rekor transparency-log** step (default-on, opt-out via
`--no-transparency-log`), and add **artifact auto-detection** that reuses
the existing `ARTIFACT_SUFFIXES` list + ELF/Mach-O/PE magic-byte detection.
The three sites that currently populate `host.distro_codename` (analogous
pattern from feature 005) show the general shape: one code path, one
helper, applied uniformly. Hard-fail on any signing-pipeline failure
(Principle III: Fail Closed). Unsigned attestations remain supported for
backwards compatibility and carry a loud warning.

## Technical Context

**Language/Version**: Rust stable (same workspace toolchain as milestones
001–005). No nightly-only features for user-space. `mikebom-ebpf` is
untouched. Signing code compiles on stable.

**Primary Dependencies**:
- `sigstore` (Rust SDK) — DSSE sign + verify, Fulcio OIDC flow, Rekor
  transparency log upload + inclusion proof
- Existing workspace deps: `anyhow`, `thiserror`, `tokio`, `serde`,
  `serde_json`, `reqwest` (rustls-tls), `clap`, `chrono`, `sha2`, `tracing`
- New dev-deps: potentially `assert_cmd` + `predicates` for end-to-end
  CLI testing if not already present

**Storage**: N/A — attestations are single JSON files (signed or
unsigned). Layout files are single JSON files. No database. In-memory
state during capture only.

**Testing**:
- `cargo test --workspace` for unit tests (no eBPF privileges required;
  mock signing identities + sigstore local-key path covers most cases)
- Integration tests for the signed-envelope round-trip: generate with
  local key, verify in-process, verify against `cosign`/`rekor-cli` if
  available (mark-ignored if not installed per Principle VII)
- Keyless (OIDC→Fulcio) flow is gated behind env-var checks since CI
  systems differ in OIDC token availability

**Target Platform**:
- User-space: Linux, macOS (scan + generate + verify subcommands), any
  platform Rust builds
- eBPF trace capture: Linux kernel ≥ 5.8 (unchanged from existing)

**Project Type**: CLI tool (single Rust workspace, three crates). Per the
constitution's three-crate architecture, no new crates added.

**Performance Goals**:
- Signing overhead ≤ 2 seconds wall-clock on the existing demos
  (SC-003)
- Subject artifact detection: O(files_created_during_trace) with
  SHA-256 per candidate; stream-hash up to `DEFAULT_SIZE_CAP_BYTES`
  (256 MB existing cap)
- Verification: single-attestation verify < 1 second (no real SC yet;
  keep as non-goal for MVP)

**Constraints**:
- Pure-Rust (Constitution Principle I). `sigstore-rs` is pure Rust; do
  not pull in crypto crates with C dependencies (verify with
  `cargo tree` before landing).
- No `.unwrap()` in production code (Principle IV / Strict Boundary 4).
- Three-crate architecture preserved (Principle VI): all new code lands
  in `mikebom-cli/` and `mikebom-common/`.
- Attestation predicate type URI
  (`https://mikebom.dev/attestation/build-trace/v1`) stays unchanged —
  existing downstream consumers keep parsing.
- Signing is opt-in by default: zero-flag invocations continue to emit
  unsigned attestations (backwards-compat per FR-019).

**Scale/Scope**:
- 5 user stories, 23 functional requirements, 9 success criteria
- ~6 new CLI flags across `trace run` / `trace capture` / `sbom
  generate` / `sbom verify` (new subcommand) / `policy init` (new
  subcommand)
- ~1,500–2,000 net new LOC (estimated per `attestations.md` architecture
  doc's rough roadmap)
- Target: 5 committable milestones matching the user-story priority
  ladder (signing → subject → verifier glue → layout → enrichment)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Evaluating the 12 Core Principles and 4 Strict Boundaries against this
feature:

| # | Principle / Boundary | Verdict | Notes |
|---|---|---|---|
| I | Pure Rust, Zero C | ✓ Pass | `sigstore-rs` is pure Rust. Verify `cargo tree -e normal` shows no libz-sys, openssl-sys, or other C-linked deps before merging (Principle I audit gate). Rustls is already the TLS backend (milestone 005 precedent). |
| II | eBPF-Only Observation | ✓ Pass | Signing/verification layers attach on top of existing trace data; they do not introduce a new dependency-discovery mechanism. Subject detection reuses the existing eBPF-captured file-access events plus post-trace artifact walk — no new discovery source. |
| III | Fail Closed | ✓ Pass | Q3 clarification (hard-fail signing) explicitly aligns with this. No silent fallback to unsigned when signing was requested. |
| IV | Type-Driven Correctness | ✓ Pass | New types introduced: `SignedEnvelope`, `SigningIdentity` enum (`LocalKey {path, passphrase_env}` / `Keyless {oidc_provider, transparency_log}` / `None`), `ArtifactSubject` (vs. `SyntheticSubject`). All use `thiserror` for error definitions. No `.unwrap()` in new production code. |
| V | Specification Compliance | ✓ Pass | DSSE envelope per in-toto spec; Statement v1 payload unchanged; CycloneDX SBOM emission unchanged. Layouts conform to in-toto layout spec (FR-013). |
| VI | Three-Crate Architecture | ✓ Pass | All new code in `mikebom-cli/` and `mikebom-common/`. Types shared across kernel/user boundary (very few in this feature — mostly user-space) land in `mikebom-common/`. No new crates. |
| VII | Test Isolation | ✓ Pass | Unit tests use local-key signing (no network, no OIDC). Integration tests for keyless flow are gated behind env-var feature flag. eBPF capture tests continue to require privileges per existing policy. |
| VIII | Completeness | ✓ Pass | Subject auto-detection is additive — it does not remove components from the SBOM. If no artifact is detected, synthetic subject still signals the trace occurred. |
| IX | Accuracy | ✓ Pass | Subject SHA-256 is computed from actual disk bytes at attestation time (FR-011), not inferred from trace events. Synthetic-algorithm marker (`synthetic:` digest algorithm) prevents verifiers from treating non-file subjects as real hashes. |
| X | Transparency | ✓ Pass | Unsigned attestations carry a warning (FR-004); synthetic subjects are explicitly marked (FR-010); Rekor opt-out requires a visible flag (`--no-transparency-log`). Every degraded-posture decision surfaces to the operator. |
| XI | Enrichment | ✓ Pass | SBOM enrichment via JSON patch (US5) is strictly additive and preserves provenance (FR-016/017). If the patch source is unavailable, the base SBOM still emits. |
| XII | External Data Source Enrichment | ✓ Pass | Fulcio/Rekor are used for signing metadata, not for dependency discovery. Layout verification consumes external policy but doesn't introduce new components. Enrichment patches can add metadata to existing components but cannot introduce new ones (enforced by verifier design). |
| SB1 | No lockfile-based dependency discovery | ✓ Pass | Unchanged — this feature is about attestation envelope + signing, not discovery. |
| SB2 | No MITM proxy | ✓ Pass | Unchanged. |
| SB3 | No C code | ✓ Pass | Contingent on `sigstore-rs` being C-free — audit task in Phase 0. |
| SB4 | No `.unwrap()` in production | ✓ Pass | Enforced by `#![deny(clippy::unwrap_used)]` at crate root. |

**Constitution gate: PASS.** One item needs Phase 0 verification: confirm
`sigstore-rs` transitive deps are C-free. If they aren't, the implementation
path becomes narrower (carve out to pure-Rust alternatives or
`ring`/`rustls`-based libraries), but no constitutional amendment is
required — the feature is the same, the dependency choice changes.

## Project Structure

### Documentation (this feature)

```text
specs/006-sbomit-suite/
├── plan.md              # This file
├── spec.md              # User-facing feature specification
├── research.md          # Phase 0 output (dependency + signing research)
├── data-model.md        # Phase 1 output (new types + relationships)
├── quickstart.md        # Phase 1 output (user walkthrough)
├── contracts/
│   ├── cli.md           # CLI surface contract (new flags, subcommands)
│   └── attestation-envelope.md  # Signed-envelope schema contract
├── checklists/
│   └── requirements.md  # From /speckit.specify (already exists)
└── tasks.md             # /speckit.tasks output (NOT created here)
```

### Source Code (repository root)

```text
mikebom-common/src/attestation/
├── statement.rs         # EXISTING — in-toto Statement type; no change
└── envelope.rs          # NEW — DSSE envelope types (SignedEnvelope,
                         #       Signature, IdentityMetadata)

mikebom-cli/src/
├── attestation/
│   ├── builder.rs       # EDIT — subject auto-detection: call resolver,
│   │                    #        accept explicit --subject overrides
│   ├── serializer.rs    # EDIT — emit signed envelope when identity
│   │                    #        present, unsigned otherwise
│   ├── signer.rs        # NEW — SigningIdentity enum + sign() flow
│   │                    #       (local PEM path, keyless OIDC path)
│   ├── subject.rs       # NEW — auto-detect build artifacts from
│   │                    #       trace events + artifact-dir walks;
│   │                    #       ELF/Mach-O/PE magic detection
│   └── verifier.rs      # NEW — signature + subject + envelope checks;
│                        #       failure-mode enum for FR-022
├── cli/
│   ├── scan.rs          # EDIT — --signing-key / --keyless /
│   │                    #        --no-transparency-log flags; pass
│   │                    #        identity into attestation builder
│   ├── run.rs           # EDIT — thread signing flags through the
│   │                    #        composed scan→generate flow
│   ├── verify.rs        # NEW — `sbom verify` subcommand
│   └── policy.rs        # NEW — `policy init` layout-scaffold
└── policy/
    ├── layout.rs        # NEW — in-toto layout generation
    └── apply.rs         # NEW — layout verification against attestation
```

Note: per Principle VI (Three-Crate Architecture), all files stay in the
two user-space crates — `mikebom-common/` for shared types,
`mikebom-cli/` for logic. No fourth crate created.

**Structure Decision**: Extend the existing three-crate workspace.
Attestation-related additions cluster under `mikebom-cli/src/attestation/`
(alongside existing `builder.rs` and `serializer.rs`); layout work gets
its own `mikebom-cli/src/policy/` module (new); DSSE envelope types go
into `mikebom-common/src/attestation/envelope.rs` since they're shared
between sign (cli) and verify (cli) paths and may be consumed by future
downstream tooling.

## Phase 0 — Research

Four open questions to resolve before design. All required; none can be
deferred to Phase 1. See `research.md` for full writeups.

1. **sigstore-rs suitability audit**:
   - Does the current `sigstore` crate (or `sigstore-rs`) support:
     (a) DSSE sign + verify, (b) Fulcio keyless cert issuance via OIDC,
     (c) Rekor upload + inclusion proof retrieval, (d) local PEM with
     optional passphrase?
   - Is the transitive dep tree C-free per Constitution Principle I
     (audit `cargo tree -e normal` for `libz-sys`, `openssl-sys`,
     `c-bindings`, etc.)?
   - Is it actively maintained (last commit < 6 months, open issue
     response rate)?

2. **In-toto layout tooling**:
   - Is there a pure-Rust in-toto layout library, or do we build minimal
     layout generation + verification ourselves on top of `serde_json`?
   - What's the minimal layout schema for a single-step build-trace
     policy (functionary key, step name, expected artifact)?

3. **CycloneDX enrichment patch mechanics**:
   - RFC 6902 (JSON Patch) vs. JSON Merge Patch (RFC 7396): which is
     more expressive for CycloneDX-specific enrichments (adding to
     arrays like `licenses[]`, `properties[]`)? Answer drives FR-015.
   - Is there a Rust crate for canonical JSON Patch that handles the
     edge cases (Unicode normalization, key ordering for deterministic
     provenance hashes)?

4. **Fulcio / Rekor URLs + OIDC config**:
   - Default Fulcio + Rekor URLs (sigstore public-good instances
     `https://fulcio.sigstore.dev` / `https://rekor.sigstore.dev`) vs.
     private-instance flags.
   - GitHub Actions OIDC token flow — what's the required env-var
     ingestion (`ACTIONS_ID_TOKEN_REQUEST_URL` + `_TOKEN`) and the
     matching `sigstore-rs` API call?

**Output**: `research.md` with one Decision/Rationale/Alternatives block
per question. All NEEDS CLARIFICATION resolved before Phase 1 begins.

## Phase 1 — Design & Contracts

**Prerequisites**: `research.md` complete and all four open questions
decided.

### 1. Data model (`data-model.md`)

New types (all in `mikebom-common/` or `mikebom-cli/`):

- **`SignedEnvelope`** (DSSE shape) — `payload_type`, `payload`
  (base64-encoded in-toto Statement), `signatures[]` with per-signature
  `keyid`, `sig`, and `identity` (certificate chain for keyless, public
  key for local).
- **`SigningIdentity`** enum:
  - `LocalKey { path: PathBuf, passphrase_env: Option<String> }`
  - `Keyless { fulcio_url: Url, rekor_url: Url, oidc_provider: OidcProvider, transparency_log: bool }`
  - `None` (unsigned fallback)
- **`Subject`** enum replacing today's single-field approach:
  - `Artifact { name: String, digest: ContentHash }` (real file + SHA-256)
  - `Synthetic { name: String, synthetic_digest: String }` (per Q5: `digest.synthetic` key carries SHA-256 of command+start-time)
- **`VerificationReport`** — `Pass` | `Fail { mode: FailureMode, detail: String }`
  where `FailureMode` has variants from FR-022: `SignatureInvalid`,
  `IdentityMismatch`, `SubjectDigestMismatch`, `LayoutViolation`,
  `MalformedEnvelope`, `NotSigned`.
- **`Layout`** — minimal in-toto layout (`steps[]`, `functionaries[]`,
  `expected_artifacts[]`).
- **`EnrichmentPatch`** — `patches: Vec<JsonPatchOp>`, `author: String`,
  `timestamp: DateTime<Utc>`, `base_attestation_ref: String` (points at
  original attestation SHA-256).

Relationships: `Attestation → SignedEnvelope (1:0..1)`, `Attestation → Subject (1:N)`,
`SignedEnvelope → SigningIdentity (1:1)`, `Layout → Functionary (1:N)`,
`Verifier.verify(Attestation, Layout?) → VerificationReport`.

### 2. Contracts

- **`contracts/cli.md`** — complete CLI surface diff:
  - `mikebom trace run`: new flags `--signing-key`, `--signing-key-passphrase-env`,
    `--keyless`, `--no-transparency-log`, `--subject` (repeatable),
    `--artifact-dir` (existing, now feeds subject detection too).
  - `mikebom trace capture`: same flag additions.
  - `mikebom sbom generate`: passes through `--subject` when building
    SBOM from an already-signed attestation.
  - `mikebom sbom verify <attestation>` (NEW): flags `--layout`, `--public-key`,
    `--identity`, `--no-transparency-log`.
  - `mikebom policy init` (NEW): flags `--output`, `--functionary-key`,
    `--step-name`.
  - `mikebom sbom enrich <sbom>` (P3, EXISTING stub): flags `--patch`
    (repeatable), `--author`.
- **`contracts/attestation-envelope.md`** — JSON schema / example of the
  signed envelope, including the `payloadType` URI, DSSE field layout,
  and the synthetic-subject shape.

### 3. Quickstart (`quickstart.md`)

User walkthrough covering the P1 scenarios end-to-end:

- **Sign a build with a local key** (3 commands: generate key, `trace run --signing-key`, `sbom verify`).
- **Sign in CI with keyless identity** (GitHub Actions snippet showing
  the OIDC env vars + `mikebom trace run --keyless`).
- **Verify an attestation from another source** (demonstrate
  `sbom verify` accepting attestations produced by another
  SBOMit-compliant tool).
- **Override subject detection** (`--subject` flag).
- Out-of-quickstart (covered later): layouts, enrichment patches.

### 4. Agent context update

Run `.specify/scripts/bash/update-agent-context.sh claude` after plan is
complete so `CLAUDE.md` picks up the new signing-related technologies
(sigstore crate, DSSE, OIDC for keyless).

## Phase 1 re-check (Constitution, post-design)

After the data-model + contracts work is drafted, re-evaluate:

- **Principle I (Zero C)**: confirmed dep audit per Phase 0 research
  question #1. No violation.
- **Principle IV (Type-Driven)**: new types isolate external-source data
  (signatures, certificates, layouts) from domain types (Subject,
  SigningIdentity). No String leakage across boundaries.
- **Principle VI (Three crates)**: still two user-space crates.
  `mikebom-common/src/attestation/envelope.rs` is the only
  common-crate addition. Principle holds.
- **Strict Boundary 3 (No C)**: enforced by the dep audit.

Post-design: Constitution gate **PASS**.

## Complexity Tracking

No constitutional violations to justify. The feature stays within:

- Existing three-crate workspace (no new crates)
- Pure-Rust dependency posture (contingent on sigstore-rs audit)
- Existing attestation predicate URI (no schema break)
- Existing CLI noun-verb pattern (per user memory: `mikebom <noun> <verb>`)

The only area that could push against limits is the **in-toto layout
tooling** question (Phase 0 research item 2) — if no good pure-Rust
layout library exists, we build a minimal schema ourselves. That's
additive code, not a constitutional concern.

**Remaining deferrals from /speckit.clarify**:

- **Enrichment patch conflict semantics** — decided during Phase 0
  research item 3 (RFC 6902 vs. Merge Patch choice drives natural
  conflict-resolution semantics). P3 story; not blocking the P1 MVP.
