# Implementation Plan: SPDX Output Support (2.3 with groundwork for 3+)

**Branch**: `010-spdx-output-support` | **Date**: 2026-04-23 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/010-spdx-output-support/spec.md`

## Summary

Add SPDX 2.3 JSON as a peer output format to the existing CycloneDX 1.6 JSON output of `mikebom sbom scan`. Ship a minimal-but-valid SPDX 3.0.1 stub emitter (one ecosystem, opt-in) to exercise the format-neutral serializer interface in real code. Preserve mikebom-specific fields (`mikebom:*` properties, evidence, compositions) losslessly via SPDX `annotations[]` with a mikebom-namespaced JSON envelope; emit CycloneDX `vulnerabilities[]` (VEX) as a separate OpenVEX 0.2.0 JSON sidecar referenced from the SPDX document. Allow a single `mikebom sbom scan` invocation to emit any subset of supported formats from one scan to avoid redundant rescanning. Ship a committed dual-format data-placement map under `docs/reference/sbom-format-mapping.md` that documents, for every emitted data element, its location in CycloneDX, SPDX 2.3, and SPDX 3, with a one-line justification per row.

The feature is purely additive: scan, resolution, and the existing CycloneDX serializer must produce byte-identical output before and after this milestone, enforced by a regression test.

## Technical Context

**Language/Version**: Rust stable (same workspace toolchain as milestones 001–009). No nightly features. `mikebom-ebpf` is untouched — this milestone is user-space only.

**Primary Dependencies**:
- *Existing, already in the workspace*: `cyclonedx-bom`, `spdx` (Embark Studios, v0.13.x — license expression canonicalization, already used since milestone 009), `serde`, `serde_json`, `tracing`, `clap`, `thiserror`, `anyhow`, `chrono`, `sha2`.
- *New for this milestone*: `jsonschema = "0.46"` (pure-Rust SPDX/OpenVEX JSON schema validator, used in tests only).
- *Not adopted*: `spdx-rs` (parser-first, dormant >30 months) and `openvex` v0.1.1 (3 years stale, 89 LoC). Both are replaced by hand-written `serde`-derived structs in `mikebom-cli/src/generate/{spdx,openvex}/` — see `research.md` for the tradeoff analysis.

**Storage**: N/A — all state is in-process for the duration of a single scan, mirroring milestones 002–009.

**Testing**: `cargo +stable test --workspace` (per-crate unit tests + workspace-level integration). New tests:
- Per-ecosystem SPDX 2.3 schema validation against the vendored `spdx-schema-v2.3.json` using `jsonschema` (pure-Rust, no Python/JVM).
- Cross-format parity tests: same fixture → CDX + SPDX, assert PURL/version/checksum parity by walking both outputs.
- Determinism test: two sequential scans → assert byte-identical output except SPDX `created` and `documentNamespace`.
- CDX regression test: pinned fixture outputs from before-milestone are byte-identical to after-milestone.
- SPDX 3 stub test: with experimental opt-in, validate against vendored SPDX 3.0.1 JSON schema; without opt-in, output is byte-identical to a build without the stub.

**Target Platform**: Same as today — Linux-first (where eBPF tracing is supported); macOS scan-mode supported (per memory). SPDX serialization is platform-independent.

**Project Type**: Single Cargo workspace, three crates per Constitution Principle VI. New code lives entirely in `mikebom-cli`.

**Performance Goals**:
- Single-format scan time MUST NOT regress measurably vs pre-milestone CDX-only baseline (target: <2% wall-clock difference on representative fixtures).
- Dual-format scan (CDX + SPDX in one invocation) MUST be at least 30% faster than two sequential single-format invocations on a representative image-scan fixture (per SC-009), reflecting that deep-hash and layer-walk work runs once.
- Memory ceiling MUST NOT exceed the existing CDX ceiling for the same scan.

**Constraints**:
- Deterministic output: byte-identical across reruns except SPDX `created` and `documentNamespace` (FR-020, SC-007).
- No `.unwrap()` in production code (Constitution Principle IV).
- All emitted PURLs and SPDX license expressions canonical (Principle V; PURL spec; `spdx::Expression::canonicalize`).
- No new crates in the workspace beyond `jsonschema` (test-only).

**Scale/Scope**: Same 9 ecosystems mikebom covers today (apk, cargo, deb, gem, golang, maven, npm, pip, rpm). Component counts up to ~tens of thousands per scan (full-OS image case). New code budget: ~600 LoC of serializer + ~400 LoC of tests + ~150 LoC for the SPDX 3 stub + the data-placement map document.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I — Pure Rust, Zero C | ✅ PASS | All new crates pure Rust (`jsonschema` 0.46 deps verified — no `bindgen`, no `cc`). Hand-written serializers use only `serde`/`serde_json`. |
| II — eBPF-Only Observation | ✅ PASS (out of scope) | This milestone touches only the `sbom scan` (static) path's serialization layer. Discovery semantics, eBPF trace, and the `sbom generate` (trace) path are untouched. |
| III — Fail Closed | ✅ PASS | When SPDX serialization fails (e.g., un-canonicalizable license expression in a code path that should not be reachable), error propagates with `anyhow`; no fallback. |
| IV — Type-Driven Correctness | ✅ PASS | New types: `SpdxId(String)` newtype, `SpdxLicenseExpression` (wraps `spdx::Expression`), `SpdxDocumentNamespace(Url)`. No raw `String` across boundaries. No `.unwrap()` in production; `#[cfg_attr(test, allow(clippy::unwrap_used))]` on test modules per CLAUDE.md convention. |
| V — Specification Compliance | ✅ PASS | Principle V (constitution v1.3.0, amended 2026-04-23) permits both SPDX 2.3 and SPDX 3.x and requires experimental SPDX 3 emitters to be visibly labeled. This milestone honors both: SPDX 2.3 as the stable format, SPDX 3.0.1 as the opt-in stub with `[EXPERIMENTAL]` labeling in CLI help, the `mikebom.spdx3-experimental.json` filename, and the produced document's tool comment (FR-019a, FR-019b). PURLs canonicalized via the `spdx` crate; CISA Minimum Elements satisfied via existing `mikebom:generation-context` metadata. |
| VI — Three-Crate Architecture | ✅ PASS | All new code in `mikebom-cli`. No new crate in the workspace. |
| VII — Test Isolation | ✅ PASS | All SPDX/OpenVEX tests are pure logic, run in unprivileged CI, no eBPF involvement. |
| VIII — Completeness | ✅ PASS (preserved) | SPDX output covers exactly the components mikebom already discovers and emits in CDX (FR-006, FR-022). No new omissions; no new additions. |
| IX — Accuracy | ✅ PASS (preserved) | Same input set as CDX. No phantom components introduced. |
| X — Transparency | ✅ PASS (strengthened) | Mikebom-specific evidence/confidence/source-files preserved in SPDX `annotations[]` per FR-016. No silent loss across format boundary. |
| XI — Enrichment | ✅ PASS (preserved) | License/supplier/hash enrichment available to SPDX serializer via the same `ResolvedComponent` model. VEX preserved via OpenVEX sidecar (FR-016a). |
| XII — External Data Source Enrichment | ✅ PASS (out of scope) | Serialization-only milestone; no new external sources. |
| Strict Boundary 1 — No lockfile-based discovery | ✅ PASS | No change. |
| Strict Boundary 2 — No MITM proxy | ✅ PASS | No change. |
| Strict Boundary 3 — No C code | ✅ PASS | Verified for `jsonschema` and all transitive deps. |
| Strict Boundary 4 — No `.unwrap()` in production | ✅ PASS | Test modules use `#[cfg_attr(test, allow(clippy::unwrap_used))]` per CLAUDE.md. |
| Pre-PR verification | ✅ ENFORCED | Plan requires `cargo +stable clippy --workspace --all-targets` and `cargo +stable test --workspace` both clean before PR. |

**Gate result**: PASS — no violations, no documented deviations. (Originally drafted with one deviation against the pre-1.3.0 Principle V; resolved by the constitution amendment landed on 2026-04-23.)

## Project Structure

### Documentation (this feature)

```text
specs/010-spdx-output-support/
├── plan.md                        # This file
├── spec.md                        # Feature spec (with Clarifications section)
├── research.md                    # Phase 0 output
├── data-model.md                  # Phase 1 output — internal types
├── quickstart.md                  # Phase 1 output — user-facing usage
├── contracts/
│   ├── cli-format-flag.md         # CLI surface contract for --format
│   ├── sbom-format-mapping.md     # Dual-format data-placement map (canonical copy; ships under docs/reference/ in code)
│   ├── mikebom-annotation.schema.json  # JSON schema for the envelope inside SPDX annotations[].comment
│   ├── spdx-2.3.schema.json       # Vendored SPDX 2.3 JSON schema (test fixture reference)
│   ├── spdx-3.0.1.schema.json     # Vendored SPDX 3.0.1 JSON schema (test fixture reference)
│   └── openvex-0.2.0.schema.json  # Vendored OpenVEX 0.2.0 JSON schema (test fixture reference)
├── checklists/
│   └── requirements.md            # Spec quality checklist
└── tasks.md                       # Phase 2 output (created by /speckit.tasks — NOT this command)
```

### Source Code (repository root)

```text
mikebom-cli/
├── src/
│   ├── generate/
│   │   ├── mod.rs                              # SerializerRegistry — format-dispatch layer (FR-019)
│   │   ├── cyclonedx/                          # UNCHANGED. Verified byte-identical by SC-006.
│   │   │   ├── mod.rs
│   │   │   ├── builder.rs
│   │   │   ├── components.rs
│   │   │   ├── compositions.rs
│   │   │   ├── dependencies.rs
│   │   │   ├── metadata.rs
│   │   │   └── vulnerabilities.rs
│   │   ├── spdx/                               # NEW. SPDX 2.3 JSON serializer (replaces existing stubs).
│   │   │   ├── mod.rs                          # Public entry: serialize_v2_3(&[ResolvedComponent], &[Relationship], &OutputConfig) -> serde_json::Value
│   │   │   ├── document.rs                     # SpdxDocument envelope, creationInfo, documentNamespace
│   │   │   ├── packages.rs                     # SpdxPackage builder, externalRefs[purl], checksums, licenses
│   │   │   ├── relationships.rs                # DEPENDS_ON / DEV_DEPENDENCY_OF / CONTAINS / DESCRIBES
│   │   │   ├── annotations.rs                  # mikebom-namespaced annotation envelopes (FR-016)
│   │   │   ├── ids.rs                          # SpdxId newtype + deterministic derivation from PURL
│   │   │   └── v3_stub.rs                      # SPDX 3.0.1 minimal stub (FR-019a, opt-in only)
│   │   └── openvex/                            # NEW. OpenVEX 0.2.0 JSON sidecar.
│   │       ├── mod.rs                          # serialize(&[Vulnerability], &OutputConfig) -> serde_json::Value
│   │       └── statements.rs                   # OpenVexStatement, mapping from CDX vulnerability records
│   ├── sbom/
│   │   └── scan_cmd.rs                         # MODIFIED: --format accepts a list (FR-004); registry dispatch
│   └── ...
└── tests/
    ├── spdx_schema_validation.rs               # NEW: per-ecosystem SPDX 2.3 schema validation
    ├── spdx_cdx_parity.rs                      # NEW: cross-format parity by PURL
    ├── spdx_determinism.rs                     # NEW: byte-identical reruns (modulo created/documentNamespace)
    ├── cdx_regression.rs                       # NEW: pinned pre-milestone CDX fixtures byte-identical
    ├── spdx3_stub.rs                           # NEW: opt-in produces valid SPDX 3.0.1; off = no change
    ├── openvex_sidecar.rs                      # NEW: VEX present → sidecar written + referenced; absent → no file
    └── fixtures/
        ├── schemas/                            # Vendored JSON schemas
        │   ├── spdx-2.3.json
        │   ├── spdx-3.0.1.json
        │   └── openvex-0.2.0.json
        └── golden/                             # Pinned outputs for regression
            └── ...

docs/
├── reference/
│   └── sbom-format-mapping.md                  # NEW. Canonical data-placement map (FR-013, FR-014). Ships in repo.
├── design-notes.md                             # MODIFIED (small): note SPDX 2.3 + SPDX 3 stub status, link to mapping doc
└── user-guide/
    └── cli-reference.md                        # MODIFIED: document --format multi-value, new format identifiers
```

**Structure Decision**: Single Cargo workspace, three crates per Constitution Principle VI. All new code lives under `mikebom-cli/src/generate/{spdx,openvex}/` plus a small dispatch surface in `generate/mod.rs` and a flag-list change in `sbom/scan_cmd.rs`. Documentation deliverable (`sbom-format-mapping.md`) is committed under `docs/reference/`, with a copy mirrored into `specs/010-spdx-output-support/contracts/` for plan-review purposes; the canonical version is the one under `docs/`.

## Complexity Tracking

No constitution violations to track. This milestone has no exceptions to flag.

(Earlier drafts of this plan documented one deviation: shipping SPDX 2.3 + SPDX 3.0.1 against the pre-1.3.0 Principle V wording, which had named SPDX 3.1 specifically. That deviation was resolved by amending Principle V to permit both SPDX 2.3 and SPDX 3.x — see constitution v1.3.0, ratified 2026-04-23. The original three-column violation entry is preserved in this file's git history if reviewers want the full alternatives-considered narrative.)
