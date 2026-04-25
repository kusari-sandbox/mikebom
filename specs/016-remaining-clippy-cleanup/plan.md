# Implementation Plan: Address the 192 Deferred Clippy Warnings

**Branch**: `016-remaining-clippy-cleanup` | **Date**: 2026-04-25 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/016-remaining-clippy-cleanup/spec.md`

## Summary

Resolve the 192 clippy warnings that survived milestone 015's autofix pass (PR #33) and lock in a CI gate that prevents regressions. Two warning categories: ~150 `dead_code`-class items (most are platform-conditional Linux-only `trace/*` and `attestation/*` paths that look dead on macOS but live on Linux; some are genuinely orphaned) and ~37 `clippy::doc_lazy_continuation` warnings (doc comments mixing sub-bullets with prose continuation). Per-item triage chooses one of three outcomes — **remove** / **gate via `#[cfg(...)]`** / **annotate `#[allow(dead_code)]`** with planned-consumer comment. After cleanup, add a `macos-latest` GitHub Actions job alongside the existing `ubuntu-latest` job, both running `cargo +stable clippy --workspace --all-targets -- -D warnings`. End state: zero warnings on both OSes, no test regressions vs. the 1385-passing baseline.

## Technical Context

**Language/Version**: Rust stable (workspace toolchain inherited from milestones 001–015; no nightly required for this user-space-only work).
**Primary Dependencies**: existing only — `cargo +stable clippy` (lint engine), `dtolnay/rust-toolchain@stable` (already used in CI), `Swatinem/rust-cache@v2` (already used). **No new crates.**
**Storage**: N/A — purely source-tree edits.
**Testing**: `cargo +stable test --workspace` (1385 passed; 0 failed today). The new behavioral test surface is the CI gate itself: a deliberate-warning probe PR (per SC-003) verifies the gate fails when expected.
**Target Platform**: macOS 14+ (maintainer dev) + Linux x86_64 (CI). Both must reach zero warnings. Linux-only code (`mikebom-ebpf` crate; user-space `#[cfg(target_os = "linux")]` blocks under `cli/scan.rs`, `trace/loader.rs`, `trace/aggregator.rs`, `trace/processor.rs`, `trace/pid_tracker.rs`, `attestation/builder.rs`) MUST cleanly compile on macOS without `dead_code` warnings via the cfg-gate strategy.
**Project Type**: Workspace cleanup pass — no new crates, no new public APIs.
**Performance Goals**: `cargo clippy --workspace --all-targets` completes in <60s on cold cache and <20s on warm cache (local). The new macOS CI job adds ~5-10 min to total CI runtime per PR (per the resolved Q1 clarification).
**Constraints**:

- Zero behavioral changes — golden tests, determinism tests, holistic_parity, mapping_doc_bidirectional, parity_cmd, all spdx*/cdx*/scan_* suites stay green.
- No new runtime crates; this rules out tools like `cargo-deny` for the warning-prevention gate.
- `mikebom-ebpf` (`no_std` + `aya-ebpf`) builds only on Linux — the macOS CI job MUST skip its eBPF-build step but still build + test the user-space `mikebom-cli` and `mikebom-common` crates.
- Constitution Principle IV (Type-Driven Correctness, no `.unwrap()` in production) — the cleanup MUST NOT introduce new `.unwrap()` calls; if a removed function was the only `.unwrap()`-shielding helper, the caller must not regress.

**Scale/Scope**: ~192 warnings across ~30 source files in `mikebom-cli/src/{attestation,trace,enrich,resolve,scan_fs,config.rs,cli/}` plus a smaller cluster in `mikebom-cli/tests/cdx_regression.rs` and `mikebom-common/src/attestation/`. CI workflow file: 1 modified, ~30 lines added.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Bearing on this feature | Pass? |
|-----------|-------------------------|-------|
| I. Pure Rust, Zero C | Cleanup adds no C dependencies; no new build-script tooling required. | ✓ |
| II. eBPF-Only Observation | Untouched — observation semantics unchanged; this feature only annotates / removes / gates code that surrounds the eBPF surface. | ✓ |
| III. Fail Closed | Untouched — failure modes unchanged. | ✓ |
| IV. Type-Driven Correctness | The cleanup MUST NOT introduce new `.unwrap()` in production. Removed code that was previously hosting `.unwrap()` calls is fine; replacement / gating preserves the deny. | ✓ |
| V. Specification Compliance | Untouched — no SBOM emission changes. The full test suite (including determinism + golden + parity tests) is the regression guard. | ✓ |
| VI. Three-Crate Architecture | No new crates introduced. Workspace stays at `mikebom-cli` (lib + bin), `mikebom-common`, `mikebom-ebpf`. | ✓ |
| VII. Test Isolation | The new macOS CI job runs without root / `CAP_BPF` (eBPF tests are gated and skip there cleanly today; verified by the existing `cargo test --workspace` already running on Linux without privileges). | ✓ |
| VIII–XII (Completeness, Accuracy, Transparency, Enrichment, External Sources) | Untouched. | ✓ |
| Strict Boundary 4 (`No .unwrap()` in production) | Same as IV — the cleanup MUST NOT regress this. Test code's `#[cfg_attr(test, allow(clippy::unwrap_used))]` guards stay. | ✓ |
| Pre-PR Verification (table at constitution.md:357-360) | This feature TIGHTENS the requirement — the new gate adds `-- -D warnings` to clippy invocation. Constitution language at line 359 currently says only "Zero errors". After this feature ships, that line should read "Zero errors AND zero warnings" to reflect reality. **Treated as a documentation follow-up — not a blocking constitutional change**, since the spirit ("clean clippy") is preserved and the Pre-PR table is descriptive of CI, not prescriptive of the lint level. The implementation MUST update the constitution table in the same PR to keep them synchronized. | ✓ (with mandatory doc update) |

**Initial gate**: PASS. No principle violations; one descriptive doc-table update is bundled into the implementation PR.

## Project Structure

### Documentation (this feature)

```text
specs/016-remaining-clippy-cleanup/
├── spec.md                  # Feature spec (already written)
├── plan.md                  # This file
├── research.md              # Phase 0 — chosen approaches (--deny mechanism, cfg-gate strategy, macOS CI shape)
├── data-model.md            # Phase 1 — minimal: triage-decision record format
├── quickstart.md            # Phase 1 — how a contributor verifies fix locally + on CI
├── contracts/
│   └── ci-clippy-gate.md    # The new clippy-gate contract (the only "interface" this feature adds)
├── checklists/
│   └── requirements.md      # spec quality checklist (already written)
└── tasks.md                 # Phase 2 output (NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
.github/workflows/
└── ci.yml                          # MODIFIED: add macos-latest job; add `-- -D warnings` to clippy step on both jobs

.specify/memory/
└── constitution.md                 # MODIFIED: pre-PR table at line 359 — "Zero errors" → "Zero errors AND zero warnings" (descriptive follow-up; sync-impact-report bumps to 1.3.1 PATCH)

mikebom-cli/src/
├── attestation/                    # MODIFIED: triage builder.rs / serializer.rs / signer.rs / subject.rs / witness_builder.rs / verifier.rs items
├── cli/                            # MODIFIED: scan.rs, generate.rs, verify.rs, auto_dirs.rs (small cluster of cfg-gates)
├── config.rs                       # MODIFIED: 10 unused constants — most legitimate (referenced via macros / cfg paths); a few may delete
├── enrich/                         # MODIFIED: ~30 unused fns (deps_dev_client, license_resolver, vex_builder, supplier_resolver, clearly_defined_*) — most genuinely orphaned, candidates for removal
├── resolve/                        # MODIFIED: url_resolver, path_resolver, purl_validator, hash_resolver — mix of unused + still-referenced
├── scan_fs/                        # MODIFIED: docker_image.rs, binary/elf.rs (small clusters — mostly cfg-gate of Linux-only paths)
└── trace/                          # MODIFIED: aggregator.rs, processor.rs, pid_tracker.rs, sni_extractor.rs, http_parser.rs, loader.rs — bulk of the Linux-only cfg-gate work

mikebom-common/src/attestation/
├── envelope.rs                     # MODIFIED: 1 doc-list warning at :183
└── witness.rs                      # MODIFIED: 3 doc-list warnings at :5–7

mikebom-cli/tests/
└── cdx_regression.rs               # MODIFIED: 10 doc-list warnings at :156–165 (single comment block)
```

**Structure Decision**: Single-workspace cleanup. No new directories or crates. The implementation is concentrated in three areas: (a) per-file source edits to triage dead-code items in-place, (b) a CI workflow update adding the `macos-latest` job and tightening clippy to `-- -D warnings`, and (c) a constitution-doc update to keep its pre-PR table in sync with the new lint level.

## Complexity Tracking

> No constitution violations to justify. Complexity is in the *count* of items to triage (~150 dead-code + ~37 doc-list), not in any architectural deviation. The triage workflow is mechanical-with-judgment: for each warning, pick remove / gate / annotate; rerun clippy; repeat until zero. The CI job addition is a standard GitHub Actions matrix expansion.
