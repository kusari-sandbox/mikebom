# Implementation Plan: Close Last Polyglot Bake-Off Findings

**Branch**: `008-polyglot-final-cleanup` | **Date**: 2026-04-23 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/008-polyglot-final-cleanup/spec.md`

## Summary

Investigation-first feature. Four user stories:

1. **US1 (P1)** — Investigate why US2 (Go test-scope intersection) and US4 (Maven Main-Class executable-JAR heuristic) merged with passing tests but didn't close their target FPs on the polyglot-builder-image bake-off. Deliverable: `investigation.md` with per-FP root cause and minimal-fix candidate.
2. **US2 (P2)** — For Go FPs Story 1 finds statically closable, ship the minimal code change. For Go FPs that no static signal can close, move to Story 4 as known limitations. No Go toolchain invocation — that's out-of-scope future work (FU-001).
3. **US3 (P3)** — Same structure for the Maven `sbom-fixture@1.0.0` case.
4. **US4 (P4)** — Document the commons-compress 1.21 vs 1.23.0 convention choice (and any Story 2/3 known-limitation FPs) in the design-notes.

Phase 0 research here doubles as Story 1's code-path investigation — done via source reading against `main` at `b06eda8` (post-007 merge). Running mikebom against the actual polyglot rootfs is a discrete step listed below; it requires fixture access that this plan makes explicit.

## Technical Context

**Language/Version**: Rust stable, same workspace as milestones 001–007. No nightly features. `mikebom-ebpf` untouched.
**Primary Dependencies**: Existing only — `quick-xml`, `zip`, `walkdir`, `serde`/`serde_json`, `tracing`. No new crates.
**Storage**: N/A — in-memory per scan.
**Testing**: `cargo +stable clippy --workspace --all-targets` + `cargo +stable test --workspace` per constitution v1.2.1.
**Target Platform**: Any host mikebom runs on; scan-mode only.
**Project Type**: CLI scanner investigation + minimal targeted fix.
**Performance Goals**: No regression vs. post-007 baseline (1119 passing tests).
**Constraints**: Static analysis only for Go filtering — no runtime `go list` invocation (feature 007 FR-007, re-affirmed here).
**Scale/Scope**: At most 5 PURLs addressed by mikebom code change; 1 documented as known upstream-data case. Two existing filters (US2, US4) may need adjustment. No new filters introduced unless Story 1 demonstrates one is unavoidable.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Scope note**: Scan mode only (same as feature 007). Trace-mode principles (II, III) and Strict Boundary #1 do not apply. Relevant principles evaluated below.

| Principle | Compliance | Notes |
|---|---|---|
| I. Pure Rust, Zero C | ✅ | No C deps added. |
| II. eBPF-Only Observation | N/A (scan mode) | Feature doesn't claim build-time observation. |
| III. Fail Closed | ✅ | Filters no-op when signals absent; nothing fabricated. |
| IV. Type-Driven Correctness | ✅ | Reuses existing `Purl`, `PackageDbEntry`, `GoScanSignals`, `EmbeddedMavenMeta` types. No `.unwrap()` in production paths (test modules gate via `#[cfg_attr(test, allow(clippy::unwrap_used))]` per CLAUDE.md). |
| V. Specification Compliance | ✅ | CycloneDX 1.6, PURL spec unchanged. Maven coord promotion to `metadata.component` (if implemented) aligns with spec convention. |
| VI. Three-Crate Architecture | ✅ | No new crates. |
| VII. Test Isolation | ✅ | Tests run without elevated privileges. |
| VIII. Completeness | ✅ | Feature only tightens emissions; no over-suppression of real components. Story 3 FR-007 asserts library JARs with Main-Class are still emitted. |
| IX. Accuracy | ✅ | Primary goal of the feature — reduces FPs. |
| X. Transparency | ✅ | `investigation.md` is a transparency artifact. Known-limitation documentation cross-references FU-001 so operators understand what mikebom chose not to close. |
| XI. Enrichment | ✅ | No impact. |
| XII. External Data Source Enrichment | ✅ | No external sources. All signals on-disk. |
| Governance / Pre-PR Verification (v1.2.1) | ✅ | Each PR runs `cargo +stable clippy --workspace --all-targets` and `cargo +stable test --workspace` clean before opening. |

**Gate: PASS.** No violations. No Complexity Tracking entries.

## Project Structure

### Documentation (this feature)

```text
specs/008-polyglot-final-cleanup/
├── plan.md              # This file
├── spec.md              # Feature spec (already clarified)
├── research.md          # Phase 0 — code-path investigation (this command)
├── investigation.md     # Story 1 deliverable — polyglot-fixture evidence (Phase 2 tasks)
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1
├── contracts/           # Phase 1
│   └── investigation-evidence.md
├── checklists/
│   └── requirements.md  # Already created
└── tasks.md             # Phase 2 (/speckit.tasks)
```

### Source Code (repository root)

```text
mikebom-cli/
├── src/
│   └── scan_fs/
│       └── package_db/
│           ├── golang.rs       # Possibly touched in Story 2 (depends on Story 1)
│           ├── go_binary.rs    # Possibly touched in Story 2
│           ├── mod.rs          # G4/G5 filter callsites — possibly adjusted
│           ├── maven.rs        # Possibly touched in Story 3
│           └── maven_sidecar.rs  # Unchanged
└── tests/
    ├── scan_go.rs              # +1 regression test per Story 2 fix
    └── scan_maven_executable_jar.rs  # +1 regression test per Story 3 fix

docs/
└── design-notes.md     # Story 4 — commons-compress + any Story 2/3 known-limitation docs
```

**Structure Decision**: No new files unless Story 1's investigation demands it. Edits are narrow and targeted. Any new fixture files land under `tests/fixtures/` matching the existing feature 007 layout.

## Complexity Tracking

None. Feature is investigation + targeted fix + documentation within the existing scan-mode architecture.
