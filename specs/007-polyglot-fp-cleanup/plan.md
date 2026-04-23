# Implementation Plan: Close Remaining Polyglot Bake-Off False Positives

**Branch**: `007-polyglot-fp-cleanup` | **Date**: 2026-04-23 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/007-polyglot-fp-cleanup/spec.md`

## Summary

Three targeted filesystem-scanner changes that close 17 of the 23 remaining false positives on the polyglot-builder-image bake-off:

1. **Fedora sidecar-POM reading** (Story 1, 12 FPs). When a JAR under a Fedora rootfs lacks embedded `META-INF/maven/` metadata, look for the matching sidecar POM under `/usr/share/maven-poms/` (filename conventions: `JPP-<name>.pom` and plain `<name>.pom`), parse its coordinates with the existing `quick-xml`-backed POM reader, resolve one level of `<parent>` inheritance when the parent POM is also on disk, and emit the resulting `pkg:maven/<g>/<a>@<v>` component related to the JAR.

2. **Go test-scope filter via intersection** (Story 2, 4 FPs). When both a compiled Go binary's BuildInfo set AND the Go source tree are available on the same rootfs, the production set is the *intersection* of (a) BuildInfo-linked modules and (b) modules reachable from non-`_test.go` imports. When only one signal is available, fall back to it alone. This extends the existing G3 filter (merged on main) with static source-import analysis.

3. **Go project-self exclusion** (Story 3, 1 FP). Drop the module declared in go.mod's `module` directive (and BuildInfo's `mod` line) from the dependency emissions; a project is not its own dependency.

Pure scan-mode feature. No eBPF code touched. No new workspace crates. Extends existing `mikebom-cli/src/scan_fs/package_db/{maven,golang,go_binary}.rs` plus a new aggregation filter callsite alongside the G3 filter in `package_db/mod.rs`.

## Technical Context

**Language/Version**: Rust stable, same workspace toolchain as milestones 001–006. No nightly features. `mikebom-ebpf` untouched.
**Primary Dependencies**: Existing only — `quick-xml = "0.31"` for POM parsing (already used in `maven.rs`), `walkdir`, `serde`/`serde_json`, `tracing`. No new crates.
**Storage**: N/A — in-memory per scan; no persistence.
**Testing**: `cargo test -p mikebom` (unit + integration). Integration fixtures live under `mikebom-cli/tests/fixtures/`.
**Target Platform**: Any host mikebom already runs on — Linux/macOS user-space. No eBPF requirement for this feature.
**Project Type**: CLI scanner (extends existing `scan_fs` subsystem).
**Performance Goals**: Sidecar-POM lookup must add ≤5% to total scan wall-time on the polyglot fixture (baseline: ~400ms). Go import analysis must complete in ≤200ms for a 100-file source tree.
**Constraints**: Offline-only; no network calls. Single-pass over the rootfs (no re-walks). All filters must no-op when their required signals are absent (e.g., no binary → BuildInfo side of intersection drops out).
**Scale/Scope**: Polyglot-builder-image is ~500 Maven components, ~10 Go modules, ~600 other-ecosystem entries. Feature must scale to container images with thousands of JARs.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Scope note**: This feature operates in mikebom's *scan mode* (filesystem scanner for pre-built rootfs / container images), not *trace mode* (eBPF build observation). The constitution's eBPF-only discovery requirements (Principles II, III; Strict Boundary #1) govern trace mode; they do not apply to scan mode, which is an independent subsystem under `scan_fs/package_db/` that has existed since milestone 002 and is the subject of every recent feature. The remaining principles are evaluated below.

| Principle | Compliance | Notes |
|---|---|---|
| I. Pure Rust, Zero C | ✅ | No C dependencies added. `quick-xml` and `walkdir` are pure Rust. |
| II. eBPF-Only Observation | N/A (scan mode) | Feature is scan-mode only; does not claim build-time observation. |
| III. Fail Closed | ✅ | Filters no-op when signals are absent; scan never fabricates coordinates. When sidecar POM parsing fails, fall back to generic-binary emission and log a warning — no silent omission of the JAR. |
| IV. Type-Driven Correctness | ✅ | Extends existing `Purl`, `PackageDbEntry`, `SbomTier` types. No new `String`-based cross-boundary values. No `.unwrap()` in production code. |
| V. Specification Compliance | ✅ | Maven coordinates emitted as validated `pkg:maven/<g>/<a>@<v>` PURLs conforming to existing PURL helpers in `generate/cpe.rs`. CycloneDX 1.6 serialization path unchanged. |
| VI. Three-Crate Architecture | ✅ | No new crates. Changes confined to `mikebom-cli`. |
| VII. Test Isolation | ✅ | New tests run under `cargo test -p mikebom` without elevated privileges. No eBPF test changes. |
| VIII. Completeness | ✅ | Sidecar-POM reading *increases* completeness (recovers 12 Maven components currently emitted only as generic binaries). The two filters *also* serve completeness by producing output that matches observable reality. |
| IX. Accuracy | ✅ | Primary goal of the feature. Reduces 17 false positives. Filters operate on deterministic static signals; no heuristic guessing. |
| X. Transparency | ✅ | FR-015 requires structured INFO-level diagnostics naming each filter, drop count, and context. FR-009 requires an explicit `sbom-tier` marker for reduced-confidence go.mod-only fallback. |
| XI. Enrichment | ✅ | Sidecar-POM reading is enrichment of a binary-discovered artifact — the JAR is already observed; the sidecar POM adds coordinates, license, and parent metadata. No components introduced without the JAR being present on disk. |
| XII. External Data Source Enrichment | ✅ | Sidecar POM is an on-disk file, not an external service. Feature is fully offline. Coordinates resolved only when the parent POM is physically present; network lookups explicitly out of scope. |

**Gate: PASS.** No violations. No Complexity Tracking entries required.

## Project Structure

### Documentation (this feature)

```text
specs/007-polyglot-fp-cleanup/
├── plan.md              # This file (/speckit.plan command output)
├── spec.md              # Feature spec (from /speckit.specify + /speckit.clarify)
├── research.md          # Phase 0 output (/speckit.plan)
├── data-model.md        # Phase 1 output (/speckit.plan)
├── quickstart.md        # Phase 1 output (/speckit.plan)
├── contracts/           # Phase 1 output (/speckit.plan) — internal scanner contracts
│   ├── sidecar-pom-lookup.md
│   ├── go-production-set.md
│   └── main-module-exclusion.md
├── checklists/
│   └── requirements.md  # Spec quality checklist (already created)
└── tasks.md             # Phase 2 output (/speckit.tasks command — NOT created here)
```

### Source Code (repository root)

```text
mikebom-cli/
├── src/
│   ├── scan_fs/
│   │   ├── mod.rs                                 # May need a minor hook for new filter
│   │   └── package_db/
│   │       ├── mod.rs                             # EXTEND: new aggregation filter callsites
│   │       │                                      #   - apply_go_test_scope_filter(entries)
│   │       │                                      #   - apply_go_main_module_filter(entries)
│   │       ├── maven.rs                           # EXTEND: sidecar POM lookup + parent resolution
│   │       ├── maven_sidecar.rs                   # NEW: isolated Fedora sidecar reader (keeps
│   │       │                                      #   maven.rs from growing past 5000 lines)
│   │       ├── golang.rs                          # EXTEND: expose source-import graph walker
│   │       ├── go_binary.rs                       # unchanged (already emits analyzed-tier set)
│   │       └── ...
│   └── ...
└── tests/
    ├── scan_go.rs                                 # EXTEND: 4 new integration tests
    ├── scan_maven_sidecar.rs                      # NEW: 5 new integration tests for Story 1
    └── fixtures/
        ├── go/
        │   └── source_with_test_imports/          # NEW fixture: go.mod + .go + _test.go
        └── maven/
            └── fedora_sidecar/                    # NEW fixture: JAR + sidecar POM tree
                ├── usr/share/maven/lib/guice-5.1.0.jar
                ├── usr/share/maven-poms/JPP-guice.pom
                └── usr/share/maven-poms/guice-parent.pom  (for inheritance tests)
```

**Structure Decision**: Single-crate extension within `mikebom-cli`. All changes in the existing `scan_fs/package_db/` subsystem. One new submodule (`maven_sidecar.rs`) to keep `maven.rs` bounded — 4648 lines is already at the point where new features should live in siblings. No workspace changes, no new crates.

## Complexity Tracking

None. All work fits within the existing scan-mode architecture, using existing types and dependencies. No constitution violations to justify.
