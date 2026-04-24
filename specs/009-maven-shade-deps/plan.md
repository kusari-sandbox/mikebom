# Implementation Plan: Emit Shade-Relocated Maven Dependencies

**Branch**: `009-maven-shade-deps` | **Date**: 2026-04-23 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/009-maven-shade-deps/spec.md`

## Summary

Extend `mikebom-cli/src/scan_fs/package_db/maven.rs` to parse embedded `META-INF/DEPENDENCIES` files during the existing JAR walk and emit one nested `PackageDbEntry` per declared ancestor coord. Each emission carries:

- `purl` = `pkg:maven/<g>/<a>@<v>` (with `?classifier=<value>` qualifier when the 5-part form is present)
- `parent_purl` = enclosing JAR's primary coord PURL
- `sbom_tier` = `"analyzed"`
- `co_owned_by` = inherited from enclosing JAR
- `licenses[]` = SPDX expression parsed from the `License:` continuation line (via existing `SpdxExpression::try_canonical`)
- Property `mikebom:shade-relocation = true` surfaced by the CDX serializer

Self-references and duplicates are de-duplicated within a single JAR. Non-shaded JARs (no DEPENDENCIES file) produce byte-for-byte identical output to pre-feature behavior.

## Technical Context

**Language/Version**: Rust stable, same workspace as milestones 001–008. No nightly features. `mikebom-ebpf` untouched.
**Primary Dependencies**: Existing only — `zip` (archive read), `spdx` (via `SpdxExpression::try_canonical`), `tracing`. No new crates.
**Storage**: N/A — in-memory per scan.
**Testing**: `cargo +stable clippy --workspace --all-targets` + `cargo +stable test --workspace` per constitution v1.2.1.
**Target Platform**: Any host mikebom runs on; scan-mode only.
**Project Type**: CLI scanner feature, additive to the existing Maven reader.
**Performance Goals**: No regression vs post-008 baseline (1128 passing). Parsing a `META-INF/DEPENDENCIES` text block is trivially fast (single pass over ≤a few KB per JAR); amortizes into the existing zip-archive iteration.
**Constraints**: Additive emission only — non-shaded JAR output must be identical to pre-feature output (spec FR-011). No new CLI flags.
**Scale/Scope**: Per-JAR parse of one small text file. At most ~50 ancestor coords per JAR in realistic fat-jars. ~100-200 lines of Rust + tests.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Scope note**: Scan mode only. Trace-mode principles (II, III) and Strict Boundary #1 don't apply.

| Principle | Compliance | Notes |
|---|---|---|
| I. Pure Rust, Zero C | ✅ | No C deps added. |
| II. eBPF-Only Observation | N/A (scan mode) | — |
| III. Fail Closed | ✅ | FR-003 + FR-002a: parse failures log and continue; never fabricate coords; never skip the JAR's other emissions. |
| IV. Type-Driven Correctness | ✅ | Reuses existing `Purl`, `PackageDbEntry`, `SpdxExpression`, `PomProperties`. No raw `String` for coord or license values across module boundaries. No `.unwrap()` in production code. Test modules use `#[cfg_attr(test, allow(clippy::unwrap_used))]` per constitution v1.2.1. |
| V. Specification Compliance | ✅ | CycloneDX 1.6: emitted PURLs conform to PURL spec including `?classifier=` qualifier. Licenses stored as `SpdxExpression` (canonical form). |
| VI. Three-Crate Architecture | ✅ | No new crates. All changes in `mikebom-cli`. |
| VII. Test Isolation | ✅ | Unit + integration tests run without elevated privileges. |
| VIII. Completeness | ✅ | Feature INCREASES completeness — surfaces ancestor deps currently invisible. Silent-shading limitation is documented per FR-014/FR-015. |
| IX. Accuracy | ✅ | Shade-relocation entries are deterministically derived from on-disk bytecode manifest — no heuristic guesses. Property marker lets consumers distinguish them from direct deps. |
| X. Transparency | ✅ | `mikebom:shade-relocation = true` property exposes emission provenance. INFO-level log per successful emission + summary log per-scan. |
| XI. Enrichment | ✅ | License extraction enriches with a signal that's literally in the JAR — same posture as feature 007 US1 sidecar POM reading. |
| XII. External Data Source Enrichment | ✅ | `META-INF/DEPENDENCIES` is on-disk, inside a JAR that's already being processed. No external services consulted. |
| Governance / Pre-PR Verification (v1.2.1) | ✅ | PR will cite `cargo +stable clippy --workspace --all-targets` and `cargo +stable test --workspace` clean. |

**Gate: PASS.** No violations. No Complexity Tracking entries.

## Project Structure

### Documentation (this feature)

```text
specs/009-maven-shade-deps/
├── plan.md              # This file
├── spec.md              # Feature spec (already clarified)
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   └── shade-relocation-emission.md
├── checklists/
│   └── requirements.md  # Already created, all passing
└── tasks.md             # Phase 2 output (/speckit.tasks)
```

### Source Code (repository root)

```text
mikebom-cli/
├── src/
│   └── scan_fs/
│       └── package_db/
│           └── maven.rs            # EXTEND: two new private functions
│                                   #   - parse_dependencies_file(bytes)
│                                   #     -> Vec<ShadeAncestor>
│                                   #   - emit_shade_relocation_entries(...)
│                                   # NEW struct: ShadeAncestor
│                                   # Wired into the existing
│                                   # `for jar_path in &jar_files` loop
│                                   # alongside `walk_jar_maven_meta`.
└── tests/
    ├── scan_maven_shade_deps.rs    # NEW: integration tests for US1
    └── scan_maven_executable_jar.rs  # UNCHANGED (regression guard)

tests/fixtures/
└── maven/
    └── shade_deps/                 # NEW: fixture JARs
        └── (synthetic zips with META-INF/DEPENDENCIES text,
             no real Java bytecode — the parser only reads
             the manifest text, not the class files)

docs/
└── design-notes.md                 # EXTEND: Story 2 known-limitation
                                    # subsection (silent shading)
```

**Structure decision**: All implementation in `maven.rs`. One new integration test file. Synthetic fixture JARs (tiny zips — no Java bytecode needed; the `META-INF/DEPENDENCIES` text is what mikebom reads). No new crates, no workspace changes.

## Complexity Tracking

None. Additive feature within existing Maven reader architecture using existing types and dependencies.
