# Implementation Plan: PURL & Scope Alignment

**Branch**: `005-purl-and-scope-alignment` | **Date**: 2026-04-20 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/005-purl-and-scope-alignment/spec.md`

## Summary

Four surgical correctness fixes to mikebom's SBOM output:

1. **NPM scoping becomes scan-mode-aware**: `--image` scans include npm's own internal packages (the `**/node_modules/npm/node_modules/**` glob); `--path` scans exclude them. Closes the 172-MISSING gap on comprehensive ground truth.
2. **deb PURL distro qualifier** switches from `VERSION_CODENAME` (e.g. `bookworm`) to `<ID>-<VERSION_ID>` (e.g. `debian-12`), matching the format already used for apk/rpm and by syft/trivy/cdxgen.
3. **deb PURL namespace** comes from `/etc/os-release::ID` rather than being hardcoded to `debian`. Ubuntu scans emit `pkg:deb/ubuntu/...`.
4. **RPM version format** aligns with `rpm -qa` output: epoch moves to the `epoch=` qualifier exclusively (never inline), and a `mikebom:raw-version` property preserves the rpmdb header's unmangled string. A written root-cause analysis precedes any code change.

Cross-cutting: when `/etc/os-release` is absent or malformed, PURLs fall back to conservative defaults AND the SBOM records the missing-field names in a `mikebom:os-release-missing-fields` metadata property so consumers can detect the degraded output.

## Technical Context

**Language/Version**: Rust stable (same workspace toolchain as milestones 001–004)
**Primary Dependencies**: No new crates. Existing: `tar = 0.4`, `object = 0.36`, `rpm = 0.22`, `cyclonedx-bom`, `serde/serde_json`, `flate2`, `tempfile`, `tracing`.
**Storage**: N/A — in-memory per scan; no persistence.
**Testing**: `cargo test --workspace`. Unit tests colocated with each reader; integration tests under `mikebom-cli/tests/` (notably `scan_binary.rs`). Live conformance verification via the `sbom-conformance` suite at `/Users/mlieberman/Projects/sbom-conformance`.
**Target Platform**: macOS development host + Linux production CLI; builds on stable Rust. No platform-specific code in this feature.
**Project Type**: CLI (single binary, three-crate workspace per Constitution VI).
**Performance Goals**: No new targets. Existing directory scans complete in seconds; Fedora image scans complete within the 2s rpmdb iteration budget. This feature introduces ~O(1) per-row work (string formatting); no perf regression expected.
**Constraints**:

- PURL strings must be byte-stable across runs of the same input (SC-004, SC-007).
- No new CLI flags or env vars (FR-003, FR-016, SC-008).
- Alpine + RPM PURLs must be byte-for-byte unchanged post-implementation (SC-004 regression guard).

**Scale/Scope**: ~22 conformance fixtures, SBOM outputs 10k–100k components for large container images. Existing scan pipeline handles this; no new scaling concerns.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Applies? | Assessment |
|---|---|---|
| I. Pure Rust, Zero C | Yes | No new dependencies. All changes are string formatting + struct field additions. PASS. |
| II. eBPF-Only Observation | No (Not applicable) | This feature operates on the `scan_fs` path, not the eBPF trace path. Constitution II governs dependency *discovery*; this feature only reshapes how already-discovered packages are encoded in output. PASS by non-applicability. |
| III. Fail Closed | Partial (adapted) | Applies to eBPF trace failure. Analogous filesystem-read posture: when `/etc/os-release` is unreadable, we fall back + surface the gap in SBOM metadata per Principle X (FR-006, FR-009, SC-009). The scan does not silently omit PURL qualifiers without a consumer-visible signal. PASS. |
| IV. Type-Driven Correctness | Yes | All PURL construction goes through the existing `Purl::new` newtype. No new `.unwrap()` in production. `mikebom:raw-version` stored as `Option<String>` field on `PackageDbEntry`. PASS. |
| V. Specification Compliance | Yes (central) | This feature IS compliance work — aligning with the purl-spec rpm/deb type definitions and tracking #423. Every change moves closer to spec, never further. PASS. |
| VI. Three-Crate Architecture | Yes | No new crates. All changes in `mikebom-cli` (plus possibly `mikebom-common` for the `PackageDbEntry` struct additions). PASS. |
| VII. Test Isolation | Yes | All new tests are unit tests (no eBPF privilege requirement). Live-fixture verification via conformance suite is an operator-run gate, not a CI prerequisite. PASS. |
| VIII. Completeness | Yes | US1 strictly ADDS components on image scans (+172 on comprehensive fixture). No completeness regression on other user stories. PASS. |
| IX. Accuracy | Yes (central) | US2, US3, US4 all improve accuracy — PURLs now match spec intent and match what the package manager actually reports. US1 improves accuracy of image-scan SBOMs (image ≡ its filesystem). PASS. |
| X. Transparency | Yes (strengthened) | `mikebom:os-release-missing-fields` metadata property (FR-006, FR-009, SC-009) is precisely the "structured metadata informs consumer of limitation" pattern Principle X calls for. PASS. |
| XI. Enrichment | N/A | Feature is not about enrichment. |
| XII. External Data Source Enrichment | N/A | `/etc/os-release` is the scanned artifact's own file, not an external source. |

| Strict Boundary | Assessment |
|---|---|
| #1 No lockfile-based discovery | Not touched. No new discovery paths. |
| #2 No MITM proxy | Not touched. |
| #3 No C code | Not touched. |
| #4 No `.unwrap()` in production | Implementation plan explicitly avoids. Covered by existing lint rules. |

**Gate decision**: PASS. No violations, no Complexity Tracking entries required.

## Project Structure

### Documentation (this feature)

```text
specs/005-purl-and-scope-alignment/
├── plan.md              # This file
├── research.md          # Phase 0 output — current-behaviour audit + decisions
├── data-model.md        # Phase 1 output — struct additions + field flows
├── quickstart.md        # Phase 1 output — how to run + verify
├── contracts/
│   ├── cli.md           # CLI invariants (no new flags)
│   └── cyclonedx-output.md  # PURL + metadata-property contracts
├── checklists/
│   └── requirements.md  # Existing — spec-quality gate
└── tasks.md             # Phase 2 output (/speckit.tasks, NOT this command)
```

### Source Code (repository root)

```text
mikebom-cli/
├── src/
│   ├── scan_fs/
│   │   ├── os_release.rs                # Existing. Reuses read_id + read_version_id.
│   │   └── package_db/
│   │       ├── mod.rs                    # PackageDbEntry struct — minor field additions.
│   │       ├── dpkg.rs                   # build_deb_purl signature change (+ namespace, - codename for qualifier).
│   │       ├── apk.rs                    # Already correct (ID-VERSION_ID). Regression guard only.
│   │       ├── rpm.rs                    # assemble_entry epoch handling + raw_version.
│   │       ├── rpm_file.rs               # parse_rpm_file same treatment as rpm.rs.
│   │       └── npm.rs                    # walk_node_modules — add path-glob guard, mode-aware.
│   ├── generate/
│   │   └── cyclonedx/
│   │       ├── builder.rs                # Emit mikebom:npm-role=internal property when set.
│   │       └── metadata.rs                # Append mikebom:os-release-missing-fields entry.
│   └── cli/
│       └── scan_cmd.rs                   # Thread ScanMode through to readers; no new CLI flags.
└── tests/
    └── scan_binary.rs                   # Integration tests — one per user story.

mikebom-common/
└── src/
    └── resolution.rs                    # PackageDbEntry is defined here if shared; otherwise stays in cli.
```

**Structure Decision**: Per Constitution VI (Three-Crate Architecture), all changes stay within `mikebom-cli` except possibly `mikebom-common` for the `PackageDbEntry` struct addition if it lives there today. Phase-0 audit confirmed `PackageDbEntry` is currently in `mikebom-cli/src/scan_fs/package_db/mod.rs` — no cross-crate changes needed.

## Phase 0 — Outline

Phase 0 output lives in `research.md`. Summary:

No truly unknown technology choices for this feature; the work is surgical edits to existing code paths. Phase-0 therefore takes the form of a **current-behaviour audit with recorded decisions**, one section per user story, confirming:

- Where the code path lives today (file + function + line).
- What the smallest diff looks like.
- Which spec-resolved clarifications apply (the three already answered in `spec.md::Clarifications`).
- Any remaining open questions (there are none — agent audit confirmed all clarifications have concrete code landing sites).

## Phase 1 — Design & Contracts

Phase 1 artifacts:

- **data-model.md**: Field-level changes to `PackageDbEntry`, the `ScanMode` enum threading, and the `OsReleaseDiagnostics` accumulator passed from `read_all` into the metadata builder.
- **contracts/cli.md**: Invariants that the CLI surface doesn't change (`--image` and `--path` continue to produce SBOMs; no new flags; no env vars; output file paths unchanged).
- **contracts/cyclonedx-output.md**: The exact PURL shape changes (deb namespace, deb distro qualifier, rpm version segment, rpm epoch qualifier) and the new component/metadata properties (`mikebom:npm-role`, `mikebom:raw-version`, `mikebom:os-release-missing-fields`).
- **quickstart.md**: How an operator runs + verifies the post-change behaviour end-to-end on four canonical fixtures (one Debian image, one Ubuntu image, one Fedora image, one Node.js image).

Agent context update: run `.specify/scripts/bash/update-agent-context.sh claude` after Phase 1 artifacts exist to refresh the auto-generated section of `CLAUDE.md`.

## Post-Design Constitution Re-check

After Phase 1 artifacts are complete, re-evaluate:

- **No new `.unwrap()` sites introduced** — verified by convention in data-model.md (`Option<String>` for raw_version, `Option<&str>` threaded for mode).
- **Specification compliance improved, never degraded** — verified by contracts/cyclonedx-output.md explicit mapping of each output field to its spec source (purl-spec type definitions, CycloneDX 1.6 fields).
- **Three-crate architecture preserved** — verified by project-structure section; no crate additions.
- **Transparency strengthened** — verified by contracts/cyclonedx-output.md's metadata section.

Expected decision: PASS. Any new violation at this stage is a design bug, not a feature scope expansion.

## Complexity Tracking

No violations. No entries required.
