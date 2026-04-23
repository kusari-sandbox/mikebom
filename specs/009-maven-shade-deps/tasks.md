---
description: "Task list for feature 009-maven-shade-deps"
---

# Tasks: Emit Shade-Relocated Maven Dependencies

**Input**: Design documents from `/specs/009-maven-shade-deps/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Regression tests required per FR-011 + FR-012 (preserve pre-feature output on non-shaded JARs; preserve existing 007/008 integration tests). Unit + integration test tasks are included.

**Organization**: Two user stories. US1 (P1) is the whole implementation. US2 (P3) is documentation. US1 is self-contained — single PR.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Parallelizable (different files, no dependencies on incomplete tasks)
- **[Story]**: US1 / US2 — maps to spec user stories
- File paths are relative to the repo root `/Users/mlieberman/Projects/mikebom/`

## Path Conventions

Single crate. No new crates. Primary edits in `mikebom-cli/src/scan_fs/package_db/maven.rs` plus small additions to `mikebom-common/src/resolution.rs` and the CycloneDX builder.

---

## Phase 1: Setup

- [ ] T001 Verify working tree is clean on branch `009-maven-shade-deps`; main at or above commit `701ea50` (post-008 US3 merge). Run `git status` and `git log --oneline -3`.
- [ ] T002 Baseline: `cargo +stable test --workspace` → expected 1128 passing (post-008 US3). Record the number for the PR description.
- [ ] T003 Baseline: `cargo +stable clippy --workspace --all-targets` → zero errors.

---

## Phase 2: Foundational

**Purpose**: Add the `shade_relocation: Option<bool>` field to shared types and wire CDX property emission. Must precede US1's implementation.

**⚠️ CRITICAL**: Phase 3 (US1) is blocked until this phase completes. All tasks here touch shared types — keep them small and focused.

- [ ] T004 Add `pub shade_relocation: Option<bool>` field (serde `default`, `skip_serializing_if = "Option::is_none"`) to `PackageDbEntry` in `mikebom-cli/src/scan_fs/package_db/mod.rs`. Default `None` in all existing constructors — grep for every `PackageDbEntry {` literal and add `shade_relocation: None,`. Mirror the `detected_go: Option<bool>` pattern.
- [ ] T005 Add the same `shade_relocation: Option<bool>` field (same serde attrs) to `ResolvedComponent` in `mikebom-common/src/resolution.rs`. Update the `Default` derive if applicable, and any existing test-fixture constructors.
- [ ] T006 Thread `shade_relocation` from `PackageDbEntry` → `ResolvedComponent` in `mikebom-cli/src/scan_fs/mod.rs`. Find the existing `detected_go: entry.detected_go,` threading line and add `shade_relocation: entry.shade_relocation,` adjacent to it.
- [ ] T007 Add CDX property emission in `mikebom-cli/src/generate/cyclonedx/builder.rs`: when `ResolvedComponent.shade_relocation == Some(true)`, emit property `{"name": "mikebom:shade-relocation", "value": "true"}`. Find the existing `mikebom:detected-go` emission branch and add a parallel branch for the new field.
- [ ] T008 Run `cargo +stable clippy --workspace --all-targets` and `cargo +stable test --workspace`. Both must stay green — 1128 passing, no new test failures (type-threading changes don't affect behavior yet). This is the foundational-phase checkpoint.

**Checkpoint**: Types + property emission wired. US1 implementation can now plug in.

---

## Phase 3: User Story 1 — Parse and emit shade-relocation entries (Priority: P1) 🎯 MVP

**Goal**: Parse `META-INF/DEPENDENCIES` inside JARs during the existing Maven scan; emit nested ancestor coords with the shade-relocation marker, license info, and PURL classifier qualifier.

**Independent Test**: End-to-end scan of the existing `/tmp/008-polyglot-rootfs/` with the post-fix binary → `pkg:maven/org.apache.commons/commons-compress@1.23.0` appears with `parent_purl = pkg:maven/org.apache.maven.surefire/surefire-shared-utils@3.2.2`, `sbom_tier = "analyzed"`, `licenses = ["Apache-2.0"]`, and the `mikebom:shade-relocation = true` property.

### Core types and parser

- [ ] T010 [US1] Add the private `ShadeAncestor` struct in `mikebom-cli/src/scan_fs/package_db/maven.rs` with fields `group_id: String`, `artifact_id: String`, `classifier: Option<String>`, `version: String`, `license: Option<SpdxExpression>`. Placement: next to the existing `PomProperties` / `EmbeddedMavenMeta` struct definitions.
- [ ] T011 [US1] Implement `fn parse_dependencies_file(bytes: &[u8]) -> Vec<ShadeAncestor>` in `maven.rs` per contracts/shade-relocation-emission.md. Line-based parser: use a regex matching both the 4-part `<g>:<a>:jar:<v>` and 5-part `<g>:<a>:jar:<classifier>:<v>` forms (per research R2). After each coord match, peek to the next non-blank line; if it begins with `License:` (trimmed), strip the prefix and any trailing `(url)` parenthetical, pass the remainder to `SpdxExpression::try_canonical`. On success, store; on error, log WARN `"shade-relocation license not parseable"` and leave `license = None`. Non-UTF-8 input → return empty vec. Malformed coord lines → silently skipped.

### Emission function

- [ ] T012 [US1] Implement `fn emit_shade_relocation_entries(ancestors: Vec<ShadeAncestor>, enclosing_primary_purl: &Purl, co_owned_by: Option<String>, source_path: &str, out: &mut Vec<PackageDbEntry>, seen_ancestor_keys: &mut HashSet<String>)` in `maven.rs` per contracts/shade-relocation-emission.md. For each ancestor: construct the PURL (including `?classifier=<value>` qualifier when present), apply self-reference guard (skip when coord equals enclosing primary), apply per-JAR dedup via `seen_ancestor_keys`, push a `PackageDbEntry` with `shade_relocation = Some(true)`, `parent_purl = Some(enclosing)`, `sbom_tier = Some("analyzed".to_string())`, `co_owned_by`, `licenses = ancestor.license.map(|l| vec![l]).unwrap_or_default()`, `source_path`, and all other fields at their `None` / empty defaults.

### Wire into the JAR loop

- [ ] T013 [US1] In `maven::read_with_claims` inside `mikebom-cli/src/scan_fs/package_db/maven.rs`, inside the existing `for jar_path in &jar_files` loop: after `walk_jar_maven_meta(jar_path)` is called, open the zip archive once more (reuse the `zip::ZipArchive` pattern from `walk_jar_maven_meta` — OK to open twice because the OS file cache makes the second open negligible; or refactor to share a single open if the diff stays small). Try to read `META-INF/DEPENDENCIES`. If present, call `parse_dependencies_file` on its bytes. If the JAR has a resolvable primary coord (either from `walk_jar_maven_meta`'s `is_primary` entry or from the feature 007 US1 sidecar resolution path), construct the primary `Purl` via `build_maven_purl` and call `emit_shade_relocation_entries`. If no primary coord is resolvable, skip emission and log WARN `"skipping shade-relocation for JAR with no primary coord"`. Log INFO `"shade-relocation ancestors emitted"` with count on successful emission.
- [ ] T014 [US1] Add a per-scan summary log at the end of `read_with_claims` (near the existing sidecar-resolved summary): `"maven shade-relocation scan: emitted N ancestor coords across M JARs"`.

### Unit tests (in `maven.rs`)

- [ ] T015 [P] [US1] Add unit tests in `#[cfg(test)] mod tests` for `parse_dependencies_file` covering all 8 normative cases in contracts/shade-relocation-emission.md: canonical 4-part entries, 5-part classifier entry, unrecognized license text (fail-soft), missing license line, malformed coord, non-UTF-8 input, empty input, mixed valid+invalid. **The existing `mod tests` block in `maven.rs` already carries `#[cfg_attr(test, allow(clippy::unwrap_used))]` (added during feature 007 US4) — add the new tests INSIDE that block. Do not create a new `mod tests` without the guard or CI clippy will reject the PR (per PR-#8 failure mode).**
- [ ] T016 [P] [US1] Add unit tests in `maven.rs`'s test module for `emit_shade_relocation_entries` covering the 6 contract cases: happy path, self-reference, within-JAR duplicate, license threading, `co_owned_by` inheritance, classifier emission. Same guard rule as T015 — add inside the existing guarded `mod tests` block.

### Integration tests (new file)

- [ ] T017 [US1] Create `mikebom-cli/tests/scan_maven_shade_deps.rs` with the standard test helpers (copy `scan_path(...)` and `maven_purls(...)` from `scan_maven_executable_jar.rs`). Integration-test files in `tests/` are separate compile units and do NOT inherit the crate-root `#[deny(clippy::unwrap_used)]`, so fixture-builder helpers may use `.unwrap()` freely (matches the existing pattern in `scan_maven_executable_jar.rs`). No clippy-guard attribute needed at file level.
- [ ] T018 [US1] Add fixture builder `build_shade_relocated_jar(&TempDir, outer_coord, ancestors: &[(g,a,v, license_opt)]) -> PathBuf` in the new test file using `zip::ZipWriter` (mirror `build_ordinary_maven_jar` from `scan_maven_executable_jar.rs`). The fixture JAR contains: `META-INF/MANIFEST.MF`, `META-INF/maven/<g>/<a>/pom.properties` + `pom.xml` for the outer coord, AND `META-INF/DEPENDENCIES` formatted per the surefire-shared-utils template (coord line + License continuation line per ancestor).
- [ ] T019 [US1] Integration test `shade_relocated_jar_emits_ancestors_with_marker_and_licenses`: build a JAR with outer `com.example:outer:1.0.0` + three ancestors (one canonical-SPDX-license `Apache-2.0`, one free-form `Apache License, Version 2.0`, one with no License line). Scan. Assert: all three ancestor PURLs present with `parent_purl` matching outer's PURL; `mikebom:shade-relocation = true` property on each; canonical-SPDX ancestor has populated `licenses[]`; free-form and no-license ancestors have empty `licenses[]`; outer primary coord still present at tier `analyzed`.
- [ ] T020 [US1] Integration test `shade_relocated_jar_preserves_classifier_in_purl`: build a JAR whose DEPENDENCIES declares `com.example:tools:jar:tests:2.0.0`. Assert: emitted PURL contains `?classifier=tests`.
- [ ] T021 [US1] Integration test `non_shaded_jar_produces_pre_feature_output` (FR-011 regression guard): build a JAR with primary coord but NO `META-INF/DEPENDENCIES`. Scan. Assert: output contains exactly the primary coord; no shade-relocation entries; no `mikebom:shade-relocation` property on any component.
- [ ] T022 [US1] Integration test `self_reference_in_dependencies_is_dropped`: build a JAR whose DEPENDENCIES lists its OWN outer coord among the ancestors. Assert: the self-reference is NOT emitted a second time; only legitimate ancestor deps surface.
- [ ] T023 [US1] Integration test `co_owned_by_inheritance_for_shade_relocation`: build a fixture JAR at a rootfs path that triggers `co_owned_by = Some("rpm")` (place under `/usr/share/java/<name>.jar` shape). Assert: emitted shade-relocation children carry the `mikebom:co-owned-by = "rpm"` property (same as their enclosing JAR).
- [ ] T023a [US1] Integration test `shade_relocation_entries_survive_scan_subject_suppression` (FR-009 regression guard): build a fixture where the enclosing JAR's outer coord triggers the 008 US3 `target/`-dir suppression (place JAR at `<tmp>/opt/javaapp/target/<artifact>-<version>.jar` with its filename stem matching the outer primary coord AND a META-INF/DEPENDENCIES listing two ancestors). Scan and assert: (a) the outer primary coord is absent from `components[]` (US3 suppression fires correctly); (b) the two shade-relocation children ARE emitted, carry `mikebom:shade-relocation = true`, and have `parent_purl` matching the promoted `metadata.component.purl`. Silent regression guard for a future change that might accidentally run scan-subject heuristics on `is_primary = true` shade children, or suppress children when their parent is suppressed.

### Verify, build, end-to-end

- [ ] T024 [US1] `cargo +stable clippy --workspace --all-targets` — zero errors.
- [ ] T025 [US1] `cargo +stable test --workspace` — expected 1128 + ~14 new (unit + integration) = ~1142 passing, 0 failing. No regressions in any existing suite.
- [ ] T026 [US1] Build release: `cargo build --release -p mikebom`. Run against the extracted polyglot rootfs from feature 008. **Precondition**: if `/tmp/008-polyglot-rootfs/` is absent (e.g. cleared since feature 008 shipped), re-extract via:
  ```bash
  docker inspect sbom-fixture-polyglot:latest >/dev/null 2>&1 || docker build -t sbom-fixture-polyglot \
    /Users/mlieberman/Projects/sbom-conformance/fixtures/polyglot-builder-image/project/
  cid=$(docker create sbom-fixture-polyglot:latest)
  mkdir -p /tmp/008-polyglot-rootfs && docker export "$cid" | tar -xf - -C /tmp/008-polyglot-rootfs
  docker rm "$cid"
  ```
  Then run the verification:
  ```bash
  ./target/release/mikebom --offline sbom scan --path /tmp/008-polyglot-rootfs --output /tmp/009-post.cdx.json
  jq '[.components[] | select(.purl | contains("commons-compress@1.23.0"))]' /tmp/009-post.cdx.json
  ```
  Assert the output contains `pkg:maven/org.apache.commons/commons-compress@1.23.0` with the expected parent_purl, license, and shade-relocation property.
- [ ] T027 [US1] If T026 does NOT show the expected entry, apply the G3-post-mortem rule: stop, investigate the gap between lab fixture and real polyglot JAR, update the implementation accordingly. Do not declare done on theory.
- [ ] T028 [US1] Commit and push `feat/009-maven-shade-deps`; open PR titled "feat(scan): shade-relocation ancestor emission (009 US1)". PR body includes constitution v1.2.1 pre-PR evidence (T024 + T025 output) and the pre/post polyglot diff from T026.

**Checkpoint**: Shaded ancestors visible in SBOM output; downstream vulnerability scanners can now match CVEs against them.

---

## Phase 4: User Story 2 — Documentation (Priority: P3)

**Goal**: Document the coverage boundary (what mikebom detects vs what it misses) + forward-compat note about CycloneDX `pedigree.ancestors[]`.

- [ ] T030 [US2] Extend `docs/design-notes.md` with a new section "Shade-relocation handling" covering: (a) what mikebom detects — JARs carrying `META-INF/DEPENDENCIES` files (Apache Maven Dependency Plugin output); (b) what it misses — silent shading (no manifest file survives the build), which is a known limitation; (c) the property marker convention (`mikebom:shade-relocation = true`); (d) forward-compat note — this is a pragmatic alternative to CycloneDX 1.6's `pedigree.ancestors[]` that's wire-compatible: consumers can filter by property, and a future feature can promote to the spec-native field without breaking downstream.
- [ ] T031 [US2] Document at least one named future-work item per FR-015 (reduced-pom.xml parsing, class-path regex heuristics, or CycloneDX pedigree.ancestors emission). Cross-reference the 009 spec's Assumptions section.
- [ ] T032 [US2] Run `cargo +stable clippy --workspace --all-targets` + `cargo +stable test --workspace`. Docs-only change; both counts must be unchanged from Phase 3 completion.
- [ ] T033 [US2] Commit and push `docs/009-shade-relocation-coverage`; open PR titled "docs(design): shade-relocation coverage boundary (009 US2)" with constitution v1.2.1 evidence.

---

## Phase 5: Polish

- [ ] T040 Rebase `main` after US1 + US2 PRs merge; verify `cargo +stable test --workspace` passes at the new baseline (~1142 + docs-PR count if tests changed, though docs-only shouldn't change it).
- [ ] T041 Run the polyglot bake-off on the merged binary. Confirm:
  - `commons-compress@1.23.0` now appears as a nested shade-relocation component under `surefire-shared-utils-3.2.2`.
  - Other ecosystem scoreboards (cargo / gem / pypi / rpm / binary / golang) unchanged from post-008 state.
  - Maven scoreboard either improves (if GT recognizes the new entry) or stays at the post-008 level (if GT needs separate alignment work).
- [ ] T042 If the GT harness doesn't recognize the shade-relocation entry, open a follow-up issue on the sbom-conformance repo to add matcher support for the `mikebom:shade-relocation` property. Not blocking for mikebom.
- [ ] T043 Delete merged feature branches. Update the spec Status to `Shipped`.

---

## Dependencies

```text
Phase 1 (Setup) ─► Phase 2 (Foundational types + property wiring) ─► Phase 3 (US1 implementation + tests + PR) ─► PR merged
                                                                                            │
                                                                                            ▼
                                                                                     Phase 4 (US2 docs PR)
                                                                                            │
                                                                                            ▼
                                                                                     Phase 5 (Polish — after all merged)
```

- **Phase 2 blocks Phase 3**: shared-type changes must land before US1's emission code can reference them.
- **Phase 3 blocks Phase 4**: docs reference the shipped behavior; write docs only after the code is final.
- **Tasks T015 and T016 are `[P]`**: unit tests for two separate functions, same file. Can run in parallel when the functions exist.
- **Tasks T019–T023 are sequential** (same test file, shared fixture builder) but can be developed incrementally.

## Parallel Execution Examples

Within Phase 3 (US1), after T013 lands the implementation:

```text
T015 [P] and T016 [P]    # unit tests, two different functions in the same file
```

Unit-test tasks and integration-test tasks are sequential relative to each other because both rely on the implementation being in place, but the INTEGRATION tests themselves are incremental additions to the same file so they're sequential among themselves.

## Implementation Strategy

**MVP = US1 alone.** Story 2 is documentation — nice to have, not blocking. Ship US1 first; US2 can follow.

**Per-PR constitution verification**: Every PR (US1, US2) MUST cite both `cargo +stable clippy --workspace --all-targets` and `cargo +stable test --workspace` output in its description. Per-crate test commands are NOT acceptable evidence.

**Verification gate per slice (G3 post-mortem rule)**: definition-of-done for US1 is NOT just passing unit + integration tests. The polyglot end-to-end test at T026 is mandatory. If T026 fails, investigate the gap before claiming done (T027).

**Rollback discipline**: single code PR (US1), single docs PR (US2). Each is independently revertible.
