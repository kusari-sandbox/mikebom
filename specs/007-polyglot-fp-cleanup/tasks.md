---
description: "Task list for feature 007-polyglot-fp-cleanup"
---

# Tasks: Close Remaining Polyglot Bake-Off False Positives

**Input**: Design documents from `/specs/007-polyglot-fp-cleanup/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Regression tests are required by FR-014 and are included.

**Organization**: Tasks grouped by user story (US1 / US2 / US3) so each story ships as its own PR and is independently testable. Each story closes a distinct bucket of polyglot FPs.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1, US2, US3 — maps to spec user stories
- File paths are absolute or relative to the repo root `/Users/mlieberman/Projects/mikebom/`

## Path Conventions

Single crate: `mikebom-cli/src/scan_fs/package_db/` (implementation) and `mikebom-cli/tests/` (integration). No new crates.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: No new infrastructure needed — this feature extends an existing scan-mode subsystem. Setup is just creating the working branch structure.

- [ ] T001 Verify working tree is clean on branch `007-polyglot-fp-cleanup` at or above commit `5b38b98` (post-G3 merge); run `git status` and `git log -1 --oneline` to confirm.
- [ ] T002 Run `cargo test -p mikebom` to establish the baseline test count (expect 1013 passing); record the exact number in the opening PR description of each slice (US1, US2, US3) — not in plan.md, which should remain free of runtime state.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared scaffolding that all three user stories depend on — the new type definitions and the filter-callsite wiring in `package_db/mod.rs`. These must land before any user-story slice can be implemented.

**⚠️ CRITICAL**: No user-story work can begin until this phase is complete.

- [ ] T003 Add new in-memory type `GoProductionImportSet { modules: HashSet<String> }` to `mikebom-cli/src/scan_fs/package_db/golang.rs`, with a `new()` constructor and a `insert(module_path: &str)` method.
- [ ] T004 Add new in-memory type `GoMainModuleSet { paths: HashSet<String> }` to `mikebom-cli/src/scan_fs/package_db/golang.rs`, with a `new()` constructor and an `insert(path: &str)` method.
- [ ] T005 In `mikebom-cli/src/scan_fs/package_db/mod.rs`, modify `DbScanResult` (the aggregation struct returned by `read_all`) to optionally carry `GoProductionImportSet` and `GoMainModuleSet` populated during the Go readers. Add empty constructors and passthrough defaults so existing callers continue to compile.
- [ ] T006 In `mikebom-cli/src/scan_fs/package_db/mod.rs`, add two empty filter functions next to the existing `apply_go_linked_filter` (G3): `apply_go_production_set_filter(entries: &mut Vec<PackageDbEntry>, import_set: &GoProductionImportSet)` and `apply_go_main_module_filter(entries: &mut Vec<PackageDbEntry>, main_modules: &GoMainModuleSet)`. Body: unconditional early-return (no-op). Wire both into `read_all` immediately after the G3 callsite, in order: G3 → G4 (production set) → G5 (main module). Verify baseline tests still pass.

**Checkpoint**: Foundation ready — all three user-story slices can now proceed independently.

---

## Phase 3: User Story 1 — Fedora sidecar POM reading (Priority: P1) 🎯 MVP

**Goal**: Recover 12 Maven components on the polyglot-builder-image bake-off by reading `/usr/share/maven-poms/*.pom` sidecar files for JARs under `/usr/share/maven/lib/` that lack embedded `META-INF/maven/` metadata.

**Independent Test**: Using the synthetic repro from `quickstart.md` (guice-5.1.0.jar + JPP-guice.pom), scan the fixture and verify `pkg:maven/com.google.inject/guice@5.1.0` appears in the output.

### Tests for User Story 1

- [ ] T010 [P] [US1] Create fixture `mikebom-cli/tests/fixtures/maven/fedora_sidecar/usr/share/maven/lib/guice-5.1.0.jar` — a minimal zip archive with NO `META-INF/maven/` entries (a single empty file `dummy.txt` is sufficient to make it a valid zip).
- [ ] T011 [P] [US1] Create fixture `mikebom-cli/tests/fixtures/maven/fedora_sidecar/usr/share/maven-poms/JPP-guice.pom` — a minimal valid POM declaring `com.google.inject:guice:5.1.0`.
- [ ] T012 [P] [US1] Create fixture `mikebom-cli/tests/fixtures/maven/fedora_sidecar/usr/share/maven/lib/aopalliance-1.0.jar` + sidecar `mikebom-cli/tests/fixtures/maven/fedora_sidecar/usr/share/maven-poms/aopalliance.pom` to exercise the plain `<name>.pom` (no JPP prefix) filename convention.
- [ ] T013 [P] [US1] Create fixture for parent-inheritance case: `mikebom-cli/tests/fixtures/maven/fedora_sidecar/usr/share/maven-poms/guice-child.pom` that inherits `<groupId>` from `mikebom-cli/tests/fixtures/maven/fedora_sidecar/usr/share/maven-poms/guice-parent.pom` (both POMs on disk in the same dir).
- [ ] T014 [P] [US1] Create fixture for the "no sidecar" negative case: `mikebom-cli/tests/fixtures/maven/fedora_sidecar/usr/share/maven/lib/orphan-3.0.jar` with NO corresponding POM anywhere.
- [ ] T015 [US1] Create integration test file `mikebom-cli/tests/scan_maven_sidecar.rs` with test skeletons (compile-only, `#[ignore]`'d) for the five normative test cases from `contracts/sidecar-pom-lookup.md`, plus the acceptance scenarios 1-5 from spec.md Story 1.

### Implementation for User Story 1

- [ ] T016 [US1] Create new file `mikebom-cli/src/scan_fs/package_db/maven_sidecar.rs`. Declare `pub(crate) struct FedoraSidecarIndex { by_basename: HashMap<String, PathBuf> }`. Implement `pub(crate) fn build_fedora_sidecar_index(rootfs: &Path) -> FedoraSidecarIndex` that walks `<rootfs>/usr/share/maven-poms/` (no-op if missing) and records each `.pom` file keyed by basename (strip `JPP-` prefix and `.pom` suffix; lowercase). When both `JPP-<name>.pom` and `<name>.pom` exist for the same basename, the non-prefixed wins (per contract).
- [ ] T017 [US1] In `maven_sidecar.rs`, implement `pub(crate) fn lookup_sidecar_pom<'a>(index: &'a FedoraSidecarIndex, jar_path: &Path) -> Option<&'a Path>`. Strip the JAR's filename of `.jar` suffix and trailing `-<version>` component (use a simple regex or char-search for the last `-` followed by a digit); look up the resulting basename in the index.
- [ ] T018 [US1] Register `maven_sidecar` as a submodule in `mikebom-cli/src/scan_fs/package_db/mod.rs` (add `pub(crate) mod maven_sidecar;`).
- [ ] T019 [US1] In `mikebom-cli/src/scan_fs/package_db/maven.rs`, in the `read_with_claims` (or whichever function iterates JARs — see function at line 1668), after `walk_jar_maven_meta(archive_path)` returns empty, invoke `maven_sidecar::lookup_sidecar_pom(&sidecar_index, archive_path)`. When a sidecar path is returned, parse it with the existing `parse_pom_xml`, resolve one level of parent inheritance using the existing `build_effective_pom` (passing the sidecar's parent directory as the search root), and emit the resulting `pkg:maven/<g>/<a>@<v>` component related to the JAR file (including the JAR's content hash in `source_files`).
- [ ] T020 [US1] Build the `FedoraSidecarIndex` once at the top of `maven::read` / `maven::read_with_claims` (whichever is the scan entry point) using the rootfs parameter; thread the `&FedoraSidecarIndex` into the per-JAR processing.
- [ ] T021 [US1] When embedded `META-INF/maven/` metadata IS present in a JAR, do NOT query the sidecar index — embedded wins per FR-004. When the sidecar POM parses but `parse_pom_xml` returns incomplete coordinates after parent resolution (missing groupId / artifactId / version), do NOT emit a Maven component — fall back to generic-binary emission per FR-005.
- [ ] T022 [US1] Add INFO-level `tracing` log line per successful sidecar resolution: `"maven sidecar resolved"` with fields `jar`, `sidecar_pom`, `purl`. Add a single summary INFO line at end of Maven scan: `"maven sidecar scan: resolved N JARs via /usr/share/maven-poms/"`.
- [ ] T023 [US1] Un-ignore the integration tests in `mikebom-cli/tests/scan_maven_sidecar.rs` (T015). Fill in each test body using the standard `tempfile::TempDir` + `copy fixtures + run scan_fs::read` pattern from the existing `scan_go.rs` tests. Verify all 5 contract cases + 5 acceptance scenarios pass.
- [ ] T024 [US1] Run `cargo test -p mikebom --test scan_maven_sidecar` individually to confirm all new tests pass. Then run `cargo test -p mikebom` in full; confirm baseline count + the new tests all pass, no regressions.
- [ ] T025 [US1] Run the quickstart.md Slice 1 synthetic repro; confirm `pkg:maven/com.google.inject/guice@5.1.0` is in the output. Log the pre/post diff as evidence.
- [ ] T026 [US1] Commit and push branch `feat/us1-fedora-sidecar-pom`; open PR titled "feat(scan): Fedora sidecar POM reading (007 US1)" with the Slice 1 repro results in the body.

**Checkpoint**: US1 fully functional, independently mergeable. Expected bake-off improvement: Maven 101/114 → ≥113/114 exact matches, finding count 23 → ≤11.

---

## Phase 4: User Story 2 — Go test-scope filter (intersection) (Priority: P2)

**Goal**: Drop 4 Go FPs (testify, go-spew, go-difflib, yaml.v3) by filtering source-tier Go emissions to the intersection of (BuildInfo-linked modules) and (modules reachable from non-`_test.go` imports).

**Independent Test**: Using the quickstart.md Slice 2 synthetic repro (go.mod + main.go importing logrus, main_test.go importing testify), scan and verify only logrus is emitted.

### Tests for User Story 2

- [ ] T030 [P] [US2] Create fixture dir `mikebom-cli/tests/fixtures/go/source_with_test_imports/` containing `go.mod` (module `example.com/us2`, requires logrus + testify), `go.sum` (both modules), `main.go` (imports logrus), and `main_test.go` (imports testify). No binary.
- [ ] T031 [P] [US2] Create fixture for the vendored case: `mikebom-cli/tests/fixtures/go/vendor_production_imports/` with `vendor/<pathof>logrus/` present and a `main.go` importing it; `go.sum` also declares a test-only module that does NOT appear under `vendor/`.
- [ ] T032 [P] [US2] Create fixture for the "binary has test module in BuildInfo" edge case: reuse `hello-linux-amd64` (already in tree) + a source tree where some BuildInfo-listed module is only imported by `_test.go` files.
- [ ] T033 [US2] In `mikebom-cli/tests/scan_go.rs`, add 4 integration test skeletons (compile-only, `#[ignore]`'d) covering the 4 Story 2 acceptance scenarios from spec.md.

### Implementation for User Story 2

- [ ] T034 [US2] In `mikebom-cli/src/scan_fs/package_db/golang.rs`, add a private helper `fn extract_go_imports(file_bytes: &[u8]) -> Vec<String>` that parses a single `.go` file's `import` blocks (both grouped `import ( ... )` and single-line `import "..."`) and returns the list of import path strings. Use a hand-rolled byte scanner (no new crate).
- [ ] T035 [US2] In `golang.rs`, add `fn build_production_import_set(source_tree_root: &Path, known_modules: &HashSet<String>) -> GoProductionImportSet`. Walks all `.go` files under `source_tree_root` excluding those whose filename ends in `_test.go` and files under `vendor/` that are test files. For each import path, longest-prefix-match against `known_modules`; record the matched module in the returned set. Vendored packages under `vendor/<module>/<path>` that are imported from production `.go` files elsewhere in the tree are counted.
- [ ] T036 [US2] Modify `golang::read` (line 589) to build the `GoProductionImportSet` alongside the current source-tier emissions. Pass the set of known modules (from go.mod `require` + go.sum entries) into `build_production_import_set`. Return the resulting `GoProductionImportSet` alongside the `Vec<PackageDbEntry>` (update the function signature as needed — propagate the tuple return up through `package_db/mod.rs::read_all`).
- [ ] T036a [US2] In `golang::read` (`mikebom-cli/src/scan_fs/package_db/golang.rs`), implement the FR-009 fallback path: when walking a Go source root finds a `go.mod` but zero parseable non-`_test.go` files AND no Go binary is present anywhere on the rootfs (coordinate this via a late-pass adjustment in `package_db/mod.rs::read_all` if binary-presence is only knowable after `go_binary::read` runs), emit ONLY the `require` directive entries from go.mod, tagged with `sbom_tier = Some("source-unverified".to_string())`. Suppress go.sum-only transitive entries in this mode. The `"source-unverified"` tier string is the exact literal per FR-009. Non-fallback scans are unchanged.
- [ ] T037 [US2] In `mikebom-cli/src/scan_fs/package_db/mod.rs`, thread the `GoProductionImportSet` returned by `golang::read` into `DbScanResult`. Fill in the body of `apply_go_production_set_filter`: retain iff `purl.ecosystem() != "golang" || sbom_tier != Some("source") || import_set.modules.contains(&entry.name)`. When import_set is empty, early-return no-op (preserves the binary-only and G3-covered cases). Emit INFO log `"G4 filter: dropped N entries (production_imports=M)"`.
- [ ] T038 [US2] Un-ignore the integration tests in `scan_go.rs` (T033). Fill in each test body. Verify: testify dropped from the source+test fixture; vendored logrus retained; BuildInfo's test-only entries dropped by the intersection.
- [ ] T039 [US2] Add unit tests for `extract_go_imports` (minimum 5 cases: single-line import, grouped block, import with alias, import with underscore, empty file) inside `golang.rs` `#[cfg(test)]`.
- [ ] T039a [US2] Add unit tests in `golang.rs` `#[cfg(test)]` for the FR-009 fallback: (a) go.mod with 2 require directives + go.sum with 5 entries + zero `.go` files → exactly 2 entries emitted, both at tier `"source-unverified"`; (b) go.mod with 1 require + NO go.sum → exactly 1 entry emitted at tier `"source-unverified"`; (c) go.mod with 0 require directives + any go.sum → zero entries emitted.
- [ ] T040 [US2] Add unit tests for `apply_go_production_set_filter` in `package_db/mod.rs` `#[cfg(test)]` covering the 5 normative cases in `contracts/go-production-set.md` PLUS an "all dependencies are test-only" case (spec Edge Cases item): source tree where every non-stdlib import is in a `_test.go` file → production import set is empty → filter drops all source-tier Go entries → zero Go components emitted, no panic, no warning spam.
- [ ] T041 [US2] Run `cargo test -p mikebom --test scan_go` + the new unit tests; confirm all pass.
- [ ] T041a [US2] Add integration test `scan_go_multiple_binaries_union_buildinfo` to `mikebom-cli/tests/scan_go.rs` (spec Edge Cases item): rootfs containing two Go binaries with overlapping-but-distinct BuildInfo sets at e.g. `/srv/app1/bin` and `/srv/app2/bin`, plus a shared go source tree importing modules from both sets. Assert: union of BuildInfo supplies the candidate set for the intersection; no module is dropped merely because it's only in one binary's BuildInfo.
- [ ] T042 [US2] Run the quickstart.md Slice 2 synthetic repro; confirm testify is absent and logrus is present. Log the pre/post diff.
- [ ] T043 [US2] Commit and push branch `feat/us2-go-test-scope-filter`; open PR titled "feat(scan): Go test-scope intersection filter (007 US2)" with the Slice 2 repro results.

**Checkpoint**: US2 fully functional. Expected bake-off improvement: Go test-scope FPs 4 → 0, finding count drops by 4.

---

## Phase 5: User Story 3 — Go main-module exclusion (Priority: P3)

**Goal**: Drop 1 Go FP (`polyglot-fixture@(devel)`) by excluding the project's own module from dependency emissions.

**Independent Test**: Using the quickstart.md Slice 3 synthetic repro (go.mod declares `module example.com/polyglot-fixture`), scan and verify no component with that module path appears.

### Tests for User Story 3

- [ ] T050 [P] [US3] Create fixture `mikebom-cli/tests/fixtures/go/main_module_self_reference/` with go.mod (`module example.com/us3fixture`), go.sum (lists a single dep + the fixture's own module — simulating the polyglot bug), and `main.go`.
- [ ] T051 [P] [US3] Create fixture for the BuildInfo-side variant: use existing `hello-linux-amd64` in a test that asserts its BuildInfo main-module (`example.com/simple`) is not emitted as a dependency.
- [ ] T052 [US3] Add 3 integration test skeletons to `mikebom-cli/tests/scan_go.rs` (compile-only, `#[ignore]`'d) covering acceptance scenarios 1-3 of Story 3.

### Implementation for User Story 3

- [ ] T053 [US3] In `mikebom-cli/src/scan_fs/package_db/golang.rs`, extend the go.mod parser to surface the `module` directive's path into a new field on the reader's return type (or via the new `GoMainModuleSet`). Populate the set during `golang::read`.
- [ ] T054 [US3] In `mikebom-cli/src/scan_fs/package_db/go_binary.rs`, ensure the BuildInfo parser's `mod <path> <version>` line populates `GoMainModuleSet`. If the parser already captures the path but doesn't expose it, add a public accessor and thread it through `go_binary::read`'s return type.
- [ ] T055 [US3] In `package_db/mod.rs::read_all`, merge the two `GoMainModuleSet` sources (go.mod-side + BuildInfo-side) into a single union. Fill in the body of `apply_go_main_module_filter`: drop iff `purl.ecosystem() == "golang"` AND `main_modules.paths.contains(&entry.name)`. Apply to ALL tiers, not just source. When the set is empty, early-return no-op. Emit INFO log `"G5 filter: dropped N main-module self-references"`.
- [ ] T056 [US3] Un-ignore the integration tests in `scan_go.rs` (T052). Fill in test bodies. Verify: go.mod-declared main module dropped; BuildInfo-declared main module dropped; coincidental-name collision still dropped per FR-012.
- [ ] T057 [US3] Add unit tests for `apply_go_main_module_filter` in `package_db/mod.rs` `#[cfg(test)]` covering the 5 normative cases in `contracts/main-module-exclusion.md`.
- [ ] T058 [US3] Run `cargo test -p mikebom`; confirm all tests pass.
- [ ] T059 [US3] Run the quickstart.md Slice 3 synthetic repro; confirm `example.com/polyglot-fixture` does NOT appear as an emitted component.
- [ ] T060 [US3] Commit and push branch `feat/us3-go-main-module-exclusion`; open PR titled "feat(scan): Go main-module exclusion (007 US3)".

**Checkpoint**: US3 fully functional. Expected bake-off improvement: Go project-self FP 1 → 0.

---

## Phase 6: Polish & Cross-Cutting

**Purpose**: Final verification after all three slices land and the bake-off measurement closes the loop.

- [ ] T070 Rebase `main` after US1, US2, US3 PRs are merged; verify `cargo test -p mikebom` baseline count rose to 1013 + (US1 tests) + (US2 tests) + (US3 tests).
- [ ] T071 Run the full polyglot-builder-image bake-off with the post-merge binary. Produce the updated scoreboard table (per spec.md SC-001 through SC-005) and attach to the PR that closes this feature branch.
- [ ] T072 Verify per-ecosystem scoreboards: cargo 11/11, gem 76/76, pypi 2/2, rpm 529/529, binary 2/2 (all unchanged); maven ≥113/114; golang with zero test-scope and zero project-self FPs.
- [ ] T073 If any slice did NOT deliver its expected FP reduction, open a follow-up issue with the observed-vs-expected delta and a working-theory root cause (per the G3 post-mortem pattern — don't declare done until measured).
- [ ] T074 Update `docs/design-notes.md` with a one-paragraph summary of the G3/G4/G5 filter composition and a link to `specs/007-polyglot-fp-cleanup/` so future scans understand why three distinct filters exist.
- [ ] T075 Delete the three feature branches (`feat/us1-*`, `feat/us2-*`, `feat/us3-*`) once merged; delete the parent `007-polyglot-fp-cleanup` branch.

---

## Dependencies

```text
Phase 1 (Setup) ─► Phase 2 (Foundational) ─┬─► Phase 3 (US1) ─► PR
                                           ├─► Phase 4 (US2) ─► PR
                                           └─► Phase 5 (US3) ─► PR
                                                     │
                                                     ▼
                                           Phase 6 (Polish — after all PRs merged)
```

- **Phase 2 blocks all three user stories.** T003–T006 add types and filter scaffolding that each slice plugs into.
- **Phases 3, 4, 5 are independent of each other** — they touch different filter callsites (or different logic within the same file). They can be developed and merged in any order, or in parallel by different developers. Recommended order: US1 → US2 → US3 (priority order), but nothing technical forces this.
- **Within each story**, fixture-creation tasks (T010–T014, T030–T032, T050–T051) are parallel [P]; wiring tasks (T019, T036, T055) must run sequentially because they modify shared source files (`maven.rs`, `golang.rs`, `mod.rs`).

## Parallel Execution Examples

**Phase 3 parallel kickoff** (after Phase 2 completes):

```text
T010 [P] T011 [P] T012 [P] T013 [P] T014 [P]     # fixtures — 5 files, independent
T015                                              # test skeletons — single file (scan_maven_sidecar.rs)
T016 ─► T017 ─► T018                              # maven_sidecar.rs + mod.rs registration (sequential)
T019 ─► T020 ─► T021 ─► T022                      # maven.rs wiring (all in same file, sequential)
T023                                              # un-ignore + fill tests
T024 ─► T025 ─► T026                              # verify + ship
```

**Phase 4 parallel kickoff** (can run in parallel with Phase 3 if two devs):

```text
T030 [P] T031 [P] T032 [P]                        # Go fixtures
T033                                              # test skeletons in scan_go.rs
T034 ─► T035 ─► T036                              # golang.rs (sequential in one file)
T037                                              # mod.rs
T038 ─► T039 ─► T040                              # test bodies + unit tests
T041 ─► T042 ─► T043                              # verify + ship
```

## Implementation Strategy

**MVP = US1 only.** The biggest single win (12 FPs) and it stands alone — Fedora sidecar reading is completely independent of the Go filter work. Ship US1 first, measure the bake-off drop, then decide whether US2 and US3 are worth chasing in this iteration (they close an additional 5 FPs).

**Incremental delivery**: each PR is its own mergeable unit. The user has already shown willingness to rebase and ship per-slice (see G1–G3 pattern). Do not bundle.

**Verification gate per slice (from G3 post-mortem)**: unit tests pass is necessary but NOT sufficient. Each slice's definition-of-done requires the quickstart.md synthetic repro PLUS a bake-off measurement showing the expected FP drop. If measurement fails to match, open a follow-up issue and do NOT claim the slice complete.
