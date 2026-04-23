---
description: "Task list for feature 008-polyglot-final-cleanup"
---

# Tasks: Close Last Polyglot Bake-Off Findings

**Input**: Design documents from `/specs/008-polyglot-final-cleanup/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Regression tests are required per FR-006 and FR-009 (preserve feature 007 US2/US4 test behaviors) and per constitution v1.2.1 (pre-PR verification). Test tasks are included.

**Organization**: Story 1 (investigation) is the hard gate for Stories 2/3. Stories 2/3 tasks are deliberately shaped to be **contingent on Story 1 findings** — the specific code change can't be pre-specified because it depends on which of R1–R8's hypotheses Story 1 confirms. Each downstream story has branch points (A / B / C) reflecting research.md R5 options.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Parallelizable (different files, no dependencies on incomplete tasks)
- **[Story]**: US1 / US2 / US3 / US4 — maps to spec user stories
- File paths are relative to the repo root `/Users/mlieberman/Projects/mikebom/` unless otherwise noted

## Path Conventions

Single crate. No new crates added. Edits confined to `mikebom-cli/src/scan_fs/package_db/` and `docs/design-notes.md`.

---

## Phase 1: Setup

**Purpose**: Confirm baseline state before investigation begins.

- [X] T001 Verify working tree is clean on branch `008-polyglot-final-cleanup` and main is at or above commit `b06eda8` (post-007 merge); run `git status` and `git log --oneline -3`. Verified at HEAD=89a334f (post-007 US4 merge), rebased onto current main.
- [X] T002 Baseline: `cargo +stable test --workspace` → **1119 passing, 0 failing** (matches post-007 expectation). Will cite this in future PR descriptions.
- [X] T003 Baseline: `cargo +stable clippy --workspace --all-targets` → **zero errors**. Pre-PR gate verified at session start per constitution v1.2.1.

---

## Phase 2: Foundational

**Purpose**: Acquire the polyglot-builder-image rootfs access that Story 1's investigation requires. Without this, Story 1 cannot be honestly completed (per the G3 post-mortem rule: evidence, not theory).

**⚠️ CRITICAL**: Story 1 is blocked until this phase completes.

- [X] T004 Polyglot rootfs extracted from local `sbom-fixture-polyglot:latest` docker image (container `cc69b6ab39cc`) via `docker export | tar -x` to `/tmp/008-polyglot-rootfs/` (2.3 GB).
- [X] T005 Built release binary at `target/release/mikebom` from commit `89a334f` (post-007 US4 merge). `mikebom 0.1.0-alpha.3`.

**Checkpoint**: Polyglot rootfs access + fresh binary confirmed. Story 1 investigation can begin.

---

## Phase 3: User Story 1 — Investigation (Priority: P1)

**Goal**: Produce `specs/008-polyglot-final-cleanup/investigation.md` that explains, per FP, exactly why the pre-existing filter didn't close it. Evidence-backed, one section per target FP.

**Independent Test**: A reviewer reading the committed `investigation.md` can state for each of the 5 target FPs: (a) which filter was supposed to close it, (b) why it didn't fire, (c) the evidence, (d) the minimal-fix category from R5, (e) its assigned downstream status (closable / known-limitation / stale-binary).

### Evidence gathering

- [ ] T010 [US1] Run mikebom with debug logging against the polyglot rootfs: `RUST_LOG=mikebom=debug ./target/release/mikebom --offline sbom scan --path <polyglot-rootfs> --output /tmp/008-polyglot.cdx.json 2> /tmp/008-polyglot.scan.log`. Save both artifacts to `/tmp/008-evidence/`.
- [ ] T011 [P] [US1] For each of the four Go FPs (testify, go-spew, go-difflib, yaml.v3), extract the `mikebom:sbom-tier` and `mikebom:source-files` properties from `/tmp/008-polyglot.cdx.json` using the `jq` commands in `quickstart.md` Slice 1 step 3. Save output as `/tmp/008-evidence/go-fps-tiers.txt`. This answers research.md Q1 (R2 tier question).
- [ ] T012 [P] [US1] Inspect the polyglot binary's BuildInfo using `go version -m <binary-path>` (investigator-side toolchain read — NOT a scan-time invocation, see quickstart.md Slice 1 step 4 for justification). Save output as `/tmp/008-evidence/buildinfo.txt`. Highlight which of the four target modules appear as `dep` lines. Answers Q2 (R3).
- [ ] T013 [P] [US1] Enumerate Go source files in the polyglot rootfs: `find <polyglot-go-project-root> -name "*.go" | sort > /tmp/008-evidence/go-files.txt`, plus split by `_test.go` vs production. Answers Q3 (R6, R8).
- [ ] T014 [P] [US1] Locate the `sbom-fixture` JAR in the polyglot rootfs and dump its manifest: `find <polyglot-rootfs> -name "*sbom-fixture*.jar" -exec sh -c 'echo "=== {} ==="; unzip -p "{}" META-INF/MANIFEST.MF' \; > /tmp/008-evidence/sbom-fixture-manifest.txt`. Also `unzip -l` to show the archive layout (look for `BOOT-INF/`, `WEB-INF/`, single-coord vs multi-coord META-INF/maven/). Answers Q4 (R4).
- [ ] T015 [P] [US1] Grep the scan log for filter decisions: `grep -E "G3 filter|G4 filter|G5 filter|sidecar|executable-jar-heuristic|fat-jar-heuristic|co_owned_by" /tmp/008-polyglot.scan.log > /tmp/008-evidence/filter-decisions.txt`. Answers Q5 (R4 `co_owned_by` branch).
- [ ] T016 [US1] Confirm the scanned binary was built from a post-007-merge commit (R7): cite `target/release/mikebom --version`, `git log -1 --oneline`, and the binary's mtime in `/tmp/008-evidence/freshness.txt`. If this fails, skip straight to conclusion "stale-binary for all FPs; re-run bake-off; no mikebom change."

### Analysis and document production

- [ ] T017 [US1] Per each of the 5 target FPs (4 Go + sbom-fixture), write one section in `specs/008-polyglot-final-cleanup/investigation.md` using the per-FP template defined in `contracts/investigation-evidence.md`. Each section MUST include: expected suppressor (G3/G4/G5/Main-Class/classic fat-jar), observed tier from T011/T012, "why it didn't fire" one-liner, at least one evidence artifact quoted from `/tmp/008-evidence/*`, minimal-fix option from R5 (A/B/C/none), and status (closable / known-limitation / stale-binary).
- [ ] T018 [US1] Add a "Binary freshness" section to `investigation.md` quoting T016's output and stating whether this invalidates all FP findings (in which case Stories 2/3 become no-ops).
- [ ] T019 [US1] Add a "Summary table" to `investigation.md`: rows = the 5 FPs, columns = {purl, expected suppressor, status}. Also add a "Planned Story 2/3 scope" list naming which FPs will be fixed in Story 2/3 vs moved to Story 4.
- [ ] T020 [US1] Verify the investigation document satisfies the acceptance criteria in `contracts/investigation-evidence.md`: every FP has a named root cause + at least one evidence artifact; no hand-waving statements remain.
- [ ] T021 [US1] Run `cargo +stable clippy --workspace --all-targets` and `cargo +stable test --workspace` on the branch to confirm no accidental code drift. Investigation is Markdown-only, so both MUST report exactly the T002/T003 baseline.
- [ ] T022 [US1] Commit and push branch `feat/us1-polyglot-investigation`; open PR titled "docs(008): polyglot FP investigation (US1)" with the investigation document + the `/tmp/008-evidence/` artifacts summarized in the PR body. PR body MUST include the `cargo +stable clippy` and `cargo +stable test` results from T021.

**Checkpoint**: Investigation committed and merged. Stories 2 / 3 / 4 scopes are now knowable. Stories 2 and 3's implementation tasks (T030+/T050+) become concrete once T017's fix-option choices are in.

---

## Phase 4: User Story 2 — Go test-scope fix (Priority: P2)

**Goal**: Close whatever Go FPs Story 1 marked `closable`. Move anything Story 1 marked `known-limitation` to Story 4. No Go toolchain invocation at scan time — that's FU-001 future work.

### Pre-implementation gate

- [ ] T030 [US2] Read the final `investigation.md` from the merged Story 1 PR. Confirm there is at least one Go FP with status `closable` before proceeding. If ALL four Go FPs are `known-limitation` or `stale-binary`, skip directly to Phase 6 (Story 4 documentation); T031–T041 become no-ops for this feature.
- [ ] T031 [US2] From `investigation.md`'s "Planned Story 2/3 scope" list, extract the chosen minimal-fix option (R5 A/B/C or bespoke) for the closable Go FPs. Record the choice in the PR description opened later.

### Implementation (shape depends on T031's choice)

These tasks are deliberately generic. Replace `<chosen file>` and `<chosen fix>` with the specifics from T031 when the PR is opened.

- [ ] T032 [US2] Implement the chosen fix in the appropriate source file. Likely candidates: `mikebom-cli/src/scan_fs/package_db/golang.rs` (if the gap is in `collect_production_imports` or in source-tier emission logic) or `mikebom-cli/src/scan_fs/package_db/mod.rs` (if the gap is in a filter's early-return / tier-gating). The fix MUST honor feature 007 FR-007 (no Go toolchain invocation at scan time; not to be confused with feature 008's own FR-007 about Maven library-JAR over-suppression). Cite the line number and function name in the PR description.
- [ ] T033 [US2] Add a regression test to `mikebom-cli/tests/scan_go.rs` that mirrors the polyglot scenario identified in T031. The test fixture shape MUST match what `investigation.md` shows for the polyglot rootfs (e.g., if Story 1 found the gap was "binary has testify in BuildInfo AND source tree has no production imports of testify," the fixture must reproduce that shape). Name the test `scan_go_<specific-scenario>_fp_is_dropped`. If the test (or any new test module) uses `.unwrap()`, add `#[cfg_attr(test, allow(clippy::unwrap_used))]` above `mod tests` per constitution v1.2.1 — otherwise CI clippy will reject the PR.
- [ ] T034 [US2] Add a negative regression test ensuring the fix does NOT over-suppress: a scenario from feature 007's US2 (e.g., `scan_go_source_production_and_test_import_dominates`) MUST continue to keep the production-imported module. FR-006.
- [ ] T035 [US2] Run `cargo +stable test -p mikebom --test scan_go` and confirm all new and pre-existing tests pass.

### Verification

- [ ] T036 [US2] Run `cargo +stable clippy --workspace --all-targets` — zero errors required.
- [ ] T037 [US2] Run `cargo +stable test --workspace` — count MUST be baseline + N (where N = number of new tests in T033 + T034). No regressions in any other suite.
- [ ] T038 [US2] Build release: `cargo build --release -p mikebom`.
- [ ] T039 [US2] Run the post-fix binary against the polyglot rootfs (same command as T010 but with the fresh binary). Confirm the target FPs listed as `closable` in `investigation.md` are absent from the output. Diff against the pre-fix scan and attach the diff to the PR.
- [ ] T040 [US2] If T039 does NOT show the expected FP drop, do NOT proceed. Follow the G3 post-mortem rule: stop, investigate the gap between lab test and real fixture, update `investigation.md` with the revised finding, and revise T032 accordingly.
- [ ] T041 [US2] Commit and push branch `feat/us2-go-test-scope-polyglot-fix`; open PR with the T031 option citation, before/after diff from T039, and the constitution v1.2.1 pre-PR evidence (T036 + T037 output). PR title: "feat(scan): close Go test-scope FPs on polyglot (008 US2)".

**Checkpoint**: Closable Go FPs dropped on polyglot; known-limitation FPs queued for Story 4 documentation.

---

## Phase 5: User Story 3 — Maven sbom-fixture fix (Priority: P3)

**Goal**: Suppress `com.example/sbom-fixture@1.0.0` from `components[]` on the polyglot image. Same conditional structure as Story 2: shape depends on which R4/R5 branch Story 1 confirms.

### Pre-implementation gate

- [ ] T050 [US3] Read `investigation.md`'s sbom-fixture section. Confirm status is `closable` before proceeding. If `known-limitation` or `stale-binary`, skip to Phase 6 and T051–T060 become no-ops.
- [ ] T051 [US3] Identify the specific R4 gap Story 1 confirmed: {no Main-Class, co_owned_by=Some, is_primary=false, primary detection stem-match failed}. This determines which R5 fix option (A/B/C or bespoke) is appropriate.

### Implementation

- [ ] T052 [US3] Implement the chosen fix in `mikebom-cli/src/scan_fs/package_db/maven.rs`. Likely candidates:
  - (A) Extend `jar_has_main_class_manifest` or the `is_executable_unclaimed_jar` predicate to also recognize `BOOT-INF/` / `WEB-INF/` layout signatures.
  - (B) Add a new predicate that detects "JAR filename stem exactly matches primary coord's `<artifactId>-<version>`" and treats matches under build-output paths as scan subjects.
  - (C) Refine `walk_jar_maven_meta`'s primary-coord stem-matching to handle the failing case.
  - Whichever applies, the change MUST NOT over-suppress library JARs that happen to declare Main-Class (FR-007 this-feature).
- [ ] T053 [US3] Build a faithful fixture for the polyglot sbom-fixture's actual shape: place a JAR with the same structural features (as documented in T014's manifest dump) under `tests/fixtures/maven/polyglot_sbom_fixture/` and wire it into a new integration test in `mikebom-cli/tests/scan_maven_executable_jar.rs` named after the specific scenario (e.g., `boot_inf_style_executable_jar_is_suppressed`). If new `#[cfg(test)]` code uses `.unwrap()`, add `#[cfg_attr(test, allow(clippy::unwrap_used))]` above `mod tests` per constitution v1.2.1.
- [ ] T054 [US3] Add a negative-case integration test: a library JAR with `Main-Class:` (e.g., `commons-lang3`-like CLI entry point) MUST NOT be suppressed. FR-007 (this feature) regression guard. Same clippy-guard note as T053 if `.unwrap()` is used.
- [ ] T055 [US3] Run `cargo +stable test -p mikebom --test scan_maven_executable_jar` and confirm all pass.

### Verification

- [ ] T056 [US3] `cargo +stable clippy --workspace --all-targets` — clean.
- [ ] T057 [US3] `cargo +stable test --workspace` — baseline + new tests, no regressions.
- [ ] T058 [US3] Build release binary; scan the polyglot rootfs; confirm `pkg:maven/com.example/sbom-fixture@1.0.0` is absent from `components[]`. Additionally, `jq '.metadata.component.purl'` on the SBOM and log the value — if the fix was designed to promote the coord to `metadata.component` (FR-008, SHOULD), the logged PURL should equal the suppressed coord; if the fix only suppressed without promoting, the logged value is informational. Record the observed behavior in the PR description so a reviewer can confirm the SHOULD status of FR-008.
- [ ] T059 [US3] If T058 fails, apply the same stop-and-investigate rule as T040.
- [ ] T060 [US3] Commit and push `feat/us3-maven-sbom-fixture-polyglot-fix`; open PR with T051's gap-identification, T058's diff, and constitution v1.2.1 evidence. PR title: "feat(scan): close sbom-fixture self-reference on polyglot (008 US3)".

**Checkpoint**: sbom-fixture absent from polyglot components[].

---

## Phase 6: User Story 4 — Documentation (Priority: P4)

**Goal**: Document the commons-compress convention choice and any known-limitation FPs surfaced by Stories 2/3.

- [ ] T070 [US4] Open `docs/design-notes.md` and add a section "Known limitations — polyglot bake-off residuals" with three subsections:
  1. **commons-compress 1.21 vs 1.23.0** — why both versions appear (`.m2` cache vs Fedora sidecar), mikebom's default (embedded wins, cite feature 007 FR-004), operator workarounds (exclude `.m2/`, or wait for FU-002).
  2. **Go BuildInfo test-scope modules** (only if Story 1 identified at least one Go FP as known-limitation) — when a compiled Go binary legitimately links a test-scope module, no static signal distinguishes it from a production use; cross-reference FU-001.
  3. **Any Story-2/3 residuals** — one paragraph each if Story 1 flagged anything else.
- [ ] T071 [US4] Ensure each subsection names at least one workaround available today (per spec FR-011). Examples: `--exclude-path`, operator manual filtering at bake-off-harness level, consumers reading `mikebom:sbom-tier` to discount `analyzed` vs `source` confidence.
- [ ] T072 [US4] Run `cargo +stable clippy --workspace --all-targets` and `cargo +stable test --workspace`. Docs-only change; counts MUST be unchanged.
- [ ] T073 [US4] Commit and push `docs/us4-polyglot-known-limitations`; open PR titled "docs(design): document polyglot bake-off known limitations (008 US4)". Include constitution v1.2.1 evidence in PR body.

---

## Phase 7: Polish & Cross-Cutting

**Purpose**: Close the feature after all four slices land.

- [ ] T080 Rebase `main` after US1/US2/US3/US4 PRs merge. Verify `cargo +stable test --workspace` passes; record the final count (baseline + new tests).
- [ ] T081 Run the final bake-off against polyglot-builder-image using the post-merge binary. Record per-ecosystem scoreboard. Confirm SC-005: finding count ≤ 1 (commons-compress as documented known behavior).
- [ ] T082 If any unexpected new FP surfaces in T081, open a follow-up issue; do NOT silently close this feature.
- [ ] T083 Delete merged feature branches. Update the spec Status to `Shipped`.

---

## Dependencies

```text
Phase 1 (Setup) ─► Phase 2 (Foundational, rootfs access) ─► Phase 3 (US1 investigation) ─► PR merged
                                                                        │
                                           ┌────────────────────────────┼────────────────────────────┐
                                           ▼                            ▼                            ▼
                                   Phase 4 (US2)              Phase 5 (US3)              Phase 6 (US4)
                                 (conditional on              (conditional on            (always runs)
                                  Story 1 findings)           Story 1 findings)
                                           │                            │                            │
                                           └────────────┬───────────────┴─────────────┬──────────────┘
                                                        ▼                             ▼
                                              Phase 7 (Polish — after all merged)
```

- **Phase 2 blocks Phase 3**: polyglot rootfs access is a hard prerequisite; the investigation cannot be honestly done without it (G3 post-mortem rule).
- **Phase 3 blocks Phases 4 and 5**: fix scope is determined by Story 1.
- **Phase 6 (Story 4) can run in parallel with Phases 4/5** if Story 1 produced any known-limitation entries; otherwise it waits until Stories 2/3 conclude so their residuals are captured too.
- **Phase 7 runs last**, after all PRs merge.

## Parallel Execution Examples

**Phase 3 — evidence gathering** (after T010's debug scan produces the base artifacts):

```text
T010                                    # scan + log capture (sequential — everything else depends on it)
T011 [P] T012 [P] T013 [P] T014 [P] T015 [P]   # five parallel evidence extractions
T016                                    # freshness check
T017 ─► T018 ─► T019 ─► T020            # write investigation.md (sequential; same file)
T021 ─► T022                            # verify + PR
```

**Phase 4 / Phase 5 can run in parallel** once Story 1 is merged, since they touch different source files (US2 → `golang.rs` / `mod.rs`, US3 → `maven.rs`).

## Implementation Strategy

**Strict gating**: Do NOT start Phase 4 or Phase 5 until the Phase 3 investigation PR has merged. The investigation might change the story scope (e.g., reveal that some FPs are actually stale-binary issues, not mikebom bugs).

**No speculative code**: Task T032 (US2) and T052 (US3) are deliberately abstract until the investigation narrows the fix option. Resist the temptation to start coding before the investigation completes — that's what caused US2/US4 not to land.

**Conditional-filler placeholders**: Tasks like T032 (`<chosen file>`, `<chosen fix>`) and T052 contain literal placeholder markers. These are INTENTIONAL conditional fillers — replaced with the concrete choice from US1's `investigation.md` when the corresponding PR is opened, not at spec time. They are not unresolved TODOs; they're the documented shape of work that cannot be specified until Story 1 completes.

**Marking gated-skipped tasks**: When a gate task (T030 for Story 2, T050 for Story 3) determines a downstream task is not applicable, the downstream task MUST be marked `[N/A]` in tasks.md with a one-line reason citing the gating task — e.g., `[N/A] T032 — gated by T030: no Go FP marked closable`. Never silently skipped, never left as `[ ]`.

**Per-PR constitution verification**: Every single PR opened against this feature MUST cite the results of `cargo +stable clippy --workspace --all-targets` and `cargo +stable test --workspace` in its description. Per-crate test commands are NOT acceptable evidence.

**Rollback discipline**: Each slice is its own PR. If any slice regresses, revert just that PR.
