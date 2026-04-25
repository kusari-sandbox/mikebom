---
description: "Task list — Address the 192 deferred clippy warnings (milestone 016)"
---

# Tasks: Address the 192 Deferred Clippy Warnings

**Input**: Design documents from `/specs/016-remaining-clippy-cleanup/`
**Prerequisites**: plan.md (✅), spec.md (✅), research.md (✅), data-model.md (✅), contracts/ci-clippy-gate.md (✅), quickstart.md (✅)

**Tests**: No new automated tests added — milestone 016 is a cleanup pass + CI-gate addition. The CI gate IS the new behavioral guarantee per spec FR-006; verification happens via the SC-003 acceptance probe (T016) and the existing 1385-passing test suite (must remain green per FR-004).

**Organization**: Tasks are grouped by user story for independent implementation:

- **US1 (P1, MVP)**: Dead-code triage and purge — ~150 of 192 warnings. Largest single contributor; clears the bulk of clippy noise.
- **US2 (P2)**: Doc-list prose restructuring — ~37 warnings. Cosmetic but improves rustdoc rendering.
- **US3 (P3)**: CI gate so warnings stay at zero — adds `macos-latest` job, `-- -D warnings` flag, constitution sync.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Maps task to spec.md user story (US1, US2, US3); omitted on Setup / Polish

## Path Conventions

Single Rust workspace; this milestone touches `mikebom-cli/src/`, `mikebom-common/src/`, `mikebom-cli/tests/`, `.github/workflows/ci.yml`, and `.specify/memory/constitution.md`. No new directories or crates.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Snapshot the current warning state so per-cluster progress is measurable and the final-state delta is auditable in the PR description.

- [X] T001 Snapshot baseline clippy output: run `cargo +stable clippy --workspace --all-targets 2>/tmp/clippy-before.txt` and `grep '^warning:' /tmp/clippy-before.txt | sort | uniq -c | sort -rn > /tmp/clippy-before-categorized.txt`. Confirm total via `grep -c '^warning:' /tmp/clippy-before.txt` (expected ≈192). Save both files for reference; the categorized counts inform per-cluster sizing in T002–T007 + T009–T012 and seed the per-resolution table in the final PR description (per `data-model.md` §"TriageDecision aggregation in PR description"). Output is local-only — not committed.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: None. Cleanup work has no shared infrastructure dependencies beyond the baseline snapshot.

**Checkpoint**: User stories may begin immediately after T001.

---

## Phase 3: User Story 1 — Dead-code triage and purge (Priority: P1) 🎯 MVP

**Goal**: Resolve every `dead_code`-class warning in the baseline (~150 of 192) by applying the three-tier triage from `research.md` §R2 — Tier A `#[cfg(target_os = "linux")]`, Tier B `#[cfg_attr(not(target_os = "linux"), allow(dead_code))]`, or Tier C delete. Per `data-model.md` §"TriageDecision validation rules", every flagged warning gets exactly one resolution; `removed` items have zero callers anywhere; `gated`/`annotated` items have a one-line rationale.

**Independent Test**: After T008, `cargo +stable clippy --workspace --all-targets 2>&1 | grep -c "never used\|never read\|never constructed"` returns 0 on both macOS and Linux. Total warning count drops from ≈192 to ≈40 (just the doc-list cluster + 3 `field_reassign_with_default` cases remain — those are US2 / T007's domain).

**Implementation note**: T002–T007 touch different files / file clusters and are file-disjoint (verified via the per-cluster file lists below) — they can be implemented in any order or in parallel. T008 must run after T002–T007.

- [X] T002 [P] [US1] Triage `mikebom-cli/src/trace/*` Linux-only items per `research.md` §R2 Tier A (preferred) or Tier B (when cross-platform reachable). Files: `aggregator.rs` (struct/methods of `EventAggregator`, `ConnectionBuilder`, `AggregatedTrace`), `processor.rs` (`TraceProcessor`, `LiveStats`, `TraceStats`), `pid_tracker.rs` (`PidTracker` struct + methods), `loader.rs` (`LoaderConfig`, `EbpfHandle`, `load_and_attach`), `sni_extractor.rs` (`extract_sni`, `parse_sni_extension`, `Cursor`), `http_parser.rs` (`parse_request`, `parse_response`, `is_http_method`, `extract_header`). For each item: prefer Tier A — add `#[cfg(target_os = "linux")]` to the item itself if `grep -rn "<item_name>" mikebom-cli/ mikebom-common/` shows callers only inside other `#[cfg(target_os = "linux")]` blocks. Fall back to Tier B if cross-platform reachable. After every cluster of fixes, re-run `cargo +stable clippy --workspace --all-targets` and confirm warning count drops without new warnings appearing. Verify cross-platform compile: `cargo +stable check --workspace` on macOS.
- [X] T003 [P] [US1] Triage `mikebom-cli/src/attestation/*` items. Files: `builder.rs` (`AttestationConfig`, `build_attestation`, `detect_host_info`, `detect_kernel_version`, `detect_distro_codename`), `serializer.rs` (`write_attestation`, `write_attestation_signed`, `write_witness_attestation_signed`, `write_signable`, `to_json`), `signer.rs` (`SigningIdentity` variants, `OidcProvider` variants, `DEFAULT_KEY_ALGORITHM`, `load_local_signer`, `scheme_for_algorithm`, `sign_local`, `sign_keyless`, `keyid_for_pem`), `subject.rs` (`ARTIFACT_SUFFIXES`, `SubjectResolver::resolve`, `detect_magic_bytes`, `is_elf`, `is_mach_o`, `is_pe`, `hex_encode`, `synthetic_descriptor`), `witness_builder.rs` (full function set: `build_witness_statement`, `resolve_subjects`, `subject_to_witness`, `build_material_attestation`, `algorithm_key`, `build_command_run_attestation`, `shell_split`, `build_product_attestation`, `build_network_trace_attestation`, `protocol_to_string`). Many of these are referenced from `mikebom-cli/src/cli/scan.rs::execute_scan` (Linux-only) per the milestone-015 exploration findings — apply Tier A. Items genuinely orphaned (zero `grep` hits anywhere in `mikebom-cli/src/` and `mikebom-cli/tests/`) get Tier C delete. Future-feature scaffolding (e.g., `OidcProvider::Keyless` if the keyless flow is post-MVP) gets Tier B + a one-line `// scaffolding for milestone-XYZ keyless signing` comment. Re-run clippy after the cluster.
- [X] T004 [P] [US1] Triage `mikebom-cli/src/enrich/*` orphans. Files: `deps_dev_client.rs` (`query_url`, `query_by_hash`), `license_resolver.rs` (`resolve_licenses`), `vex_builder.rs` (`build_vex_entries`), `supplier_resolver.rs` (`resolve_supplier`), `clearly_defined_client.rs` (`with_base_url`), `clearly_defined_source.rs` (`with_client`). Most are post-#17-refactor leftovers (compare-subcommand removal cascaded callers away) and are Tier C delete candidates — verify with `grep -rn "<fn_name>" mikebom-cli/ mikebom-common/` showing zero hits before deletion. Items still referenced under `cli/enrich.rs::execute` get Tier B. Re-run clippy after the cluster.
- [X] T005 [P] [US1] Triage `mikebom-cli/src/resolve/*` items. Files: `url_resolver.rs` (`resolve_url`), `path_resolver.rs` (`resolve_path`), `purl_validator.rs` (`validate_purl`, `validate_maven`, `validate_deb`), `hash_resolver.rs` (`HashResolver::with_base_url`, `HashResolver::timeout`). Apply the same triage logic as T004 — most are orphans (Tier C); any still referenced from `resolve/pipeline.rs` get Tier B. Verify with grep before deletion. Re-run clippy.
- [X] T006 [P] [US1] Triage long-tail dead-code in `mikebom-cli/src/{cli,scan_fs,config.rs}`. Files: `config.rs` (`DEFAULT_ATTESTATION_OUTPUT`, `DEFAULT_CDX_OUTPUT`, `DEFAULT_RING_BUFFER_SIZE`, `DEFAULT_DEPS_DEV_TIMEOUT`, `OutputFormat::CycloneDxXml`, `OutputFormat::SpdxJson` — note: `TOOL_NAME`, `TOOL_VERSION`, `INTOTO_STATEMENT_TYPE`, `PREDICATE_TYPE` ARE used per the milestone-015 grep findings; verify before classifying), `cli/auto_dirs.rs`, `cli/scan.rs` (any items not covered by T002/T003), `scan_fs/mod.rs`, `scan_fs/docker_image.rs`, `scan_fs/binary/elf.rs`, `scan_fs/package_db/maven.rs`, `scan_fs/package_db/pip.rs`, `scan_fs/package_db/rpmdb_sqlite/page.rs` (the `rowid` field). For each: grep for callers; pick remove / gate / annotate. Re-run clippy.
- [X] T007 [P] [US1] Resolve the 3 `field_reassign_with_default` warnings per spec FR-008. Sites: `mikebom-cli/src/scan_fs/binary/elf.rs:85` (`ElfScan::default()` then conditional field-set), `mikebom-cli/src/scan_fs/package_db/pip.rs:1479`, `mikebom-cli/src/scan_fs/package_db/pip.rs:1490`. For each: attempt a struct-init refactor (compute all fields first, then construct in one expression); if the conditional-set pattern is genuinely the cleanest expression, fall back to `#[allow(clippy::field_reassign_with_default)]` with a one-line comment naming the conditional rationale (e.g., `// .has_dynamic depends on section presence; .needed and .note_package only set on success — struct-init would force three Option-unwraps`). Re-run clippy.
- [X] T008 [US1] Verify zero dead-code warnings end-state. Run `cargo +stable clippy --workspace --all-targets 2>/tmp/clippy-after-us1.txt` AND `grep -c "never used\|never read\|never constructed" /tmp/clippy-after-us1.txt` — expected `0`. Run `cargo +stable test --workspace 2>&1 | grep "test result" | grep -v "0 failed" | wc -l` — expected `0`. Cross-check on macOS (the maintainer's local dev env). If any dead-code warning persists, return to the appropriate T002–T007 task and resolve. **Depends on T002–T007 being complete.**

**Checkpoint**: After T008, the clippy log contains only the ~37 doc-list warnings (US2's domain). The 1385-passing test baseline still holds.

---

## Phase 4: User Story 2 — Doc-list prose restructuring (Priority: P2)

**Goal**: Resolve every `clippy::doc_lazy_continuation` warning by restructuring doc comments per `quickstart.md` §"Common pitfalls" (blank-line paragraph break OR sub-bullet reformat OR per-block `#[allow]` with rationale).

**Independent Test**: After T013, `cargo +stable clippy --workspace --all-targets 2>&1 | grep -c "doc list item"` returns `0`. `cargo doc --workspace --no-deps` succeeds and the affected modules render with intended structure (sub-bullets show as nested lists, prose paragraphs show as paragraphs).

**Implementation note**: T009–T012 touch different files and are file-disjoint — parallel-safe.

- [X] T009 [P] [US2] Restructure the 10-warning doc-comment cluster in `mikebom-cli/tests/cdx_regression.rs:152-165`. The single doc comment for `fn normalize` mixes a numbered parent bullet with two sub-bullets (Maven JARs, Go module zips) followed by prose continuation. Insert a blank `///` line after the sub-bullet list to break clippy's lazy-continuation parsing, OR indent the prose continuation 4 more spaces to align under the parent bullet. Re-run `cargo +stable clippy -p mikebom --tests` and confirm zero `doc list item` warnings for this file. Verify `cargo doc -p mikebom --no-deps` renders the comment correctly.
- [X] T010 [P] [US2] Restructure the 8-warning doc-comment cluster in `mikebom-cli/src/scan_fs/mod.rs` (lines 103, 541-547 per the baseline categorization). Apply the same blank-line-break OR re-indent strategy as T009. Re-run clippy + cargo doc to verify.
- [X] T011 [P] [US2] Restructure doc-list warnings in `mikebom-common/src/attestation/{envelope.rs,witness.rs}`. Specifically `envelope.rs:183` (1 warning) and `witness.rs:5,6,7` (3 warnings). Re-run clippy + cargo doc. Verify rustdoc still renders the witness module's "branch `add-networktrace-attestor` @ `23a67367`. Emitting this shape makes mikebom attestations directly consumable by `sbomit generate`" prose correctly after the restructure.
- [X] T012 [P] [US2] Mop up any remaining doc-list sites not in T009-T011. Likely candidates per the baseline's per-file count: `mikebom-cli/src/scan_fs/package_db/pip.rs:139` (1 warning), `mikebom-cli/src/cli/auto_dirs.rs` (4 warnings). Apply the same restructuring strategy. Run `cargo +stable clippy --workspace --all-targets 2>&1 | grep -c "doc list item"` after — expected `0`.
- [X] T013 [US2] Verify zero doc-list warnings end-state. Run `cargo +stable clippy --workspace --all-targets 2>/tmp/clippy-after-us2.txt`; confirm `grep -c "doc list item" /tmp/clippy-after-us2.txt` returns `0` AND `grep -c '^warning:' /tmp/clippy-after-us2.txt` returns ≤3 (the 3 `field_reassign_with_default` warnings are also resolved by T007 by this point). Run `cargo doc --workspace --no-deps 2>&1 | grep -c warning` — expected `0`. **Depends on T009–T012.**

**Checkpoint**: After T013, the workspace emits zero clippy warnings. US3 can flip the `-- -D warnings` switch.

---

## Phase 5: User Story 3 — CI gate so warnings stay at zero (Priority: P3)

**Goal**: Lock the zero-warnings baseline against future regression by adding a `macos-latest` CI job, flipping the existing Linux job to `-- -D warnings`, and bumping the constitution to keep its pre-PR-table description in sync.

**Independent Test**: After T016, a deliberately-warning-introducing probe PR fails both jobs of the workflow with a `dead_code` annotation; the probe PR is closed without merging. A clean PR (post-T013 main) passes both jobs.

- [X] T014 [US3] Modify `.github/workflows/ci.yml`: (a) add a new job `lint-and-test-macos` running on `runs-on: macos-latest` with steps per `research.md` §R3 (checkout → install stable Rust + clippy → cache → run clippy with `-- -D warnings` → run tests); skip the eBPF/sbomqs/nightly steps that the existing Linux job has. (b) Modify the existing `lint-and-test` job's clippy step to add `-- -D warnings` to the cargo invocation. (c) Update the rationale comment block above the clippy step (currently lines ~70-77 of ci.yml) to say "After milestone 016, `-D warnings` is on: the legacy backlog is cleared (zero warnings baseline). New lint categories from future toolchain bumps fail CI loudly; resolve by fixing the new category in the same PR or adding `#[allow(...)]` justification." Verify the workflow YAML is well-formed (e.g., `python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/ci.yml"))'`).
- [X] T015 [US3] Bump `.specify/memory/constitution.md` from version 1.3.0 → 1.3.1 (PATCH) per `research.md` §R6. Update the SYNC IMPACT REPORT block at the top of the file with: (a) version change line `1.3.0 → 1.3.1`, (b) bump rationale `PATCH — pre-PR table line 359 updated to reflect the post-milestone-016 zero-warnings baseline; clarified deliberate divergence with line 346 quick-reference command`, (c) modified-sections list naming the Pre-PR Verification table, (d) templates-requiring-updates list with `✅ no update needed` for all five templates. Update the table at line 357-360: clippy command becomes `cargo +stable clippy --workspace --all-targets -- -D warnings`; passing condition becomes `Zero errors and zero warnings`. **Also append a one-paragraph note immediately after the Pre-PR Verification table explaining the deliberate divergence with the Build & Test Commands quick-reference at line 346**: line 346's `cargo clippy --all-targets --all-features -- -D warnings` is the thorough developer-local lint that exercises feature-gated code; line 359's `cargo +stable clippy --workspace --all-targets -- -D warnings` is the canonical CI gate matching `.github/workflows/ci.yml` exactly. Both must pass for a PR to merge; the flag-set difference (`--all-features` vs `--workspace`) is intentional and prevents a future contributor from "harmonizing" them. Update the footer at line 417: `**Last Amended**: 2026-04-25`. Verify constitution still parses by running `grep -c "^### " .specify/memory/constitution.md` — expected `12` (one heading per principle).
- [X] T016 [US3] Verify SC-003 acceptance test for the new gate. **Deferred to post-merge**: the probe PR can only meaningfully fail once the new CI workflow is live on `main`. After this PR merges, run the probe-PR recipe from `quickstart.md` once and capture the failing-log URL in a follow-up note. From a throwaway branch off `016-remaining-clippy-cleanup` (do NOT merge): `git checkout -b 016-deliberate-warning-probe`; append `pub fn deliberate_dead_code() {}` to `mikebom-cli/src/lib.rs`; commit with `probe: deliberate dead-code (will close, do not merge)`; push and open a probe PR. Confirm both `lint-and-test (linux-x86_64)` and `lint-and-test-macos` jobs FAIL with the `dead_code` annotation pointing at the new line. Capture the failing log URL for the implementation PR's description as evidence. Close the probe PR without merging; delete the local + remote probe branch. **Depends on T014.**

**Checkpoint**: After T016, the gate is verifiably catching regressions. The implementation PR is ready for the polish phase.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final verification across all stories + PR-description compilation per `data-model.md`.

- [X] T017 [P] Run final pre-PR gate locally on macOS: `cargo +stable clippy --workspace --all-targets 2>&1 | grep -c '^warning:'` — expected `0`. `cargo +stable clippy --workspace --all-targets -- -D warnings` — expected exit 0. Capture the warning-count delta (192 → 0) for the PR description.
- [X] T018 [P] Verify zero test regressions: `cargo +stable test --workspace 2>&1 | tee /tmp/tests-final.txt`; confirm `grep "test result:" /tmp/tests-final.txt | grep -v "0 failed" | wc -l` returns `0`; confirm `grep "test result: ok" /tmp/tests-final.txt | awk '{sum+=$4} END {print sum}'` matches the baseline (1385 from milestone-015 PR #33 description). Capture per-target counts for the PR description per `feedback_prepr_gate_full_output.md`.
- [ ] T019 Compile the per-resolution triage summary table for the PR description per `data-model.md` §"TriageDecision aggregation in PR description". The table MUST list: removed count + 1 example, gated Tier A count + 1 example, gated Tier B count + 1 example, annotated count + 1 example, restructured count + 1 example, and the total. Plus call out any 5+ item clusters by file (e.g., "All 13 `attestation/witness_builder.rs` items annotated with `#[allow(dead_code)]` — planned consumer is the upcoming witness-collection emit path under `cli/scan.rs::execute_scan` Linux block"). Save to a local note for use in T020.
- [ ] T020 Open the milestone-016 PR. Title: `feat(016): zero-warnings clippy baseline + macOS CI gate`. Body MUST include: (a) summary of triage stats (pulled from T019), (b) cite per-target test pass counts (from T018) per `feedback_prepr_gate_full_output.md`, (c) link to the closed probe PR from T016 as SC-003 evidence, (d) note the constitution bump and link to its diff, (e) acceptance-test checklist matching SC-001 through SC-006 from spec.md.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: T001 only — no dependencies.
- **Foundational (Phase 2)**: empty.
- **US1 (Phase 3)**: T002–T007 [P] all depend on T001 (need the baseline). T008 depends on T002–T007.
- **US2 (Phase 4)**: T009–T012 [P] all depend on T001. T013 depends on T009–T012. US2 is *independent* of US1 — they can run in parallel by different developers, or sequentially in either order.
- **US3 (Phase 5)**: T014 + T015 are [P] (different files). T016 depends on T014. **All of T002–T013 must be complete before T014 fires `-- -D warnings`** — flipping the deny when warnings remain would fail every CI run.
- **Polish (Phase 6)**: T017 + T018 [P]; T019 sequential; T020 depends on T017+T018+T019.

### User Story Dependencies

- **US1 (P1, MVP)**: independent. Ships a partial improvement (zero dead-code) even without US2 or US3.
- **US2 (P2)**: independent. Can ship as a separate PR after US1 or in parallel.
- **US3 (P3)**: depends on US1 + US2 being complete (`-- -D warnings` requires zero warnings).

### Parallel Opportunities

- **US1 fixes**: T002 + T003 + T004 + T005 + T006 + T007 [P] — six file-disjoint clusters; biggest parallelizable batch in this milestone.
- **US2 fixes**: T009 + T010 + T011 + T012 [P] — four file-disjoint clusters.
- **US3 file edits**: T014 + T015 [P] — different files (ci.yml vs constitution.md).
- **Polish**: T017 + T018 [P] — independent verification runs.

---

## Parallel Example: US1 dead-code triage

```bash
# Six independent triage tasks, file-disjoint:
Task: "Triage mikebom-cli/src/trace/* Linux-only items per Tier A/B"
Task: "Triage mikebom-cli/src/attestation/* items"
Task: "Triage mikebom-cli/src/enrich/* orphans"
Task: "Triage mikebom-cli/src/resolve/* items"
Task: "Triage long-tail dead-code in cli/scan_fs/config.rs"
Task: "Resolve 3 field_reassign_with_default warnings in elf.rs + pip.rs"

# Then sequential:
Task: "Verify zero dead-code warnings via re-snapshot (T008)"
```

---

## Implementation Strategy

### MVP First (US1 only)

1. Complete Phase 1: Setup (T001). ~5 minutes.
2. Skip Phase 2 (empty).
3. Complete Phase 3: US1 (T002–T008). ~3-5 hours — biggest time sink; parallelize by file cluster.
4. Run `cargo +stable clippy --workspace --all-targets 2>&1 | grep -c '^warning:'` — expect ≈40 (only doc-list + 0 other lints, since T007 covered field_reassign).
5. Ship as a standalone PR — clears the `dead_code` cluster, the largest source of clippy noise. Defer US2 + US3 to separate PRs.

### Incremental Delivery

1. Setup → ready.
2. US1 → MVP ships. Zero dead-code warnings.
3. US2 → ships. Zero doc-list warnings.
4. US3 → ships. CI gate locks the baseline.
5. Polish → final pre-PR gate + PR-description compilation.

Recommended for this milestone (single maintainer): bundle all three stories + polish into one PR, since US3 requires US1 + US2 complete to flip the deny safely. The chunked-commits guidance in `quickstart.md` keeps the diff reviewable.

### Parallel Team Strategy

Two-developer split:

- Developer A: US1 (T002–T008) — the dead-code triage.
- Developer B: US2 (T009–T013) — the doc-list restructuring.

Both converge on US3 (T014–T016) once US1 and US2 are merged.

---

## Notes

- File paths absolute relative to repo root; cargo commands run from repo root.
- After every file cluster (T002, T003, etc.), re-run `cargo +stable clippy --workspace --all-targets` and confirm the warning count drops monotonically. Never let it go up — that signals a cascade.
- Per `feedback_prepr_gate_full_output.md`, the PR description MUST cite per-target `ok. N passed; 0 failed` lines, not grep summaries.
- The `mikebom-cli/src/main.rs:7` `#![deny(clippy::unwrap_used)]` stays — that's Constitution Principle IV. The new `-- -D warnings` flag is additive.
- `T016` (the deliberate-warning probe) is a one-time verification, not standing infrastructure. The probe PR is closed and the branch deleted; the only artifact is the failing-log URL captured in the implementation PR description.
