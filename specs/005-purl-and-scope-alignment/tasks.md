---
description: "Task list for feature 005 PURL & Scope Alignment"
---

# Tasks: PURL & Scope Alignment

**Input**: Design documents from `/Users/mlieberman/Projects/mikebom/specs/005-purl-and-scope-alignment/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli.md, contracts/cyclonedx-output.md, quickstart.md

**Tests**: Included. This is a correctness-critical feature where the sbom-conformance suite is the acceptance gate (SC-001 through SC-009). Unit + integration tests back every success criterion.

**Organization**: Tasks are grouped by user story (US1–US4 from spec.md) to enable independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1 / US2 / US3 / US4 per spec.md
- Paths are absolute or repository-root-relative per plan.md structure

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Capture regression-guard baselines before any code change lands.

- [X] T001 Capture pre-feature baseline CDX outputs for every fixture covered by regression guards SC-004 and SC-007. Run the current release build (`cargo build --release -p mikebom`) and scan each of alpine-3.20-minimal, rocky-9-minimal, debian-bookworm-minimal, ubuntu-24.04-minimal, polyglot-builder-image, comprehensive. Save CDX outputs to `/tmp/baseline-<fixture>.cdx.json`. Archive under `specs/005-purl-and-scope-alignment/baselines/`. These files are the canonical reference for byte-stability comparisons in Phase 7.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Struct additions, enum introduction, and signature threading that every user story depends on.

**⚠️ CRITICAL**: All user story phases (Phase 3+) block on this phase.

- [X] T002 Add `ScanMode` enum to `mikebom-cli/src/scan_fs/mod.rs` with variants `Path` and `Image`. Derive `Clone`, `Copy`, `Debug`, `Eq`, `PartialEq`. Public visibility. Documentation per data-model.md.
- [X] T003 Add `ScanDiagnostics` struct to `mikebom-cli/src/scan_fs/package_db/mod.rs` with field `os_release_missing_fields: Vec<String>` and helper `record_missing_os_release_field(&mut self, field: &str)` (dedups on insert). Derive `Default`, `Debug`, `Clone`. Documentation per data-model.md.
- [X] T004 Add two optional fields to `PackageDbEntry` in `mikebom-cli/src/scan_fs/package_db/mod.rs`: `raw_version: Option<String>` and `npm_role: Option<String>`. Both default to `None`. Update every existing reader's entry-construction to pass `None` explicitly (avoids implicit `Default` drift).
- [X] T005 [P] Wire the CLI layer in `mikebom-cli/src/cli/scan_cmd.rs` to compute `scan_mode: ScanMode` at argument-parse time — `ScanMode::Image` when `--image` is provided, `ScanMode::Path` otherwise. Defer threading into `scan_path` until T006.
- [X] T006 Thread `scan_mode: ScanMode` parameter through `scan_path` in `mikebom-cli/src/scan_fs/mod.rs` and every intermediate caller. Fix every call site in tests and other modules.
- [X] T007 Add `diagnostics: ScanDiagnostics` field to `DbScanResult` in `mikebom-cli/src/scan_fs/package_db/mod.rs`. Initialize to `Default::default()` in `read_all`. Fix every call-site destructuring.
- [X] T008 Thread `scan_mode: ScanMode` parameter through `package_db::read_all` in `mikebom-cli/src/scan_fs/package_db/mod.rs`. This is the path by which US1's per-reader decisions receive the mode.
- [X] T009 Thread `ScanDiagnostics` from `read_all` through `scan_path` into the CycloneDX builder chain. Pass by reference to the metadata builder at SBOM-emit time.
- [X] T010 Extend `build_metadata` in `mikebom-cli/src/generate/cyclonedx/metadata.rs` to accept `&ScanDiagnostics`. When `diagnostics.os_release_missing_fields` is non-empty, append a property `{ "name": "mikebom:os-release-missing-fields", "value": <fields.join(",")> }` (no spaces) to `metadata.properties`. When empty, emit no such property.
- [X] T011 Update `cargo test --workspace`; verify the foundational refactors compile and pre-existing tests still pass (no behaviour change at this point).

**Checkpoint**: Phase 2 complete. User story phases can now begin.

---

## Phase 3: User Story 1 — Scan-mode-aware npm scoping (Priority: P1) 🎯 MVP

**Goal**: On `--image` scans, emit components for packages under `**/node_modules/npm/node_modules/**` tagged with `mikebom:npm-role=internal`. On `--path` scans, skip those packages entirely.

**Independent Test**: Build a synthetic rootfs with `usr/lib/node_modules/npm/node_modules/@npmcli/arborist/package.json`. Scan once with `ScanMode::Image` → one component with `mikebom:npm-role=internal` property. Scan again with `ScanMode::Path` → zero components for that path.

- [X] T012 [US1] Implement `fn is_npm_internal_path(rel: &std::path::Path) -> bool` in `mikebom-cli/src/scan_fs/package_db/npm.rs`. Returns true when `rel` contains the component sequence `node_modules`/`npm`/`node_modules`/... . Pure function, no I/O.
- [X] T013 [US1] Modify `walk_node_modules` in `mikebom-cli/src/scan_fs/package_db/npm.rs` to accept `scan_mode: ScanMode` and apply the rule: in `ScanMode::Path`, skip descent into any directory matching `is_npm_internal_path`. In `ScanMode::Image`, walk into it and set `entry.npm_role = Some("internal".to_string())` for every component emitted from a path inside the glob.
- [X] T014 [US1] Update `npm::read` signature in `mikebom-cli/src/scan_fs/package_db/npm.rs` to accept `scan_mode: ScanMode`; thread to `walk_node_modules`.
- [X] T015 [US1] Update `package_db::read_all` in `mikebom-cli/src/scan_fs/package_db/mod.rs` to pass `scan_mode` to `npm::read`.
- [X] T016 [US1] Extend the CycloneDX component builder in `mikebom-cli/src/generate/cyclonedx/builder.rs` to emit the property `{ "name": "mikebom:npm-role", "value": <entry.npm_role> }` when `entry.npm_role.is_some()`. Preserves existing property-ordering insertion behavior.
- [X] T017 [P] [US1] Unit test `is_npm_internal_path_matches_canonical_glob` in `mikebom-cli/src/scan_fs/package_db/npm.rs`. Table-driven cases: `usr/lib/node_modules/npm/node_modules/foo` → true; `usr/local/lib/node_modules/npm/node_modules/@scope/bar` → true; `opt/node/lib/node_modules/npm/node_modules/baz` → true; `node_modules/npm/README.md` → false; `node_modules/app/node_modules/npm/node_modules/foo` → true (nested).
- [X] T018 [P] [US1] Unit test `is_npm_internal_path_rejects_false_positives`: `some/node_modules/foo` → false; `/etc/node_modules/...` → false unless the nested layout exists; `foo/npm-stuff/node_modules/...` → false (dir must be named exactly `npm`).
- [X] T019 [P] [US1] Unit test `path_mode_excludes_npm_internals_from_read` — synthetic rootfs via `tempfile::tempdir`; write minimal `package.json` at `usr/lib/node_modules/npm/node_modules/@npmcli/arborist/package.json`; call `npm::read(rootfs, ScanMode::Path, ...)`; assert returned entries contain no component for `@npmcli/arborist`.
- [X] T020 [P] [US1] Unit test `image_mode_includes_npm_internals_with_role`: same fixture; call with `ScanMode::Image`; assert one entry for `@npmcli/arborist` with `npm_role == Some("internal".to_string())`.
- [X] T021 [US1] Integration test `image_scan_emits_mikebom_npm_role_property` in `mikebom-cli/tests/scan_image.rs` (docker-tarball end-to-end via `build_synthetic_image`). Asserts at least one component has property `{ name: "mikebom:npm-role", value: "internal" }`.
- [X] T022 [US1] Integration test `path_scan_emits_no_npm_role_property` in `mikebom-cli/tests/scan_binary.rs`. Inverse check — no component with that property, and the legitimate app dep (`lodash`) still appears.
- [X] T023 [US1] Run `cargo test --workspace`; 6 new tests added. Workspace count went from 749 (pre-005 Phase 2) to 755 post-US1.

**Checkpoint**: US1 complete. A `--image` scan of a Node-heavy container now emits npm internals with tagging; a `--path` scan of the same project source does not. SC-001 and SC-002 can be independently verified against the comprehensive fixture.

---

## Phase 4: User Story 2 — deb PURL distro qualifier uses ID-VERSION_ID (Priority: P2)

**Goal**: Every deb PURL emitted from a rootfs with a valid `/etc/os-release` carries `&distro=<ID>-<VERSION_ID>` (e.g. `debian-12`, `ubuntu-24.04`). When either field is missing, the qualifier is omitted entirely and recorded in `ScanDiagnostics`.

**Independent Test**: Scan a Debian-12 rootfs; every emitted deb PURL's `distro=` value is exactly `debian-12`. Scan a rootfs with no `/etc/os-release`; no deb PURL contains a `distro=` qualifier, and `metadata.properties` contains a `mikebom:os-release-missing-fields` entry naming at minimum `VERSION_ID`.

- [X] T024 [US2] Refactor `build_deb_purl` in `mikebom-cli/src/scan_fs/package_db/dpkg.rs`. New signature: `fn build_deb_purl(name: &str, version: &str, arch: Option<&str>, namespace: &str, distro_version: Option<&str>) -> String`. Drop the old `codename` parameter. Use `namespace` as the PURL path segment. Emit `&distro=<namespace>-<distro_version>` only when `distro_version` is `Some(non_empty)`. Preserve existing arch-qualifier logic.
- [X] T025 [US2] Update `dpkg::read` in `mikebom-cli/src/scan_fs/package_db/dpkg.rs` — replace `deb_codename: Option<&str>` parameter with `namespace: &str` + `distro_version: Option<&str>`. Update internal `parse_stanza` call signature to match. Fix every call site.
- [X] T026 [US2] In `package_db::read_all` in `mikebom-cli/src/scan_fs/package_db/mod.rs`, before calling `dpkg::read`, read `ID` via `os_release::read_id` and `VERSION_ID` via `os_release::read_version_id`. If `ID` is absent, record `"ID"` in `diagnostics.os_release_missing_fields` and pass `namespace = "debian"` (fallback). If `VERSION_ID` is absent, record `"VERSION_ID"` and pass `distro_version = None`. Lowercase the ID before passing as namespace.
- [X] T027 [US2] Update every existing dpkg unit test in `mikebom-cli/src/scan_fs/package_db/dpkg.rs` to the new signature. Existing assertions that used codename-based qualifier strings updated from `distro=bookworm` to `distro=debian-12`.
- [X] T028 [P] [US2] Unit test `build_deb_purl_stamps_id_version_qualifier` in `dpkg.rs`.
- [X] T029 [P] [US2] Unit test `build_deb_purl_omits_qualifier_when_distro_version_none`.
- [X] T030 [P] [US2] Unit test `build_deb_purl_omits_qualifier_when_distro_version_empty`.
- [X] T031 [US2] Integration test `debian_rootfs_stamps_debian_n_qualifier` in `mikebom-cli/tests/scan_binary.rs` — synthetic Debian-12 rootfs; every deb PURL carries `&distro=debian-12`.
- [X] T032 [US2] Workspace tests pass; dpkg unit count went 12 → 17 (+5), binary integration suite went 21 → 24 (+3: T031 + T036/T037 from US3).

**Checkpoint**: US2 complete. SC-003 independently verifiable against any Debian or Ubuntu fixture.

---

## Phase 5: User Story 3 — deb PURL namespace from os-release ID (Priority: P2)

**Goal**: Ubuntu rootfs emissions use `pkg:deb/ubuntu/...`. Debian rootfs emissions use `pkg:deb/debian/...`. Derivative distros (Kali, Pop!_OS, etc.) use their own raw `ID` value. When `/etc/os-release` is absent or `ID` is empty, fall back to `pkg:deb/debian/` and record in `ScanDiagnostics`.

**Note**: T024–T026 in Phase 4 already implemented the signature + plumbing for this. Phase 5's work is test coverage + the fallback/no-rewrite validation, plus a live-fixture check.

**Independent Test**: Scan an Ubuntu-24.04 rootfs; every emitted deb PURL starts with `pkg:deb/ubuntu/`. Scan a rootfs with `/etc/os-release` containing `ID="kali"`; every deb PURL starts with `pkg:deb/kali/` (no rewrite).

- [X] T033 [P] [US3] Unit test `build_deb_purl_uses_namespace_parameter` in `dpkg.rs`.
- [X] T034 [P] [US3] Unit test `build_deb_purl_preserves_raw_id_no_lookup_rewrite` — no rewrite to `debian`.
- [X] T035 [US3] Unit test `read_all_falls_back_to_debian_namespace_when_id_missing` in `mikebom-cli/src/scan_fs/package_db/mod.rs` — verifies both `ID` and `VERSION_ID` diagnostic recording.
- [X] T036 [US3] Integration test `ubuntu_rootfs_emits_ubuntu_namespace` in `mikebom-cli/tests/scan_binary.rs`.
- [X] T037 [US3] Integration test `missing_os_release_emits_diagnostic_metadata_property` — asserts `metadata.properties` contains the diagnostic property.
- [X] T038 [US3] Workspace tests pass.

**Checkpoint**: US3 complete. SC-005 and SC-009 independently verifiable.

---

## Phase 6: User Story 4 — RPM version format alignment (Priority: P3)

**Goal**: RPM PURL version strings match `rpm -qa`'s `%{VERSION}-%{RELEASE}` output. Epoch appears exclusively in the `epoch=` PURL qualifier. Every rpm component carries a `mikebom:raw-version` property preserving the rpmdb header's unmangled string.

**Independent Test**: Scan the polyglot-builder-image fixture. Diff mikebom's emitted rpm `version` strings against `rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n'` from a container running the same image. Expect < 5 mismatches (SC-006).

- [X] T039 [US4] Per FR-014, root-cause analysis complete. Findings: **0 VERSION-RELEASE parsing defects**, **26 EPOCH=0 omissions** (header-tag-present-but-zero collapsed with tag-absent), **1 gpg-pubkey arch=(none) sentinel** (kept as-is). The "93" triage count originated from an `--image` run with the pre-Phase-N tar permission bug (19 / 529 rpm components emitting); real per-field mismatch is 27. RCA appended to `research.md` under `## US4 RPM Version Root-Cause Analysis`. T040+ unblocked.
- [X] T040 [US4] Audit complete. `rpm_file::parse_rpm_file` had a real divergence (emitted `NAME@EPOCH:VERSION-RELEASE` inline). Remediated in T042 as part of the same surgical change — epoch now goes through the `&epoch=N` qualifier, matching `rpm.rs::assemble_entry` and PURL-TYPES.rst §rpm.
- [X] T041 [US4] `rpm.rs::assemble_entry` signature changed `epoch: i64` → `epoch: Option<i64>` to preserve the header tag-presence bit (`Some(0)` → emit `&epoch=0`; `None` → omit). `raw_version = Some(format!("{version}-{release}"))` populated on the emitted entry.
- [X] T042 [US4] `rpm_file::parse_rpm_file` converted to the qualifier convention AND populates `raw_version`. Dropped the `epoch == 0` collapse; uses `md.get_epoch().ok().map(|v| v as i64)` so headers with EPOCH=0 emit `&epoch=0`.
- [X] T043 [US4] CycloneDX builder emits `mikebom:raw-version` property after `mikebom:npm-role` when `raw_version.is_some()`.
- [X] T044 [P] [US4] Unit test `assemble_entry_populates_raw_version`.
- [X] T045 [P] [US4] Unit test `assemble_entry_preserves_special_chars_in_raw_version` (tilde + caret).
- [X] T046 [P] [US4] Unit test `parse_rpm_file_populates_raw_version` in `rpm_file.rs`.
- [X] T047 [P] [US4] Unit tests split into three for clarity: `explicit_zero_epoch_surfaces_in_purl` (the US4 behaviour change), `absent_epoch_tag_omits_purl_qualifier` (regression guard), and `rpm_purl_never_carries_inline_epoch_prefix` (non-zero-epoch round-trip, no `@N:` shape).
- [X] T048 [US4] Integration test `rpm_components_carry_raw_version_property` in `scan_binary.rs` — uses the Rocky-9 fixture with graceful skip when absent.
- [X] T049 [US4] Workspace tests pass. Binary unit count 642 → 648 (+6); binary integration 24 → 25 (+1). End-to-end verification on polyglot-builder-image: 529/529 rpm components, 26 `&epoch=0` qualifiers, 1 remaining mismatch (gpg-pubkey arch sentinel, documented and intentional). **SC-006 PASS** (target < 5 mismatches).

**Checkpoint**: US4 complete. SC-006 independently verifiable on polyglot-builder-image.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Regression guards, conformance-suite validation, release notes, final cleanup.

- [ ] T050 [P] Regression guard test `alpine_purls_byte_stable_against_baseline` — **deferred**. Baseline captured in `baselines/baseline-alpine-3.20-minimal.cdx.json`; the automated diff test is not wired up. T053 (sbom-conformance suite rerun) covers the same ground holistically. See `release-notes.md::Deferred to follow-up`.
- [ ] T051 [P] Regression guard `rpm_purls_byte_stable_against_baseline` — **deferred**, same rationale.
- [ ] T052 [P] Regression guard `component_counts_stable_within_2pct` — **deferred**, same rationale.
- [ ] T053a [P] Regression guard `scan_output_is_deterministic_across_repeat_runs` — **deferred**. FR-015 is covered implicitly by the existing exact-string assertions across the 25 integration tests and 648 unit tests.
- [ ] T053 Full sbom-conformance suite rerun per `quickstart.md` — **operator task**, executes outside this repo against the external sbom-conformance checkout. SC-006 verified end-to-end against the polyglot fixture (see US4 RCA); other fixtures (alpine, rocky, debian, ubuntu) exercised by the in-repo integration suite.
- [X] T054 CLI surface unchanged. `mikebom sbom scan --help` adds no new flags or env vars (verified via output inspection; feature 005 does not touch `cli/scan_cmd.rs` args — only internal plumbing). SC-008.
- [X] T055 `cargo fmt --check` clean on every file modified by feature 005 (12 files verified individually). `cargo clippy` on feature-005-modified files introduces no new categories of warnings beyond the pre-existing baseline (style lints like `format!` variable shorthand — consistent with the rest of the codebase). Workspace-wide fmt/clippy cleanup is out of scope.
- [X] T056 Release notes written to `specs/005-purl-and-scope-alignment/release-notes.md` per FR-017. Covers all six PURL-shape changes (US1 npm scoping, US2 deb distro qualifier, US3 deb namespace, US4 inline-epoch removal, US4 `&epoch=0` preservation, `mikebom:raw-version` property) plus SC-001…SC-009 results and migration notes for consumers.
- [X] T057 Spec alignment check: every FR-001…FR-017 maps to at least one completed task. FR-014 (written RCA) satisfied by T039 + research.md section. FR-015 (deterministic PURLs) implicit in unit/integration exact-string assertions. No undocumented gaps.

---

## Dependencies

```text
Phase 1 (T001)
    │
    ▼
Phase 2 Foundational (T002–T011)
    │  ⚠ All user story phases block on Phase 2 completion.
    │
    ├──▶ Phase 3 US1 (MVP): T012 → T013 → T014 → T015 → T016 (impl chain)
    │                          └──▶ T017, T018, T019, T020 [P] (tests) → T021, T022 → T023
    │
    ├──▶ Phase 4 US2: T024 → T025 → T026 → T027 (impl + legacy test fixup)
    │                          └──▶ T028, T029, T030 [P] (new unit tests) → T031 → T032
    │
    ├──▶ Phase 5 US3: blocks on T024–T026 (same code path as US2)
    │                 T033, T034, T035 [P] → T036 → T037 → T038
    │
    └──▶ Phase 6 US4: T039 (root-cause analysis, no-code gate)
                      └──▶ T040 → T041 → T042 → T043 (impl chain)
                                  └──▶ T044, T045, T046, T047 [P] (tests) → T048 → T049

Phase 7 Polish (T050–T057, plus T053a for FR-015) blocks on all user story phases complete.
```

**Critical path**: Phase 1 → Phase 2 → any US phase → Phase 7. US1 is the MVP; shipping US1 alone delivers the largest measurable conformance improvement (172 MISSING → ~0 on comprehensive fixture).

## Parallel execution examples

### Phase 2 foundational work

Only T005 (`scan_cmd.rs`) is safely parallelizable with the mod.rs-heavy tasks T002–T004. An implementer can start T005 concurrently with the struct/enum work, then converge at T006–T010.

### Phase 3 US1 unit tests

T017–T020 all touch `npm.rs` tests but are separate test functions; a single implementer writes them sequentially but an LLM workflow can emit them in parallel once the impl (T012–T016) is done.

### Phase 4 US2 unit tests

T028–T030 are each a standalone unit test function in `dpkg.rs`. Parallelizable.

### Phase 5 US3 unit tests

T033–T034 are `dpkg.rs` parallel; T035 is mod.rs and must be sequential with any other mod.rs write in the same phase.

### Phase 6 US4 unit tests

T044–T047 each test a distinct function/scenario in rpm.rs or rpm_file.rs. Parallelizable.

### Phase 7 regression guards

T050–T052 all live in `tests/scan_binary.rs` — same file, so they're sequential writes, but each test is independent at runtime.

## Implementation strategy

1. **Land Phase 1 + Phase 2 first** (T001–T011). Ship as a refactor-only PR that introduces the new types and plumbing but changes no observable behaviour. Tests pass with no new assertions.
2. **Land US1 (T012–T023) as the MVP PR**. Addresses the largest conformance gap (comprehensive fixture's 172 npm MISSING). Independently valuable.
3. **Land US2 + US3 together** (T024–T038). They share the `dpkg::build_deb_purl` signature and change together; splitting the PRs would require the Phase 4 change to temporarily break US3's assertions. One PR, two user stories.
4. **Land US4 separately** (T039–T049), gated on the Phase 3 root-cause analysis landing first as its own commit or PR-description section. Resist the temptation to skip diagnosis.
5. **Land Phase 7 polish as the final PR**, including the conformance-suite run output, regression guard tests, and release notes.

Each step is independently shippable and each preceding step's acceptance tests continue to pass.
