# Feature Specification: SPDX Byte-Identity Goldens + Cross-Host Determinism Parity

**Feature Branch**: `017-spdx-byte-identity-goldens`
**Created**: 2026-04-25
**Status**: Draft
**Input**: User audit follow-on to milestone 016 + PR #38; Tier 2 of the post-016 cleanup roadmap

## Background

Milestone 010 (SPDX 2.3 output) and milestone 011 (SPDX 3.0.1 output) shipped with full schema validation and per-run determinism guards but **without byte-identity goldens**. The CycloneDX path established alongside them in `mikebom-cli/tests/cdx_regression.rs` carries committed golden files for all 9 ecosystems plus a documented `MIKEBOM_UPDATE_CDX_GOLDENS=1` regeneration mechanism — the load-bearing FR-022 / SC-006 guarantee against silent CDX-output drift.

The SPDX tests today (`spdx_determinism.rs`, `spdx3_determinism.rs`) verify only run-vs-run equality on the same host: two scans of the same fixture produce identical bytes after masking `creationInfo.created` (SPDX 2.3) or the `CreationInfo.created` graph element (SPDX 3). They do not verify that the bytes match a *committed* reference. Three concrete consequences:

- A regression that produces deterministically-wrong SPDX output (a serialization-order change, a field rename, an emitter that omits a property for all 9 ecosystems) passes both determinism tests because both scans agree with each other.
- The cross-host fragility that `cdx_regression.rs:36-37` and `:152-180` solved with the workspace-path placeholder + UUID/timestamp masking + HOME/M2_REPO/MAVEN_HOME/GOPATH/GOMODCACHE/CARGO_HOME isolation (per `cdx_regression.rs:75-93`) is not enforced for SPDX. Workspace-path leakage through SPDX `comment` fields, annotation envelopes, or `evidence`-style references would produce host-specific output without being caught.
- The normalization discipline lives only as inline code in `cdx_regression.rs`. Every new acceptance test in milestones 010-013 reinvented some subset of it; a few got it wrong (per the milestone-016 audit, `spdx_us1_acceptance.rs` and `spdx3_us3_acceptance.rs` set `HOME`/`MAVEN_HOME` but skip UUID/timestamp masking).

PR #38 (Tier 1) finished the test-helper dedup so all SPDX acceptance tests now share `tests/common/{bin, workspace_root, EcosystemCase, CASES}`. This milestone (Tier 2) builds on that infrastructure to extend the byte-identity guarantee from CycloneDX to all three formats.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — SPDX byte-identity goldens for all 9 ecosystems (Priority: P1) 🎯 MVP

As a maintainer reviewing a PR that touches SPDX emission code (a new annotation, a license-handling fix, a relationship-graph change), I want a deterministic byte-level diff against pinned reference output so that any unintended drift in SPDX 2.3 or SPDX 3 output for any of the 9 supported ecosystems is caught at the pre-PR gate.

**Why this priority**: This is the load-bearing equivalent of the CDX FR-022 guarantee from milestone 010. Without it, SPDX output can drift silently while passing the existing per-run determinism tests. Closing this gap brings SPDX coverage to parity with CDX *before* Tier 3-6 work touches the emitters further. The MVP bundles US2 (the shared helper module) by necessity — without it, this story's tests would duplicate the inline normalize logic from `cdx_regression.rs`, recreating the very fragmentation US2 is meant to prevent. P1 and P2 here are *implementation phases*, not separable shipping units.

**Independent Test**: After this story ships:

- `mikebom-cli/tests/fixtures/golden/spdx-2.3/` and `mikebom-cli/tests/fixtures/golden/spdx-3/` each contain 9 pinned files (`{apk,cargo,deb,gem,golang,maven,npm,pip,rpm}.spdx.json` and the same 9 names with `.spdx3.json`).
- New test files `mikebom-cli/tests/spdx_regression.rs` and `mikebom-cli/tests/spdx3_regression.rs` scan each fixture, normalize, and assert byte-equality against the committed golden — one `#[test]` per ecosystem so a failure names the offender.
- Maintainers regenerate goldens via `MIKEBOM_UPDATE_SPDX_GOLDENS=1 cargo test -p mikebom --test spdx_regression` and `MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo test -p mikebom --test spdx3_regression`, matching the existing `MIKEBOM_UPDATE_CDX_GOLDENS=1` pattern from `cdx_regression.rs:12`.

**Acceptance Scenarios**:

1. **Given** the current main, **When** `spdx_regression.rs` and `spdx3_regression.rs` land with 9 + 9 = 18 committed golden files, **Then** `./scripts/pre-pr.sh` passes locally on macOS and on both CI legs (Linux + macOS).
2. **Given** a deliberate PR that changes the SPDX 2.3 emitter to add a new field on every Package, **When** CI runs, **Then** `spdx_regression` fails for all 9 ecosystem fixtures with a clear "golden mismatch" diff naming the diverging path.
3. **Given** a deliberate PR that introduces workspace-path leakage in an SPDX field (e.g., a comment carrying `/Users/<dev>/Projects/...`), **When** CI runs the macOS leg of the gate, **Then** the test fails because the leaked path doesn't match the committed `<WORKSPACE>`-placeholder golden.

---

### User Story 2 — Shared normalization helper (Priority: P2)

As a contributor adding a new SPDX-touching acceptance test, I want one place to import the cross-host normalization utilities (workspace-path masking, UUID/timestamp/document-IRI masking, hash stripping, fake-HOME setup) so that I don't accidentally normalize half the fields and ship a flaky test.

**Why this priority**: Today the discipline lives inline in `cdx_regression.rs` and is applied nowhere else. Extracting it makes the next acceptance test (or a developer fixing a fragility regression in an existing test) trivial to write. Without this helper, every new test gets it slightly wrong — exactly the failure mode the user's `feedback_cross_host_goldens` memory was tagged for ("rewrite workspace path, strip hashes, isolate HOME, mask serial/timestamp ALL AT ONCE").

**Dependency note**: US2 is a hard prerequisite for US1's implementation, not an independent shipping unit. The P2 label reflects user-visible value (developer ergonomics for *future* test additions) — but in this milestone's execution US2 lands first as Phase 2 of `tasks.md` because Phase 3 cannot start without it.

**Independent Test**: After this story ships:

- `mikebom-cli/tests/common/normalize.rs` exists and exports per-format normalizers (`normalize_cdx_for_golden`, `normalize_spdx23_for_golden`, `normalize_spdx3_for_golden`) plus a uniform `apply_fake_home_env(&mut Command, &Path)` helper.
- `cdx_regression.rs` migrates from its inline `normalize()` (lines 143-183) to `common::normalize::normalize_cdx_for_golden` with no behavior change — all 9 existing CDX goldens match byte-for-byte without regeneration.
- The new `spdx_regression.rs` and `spdx3_regression.rs` test files require zero copy/paste from `cdx_regression.rs`; their normalize calls use the shared helper.

**Acceptance Scenarios**:

1. **Given** `cdx_regression.rs` migrates to the shared helper, **When** `cargo test --workspace` runs, **Then** all 9 CDX goldens match byte-for-byte (no regen required, byte-identical to PR #38's tip).
2. **Given** `spdx_regression.rs` and `spdx3_regression.rs` are written from scratch using `common::normalize`, **Then** their `use common::normalize::*;` import is the only normalization import they need.
3. **Given** a contributor reads `tests/common/normalize.rs`, **Then** the file's module-doc explains exactly which fields each format requires masking and *why* (citing the CDX spec for `serialNumber`, the SPDX spec for `creationInfo.created`, the SPDX 3 spec for `CreationInfo.created`, and the cross-host workspace-path leak vectors).

---

### User Story 3 — Uniform fake-HOME isolation across all acceptance tests (Priority: P3)

As a maintainer, I want every test that shells out to the `mikebom` binary to redirect `HOME`, `M2_REPO`, `MAVEN_HOME`, `GOPATH`, `GOMODCACHE`, `CARGO_HOME` (and any future cache-pointing env var) to a tempdir so that scanner output cannot vary based on whether the host has cached Maven / Go / Cargo metadata. Today the discipline is applied unevenly: `cdx_regression.rs` and `spdx3_determinism.rs` apply all six; `spdx_us1_acceptance.rs`, `spdx3_us3_acceptance.rs`, and ~5 others apply a subset. This is the root cause of the dev-vs-CI golden mismatch the user's memory captured ("commons-text Package showed up on dev but not CI because `~/.m2/` had it cached").

**Why this priority**: This is the durability story. Without uniform isolation, the next time someone adds a new env-var read to an ecosystem reader (e.g., `GOROOT`, `PYTHONPATH`, `BUNDLE_PATH`), tests that don't apply isolation start producing host-dependent output and the milestone-010 fragility regresses. Having every test go through one helper makes the fix a one-line change forever after.

**Independent Test**: After this story ships, `rg -l 'env\("HOME"' mikebom-cli/tests/ -g '!common/' -g '!dual_format_perf.rs'` finds 0 inline call sites — every test that sets `HOME` does so via `common::apply_fake_home_env`. A grep over the test tree for `env\("M2_REPO"|GOPATH|GOMODCACHE|CARGO_HOME` (with the same exclusions) likewise returns 0 inline sites. `tests/dual_format_perf.rs` keeps a local clone for the documented submodule-context reason; see FR-008.

**Acceptance Scenarios**:

1. **Given** a contributor adds a new env-var-driven cache path to an ecosystem reader, **When** they update `apply_fake_home_env` to redirect that var to the fake-home tempdir, **Then** every test using the helper picks up the isolation automatically — zero per-test edits.
2. **Given** the existing acceptance tests that today inline 5–7 lines of env redirect, **When** they migrate, **Then** total LOC drops by ~30 lines without changing test behavior (all goldens match byte-for-byte; existing run-vs-run determinism tests stay green).

---

### Edge Cases

- **SPDX 2.3 `documentNamespace` is timestamp-derived in some emitter paths**. `spdx_determinism.rs:92-100` already asserts it's stable across runs. The golden must capture whatever the deterministic value is; if the emitter ever switches to a UUID-based namespace, the golden + normalize helper must mask it (analogous to CDX `serialNumber`).
- **SPDX 3 document IRI is content-derived (SHA-256 over target-name + version + sorted PURL list per `spdx3_determinism.rs:11-13`)** so it's stable across runs and across hosts — no normalization needed today. If a future emitter change makes any IRI segment host-dependent, that's a regression the goldens will catch.
- **Hash strip vs. hash preserve**: `cdx_regression.rs` strips component-level hashes (`strip_component_hashes` at :185+) because they include deep-hash content from the host filesystem. SPDX 2.3 / SPDX 3 emit hashes in different shapes (`Package.checksums[]` for 2.3, `Package.verifiedUsing[]` for 3); the per-format normalizer must apply the same strip for the same reason but to the format-appropriate location.
- **Annotation-envelope content is itself JSON** (per `MikebomAnnotationCommentV1`). If the envelope's payload contains a workspace-relative path, the workspace-path placeholder substitution must apply *inside* the encoded JSON string. CDX puts this content in `properties[].value`; SPDX 2.3 in `annotations[].comment`; SPDX 3 in annotation graph elements.
- **Container-image fixture (used by `holistic_parity.rs` and `dual_format_perf::build_benchmark_fixture`)** is built fresh per test run from a synthetic tarball; its goldens, if any, would need the synthetic-image-hash masked. P1 scope is the 9 ecosystem fixtures only; the synthetic image is excluded from goldens to keep regen cost bounded.
- **Future-feature emitter additions**: this milestone's goldens are committed to the post-#38 emitter behavior. Any future PR that legitimately changes SPDX output (e.g., a milestone that adds a new `mikebom:*` annotation field) MUST regenerate goldens in the same PR with `MIKEBOM_UPDATE_SPDX_GOLDENS=1` / `MIKEBOM_UPDATE_SPDX3_GOLDENS=1` and document the diff in the PR description.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: After this feature ships, `mikebom-cli/tests/fixtures/golden/spdx-2.3/` MUST contain exactly 9 files named `{label}.spdx.json` for each `label` in `common::CASES`, byte-stable across macOS and Linux.
- **FR-002**: After this feature ships, `mikebom-cli/tests/fixtures/golden/spdx-3/` MUST contain exactly 9 files named `{label}.spdx3.json` for each `label` in `common::CASES`, byte-stable across macOS and Linux.
- **FR-003**: A new integration test `mikebom-cli/tests/spdx_regression.rs` MUST exist with one `#[test]` per ecosystem (9 total). Each test runs `mikebom sbom scan --format spdx-2.3-json` against its fixture under fake-HOME isolation, applies `common::normalize::normalize_spdx23_for_golden`, and asserts byte-equality against the committed golden. Test names match the CDX pattern (e.g., `apk_byte_identity`, `cargo_byte_identity`, ...).
- **FR-004**: A new integration test `mikebom-cli/tests/spdx3_regression.rs` MUST exist with the same shape as FR-003 but for SPDX 3 output.
- **FR-005**: The environment variables `MIKEBOM_UPDATE_SPDX_GOLDENS=1` and `MIKEBOM_UPDATE_SPDX3_GOLDENS=1` MUST trigger in-place regeneration of the corresponding golden files when the regression tests run, matching `MIKEBOM_UPDATE_CDX_GOLDENS=1`'s behavior. The regen path MUST write the *normalized* output (not the raw scan output) so the on-disk golden remains host-portable.
- **FR-006**: A new module `mikebom-cli/tests/common/normalize.rs` MUST export at least the following public items: `normalize_cdx_for_golden(raw: &str, workspace: &Path) -> String`, `normalize_spdx23_for_golden(raw: &str, workspace: &Path) -> String`, `normalize_spdx3_for_golden(raw: &str, workspace: &Path) -> String`, and `apply_fake_home_env(cmd: &mut std::process::Command, fake_home: &Path)`. The three normalizers share an `&str -> String` shape so callers do exactly one helper call per scan; each normalizer is responsible for the workspace-path string-replace + parsing + format-specific masking + re-serialization. The module-doc MUST explain the *why* of each masking step (cite the spec or the leak vector).
- **FR-007**: `cdx_regression.rs` MUST migrate to the shared helper from FR-006 *without changing any committed CDX golden*. Verified: a regen run with `MIKEBOM_UPDATE_CDX_GOLDENS=1` produces zero diff vs. the post-#38 tip.
- **FR-008**: Every test under `mikebom-cli/tests/*.rs` that today calls `Command::new(...).env("HOME", ...)` MUST migrate to `common::apply_fake_home_env`. Verified: `rg 'env\("HOME"' mikebom-cli/tests/ -g '!common/' -g '!dual_format_perf.rs'` returns 0 hits after the migration. **Documented exception**: `tests/dual_format_perf.rs` is included as a submodule of `tests/holistic_parity.rs` (`mod dual_format_perf;`) AND is its own test target; this dual context defeats both bare `mod common;` (resolves to wrong path under the parent) and `#[path = "common/mod.rs"] mod common;` (causes a "module loaded multiple times" error in the parent's compile because the parent already declares `mod common;`). The file therefore keeps a local `apply_fake_home_env` clone alongside the existing local `fn bin()` clone, with a doc comment naming this exception. Same precedent the milestone-016 audit already documented for `bin()`.
- **FR-009**: All existing test results MUST remain green. `./scripts/pre-pr.sh` MUST pass on both macOS and Linux with zero failures and zero new clippy warnings. Test-name and per-target counts may change because new test names are added; existing test names MUST NOT disappear.
- **FR-010**: The byte-identity goldens MUST tolerate the legitimate run-scoped fields by masking exactly: SPDX 2.3 — `creationInfo.created` AND every `annotations[].annotationDate` (document-level and per-package; surfaced empirically during T009 regen); SPDX 3 — every `CreationInfo.created` graph element AND, if document IRI is run-scoped in any future emitter path, the IRI itself. Additional run-scoped fields surfaced during T013 regen for SPDX 3 are added by the same pattern. The set of masked fields MUST be documented in `tests/common/normalize.rs` module-doc with rationale per field.
- **FR-011**: The new tests MUST run as part of the default `cargo +stable test --workspace` invocation — no `#[ignore]`, no opt-in feature flag. The macOS CI gate added in milestone 016 (PR #34) MUST exercise them on every PR.

### Key Entities *(include if feature involves data)*

- **Golden file**: A pinned reference SBOM document (CycloneDX JSON / SPDX 2.3 JSON / SPDX 3 JSON) under `mikebom-cli/tests/fixtures/golden/<format>/<ecosystem>.{cdx,spdx,spdx3}.json`. Carries the *normalized* content — workspace paths replaced with `<WORKSPACE>`, run-scoped UUIDs/timestamps replaced with documented placeholders, host-specific deep hashes stripped. Refreshed only via the documented `MIKEBOM_UPDATE_*_GOLDENS=1` env-var flow.
- **Normalize helper**: A pure function over a parsed JSON document (or raw string for CDX where serialization order matters) that applies the format-specific masking + workspace-path substitution. Lives in `tests/common/normalize.rs`. No I/O.
- **Fake-HOME env helper**: A function that mutates a `std::process::Command` to redirect every cache-pointing env var to a single tempdir. Lives in the same module as the normalizer because the two are always used together.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: After this feature ships, `cargo +stable test --workspace` runs the new `spdx_regression` and `spdx3_regression` tests on every invocation; both report `ok. 9 passed; 0 failed`. Verified by the test-result lines in CI logs on both Linux and macOS.
- **SC-002**: `./scripts/pre-pr.sh` exits 0 from a clean working tree on macOS and Linux with the new tests in place. Verified locally before PR + by both CI legs.
- **SC-003**: A deliberate one-byte change to any committed SPDX golden causes the corresponding ecosystem's test to fail with a diff that names both files. Verified by a one-time probe (modify a committed `npm.spdx.json` to change one byte; run the test; observe the failure; revert).
- **SC-004**: `rg 'env\("HOME"' mikebom-cli/tests/ -g '!common/' -g '!dual_format_perf.rs'` returns 0 hits after the migration. Verified by the grep itself. The `dual_format_perf.rs` exclusion is the documented exception per FR-008.
- **SC-005**: A maintainer reviewing a PR that changes SPDX output can verify the change's correctness in **under 5 minutes** via the per-ecosystem golden diff in the PR's `git diff` — without running the SBOM tooling locally — because the goldens are committed normalized JSON.
- **SC-006**: For at least 90 days after the feature ships, no PR regenerates SPDX goldens without an accompanying explanation of *why* the regen is correct (in the PR description). Verified by spot-checking merged-PR descriptions at the 30, 60, and 90-day marks.

## Clarifications

### Session 2026-04-25

- Q: Should the synthetic container-image fixture from `dual_format_perf::build_benchmark_fixture` get its own goldens? → A: No. P1 scope is the 9 ecosystem fixtures only. Synthetic images are built fresh per run with a fixture-time-dependent inner hash; pinning a golden adds normalization complexity (mask the synthetic-image SHA) without adding regression coverage that the per-ecosystem goldens don't already provide.
- Q: Should this milestone also normalize SPDX 3 document IRIs? → A: Not today. Per `spdx3_determinism.rs:11-13`, the IRI is SHA-256-derived from target-name + version + sorted PURL list — host-stable by construction. The normalizer leaves it alone; if a future emitter change introduces host-dependence, the goldens catch it as a real regression.

## Assumptions

- The post-#38 SPDX 2.3 and SPDX 3 emitter output is the *correct* baseline. If the goldens-regen pass surfaces emitter bugs (e.g., a field that should be sorted but isn't), those are fixed in this same milestone before pinning, not papered over by the goldens.
- The cross-host byte-identity discipline that works for CDX (per `cdx_regression.rs`) translates cleanly to SPDX 2.3 and SPDX 3 with format-specific field choices. If a structural difference (e.g., SPDX 3's `@graph` shape) requires a different normalization strategy than CDX's flat-document shape, the per-format normalizer in `tests/common/normalize.rs` is the right place for that divergence.
- The existing `spdx_determinism.rs` and `spdx3_determinism.rs` tests stay in place as a complementary signal: they catch run-vs-run variance even before the byte-identity tests catch cross-host variance. Removing them would lose that earlier-failure-detection benefit.
- The existing `spdx_schema_validation.rs` and `spdx3_schema_validation.rs` tests stay in place as orthogonal coverage: schema validation guards "valid SPDX"; byte-identity guards "the *exact* SPDX we expect." Both signals are needed; this milestone adds the second without removing the first.
- Workspace `Cargo.toml` does not gain new test-only crates. The existing `tempfile`, `serde_json`, and standard library are sufficient for the normalize helper.

## Out of Scope

- Tier 3 work (`.expect()` audit, `anyhow!("{}", e)` → `.context(...)` in `attestation/serializer.rs`, silent `.ok()` → `tracing::warn!`). Separate milestone.
- Tier 4 work (`pip.rs` / `npm.rs` / `binary/mod.rs` module splits). Separate milestone.
- Tier 5 work (`EcosystemReader` trait pilot). Separate milestone, design-first.
- Tier 6 work (`mikebom-ebpf` Cargo feature gate). Separate milestone, architectural.
- Goldens for the container-image fixture (per the clarification above).
- Removing `spdx_determinism.rs` / `spdx3_determinism.rs`. Both stay; byte-identity is additive.
- Refactoring `cdx_regression.rs`'s test names or per-test layout. The migration is "swap inline `normalize()` for the helper"; the test surface is unchanged.
- Adding goldens for new SBOM formats not yet emitted (e.g., CycloneDX 1.7, SPDX 3.1). When mikebom starts emitting them, this same pattern extends.
