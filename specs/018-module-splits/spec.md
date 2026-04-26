# Feature Specification: Module Splits — pip.rs, npm.rs, binary/mod.rs

**Feature Branch**: `018-module-splits`
**Created**: 2026-04-25
**Status**: Draft
**Input**: User audit follow-on; Tier 4 of the post-016 cleanup roadmap (after 017's byte-identity goldens + #41's error-handling tightening shipped)

## Background

Three files in `mikebom-cli/src/scan_fs/` carry > 1500 LOC each, each with multiple distinct responsibilities packed into one module. Per the post-016 audit:

```
1965  mikebom-cli/src/scan_fs/package_db/pip.rs
1858  mikebom-cli/src/scan_fs/binary/mod.rs
1616  mikebom-cli/src/scan_fs/package_db/npm.rs
```

(`maven.rs` at 5702 LOC was deferred from this milestone — its sub-concerns are deeply intertwined by Maven's build model itself; it warrants separate consideration.)

Each of the three target files mixes three or more separable concerns under one `pub fn read(...)` entry point:

- **pip.rs** — Poetry lockfile parser, Pipfile lockfile parser, `requirements.txt` parser, dist-info walker (PEP 376), project-root discovery, PURL builder, and a dedup-and-merge layer that picks "best" entries when multiple sources cover the same package.
- **npm.rs** — `package-lock.json` parser (lockfile v2/v3), `pnpm-lock.yaml` parser, `node_modules/` flat-walker, root `package.json` reader, integrity-string parser (SRI base64-decoded SHA-256/SHA-512), and an author-enrichment layer that opens installed `package.json` files to backfill missing author fields.
- **binary/mod.rs** — rootfs-kind detection (host-system-image-vs-ordinary-tree heuristics), filesystem walker that finds candidate binary files, single-file binary scanner (ELF / Mach-O / fat-Mach-O / PE), version-match-to-component conversion, file-level component synthesizer, and an OS-managed-directory predicate.

Three concrete pain points that derive from the size:

1. **Reading is slow.** A maintainer wanting to fix a Poetry lockfile parsing edge case has to scroll through 1500 lines of `requirements.txt` parsing + dist-info walking + PURL building before reaching the Poetry section. Rust's compiler diagnostics name the file but not the conceptual section, so a regression in Poetry surfaces as "pip.rs:823 unexpected token" with no hint about which parser shape is at fault.
2. **Code review burden is unfair.** A diff that touches one parser routinely shows up in PR review against a 2000-line file context, even when the change is isolated. Reviewers can't quickly see "this only affects Poetry" without manually narrowing.
3. **Onboarding cost.** New contributors looking to add a Pipfile-tooling fix have to read the whole file to discover the relevant 200-line section. Module boundaries that match the parser shape (one module per parsing format) make this navigation free.

The audit identified clean internal seams in all three files (verified during reconnaissance):

- pip.rs: `read_venv_dist_info` (lines 325-694), `read_poetry_lock` (697-833), `read_pipfile_lock` (834-925), `read_requirements_files` (927-end).
- npm.rs: `read_package_lock` (311-447), `read_pnpm_lock` (491-628), `read_node_modules` + `walk_node_modules` (630-787), enrichment helpers (789-863), `read_root_package_json` (866-end).
- binary/mod.rs: `discover_binaries` + `walk_dir` + `is_supported_binary` (861-939), `scan_binary` + `collect_string_region` + `scan_fat_macho` (641-859), `version_match_to_entry` + `make_file_level_component` + `note_package_to_entry` (583-639, 940-end).

This milestone splits each file along its natural seams without changing any production behavior. The 27 byte-identity goldens (9 CDX + 9 SPDX 2.3 + 9 SPDX 3) committed in #38 / #40 are the load-bearing regression test: any cross-host-stable byte change in scan output trips them.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — pip.rs split into pip/ submodule (Priority: P1) 🎯 MVP

As a maintainer fixing a Poetry-lockfile-specific bug, I want to navigate directly to a `pip/poetry.rs` submodule whose entire content is Poetry parsing, so that I don't have to skim 1500 lines of unrelated parsers and walkers to find the relevant code.

**Why this priority**: pip.rs is the largest of the three target files (1965 LOC) and has the cleanest seams — four parsers (dist-info, Poetry, Pipfile, requirements.txt) with minimal cross-references. It's the lowest-risk-and-highest-value split, so it ships first and validates the milestone's general approach.

**Independent Test**: After this story ships:

- `mikebom-cli/src/scan_fs/package_db/pip.rs` does not exist as a single file. The module is now a directory `mikebom-cli/src/scan_fs/package_db/pip/` containing at least: `mod.rs` (the `pub fn read` entry point and shared PURL helpers), `dist_info.rs` (venv PEP 376 walker), `poetry.rs` (poetry.lock parser), `pipfile.rs` (Pipfile.lock parser), `requirements_txt.rs` (requirements.txt parser).
- The public surface of the module is unchanged: `mikebom_cli::scan_fs::package_db::pip::read(...)` and `pip::collect_claimed_paths(...)` work the same as before. Internal-only functions stay `fn`/`pub(crate)` per existing conventions.
- The 27 byte-identity goldens still match — `MIKEBOM_UPDATE_*_GOLDENS=1` regen would produce zero `git diff`. Verified by running the existing `cdx_regression`, `spdx_regression`, `spdx3_regression` tests.

**Acceptance Scenarios**:

1. **Given** the post-#41 main, **When** the pip split lands, **Then** `./scripts/pre-pr.sh` passes clean — zero clippy warnings, all test target lines `ok. N passed; 0 failed` (matching the post-#41 baseline).
2. **Given** the split lands, **When** a maintainer runs `MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo test -p mikebom --test cdx_regression`, **Then** `git diff mikebom-cli/tests/fixtures/golden/cyclonedx/` is empty — the python pip golden bytes are unchanged.
3. **Given** the same split, **When** the same regen is run for `MIKEBOM_UPDATE_SPDX_GOLDENS=1` and `MIKEBOM_UPDATE_SPDX3_GOLDENS=1`, **Then** both produce zero diff against the post-#40 goldens.
4. **Given** any future PR that adds a Poetry-specific feature, **When** the maintainer searches for "poetry" within the codebase, **Then** results cluster in `pip/poetry.rs` and `tests/` — not scattered through a 1965-line file.

---

### User Story 2 — npm.rs split into npm/ submodule (Priority: P2)

As a maintainer chasing a `pnpm-lock.yaml` regression, I want a `npm/pnpm_lock.rs` submodule whose entire content is pnpm parsing, so that I don't have to disambiguate it from `package-lock.json` v2/v3 logic in the same file.

**Why this priority**: npm.rs has three independent parsers (package-lock, pnpm-lock, flat node_modules walk) plus enrichment. Same shape as pip's split but smaller (1616 LOC). Lower risk than pip because npm has no shared parser-output-merging dance — each format is read independently and then deduped at the end.

**Independent Test**: Same shape as US1 but for npm:

- `mikebom-cli/src/scan_fs/package_db/npm/` directory exists with at least: `mod.rs`, `package_lock.rs`, `pnpm_lock.rs`, `walk.rs` (the `node_modules/` flat-walker), and `enrich.rs` (the author-backfill layer).
- `npm::read(...)` public surface unchanged.
- All 27 byte-identity goldens unchanged (npm-relevant ones particularly: `golden/cyclonedx/npm.cdx.json`, `golden/spdx-2.3/npm.spdx.json`, `golden/spdx-3/npm.spdx3.json`).

**Acceptance Scenarios**:

1. **Given** the post-US1 state (pip already split), **When** the npm split lands, **Then** `./scripts/pre-pr.sh` passes clean.
2. **Given** the split lands, **When** the npm-targeted goldens are regen'd, **Then** zero diff.
3. **Given** the existing `tests/scan_npm.rs` integration test (if any), **When** it runs, **Then** every assertion passes unchanged — the split is purely organizational.

---

### User Story 3 — binary/mod.rs split into binary/ submodule (Priority: P3)

As a maintainer adding support for a new binary format (or fixing a Mach-O fat-binary edge case), I want `binary/scan.rs` and `binary/discover.rs` separated so that the scan-one-file logic is independent of the find-binaries-in-a-tree logic.

**Why this priority**: binary/mod.rs is mid-sized (1858 LOC) and slightly more entangled than pip/npm — `read()` orchestrates discover → scan → entry-conversion in one tight loop, with shared state (the `RootfsKind` enum, OS-managed-directory predicates). Splitting requires a tighter interface design between the new submodules. Lowest priority of the three for that reason.

**Independent Test**: Same shape:

- `mikebom-cli/src/scan_fs/binary/` directory gains: `discover.rs` (filesystem walker — `discover_binaries`, `walk_dir`, `is_supported_binary`), `scan.rs` (single-file binary scan — `scan_binary`, `scan_fat_macho`, `collect_string_region`), `entry.rs` (PackageDbEntry conversion — `make_file_level_component`, `note_package_to_entry`, `version_match_to_entry`). The existing `linkage.rs`, `elf.rs`, `go_binary.rs`, `python_collapse.rs` siblings stay where they are.
- `binary::read(...)` public surface unchanged.
- 27 byte-identity goldens unchanged (binary-relevant ones via `tests/scan_binary.rs`).

**Acceptance Scenarios**:

1. **Given** the post-US2 state, **When** the binary split lands, **Then** `./scripts/pre-pr.sh` passes clean.
2. **Given** the split, **When** the goldens are regen'd, **Then** zero diff.
3. **Given** `tests/scan_binary.rs` (1337 LOC) runs, **Then** every assertion passes — the integration test exercises every binary-format code path.

---

### Edge Cases

- **Inline `#[cfg(test)]` modules** in each target file — pip.rs, npm.rs, and binary/mod.rs all carry inline tests at the bottom of the file. The inline tests reference the file's private functions, so they need to either move to the appropriate submodule (when they test that submodule's content) or stay near the orchestrator (when they test cross-cutting behavior). The split will preserve every existing test name; tests that move don't change their contents.
- **Cross-submodule helpers** — pip.rs's `merge_without_override`, `should_skip_python_descent`, and `has_python_project_marker` are used by multiple parsers. These stay at `pip/mod.rs` (or `pip/walker.rs`) and are imported by parser submodules.
- **Type re-exports** — types defined in pip.rs that are public to the rest of mikebom-cli (e.g., `PipDistInfoEntry` at line 426 if exposed) need to be re-exported from `pip/mod.rs` so callers don't break. Same for npm + binary.
- **Parsers that share state** — pip.rs's parsers feed into a unified `merge_without_override` after each one runs. The split must preserve the calling order and merge semantics; the orchestrator (`pip/mod.rs::read`) keeps the unified logic.
- **Existing `clippy::*` allows** — any `#![allow(clippy::SOMETHING)]` at the file head moves to the new module containing the offending code, OR is added to the new orchestrator if it covers cross-cutting concerns. Verified by `./scripts/pre-pr.sh` passing under `-D warnings`.
- **`maven.rs` — explicitly out of scope** (5702 LOC). Its sub-concerns (pom.xml inheritance + property interpolation, shade-plugin detection, repo cache traversal, transitive dependency resolution) are deeply coupled by Maven's build model, not by accident of file growth. Splitting it would require breaking up tightly-coupled state machines, not extracting parallel-shaped parsers. Deferred to future consideration.
- **`scan_fs/mod.rs`** — top-level scan dispatcher (1038 LOC) — uses `crate::scan_fs::package_db::pip::read` etc. by path. After the split, the path is unchanged because `pip/` is a directory module that re-exports `pub fn read` from `pip/mod.rs`.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: After this milestone ships, `mikebom-cli/src/scan_fs/package_db/pip.rs` MUST NOT exist as a single file. The module is replaced by a directory `mikebom-cli/src/scan_fs/package_db/pip/` containing at minimum `mod.rs` plus per-format submodules (`dist_info.rs`, `poetry.rs`, `pipfile.rs`, `requirements_txt.rs`). Each submodule's content is the corresponding pre-split section of the original file (verbatim, modulo `pub`/`pub(crate)` visibility adjustments needed for cross-submodule access).
- **FR-002**: After this milestone ships, `mikebom-cli/src/scan_fs/package_db/npm.rs` MUST NOT exist as a single file. The module is replaced by a directory `mikebom-cli/src/scan_fs/package_db/npm/` containing at minimum `mod.rs` plus per-format submodules (`package_lock.rs`, `pnpm_lock.rs`, `walk.rs`, `enrich.rs`). Same content-preservation rule as FR-001.
- **FR-003**: After this milestone ships, `mikebom-cli/src/scan_fs/binary/mod.rs` MUST be reduced to ≤ 800 LOC by extracting at minimum the file-discovery walker (`discover.rs`), the single-file scanner (`scan.rs`), and the entry-conversion helpers (`entry.rs`). The orchestrator `read()` function stays in `mod.rs`.
- **FR-004**: The public surface of each split module MUST be unchanged. Specifically: `pub fn read(...)` for each of `pip`, `npm`, `binary` must keep its exact signature; any `pub` types or `pub fn` items defined in the pre-split file must be re-exported from the new module's `mod.rs` so external callers (`scan_fs/mod.rs`, integration tests, etc.) don't break.
- **FR-005**: Zero behavioral changes. The 27 committed byte-identity goldens (`tests/fixtures/golden/cyclonedx/`, `tests/fixtures/golden/spdx-2.3/`, `tests/fixtures/golden/spdx-3/`) MUST be byte-identical after each split. Verified by running `MIKEBOM_UPDATE_*_GOLDENS=1` regen and observing zero `git diff` against the post-#41 main.
- **FR-006**: The full test suite MUST remain green. `./scripts/pre-pr.sh` exit code 0 from a clean tree on macOS and Linux. Test-name list MUST NOT lose any entries (per the FR-009 pattern from milestone 017); test counts may go up only if a test that lived inside a file's inline `#[cfg(test)]` module gets renamed in the move (rare; flagged in PR description if it happens).
- **FR-007**: Inline `#[cfg(test)]` test modules MUST be preserved. Tests that exercise a specific submodule's logic (e.g., a test for `parse_requirements_line`) move into the corresponding submodule's `#[cfg(test)] mod tests` block. Tests that exercise the orchestrator-level read() flow stay at `mod.rs`. Test names are preserved verbatim.
- **FR-008**: No new runtime crates. The split is purely organizational — no `Cargo.toml` changes for `mikebom-cli` (other than possibly adjusting `cargo machete` exclusions if any module name shifts, which is unlikely). Per Constitution Principle VI.
- **FR-009**: Each user story (US1, US2, US3) lands as a separate logical commit on the milestone branch. The PR may bundle them, but each commit's diff is self-contained — `./scripts/pre-pr.sh` passes after each commit, so reviewers can `git diff <commit>~..<commit>` to see one split at a time.
- **FR-010**: The line-count target is met: post-split, no source file under `mikebom-cli/src/scan_fs/package_db/{pip,npm}/` or `mikebom-cli/src/scan_fs/binary/` exceeds 800 LOC, with the exception of `pip/requirements_txt.rs` (the requirements parser is genuinely large at ~1040 LOC of historical complexity; ≤ 1100 LOC is acceptable for that file alone). The `scan_fs/binary/mod.rs` orchestrator MUST be ≤ 800 LOC.

### Key Entities *(include if feature involves data)*

This milestone has no new data — it's source-tree organization. Existing types (`PackageDbEntry`, `Purl`, `RootfsKind`, etc.) keep their definitions in their current locations; what moves is the *parsing code* that produces them.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: After this milestone ships, `wc -l mikebom-cli/src/scan_fs/binary/mod.rs` reports ≤ 800. `wc -l mikebom-cli/src/scan_fs/package_db/pip/*.rs` reports no file > 1100 (with `requirements_txt.rs` allowed up to 1100; all other pip submodules ≤ 800). `wc -l mikebom-cli/src/scan_fs/package_db/npm/*.rs` reports no file > 800.
- **SC-002**: `./scripts/pre-pr.sh` exits 0 on macOS and Linux. Verified locally + by both CI legs on the open PR.
- **SC-003**: The 27 byte-identity goldens are unchanged. Verified by running `MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo test -p mikebom --test cdx_regression`, `MIKEBOM_UPDATE_SPDX_GOLDENS=1 cargo test -p mikebom --test spdx_regression`, `MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo test -p mikebom --test spdx3_regression`, then `git diff mikebom-cli/tests/fixtures/golden/` returning empty.
- **SC-004**: Test-name parity per FR-006. After the milestone, `grep -E '^test [a-z_:]+ \.\.\. ok' < pre-PR-baseline > post-baseline` shows zero removed test names. Added test names are allowed only if a test was renamed during the move (must be flagged in PR description).
- **SC-005**: A maintainer chasing a Poetry-specific bug post-merge can find the relevant code in **under 30 seconds** via `find mikebom-cli/src -name 'poetry.rs'` or by descending into `mikebom-cli/src/scan_fs/package_db/pip/`. Verified by the maintainer's own next encounter with such a bug; no formal test.
- **SC-006**: For at least 30 days post-merge, no PR re-bundles the split parsers back into a single file. (Anti-regression durability check.) Verified by spot-checking merged-PR diffs at the 30-day mark.

## Clarifications

### Session 2026-04-25

- Q: Should `maven.rs` (5702 LOC) be included in this milestone? → A: No. Maven's sub-concerns (pom.xml inheritance, property interpolation, shade-plugin, repo cache traversal, transitive resolution) are coupled by Maven's build model itself, not by accidental file growth. Splitting maven.rs would require breaking up tightly-coupled state machines, not extracting parallel-shaped parsers as in pip/npm. Deferred to future consideration; if attempted, it warrants its own design-first milestone.
- Q: Should the integration test files (`tests/scan_binary.rs` at 1337 LOC, `tests/scan_go.rs` at 743, `tests/scan_maven.rs` at 706) also be split? → A: No. Integration tests are organized by feature/scenario, not by parser shape. Their size reflects test-scenario coverage; splitting wouldn't improve readability the same way. Out of scope for this milestone.
- Q: Should `pip.rs`'s requirements_txt parser be further sub-split (e.g., `requirements_txt/parser.rs` + `requirements_txt/types.rs`)? → A: Not in this milestone. Get the top-level pip/ directory shipped first; sub-splitting `requirements_txt.rs` from ~1040 LOC down further can be a follow-up if a future contributor finds it worthwhile. The 1100-LOC ceiling acknowledges this is a known-large file.

## Assumptions

- The byte-identity goldens (#38 + #40) are the load-bearing regression test for "no behavior change." If the goldens trip during the split, the split is wrong and must be reconciled before commit. (T013b-equivalent emitter-bug discovery is unlikely here because we're moving code, not changing what it produces.)
- `scan_fs/mod.rs` (the dispatcher) imports each ecosystem reader by path: `crate::scan_fs::package_db::pip::read`. After splitting `pip.rs` → `pip/mod.rs`, this path resolves identically. No call-site changes needed.
- Inline `#[cfg(test)]` modules can be safely moved into per-submodule files. Each test's body references the submodule's private items; relocating both the production code AND its inline test together preserves access without `pub`-leaking the items.
- `clippy::*` configuration at the file head is portable: any `#![allow(...)]` directive moves with the relevant code. If a directive was load-bearing only in combination with code that's now in a different submodule, the post-split `pre-pr.sh` will surface that and we adjust.
- Workspace `Cargo.toml` doesn't need changes. The splits are discovered automatically by the Rust module system via `pip/mod.rs` declaring `mod poetry;` etc.

## Out of Scope

- `maven.rs` (5702 LOC) split. Per the clarification above.
- Splitting integration test files (`tests/scan_*.rs`). Per the clarification above.
- Sub-splitting any individual submodule below the FR-010 thresholds. (Future polish if it surfaces a real readability win.)
- Refactoring the parser logic itself. The split is purely "move code into a directory"; behavior unchanged.
- Renaming the `pub fn read()` entry points. Existing callers depend on the current names; renaming is a separate concern.
- Adding new tests. The existing 27 byte-identity goldens + every existing inline `#[cfg(test)]` test + every existing integration test under `tests/` are the regression surface; we run them, we don't add to them.
- Changing visibility of pre-existing `pub` items beyond what's mechanically required. If `PipDistInfoEntry` was `pub` before, it stays `pub` after via re-export from `pip/mod.rs`.
- Touching `cdx_regression.rs`, `spdx_regression.rs`, or `spdx3_regression.rs` test files in any way. They run as-is; the goldens drive the verification.
