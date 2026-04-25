# Feature Specification: Address the 192 Deferred Clippy Warnings

**Feature Branch**: `016-remaining-clippy-cleanup`
**Created**: 2026-04-25
**Status**: Draft
**Input**: User description: "I want to now look at the 192 deferred"

## Background

PR #33 (commit `2d40bb5`, milestone 015) ran `cargo +stable clippy --workspace --all-targets --fix` and dropped clippy warnings from 310 → 192 (-118). The 192 that remain were explicitly deferred because they fall outside the "mechanical autofix" boundary:

- **~37 doc-list lazy-continuation warnings** — clippy flags doc comments that mix bullet sub-items with prose continuation; rustfix can't auto-apply the suggestion because the indentation choice depends on intent (is this a sub-bullet, a paragraph, or a continuation?).
- **~150 dead-code warnings** — `dead_code` warnings on functions, structs, fields, and enum variants. Many are *platform-conditional*: `#[cfg(target_os = "linux")]` blocks evaluated as dead on macOS but live on Linux. Some are *genuinely orphaned* — leftover scaffolding from prior milestones whose callers were removed.

Those warnings clog clippy output on every PR, making it hard to spot *new* warnings introduced by a change. Eliminating them — by either annotating, restructuring, or removing — restores clippy as a useful signal.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Dead-code triage and purge (Priority: P1) 🎯 MVP

As a maintainer reviewing a PR, I want clippy output to contain zero spurious dead-code warnings so that any new dead-code warning that appears is signal, not noise.

**Why this priority**: Dead-code warnings are the bulk of the noise (~150 of 192). Cleaning them is the largest single contributor to a quiet clippy. They also force a real decision per item: is this code intentional scaffolding (annotate), platform-conditional (cfg-gate), or orphaned (remove)?

**Independent Test**: After this story ships, `cargo +stable clippy --workspace --all-targets 2>&1 | grep -c "never used\|never read\|never constructed"` returns 0 on both macOS and Linux. The pre-PR gate (`cargo +stable clippy --workspace --all-targets`) emits ≤55 warnings (only the doc-list set + the 3 `field_reassign_with_default` cases), versus the current 192.

**Acceptance Scenarios**:

1. **Given** the current main with 192 clippy warnings, **When** the dead-code triage and resolution lands, **Then** all `dead_code` warnings disappear from `cargo clippy` output on the maintainer's macOS development machine and on Linux CI.
2. **Given** a future PR introduces a genuinely orphaned function (e.g., a function whose only caller was just deleted), **When** the contributor runs `cargo clippy`, **Then** the warning surfaces clearly because no other dead-code warnings drown it out.
3. **Given** a code path that exists only on Linux (`#[cfg(target_os = "linux")]`), **When** `cargo clippy` runs on macOS, **Then** the platform-conditional code does not produce a dead-code warning (it's correctly gated).

---

### User Story 2 — Doc-list prose restructuring (Priority: P2)

As a contributor reading mikebom's source, I want doc comments to render correctly in `cargo doc` and `rustdoc` output so that the architectural commentary in tests and modules is faithfully reproduced in generated documentation.

**Why this priority**: Doc-list warnings (~37) are cosmetic — they don't change runtime behavior. But they indicate doc comments where rustdoc's output may not match the author's intent (sub-bullets misrendered as paragraph continuations, or vice versa). Fixing them improves generated docs and is the second-largest warning category.

**Independent Test**: After this story ships, `cargo +stable clippy --workspace --all-targets 2>&1 | grep -c "doc list item"` returns 0. `cargo doc --workspace --no-deps` produces output where the affected doc comments render with the intended structure (sub-bullets show as nested lists, prose paragraphs show as paragraphs).

**Acceptance Scenarios**:

1. **Given** `mikebom-cli/tests/cdx_regression.rs` has 10 doc-list warnings clustered in one long doc comment, **When** the doc comment is restructured (blank-line paragraph breaks added or sub-bullets reformatted), **Then** clippy emits zero warnings for that file and `cargo doc` output reads naturally.
2. **Given** `mikebom-cli/src/scan_fs/mod.rs` has 8 doc-list warnings across module-level comments, **When** the comments are restructured, **Then** clippy emits zero warnings for that file.

---

### User Story 3 — CI gate so warnings stay at zero (Priority: P3)

As a project maintainer, I want CI to fail when a PR introduces new clippy warnings so that the carefully-cleaned baseline doesn't degrade over time.

**Why this priority**: This is the durability story. Without an automated guard, the warning count will silently regrow as new code lands. A CI gate makes "no new warnings" a contract rather than a hope.

**Independent Test**: After this story ships, a deliberately-warning-introducing PR (e.g., add an unused `pub fn foo() {}`) fails the pre-PR gate locally and on CI with a clear "new clippy warnings detected" message. A clean PR (no new warnings) passes.

**Acceptance Scenarios**:

1. **Given** the CI pre-PR gate runs `cargo +stable clippy --workspace --all-targets` with `--deny warnings` (or equivalent), **When** a contributor pushes a branch with a clean tree, **Then** CI passes.
2. **Given** the same CI gate, **When** a contributor pushes a branch that adds a new `unused_imports` or `dead_code` warning, **Then** CI fails with a message naming the offending file:line.
3. **Given** a legitimate platform-conditional path that's "dead" on macOS but live on Linux, **When** CI runs both macOS and Linux jobs, **Then** both pass because the path is correctly gated with `#[cfg(...)]`.

---

### Edge Cases

- **Linux-only code**: many `dead_code` warnings come from `#[cfg(target_os = "linux")]` items (eBPF probes, `aya` integration, kernel-side trace types). Fixing these requires gating *every reference* to the type, not just the type itself, so the unused-on-macOS warning chain unwinds cleanly. Some may need `#[allow(dead_code)]` if cfg-gating cascades too widely.
- **Test-only code**: items used only inside `#[cfg(test)]` modules but defined outside them. These produce dead-code warnings in non-test builds. Fix by moving the item into a `#[cfg(test)]` block, or annotating with `#[cfg_attr(not(test), allow(dead_code))]`.
- **Public API surface that's bin-only**: items declared `pub` in modules under `mikebom-cli/src/` that are only used by the binary's main module. The library crate (`pub mod parity;` in `lib.rs`) doesn't reference them, so they may be flagged dead in some build configurations.
- **Future-feature scaffolding**: items that exist as deliberate prep for an upcoming milestone (e.g., `attestation/witness_builder.rs` functions wired into trace flows that aren't fully shipped). These need an explicit `#[allow(dead_code)]` with a comment explaining the planned consumer.
- **Per-item triage decisions disagreed on by reviewers**: e.g., a function might look orphaned but the maintainer knows it's load-bearing for a Q3 feature. Disagreements need per-item commit messages or PR comments documenting the call.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: After this feature ships, running `cargo +stable clippy --workspace --all-targets` from a clean working tree on either macOS or Linux MUST emit zero `dead_code`-class warnings (`function … is never used`, `field … is never read`, `struct … is never constructed`, `variants … are never constructed`, `multiple associated items are never used`).
- **FR-002**: After this feature ships, running `cargo +stable clippy --workspace --all-targets` MUST emit zero `clippy::doc_lazy_continuation`-class warnings (`doc list item without indentation`, `doc list item overindented`).
- **FR-003**: For each item triaged in FR-001, the resolution MUST fall into exactly one of three categories: (a) **removed** (file/struct/function/field deleted from the tree; verified by `grep -rn` showing zero callers anywhere in the post-cleanup tree), (b) **gated** (annotated with `#[cfg(...)]` or `#[cfg_attr(..., allow(dead_code))]` to scope visibility to the platforms or build configurations where the item is actually used), or (c) **annotated** (annotated with `#[allow(dead_code)]` accompanied by a one-line comment that MUST cite a *concrete* planned consumer — a milestone identifier (e.g., `milestone-018`), a spec ID (e.g., `specs/017-...`), an issue/PR reference, or a named function/module that does not yet exist but whose addition is committed to the roadmap. Bare `#[allow(dead_code)]` without a concrete planned-consumer reference is NOT acceptable; such items MUST default to category (a) `removed` instead. Vague rationale like "future use" or "may need this later" does not qualify).
- **FR-004**: Behavioral changes MUST NOT occur. The full workspace test suite (`cargo +stable test --workspace`) MUST report the same `N passed; 0 failed` totals before and after the feature ships, with the same set of test names.
- **FR-005**: Per-item resolution decisions MUST be recorded in the PR description (or commit message) at the granularity of "removed N items, gated M items, annotated K items, with one-line rationale per category." A maintainer reviewing the PR MUST be able to verify each decision without reading every diff hunk.
- **FR-006**: After this feature ships, the project MUST have an automated pre-PR / CI gate that fails when a PR introduces any new clippy warning (any class — not just dead-code or doc-list). Implementation may be `cargo clippy --workspace --all-targets --deny warnings`, a baseline-diff tool, or equivalent.
- **FR-007**: The CI gate from FR-006 MUST run on both macOS and Linux configurations so that platform-conditional warnings are caught on either side. CI today runs only `ubuntu-latest` (`.github/workflows/ci.yml::lint-and-test`); this feature MUST add a `macos-latest` job that runs the same clippy gate (`cargo +stable clippy --workspace --all-targets --deny warnings`) plus the workspace test suite. The macOS job MAY skip the eBPF build steps (eBPF is Linux-only by definition) and the bpf-linker installation. The Linux job remains the canonical reference for full-stack tests.
- **FR-008**: The 3 remaining `clippy::field_reassign_with_default` warnings MUST be either (a) refactored to struct-init syntax, or (b) explicitly justified with `#[allow(clippy::field_reassign_with_default)]` plus a comment explaining why the conditional-set pattern is preferred. Letting them remain unaddressed is not acceptable.

### Key Entities *(include if feature involves data)*

- **Dead-code item**: a Rust item (function, struct, field, enum variant) flagged by clippy's `dead_code` lint. Carries a file path, line, item kind, and a triage classification (removed / gated / annotated).
- **Doc-list warning site**: a doc comment cluster flagged by `clippy::doc_lazy_continuation`. Carries a file path, line range, and a chosen restructuring strategy (blank-line break / sub-bullet reformat / explicit `#[allow]`).
- **Triage decision log**: a per-PR record listing every triaged item and its category. Lives in the PR description and survives in git history via the merge commit message.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `cargo +stable clippy --workspace --all-targets` emits **zero warnings** on the maintainer's macOS development machine after the feature ships (down from 192 today). Verified by `grep -c '^warning:'` returning `0`.
- **SC-002**: `cargo +stable clippy --workspace --all-targets` emits **zero warnings** on the Linux CI runner after the feature ships. Verified by the CI log.
- **SC-003**: A PR that deliberately introduces a new clippy warning (e.g., an `unused_imports` line) fails CI within the same pre-PR gate that already runs `cargo clippy`. Verified by a one-time deliberate test PR before the feature is declared done; the test PR is then closed without merging.
- **SC-004**: `cargo +stable test --workspace` continues to report the exact same `N passed; 0 failed` totals as before the feature (today's baseline: 1385 passed; 0 failed). Verified by comparing test-result lines pre- and post-merge.
- **SC-005**: A maintainer reviewing the PR can verify the dead-code triage decisions in **under 15 minutes**, without needing to re-read every changed file, because the PR description provides a per-category summary (e.g., "Removed 12 truly-orphaned helpers under `enrich/` and `resolve/`; gated 80 Linux-only `trace/*` items behind `#[cfg(target_os = \"linux\")]`; annotated 8 future-feature scaffolding items with `#[allow(dead_code)]` + planned-consumer comment").
- **SC-006**: For at least 90 days after the feature ships, no new PR introduces a clippy warning that survives the CI gate. Verified by spot-checking the workflow logs of merged PRs at the 30, 60, and 90-day marks.

## Clarifications

### Session 2026-04-25

- Q: CI today runs only on Linux (`ubuntu-latest`). The warning-prevention gate (FR-007) needs to catch macOS-only platform-conditional regressions. How? → A: Add a `macos-latest` CI job running the same clippy gate. Most thorough; matches the maintainer's dev environment. Adds ~5-10 min to CI runtime and GitHub Actions cost.

## Assumptions

- The maintainer is willing to make per-item triage calls during implementation and is the canonical source of truth for "is this dead or scaffolding for a future feature."
- The current 192 warning count is a reasonable proxy for completeness; if a few more warnings appear in the meantime (e.g., from a new PR landing while this is in flight), the implementer rebaselines on top.
- The Rust toolchain version pinned by the workspace stays compatible with the clippy lints referenced here (`dead_code`, `doc_lazy_continuation`, `field_reassign_with_default`). A toolchain bump that introduces new lint categories would require a follow-up — out of scope for this feature.
- Existing `#[allow(dead_code)]` annotations in the tree (a small handful, e.g., `mikebom-cli/src/generate/mod.rs:73`, `mikebom-cli/src/generate/spdx/packages.rs:68`) are reviewed during implementation; ones whose justification has expired (the planned consumer never landed) get re-evaluated.
- The 3 `field_reassign_with_default` warnings (in `scan_fs/binary/elf.rs:85` and `scan_fs/package_db/pip.rs:1479, 1490`) are intentional — those structs use a "default-then-conditionally-set" pattern that's hard to refactor to struct-init syntax. The expected resolution is to add `#[allow(clippy::field_reassign_with_default)]` with a one-line comment, but if a clean struct-init refactor is feasible, that's preferred.

## Out of Scope

- Refactoring large modules even where the dead-code triage might suggest it (e.g., consolidating `attestation/witness_builder.rs` if many of its functions turn out to be orphaned). This feature stops at "remove / gate / annotate"; structural refactors are separate work.
- Adding new tests beyond what's needed to keep `cargo test --workspace` green. The CI gate is itself the new test for FR-006.
- Documenting historical context for every dead item ("why was this written?"). The triage is forward-looking — what to do *now* — not archeological.
- The duplicate `EcosystemCase` struct + `fn bin()` test-helper deduplication identified in milestone-015's plan. That's a separate, unrelated cleanup tracked elsewhere.
- The inefficiency hot spots in `trace/aggregator.rs` (`serde_json::to_string` in loops, `Vec::clone` then sort/dedup) — those are performance work, not clippy-warning work.
