# Feature Specification: Close Last Polyglot Bake-Off Findings

**Feature Branch**: `008-polyglot-final-cleanup`
**Created**: 2026-04-23
**Status**: Draft
**Input**: User description: "6 findings remain after feature 007 merged: 4 Go test-scope FPs (go-spew, go-difflib, testify, yaml.v3), 1 Maven project-self (sbom-fixture), 1 real version disagreement (commons-compress 1.21 vs 1.23.0). Close what mikebom can close."

## Context: Why this feature is needed

Feature 007 shipped three filters targeting polyglot-builder-image FPs:

- US1 (PR #8) — Fedora sidecar POM reading: closed 12 FPs as expected.
- US2 (PR #10) — Go test-scope intersection filter via production-imports ∩ BuildInfo: **designed to close the 4 Go test-scope FPs, but the post-merge bake-off shows they still appear.**
- US3 (PR #10) — Go main-module exclusion: closed the 1 project-self FP.
- US4 (PR #11) — Maven executable-JAR self-reference via `Main-Class:` heuristic: **designed to close `sbom-fixture@1.0.0`, but the post-merge bake-off shows it still appears.**

Two distinct problems remain:

1. Two already-shipped filters (US2, US4) did not land on the actual polyglot image even though their unit and integration tests pass on synthetic fixtures. This is the SAME failure pattern as the M4 → G3 post-mortem: the feature closes the lab reproduction but not the real-world scenario.
2. `commons-compress` 1.21 vs 1.23.0 is a genuine data disagreement between the `.m2/repository/` cache and the Fedora sidecar POM. Not a mikebom bug; a real question about which version is "the shipped one."

This feature is **investigation-first**: before proposing any new code change, mikebom must understand why US2 and US4 didn't close their targeted findings on polyglot-builder-image. The fix strategy is chosen based on what the investigation finds, not guessed in advance.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Root-cause the US2 and US4 landing gap (Priority: P1)

A maintainer running the polyglot-builder-image bake-off sees that four Go test-scope components (`go-spew`, `go-difflib`, `testify`, `yaml.v3`) and one Maven self-reference (`com.example/sbom-fixture@1.0.0`) still appear in the mikebom output, even though feature 007 shipped filters specifically targeting these cases and the filters passed synthetic-fixture tests. Before changing any code, the maintainer needs a written explanation of why each filter didn't fire on the polyglot image, supported by direct inspection of the actual mikebom output against the actual polyglot rootfs.

After this story lands, there is a committed investigation document in this feature's directory answering these questions for each of the five FPs:

- Which filter was supposed to close it (G3, G4, G5, or the Main-Class heuristic)?
- Why didn't the filter fire? Concrete evidence from the scan output or a reproduction.
- What's the minimal code change that would make the filter fire, assuming one exists.
- If no static signal can close it within feature 007's constraints (FR-007: no Go toolchain invocation), flag it as a known limitation — that FP moves to Story 4's documentation scope and is also cross-referenced to FU-001 (opt-in toolchain mode, future work) so it's not lost.

**Why this priority**: The G3 post-mortem already showed what happens when mikebom ships a feature that passes unit tests but doesn't close the targeted real-world case. The post-mortem produced a rule: "before claiming a fix reduces FPs, read an actual FP coord from the polyglot mikebom output and measure the FP count on a reproduction that mirrors the polyglot scenario, not just unit tests." US2 and US4 apparently skipped step 2. The investigation must happen before any additional code ships.

**Independent Test**: Run the current (post-007) mikebom binary against the polyglot-builder-image extracted rootfs. Verify by `jq` that the five target FP PURLs appear in `components[]`. Then, for each one, trace through the mikebom code path that should have suppressed it; record the specific reason it didn't. The deliverable is a markdown document; no new Rust code is required to validate this story.

**Acceptance Scenarios**:

1. **Given** the polyglot-builder-image rootfs extracted on disk **and** the current mikebom binary from `main`, **When** a maintainer runs `mikebom sbom scan` and greps for `pkg:golang/github.com/stretchr/testify` in the output, **Then** the investigation document explains why G3+G4 let it through: either BuildInfo includes it AND production-imports includes it, OR production-imports is empty (G4 no-ops) and BuildInfo includes it, OR some third reason.
2. **Given** the same rootfs, **When** the maintainer greps for `pkg:maven/com.example/sbom-fixture@1.0.0`, **Then** the investigation document explains why none of US4's gating branches fired: either the JAR is claimed (`co_owned_by.is_some()`), or the JAR has no `Main-Class:` manifest entry, or the primary-coord detection failed upstream in `walk_jar_maven_meta`.
3. **Given** the investigation document, **When** a reviewer reads it, **Then** each of the five FPs has a named root cause supported by a concrete artifact (a `jq` output snippet, a `tracing::debug!` log line, a fixture that reproduces the behavior, or a code-path walkthrough).

---

### User Story 2 - Close the Go test-scope FPs on the polyglot image (Priority: P2)

After Story 1 identifies the specific gap(s) that prevented G3+G4 from closing the four Go test-scope FPs, implement the minimal code change that closes them against the actual polyglot image. The shape of the fix is determined by what Story 1 finds:

- If the gap is that the polyglot source tree has no `.go` files on the rootfs (so G4 production-imports is empty and no-ops) — fix by falling back to go.sum vs `go list`-equivalent analysis, either by (a) parsing test-scope hints from go.mod require comments, (b) reading `go.sum` transitive chains to detect test-only subtrees, or (c) accepting a known limitation.
- If the gap is that the source tree IS present but my walker fails to find it (depth limit, `should_skip_descent` too aggressive, etc.) — fix by adjusting the walker.
- If the gap is that BuildInfo somehow includes testify (because the polyglot binary is built with a test-harness flag that links test deps) — document as known limitation, since no static filter can distinguish "test dep linked in for unusual reasons" from "production dep."
- If the gap is something entirely different — the Story 1 document says what.

mikebom's default scan mode MUST remain purely static: no runtime Go toolchain invocation at scan time (feature 007's FR-007 continues in force). All filtering is derived from signals already on disk — go.mod, go.sum, Go binary BuildInfo, `.go` source files — or documented as a known limitation when no static signal can close a specific FP. An opt-in toolchain-assisted mode is recorded as future work (see "Out of Scope / Follow-up Work") but is explicitly NOT built in this feature.

**Why this priority**: Closing the 4 Go FPs is worth 4 points on the bake-off scoreboard. Story 1's investigation determines what's achievable statically. What's closable statically gets shipped in Story 2; what isn't gets documented as a known limitation under Story 4. No FP is left unaccounted for.

**Independent Test**: After the fix ships, run the post-fix binary against the polyglot image and confirm the FPs Story 1 identified as statically-closable no longer appear. Ecosystem scoreboards for cargo / gem / pypi / rpm / binary MUST remain unchanged. Existing US2 / US3 integration tests MUST remain passing.

**Acceptance Scenarios**:

1. **Given** Story 1 has identified a statically-closable root cause, **When** the minimal fix ships, **Then** the corresponding Go test-scope PURLs are absent from `components[]` on the polyglot bake-off run.
2. **Given** the fix, **When** a different scan targets a healthy Go source tree with both production and test dependencies, **Then** production deps are still emitted and test-only deps are still suppressed (no regression of US2's intended behavior on the synthetic case).
3. **Given** Story 1 identified a Go FP that no static signal can close, **When** Story 2 is shipped, **Then** that specific FP is documented as a known limitation under Story 4 — not silently papered over, not silently fixed by shelling out to `go list`.

---

### User Story 3 - Close the Maven sbom-fixture self-reference on the polyglot image (Priority: P3)

After Story 1 identifies why US4's Main-Class heuristic didn't fire for `com.example/sbom-fixture@1.0.0`, implement the minimal code change that suppresses this coord from `components[]` on the actual polyglot image, preferably by routing it to `metadata.component` (CycloneDX 1.6 convention).

Candidate root causes Story 1 will confirm or rule out:

- The JAR is claimed by an OS package-db reader (`co_owned_by.is_some()`), which disables both the classic fat-jar heuristic and the new Main-Class heuristic.
- The JAR doesn't have `Main-Class:` in its manifest (maybe it's a fat-jar but launched via `java -cp` rather than `java -jar`).
- The JAR's primary coord isn't identified as `is_primary` by `walk_jar_maven_meta` (stem-matching failed, or the JAR filename doesn't match `<artifactId>-<version>.jar`).
- Something in the M3 / US4 heuristic's order-of-operations makes the suppression fire too early or too late.

**Why this priority**: 1 FP. Lowest priority. The GT harness has a hardcoded workaround, so this is cosmetic on the bake-off side — but fixing it on mikebom's side produces a spec-compliant SBOM that doesn't need downstream consumers to special-case the scan subject.

**Independent Test**: After the fix, the polyglot bake-off output must not contain `pkg:maven/com.example/sbom-fixture@1.0.0` in `components[]`. If the fix additionally promotes the coord to `metadata.component`, the SBOM's `metadata.component.purl` should name it.

**Acceptance Scenarios**:

1. **Given** Story 1 has identified the exact reason US4's heuristic didn't fire for this JAR, **When** the targeted fix ships, **Then** `components[]` on the polyglot bake-off no longer contains `pkg:maven/com.example/sbom-fixture@1.0.0`.
2. **Given** the fix, **When** scanning a rootfs with a genuine Maven dependency JAR at `/usr/share/java/commons-lang3.jar` that happens to have a `Main-Class:` manifest entry for library-provided CLI tools, **Then** that JAR is NOT suppressed — it's a dependency, not a scan subject.
3. **Given** the fix, **When** the suppressed coord is promoted to `metadata.component`, **Then** the CycloneDX 1.6 document validates and downstream consumers see the project's identity where CycloneDX says it should live.

---

### User Story 4 - Document commons-compress version disagreement as known limitation (Priority: P4)

The `commons-compress` 1.21 vs 1.23.0 finding is not a mikebom bug. It arises because the polyglot image has `commons-compress-1.21.jar` in a `.m2/repository/` cache directory (what a developer's local build pulled in) and `apache-commons-compress.pom` at version 1.23.0 in `/usr/share/maven-poms/` (what the Fedora RPM declares). Both paths are legitimately "on disk"; both versions are plausibly "shipped."

mikebom's current behavior: embedded `META-INF/maven/` metadata in the `.m2` JAR wins over the sidecar POM (spec feature 007 FR-004). The ground truth tool takes the opposite default. Neither tool is wrong; they've made different convention choices.

After this story lands, the behavior is documented as a known limitation in the design-notes, with a pointer to where an operator who disagrees with mikebom's default could work around it (e.g., the `.m2` cache could be excluded from the scan, or the sidecar-POM path could take precedence via a future feature flag).

**Why this priority**: This is the ONLY remaining FP after Stories 2 and 3 land, and it's not a bug. It deserves a paragraph of documentation, not code. Including it in scope ensures the feature properly "closes the book" on the polyglot bake-off rather than leaving one unexplained finding.

**Independent Test**: After this story lands, the next reader of `docs/design-notes.md` can explain in their own words why `commons-compress` shows two versions without saying "mikebom has a bug."

**Acceptance Scenarios**:

1. **Given** an operator sees the commons-compress 1.21 vs 1.23.0 disagreement in their bake-off output, **When** they consult the documentation, **Then** they find a paragraph explaining the convention choice (embedded POM wins) and pointing to the relevant FR.
2. **Given** a future operator wants to invert the default (sidecar wins over embedded), **When** they search the documentation, **Then** they find an open follow-up item describing what would need to change.

---

### Edge Cases

- **Story 1 discovers that US2 is actually working correctly and the bake-off harness is running against a stale binary**: the "fix" is to re-run the bake-off, not to change mikebom. Story 1's investigation MUST distinguish this case from a genuine mikebom bug.
- **Story 1 discovers that US4 is actually working correctly and the bake-off output is stale**: same pattern as above.
- **Story 2 concludes that only `go list` (or similar toolchain invocation) can close some of the 4 Go FPs**: those FPs are moved to Story 4 as documented known limitations. Story 2 does NOT silently add a Go toolchain invocation. A future opt-in toolchain mode is captured under "Out of Scope / Follow-up Work" and is explicitly not built in this feature.
- **Story 3's fix risks over-suppressing legitimate dependency JARs with `Main-Class:` entries**: the fix MUST include a regression test asserting a library JAR with Main-Class is still emitted (like `commons-lang3`, which includes CLI entry points).
- **After Stories 1–3 land, the polyglot bake-off still shows a Go or Maven FP**: means Story 1's investigation was incomplete. Re-open, don't paper over.

## Requirements *(mandatory)*

### Functional Requirements

> **Note on FR numbering**: Feature 008's FR identifiers (FR-001 through FR-013 below) are local to this feature. Feature 007 also had an FR-007 with a different meaning (no Go toolchain invocation at scan time). Where this spec re-affirms feature 007's rule, it is cited explicitly as "feature 007 FR-007" to avoid confusion with feature 008's own FR-007 (Maven library-JAR over-suppression guard).

**Investigation (Story 1)**

- **FR-001**: The feature MUST produce a committed investigation document at `specs/008-polyglot-final-cleanup/investigation.md` that names, for each of the 5 mikebom-closable FPs (4 Go + 1 Maven), the specific reason the pre-existing filter didn't fire on the polyglot image.
- **FR-002**: The investigation MUST be supported by concrete artifacts: actual `jq` output from the polyglot scan, or `tracing` log output captured at `--log-level=debug`, or a code-path walkthrough that cites specific line numbers.
- **FR-003**: The investigation MUST distinguish between (a) a genuine mikebom bug closable with static signals, (b) a test-harness / stale-binary issue, (c) a case that no static signal can close — which becomes a known limitation under Story 4, cross-referenced to FU-001.

**Go test-scope fix (Story 2)**

- **FR-004**: If Story 1 finds a genuine mikebom bug closable with static signals alone, Story 2 MUST ship the minimal code change to close it. The change MUST honor feature 007's FR-007 (no runtime Go toolchain invocation).
- **FR-005**: If Story 1 finds that a Go FP cannot be closed by any static signal, that FP is moved to Story 4 as a documented known limitation. Story 2 does NOT silently shell out to `go list` or any other Go toolchain. A future opt-in toolchain-assisted mode is captured in the "Out of Scope / Follow-up Work" section below and is explicitly not in scope for this feature.
- **FR-006**: Any Go filter change MUST preserve all existing feature 007 US2 test behaviors (the synthetic-fixture integration tests at `scan_go_source_test_only_import_is_dropped` etc. MUST still pass).

**Maven project-self fix (Story 3)**

- **FR-007**: The Maven fix MUST NOT suppress dependency JARs that happen to declare `Main-Class:` — the fix must refine the heuristic in a way that distinguishes scan subject from dependency more precisely than the current US4 gate does.
- **FR-008**: If the suppressed coord can be routed to `metadata.component` per CycloneDX 1.6 convention, it SHOULD be; if routing is non-trivial, suppression alone satisfies the FR and promotion can be a follow-up.
- **FR-009**: Any Maven fix MUST preserve all existing feature 007 US4 test behaviors.

**Documentation (Story 4)**

- **FR-010**: The commons-compress version-disagreement behavior MUST be documented in `docs/design-notes.md` (or equivalent project-architecture doc) with a pointer to the relevant FR and the reasoning behind the convention choice.
- **FR-011**: The documentation MUST name at least one workaround available today to an operator who wants the opposite default.

**Cross-cutting**

- **FR-012**: Pre-PR verification per constitution v1.2.1 (both `cargo +stable clippy --workspace --all-targets` and `cargo +stable test --workspace` passing) MUST be evidenced in each PR description that ships against this feature.
- **FR-013**: The per-ecosystem bake-off scoreboard for cargo, gem, pypi, rpm, and binary/generic MUST remain at perfect-match after each PR merges. No regression.

### Key Entities

- **Polyglot bake-off output**: the `mikebom.cdx.json` document mikebom produces when scanning the polyglot-builder-image rootfs. The authoritative "did we close the FP" artifact.
- **Investigation document**: `specs/008-polyglot-final-cleanup/investigation.md` — the committed, reviewable writeup answering "why didn't the shipped filter fire."
- **Target FPs**: the five PURLs enumerated in Context; each must be addressed by one of Stories 1–3.
- **Known limitation**: an FP that no static signal can close; documented under Story 4 and cross-referenced to FU-001 for future toolchain-assisted handling.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: After Story 1 lands, a reviewer reading `investigation.md` can name, for each of the 5 target FPs, the specific reason the pre-existing filter didn't close it on the polyglot image — no ambiguity, no hand-waving.
- **SC-002**: After Story 2 lands (assuming Story 1 found a closable gap), a polyglot bake-off run against the post-Story-2 binary shows `components[]` contains none of: `pkg:golang/github.com/stretchr/testify@*`, `pkg:golang/github.com/davecgh/go-spew@*`, `pkg:golang/github.com/pmezard/go-difflib@*`, `pkg:golang/gopkg.in/yaml.v3@*`.
- **SC-003**: After Story 3 lands, a polyglot bake-off run shows `components[]` contains no entry with purl `pkg:maven/com.example/sbom-fixture@1.0.0`.
- **SC-004**: After Story 4 lands, the commons-compress disagreement is documented such that a fresh reader of the design-notes can describe the mikebom behavior and the Ground Truth harness behavior in one paragraph each.
- **SC-005**: Cumulative: after all four stories land, the polyglot bake-off finding count is **at most 1** (the commons-compress case, now documented as known behavior). Per-ecosystem scoreboards cargo 11/11, gem 76/76, pypi 2/2, rpm 529/529, binary 2/2 all unchanged.
- **SC-006**: Existing `cargo +stable test --workspace` baseline of 1119 (post-007) MUST be preserved or increased; no regressions in any existing test suite.
- **SC-007**: If any Go FP is moved to Story 4 as a known limitation, the documentation explicitly names the static-signal gap that makes it unclosable and cross-references the follow-up "opt-in toolchain mode" item so a future maintainer can pick it up.

## Out of Scope / Follow-up Work

### FU-001 — Opt-in Go toolchain-assisted scan mode (future enhancement)

A non-default CLI flag (shape TBD, e.g. `--use-go-toolchain` or equivalent) that, when present, invokes `go list -deps -test=false ./...` or similar commands to answer questions that static analysis cannot (test-scope classification, resolved import graph for complex vendoring layouts, etc.). Design considerations when this is picked up:

- Strictly opt-in. Default remains static-only, matching feature 007 FR-007.
- Requires a local Go toolchain available on `$PATH`; when the flag is set and the toolchain is missing, the scan fails closed with a clear error rather than silently falling back.
- The toolchain-assisted results are annotated with provenance metadata (per constitution Principle X "Transparency") so consumers can tell static vs toolchain-derived signals apart.
- Scope must be decided: does the flag only assist the test-scope filter, or does it also override other static filters? To be settled at spec time for that future feature.
- Not built in feature 008. Captured here so the idea isn't lost.

### FU-002 — Invert sidecar-POM vs embedded-POM precedence

Currently (feature 007 FR-004) embedded `META-INF/maven/` metadata wins over a sidecar POM on disagreement. Story 4 documents this; if a future operator needs the opposite default, a feature flag or a separate feature captures that work.

## Assumptions

- The "it's shipped and tests pass but the FPs are still there" pattern was seen before (M4 → G3 post-mortem) and the rule established then applies here: synthetic-fixture tests are necessary but not sufficient; real-fixture measurement is the final gate. The mikebom team already knows this rule; this feature re-applies it with discipline.
- The polyglot-builder-image rootfs is available to the maintainer doing the investigation (either as a local extraction or as a reproducible build). If it isn't, Story 1 begins with making it available — this sub-step may require a small pre-feature PR.
- The current `main` branch at commit `6ec1cf3` or later (post-007-merge) is the baseline for all investigation and fixes.
- The commons-compress case is intentionally NOT being closed on mikebom's side in this feature. If later investigation or future operator demand changes that, a separate feature ticket captures the work — not this one.
- Story 2's scope is bounded: no runtime Go toolchain invocation. A toolchain-assisted opt-in mode is captured as future work (FU-001) and is not built in this feature. FPs that static signals cannot close are moved to Story 4 as documented known limitations rather than silently fixed by shelling out.
- Pre-PR verification (constitution v1.2.1) is enforced on every PR this feature produces. Locally running `cargo +stable clippy --workspace --all-targets` and `cargo +stable test --workspace` clean is a precondition for opening a PR, not an optional check.
