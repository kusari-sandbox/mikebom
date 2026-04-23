# Phase 0 Research: Polyglot Final Cleanup

This document is a code-path investigation of why feature 007 US2 (Go test-scope intersection) and US4 (Maven Main-Class executable-JAR heuristic) shipped with green tests but apparently did not close their target FPs on the polyglot-builder-image bake-off. The investigation is done from source reading alone; the actual "run mikebom against the polyglot rootfs and capture evidence" step is Story 1's committed deliverable (tracked in `investigation.md`, produced during Phase 2 tasks).

The hypotheses below are prioritized by likelihood. Story 1's job is to confirm or rule out each one by direct evidence.

## R1 — G4 filter code path and early-return semantics

**Decision**: G4 (`apply_go_production_set_filter` in `mikebom-cli/src/scan_fs/package_db/mod.rs`) early-returns when `production_imports` is empty. This is by design — an empty import set means no source tree was parsed, so source-tier go.sum entries pass through unfiltered. G3 alone drives Go filtering in that case.

**Rationale**: The filter is defined as the intersection of (BuildInfo-linked modules) ∩ (modules reached from non-`_test.go` imports). An empty RHS makes the intersection empty, which would drop EVERYTHING — clearly wrong. The early-return preserves existing behavior when the source-import signal is unavailable.

**Implication for polyglot**: If the polyglot rootfs has a Go binary whose BuildInfo includes testify/go-spew/go-difflib/yaml.v3 as ANALYZED-tier entries (not source-tier), those pass through both G3 and G4 regardless. G4 only touches source-tier entries.

## R2 — Tier of the emitted FPs

**Decision**: The four Go FPs that still appear on polyglot are likely emitted at `sbom_tier = "analyzed"` (from `go_binary::read`'s BuildInfo extraction), not `sbom_tier = "source"` (from `golang::read`'s go.sum parsing).

**Rationale**: `apply_go_linked_filter` (G3) only touches entries with `sbom_tier == Some("source")`. Same for `apply_go_production_set_filter` (G4). Analyzed-tier entries are passthrough on purpose — BuildInfo is considered authoritative. If testify is in the compiled binary's BuildInfo, it emits as analyzed and nothing in G3/G4 touches it.

**Story 1 evidence to collect**: `jq '.components[] | select(.purl | contains("testify")) | .properties[] | select(.name == "mikebom:sbom-tier")'` on the polyglot SBOM output. If value is `"analyzed"`, this hypothesis is confirmed — the filter chain is working exactly as designed, and US2's lab-fixture tests never exercised this path because the fixtures deliberately kept test-deps out of BuildInfo.

## R3 — Why would BuildInfo legitimately include testify?

**Decision**: If the polyglot binary was compiled with `go test -c` (producing a test binary) OR the main package has a non-`_test.go` import of a testify subpackage OR the binary was compiled with specific build flags that link test infrastructure, its BuildInfo would list testify. No static signal distinguishes "testify linked for legitimate production reasons" from "testify linked but only used in tests" when only the final binary is observed.

**Rationale**: Go's `runtime/debug.BuildInfo` records modules the linker actually included — not the purpose it was included for. A testify reference in `main.go` (even a `var _ = assert.Equal` compilation-assertion smoke-test) is enough to pull it in. The build.go process erases the test/production distinction at the binary level.

**Story 1 evidence to collect**: `go version -m <polyglot-binary-path>` output (or equivalent `debug/buildinfo` inspection from Rust). If testify appears in the `dep` lines, the binary genuinely links it. mikebom cannot distinguish "test harness compiled in" from "production use" without toolchain support — so this becomes a known limitation per spec Story 4 + cross-ref to FU-001.

## R4 — US4's Main-Class heuristic gating

**Decision**: `is_executable_unclaimed_jar` in `maven.rs` requires THREE conditions simultaneously:
1. `meta.is_primary == true`
2. `co_owned_by.is_none()`
3. `jar_has_main_class_manifest(...) == true`

**Rationale**: Any one being false disables the suppression for a given JAR. The existing classic `is_unclaimed_fat_jar` heuristic also requires `meta_list.len() >= 2` (≥2 embedded `META-INF/maven/` entries). If the `sbom-fixture` JAR has a single primary coord + no Main-Class + no OS-package claim, BOTH heuristics miss it.

**Story 1 evidence to collect** (for `com.example/sbom-fixture@1.0.0`):
- Extract the polyglot rootfs's `sbom-fixture` JAR.
- `unzip -p <jar> META-INF/MANIFEST.MF` — check for `Main-Class:` line. If absent, that's the gap.
- `walk_jar_maven_meta` output (`tracing::debug!` at `--log-level=debug`) — inspect `is_primary` flag on the emitted meta.
- mikebom's `co_owned_by` determination — is the JAR under a path the binary-walker treated as package-db-claimed?

## R5 — Candidate minimal fixes per gap

If Story 1 confirms **R3 scenario** (BuildInfo legitimately lists testify), no static fix exists without a toolchain. Move to Story 4 known-limitation doc + cross-ref FU-001.

If Story 1 confirms **US4 gap is "no Main-Class"** for sbom-fixture (R4), candidates:
- **Option A**: extend the executable-JAR heuristic to ALSO fire on JARs that contain a `WEB-INF/` or `BOOT-INF/classes/` entry (Spring-Boot and servlet-container signatures that are just as reliable as Main-Class).
- **Option B**: extend to fire when the JAR's filename stem exactly matches the embedded primary coord AND the JAR is unclaimed (rare in deps, common in build outputs).
- **Option C**: fire when the JAR is under a conventional build-output path (`/app/`, `/srv/`, `/opt/<name>/*.jar`) — path heuristic. Less reliable but catches a broader set.

Pick based on whichever matches the polyglot sbom-fixture's actual shape without over-suppressing regular dependency JARs.

If Story 1 confirms **US4 gap is "JAR is OS-claimed"** (R4 co_owned_by branch), then sbom-fixture is co-owned by an OS package-db reader — which is unusual for a build-output fat-jar. In that case the fix might be to allow suppression when co_owned_by is Some AND a stronger positive scan-subject signal fires (e.g., matches `scan_target_name`).

If Story 1 confirms **US4 gap is "primary detection failed"** (R4 `is_primary` branch), the fix is in `walk_jar_maven_meta`'s stem-matching — compare the JAR filename against the coord's `<artifactId>-<version>` more permissively (allow trailing `-SNAPSHOT`, `-jar-with-dependencies`, etc.).

## R6 — G4 walker coverage of real source trees

**Decision**: `collect_production_imports` (in `golang.rs`) walks from each `project_root` (where go.mod lives) and uses `should_skip_descent` to avoid vendored and build directories. Max depth is `MAX_PROJECT_ROOT_DEPTH = 6`.

**Risk**: If the polyglot Go source is structured such that main.go lives deeper than 6 levels from the go.mod root (unusual but possible in monorepos), imports wouldn't be collected. Similarly, if main.go is under a directory name the walker skips (unlikely in practice — the skip set is `vendor`, `node_modules`, `target`, `dist`, `build`, `__pycache__`, dotdirs), it'd be missed.

**Story 1 evidence to collect**: `find <rootfs>/<go-project-root> -maxdepth 6 -name "*.go" -not -name "*_test.go"` — compare against what mikebom's walker found via `--log-level=debug` logs.

## R7 — Binary selection and staleness checks

**Decision**: Before claiming any filter is buggy, Story 1 MUST confirm the bake-off ran against a binary built from `main` at post-007-merge commit or later.

**Rationale**: The M4 → G3 post-mortem already showed that a stale binary can make a shipped fix look unshipped. The governance note on CI verification (constitution v1.2.1) makes this the operator's responsibility; Story 1 formalizes the check.

**Story 1 evidence to collect**: `mikebom --version` output + git SHA embedded in the binary (if present) + bake-off harness log showing which binary it invoked + the binary's mtime vs. the merge timestamp of PR #10/#11.

## R8 — Fixture delta between lab tests and polyglot reality

**Decision**: The US2 integration tests (`scan_go_source_test_only_import_is_dropped`, `scan_go_source_production_and_test_import_dominates`) construct synthetic fixtures where:
- main.go imports logrus from production code
- main_test.go imports testify from test code only
- go.sum lists both

Both fixtures have `.go` files → `production_imports` is non-empty → G4 actively filters → testify dropped.

The polyglot fixture might differ in one or more of these dimensions:
- No source tree on the rootfs (only the binary, plus go.mod/go.sum) → G4 no-ops → R2 scenario.
- Source tree present but with no `.go` files (only `_test.go`) → `production_imports` could be empty → R2 scenario again but via a different path.
- Binary-side BuildInfo legitimately lists testify → R3 scenario.

**Story 1 evidence to collect**: `find <polyglot-rootfs>/<go-project> -name "*.go"` enumeration, split by `_test.go` vs production. If production count is 0 or the tree has no go files at all, that's a gap neither lab test covers.

## Summary of decisions

| # | Area | Decision |
|---|------|----------|
| R1 | G4 early-return | By design; empty import set no-ops the filter |
| R2 | Likely tier of surviving FPs | `analyzed` (BuildInfo-sourced), not `source` — passes through by design |
| R3 | Why BuildInfo includes testify | Binary genuinely links it; no static signal can distinguish intent |
| R4 | US4 three-condition gate | Any single false condition disables the suppression |
| R5 | Candidate minimal fixes | Options A/B/C depending on what Story 1 confirms |
| R6 | G4 walker coverage | Adequate up to depth 6; risk in unusual monorepo shapes |
| R7 | Stale binary check | Required before claiming any filter is buggy |
| R8 | Lab-vs-polyglot fixture delta | Synthetic tests likely don't exercise the analyzed-tier passthrough |

## Open research questions (resolved by Story 1 evidence)

1. **Q1**: For each of testify, go-spew, go-difflib, yaml.v3 on the polyglot output — what is the `mikebom:sbom-tier` property value? (R2)
2. **Q2**: Does the polyglot binary's BuildInfo list any of the four FP modules? (R3)
3. **Q3**: Does the polyglot rootfs contain a Go source tree with non-`_test.go` files, and does `mikebom --log-level=debug` show `collect_production_imports` finding them? (R6, R8)
4. **Q4**: Does `<polyglot-rootfs>/<sbom-fixture.jar>` have `Main-Class:` in its MANIFEST.MF? (R4)
5. **Q5**: Is the `sbom-fixture` JAR `co_owned_by.is_some()` in the mikebom trace logs? (R4)
6. **Q6**: Confirmed that the bake-off ran against a post-007-merge mikebom binary? (R7)

All questions are answerable with file reads + a single `--log-level=debug` mikebom run against the polyglot rootfs. No code changes required to answer any of them.
