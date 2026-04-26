# Quickstart: Implement and Verify Milestone 017

**Phase 1 quickstart for** `/specs/017-spdx-byte-identity-goldens/spec.md`

This document is the cookbook for a contributor (the maintainer, in practice) to scaffold the helper, write one new test file, regenerate goldens, and verify the whole feature end-to-end.

## Prerequisites

- macOS dev machine with stable Rust + clippy installed.
- Repo checked out at `main`, branch `017-spdx-byte-identity-goldens` already created (matches the spec).
- `./scripts/pre-pr.sh` runs successfully on `main` (post-#38 baseline: 1385 passing tests + 0 clippy warnings).

## Workflow

### Phase A — Build the helper module, prove CDX migration is byte-identical

The helper goes in first because it's the foundation. Migrating `cdx_regression.rs` to use it is the proof-of-correctness gate before pinning any new SPDX golden.

```bash
# A1. Create the helper module skeleton.
touch mikebom-cli/tests/common/normalize.rs
# Edit common/normalize.rs to add:
#   - module-doc per data-model.md "Module-doc shape"
#   - empty function bodies matching the FR-006 signatures
#   - `pub use` re-exports if convenient

# A2. Port the CDX normalize logic from cdx_regression.rs:143-183
# into normalize_cdx_for_golden. Same string-replace, same JSON walk,
# same hash strip — verbatim. The only change is the function name +
# module location.

# A3. Update cdx_regression.rs to call the helper.
# The inline `fn normalize(raw: &str) -> String {...}` is removed; the
# only call site (around the assert / regen branch) becomes
# `common::normalize::normalize_cdx_for_golden(&raw, &workspace_root())`.

# A4. Verify CDX goldens are byte-identical.
cargo +stable test -p mikebom --test cdx_regression
# All 9 tests must pass.

# A5. Verify regen produces zero diff (the strict check).
MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo +stable test -p mikebom --test cdx_regression
git diff mikebom-cli/tests/fixtures/golden/cyclonedx/
# Output must be empty. If diff is non-empty, the helper diverged
# from the inline behavior — reconcile before proceeding.

# A6. Add apply_fake_home_env. Migrate cdx_regression.rs's run_scan
# to use it (the 6-line env block at cdx_regression.rs:88-93 collapses
# to `common::normalize::apply_fake_home_env(&mut cmd, fake_home.path());`).
# Re-run A4 + A5 — still byte-identical.
```

**Checkpoint**: Helper exists, CDX uses it, goldens unchanged. The infrastructure is now ready for SPDX.

### Phase B — Write `spdx_regression.rs` + commit 9 SPDX 2.3 goldens

```bash
# B1. Create the test file by copying cdx_regression.rs as a template.
cp mikebom-cli/tests/cdx_regression.rs mikebom-cli/tests/spdx_regression.rs
# Edit spdx_regression.rs:
#   - rename normalize() calls to normalize_spdx23_for_golden
#   - change --format flag from cyclonedx-json to spdx-2.3-json
#   - change golden_path() to point at tests/fixtures/golden/spdx-2.3/{label}.spdx.json
#   - change MIKEBOM_UPDATE_CDX_GOLDENS to MIKEBOM_UPDATE_SPDX_GOLDENS
#   - rename test functions: <ecosystem>_byte_identity (matching cdx pattern)

# B2. Implement normalize_spdx23_for_golden in common/normalize.rs.
# Apply the placeholder catalog from data-model.md:
#   - Workspace-path string-replace (same as CDX, on the raw output)
#   - Mask creationInfo.created → "1970-01-01T00:00:00Z"
#   - Strip packages[].checksums[]

# B3. Generate the 9 SPDX 2.3 goldens.
mkdir -p mikebom-cli/tests/fixtures/golden/spdx-2.3
MIKEBOM_UPDATE_SPDX_GOLDENS=1 cargo +stable test -p mikebom --test spdx_regression
# All 9 tests should now pass (because regen always succeeds).

# B4. Empirical workspace-path leak sweep (per research.md R3).
rg '/Users/[^"]*' mikebom-cli/tests/fixtures/golden/spdx-2.3/
# Output should be empty.
# If non-empty: a leak vector was missed. Add the leaked path's prefix
# to the workspace-path-replacement step in normalize_spdx23_for_golden,
# regen (B3), and re-rg until empty.

# B5. Pin the goldens.
git add mikebom-cli/tests/fixtures/golden/spdx-2.3/
# Commit. The goldens are now the reference output.

# B6. Sanity-check the assert path (no regen).
cargo +stable test -p mikebom --test spdx_regression
# All 9 tests pass. Goldens are now load-bearing.
```

### Phase C — Write `spdx3_regression.rs` + commit 9 SPDX 3 goldens

Same shape as Phase B but for SPDX 3. The `@graph`-shaped document means the masker walks `@graph[]` looking for elements with `type == "CreationInfo"` (vs. the flat-document SPDX 2.3 case).

```bash
# C1. Create spdx3_regression.rs (copy spdx_regression.rs as template).
# Adjust:
#   - normalize_spdx3_for_golden
#   - --format spdx-3-json
#   - tests/fixtures/golden/spdx-3/{label}.spdx3.json
#   - MIKEBOM_UPDATE_SPDX3_GOLDENS

# C2. Implement normalize_spdx3_for_golden. Walk @graph[] for
# CreationInfo elements; mask their `created`. Strip
# verifiedUsing[] from Package elements.

# C3. Generate 9 SPDX 3 goldens.
mkdir -p mikebom-cli/tests/fixtures/golden/spdx-3
MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test -p mikebom --test spdx3_regression

# C4. Empirical leak sweep.
rg '/Users/[^"]*' mikebom-cli/tests/fixtures/golden/spdx-3/

# C5. Pin + sanity-check.
git add mikebom-cli/tests/fixtures/golden/spdx-3/
cargo +stable test -p mikebom --test spdx3_regression
```

### Phase D — Migrate inline fake-HOME setup across the test tree

```bash
# D1. Find every test that inlines env("HOME").
rg -l 'env\("HOME"' mikebom-cli/tests/ -g '!common/'
# Expect ~25 hits (every acceptance test that shells the binary).

# D2. For each, replace the 5-7-line env block with one call to
# common::normalize::apply_fake_home_env(&mut cmd, fake_home.path()).
# The TempDir-binding pattern stays the same: hold the TempDir alive
# across the Command::output() call.

# D3. Run the workspace test suite.
cargo +stable test --workspace
# All previously-passing tests still pass. New tests (B + C) still pass.

# D4. Verify FR-008 grep returns clean.
rg 'env\("HOME"' mikebom-cli/tests/ -g '!common/'
# Output: empty.
rg 'env\("M2_REPO"|env\("MAVEN_HOME"|env\("GOPATH"|env\("GOMODCACHE"|env\("CARGO_HOME"' mikebom-cli/tests/ -g '!common/'
# Output: empty.
```

### Phase E — Cross-host verification

```bash
# E1. Push the branch.
git push -u origin 017-spdx-byte-identity-goldens

# E2. Open the PR.
gh pr create --title "feat(017): SPDX byte-identity goldens + cross-host determinism parity" ...

# E3. Watch the CI run.
gh run watch
# Both Linux and macOS legs must pass. Either failing the SPDX
# regression tests means the leak-vector sweep (B4 / C4) missed
# a vector that surfaces only on the OTHER host. Iterate B/C
# until both legs are green.
```

## Recommended commit chunking

To keep the PR reviewable per FR-009 + spec SC-005, commit in logical chunks:

| Chunk | Files added/changed | Commit message |
|---|---|---|
| 1. Helper module + CDX migration | `tests/common/normalize.rs`, `tests/cdx_regression.rs` | `test: extract tests/common/normalize.rs; migrate cdx_regression to it (byte-identical)` |
| 2. SPDX 2.3 regression test + goldens | `tests/spdx_regression.rs`, `tests/fixtures/golden/spdx-2.3/*` | `test: add spdx_regression.rs + 9 SPDX 2.3 byte-identity goldens` |
| 3. SPDX 3 regression test + goldens | `tests/spdx3_regression.rs`, `tests/fixtures/golden/spdx-3/*` | `test: add spdx3_regression.rs + 9 SPDX 3 byte-identity goldens` |
| 4. Fake-HOME migration sweep | ~25 test files | `test: migrate inline fake-HOME isolation to common::apply_fake_home_env` |

Each chunk's commit MUST leave the tree green (`./scripts/pre-pr.sh` passes per chunk).

## Common pitfalls

1. **CDX migration produces a non-empty diff under `MIKEBOM_UPDATE_CDX_GOLDENS=1` regen** — the helper diverged from the inline `normalize()` behavior. Diff the helper against `cdx_regression.rs:143-183` line-for-line; some subtle behavior (e.g., a specific JSON-serialization quirk) probably moved.
2. **macOS-pinned goldens fail on Linux CI** — workspace-path replacement missed a leak vector that's expressed differently on Linux. Look at the per-ecosystem failing diff in the CI log; the offending lines will contain `/home/runner/work/mikebom/mikebom/...`. Add that prefix to the substitution pass and regen on macOS.
3. **One ecosystem's golden is huge** — `maven` and `npm` fixtures emit dozens of components. That's expected; `git diff` over a large golden is still reviewable because of pretty-print + sorted keys. Don't try to summarize or compress.
4. **`spdx_determinism.rs` starts failing** — the run-vs-run determinism test is orthogonal to byte-identity goldens. If it breaks during this milestone, the cause is the fake-HOME migration (Phase D) or an emitter side-effect of the golden regen, not the new infrastructure. Verify with `git stash; cargo test -p mikebom --test spdx_determinism` to confirm the test passed pre-change.
5. **A new field appears in the goldens but doesn't appear in `git diff` of `mikebom-cli/src/`** — usually means a new transitive-dep update (e.g., `cyclonedx-bom` 0.x → 0.y) added a field. Document it in the PR description as a benign upstream change.

## After PR merge

- Verify the next 30-day spot-check (per spec SC-006) that no merged PR regenerates SPDX goldens without an accompanying explanation in the PR description.
- If the explanation pattern reveals a category of "always-regenerated together" goldens (e.g., every emitter change touches all 9), consider documenting the regen-discipline best practice in `docs/architecture/generation.md` for future milestones.
