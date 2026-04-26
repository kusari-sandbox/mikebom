# Quickstart: Implement and Verify Milestone 018

**Phase 1 quickstart for** `/specs/018-module-splits/spec.md`

This is the cookbook for executing one split (pip / npm / binary) end-to-end. The same recipe applies to all three.

## Prerequisites

- macOS dev machine with stable Rust + clippy installed.
- Repo at `main`, branch `018-module-splits` already created.
- Post-#41 baseline: `./scripts/pre-pr.sh` passes clean from a fresh tree.

## Workflow per split

The five-step recipe. Apply once per user story (US1: pip, US2: npm, US3: binary).

```bash
# Step 1 — Snapshot baseline test names so SC-004 can verify zero
# removed test names post-split.
./scripts/pre-pr.sh 2>&1 | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/pre-split-tests.txt
wc -l /tmp/pre-split-tests.txt
# Output: ~1216 (post-#41 count from milestone 017's T021)

# Step 2 — Create the directory module skeleton. For pip:
mkdir mikebom-cli/src/scan_fs/package_db/pip
touch mikebom-cli/src/scan_fs/package_db/pip/{mod,dist_info,poetry,pipfile,requirements_txt}.rs

# Step 3 — Move code from pip.rs into the new submodules per
# `data-model.md` "Visibility ladder — pip.rs split".
#
# IMPORTANT — do this as one atomic edit, not piecemeal. The
# intermediate state (pip.rs partially gutted, pip/poetry.rs
# partially populated) is broken because Rust's module system
# either has pip OR pip/, never both. Plan the full move on
# paper, execute it as one git operation, then compile.
#
# The moves:
#   - lines 56, 152-323 (helpers + walker) → pip/mod.rs
#   - lines 247, 278 (merge + claimed-paths) → pip/mod.rs
#   - lines 325-694 (dist_info section) → pip/dist_info.rs
#   - lines 697-833 (poetry section) → pip/poetry.rs
#   - lines 834-925 (pipfile section) → pip/pipfile.rs
#   - lines 927-1965 (requirements section) → pip/requirements_txt.rs
#
# pip/mod.rs MUST start with `mod dist_info; mod poetry; mod pipfile;
# mod requirements_txt;` declarations and `use` lines bringing in
# the `pub(super)` items the orchestrator needs.
#
# rm mikebom-cli/src/scan_fs/package_db/pip.rs

# Step 4 — Adjust visibility per data-model.md table.
# Run cargo +stable check --workspace --tests; the compiler will
# tell you which items need pub(super) (or pub re-export from mod.rs).
# Iterate until clean.
cargo +stable check --workspace --tests 2>&1 | tail -10

# Step 5 — Verify zero behavior change via the byte-identity
# goldens (the load-bearing regression test for this milestone).
MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo +stable test -p mikebom --test cdx_regression
MIKEBOM_UPDATE_SPDX_GOLDENS=1 cargo +stable test -p mikebom --test spdx_regression
MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test -p mikebom --test spdx3_regression
git diff --stat mikebom-cli/tests/fixtures/golden/
# Expected: empty. If non-empty, the split changed scan output and
# is wrong — diff the pre/post code path-by-path.

# Step 6 — Full pre-PR.
./scripts/pre-pr.sh
# Should pass clean: zero clippy warnings, all test target lines
# `ok. N passed; 0 failed`.

# Step 7 — Verify SC-004 test-name parity.
./scripts/pre-pr.sh 2>&1 | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/post-split-tests.txt
echo "=== Removed (must be empty) ==="
comm -23 /tmp/pre-split-tests.txt /tmp/post-split-tests.txt
echo "=== Added (allowed only if a test was renamed during the move) ==="
comm -13 /tmp/pre-split-tests.txt /tmp/post-split-tests.txt
# Expected: zero removed, zero added. If any added, document why
# in the commit message + PR description.

# Step 8 — Commit per FR-009. Each user story = one commit.
git add mikebom-cli/src/scan_fs/package_db/pip/ \
        mikebom-cli/src/scan_fs/package_db/pip.rs   # 'rm' is captured by `git add` of the deletion
git commit -m "refactor(018/US1): split pip.rs into pip/ submodule"
```

## Recommended commit chunking

Per FR-009: **one commit per user story.** The PR bundles all three.

| Commit | Scope | Files affected |
|---|---|---|
| 1. US1: pip split | `pip.rs` → `pip/` (5 files) | `mikebom-cli/src/scan_fs/package_db/pip*` |
| 2. US2: npm split | `npm.rs` → `npm/` (5 files) | `mikebom-cli/src/scan_fs/package_db/npm*` |
| 3. US3: binary split | `binary/mod.rs` shrinks; new siblings `discover.rs`, `scan.rs`, `entry.rs` | `mikebom-cli/src/scan_fs/binary/*` |

Each commit's message follows the existing convention (e.g., `refactor(018/US1): split pip.rs into pip/ submodule`).

Each commit MUST leave the tree green (`./scripts/pre-pr.sh` exit 0) AND the byte-identity goldens unchanged (per Step 5 above).

## Final-state verification (acceptance test)

After all three commits land, before opening PR:

```bash
# (a) FR-010 LOC ceilings.
test "$(wc -l < mikebom-cli/src/scan_fs/binary/mod.rs)" -le 800 || echo "binary/mod.rs > 800 LOC"
for f in mikebom-cli/src/scan_fs/package_db/pip/*.rs; do
  loc=$(wc -l < "$f")
  if [ "$loc" -gt 1100 ]; then echo "FAIL: $f = $loc LOC > 1100"; fi
  if [ "$loc" -gt 800 ] && [ "$(basename "$f")" != "requirements_txt.rs" ]; then
    echo "FAIL: $f = $loc LOC > 800 (only requirements_txt.rs allowed up to 1100)"
  fi
done
for f in mikebom-cli/src/scan_fs/package_db/npm/*.rs; do
  loc=$(wc -l < "$f")
  if [ "$loc" -gt 800 ]; then echo "FAIL: $f = $loc LOC > 800"; fi
done

# (b) FR-005 byte-identity goldens still match.
MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo +stable test -p mikebom --test cdx_regression > /dev/null
MIKEBOM_UPDATE_SPDX_GOLDENS=1 cargo +stable test -p mikebom --test spdx_regression > /dev/null
MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test -p mikebom --test spdx3_regression > /dev/null
git diff --stat mikebom-cli/tests/fixtures/golden/
# Expected: empty.

# (c) FR-006 / SC-002 full pre-PR.
./scripts/pre-pr.sh

# (d) SC-004 test-name parity (final).
./scripts/pre-pr.sh 2>&1 | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/final-tests.txt
diff /tmp/pre-split-tests.txt /tmp/final-tests.txt
# Expected: empty diff (or only added lines, with PR description rationale).
```

## CI verification

After pushing the branch:

```bash
gh pr create --title "refactor(018): module splits — pip / npm / binary" --body ...
gh run watch
# Expect: both lint-and-test (linux-x86_64) AND lint-and-test-macos pass.
```

Cross-host verification matters here for the same reason as #40 — splitting code can in principle expose hidden ordering or lookup-set differences (HashMap iteration, glob results) across hosts. The 27 byte-identity goldens are the canary; if cross-host breaks, the failure mode is visible diff in the goldens, just like 017.

## Common pitfalls

1. **Half-moved code mid-step**: trying to incrementally move parsers ("first poetry, then pipfile") breaks compilation between sub-steps because Rust's module system requires `pip.rs` OR `pip/`, never both. Plan the full move on paper, execute as one operation. If the compiler is unhappy mid-step, revert and try again with the full move.
2. **Stale `pub` reductions**: it's tempting during the move to make a previously-`pub` item `pub(super)` if you observe no caller. Don't — visibility *contraction* is out of scope (per FR-004). Stay verbatim on the pre-split visibility level for items already external; only *expand* visibility (`fn` → `pub(super) fn`) where the new sibling-call graph requires.
3. **Scan output drift from accidental field-order change**: if you accidentally reorder a `vec.sort_by(...)` predicate or change the order of `obj.insert(...)` calls during the move, the goldens trip. The `pre-pr.sh` will catch it (the spdx*/cdx_regression tests fail with the diff named). Diff the pre-split production code against post-split byte-for-byte to find it.
4. **Inline test placement**: a test inside `pip.rs::tests` that exercises both `read_poetry_lock` and `parse_requirements_line` doesn't have a single home post-split. Either split the test into two (one per submodule), or place it at `pip/mod.rs::tests` (it's now an orchestrator-level test). Prefer the latter for cross-cutting tests.
5. **`#![allow(...)]` directives at file head**: the pre-split file may have `#![allow(clippy::SOMETHING)]` covering offending code that's about to land in a specific submodule. Move the allow directive with the code (`#[allow(...)]` on the function, not `#![...]` on the new module) unless the allow is genuinely needed for multiple post-split files.

## After PR merge

- Verify the post-#018 baseline at the next milestone (019). The new test-name list becomes the baseline for FR-009-style diffs in 019's pre-PR.
- Update `docs/architecture/scanning.md` if it references `pip.rs` or `npm.rs` as single files. (Spot-check; not blocking the PR.)
- Verify SC-005 the next time you fix a Poetry-specific bug — does navigation feel faster? If yes, the milestone delivered. If no, the split needs further sub-decomposition (follow-up milestone, not this one).
