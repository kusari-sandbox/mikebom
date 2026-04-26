# Quickstart: Implement and Verify Milestone 019

**Phase 1 quickstart for** `/specs/019-binary-split/spec.md`

This is the cookbook for executing the binary/mod.rs split end-to-end. Each submodule extraction is one atomic commit; the milestone-018 lesson is that piecemeal extraction breaks Rust's module system.

## Prerequisites

- macOS dev machine with stable Rust + clippy installed.
- Repo at `main`, branch `019-binary-split` already created.
- Post-#43 baseline: `./scripts/pre-pr.sh` passes from a fresh tree (modulo pre-existing flaky tests).

## Workflow per submodule

The five-step recipe. Apply once per submodule extraction, in order: `predicates.rs`, `discover.rs`, `entry.rs`, `scan.rs`. Final commit: full pre-PR + verification.

```bash
# Step 1 — Snapshot baseline test names (once, before any split).
./scripts/pre-pr.sh 2>&1 | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/baseline-019-tests.txt

# Step 2 — For each submodule, plan the move on paper using
# data-model.md "Visibility ladder" + "Cross-submodule import inventory".
#
# IMPORTANT — execute one submodule per commit, atomically. Don't
# try to incrementally extract sub-functions; Rust's module system
# rejects intermediate states (file exists in two places, name
# resolution conflicts).

# Step 3 — Construct the new submodule file. Use sed -n M,Np to
# extract the source-line range from binary/mod.rs:
#
#   predicates: lines 45-168 (RootfsKind, detect_rootfs_kind,
#                              is_host_system_path, has_rpmdb_at,
#                              is_os_managed_directory)
#   discover:   lines 861-938 (discover_binaries, walk_dir,
#                              is_supported_binary, detect_format)
#   entry:      lines 583-639 + 940-1152 (BinaryScan, version_match_to_entry,
#                                          make_file_level_component,
#                                          note_package_to_entry, impl)
#   scan:       lines 170-249 + 641-859 (is_go_binary, scan_binary,
#                                         scan_fat_macho, collect_string_region)
#
# Each new file gets:
#   1. Module-doc header (1-line description)
#   2. Imports (per data-model.md "Cross-submodule import inventory")
#   3. The extracted production code with visibility adjustments
#      (private fn → pub(super) fn for cross-sibling callers)
#   4. The corresponding tests block with use super::*; etc.

# Step 4 — Update binary/mod.rs to:
#   1. Add `mod predicates;` (etc.) declaration near the existing pub mod block
#   2. Delete the moved code
#   3. Qualify cross-submodule call sites in read():
#        detect_rootfs_kind(...) → predicates::detect_rootfs_kind(...)
#        discover_binaries(...) → discover::discover_binaries(...)
#        scan_binary(...) → scan::scan_binary(...)
#        version_match_to_entry(...) → entry::version_match_to_entry(...)
#        etc.

# Step 5 — Verify via byte-identity goldens (the load-bearing check).
cargo +stable check --workspace --tests
MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo +stable test -p mikebom --test cdx_regression > /dev/null 2>&1
MIKEBOM_UPDATE_SPDX_GOLDENS=1 cargo +stable test -p mikebom --test spdx_regression > /dev/null 2>&1
MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test -p mikebom --test spdx3_regression > /dev/null 2>&1
git diff --stat mikebom-cli/tests/fixtures/golden/   # MUST be empty

# Step 6 — Run pre-PR.
./scripts/pre-pr.sh 2>&1 | tail -3

# Step 7 — Commit per FR-008.
git add mikebom-cli/src/scan_fs/binary/<new_file>.rs \
        mikebom-cli/src/scan_fs/binary/mod.rs
git commit -m "refactor(019/extract-<concern>): move <items> from binary/mod.rs to <new_file>.rs"
```

## Recommended commit chunking

Per FR-008 — one atomic commit per submodule extraction. Total: 4 extraction commits + 1 spec commit.

| Commit | Scope | Files affected | Estimated LOC moved |
|---|---|---|---|
| 1. spec set | `specs/019-binary-split/*` | (docs only) | — |
| 2. extract predicates.rs | RootfsKind + 4 OS predicates + 14 tests | predicates.rs (NEW), mod.rs | -350 from mod.rs |
| 3. extract discover.rs | discover_binaries + walk_dir + is_supported_binary + detect_format | discover.rs (NEW), mod.rs | -85 from mod.rs |
| 4. extract entry.rs | BinaryScan + 3 conversion fns + impl PackageDbEntry + 12 tests | entry.rs (NEW), mod.rs | -490 from mod.rs |
| 5. extract scan.rs | scan_binary + scan_fat_macho + collect_string_region + is_go_binary + 4 tests | scan.rs (NEW), mod.rs | -440 from mod.rs |

**Order matters**: extract `entry.rs` BEFORE `scan.rs`, because scan.rs's new file needs `use super::entry::BinaryScan;` — that import resolves only after entry.rs exists. Other orderings (predicates first, then discover, then entry+scan) are constraint-free.

After all 5 extractions: mod.rs ≈ 1858 - 350 - 85 - 490 - 440 = 493 LOC + ~80 LOC of new `mod` declarations + remaining tests. Net: ~575 LOC. ✓ under 800.

## Final-state verification (acceptance test)

After all 4 extraction commits land:

```bash
# (a) FR-001 LOC ceiling
test "$(wc -l < mikebom-cli/src/scan_fs/binary/mod.rs)" -le 800 && echo "✓ mod.rs LOC OK"
for f in mikebom-cli/src/scan_fs/binary/{discover,entry,predicates,scan}.rs; do
  loc=$(wc -l < "$f")
  if [ "$loc" -gt 800 ]; then echo "FAIL: $f = $loc LOC > 800"; fi
done

# (b) FR-004 byte-identity goldens
MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo +stable test -p mikebom --test cdx_regression > /dev/null
MIKEBOM_UPDATE_SPDX_GOLDENS=1 cargo +stable test -p mikebom --test spdx_regression > /dev/null
MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test -p mikebom --test spdx3_regression > /dev/null
git diff --stat mikebom-cli/tests/fixtures/golden/   # MUST be empty

# (c) SC-002 test-name parity
./scripts/pre-pr.sh 2>&1 | grep -E '^test [a-z_:]+ \.\.\. ok' | sort -u > /tmp/post-019-tests.txt
echo "removed test names:"
comm -23 /tmp/baseline-019-tests.txt /tmp/post-019-tests.txt
# expected: only renames (e.g., binary::tests::is_go_binary_* removed
# because they appeared as binary::scan::tests::is_go_binary_* added)

# (d) FR-008 / SC-004 full pre-PR
./scripts/pre-pr.sh   # expected: clean (modulo pre-existing flakiness in
                     # dual_format_perf, spdx_us1_acceptance, spdx_determinism)

# (e) SC-005 external call sites unchanged
git diff main..019-binary-split -- mikebom-cli/src/scan_fs/mod.rs \
                                    mikebom-cli/src/scan_fs/package_db/maven.rs \
                                    mikebom-cli/src/scan_fs/package_db/go_binary.rs \
                                    mikebom-cli/src/scan_fs/binary/linkage.rs
# expected: empty (no edits to these files)
```

## CI verification

After pushing the branch:

```bash
gh pr create --title "refactor(019): binary/mod.rs split — design-first, 5 files" --body ...
gh run watch
# Expect: both lint-and-test (linux-x86_64) AND lint-and-test-macos pass.
```

The 27 byte-identity goldens are the cross-host canary, same gate that protected milestones 017 and 018.

## Common pitfalls

1. **Extracting `scan.rs` before `entry.rs`**. `scan.rs` needs `use super::entry::BinaryScan;` — that import resolves only after entry.rs exists as a module. Order matters.
2. **Forgetting to qualify call sites in `read()`**. After extracting `discover.rs`, `read()` still says `discover_binaries(...)` (unqualified). Cargo will error: "function not found in this scope." Update to `discover::discover_binaries(...)` in the same commit.
3. **Tests that use `BinaryScan` in mod.rs::tests**. The `claim_skip_*` and `inode_match_*` tests (which stay in mod.rs) don't reference `BinaryScan` — they test `is_path_claimed`. Confirmed by spot-checking the test bodies during reconnaissance. If a test that DOES reference `BinaryScan` ends up in mod.rs::tests, it needs `use super::entry::BinaryScan;` — verify during T-step.
4. **Sibling-module references like `super::elf` in moved code**. From entry.rs, `super::elf::ElfNotePackage` resolves to `binary/elf.rs` (existing sibling). This works because new submodules are direct siblings of `elf.rs`. No change needed — the imports just look like `use super::elf;` after move.
5. **`is_path_claimed` accidentally moved to scan.rs**. Per research.md R2, it stays in mod.rs. Don't move it just because it's a "predicate-shaped" function; its callers (read + external crate paths) make mod.rs the right home.

## After PR merge

- The post-019 baseline becomes the new `tests/scan_binary.rs` regression set.
- Update `docs/architecture/scanning.md` if it references `binary/mod.rs` as a single file (spot-check; not blocking the PR).
- Verify SC-006 the next time you fix a Mach-O fat-binary or PE-format bug — does `find binary -name 'scan*.rs'` jump straight to it? If yes, the milestone delivered.
