# Quickstart: Implement and Verify Milestone 016

**Phase 1 quickstart for** `/specs/016-remaining-clippy-cleanup/spec.md`

This document is the cookbook for a contributor (the maintainer, in practice) to triage one warning, then to verify the whole feature end-to-end.

## Prerequisites

- macOS dev machine with stable Rust + clippy installed.
- Repo checked out at `main`, branch `016-remaining-clippy-cleanup` already created (matches the spec).
- `cargo +stable clippy --workspace --all-targets` runs successfully (current state: 192 warnings).

## Workflow per warning

The triage loop, applied to one warning at a time:

```bash
# 1. Snapshot the current warning set.
cargo +stable clippy --workspace --all-targets 2>/tmp/clippy.txt
grep -c '^warning:' /tmp/clippy.txt
# Output: 192 (initially); should drop after each fix

# 2. Pick the topmost dead-code or doc-list warning.
grep '^warning:' /tmp/clippy.txt | head -3

# 3. Open the file at the cited line. Decide its tier:
#    - Tier A: Only used from #[cfg(target_os = "linux")] scopes
#              → add #[cfg(target_os = "linux")] to the item.
#    - Tier B: Used cross-platform but dead on macOS
#              → add #[cfg_attr(not(target_os = "linux"), allow(dead_code))].
#    - Tier C: Zero callers anywhere
#              → grep -rn "<item_name>" mikebom-cli mikebom-common mikebom-ebpf
#              → if zero hits, delete the item.
#    - Doc-list: prose mixing sub-bullets and continuation
#              → add a blank `///` line after sub-bullets, OR
#              → reformat sub-bullets to be properly indented under the parent.

# 4. Apply the fix.

# 5. Verify the warning is gone AND no new warning appeared.
cargo +stable clippy --workspace --all-targets 2>/tmp/clippy.txt
grep -c '^warning:' /tmp/clippy.txt
# Output should be N-1 (or N-K if the fix collapsed multiple warnings, e.g.,
# cfg-gating a struct also silences warnings on its associated impl).

# 6. Run tests (mandatory after every cluster of fixes).
cargo +stable test --workspace 2>&1 | grep "test result" | grep -v "0 failed"
# Output should be empty (no failed test results).

# 7. Commit per logical chunk (e.g., "cleanup: gate trace/* items behind cfg(linux)").
git add -p && git commit
```

## Recommended commit chunking

To make the PR reviewable per SC-005, commit in logical chunks rather than one big bang:

| Chunk                                       | Approximate warning count cleared | Commit message                                                                            |
|---------------------------------------------|-----------------------------------:|-------------------------------------------------------------------------------------------|
| 1. Doc-list restructuring                   | ~37                                | `cleanup: restructure doc comments to fix doc_lazy_continuation`                          |
| 2. `mikebom-cli/src/trace/*` Linux-only gates | ~50                              | `cleanup: cfg-gate trace/* items behind target_os = "linux"`                              |
| 3. `mikebom-cli/src/attestation/*` triage   | ~50                                | `cleanup: gate attestation/* Linux-only items; remove orphan helpers; annotate scaffolding` |
| 4. `mikebom-cli/src/{enrich,resolve}/*` orphans | ~30                            | `cleanup: remove orphaned enrich/resolve helpers (no callers post-#17)`                   |
| 5. `mikebom-cli/src/{cli,scan_fs,config.rs}` long tail | ~25                     | `cleanup: triage remaining dead-code warnings in cli/scan_fs/config`                       |
| 6. `field_reassign_with_default` (3 sites)  | 3                                  | `cleanup: justify field_reassign_with_default in elf.rs + pip.rs`                         |
| 7. CI workflow + constitution update        | (gate flip)                        | `ci: add macos-latest job; deny clippy warnings; bump constitution 1.3.0 → 1.3.1`         |

Each chunk's commit MUST leave the tree green (`cargo clippy + cargo test` pass per chunk; final-state warning count drops monotonically).

## Final-state verification (acceptance test)

After all chunks land, before opening PR:

```bash
# (a) Local zero-warnings check on macOS.
cargo +stable clippy --workspace --all-targets 2>/tmp/clippy-final.txt
test "$(grep -c '^warning:' /tmp/clippy-final.txt)" = "0"
# Should pass.

# (b) Local zero-warnings check via the new gate command.
cargo +stable clippy --workspace --all-targets -- -D warnings
# Should exit 0.

# (c) Full test suite green.
cargo +stable test --workspace 2>&1 | tee /tmp/tests.txt
grep -c "test result: ok" /tmp/tests.txt
# Should match the count from PR #33's baseline (1385 passed total — but the
# count of "test result" LINES is what we compare; today that's ~50 lines).
grep "test result:" /tmp/tests.txt | grep -v "0 failed" | wc -l
# Output: 0 (no failed-test result lines).
```

## CI verification

After pushing the branch:

```bash
# Watch the workflow run.
gh run watch
# Expect: both lint-and-test (linux-x86_64) AND lint-and-test-macos pass.
```

Optional one-time verification of SC-003 (the gate actually catches new warnings):

```bash
# On a throwaway branch off this feature:
git checkout -b 016-deliberate-warning-probe
echo "pub fn deliberate_dead_code() {}" >> mikebom-cli/src/lib.rs
git commit -am "probe: deliberate dead-code (will close, do not merge)"
git push -u origin 016-deliberate-warning-probe
# Open the probe PR. Confirm both jobs fail with the dead_code warning
# annotated on the new line. Close PR without merging; delete branch.
```

This step is performed once during this milestone's implementation, then the probe branch and PR are discarded.

## Common pitfalls

1. **Cfg-gate cascade**: gating a struct sometimes triggers `dead_code` on its `impl` blocks if those aren't gated too. Use `cargo +stable check --workspace` after each gate to catch cascade quickly; clippy will flag the cascade with the same vocabulary.
2. **Test-only items**: an item used only inside `#[cfg(test)]` modules but defined outside them produces dead-code warnings in non-test builds. Move the item INTO the test module if possible; otherwise use `#[cfg_attr(not(test), allow(dead_code))]`.
3. **Cross-platform `pub fn`**: a `pub fn` that's "dead" on macOS may actually be reachable through the binary's main module. Run `grep -rn "<fn_name>" .` (excluding `target/`) — if anything in `mikebom-cli/src/main.rs`, `mikebom-cli/src/cli/`, or `mikebom-cli/tests/` calls it, it's NOT dead; use Tier B annotation instead.
4. **`#[allow(dead_code)]` orphans**: the existing tree has a handful of these annotations (e.g., `mikebom-cli/src/generate/spdx/packages.rs:68`). Re-evaluate each — if its planned consumer landed, remove the `#[allow]`; if it never landed, the annotated item itself is a Tier C deletion candidate.
5. **Doc-list restructuring leaks behavioral changes**: doc comments are *only* compiled for rustdoc, but mixing up `#[doc = "..."]` with the surrounding code can break invocations like `#[doc(hidden)]`. Verify after restructuring with `cargo doc --workspace --no-deps` — should succeed without warnings.

## After PR merge

- Verify on the next 30-day workflow-log spot check (per SC-006) that no PR has slipped a warning past the gate.
- Re-evaluate the macOS CI runtime cost; if it's adding excessive minutes (>10 min per PR), consider switching to `paths-ignore: ['docs/**']` or deferring the macOS job to push-to-main only.
