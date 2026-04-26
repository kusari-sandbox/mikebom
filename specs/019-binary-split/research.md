# Research: binary/mod.rs Split — Design-First

**Phase 0 output for** `/specs/019-binary-split/spec.md`

This document resolves the open technical questions from `plan.md`. Each section follows: **Decision** / **Rationale** / **Alternatives considered**. The lessons from milestone 018's deferred US3 inform every decision below.

---

## R1. Why 5 files instead of milestone-018's planned 4?

**Context**: Milestone 018's spec planned a 4-file split: `mod.rs` + `discover.rs` + `scan.rs` + `entry.rs`. Reconnaissance after #43 merged showed the inline `#[cfg(test)] mod tests` block in `binary/mod.rs` is ~700 LOC carrying 38 functions (37 tests + 1 helper). About 14 of those tests exercise OS-aware predicates (`RootfsKind`, `detect_rootfs_kind`, `is_host_system_path`, `has_rpmdb_at`, `is_os_managed_directory`) — a cohesive group of ~150 LOC of production code.

If those predicates stay in `mod.rs` along with their tests, the LOC math is:

```
production code (read + is_path_claimed + RootfsKind/predicates):  ~485
inline tests staying in mod.rs (22 of 38):                         ~600
total mod.rs:                                                     ~1085
```

That blows the FR-001 800-LOC ceiling.

**Decision**: Extract the OS-aware predicates and their tests into a fifth submodule `predicates.rs`. Post-split mod.rs lands at ~575 LOC.

**Rationale**:

- The predicates form a coherent group: every one of them answers "is this rootfs / file path part of the operating-system layer?" — used to filter binary scanning to user-space components and to skip OS-managed directories.
- Their 14 tests group equally cohesively (the test names cluster: `detect_rootfs_kind_*`, `has_rpmdb_at_*`, `is_os_managed_directory_*`, `is_host_system_path_*`).
- 150 LOC of production + ~200 LOC of tests = ~350 LOC for `predicates.rs` — comfortably under the 800-LOC ceiling, and the resulting `mod.rs` lands ~575 LOC also under the ceiling.
- An alternative — letting `mod.rs` exceed 800 — would require updating FR-001 to ~1100 (similar to how milestone 018's `requirements_txt.rs` got an exception). That carries weight; better to avoid it when a clean fifth submodule is right there.

**Alternatives considered**:

- **4-file split, accept mod.rs ~1100 LOC**: Rejected. The ceiling exists to bound reading cost. 1100 LOC is what the audit was trying to escape; landing within 200 LOC of the original size defeats the milestone's goal.
- **4-file split, prune tests**: Rejected. FR-005 requires tests preserved verbatim. Removing tests to fit under the ceiling violates the contract.
- **6+ file split (e.g., `predicates.rs` further subdivided into `rootfs_kind.rs` + `os_paths.rs`)**: Rejected as over-decomposition. The predicate group is cohesive — they all use `Path` introspection to classify; splitting further wouldn't improve readability.

---

## R2. Why does `is_path_claimed` stay in `mod.rs`?

**Context**: Milestone 018's plan suggested moving `is_path_claimed` into `scan.rs`. Reconnaissance shows three external crate-path callers (`maven.rs:2274`, `go_binary.rs:517`, `linkage.rs:45`) reference it as `crate::scan_fs::binary::is_path_claimed`. If we move it to `scan.rs`, callers see `crate::scan_fs::binary::scan::is_path_claimed` — a path change that either requires editing all 3 call sites OR adding a `pub(crate) use scan::is_path_claimed;` re-export in `mod.rs`.

**Decision**: **Keep `is_path_claimed` in `binary/mod.rs`** at its current `pub(crate)` visibility.

**Rationale**:

- It's called by `read()` (which stays in `mod.rs`) at line 363 — proximity to its primary internal caller is a value.
- External callers' paths don't change — FR-003 holds.
- Re-export via `pub(crate) use scan::is_path_claimed;` is a workable alternative but adds a synthetic layer that the next contributor has to chase when navigating call sites. Direct location is cleaner.
- The function's purpose ("did the package_db reader already claim this file path? → don't double-emit a binary component") sits at the orchestrator layer (combining package_db state with binary discovery), not the per-file scan layer. Logically it belongs at `mod.rs`, not `scan.rs`.

**Alternatives considered**:

- **Move to scan.rs + re-export**: Rejected per the proximity + clean-location argument.
- **Move to predicates.rs**: It IS a path-classification predicate. But its callers (`read` in mod.rs + tests for claim_skip / inode_match) tightly couple it to mod.rs's loop. Plus it's testable independent of OS-detection state, unlike the rootfs predicates. Different cohort.

---

## R3. Where does `BinaryScan` live?

**Context**: `pub(crate) struct BinaryScan` (line 626 in current `mod.rs`) is the intermediate type returned by `scan_binary` and `scan_fat_macho` (the per-file scanners) and consumed by `make_file_level_component` (the entry-conversion code). `scan_binary` lives in scan.rs post-split; `make_file_level_component` lives in entry.rs.

**Decision**: **`BinaryScan` lives in `entry.rs`.** `scan.rs` accesses it via `use super::entry::BinaryScan;`. Visibility stays `pub(crate)`.

**Rationale**:

- `entry.rs` is the conceptual "owner" of binary-scan-result modeling — it's where the BinaryScan→PackageDbEntry transformation happens. Putting the type next to its primary transformation is the natural location.
- `scan.rs` is the producer of `BinaryScan` values; it naturally imports the type from where the consumer lives.
- The alternative — keeping `BinaryScan` in `mod.rs` and having both `scan.rs` and `entry.rs` import it — is also workable but adds a cross-import for a type that's not used by `read()` itself.

**Alternatives considered**:

- **`BinaryScan` in scan.rs (the producer)**: Plausible. Producer-side ownership is also a valid pattern. Decided against because consumers traditionally outnumber producers; `entry.rs` will likely accumulate more code that wraps `BinaryScan` over time, and proximity to that growth makes more sense.
- **`BinaryScan` in mod.rs**: Rejected — would mean `mod.rs` owns a type that neither it nor `read()` directly consumes (post-split). Tracks against the goal of mod.rs being the orchestrator.
- **`BinaryScan` as its own file (`binary/scan_result.rs`)**: Over-decomposition. The type is a 15-line struct + 1 method; a dedicated file is junk-drawer-tier ceremony for that.

---

## R4. Visibility ladder

**Context**: Same rule as milestone 018: `pub(super) fn` for cross-sibling-only callers; `pub(crate)` reserved for items already at that level OR with legitimate crate-wide callers; `pub` only for the documented public surface (`fn read`).

**Decision**: Per `data-model.md` "Visibility ladder" table. Summary:

| Item | Pre-split | Post-split | File |
|---|---|---|---|
| `pub fn read` | `pub` | `pub` (unchanged) | mod.rs |
| `pub(crate) fn is_path_claimed` | `pub(crate)` | `pub(crate)` (unchanged) | mod.rs |
| `pub(crate) struct BinaryScan` | `pub(crate)` | `pub(crate)` (unchanged) | entry.rs |
| `pub(crate) fn detect_format` | `pub(crate)` | reduced to `fn` (private) — only caller is `is_supported_binary` in same file | discover.rs |
| `enum RootfsKind` | `enum` (private) | `pub(super) enum` — used by mod.rs's `read()` | predicates.rs |
| `fn detect_rootfs_kind` | `fn` | `pub(super) fn` — called from mod.rs's `read()` | predicates.rs |
| `fn is_host_system_path` | `fn` | `pub(super) fn` — called from mod.rs's `read()` | predicates.rs |
| `fn has_rpmdb_at` | `fn` | `pub(super) fn` — called from `detect_rootfs_kind` (same file, but also from mod.rs) | predicates.rs |
| `fn is_os_managed_directory` | `fn` | `pub(super) fn` — called from mod.rs's `read()` | predicates.rs |
| `fn discover_binaries` | `fn` | `pub(super) fn` — called from mod.rs's `read()` | discover.rs |
| `fn scan_binary` | `fn` | `pub(super) fn` — called from mod.rs's `read()` | scan.rs |
| `fn version_match_to_entry` | `fn` | `pub(super) fn` — called from mod.rs's `read()` | entry.rs |
| `fn make_file_level_component` | `fn` | `pub(super) fn` — called from mod.rs's `read()` | entry.rs |
| `fn note_package_to_entry` | `fn` | `pub(super) fn` — called from mod.rs's `read()` | entry.rs |

`detect_format`'s reduction from `pub(crate)` to private is unique. It's a misnamed item — currently `pub(crate)` but no external callers. Reconnaissance with `rg detect_format` shows only one site: line 901 inside `is_supported_binary` (same file post-split). Visibility *contraction* is normally out of scope (FR-006 says only expansion), but here it's correcting a stale `pub(crate)` that has no callers. Following the spirit of FR-006 ("minimum visibility needed"), I'll demote it to private.

Wait — actually let me reconsider. FR-006 explicitly says "Visibility contraction is out of scope." Strict reading says keep `detect_format` as `pub(crate)` even though it has no current external callers. I'll follow the strict rule: keep `pub(crate)`. Future contributor can demote if they're so inclined.

**Decision (revised)**: `detect_format` stays `pub(crate)` per FR-006 strict reading. Move it to `discover.rs` with visibility unchanged.

**Alternatives considered**:

- **Move all the OS predicates to `pub(super)` only when externally needed** (vs blanket pub(super) for everything in predicates.rs): Marginal preference; both work. Going with blanket `pub(super)` for predicates.rs because it makes the contract uniform — every fn in predicates.rs is reachable from mod.rs.
- **Make `BinaryScan` `pub` instead of `pub(crate)`**: Out of scope per FR-006 (no contraction). Keep `pub(crate)`.

---

## R5. Atomic-per-submodule commits, not incremental

**Context**: Milestone 018's deferred US3 attempt failed in part because it tried to extract submodules incrementally (one chunk at a time, leaving intermediate state where `binary/mod.rs` had partially-removed code AND a sibling file with the just-extracted version simultaneously). Rust's module system rejects this — name resolution conflicts kick in.

**Decision**: One atomic commit per submodule extraction. Within a commit, `mod.rs` and the new sibling file are both fully consistent. Five commits total: predicates.rs, then discover.rs, scan.rs, entry.rs, plus a final pre-PR / verification commit if needed.

**Rationale**:

- Same lesson as milestone 018's pip and npm splits (which followed this pattern and worked cleanly).
- Per-commit `./scripts/pre-pr.sh` passes (FR-008). Reviewers can `git diff <commit>~..<commit>` to see one logical chunk at a time.
- Cross-submodule dependencies are unidirectional: predicates.rs has no dependencies on the other new siblings; discover.rs depends on nothing new; scan.rs depends on entry.rs (for `BinaryScan`); entry.rs has no dependencies on the other new siblings. Order of extraction is therefore: predicates → discover → entry → scan (so scan can `use super::entry::BinaryScan`).

**Alternatives considered**:

- **One mega-commit for all 4 submodules**: Less reviewable. Per-submodule diff doesn't isolate one extraction's correctness.
- **Sub-commits per function within a submodule**: Rejected per the milestone-018 lesson. Half-moved state breaks compilation.

---

## R6. Verifying "no scan output drift"

**Context**: The 27 byte-identity goldens (`mikebom-cli/tests/fixtures/golden/{cyclonedx,spdx-2.3,spdx-3}/`) shipped in #38 + #40 are the canonical regression test for "scan output is unchanged."

**Decision**: After each commit on the milestone branch, run:

```bash
MIKEBOM_UPDATE_CDX_GOLDENS=1 cargo +stable test -p mikebom --test cdx_regression > /dev/null 2>&1
MIKEBOM_UPDATE_SPDX_GOLDENS=1 cargo +stable test -p mikebom --test spdx_regression > /dev/null 2>&1
MIKEBOM_UPDATE_SPDX3_GOLDENS=1 cargo +stable test -p mikebom --test spdx3_regression > /dev/null 2>&1
git diff --stat mikebom-cli/tests/fixtures/golden/   # MUST be empty
```

**Rationale**:

- Same gate that caught milestone 017's T013b emitter bug.
- Same gate that protected milestone 018's pip and npm splits.
- Same gate that confirmed #43's walker dedup didn't drift scan output.
- More stringent than `cargo test` alone, because the goldens are byte-comparison, not just "tests pass."

If a commit's regen produces a non-empty diff, the commit is wrong; reconcile before proceeding to the next submodule.

**Alternatives considered**:

- **Trust `cargo test` alone**: Rejected — `cargo test` doesn't catch byte-level drift in JSON output ordering, only assertion failures. Goldens catch what `cargo test` misses.
