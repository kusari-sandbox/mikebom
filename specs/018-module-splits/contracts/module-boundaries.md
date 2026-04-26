# Contract: Module Boundaries — pip / npm / binary

**Phase 1 contract for** `/specs/018-module-splits/spec.md`

This document is the formal contract for the per-submodule entry points and visibility surface introduced by milestone 018. Anyone touching one of the three split directories AFTER this milestone ships should preserve these boundaries; departures need a follow-up milestone, not a silent edit.

## `pip/` directory module

### Public surface (re-exported from `pip/mod.rs`)

```rust
// In pip/mod.rs:
pub fn read(rootfs: &Path, include_dev: bool) -> Vec<PackageDbEntry>;
pub fn collect_claimed_paths(rootfs: &Path, include_dev: bool) -> Vec<PathBuf>;
// Plus any types previously pub from pip.rs (e.g., PipDistInfoEntry if it was pub).
```

External callers import `crate::scan_fs::package_db::pip::{read, collect_claimed_paths}` exactly as they did before the split. The PR's visibility-ladder check (per data-model.md) verifies no external caller's import path changes.

### Cross-sibling surface (`pub(super)` items in submodules)

```rust
// pip/mod.rs declares:
mod dist_info;
mod poetry;
mod pipfile;
mod requirements_txt;

// pip/dist_info.rs exposes:
pub(super) fn read_venv_dist_info(rootfs: &Path) -> Vec<PackageDbEntry>;

// pip/poetry.rs exposes:
pub(super) fn read_poetry_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>>;

// pip/pipfile.rs exposes:
pub(super) fn read_pipfile_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>>;

// pip/requirements_txt.rs exposes:
pub(super) fn read_requirements_files(rootfs: &Path) -> Option<Vec<PackageDbEntry>>;

// pip/mod.rs additionally hosts cross-sibling helpers:
pub(super) fn build_pypi_purl_str(name: &str, version: &str) -> String;
pub(super) fn should_skip_python_descent(name: &str) -> bool;
```

### Orchestration contract

`pip::read` runs the four parsers in this order, merging each result into the running set via `merge_without_override`:

1. `read_venv_dist_info` (PEP 376 venv first — most authoritative for installed packages)
2. `read_poetry_lock` (Poetry-managed projects)
3. `read_pipfile_lock` (Pipenv-managed projects)
4. `read_requirements_files` (legacy / heterogeneous)

Order matters for the merge semantics. Future contributors changing the order MUST regenerate the byte-identity goldens AND document the change in the PR description (the same regen-decision-record discipline as 017).

---

## `npm/` directory module

### Public surface (re-exported from `npm/mod.rs`)

```rust
// In npm/mod.rs:
pub enum NpmError { /* variants unchanged */ }
pub fn read(...) -> Result<Vec<PackageDbEntry>, NpmError>;
```

### Cross-sibling surface

```rust
// npm/mod.rs declares:
mod package_lock;
mod pnpm_lock;
mod walk;
mod enrich;

// npm/package_lock.rs exposes:
pub(super) fn read_package_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>>;

// npm/pnpm_lock.rs exposes:
pub(super) fn read_pnpm_lock(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>>;

// npm/walk.rs exposes:
pub(super) fn read_node_modules(...) -> Option<Vec<PackageDbEntry>>;
pub(super) fn read_root_package_json(rootfs: &Path, include_dev: bool) -> Option<Vec<PackageDbEntry>>;

// npm/enrich.rs exposes:
pub(super) fn enrich_entries_with_installed_authors(...);

// npm/mod.rs additionally hosts cross-sibling helpers:
pub(super) fn build_npm_purl(name: &str, version: &str) -> Option<Purl>;
pub(super) fn should_skip_descent(name: &str) -> bool;
```

### Orchestration contract

`npm::read` runs the parsers in this order:

1. `read_package_lock` (lockfile v2/v3 — most authoritative)
2. `read_pnpm_lock` (pnpm projects)
3. `read_node_modules` (flat-walk for installed packages, post-lockfile)
4. `read_root_package_json` (project root metadata)
5. `enrich_entries_with_installed_authors` (post-merge enrichment)

Same regen-discipline rule as pip applies if the order changes.

---

## `binary/` directory module

### Public surface (`binary/mod.rs`)

```rust
// Unchanged from pre-split:
pub fn read(...) -> Vec<PackageDbEntry>;
```

### Cross-sibling surface

```rust
// binary/mod.rs declares (in addition to existing siblings):
mod discover;
mod scan;
mod entry;
// (existing siblings stay declared: linkage, elf, go_binary, python_collapse)

// binary/discover.rs exposes:
pub(super) fn discover_binaries(root: &Path) -> Vec<PathBuf>;

// binary/scan.rs exposes:
pub(super) fn scan_binary(path: &Path, bytes: &[u8]) -> Option<BinaryScan>;

// binary/entry.rs exposes:
pub(super) fn version_match_to_entry(...) -> Option<PackageDbEntry>;
pub(super) fn make_file_level_component(...) -> PackageDbEntry;
pub(super) fn note_package_to_entry(...) -> Option<PackageDbEntry>;
```

### Orchestration contract

`binary::read` runs:

1. `detect_rootfs_kind(rootfs)` (in `mod.rs`)
2. `discover_binaries(root)` → list of candidate file paths (in `discover.rs`)
3. For each candidate: `scan_binary(path, bytes)` → `Option<BinaryScan>` (in `scan.rs`)
4. For each scan result: convert to `PackageDbEntry` via `version_match_to_entry` / `make_file_level_component` / `note_package_to_entry` (in `entry.rs`)
5. Apply cross-cutting predicates (`is_host_system_path`, `is_os_managed_directory`) before final dedup (in `mod.rs`)

The existing siblings (`linkage.rs`, `elf.rs`, `go_binary.rs`, `python_collapse.rs`) are consumed by `scan.rs` and `entry.rs` per their existing visibility — no changes to those files in this milestone.

---

## Visibility expansion rules

When a contributor needs to make a previously-private item reachable from a sibling:

1. **First choice**: `pub(super) fn` in the sibling, called via the sibling's module path.
2. **Second choice**: move the item into `mod.rs` and mark `pub(super)` if it's used by ≥ 2 sibling submodules.
3. **NEVER**: `pub` (without `(super)`) for items not part of the documented public surface above. `pub` opens the item to the entire `mikebom-cli` crate, which is over-exposure.

When a contributor needs to expose a previously-private item to the rest of `mikebom-cli` (e.g., a new caller in `scan_fs/mod.rs`):

1. **First choice**: `pub(crate) fn` in the submodule + `pub(crate) use` re-export from `mod.rs`.
2. **NEVER**: `pub` re-export unless the item is part of the milestone-stable public surface (which requires its own follow-up to update this contract).

---

## Anti-patterns to avoid

These are not blockers (the byte-identity goldens catch behavioral drift), but they're style violations that defeat the milestone's readability goal:

- **`pub use` glob re-exports** (`pub use poetry::*;` from `mod.rs`). Defeats the per-module visibility surface; reviewers can't see what's exposed without expanding the wildcard. Use explicit `pub use poetry::read_poetry_lock;` if absolutely needed.
- **Helper modules named `util.rs` / `helpers.rs` / `common.rs`**. Junk-drawer risk. If a helper is shared by 2+ siblings, it lands in `mod.rs`. If by 1 sibling, it lives in that sibling.
- **Cross-directory imports** (`use crate::scan_fs::package_db::pip::poetry::poetry_is_dev;` from `npm/`). Tight coupling between unrelated ecosystems. If pip and npm legitimately share a helper, it goes into a shared module (e.g., `package_db/common.rs`) — but defer that to a follow-up milestone if the need arises.
- **Public surface contraction without a milestone**. Don't downgrade `pub fn collect_claimed_paths` to `pub(crate)` even if you observe no external caller. Visibility downgrades are a separate concern that warrants their own discussion (Constitution Principle V — specification compliance).
