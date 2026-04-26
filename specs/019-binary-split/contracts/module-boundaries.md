# Contract: Module Boundaries — `binary/`

**Phase 1 contract for** `/specs/019-binary-split/spec.md`

This document is the formal contract for the per-submodule entry points and visibility surface introduced by milestone 019. Anyone touching the `binary/` directory AFTER this milestone ships should preserve these boundaries.

## `binary/` directory module

### Public surface

```rust
// binary/mod.rs:
pub fn read(
    rootfs: &Path,
    deb_codename: Option<&str>,
    max_file_size: u64,
    deep_hash: bool,
    /* additional args */
) -> Vec<PackageDbEntry>;
```

External callers (1):
- `crate::scan_fs::mod.rs:218` — `binary::read(...)`

### Crate-visible surface

```rust
// binary/mod.rs (kept):
pub(crate) fn is_path_claimed(
    path: &Path,
    claimed: &HashSet<PathBuf>,
    inodes: &HashSet<(u64, u64)>,
) -> bool;

// binary/entry.rs (moved):
pub(crate) struct BinaryScan { /* fields */ }

// binary/discover.rs (moved):
pub(crate) fn detect_format(magic: &[u8]) -> Option<&'static str>;
```

External callers of `is_path_claimed` (3):
- `crate::scan_fs::package_db::maven.rs:2274`
- `crate::scan_fs::package_db::go_binary.rs:517`
- `crate::scan_fs::binary::linkage.rs:45` (sibling)

`BinaryScan` and `detect_format` have no external crate callers today. Their `pub(crate)` visibility is preserved per FR-006 (no contraction).

### Cross-sibling surface (`pub(super)` in submodules)

```rust
// binary/predicates.rs:
pub(super) enum RootfsKind { /* variants */ }
pub(super) fn detect_rootfs_kind(rootfs: &Path) -> RootfsKind;
pub(super) fn is_host_system_path(soname: &str) -> bool;
pub(super) fn has_rpmdb_at(rootfs: &Path) -> bool;
pub(super) fn is_os_managed_directory(rootfs: &Path, path: &Path) -> bool;

// binary/discover.rs:
pub(super) fn discover_binaries(root: &Path) -> Vec<PathBuf>;

// binary/scan.rs:
pub(super) fn scan_binary(path: &Path, bytes: &[u8]) -> Option<BinaryScan>;

// binary/entry.rs:
pub(super) fn version_match_to_entry(/* args */) -> Option<PackageDbEntry>;
pub(super) fn make_file_level_component(scan: &BinaryScan, /* args */) -> PackageDbEntry;
pub(super) fn note_package_to_entry(note: &elf::ElfNotePackage, /* args */) -> Option<PackageDbEntry>;
```

All called from `mod.rs::read()` — single sibling caller, hence `pub(super)` is the minimum.

### Module declarations

`binary/mod.rs` declares:

```rust
// EXISTING — unchanged:
pub mod elf;
pub mod jdk_collapse;
pub mod linkage;
pub mod macho;            // stub
pub mod packer;           // stub
pub mod pe;               // stub
pub mod python_collapse;
pub mod version_strings;  // stub

// NEW (this milestone):
mod discover;
mod entry;
mod predicates;
mod scan;
```

The new submodules are NOT declared `pub mod` because nothing outside the `binary/` directory references them by path — all access is through `mod.rs`'s `pub fn read` and `pub(crate) fn is_path_claimed`.

### Orchestration contract

`binary::read` runs:

1. `predicates::detect_rootfs_kind(rootfs)` → tags the rootfs's package-management style.
2. `discover::discover_binaries(rootfs)` → list of candidate file paths.
3. For each candidate: `scan::scan_binary(path, bytes)` → `Option<BinaryScan>`.
4. For each scan result: convert to `PackageDbEntry` via `entry::version_match_to_entry` / `entry::make_file_level_component` / `entry::note_package_to_entry`.
5. Apply cross-cutting predicates (`predicates::is_host_system_path`, `predicates::is_os_managed_directory`) before final dedup.
6. Apply `is_path_claimed` to filter out files the package_db readers already claimed.

The `linkage::dedup_globally` pass (in the existing sibling `binary/linkage.rs`) runs at the end — unchanged from pre-split.

---

## Visibility expansion rules

Same as milestone 018:

1. **First choice**: `pub(super) fn` for sibling-only access.
2. **Second choice**: move the item into `mod.rs` if used by ≥ 2 sibling submodules (none in this milestone).
3. **NEVER**: `pub` for items not in the documented public surface above.

---

## Anti-patterns to avoid

- **Adding a `mod.rs::pub use scan::is_path_claimed;` re-export to "make symmetry"**. `is_path_claimed` lives in `mod.rs` directly per research.md R2. Re-exporting from a submodule it doesn't live in is misleading.
- **Reducing `BinaryScan` to private**. It's `pub(crate)` for a reason (internal-to-crate sharing across `binary/` and potentially `package_db/` in future enrichments). Don't tighten without thinking.
- **Moving `is_path_claimed` to `predicates.rs`**. It's path-classification-shaped but its callers (`read()` and external crate paths) couple it to mod.rs's loop. Different cohort from the OS-aware predicates.
- **Renaming `pub fn read`**. External callers depend on the path; don't change it without a separate milestone.
- **Adding `pub mod` for the new submodules**. Nothing outside `binary/` should reference `discover::*` / `scan::*` / `entry::*` / `predicates::*` directly. All access is through `mod.rs`.
