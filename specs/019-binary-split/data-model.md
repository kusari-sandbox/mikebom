# Data Model: binary/mod.rs Split

**Phase 1 output for** `/specs/019-binary-split/spec.md`

## Scope

Source-tree refactor only — no new runtime data. The only artifacts captured here are (a) the per-item visibility ladder mapping every existing item in `binary/mod.rs` to its target submodule + post-split visibility, and (b) the inline-test distribution table.

---

## Visibility ladder

**Pre-split file**: `mikebom-cli/src/scan_fs/binary/mod.rs` (1858 LOC)

**Post-split**: `binary/mod.rs` (~575 LOC) + 4 new siblings.

### Items staying in `binary/mod.rs`

| Pre-split item | Visibility | Post-split visibility | Reason |
|---|---|---|---|
| `pub fn read(rootfs, deb_codename, max_file_size, deep_hash, ...)` | `pub` | `pub` (unchanged) | External caller in `scan_fs/mod.rs:218` |
| `pub(crate) fn is_path_claimed(path, claimed, inodes)` | `pub(crate)` | `pub(crate)` (unchanged) | External callers in `maven.rs:2274`, `go_binary.rs:517`, `linkage.rs:45`. Stays in mod.rs to keep callers' paths stable (per research.md R2). |

### Items landing in `binary/predicates.rs` (NEW)

| Pre-split item | Pre-split visibility | Post-split visibility | Reason |
|---|---|---|---|
| `enum RootfsKind` | `enum` (private) | `pub(super) enum` | Used by `read()` in mod.rs |
| `fn detect_rootfs_kind(rootfs) -> RootfsKind` | `fn` | `pub(super) fn` | Called from `read()` |
| `fn is_host_system_path(soname) -> bool` | `fn` | `pub(super) fn` | Called from `read()` (filtering linkage entries) |
| `fn has_rpmdb_at(rootfs) -> bool` | `fn` | `pub(super) fn` | Called from `detect_rootfs_kind` (same file) AND from `read()` |
| `fn is_os_managed_directory(rootfs, path) -> bool` | `fn` | `pub(super) fn` | Called from `read()` (skip-list construction) |

### Items landing in `binary/discover.rs` (NEW)

| Pre-split item | Pre-split visibility | Post-split visibility | Reason |
|---|---|---|---|
| `fn discover_binaries(root) -> Vec<PathBuf>` | `fn` | `pub(super) fn` | Called from `read()` |
| `fn walk_dir(dir, &mut Vec<PathBuf>)` | `fn` | `fn` (private) | Only called from `discover_binaries` (same file) |
| `fn is_supported_binary(path) -> bool` | `fn` | `fn` (private) | Only called from `walk_dir` (same file) |
| `pub(crate) fn detect_format(magic) -> Option<&'static str>` | `pub(crate)` | `pub(crate)` (unchanged per FR-006 strict reading) | Currently unused externally but visibility-contraction is out of scope |

### Items landing in `binary/scan.rs` (NEW)

| Pre-split item | Pre-split visibility | Post-split visibility | Reason |
|---|---|---|---|
| `fn scan_binary(path, bytes) -> Option<BinaryScan>` | `fn` | `pub(super) fn` | Called from `read()` |
| `fn scan_fat_macho(path, bytes) -> Option<BinaryScan>` | `fn` | `fn` (private) | Only called from `scan_binary` (same file) |
| `fn collect_string_region(file, class) -> Vec<u8>` | `fn` | `fn` (private) | Only called from `scan_binary` (same file) |
| `fn is_go_binary(bytes) -> bool` | `fn` | `fn` (private) | Only called from `scan_binary` (same file) |

### Items landing in `binary/entry.rs` (NEW)

| Pre-split item | Pre-split visibility | Post-split visibility | Reason |
|---|---|---|---|
| `pub(crate) struct BinaryScan { ... }` | `pub(crate)` | `pub(crate)` (unchanged) | Used by `scan.rs::scan_binary` (constructs it) and `entry.rs::make_file_level_component` (consumes it) |
| `fn version_match_to_entry(...)` | `fn` | `pub(super) fn` | Called from `read()` |
| `fn make_file_level_component(scan: &BinaryScan, ...)` | `fn` | `pub(super) fn` | Called from `read()` |
| `fn note_package_to_entry(note, ...)` | `fn` | `pub(super) fn` | Called from `read()` |
| `impl PackageDbEntry { ... }` | `impl` | `impl` (unchanged) | The methods stay attached to the type; the impl block lands in entry.rs and Rust resolves the type via path |

---

## Cross-submodule import inventory

Concrete `use` lines that each new submodule needs at the top:

### `binary/predicates.rs`

```rust
use std::path::Path;
```

No cross-submodule dependencies. Self-contained.

### `binary/discover.rs`

```rust
use std::path::{Path, PathBuf};
```

No cross-submodule dependencies. Self-contained.

### `binary/scan.rs`

```rust
use std::path::Path;

use mikebom_common::types::hash::ContentHash;
use mikebom_common::types::purl::Purl;
use object::ObjectSection;
use sha2::{Digest, Sha256};

use super::entry::BinaryScan;       // cross-sibling type
use super::elf;                     // existing sibling
use super::packer;                  // existing sibling
use super::version_strings;         // existing sibling
use super::super::package_db::rpm_vendor_from_id;  // ../package_db
```

### `binary/entry.rs`

```rust
use std::path::Path;

use mikebom_common::types::hash::ContentHash;
use mikebom_common::types::purl::Purl;
use object::ObjectSection;
use sha2::{Digest, Sha256};

use super::elf::ElfNotePackage;     // BinaryScan struct depends on ElfNotePackage
use super::super::package_db::{rpm_vendor_from_id, PackageDbEntry};
```

### `binary/mod.rs` (post-split, header)

```rust
use std::path::{Path, PathBuf};

use mikebom_common::types::hash::ContentHash;
use mikebom_common::types::purl::Purl;
// (object, sha2 may drop here if no longer used directly in mod.rs)

use super::package_db::PackageDbEntry;
// (rpm_vendor_from_id moves out — no longer needed in mod.rs)

mod discover;
mod entry;
mod predicates;
mod scan;
```

---

## Inline test distribution

Per FR-005, the 38 inline tests in `binary/mod.rs::tests` distribute by which production code each test exercises. Names preserved verbatim.

### Tests staying in `binary/mod.rs::tests` (8)

These exercise `read()` orchestration and `is_path_claimed`:

- `empty_rootfs_yields_zero_binary_components`
- `non_elf_files_are_skipped`
- `claim_skip_recognizes_usrmerge_symlink_path`
- `claim_skip_without_symlink_still_works`
- `claim_skip_broken_symlink_does_not_panic`
- `claim_skip_via_inode_on_symlinked_library`
- `inode_match_survives_hard_link`
- (one more to be confirmed during T-step verification)

### Tests landing in `binary/predicates.rs::tests` (14)

These exercise `RootfsKind` / `detect_rootfs_kind` / `has_rpmdb_at` / `is_os_managed_directory` / `is_host_system_path`:

- `detect_rootfs_kind_alpine_from_apk_db`
- `detect_rootfs_kind_debian_from_dpkg_status`
- `detect_rootfs_kind_rhel_from_rpmdb`
- `detect_rootfs_kind_fedora_sysimage_path`
- `detect_rootfs_kind_from_os_release_id`
- `detect_rootfs_kind_unknown_for_plain_directory`
- `has_rpmdb_at_detects_legacy_var_lib_path`
- `has_rpmdb_at_detects_sysimage_path`
- `has_rpmdb_at_returns_false_on_bare_rootfs`
- `has_rpmdb_at_detects_legacy_bdb_packages_file`
- `is_host_system_path_blocks_macos_frameworks`
- `is_host_system_path_allows_real_sonames`
- `is_os_managed_directory_matches_standard_paths`
- `is_os_managed_directory_allows_opt_and_local_paths`

### Tests landing in `binary/scan.rs::tests` (4)

These exercise `is_go_binary`:

- `is_go_binary_detects_buildinfo_magic`
- `is_go_binary_returns_false_without_magic`
- `is_go_binary_detects_magic_past_old_2mb_cap`
- `is_go_binary_bounded_probe_at_64mb`

### Tests landing in `binary/entry.rs::tests` (12)

These exercise `note_package_to_entry`, `make_file_level_component`, and the `fake_binary_scan` helper:

- `note_package_rpm_produces_canonical_purl`
- `note_package_rpm_uses_os_release_namespace_when_note_distro_absent`
- `note_package_rpm_prefers_note_distro_over_os_release`
- `note_package_rpm_percent_encodes_plus_in_name`
- `note_package_rpm_percent_encodes_mid_name_plus`
- `note_package_rpm_falls_back_to_rpm_when_no_context`
- `note_package_alpm_uses_arch_namespace`
- `note_package_deb_falls_back_to_debian_vendor`
- `note_package_deb_uses_os_release_namespace_for_ubuntu`
- `note_package_unknown_type_becomes_generic`
- `make_file_level_component_sets_detected_go_when_flag_set`
- `make_file_level_component_leaves_detected_go_none_for_non_go`
- `fake_binary_scan` (helper — used by `make_file_level_component_*` tests)

### Tests landing in `binary/discover.rs::tests` (0)

The current inline test mod has no specific tests for `discover_binaries`, `walk_dir`, `is_supported_binary`, or `detect_format`. The `tests/scan_binary.rs` integration test exercises them end-to-end. No inline tests move to `discover.rs::tests`.

---

## Validation rules

- Every item in pre-split `binary/mod.rs` MUST have a row in the appropriate visibility-ladder table above. A code reviewer can verify completeness by `git diff --stat` showing the original file shrinking and the four new files appearing with summed LOC ≈ pre-split + ~150 (mod declarations / `use` lines / per-file headers).
- Every visibility ladder entry MUST be the minimum needed for the post-split call graph. `pub(super)` for sibling-only callers; `pub(crate)` only for items already at that level (per FR-006 strict reading).
- Inline test names MUST be preserved verbatim. SC-002 enforces with sorted-name diff against post-#43 baseline.
