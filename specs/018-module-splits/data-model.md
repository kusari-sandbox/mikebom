# Data Model: Module Splits — pip.rs, npm.rs, binary/mod.rs

**Phase 1 output for** `/specs/018-module-splits/spec.md`

## Scope

This milestone has minimal "data" — it's a source-tree refactor with zero behavioral changes. The single artifact this document captures is the **per-item visibility ladder**: every function, struct, or constant in the three target files, where it lands post-split, and what visibility it carries. A code reviewer can use this table to verify "this `fn` became `pub(super)` because it's called from sibling X."

A second artifact captures the **inline-test placement decisions**: which `#[cfg(test) mod tests` test blocks move into which post-split submodule.

---

## Visibility ladder — pip.rs split

**Pre-split file**: `mikebom-cli/src/scan_fs/package_db/pip.rs` (1965 LOC)

**Post-split directory**: `mikebom-cli/src/scan_fs/package_db/pip/`

### Items landing in `pip/mod.rs` (orchestrator + cross-sibling helpers)

| Pre-split item | Visibility | Reason |
|---|---|---|
| `pub fn read(rootfs, include_dev) -> Vec<PackageDbEntry>` | `pub` | External callers (`scan_fs/mod.rs`) |
| `pub fn collect_claimed_paths(rootfs) -> Vec<PathBuf>` | `pub` | External caller |
| `fn build_pypi_purl_str(name, version) -> String` | `pub(super)` | Used by every parser submodule |
| `fn candidate_python_project_roots(rootfs) -> Vec<PathBuf>` | `fn` (private) | Called only from `read()` |
| `fn walk_for_python_roots(...)` | `fn` | Called only from `candidate_python_project_roots` |
| `fn has_python_project_marker(dir) -> bool` | `fn` | Called only from walker (in same file) |
| `fn should_skip_python_descent(name) -> bool` | `pub(super)` | Used by walkers in dist-info AND requirements walks |
| `fn merge_without_override(base, incoming) -> ...` | `fn` | Called only from `read()` post-each-parser |

### Items landing in `pip/dist_info.rs` (PEP 376 venv walker)

| Pre-split item | Visibility | Reason |
|---|---|---|
| `fn read_venv_dist_info(rootfs) -> Vec<PackageDbEntry>` | `pub(super) fn` | Called from `pip/mod.rs::read` |
| `fn candidate_site_packages_roots(rootfs) -> Vec<PathBuf>` | `fn` | Called only from `read_venv_dist_info` |
| `fn find_site_packages_under(base) -> Vec<PathBuf>` | `fn` | Called only from `candidate_site_packages_roots` |
| `fn parse_dist_info_dir(dist_info) -> Option<PackageDbEntry>` | `fn` | Called only from `read_venv_dist_info` |
| `struct PipDistInfoEntry` + `impl PipDistInfoEntry` | `struct` (private) | If pre-split was private. If was `pub`, becomes `pub` and re-exported from `pip/mod.rs`. |

### Items landing in `pip/poetry.rs` (poetry.lock parser)

| Pre-split item | Visibility | Reason |
|---|---|---|
| `fn read_poetry_lock(rootfs, include_dev) -> Option<Vec<PackageDbEntry>>` | `pub(super) fn` | Called from `pip/mod.rs::read` |
| `fn poetry_is_dev(tbl) -> Option<bool>` | `fn` | Called only from `read_poetry_lock` |

### Items landing in `pip/pipfile.rs` (Pipfile.lock parser)

| Pre-split item | Visibility | Reason |
|---|---|---|
| `fn read_pipfile_lock(rootfs, include_dev) -> Option<Vec<PackageDbEntry>>` | `pub(super) fn` | Called from `pip/mod.rs::read` |

### Items landing in `pip/requirements_txt.rs` (requirements.txt parser)

| Pre-split item | Visibility | Reason |
|---|---|---|
| `fn read_requirements_files(rootfs) -> Option<Vec<PackageDbEntry>>` | `pub(super) fn` | Called from `pip/mod.rs::read` |
| `struct RequirementsTxtEntry` + `impl RequirementsTxtEntry` | `struct` (private) | Used only inside this submodule |
| `fn parse_requirements_line(line) -> Option<RequirementsTxtEntry>` | `fn` | Used only inside this submodule (also tested) |
| `fn parse_hash_flags(line) -> Vec<ContentHash>` | `fn` | Used only inside this submodule |
| `fn parse_hash_alg(s) -> Option<HashAlgorithm>` | `fn` | Used only inside this submodule |
| `fn egg_fragment(url) -> Option<String>` | `fn` | Used only inside this submodule |
| `fn pinned_version_from(body) -> Option<String>` | `fn` | Used only inside this submodule |
| `fn marker_probably_matches(marker) -> bool` | `fn` | Used only inside this submodule |

---

## Visibility ladder — npm.rs split

**Pre-split file**: `mikebom-cli/src/scan_fs/package_db/npm.rs` (1616 LOC)

**Post-split directory**: `mikebom-cli/src/scan_fs/package_db/npm/`

### Items landing in `npm/mod.rs`

| Pre-split item | Visibility | Reason |
|---|---|---|
| `pub enum NpmError` | `pub` | External callers may match on it |
| `pub fn read(...)` | `pub` | External caller |
| `fn candidate_project_roots(rootfs) -> Vec<PathBuf>` | `fn` | Called only from `read()` |
| `fn walk_for_project_roots(...)` | `fn` | Called only from `candidate_project_roots` |
| `fn should_skip_descent(name) -> bool` | `pub(super)` | Used by both lockfile parsers + node_modules walk |
| `fn has_npm_signal(dir) -> bool` | `fn` (private) | Called only from `read()` walkers |
| `struct NpmIntegrity` + `impl NpmIntegrity` | `struct` (private) | Used inside `mod.rs` for integrity-string parsing |
| `fn base64_decode(input) -> Option<Vec<u8>>` | `fn` | Used only by integrity parsing |
| `fn build_npm_purl(name, version) -> Option<Purl>` | `pub(super) fn` | Used by every parser submodule |

### Items landing in `npm/package_lock.rs`

| Pre-split item | Visibility | Reason |
|---|---|---|
| `fn read_package_lock(rootfs, include_dev) -> Option<Vec<PackageDbEntry>>` | `pub(super) fn` | Called from `npm/mod.rs::read` |
| `fn derive_name_from_path_key(key) -> String` | `fn` | Used only inside this submodule (also tested) |

### Items landing in `npm/pnpm_lock.rs`

| Pre-split item | Visibility | Reason |
|---|---|---|
| `fn read_pnpm_lock(rootfs, include_dev) -> Option<Vec<PackageDbEntry>>` | `pub(super) fn` | Called from `npm/mod.rs::read` |
| `fn parse_pnpm_key(key) -> Option<(String, String)>` | `fn` | Used only inside this submodule (also tested) |

### Items landing in `npm/walk.rs`

| Pre-split item | Visibility | Reason |
|---|---|---|
| `fn read_node_modules(...)` | `pub(super) fn` | Called from `npm/mod.rs::read` |
| `fn walk_node_modules(...)` | `fn` | Called only from `read_node_modules` |
| `fn read_root_package_json(rootfs, include_dev) -> Option<Vec<PackageDbEntry>>` | `pub(super) fn` | Called from `npm/mod.rs::read` |
| `fn classify_npm_source(range) -> Option<String>` | `fn` | Used only inside this submodule (also tested) |

### Items landing in `npm/enrich.rs`

| Pre-split item | Visibility | Reason |
|---|---|---|
| `fn enrich_entries_with_installed_authors(...)` | `pub(super) fn` | Called from `npm/mod.rs::read` |
| `fn extract_author_string(pkg_json) -> Option<String>` | `fn` | Used only inside this submodule |
| `fn person_from_value(value) -> Option<String>` | `fn` | Used only inside this submodule |

---

## Visibility ladder — binary/mod.rs split

**Pre-split file**: `mikebom-cli/src/scan_fs/binary/mod.rs` (1858 LOC)

**Post-split file** (smaller): `mikebom-cli/src/scan_fs/binary/mod.rs` (~700 LOC) + new sibling files

### Items staying in `binary/mod.rs` (orchestrator + cross-cutting predicates)

| Pre-split item | Visibility | Reason |
|---|---|---|
| `pub fn read(...)` | `pub` (unchanged) | External caller |
| `enum RootfsKind` | `enum` (unchanged) | Used inside `mod.rs::read` and possibly `discover.rs` (TBD) |
| `fn detect_rootfs_kind(rootfs) -> RootfsKind` | `fn` | Called only from `read()` |
| `fn is_host_system_path(soname) -> bool` | `fn` | Called only from `read()` |
| `fn has_rpmdb_at(rootfs) -> bool` | `fn` | Called only from `read()` |
| `fn is_os_managed_directory(rootfs, path) -> bool` | `fn` | Called only from `read()` |

### Items landing in `binary/discover.rs` (filesystem walker)

| Pre-split item | Visibility | Reason |
|---|---|---|
| `fn discover_binaries(root) -> Vec<PathBuf>` | `pub(super) fn` | Called from `binary/mod.rs::read` |
| `fn walk_dir(dir, acc)` | `fn` | Called only from `discover_binaries` |
| `fn is_supported_binary(path) -> bool` | `fn` | Called only from `walk_dir` |

### Items landing in `binary/scan.rs` (single-file scanner)

| Pre-split item | Visibility | Reason |
|---|---|---|
| `fn scan_binary(path, bytes) -> Option<BinaryScan>` | `pub(super) fn` | Called from `binary/mod.rs::read` |
| `fn scan_fat_macho(path, bytes) -> Option<BinaryScan>` | `fn` | Called only from `scan_binary` |
| `fn collect_string_region(file, class) -> Vec<u8>` | `fn` | Called only from `scan_binary` |
| `fn is_go_binary(bytes) -> bool` | `fn` | Called only from `scan_binary` |

### Items landing in `binary/entry.rs` (PackageDbEntry conversion)

| Pre-split item | Visibility | Reason |
|---|---|---|
| `fn version_match_to_entry(...)` | `pub(super) fn` | Called from `binary/mod.rs::read` |
| `fn make_file_level_component(...)` | `pub(super) fn` | Called from `binary/mod.rs::read` |
| `fn note_package_to_entry(...)` | `pub(super) fn` | Called from `binary/mod.rs::read` |
| `impl PackageDbEntry { ... }` | `impl` (unchanged) | Methods stay attached to the type, which lives elsewhere — these `impl` blocks land in `entry.rs` and Rust resolves the type via path |

---

## Inline `#[cfg(test)]` test placement

Per R1: tests move with the production code they test.

### pip — test placement

| Pre-split test name | Lands in | Reason |
|---|---|---|
| `parse_requirements_line_simple_pin` | `pip/requirements_txt.rs::tests` | Tests `parse_requirements_line` |
| `parse_hash_flags_*` | `pip/requirements_txt.rs::tests` | Tests `parse_hash_flags` |
| `parse_hash_alg_*` | `pip/requirements_txt.rs::tests` | Tests `parse_hash_alg` |
| `egg_fragment_*` | `pip/requirements_txt.rs::tests` | Tests `egg_fragment` |
| `pinned_version_from_*` | `pip/requirements_txt.rs::tests` | Tests `pinned_version_from` |
| `marker_probably_matches_*` | `pip/requirements_txt.rs::tests` | Tests `marker_probably_matches` |
| `parse_dist_info_dir_*` | `pip/dist_info.rs::tests` | Tests `parse_dist_info_dir` |
| `poetry_is_dev_*` | `pip/poetry.rs::tests` | Tests `poetry_is_dev` |
| `read_*_orchestrator` (any cross-parser tests) | `pip/mod.rs::tests` | Tests the orchestrator's merge / dedup behavior |

### npm — test placement

| Pre-split test name | Lands in | Reason |
|---|---|---|
| `derive_name_from_path_key_*` | `npm/package_lock.rs::tests` | Tests `derive_name_from_path_key` |
| `parse_pnpm_key_*` | `npm/pnpm_lock.rs::tests` | Tests `parse_pnpm_key` |
| `classify_npm_source_*` | `npm/walk.rs::tests` | Tests `classify_npm_source` |
| `npm_integrity_*` | `npm/mod.rs::tests` | Tests integrity parsing (in mod.rs) |
| `extract_author_string_*` | `npm/enrich.rs::tests` | Tests author extraction |

### binary — test placement

The integration test `tests/scan_binary.rs` (1337 LOC) carries the bulk of binary coverage. The inline `#[cfg(test)]` block in `binary/mod.rs` is small.

| Pre-split test name | Lands in | Reason |
|---|---|---|
| `discover_binaries_*` | `binary/discover.rs::tests` | If any inline tests exist for `discover_binaries` |
| `scan_binary_*` | `binary/scan.rs::tests` | If any inline tests exist for `scan_binary` |
| Cross-cutting `read_*` tests | `binary/mod.rs::tests` | Tests the orchestrator |

---

## Validation rules

- Every item in the pre-split file MUST have a row in the appropriate visibility-ladder table above. A code reviewer can verify completeness by `git diff --stat` showing the pre-split file deleted and the per-submodule files added with summed LOC matching pre-split (modulo the few lines of `mod foo;` declarations and `pub use` re-exports added).
- Every visibility ladder entry MUST be the minimum needed for the post-split call graph. `pub(super)` only when called by a sibling; `pub(crate)` only when called by `mikebom-cli` outside the directory; `pub` only for the documented public surface.
- Inline test names MUST be preserved verbatim; SC-004 enforces this with a sorted-name diff against the pre-split baseline.
