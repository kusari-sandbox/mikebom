---
description: "Task list for feature implementation"
---

# Tasks: Multi-Ecosystem Expansion — Go, RPM, Maven, Cargo, Gem

**Input**: Design documents from `/specs/003-multi-ecosystem-expansion/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli-interface.md, contracts/component-output.md, contracts/schema.md, quickstart.md — all present.

**Tests**: integration tests are required per story (spec §User Stories declares Independent Test criteria for each); unit tests are required per research.md R10 (defense-in-depth lint gate).

**Organization**: Tasks grouped by user story so each can be implemented, tested, and shipped independently. MVP target = US1 (Go) alone; each subsequent story extends ecosystem breadth without touching prior work.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on earlier incomplete tasks)
- **[Story]**: Which user story this task belongs to — US1 / US2 / US3 / US4 / US5

## Path Conventions

mikebom is a single-crate CLI workspace member. Paths below are repository-root-relative — `mikebom-cli/src/...` for source, `mikebom-cli/tests/` for integration tests, `tests/fixtures/` at the repo root for shared fixtures.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Add workspace-level dependencies + create skeleton fixture trees. No logic yet.

- [X] T001 Add new workspace dependencies. Exact feature pinning is required for Principle I compliance:
    - `object = { version = "0.36", default-features = false, features = ["read", "std", "elf", "macho"] }` — Go BuildInfo section lookup; explicit features keep the dep surface minimal.
    - `quick-xml = { version = "0.31", default-features = false }` — pom.xml parser; no C deps.
    - `zip = { version = "0.6", default-features = false, features = ["deflate-miniz"] }` — JAR walker. MUST NOT enable `deflate-zlib` or `deflate-zlib-ng` (both pull libz-sys / C). The `deflate-miniz` feature routes through `flate2` with the `rust_backend` backend (pure `miniz_oxide`).
    - Confirm `toml` (already present from milestone 002) is version ≥0.8 for Cargo.lock v4 compatibility.
    - After adding dependencies, run the verification command: `cargo tree -p mikebom -e normal --target all | rg -i 'libz|c-bindings|zlib-ng|libsqlite3'` — output MUST be empty.
    - Run `cargo build --workspace` and confirm no new C deps appear in `cargo tree`.
    Unit test: add a `#[test] fn no_c_dependencies_in_tree()` to the crate that parses `cargo tree` output and asserts zero matches for the blacklist patterns above; fails CI if a future version bump silently introduces a C backend.
- [X] T002 [P] Create fixture skeletons at `tests/fixtures/go/` with subdirs `simple-module/`, `pseudo-version-module/`, `indirect-only-module/`, `binaries/` — empty placeholder READMEs only; fixture bodies land in US1 tasks.
- [X] T003 [P] Create fixture skeletons at `tests/fixtures/rpm/` with subdirs `rhel-image/`, `rocky-image/`, `amzn-image/`, `opensuse-image/` and a placeholder `minimal-rpmdb.sqlite` marker file; fixture bodies land in US2 tasks.
- [X] T004 [P] Create fixture skeletons at `tests/fixtures/maven/` with `pom-three-deps/`, `pom-with-property-ref/`, and a placeholder `fat-jar-three-vendored.jar` marker; fixture bodies land in US3 tasks.
- [X] T005 [P] Create fixture skeletons at `tests/fixtures/cargo/` with `lockfile-v3/`, `lockfile-v4/`, `lockfile-v1-refused/`, `lockfile-v2-refused/` — empty placeholders only.
- [X] T006 [P] Create fixture skeletons at `tests/fixtures/gem/` with `simple-bundle/` and `bundler-1x-legacy/` — empty placeholders.
- [X] T007 [P] Create polyglot fixture skeleton at `tests/fixtures/polyglot-five/` with subdirs `go-service/`, `rust-service/`, `ruby-worker/` (reuse `tests/fixtures/python/simple-venv/` and `tests/fixtures/npm/lockfile-v3/` via symlinks for the Python + npm project roots). Placeholder READMEs only.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Cross-cutting infrastructure that every ecosystem reader needs. Completed before any user story begins.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T008 Register the new `mikebom:buildinfo-status` property key in `mikebom-cli/src/generate/cyclonedx/builder.rs` — extend the property-emission match block so that entries flagged with `BuildInfoStatus::Missing` or `::Unsupported` serialize the property with the right value. Add unit test in builder.rs covering both value paths.
- [X] T009 [P] Add a `PackageDbError::Cargo` variant in `mikebom-cli/src/scan_fs/package_db/mod.rs` (mirroring the existing `Npm` variant). Add a `cargo::CargoError` enum with `LockfileUnsupportedVersion { path: PathBuf, version: u64 }` and `#[from]` conversion into `PackageDbError`. Unit test: error constructor + `Display` impl renders the contract-specified stderr message.
- [X] T010 [P] Extend `mikebom-cli/src/scan_fs/os_release.rs` with a new `read_id(path: &Path) -> Option<String>` helper that returns the raw `ID=` value from `/etc/os-release`. Keep the existing `read_version_codename` untouched. Unit tests covering RHEL, Rocky, Fedora, Amazon Linux, CentOS Stream, Oracle Linux, AlmaLinux, openSUSE, SLES.
- [X] T011 [P] Add the pure-Rust RPM vendor mapping helper `rpm_vendor_from_id(id: &str) -> String` in `mikebom-cli/src/scan_fs/package_db/mod.rs` (sibling to existing helpers). Implements the 9-entry map from research.md R8 with verbatim-ID fallback. Unit tests: every mapped ID produces the expected vendor + one unmapped ID (e.g. `mageia`) returns the literal string unchanged.
- [X] T012 Register a `#![deny(clippy::unwrap_used)]` lint gate at the crate root of `mikebom-cli/src/main.rs` (or create a `mikebom-cli/src/lib.rs` if one doesn't exist). Scope the lint to production code only via `#[cfg_attr(test, allow(clippy::unwrap_used))]` on every `#[cfg(test)] mod tests` block that currently uses `.unwrap()`. Run `cargo clippy --all-targets --all-features -- -D warnings` once — fix any newly-surfaced prod-code `.unwrap()` calls by converting to `?` / `.ok_or(...)?`. Scope: touch only existing prod code to eliminate violations; no functional change.
- [X] T013 Register the five new ecosystem modules in `mikebom-cli/src/scan_fs/package_db/mod.rs` with empty `pub mod golang;`, `pub mod go_binary;`, `pub mod rpm;`, `pub mod maven;`, `pub mod cargo;`, `pub mod gem;` lines; each module file starts as a stub with `pub fn read(_rootfs: &Path, _include_dev: bool) -> Vec<PackageDbEntry> { Vec::new() }` so the workspace compiles. Integrate each stub into `read_all()` (the npm v1 refusal pattern — `cargo::read()` returns `Result<Vec<PackageDbEntry>, CargoError>` and propagates via `?`; others return `Vec<PackageDbEntry>` directly). Workspace must build cleanly after this task.
- [X] T014 [P] Create the `mikebom-cli/src/scan_fs/package_db/rpmdb_sqlite/` submodule with `mod.rs` declaring `mod page; mod record; mod schema;` and empty stub files for each. Add a `pub struct SqliteFile` stub + `pub enum RpmdbSqliteError` in mod.rs. This is scaffolding only — concrete parsing lands in US2.

**Checkpoint**: Foundation ready. All user stories can now start in parallel. Workspace builds clean, all existing 430 tests still pass (`cargo test --workspace`), and the ecosystem module dispatcher is wired up.

---

## Phase 3: User Story 1 — Go source + binary analysis (Priority: P1) 🎯 MVP

**Goal**: `mikebom sbom scan` produces a complete SBOM for Go source trees (via go.mod + go.sum) AND for compiled Go binaries (via `runtime/debug.BuildInfo`), including scratch/distroless images.

**Independent Test**: Scan `tests/fixtures/go/simple-module/` — expect 5 `pkg:golang/...` components with canonical PURLs, dep tree from go.mod. Scan `tests/fixtures/go/binaries/hello-linux-amd64` — expect embedded-module list. Scan a synthetic scratch image (tarball with nothing but a Go binary) via `--image` — expect same module list + `aggregate: complete` composition for `golang`.

### Implementation for User Story 1

- [X] T015 [P] [US1] Implement `go.mod` parser in `mikebom-cli/src/scan_fs/package_db/golang.rs` — line parser recognising `module <path>`, `go <version>`, `require ( ... )` blocks (including indirect comments), `replace <old> => <new>`, `exclude <module> <version>`. Returns a `GoModDocument { module_path, go_version, requires: Vec<GoModRequire>, replaces: HashMap<(path,ver),(path,ver)>, excludes: HashSet<(path,ver)> }`. Unit tests: minimal go.mod, multi-require block, replace directive, exclude directive, comment handling.
- [X] T016 [P] [US1] Implement `go.sum` parser in `golang.rs` — line parser: each line is `<module> <version> h1:<base64-sha256>` OR `<module> <version>/go.mod h1:<base64-sha256>`. Returns `Vec<GoSumEntry { module, version, hash, kind: Module | GoMod }>`. Only the `Module` kind produces components; `GoMod` kind is retained for integrity but not converted. Unit tests: simple, pseudo-version, module + go.mod pair, malformed line (returns None, doesn't panic).
- [X] T017 [US1] Implement `GoModEntry → PackageDbEntry` conversion in `golang.rs` — PURL: `pkg:golang/<module-path>@<version>` via `Purl::new(...)`. `sbom_tier = Some("source")`. `depends` populated from go.mod `require` names (direct only; indirect filtered). Apply `replace` directives BEFORE PURL construction. Unit tests: replace changes PURL, exclude filters out the entry, pseudo-version round-trips through packageurl-python (build a Python subprocess check or assert the raw bytes match reference output).
- [X] T018 [US1] Implement `pub fn read(rootfs, include_dev) -> Vec<PackageDbEntry>` in `golang.rs` — discovers Go project roots via the milestone-002 bounded recursive walk pattern (reuse `candidate_project_roots` shape; skip descents into `vendor/`, `.git/`, `node_modules/`, `target/`, `dist/`, `__pycache__/`). At each root with `go.sum`, parse + convert; also parse `go.mod` at the same root for the dep-graph. Returns vec of source-tier entries. Unit tests: single-module fixture, monorepo with `services/{api,web}/go.sum`, rootfs without any go.mod returns empty.
- [X] T019 [P] [US1] Implement `go_binary::detect_is_go(path)` in `mikebom-cli/src/scan_fs/package_db/go_binary.rs` using the `object` crate — opens the binary, probes for the `.go.buildinfo` ELF section or `__DATA,__go_buildinfo` Mach-O section by name; falls back to a memmem scan for the magic bytes `\xff Go buildinf:`. Returns a tri-state: `Found { buildinfo_offset }`, `NotGoBinary`, `AmbiguousError`. Bounded read: refuses files >500 MB. Unit tests: known Go ELF binary, known non-Go ELF, Mach-O, stripped binary (section missing but magic still present), malformed binary with truncated header.
- [X] T020 [P] [US1] Implement the BuildInfo decoder in `go_binary.rs` — parses the 32-byte header, reads varint-prefixed `path`, `mod`, `dep` lines, tokenises each `dep` line into `(module_path, version, h1_hash)`. Handles both the Go 1.18+ inline format and the pre-1.18 pointer-indirection form (latter returns `BuildInfoStatus::Unsupported`). Unit tests: hand-crafted BuildInfo blob with 3 deps, empty-deps binary, truncated blob, pre-1.18 pointer-based layout.
- [X] T021 [US1] Implement the ELF / Mach-O section-lookup path in `go_binary.rs` `pub fn read_binary(path: &Path) -> Result<GoBinaryInfo, GoBinaryError>` — combines T019 + T020; returns either the filled `GoBinaryInfo` or the stripped-binary diagnostic shape. Unit tests: end-to-end against checked-in hello-linux-amd64 and stripped-hello-linux-amd64 fixtures (placed via T029 below).
- [X] T022 [US1] Implement `pub fn read(rootfs, include_dev) -> Vec<PackageDbEntry>` in `go_binary.rs` — walks the rootfs (reuse `walker::walk_and_hash` artifact iterator) looking for ELF + Mach-O files bigger than 1 KB, applies `detect_is_go` to each, and for every positive detection calls `read_binary`. Converts `GoBinaryModule` → `PackageDbEntry` with `sbom_tier = Some("analyzed")`, PURL `pkg:golang/<module>@<version>`. Emits a file-level component (type=file) with the `mikebom:buildinfo-status` property when BuildInfo is absent or unsupported (per FR-015 + contracts/cli-interface.md). Unit tests: synthetic rootfs with one Go binary + one non-Go binary; synthetic rootfs with a stripped Go binary (expect file-level diagnostic component).
- [X] T023 [US1] Wire Go into the scan_fs orchestration in `mikebom-cli/src/scan_fs/mod.rs` + `mikebom-cli/src/scan_fs/package_db/mod.rs` — `package_db::read_all()` now also invokes `go_binary::read()` and `golang::read()`. Mark `"golang"` in `complete_ecosystems` when either source-tier (`go.sum`-sourced) OR analyzed-tier (BuildInfo-sourced) entries are observed AND represent the totality of the ecosystem's reach in the scan (i.e. the compositions record fires whenever any Go entry is emitted — Go binary analysis on a scratch image IS authoritative because the binary IS the whole ecosystem). Unit tests: scan_fs with one Go fixture emits the composition, scan_fs without Go emits no golang composition.
- [X] T024 [US1] Implement Go source ↔ binary dedup rule in `mikebom-cli/src/resolve/deduplicator.rs` — when two components share the same PURL and one is `source` tier + the other `analyzed`, merge into a single entry with `sbom_tier = "source"` but merge `evidence.source_file_paths` from both. Unit test covering this case.
- [X] T025 [P] [US1] Extend `mikebom-cli/src/resolve/path_resolver.rs` with a `resolve_golang_path()` matcher for `.go` source files + Go module cache paths (`$GOPATH/pkg/mod/<module>@<version>/`, `/go/pkg/mod/`). These produce filename-tier matches that the dedup rule in T024 will collapse into the higher-confidence BuildInfo or go.sum entries. Unit tests: module cache path patterns.
- [X] T026 [P] [US1] Verify or extend the golang branch in `mikebom-cli/src/generate/cpe.rs` — `synthesize_cpes` must emit a candidate with `vendor=<last-path-segment-before-name>` and `product=<name>` for each Go module (e.g. `pkg:golang/github.com/spf13/cobra@v1.7.0` → `cpe:2.3:a:spf13:cobra:v1.7.0:...`). Unit tests: common github.com patterns + stdlib modules (no-vendor edge case).
- [X] T027 [US1] Populate `tests/fixtures/go/simple-module/` with a `go.mod` + `go.sum` declaring 5 real modules (e.g. `github.com/spf13/cobra@v1.7.0`, `github.com/sirupsen/logrus@v1.9.0`, `github.com/stretchr/testify@v1.8.4`, `gopkg.in/yaml.v3@v3.0.1`, `github.com/mattn/go-isatty@v0.0.19`) with real `h1:` hashes copied from upstream. `pseudo-version-module/` gets an entry with a `v0.0.0-<date>-<sha>` pin. `indirect-only-module/` gets deps only in `go.sum` with no `go.mod` require entries.
- [X] T027a [P] [US1] Populate `tests/fixtures/go/twenty-module/` with a `go.mod` + `go.sum` declaring ~20 real modules (copy directly from a small real-world Go project like `cobra` or `viper`'s lockfile, normalised to ensure every listed version is pinned and hashes are authentic). Exercises the mid-size SC-001 tier without bloating the repo.
- [X] T028 [US1] Populate `tests/fixtures/go/binaries/` with checked-in compiled Go binaries: `hello-linux-amd64` (ELF, normal build), `hello-darwin-arm64` (Mach-O, normal build), `stripped-hello-linux-amd64` (`go build -ldflags="-s -w"` + external `strip`). Also add `tests/fixtures/go/binaries/src/main.go` + `src/go.mod` so maintainers can regenerate. Known-good module set documented in `src/README.md`.
- [X] T029 [US1] Integration test `scan_go_source_tree_emits_canonical_purls` in `mikebom-cli/tests/scan_go.rs` — scans `tests/fixtures/go/simple-module` AND `tests/fixtures/go/twenty-module` via `--path`. For each fixture: (a) parses the fixture's go.sum at test time and counts `Module`-kind entries; (b) asserts the SBOM's `pkg:golang/...` component count ≥ (go.sum count − 1) per the SC-001 tolerance; (c) asserts a `{"ref": "pkg:golang/<main>", "dependsOn": [...]}` dep record exists for the main module with all direct requires.
- [X] T030 [US1] Integration test `scan_go_binary_emits_buildinfo_modules` in `scan_go.rs` — scans `tests/fixtures/go/binaries/hello-linux-amd64` via `--path`, asserts ≥3 `pkg:golang/...` components (main + stdlib + embedded deps), asserts a `golang` composition record `aggregate=complete`.
- [X] T031 [US1] Integration test `scan_go_stripped_binary_emits_diagnostic_property` in `scan_go.rs` — scans the stripped binary, asserts exit 0, asserts the file-level component carries `mikebom:buildinfo-status=missing` (or `unsupported`).
- [X] T032 [US1] Integration test `scan_go_scratch_image_via_image_flag` in `scan_go.rs` — builds a synthetic docker-save tarball in-memory (reuse `build_synthetic_image` pattern from `scan_image.rs`) containing ONLY a Go binary at `/app/hello`, scans via `--image`, asserts the module set matches the source-tree scan from T029 (dedup rule validates).

**Checkpoint**: US1 complete — Go ecosystem shipped. Scans produce valid SBOMs for source trees, single binaries, and scratch images. All 4 integration tests green; all new unit tests green.

---

## Phase 4: User Story 2 — RPM (Priority: P2)

**Goal**: `mikebom sbom scan --path <rootfs>` (or `--image`) emits correct `pkg:rpm/<vendor>/...` components for every installed package in `/var/lib/rpm/rpmdb.sqlite`, with dep-tree edges from `REQUIRES`, licenses from the `LICENSE` column, and supplier from `PACKAGER`.

**Independent Test**: Scan a synthetic rootfs containing `rpmdb.sqlite` with ≥10 packages — expect exactly those components with matching PURL format, `aggregate=complete` composition for `rpm`, vendor mapping correct for RHEL, Rocky, Fedora, Amazon Linux, openSUSE, and verbatim-fallback for an unmapped ID.

### Implementation for User Story 2

- [X] T033 [P] [US2] Implement `mikebom-cli/src/scan_fs/package_db/rpmdb_sqlite/page.rs` — SQLite page decoder covering interior-table and leaf-table B-tree pages. Decodes page headers, cell pointer arrays, and cell payload offsets. Bounded reads: each page MUST NOT be larger than `header.page_size`; refuses overflow pages (returns `Err(RpmdbSqliteError::OverflowPageUnsupported)`). Unit tests: hand-crafted leaf page with 3 cells, interior page with 5 cells + right-pointer, truncated cell array.
- [X] T034 [P] [US2] Implement `mikebom-cli/src/scan_fs/package_db/rpmdb_sqlite/record.rs` — varint + record-format decoder. Handles serial types 0 (null), 1-6 (integer widths 8/16/24/32/48/64), 7 (real), 8/9 (zero/one), 12 (blob), 13+ (text). UTF-8 only; UTF-16 text returns `Err(TextEncodingUnsupported)`. Unit tests: each serial type, mixed-type record, truncated payload, UTF-16 refusal.
- [X] T035 [P] [US2] Implement `mikebom-cli/src/scan_fs/package_db/rpmdb_sqlite/schema.rs` — reads the `sqlite_schema` system table to locate the rpmdb packages table(s) by name. Returns a `TableInfo { name, root_page, column_order }` per table. Unit tests: schema with a single table, schema with 3 tables, corrupt schema → error.
- [X] T036 [US2] Implement `rpmdb_sqlite::SqliteFile::open(path, max_size_bytes) -> Result<Self, RpmdbSqliteError>` + `.iter_table_rows(table_name) -> Iterator<Record>` in `rpmdb_sqlite/mod.rs`. Enforces the 100-byte file header, the `max_size_bytes` cap (defense-in-depth per FR-009), the per-query timeout wrapper (applied at caller site via tokio::time::timeout, not inside this module). Unit tests: open against a known-good rpmdb.sqlite fixture, reject an oversized file (synthesise one >200 MB), reject non-SQLite file (wrong magic).
- [X] T037 [US2] Implement `pub fn read(rootfs, include_dev) -> Vec<PackageDbEntry>` in `mikebom-cli/src/scan_fs/package_db/rpm.rs` — opens `/var/lib/rpm/rpmdb.sqlite` via `SqliteFile::open` with a 200 MB size cap, iterates the packages table, extracts columns (name, epoch, version, release, arch, license, packager, requires), tokenises `requires` to bare names (strip version constraints), and converts each row to `PackageDbEntry`. Vendor derived from `os_release::read_id(rootfs)` → `rpm_vendor_from_id(...)`.
    **Timeout enforcement (FR-009 completion):** wrap the entire `SqliteFile::iter_table_rows(...)` iteration in a synchronous bounded loop with a per-iteration wall-clock budget: check `Instant::now().elapsed()` against a hard-coded `Duration::from_secs(2)` ceiling (no new CLI flag). On timeout, abort the iteration, log a WARN with the observed row count, and return whatever was collected so far — do NOT error out (degraded output is per FR-020's graceful-degradation posture). Document the choice of sync rather than `tokio::time::timeout` as an intentional simplification (no new tokio integration in rpm.rs; the scan pipeline is sync from the caller's perspective).
    Unit tests: (a) extract from fixture rpmdb; (b) row with epoch=0 omits epoch in PURL; (c) epoch≠0 includes; (d) synthetic pathological rpmdb with an infinite-loop B-tree cycle (hand-crafted fixture `tests/fixtures/rpm/pathological-loop.sqlite`) aborts within ~2.1 s and emits a WARN with the partial count.
- [X] T038 [US2] Diagnose BDB rpmdb (FR-020) in `rpm.rs` — when `rootfs/var/lib/rpm/Packages` exists but `rpmdb.sqlite` does not, log the contract-specified stderr warning once and return empty vec. Integration test in T045 below.
- [X] T039 [US2] Wire the `rpm` ecosystem into the `complete_ecosystems` detection in `mikebom-cli/src/scan_fs/mod.rs` — append `"rpm"` when any `pkg:rpm/...` entry was produced by the package-db read path.
- [X] T040 [P] [US2] Verify or extend the rpm branch in `mikebom-cli/src/generate/cpe.rs` — `synthesize_cpes` must emit a candidate with vendor = the PURL's vendor segment (`redhat`, `rocky`, etc.) and product = name. Unit tests: RHEL, Rocky, AlmaLinux.
- [X] T041 [P] [US2] Extend `mikebom-cli/src/resolve/path_resolver.rs` with `resolve_rpm_path()` matching `.rpm` cache files in `/var/cache/dnf/` and related paths. These produce filename-tier matches; dedup collapses them into rpmdb-sourced deployed-tier entries when both are observed. Unit tests: typical dnf cache patterns.
- [X] T042 [US2] Populate `tests/fixtures/rpm/minimal-rpmdb.sqlite` — hand-craft a valid SQLite file with ≥10 rows in the packages table. Generation script: provide a Python helper `tests/fixtures/rpm/generate_rpmdb.py` (checked in) that creates the file from a JSON row dump; the generated `.sqlite` is also checked in for test determinism.
- [X] T043 [US2] Populate the four fixture rootfs subtrees: `tests/fixtures/rpm/rhel-image/{etc/os-release,var/lib/rpm/rpmdb.sqlite}`, `rocky-image/`, `amzn-image/`, `opensuse-image/` — each with the matching `/etc/os-release::ID` value. `rhel-image` reuses the shared rpmdb from T042; other images link to differently-shaped rpmdbs (or reuse the same fixture — the test asserts the vendor mapping, not the row count).
- [X] T044 [US2] Integration test `scan_rpm_fixture_emits_canonical_purls` in `mikebom-cli/tests/scan_rpm.rs` — scans `tests/fixtures/rpm/rhel-image` via `--path`, asserts ≥10 `pkg:rpm/redhat/...` components, asserts each component carries a license + supplier, asserts `aggregate=complete` composition record for `rpm`.
- [X] T045 [US2] Integration test `scan_rpm_vendor_mapping_across_distros` in `scan_rpm.rs` — iterates over `rocky-image`, `amzn-image`, `opensuse-image` fixtures, asserts PURL vendor segment matches the expected map output (`rocky`, `amazon`, `opensuse`) — plus a synthetic `mageia` image asserting the verbatim-ID fallback produces `pkg:rpm/mageia/...`.
- [X] T046 [US2] Integration test `scan_rpm_bdb_diagnoses_and_emits_zero` in `scan_rpm.rs` — synthesise a rootfs with `/var/lib/rpm/Packages` (empty file, simulating legacy BDB) + no rpmdb.sqlite, asserts exit 0, asserts zero rpm components, asserts stderr contains the BDB-detected warning.
- [X] T047 [US2] Integration test `scan_rpm_depends_edges_resolve_to_observed_purls` in `scan_rpm.rs` — the fixture rpmdb contains packages with `REQUIRES` entries that resolve to other packages in the same fixture; assert the `dependencies[]` block contains the expected edges and drops any dangling targets.

**Checkpoint**: US2 complete — RPM ecosystem shipped. RHEL/Rocky/Fedora/Amazon Linux/CentOS/Oracle/AlmaLinux/openSUSE/SLES all scan cleanly. BDB legacy path diagnosed.

---

## Phase 5: User Story 3 — Maven / Java (Priority: P3)

**Goal**: `mikebom sbom scan --path <project>` reads `pom.xml` and every `*.jar`/`*.war`/`*.ear` it finds, emitting `pkg:maven/...` components from both sources with the appropriate tier.

**Independent Test**: Scan `tests/fixtures/maven/pom-three-deps/` — expect 3 source-tier components from `pom.xml`. Scan `tests/fixtures/maven/fat-jar-three-vendored.jar` via `--path` — expect 3 analyzed-tier components from embedded `pom.properties`. Scan the combined Maven project — expect deduplicated union.

### Implementation for User Story 3

- [X] T048 [P] [US3] Implement `pom.xml` parser in `mikebom-cli/src/scan_fs/package_db/maven.rs` using `quick-xml` — event-driven traversal, extracts `<project>/<groupId>` + `<artifactId>` + `<version>`, `<project>/<parent>/<version>` (for parent-POM version inheritance), `<project>/<properties>` block, and `<project>/<dependencies>/<dependency>` entries with `groupId`, `artifactId`, `version`, `scope`. Returns `PomXmlDocument { self_coord, parent_coord, properties, dependencies }`. Unit tests: minimal pom, pom with property substitution, pom with `<parent>` block, pom with `<dependencies>` declaring 3 deps of different scopes.
- [X] T049 [P] [US3] Implement Maven property resolver in `maven.rs` — given a `PomXmlDocument`, resolves `${project.version}`, `${project.groupId}`, and any `${name}` reference via `<properties>` lookup. Returns `(MavenVersion::Resolved | MavenVersion::Placeholder)` per R5. Unit tests: resolved reference, unresolved reference returns Placeholder variant with the raw placeholder text.
- [X] T050 [P] [US3] Implement JAR archive walker in `maven.rs` using `zip` crate — opens the archive as a reader, iterates entries in-memory, applies the zip-slip guard per FR-009 (rejects entries whose normalised path contains `..`), reads `META-INF/MANIFEST.MF` and `META-INF/maven/*/*/pom.properties` entries only. Returns `JarInspection { manifest_fields, pom_properties: Vec<PomProperties> }`. Size cap per entry: 64 MB. Unit tests: valid fat JAR with 3 embedded pom.properties, JAR with zip-slip attempt (expect rejection), oversized entry (expect skip with warning).
- [X] T051 [P] [US3] Implement `MANIFEST.MF` parser in `maven.rs` — line-oriented parser recognising `Bundle-Name`, `Bundle-Version`, `Bundle-Vendor`, `Bundle-License`, `Implementation-Vendor`, `Implementation-Version`. Handles RFC 822-style continuation lines. Unit tests: simple manifest, manifest with continuation lines, malformed line (returns partial result, doesn't panic).
- [X] T052 [US3] Implement the Maven→`PackageDbEntry` conversion in `maven.rs` — pom.xml-sourced entries get `sbom_tier = "source"` (or `"design"` when version is Placeholder); JAR-embedded entries get `sbom_tier = "analyzed"`. PURL: `pkg:maven/<groupId>/<artifactId>@<version>`. `requirement_range` populated for Placeholder versions. `depends` populated from pom.xml `<dependencies>` for source-tier. Unit tests: each conversion path.
- [X] T053 [US3] Implement `pub fn read(rootfs, include_dev) -> Vec<PackageDbEntry>` in `maven.rs` — walks the rootfs looking for `pom.xml` files (via the bounded recursive walker) AND for `*.jar`/`*.war`/`*.ear` files. For each found, invoke the appropriate source-specific parser and accumulate. `include_dev` filters out `<scope>test</scope>` deps when false. Unit tests: pom-only project, JAR-only directory, mixed directory, deduplication when pom.xml and vendored pom.properties declare the same coord.
- [X] T054 [US3] Wire `maven` ecosystem into `complete_ecosystems` in `scan_fs/mod.rs` — mark complete only when the reader parsed at least one pom.xml in full (all deps resolved to concrete versions, no Placeholder entries in the output set for that root). JAR-only scans do NOT mark the ecosystem complete because a fat JAR is inherently a subset.
- [X] T055 [P] [US3] Extend `path_resolver.rs` with `resolve_jar_path()` matching `*.jar`, `*.war`, `*.ear` in common Java cache paths (`~/.m2/repository/...`, `/opt/*/lib/`). Filename-tier matches; dedup collapses them into maven-sourced entries when both observed. Unit tests: typical .m2 cache patterns, WAR/EAR variants.
- [X] T056 [US3] Populate `tests/fixtures/maven/pom-three-deps/pom.xml` — real pom.xml declaring `com.google.guava:guava:32.1.3-jre`, `org.apache.commons:commons-lang3:3.14.0`, `junit:junit:4.13.2` under `<dependencies>`.
- [X] T057 [US3] Populate `tests/fixtures/maven/pom-with-property-ref/pom.xml` — pom declaring a `${project.version}` reference that cannot be resolved (no parent POM in-scope).
- [X] T058 [US3] Populate `tests/fixtures/maven/fat-jar-three-vendored.jar` — hand-craft a JAR containing `META-INF/MANIFEST.MF` + three `META-INF/maven/<group>/<artifact>/pom.properties` files. Generation script `tests/fixtures/maven/generate_fat_jar.py` (checked in) produces the JAR from a YAML spec.
- [X] T059 [US3] Integration test `scan_maven_pom_emits_source_tier_components` in `mikebom-cli/tests/scan_maven.rs` — scans `pom-three-deps/`, asserts exactly 3 components with expected GAV coords.
- [X] T060 [US3] Integration test `scan_maven_jar_emits_analyzed_tier_components` — scans `fat-jar-three-vendored.jar`, asserts 3 components with `sbom_tier=analyzed`.
- [X] T061 [US3] Integration test `scan_maven_placeholder_version_becomes_design_tier` — scans `pom-with-property-ref/`, asserts the component has `sbom_tier=design` + `mikebom:requirement-range=${project.version}`.

**Checkpoint**: US3 complete — Maven ecosystem shipped with both pom.xml and JAR paths.

---

## Phase 6: User Story 4 — Cargo / Rust (Priority: P4)

**Goal**: `mikebom sbom scan --path <workspace>` reads `Cargo.lock` v3/v4 and emits `pkg:cargo/...` components with SHA-256 checksums.

**Independent Test**: Scan `tests/fixtures/cargo/lockfile-v3/` and `tests/fixtures/cargo/lockfile-v4/` — expect one component per `[[package]]` with SHA-256 from the `checksum` field (registry crates) and `mikebom:source-type=git/path` on non-registry entries. Scan `tests/fixtures/cargo/lockfile-v1-refused/` — expect non-zero exit + actionable stderr message.

### Implementation for User Story 4

- [X] T062 [US4] Implement Cargo.lock parser in `mikebom-cli/src/scan_fs/package_db/cargo.rs` using the `toml` crate — branches on the top-level `version = N` field. v1/v2 return `CargoError::LockfileUnsupportedVersion`. v3/v4 iterate `[[package]]` entries extracting `name`, `version`, `source`, `checksum`, `dependencies`. Unit tests: v3 lockfile, v4 lockfile, v1 refusal, v2 refusal, mixed registry+git+path sources.
- [X] T063 [US4] Implement source-kind classification in `cargo.rs` — parses the `source =` field: `"registry+https://..."` → Registry, `"git+https://..."` → Git, `None` or workspace-local → Local, path-like → Path. Unit tests covering each kind.
- [X] T064 [US4] Implement `CargoPackage → PackageDbEntry` conversion in `cargo.rs` — PURL: `pkg:cargo/<name>@<version>`. Registry crates with a `checksum` get a SHA-256 `ContentHash` attached; git/path crates do NOT. `sbom_tier = "source"`. `source_type` property populated for non-registry sources. `depends` populated from the `dependencies` list. Unit tests: each source-kind produces the right property/hash shape.
- [X] T065 [US4] Implement `pub fn read(rootfs, include_dev) -> Result<Vec<PackageDbEntry>, CargoError>` in `cargo.rs` — walks the rootfs for `Cargo.lock` files (bounded recursive walk, skip `target/`, `vendor/`, `.git/`), parses each, and returns accumulated entries. v1/v2 refusal at any root short-circuits the whole scan with the typed error. Unit tests: lockfile-present rootfs, workspace with per-member Cargo.toml files (only the workspace-root Cargo.lock is parsed).
- [X] T066 [US4] Wire cargo into the `complete_ecosystems` + error-propagation paths in `scan_fs/mod.rs` + `package_db/mod.rs`. `cargo::read()` returning Err propagates up through `ScanError::PackageDb(PackageDbError::Cargo(...))`, converted to a non-zero exit with the stderr message documented in contracts/cli-interface.md. Mark `"cargo"` in complete_ecosystems when any v3/v4 lockfile was parsed successfully.
- [X] T067 [P] [US4] Extend `path_resolver.rs` — the existing `resolve_cargo_path()` already handles `.crate` cache files; verify this still works; add a single unit test asserting canonical `pkg:cargo/<name>@<version>` output.
- [X] T068 [US4] Populate `tests/fixtures/cargo/lockfile-v3/Cargo.lock` with a real v3 lockfile containing ~10 packages (mix of registry, git, path sources). `lockfile-v4/Cargo.lock` gets a v4 lockfile (generate with Rust 1.78+ — document the regeneration command). `lockfile-v1-refused/Cargo.lock` and `lockfile-v2-refused/Cargo.lock` get hand-written v1 and v2 shape files.
- [X] T069 [US4] Integration test `scan_cargo_v3_and_v4_fixtures_emit_conformant_sboms` in `mikebom-cli/tests/scan_cargo.rs` — scans both lockfile-v3 and lockfile-v4 fixtures, asserts the expected component counts + that registry crates have SHA-256 hashes + that git entries carry `mikebom:source-type=git`.
- [X] T070 [US4] Integration test `scan_cargo_v1_and_v2_lockfiles_refuse_with_actionable_error` — scans both lockfile-v1-refused and lockfile-v2-refused, asserts non-zero exit, stderr contains the contract string, no output file written.

**Checkpoint**: US4 complete — Cargo/Rust ecosystem shipped with v3+v4 support and v1/v2 refusal.

---

## Phase 7: User Story 5 — Gem / Ruby (Priority: P5)

**Goal**: `mikebom sbom scan --path <project>` reads `Gemfile.lock` and emits `pkg:gem/...` components per gem in GEM/GIT/PATH sections, with direct-dep edges from the `DEPENDENCIES` block.

**Independent Test**: Scan `tests/fixtures/gem/simple-bundle/` — expect one component per gem in the lockfile with canonical PURL, GIT/PATH entries tagged via `mikebom:source-type`, and a `dependencies[]` record for the root project listing the `DEPENDENCIES` gems.

### Implementation for User Story 5

- [X] T071 [US5] Implement `Gemfile.lock` parser in `mikebom-cli/src/scan_fs/package_db/gem.rs` — hand-written line-parser recognising `GEM`, `GIT`, `PATH`, `PLATFORMS`, `DEPENDENCIES`, `BUNDLED WITH` sections. For GEM/GIT/PATH: nested indent means `    gem-name (version)` is the gem entry, `      nested-dep (spec)` is the gem's transitive dep. For DEPENDENCIES: one gem name per line at indent 2. Returns `GemfileLockDocument`. Unit tests: simple bundle, bundler v2 format, bundler v1 legacy format (partial parse with warning per R7), missing BUNDLED WITH section.
- [X] T072 [US5] Implement `GemEntry → PackageDbEntry` conversion in `gem.rs` — PURL: `pkg:gem/<name>@<version>`. `sbom_tier = "source"`. `source_type` property populated for GIT/PATH entries. `depends` populated from the `DEPENDENCIES` block for the root project's direct deps (per-gem transitive not available in Gemfile.lock — intentionally empty). Unit tests: GEM entry, GIT entry with source-type property, PATH entry.
- [X] T073 [US5] Implement `pub fn read(rootfs, include_dev) -> Vec<PackageDbEntry>` in `gem.rs` — walks for `Gemfile.lock` files (bounded recursive walk), parses each, and accumulates. Unit tests: simple fixture, multi-project monorepo.
- [X] T074 [US5] Wire gem into `complete_ecosystems` in `scan_fs/mod.rs` — mark `"gem"` when any Gemfile.lock was parsed.
- [X] T075 [P] [US5] Extend `path_resolver.rs` with `resolve_gem_path()` matching `.gem` cache files in `~/.gem/`, `/usr/local/bundle/cache/`. Filename-tier; dedup absorbs them. Unit tests: typical paths.
- [X] T076 [US5] Populate `tests/fixtures/gem/simple-bundle/Gemfile.lock` — real Gemfile.lock content with ~15 gems across GEM, GIT, PATH sections + a DEPENDENCIES block declaring ~3 direct deps. `tests/fixtures/gem/bundler-1x-legacy/Gemfile.lock` gets a legacy-format sample for the graceful-degradation test.
- [X] T077 [US5] Integration test `scan_gem_fixture_emits_canonical_purls` in `mikebom-cli/tests/scan_gem.rs` — scans `simple-bundle/`, asserts component count matches Gemfile.lock gem count, asserts GIT/PATH entries carry `mikebom:source-type`, asserts a dep record for the project root lists the DEPENDENCIES gems.

**Checkpoint**: US5 complete — Gem/Ruby ecosystem shipped. All five new ecosystems live.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Cross-ecosystem integration testing, documentation refresh, perf validation, constitution gate.

- [ ] T078 Integration test `scan_five_ecosystem_polyglot_monorepo` in `mikebom-cli/tests/scan_five_ecosystem_polyglot.rs` — scans `tests/fixtures/polyglot-five/`, asserts all five new ecosystems AND the two pre-existing (pypi, npm) are represented, asserts exit 0, asserts one composition record per authoritative ecosystem. This covers SC-007.
- [ ] T079 Integration test `scan_rhel_image_with_go_binary` in `mikebom-cli/tests/scan_rhel_go_image.rs` — builds a synthetic docker-save tarball containing a RHEL `/etc/os-release`, a populated `rpmdb.sqlite`, AND a `/usr/local/bin/app` Go binary (reuse a checked-in hello binary). Asserts the SBOM emits both `pkg:rpm/redhat/...` AND `pkg:golang/...` components from the same scan. Covers SC-008.
- [ ] T080 [P] Update `EVALUATION.md` at the repo root with per-ecosystem coverage rows in the benchmark comparison tables vs syft + trivy. Include Go source + Go binary + RHEL rpm + JAR analysis + Cargo + Gemfile measurements against at least one reference input per ecosystem. Document the fuzz-seed staging from R11 as "staged but harness deferred".
- [ ] T081 [P] Update the Constitution compliance note in `README.md` (or create a `COMPLIANCE.md` at the repo root) documenting how each principle was honoured in milestone 003, specifically (a) Principle I via the pure-Rust SQLite reader, (b) Principle IV via the `#[deny(clippy::unwrap_used)]` gate, (c) Principle X via the `mikebom:buildinfo-status` diagnostic.
- [ ] T082 [P] Run `cargo test --workspace --all-targets`; verify green. Record the new test count in the PR description. Per milestone-002 precedent, expect ≥30 new test cases across units + integration.
- [ ] T083 [P] Run `cargo clippy --all-targets --all-features -- -D warnings` with the new `#[deny(clippy::unwrap_used)]` in effect; fix any new violations. Record zero-warnings compliance in the PR description.
- [ ] T084 [P] Performance benchmark per R12: on the largest checked-in fixture (scan a mixed rootfs containing Go source + Go binary + synthetic rpmdb + Maven pom + Cargo.lock + Gemfile.lock), time `mikebom sbom scan --path . --offline --no-deep-hash`. Assert wall-clock ≤10 s on a modern dev laptop (SC-010). If over budget, profile the hot path and file a follow-up TODO — do NOT ship performance regressions.
- [ ] T085 Run the `quickstart.md` reviewer scenarios end-to-end on a clean checkout; document command outputs + expected values in a new `mikebom-cli/tests/quickstart_smoke.rs` if feasible (otherwise attach to the PR description). Cross-verify every SC bullet from spec.md is measured by at least one test or documented check.
- [ ] T086 Final constitution gate: re-read `.specify/memory/constitution.md`; confirm all 12 principles + 4 strict boundaries still pass on the resulting code. Specifically verify: (I) no new C source files or transitive C deps via `cargo tree | rg -i 'sys|c-'`, (II) scan-mode work correctly stamps `GenerationContext::FilesystemScan` / `::ContainerImageScan`, (IV) zero `.unwrap()` in production paths via `rg '\.unwrap\(\)' mikebom-cli/src/ mikebom-common/src/ | rg -v '#\[cfg\(test'`, (V) `packageurl-python` round-trip holds for every new ecosystem by running the conformance probe from `quickstart.md` Scenario 1–5. Document the check in the PR description.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1, T001–T007)**: no dependencies; can start immediately.
- **Foundational (Phase 2, T008–T014)**: depends on Setup completion; BLOCKS all user stories.
- **User Stories (Phase 3–7)**: all depend on Foundational completion. Stories are independent of each other — Go/RPM/Maven/Cargo/Gem can all run in parallel once Phase 2 checkpoint is green.
- **Polish (Phase 8)**: depends on at least US1–US2 being complete (SC-008 requires both); fully actionable after all five stories.

### User Story Dependencies

- **US1 Go**: independent. MVP candidate.
- **US2 RPM**: independent.
- **US3 Maven**: independent.
- **US4 Cargo**: independent.
- **US5 Gem**: independent.

### Critical path inside US2 (RPM)

T033 / T034 / T035 are parallel (different files in `rpmdb_sqlite/`). T036 depends on T033+T034+T035. T037 depends on T036. Everything else in US2 depends on T037.

### Critical path inside US1 (Go)

T015 / T016 parallel (both inside golang.rs but different files would be ideal — if they share the file, sequence as T015 → T016). T017 depends on T015+T016. T018 depends on T017. T019+T020 parallel (go_binary.rs). T021 depends on T019+T020. T022 depends on T021. T023 depends on T018+T022. T024 depends on T023. Integration tests T029–T032 depend on T023+T024 + the fixtures T027+T028.

### Parallel Opportunities

- Setup Phase: T002–T007 all `[P]` (different fixture directories).
- Foundational Phase: T009 / T010 / T011 / T014 `[P]`; T008 / T012 / T013 are sequential (builder / lint gate / dispatcher all touch shared files).
- Once Foundational closes, five developers could parallelise US1–US5 without stepping on each other.
- Within US1: T015 + T016 + T019 + T020 + T025 + T026 are `[P]`; the rest sequence.
- Within US2: T033 + T034 + T035 + T040 + T041 `[P]`.
- Within US3: T048 + T049 + T050 + T051 + T055 `[P]`.
- Within US4: T067 `[P]` (path_resolver-only); rest sequence.
- Within US5: T075 `[P]`; rest sequence.

---

## Parallel Example: User Story 1 (kickoff after Foundational)

```text
# The moment Phase 2 closes (T008–T014 done), developer on US1 can launch:
Task: "Implement go.mod parser in golang.rs (T015)"
Task: "Implement go.sum parser in golang.rs (T016)"
Task: "Implement object-crate-based Go binary detector in go_binary.rs (T019)"
Task: "Implement BuildInfo decoder in go_binary.rs (T020)"
Task: "Extend path_resolver.rs for Go module cache patterns (T025)"
Task: "Verify/extend CPE synthesis for golang ecosystem (T026)"

# Converge at T017 (go.mod→PackageDbEntry), T021 (read_binary), then serialise through
# T018 → T022 → T023 → T024 → tests T029/T030/T031/T032 plus fixtures T027/T028 in parallel.
```

## Parallel Example: User Story 2 (RPM SQLite submodule)

```text
Task: "Implement SQLite page decoder in rpmdb_sqlite/page.rs (T033)"
Task: "Implement SQLite record decoder in rpmdb_sqlite/record.rs (T034)"
Task: "Implement SQLite schema walker in rpmdb_sqlite/schema.rs (T035)"

# Converge at T036 (SqliteFile::open + iter_table_rows), then T037 (rpm.rs).
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Complete Setup + Foundational (T001–T014).
2. Complete US1 (T015–T032).
3. **STOP and VALIDATE**: Go ecosystem fully functional, scratch/distroless image scans work.
4. Demo / merge as MVP — the distroless gap is closed; trivy/syft parity on that one axis.

### Incremental Delivery

1. Setup + Foundational → foundation ready.
2. Add US1 (Go) → test independently → merge (MVP).
3. Add US2 (RPM) → test independently → merge (enterprise unlock).
4. Add US3 (Maven) → test independently → merge.
5. Add US4 (Cargo) → test independently → merge.
6. Add US5 (Gem) → test independently → merge.
7. Polish (T078–T086) → final milestone merge.

Each ecosystem in isolation extends the tool; none breaks prior milestones' fixtures or tests (guarded by the full regression sweep in T082).

### Parallel Team Strategy

- **Developer A**: owns Foundational + US1 (Go is largest).
- **Developer B**: waits for Foundational, then US2 (RPM — the SQLite submodule is the critical subgraph).
- **Developer C**: waits for Foundational, then splits US3 (Maven) + US4 (Cargo) — both smaller than the other two.
- **Developer D**: waits for Foundational, then US5 (Gem) + owns Polish phase.

All five stories merge in priority order per the incremental plan above.

---

## Notes

- `[P]` tasks = different files, no cross-task data dependencies.
- `[Story]` label maps every implementation task to its user story — Polish/Setup/Foundational tasks carry no story label.
- Each user story completes end-to-end before the next begins (within a single developer's flow); parallel teams run stories concurrently.
- Integration tests precede fixture population only if the fixture is synthesised in-test (as in `scan_image.rs`); when checked-in fixtures are needed (e.g. real Go binaries or rpmdb.sqlite), the fixture task precedes its test task in the sequence.
- Every task includes an exact file path; no vague "in the right module" placeholders.
- Commit after each task or logical group; stop at any checkpoint to validate the story independently.
- Avoid: cross-story file edits that break another story's unit tests, premature generalisation (e.g. merging the five ecosystem readers into one mega-module before they're all shipped), introducing new workspace crates (Principle VI).
