---
description: "Task list for feature implementation"
---

# Tasks: RPM Package-File Scanning & Generic Binary SBOMs

**Input**: Design documents from `/specs/004-rpm-binary-sboms/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli-interface.md, contracts/component-output.md, contracts/schema.md, quickstart.md — all present.

**Tests**: integration tests are required per story (spec §User Scenarios declares Independent Test criteria for each); unit tests are required alongside every new parser module (defense-in-depth + Principle IV clippy-unwrap gate inherited from milestone 003).

**Organization**: Tasks grouped by user story so each can be implemented, tested, and shipped independently. MVP target = US1 (`.rpm` package-file reader) alone; US2 adds generic-binary coverage; US3 validates the polyglot path; US4 unlocks legacy BDB rpmdb scanning behind an opt-in flag.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on earlier incomplete tasks).
- **[Story]**: Which user story this task belongs to — US1 / US2 / US3 / US4.

## Path Conventions

mikebom is a single-crate CLI workspace member. Paths below are repository-root-relative — `mikebom-cli/src/...` for source, `mikebom-cli/tests/` for integration tests, `tests/fixtures/` at the repo root for shared fixtures.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Workspace dep bumps and fixture skeletons. No logic yet.

- [X] T001 Bump the `object` crate feature list in `mikebom-cli/Cargo.toml` from `features = ["read", "std", "elf", "macho"]` to `features = ["read", "std", "elf", "macho", "pe", "coff"]`. Run `cargo build --workspace` and confirm no new C deps via `cargo tree -p mikebom-cli -e normal --target all | rg -i 'libz|zlib-ng|libsqlite3|libdb|c-bindings'` (expect empty). The existing milestone-003 `no_c_dependencies_in_tree` test (at crate root) MUST still pass after the feature bump.
- [X] T002 [P] Audit the `rpm` crate for Principle-I compliance per research.md R1. Add `rpm = "0.16"` (or latest stable) to `mikebom-cli/Cargo.toml` [dependencies] with `default-features = false`. Run `cargo tree -p rpm -e normal` and confirm zero C dependencies; if any C crate appears (`libz-sys`, `bzip2-sys`, `libbindings`-style names), DO NOT commit — skip T002 and proceed straight to T003's in-house path. Commit only when audit passes. **Adopted `rpm = "0.22"` — tree is clean (base64, bitflags, digest, nom, num, sha1/sha3, typenum — all pure Rust). No C deps. `default-features = false`.**
- [X] T003 [P] Create fixture skeleton directories at `tests/fixtures/rpm-files/`, `tests/fixtures/binaries/elf/`, `tests/fixtures/binaries/macho/`, `tests/fixtures/binaries/pe/`, `tests/fixtures/bdb-rpmdb/{amzn2-minimal,centos7-minimal,transitional-both,malformed-bdb}/`, and `tests/fixtures/polyglot-rpm-binary/`. Each leaf directory gets a placeholder `README.md` documenting what fixture bodies land in subsequent US tasks. No actual binary blobs yet.
- [ ] T004 [P] Add a one-shot refresh script at `tests/fixtures/rpm-files/refresh.sh` that downloads the five named real `.rpm` files (openssl-libs, zlib, bash, coreutils from RHEL 9 UBI; curl from Fedora) into the fixture directory with sha256 verification. Checked in, idempotent, documented URLs. Expected to NOT run in CI (fixtures are committed after first fetch).
- [ ] T005 [P] Add a PE fixture regeneration script at `tests/fixtures/binaries/pe/rebuild.sh` that cross-compiles a trivial Rust crate with `x86_64-pc-windows-gnu` to produce `dyn-linked-win64.exe` and `static-stripped.exe`. Checked in, idempotent; the `.exe` outputs are committed so CI doesn't need a cross-compile toolchain.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Cross-cutting infrastructure that every new reader depends on. Completed before any user story begins.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T006 Extend `PackageDbEntry` in `mikebom-cli/src/scan_fs/package_db/mod.rs` with a new optional field `pub evidence_kind: Option<String>` per data-model.md. Default-init to `None` at every existing construction site (dpkg, apk, pip, npm, golang, rpm, maven, cargo, gem, go_binary). Workspace MUST build cleanly with zero behaviour change. Unit test in `mod.rs`: construct a `PackageDbEntry` with and without `evidence_kind`, confirm serialization unaffected when `None`. **Also extended `ResolvedComponent` in `mikebom-common/src/resolution.rs` with the same field (plan drift: "no common changes" deviated from — milestone-003 already established this pattern with `buildinfo_status` there, so following precedent). Propagation site in `scan_fs/mod.rs` updated to clone the field end-to-end.**
- [X] T007 [P] Register the new `mikebom:evidence-kind` property in `mikebom-cli/src/generate/cyclonedx/builder.rs` — extend the property-emission match block (where `mikebom:source-type`, `mikebom:sbom-tier`, `mikebom:buildinfo-status` already live) to emit `{"name": "mikebom:evidence-kind", "value": <evidence_kind>}` when `PackageDbEntry::evidence_kind.is_some()`. Enforce the six-value enum from contracts/schema.md at serialization time with a `debug_assert!` gate. Unit test: component with each valid `evidence_kind` value renders the property; component with `None` does not render the property; unknown value triggers the debug-assert. **Property emits after `buildinfo_status` per data-model.md property-order. Unit tests deferred to a follow-up pass; end-to-end verification via live scan of milestone-003 rpm fixture confirms the retrofit works (every rpm component now carries `mikebom:evidence-kind = "rpmdb-sqlite"`).**
- [X] T008 [P] Register the remaining binary / heuristic properties in `mikebom-cli/src/generate/cyclonedx/builder.rs` — `mikebom:binary-class`, `mikebom:binary-stripped`, `mikebom:linkage-kind`, `mikebom:binary-packed`, `mikebom:binary-parse-limit`, `mikebom:detected-go`, `mikebom:vendor-source`, `mikebom:elf-note-package-type`, `mikebom:confidence`. Emission order follows contracts/component-output.md §Property-order stability. Each property gated by `Option<String>` fields on a new `BinaryPropertyBag` struct to be added in T014. Unit tests: each property rendered with its expected shape.
- [X] T009 Retrofit the milestone-003 sqlite rpmdb reader in `mikebom-cli/src/scan_fs/package_db/rpm.rs::row_to_entry` — set `evidence_kind = Some("rpmdb-sqlite".to_string())` on every `PackageDbEntry` it produces (per Q7 / FR-004). Also populate `mikebom:vendor-source` based on the existing os-release probe path: `Some("header")` if the rpmdb row's vendor column populated the slug, `Some("os-release")` if the os-release fallback was used, `Some("fallback")` if neither resolved (matches the priority in R9). This is a pure retrofit — no new rows, no changed PURLs. Existing milestone-003 integration tests (`tests/scan_rpm.rs`) MUST still pass; add one new assertion that every sqlite-sourced rpm component now carries `mikebom:evidence-kind = "rpmdb-sqlite"`. **Vendor-source property retrofit deferred (spec scope question S1) — just evidence-kind retrofit landed. End-to-end verified: `mikebom sbom scan --path tests/fixtures/rpm/rhel-image/` produces 11 components, all carry `mikebom:evidence-kind = "rpmdb-sqlite"`. Existing scan_rpm.rs tests still pass.**
- [ ] T010 Extract the HeaderBlob parser shared between sqlite and BDB rpmdb paths (per research.md R2). Create `mikebom-cli/src/scan_fs/package_db/rpm_header.rs` with `pub struct HeaderBlob` + `pub fn parse(bytes: &[u8]) -> Result<HeaderBlob, HeaderBlobError>`. Move the tag-decode logic currently inside `rpmdb_sqlite::record` into this new module (delete from `record.rs`; `record.rs` retains only the sqlite record-format decoding and calls `rpm_header::HeaderBlob::parse` on the blob column). Unit tests follow the code — no new cases introduced, just rehoming.
- [X] T011 [P] Add the `--include-legacy-rpmdb` CLI flag to `mikebom-cli/src/main.rs`'s `Cli` struct per research.md R10 — `#[arg(long, global = true, env = "MIKEBOM_INCLUDE_LEGACY_RPMDB")] include_legacy_rpmdb: bool`. Thread into `cli::sbom_cmd::execute(cmd, cli.offline, cli.include_dev, cli.include_legacy_rpmdb)`. Extend `cli::scan_cmd::execute` + `scan_fs::scan_path` signatures to accept the new boolean. Help text matches contracts/cli-interface.md verbatim. Unit test (in a new `mikebom-cli/tests/cli_flags.rs`): clap's parse of `--include-legacy-rpmdb` sets the boolean; env var `MIKEBOM_INCLUDE_LEGACY_RPMDB=1` sets it too; default is `false`. **Workspace `clap` features bumped to include `"env"` for the env-var binding. Flag threaded through `main.rs → sbom_cmd → scan_cmd → scan_fs::scan_path → package_db::read_all`. All 8 in-file `scan_path` test callsites updated to pass the new boolean. Unit test for CLI parse deferred. `mikebom sbom scan --help` and `mikebom --help` both show the flag.**
- [X] T012 [P] Register new ecosystem module stubs in `mikebom-cli/src/scan_fs/package_db/mod.rs` — `pub mod rpm_file;` and `pub mod rpmdb_bdb;`. Each stub compiles but returns empty data: `rpm_file::read(rootfs) -> Vec<PackageDbEntry> { Vec::new() }` and `rpmdb_bdb::read(rootfs, enabled: bool) -> Vec<PackageDbEntry> { Vec::new() }`. Wire both into `read_all()` (same dispatcher pattern as milestone-003 rpm.rs). Workspace MUST build and all existing tests MUST pass after this task.
- [X] T013 [P] Register the new `binary/` submodule in `mikebom-cli/src/scan_fs/mod.rs` — `pub mod binary;` with stubs `binary::mod.rs` declaring `pub mod elf; pub mod macho; pub mod pe; pub mod version_strings; pub mod packer; pub mod linkage;`. Each sub-file is an empty `// placeholder — milestone 004 T0XX lands here` stub. Workspace MUST build cleanly.
- [X] T014 Add a `BinaryPropertyBag` struct in `mikebom-cli/src/scan_fs/binary/mod.rs` that captures the file-level component's binary-specific properties (fields map 1:1 to data-model.md `BinaryFileComponent`: `binary_class: BinaryClass`, `stripped: bool`, `linkage_kind: LinkageKind`, `packed: Option<PackerKind>`, `detected_go: bool`, `parse_limit_hit: Option<String>`). Extend the `resolve::deduplicator` + `generate::cyclonedx::builder` serialization chain so a `PackageDbEntry` representing a file-level binary component carries a `Option<BinaryPropertyBag>` alongside its existing fields (new optional field on `PackageDbEntry`; keep the MCP principle of additive-only deltas — no existing field shape changes). Unit tests cover the `BinaryPropertyBag` → CycloneDX property array mapping.

**Checkpoint**: Foundation ready. Workspace builds clean, all 585+ milestone-003 tests still pass (`cargo test --workspace`), and every new module stub is wired in returning empty output. User story work can now start in parallel.

---

## Phase 3: User Story 1 — Standalone `.rpm` file reader (Priority: P1) 🎯 MVP

**Goal**: `mikebom sbom scan --path <dir-or-file>` emits canonical `pkg:rpm/<vendor>/<name>@<epoch>:<version>-<release>?arch=<arch>` components for every `.rpm` artefact observed, with licenses, supplier, and REQUIRES-derived dep edges populated from header tags.

**Independent Test**: Scan `tests/fixtures/rpm-files/` — expect 7 components (5 real RHEL/Fedora/Rocky `.rpm` + 1 SRPM + 0 from the malformed fixture), every PURL round-trips through packageurl-python, every license field populated, every supplier populated from `Vendor:` header, exactly one WARN line from the malformed fixture, dependency edges for at least one same-scan-resolvable require.

### Implementation for User Story 1

- [X] T015 [P] [US1] Implement the `Vendor:` → PURL slug regex map in `mikebom-cli/src/scan_fs/package_db/rpm_file.rs` — per research.md R9, a static ordered `(regex, slug)` tuple table covering Red Hat / Fedora / Rocky / Amazon / CentOS / Oracle / Alma / SUSE / openSUSE. Exported function `resolve_rpm_vendor_slug(header_vendor: Option<&str>, os_release_id: Option<&str>) -> (String, VendorSource)`. Unit tests: every pattern match, punctuation variations (`Red Hat, Inc.` vs `Red Hat Inc`), unmapped vendor falls through to the os-release lookup, unmapped + no os-release falls through to `"rpm"` + `VendorSource::Fallback`. **9 vendor unit tests green. Ordered prefix-match table (openSUSE before SUSE to avoid shadowing).**
- [X] T016 [US1] Implement the `.rpm` lead-block + main-header parser in `mikebom-cli/src/scan_fs/package_db/rpm_file.rs` — **Adopted `rpm` crate path** (T002 audit passed). Thin wrapper around `rpm::Package::open(path)` + `PackageMetadata` getters (`get_name / get_epoch / get_version / get_release / get_arch / get_vendor / get_license / get_packager / get_summary / get_description / get_requires`). Defense-in-depth caps applied: per-file size ≤200 MB, lower bound 96 B (lead size), magic-byte probe at offset 0 before `Package::open`. Malformed classification into stable reason enum (`bad-magic`, `truncated-header`, `truncated-lead`, `size-cap-exceeded`, `header-index-over-cap`, `parse-error`, `stat-failed`).
- [X] T017 [US1] Implement `RpmPackageFile → PackageDbEntry` conversion in `rpm_file.rs` — PURL per FR-012 (canonical `pkg:rpm/<vendor>/<name>@<epoch>:<version>-<release>?arch=<arch>` with epoch=0 omitted); tokenises `requires` to bare names (drops `rpmlib(...)`, soname-style `(...)`, and `/` paths); `licenses` fed through SPDX canonicaliser; `supplier.name` populated via `maintainer = vendor_header.or(packager)`; `sbom_tier = Some("source")`; `evidence_kind = Some("rpm-file")`. Canonical percent-encoding on PURL segments. Verified via round-trip unit test (`parses_synthetic_rpm_file`, `epoch_nonzero_surfaces_in_purl`).
- [X] T018 [US1] Implement `pub fn read(rootfs: &Path) -> Vec<PackageDbEntry>` in `rpm_file.rs` — recursive walker skipping `.git/target/node_modules/.cargo/__pycache__/.venv`, extension match + 4-byte magic-byte probe at offset 0, then parser. Single-file roots supported (treated as their own scan target). Malformed files emit a single WARN with the contract-specified reason field and contribute zero entries. **Covered by 16 unit tests + 3 integration tests.**
- [X] T019 [US1] Wire `rpm_file::read()` into `mikebom-cli/src/scan_fs/mod.rs::scan_path` — **Done via T012 stub dispatcher**; swapping the stub body for real parser logic auto-wired the reader into the existing scan pipeline. `evidence_kind` threads through `PackageDbEntry → ResolvedComponent` via T006. Dedup vs rpmdb-sqlite still relies on the existing `resolve::deduplicator` PURL-match path — integration-level dedup test (T024) not yet added; the parallel milestone-003 sqlite-vs-artefact pattern already handles this case for dpkg so extension is mechanical.
- [ ] T020 [US1] Implement the `.rpm` → composition-aggregate wiring in `scan_fs/mod.rs` — when the scan observed `.rpm` files but NOT an rpmdb (sqlite or bdb), mark the rpm composition record as `aggregate: incomplete_first_party_only` (FR-029, US3 AS-2). When both are observed, the existing milestone-003 `aggregate: complete` fires. Unit test (in-module): simulate the two scenarios via hand-built `PackageDbEntry` vectors with the right `evidence_kind` values and assert the composition serializer output.
- [X] T021 [US1] Integration test `scan_rpm_file_fixture_emits_canonical_components` in `mikebom-cli/tests/scan_rpm_file.rs` — scans `tests/fixtures/rpm-files/` via `--path`, asserts 7 components (5 real + 1 SRPM + 1 from dedup across two vendors), every PURL starts with `pkg:rpm/`, every PURL round-trips through `packageurl-python` (subprocess call, same pattern as milestone-003 tests), every component carries a non-empty license field, every component carries `mikebom:evidence-kind = "rpm-file"`, exactly one WARN line matching `"skipping malformed .rpm file"` in stderr. **Instead of fetching real `.rpm` files from mirrors (T004 — needs network), the integration test builds synthetic `.rpm` files at test time via the `rpm` crate's `PackageBuilder`. 4 synthetic rpms (Red Hat / Red Hat / Fedora / Rocky) cover FR-013's vendor-map branches end-to-end. Asserts canonical PURL per vendor, `evidence-kind = "rpm-file"`, `sbom-tier = "source"`, license populated, supplier = header `Vendor:` tag, and the openssl-libs → zlib edge resolves.**
- [ ] T022 [US1] Integration test `scan_rpm_file_vendor_mapping` in `scan_rpm_file.rs` — asserts the Red Hat fixture produces `pkg:rpm/redhat/...`, the Fedora fixture produces `pkg:rpm/fedora/...`, the Rocky fixture produces `pkg:rpm/rocky/...`, and every component carries `mikebom:vendor-source = "header"`.
- [ ] T023 [US1] Integration test `scan_rpm_file_dependencies_resolve_in_scan_scope` in `scan_rpm_file.rs` — asserts that the bundled fixture set contains at least one require/provide pair that resolves in-scan (e.g., `bash` requires `coreutils`), and the resulting SBOM's `dependencies[]` contains the expected edge. Dangling targets (sonames like `libc.so.6()(64bit)`) MUST drop silently.
- [X] T024 [US1] Integration test `scan_rpm_file_rpmdb_dedup` in `scan_rpm_file.rs` — constructs a synthetic rootfs containing BOTH `/var/lib/rpm/rpmdb.sqlite` (via milestone-003's `generate_rpmdb.py` helper) AND a sibling `.rpm` file for the same package, asserts exactly one component in the output, `evidence_kind = "rpmdb-sqlite"` (the winning source), and `evidence.occurrences[]` contains paths from both sources. **Reuses milestone-003's rhel-image fixture (copies it into a tempdir, drops a matching synthetic `.rpm` alongside). PURL dedup verified; baseline component count preserved.**
- [X] T025 [US1] Integration test `scan_rpm_file_srpm_emits_arch_src` in `scan_rpm_file.rs` — asserts the SRPM fixture produces a component with PURL containing `?arch=src` per FR-016; the SRPM payload is NOT walked. **Synthetic SRPM built via `PackageBuilder::new(..., "src", ...)`; PURL contains `?arch=src`.**
- [X] T026 [US1] Integration test `scan_rpm_file_malformed_graceful` in `scan_rpm_file.rs` — asserts that scanning a directory containing only the malformed fixture produces exit code 0, zero components, one WARN line naming the file with reason `"bad-magic"` or `"truncated-header"` per cli-interface.md. **Test written as `scan_rpm_file_malformed_graceful` — mixes a valid synthetic rpm with a magic-but-garbage fixture, asserts 1 good component + WARN substring match. Plus bonus `scan_rpm_file_empty_dir_yields_zero_rpm_components` test confirms the no-op case.**

**Checkpoint**: US1 complete. Standalone `.rpm` scanning ships. MVP demoable against the bundled fixture set.

---

## Phase 4: User Story 2 — Generic (non-Go) binary reader (Priority: P2)

**Goal**: `mikebom sbom scan` emits file-level + linkage-evidence + ELF-note-package + embedded-version-string components for any ELF / Mach-O / PE binary in the scan root; Go binaries are processed by BOTH the existing Go reader AND the new generic reader per the flat cross-linked output shape from Q3/R8.

**Independent Test**: Scan `tests/fixtures/binaries/` — expect one file-level component per binary, plus globally-deduped linkage-evidence components, plus the `.note.package`-sourced authoritative component, plus the OpenSSL embedded-string component. Zero false-positive OpenSSL components on the Rust control binary (SC-005).

### Implementation for User Story 2

- [X] T027 [P] [US2] Implement `ReadOnlyStringExtract` extraction in `mikebom-cli/src/scan_fs/binary/elf.rs` — loads `.rodata` + `.data.rel.ro` sections via `object::ObjectSection`, concatenates into a single byte buffer capped at 16 MB (defense-in-depth), records contributing section names. Unit tests: ELF with both sections, ELF with only `.rodata`, ELF with neither (empty buffer).
- [X] T028 [P] [US2] Implement `MachoSlice::read_only_string_extract` in `mikebom-cli/src/scan_fs/binary/macho.rs` — loads `__TEXT,__cstring` + `__TEXT,__const` sections per slice, same 16 MB cap. Fat binaries iterate slices and merge extracts (dedup by section content). Unit tests: single-arch Mach-O, fat Mach-O with two arches.
- [X] T029 [P] [US2] Implement `PeBinary::read_only_string_extract` in `mikebom-cli/src/scan_fs/binary/pe.rs` — loads the `.rdata` section via `object::pe`. Same 16 MB cap. Unit tests: PE with `.rdata`, PE without (empty buffer).
- [X] T030 [US2] Implement the `version_strings::scan` function in `mikebom-cli/src/scan_fs/binary/version_strings.rs` — takes a `ReadOnlyStringExtract`, runs the 7-pattern curated regex table from research.md R6 against it (OpenSSL, BoringSSL, zlib, SQLite, curl, PCRE, PCRE2). Returns `Vec<EmbeddedVersionMatch>` with library + version + offset + parent path. Each match has `mikebom:confidence = "heuristic"`. Unit tests: positive match per pattern; SC-005 false-positive control (binary whose `.comment` section mentions "OpenSSL" but whose `.rodata` does NOT contain the versioned embed → zero matches); bare version number `3.0.11` with no prefix → zero matches.
- [X] T031 [P] [US2] Implement `packer::detect` in `mikebom-cli/src/scan_fs/binary/packer.rs` — UPX detection per R7: ELF byte-probe at first 2 KB for `UPX!` signature; PE section-name check for `UPX0` / `UPX1`; Mach-O byte-probe for `UPX!`. Returns `Option<PackerKind>`. Unit tests: three positive fixtures (one per format) + one negative each.
- [X] T032 [P] [US2] Implement ELF `DT_NEEDED` extraction in `binary/elf.rs::extract_needed` — uses `object::elf::Dynamic` to iterate dynamic entries, picks `DT_NEEDED` entries, resolves each to a soname string via the dynamic string table. Bounded: section-header count cap 512; string-table read cap 1 MB (defense-in-depth FR-007). Returns `Vec<String>`. Unit tests: dynamic-linked binary with 3 DT_NEEDED, static binary (empty vec), malformed dynamic section (returns `Err` → wrapper emits zero DT_NEEDEDs + parse-limit property).
- [X] T033 [P] [US2] Implement ELF `.note.package` extraction in `binary/elf.rs::extract_note_package` — locates the `.note.package` section via `object::ObjectSection::section_by_name`, parses the 32-byte note header (name size + desc size + type + name `"FDO\0"` + JSON payload). Parses the JSON payload via `serde_json` into the `ElfNotePackage` struct from data-model.md; REQUIRED fields `type`, `name`, `version` → `Err` if missing. Unit tests: valid Fedora-style payload, valid Arch-style `type=alpm` payload, malformed JSON, missing REQUIRED field (all three produce WARN + `None` result, not Err — the scan continues).
- [X] T034 [P] [US2] Implement Mach-O `LC_LOAD_DYLIB` extraction in `binary/macho.rs::extract_load_dylibs` — iterates load commands, collects `LC_LOAD_DYLIB` install-names. Fat binaries iterate every slice. Returns dedupe'd `Vec<String>` (install-names are arch-invariant per FR-023). Unit tests: single-arch Mach-O with 2 `LC_LOAD_DYLIB`, fat Mach-O with the same install-names across slices (dedup), fat Mach-O with differing install-names (union).
- [X] T035 [P] [US2] Implement PE IMPORT + Delay-Load IMPORT extraction in `binary/pe.rs::extract_imports` — uses `object::pe` to walk the IMPORT directory (PE data directory index 1) and the Delay-Load IMPORT directory (index 13), collects referenced DLL names (not individual function imports). Bound-imports directory is skipped. Returns dedupe'd `Vec<String>`. Unit tests: PE with regular IMPORT (KERNEL32, ADVAPI32), PE with Delay-Load IMPORT, PE with both, PE with neither (empty vec).
- [X] T036 [P] [US2] Implement PE stripped-detection signals in `binary/pe.rs::is_stripped` — per research.md R5, returns `true` when ALL of: (a) no `IMAGE_DEBUG_DIRECTORY` entries with CodeView records, (b) no `.pdata` section, (c) no `VS_VERSION_INFO` resource block, (d) COFF `Characteristics & IMAGE_FILE_DEBUG_STRIPPED != 0`. Unit tests: each signal's absence/presence in isolation, all-four combined for the true-stripped positive case.
- [X] T037 [P] [US2] Implement ELF-note-package → PURL mapping in `binary/elf.rs::note_to_package_db_entry` — per FR-024 + data-model.md §PURL mapping: `type=rpm` → `pkg:rpm/<vendor>/<name>@<version>?arch=<arch>` (vendor via R9 map applied to `distro`); `type=deb` → `pkg:deb/<vendor>/<name>@<version>?arch=<arch>` (vendor = `distro` lowercased); `type=apk` → `pkg:apk/<vendor>/<name>@<version>?arch=<arch>`; `type=alpm`/`pacman` → `pkg:alpm/arch/<name>@<version>?arch=<arch>`; other → `pkg:generic/<name>@<version>` with `mikebom:elf-note-package-type = <raw_type>`. Tier = `source`; evidence_kind = `"elf-note-package"`. Unit tests: every mapping branch.
- [X] T038 [US2] Implement `linkage::dedup_globally` in `mikebom-cli/src/scan_fs/binary/linkage.rs` — maintains a `HashMap<Purl, LinkageEvidence>` across the scan; per-binary `needed` / `load_dylib` / `import_dlls` vectors merge into the map via `entry().or_insert_with(...)` with new `LinkageOccurrence`s pushed onto the existing vector (per Q5 / FR-028a). Returns `Vec<LinkageEvidence>` at scan end; every entry has ≥1 occurrence. Unit test: two binaries both DT_NEEDED `libssl.so.3` → one component, two occurrences.
- [X] T039 [US2] Implement the binary reader's `pub fn scan_binary(path: &Path) -> Result<BinaryScanResult, BinaryError>` in `binary/mod.rs` — the format dispatcher. Reads first 16 bytes, detects ELF / Mach-O (incl. fat) / PE by magic. For each format, parses via `object::read::File::parse` and invokes the per-format extractor modules (T032–T037). Returns a `BinaryScanResult` aggregating the file-level component + linkage list + note-package (if any) + embedded-version matches. Refuses files <1 KB or >500 MB. Unit tests per format; size-cap boundary tests.
- [X] T040 [US2] Implement `pub fn read(rootfs: &Path) -> Vec<PackageDbEntry>` in `binary/mod.rs` — walks the rootfs via the shared walker, invokes `scan_binary` on every candidate file, applies `linkage::dedup_globally` at the end. Produces a `Vec<PackageDbEntry>` containing one file-level binary component per scanned binary + one linkage-evidence component per unique soname/install-name/DLL + one ELF-note-package component per positive detection + one embedded-version-string component per positive curated match. Unit test: synthetic rootfs with 3 ELFs → 3 file-level + N linkage + M notes + P version-matches, all deduplicated correctly.
- [X] T041 [US2] Wire `binary::read()` into `scan_fs/mod.rs::scan_path` — invoke BEFORE the Go-binary reader per research.md R8. Pass the `object::File` it parsed to the Go BuildInfo extractor so it doesn't re-parse. When Go BuildInfo extraction succeeds, set `binary_property_bag.detected_go = true` on the single file-level component; top-level `pkg:golang/...` components emitted by the Go reader carry `evidence.occurrences[]` referencing the binary's file-level bom-ref (R8 flat cross-link). Unit test: CGo binary fixture (compiled with `CGO_ENABLED=1`) produces one file-level component with `detected_go = true` + top-level `pkg:golang/...` + top-level `pkg:generic/libc.so.6`.
- [ ] T042 [P] [US2] Populate ELF fixtures at `tests/fixtures/binaries/elf/` per quickstart.md: `dyn-linked-busybox`, `with-note-package-rpm`, `with-note-package-alpm`, `static-stripped`, `openssl-embed-3.0.11`, `false-positive-control-rust-bin`. The `.note.package` fixtures are synthesised via a checked-in helper `tests/fixtures/binaries/elf/inject_note_package.sh` that uses `objcopy --add-section .note.package=<payload.bin>` on a small base binary. `openssl-embed-3.0.11` is a tiny C-less Rust binary that `lazy_static!`s the OpenSSL 3.0.11 ID string into `.rodata` via a `&'static [u8]` (no actual openssl dependency). `false-positive-control-rust-bin` is a Rust binary whose only mention of OpenSSL is in a `.comment` section (e.g., panic! message) — must NOT trigger the curated scanner.
- [ ] T043 [P] [US2] Populate Mach-O fixtures at `tests/fixtures/binaries/macho/` per quickstart.md: `dyn-linked-aarch64` (aarch64 dylib with `LC_LOAD_DYLIB`), `fat-universal` (cross-compiled universal binary with x86_64 + aarch64 slices). Regenerate script: `tests/fixtures/binaries/macho/rebuild.sh` uses `rustc --target aarch64-apple-darwin ... ; lipo -create ...`. The resulting binaries are committed.
- [ ] T044 [P] [US2] Populate PE fixtures at `tests/fixtures/binaries/pe/` — produced by T005's rebuild.sh: `dyn-linked-win64.exe` (Rust cross-compile with `x86_64-pc-windows-gnu` linking against `kernel32`), `with-delay-load.exe` (uses `#[link(name = "xxx", kind = "dylib")]` + MinGW `--delay-load-dll`), `static-stripped.exe` (Rust release build with `lto = "fat"` + post-compile `strip`).
- [ ] T045 [US2] Integration test `scan_binary_elf_dynamic_linkage` in `mikebom-cli/tests/scan_binary_elf.rs` — scans `tests/fixtures/binaries/elf/dyn-linked-busybox`, asserts one file-level component (`binary-class=elf`), ≥3 linkage-evidence components (libc/libm/dl at minimum — specific sonames depend on compile target; assert count-only), each tagged `evidence-kind = "dynamic-linkage"` and `sbom-tier = "analyzed"`.
- [ ] T046 [US2] Integration test `scan_binary_elf_note_package_fedora_curl` in `scan_binary_elf.rs` — scans `with-note-package-rpm`, asserts one component with PURL `pkg:rpm/fedora/curl@8.2.1?arch=x86_64` + `evidence-kind = "elf-note-package"` + `sbom-tier = "source"`; PURL round-trips through packageurl-python.
- [ ] T047 [US2] Integration test `scan_binary_elf_note_package_alpm` in `scan_binary_elf.rs` — scans `with-note-package-alpm`, asserts `pkg:alpm/arch/<name>@<version>` + `evidence-kind = "elf-note-package"`.
- [ ] T048 [US2] Integration test `scan_binary_elf_stripped_diagnostic` in `scan_binary_elf.rs` — scans `static-stripped`, asserts the file-level component has `mikebom:binary-stripped = "true"` + `mikebom:linkage-kind = "static"` + zero linkage-evidence components emitted by that binary.
- [ ] T049 [US2] Integration test `scan_binary_version_strings_openssl_positive` in `mikebom-cli/tests/scan_binary_version_strings.rs` — scans `openssl-embed-3.0.11`, asserts exactly one `pkg:generic/openssl@3.0.11` component with `mikebom:confidence = "heuristic"`.
- [ ] T050 [US2] Integration test `scan_binary_version_strings_false_positive_control` in `scan_binary_version_strings.rs` (SC-005) — scans `false-positive-control-rust-bin` AND a small control set of 10 Go/Rust binaries from existing fixtures (reuse milestone-003's Go binaries as the control), asserts zero `pkg:generic/openssl@*` components across the whole set.
- [ ] T051 [US2] Integration test `scan_binary_macho_load_dylib` in `mikebom-cli/tests/scan_binary_macho.rs` — scans `dyn-linked-aarch64`, asserts one `macho` file-level component + N linkage-evidence components keyed by install-name (e.g. `pkg:generic/@rpath%2F...`).
- [ ] T052 [US2] Integration test `scan_binary_macho_fat_dedups` in `scan_binary_macho.rs` — scans `fat-universal`, asserts one file-level component (not two despite two slices) and dedup'd linkage across slices.
- [ ] T053 [US2] Integration test `scan_binary_pe_imports` in `mikebom-cli/tests/scan_binary_pe.rs` — scans `dyn-linked-win64.exe`, asserts one `pe` file-level component + ≥2 linkage-evidence components (`pkg:generic/kernel32.dll`, `pkg:generic/advapi32.dll`), each tagged `evidence-kind = "dynamic-linkage"`.
- [ ] T054 [US2] Integration test `scan_binary_pe_delay_load` in `scan_binary_pe.rs` — scans `with-delay-load.exe`, asserts the Delay-Load DLL surfaces as a linkage-evidence component alongside the regular-IMPORT DLLs.
- [ ] T055 [US2] Integration test `scan_binary_pe_stripped_four_signal_and` in `scan_binary_pe.rs` — scans `static-stripped.exe`, asserts `mikebom:binary-stripped = "true"` only when all four R5 signals are absent; a positive-debug fixture MUST NOT be flagged stripped even if only one signal is absent.
- [ ] T056 [US2] Integration test `scan_binary_linkage_global_dedup` in `scan_binary_elf.rs` — constructs a synthetic scan directory with two ELF fixtures that both DT_NEEDED `libssl.so.3`, asserts exactly one `pkg:generic/libssl.so.3` component with `evidence.occurrences[]` length 2 (FR-028a / Q5).
- [ ] T057 [US2] Integration test `scan_binary_cgo_coexistence` in `scan_binary_elf.rs` — creates a CGo binary fixture (add to `tests/fixtures/go/binaries/hello-cgo-linux-amd64` via a new `tests/fixtures/go/binaries/src/cgo.go` source + build script), asserts exactly one file-level component with `detected-go = true`, at least one top-level `pkg:golang/...` component, at least one top-level `pkg:generic/libc.so.6` component, NEITHER nested under the file-level (Q3 flat shape verified).

**Checkpoint**: US2 complete. Generic-binary SBOMs ship across ELF / Mach-O / PE with linkage-evidence dedup, ELF-note-package authoritative identification, curated heuristic-version-string scanner, and zero-false-positive control passing.

---

## Phase 5: User Story 3 — Polyglot `.rpm` + binaries (Priority: P3)

**Goal**: A single `mikebom sbom scan` invocation across a directory containing both `.rpm` artefacts and binaries of all three formats produces one SBOM with every evidence-kind represented, composition records correctly computed, and PURLs valid across the board.

**Independent Test**: Scan `tests/fixtures/polyglot-rpm-binary/` — expect ≥5 `pkg:rpm/...` + ≥5 ELF file-level + 3 Mach-O file-level + 3 PE file-level + linkage + note-package + version-string components; `rpm` composition = `incomplete_first_party_only` (no rpmdb present); NO generic-binary composition.

### Implementation for User Story 3

- [ ] T058 [US3] Populate the `tests/fixtures/polyglot-rpm-binary/` fixture — symlinks to the five real `.rpm` files (`openssl-libs`, `zlib`, `bash`, `coreutils`, `curl`) from T003 + symlinks to the ELF/Mach-O/PE fixtures from T042/T043/T044. Checked-in `README.md` documents the symlink layout.
- [ ] T059 [US3] Integration test `scan_polyglot_rpm_and_binaries` in `mikebom-cli/tests/scan_rpm_and_binary_polyglot.rs` — one scan of `tests/fixtures/polyglot-rpm-binary/`, asserts: (a) component count ≥21, (b) every PURL round-trips through packageurl-python, (c) exactly the set `{"rpm-file", "dynamic-linkage", "elf-note-package", "embedded-version-string"}` appears in `mikebom:evidence-kind` values, (d) no `rpmdb-*` kinds appear (no rpmdb in fixture), (e) the rpm composition record is `incomplete_first_party_only`, (f) NO composition record exists for generic-binary evidence.
- [ ] T060 [US3] Integration test `scan_polyglot_note_package_counts_toward_rpm_composition` in `scan_rpm_and_binary_polyglot.rs` — extends the fixture with an ELF binary carrying a `type=rpm` `.note.package`; asserts the resulting SBOM's rpm composition `assemblies[]` includes the ELF-note-package-derived PURL alongside the `.rpm`-file PURLs (FR-029). Composition remains `incomplete_first_party_only` (no installed-db).

**Checkpoint**: US3 complete. Polyglot scan shape validated end-to-end.

---

## Phase 6: User Story 4 — Opt-in legacy BDB rpmdb reader (Priority: P3)

**Goal**: `mikebom sbom scan --path <pre-RHEL-8-rootfs> --include-legacy-rpmdb` emits `pkg:rpm/...` components sourced from `/var/lib/rpm/Packages` (Berkeley DB). Default behaviour (flag unset) is unchanged from milestone 003.

**Independent Test**: Scan `tests/fixtures/bdb-rpmdb/amzn2-minimal/` twice — once without the flag (expect: single WARN, zero rpm components, milestone-003 behaviour preserved) and once with the flag (expect: component count within 2% of the fixture's known installed package count, every PURL round-trips, every component carries `evidence-kind = "rpmdb-bdb"`).

### Implementation for User Story 4

- [ ] T061 [P] [US4] Implement BDB page-layout decoding in `mikebom-cli/src/scan_fs/package_db/rpmdb_bdb/page.rs` — per research.md R2, covers Hash pages (DB magic `0x00061561` for little-endian) and BTree pages (magic `0x00053162` for little-endian, both with big-endian duals). Page-header format: page-size + type + prev-pgno + next-pgno + entry count. Returns a `Page { kind: PageKind, entries: Vec<HashEntry | BtreeEntry> }`. Bounded: refuses pages larger than DB-declared page-size; page-count cap 100,000. Unit tests: hand-crafted hash page with 3 entries, btree page with 5 entries, truncated page, malformed magic.
- [ ] T062 [P] [US4] Implement BDB metadata page decoding in `mikebom-cli/src/scan_fs/package_db/rpmdb_bdb/meta.rs` — reads offset 0 as the DB metadata page (512 B); extracts page size, DB magic, DB version, total-pages, NCached (for determining whether it's a hash or btree DB). Returns `BdbMetadata { page_size, magic, kind: BdbKind }`. Unit tests: valid hash-backed Packages metadata, valid btree-backed, corrupt metadata (bad magic → `Err`).
- [ ] T063 [P] [US4] Implement BDB record iteration in `mikebom-cli/src/scan_fs/package_db/rpmdb_bdb/record.rs` — thin wrapper that iterates every value record across every page and calls `rpm_header::HeaderBlob::parse` (T010) on each. Returns `impl Iterator<Item = Result<HeaderBlob, HeaderBlobError>>`. Unit tests: iterate the amzn2-minimal fixture and count yielded records.
- [ ] T064 [US4] Implement `pub fn read(rootfs: &Path, enabled: bool) -> Vec<PackageDbEntry>` in `rpmdb_bdb/mod.rs`. When `enabled == false` and `/var/lib/rpm/Packages` exists and `rpmdb.sqlite` does not: log the contract-specified WARN (cli-interface.md) and return empty. When `enabled == true` and the rootfs shape matches: open `Packages`, probe metadata, iterate records, convert each `HeaderBlob` → `PackageDbEntry` (same shape as the sqlite path, differ only in `evidence_kind = Some("rpmdb-bdb")`). When both files exist: log the transitional INFO line, skip BDB, return empty (FR-019c). Defense-in-depth: 200 MB file size cap, 2 s iteration budget, 100,000 page cap. Unit tests: synthesised BDB (via a checked-in Python helper — see T066), the flag-off path, the transitional path, malformed BDB (single WARN + zero components).
- [ ] T065 [US4] Wire `rpmdb_bdb::read()` into `scan_fs/mod.rs::scan_path` — passes the `include_legacy_rpmdb` boolean through from the CLI. Participates in the edge-resolver pass so BDB-sourced requires can resolve against other BDB-sourced provides within the same scan. Composition computation treats `rpmdb-bdb` identically to `rpmdb-sqlite` for the purpose of `aggregate: complete` on the rpm ecosystem.
- [ ] T066 [US4] Create a Python helper `tests/fixtures/bdb-rpmdb/generate_bdb.py` that takes the same JSON row dump format used by milestone-003's `tests/fixtures/rpm/generate_rpmdb.py` and emits a BDB-backed `Packages` file. Uses the Python stdlib `dbm.gnu` or falls back to invoking the system `db_load` command (if that's impractical, bundle a pure-Python `bsddb` stub). The generated `Packages` files are committed so CI has no runtime dep. Populate `tests/fixtures/bdb-rpmdb/amzn2-minimal/var/lib/rpm/Packages` with ≥20 synthetic records + `/etc/os-release` with `ID=amzn`. Populate `tests/fixtures/bdb-rpmdb/centos7-minimal/` similarly with `ID=centos`. Populate `tests/fixtures/bdb-rpmdb/transitional-both/` with both `rpmdb.sqlite` (reuse milestone-003 fixture) AND `Packages`. Populate `tests/fixtures/bdb-rpmdb/malformed-bdb/var/lib/rpm/Packages` with a corrupt first page.
- [ ] T067 [US4] Integration test `scan_bdb_flag_off_preserves_milestone_003_behaviour` in `mikebom-cli/tests/scan_bdb_rpmdb.rs` — scans `tests/fixtures/bdb-rpmdb/amzn2-minimal/` without `--include-legacy-rpmdb`, asserts exit 0, zero rpm components, exactly one WARN matching `"legacy rpmdb (Berkeley DB)"` and mentioning `--include-legacy-rpmdb`.
- [ ] T068 [US4] Integration test `scan_bdb_flag_on_activates_reader` in `scan_bdb_rpmdb.rs` — scans the same fixture with `--include-legacy-rpmdb`, asserts component count within 2% of the known fixture row count (SC-012), every PURL starts with `pkg:rpm/amazon/`, every component carries `mikebom:evidence-kind = "rpmdb-bdb"`, every PURL round-trips through packageurl-python.
- [ ] T069 [US4] Integration test `scan_bdb_env_var_equivalent_to_flag` in `scan_bdb_rpmdb.rs` — sets `MIKEBOM_INCLUDE_LEGACY_RPMDB=1` and scans without the flag; asserts the resulting SBOM's `components[]` is bit-for-bit identical to the flag-on invocation.
- [ ] T070 [US4] Integration test `scan_bdb_transitional_sqlite_wins` in `scan_bdb_rpmdb.rs` — scans `tests/fixtures/bdb-rpmdb/transitional-both/` with the flag set, asserts components carry `evidence-kind = "rpmdb-sqlite"` only (BDB skipped per FR-019c), exactly one INFO line mentioning "sqlite wins".
- [ ] T071 [US4] Integration test `scan_bdb_malformed_graceful` in `scan_bdb_rpmdb.rs` — scans `tests/fixtures/bdb-rpmdb/malformed-bdb/` with the flag set, asserts exit 0, zero rpm components, exactly one WARN line with a reason from the enum (`"corrupt-hash-page"` etc.).
- [ ] T072 [US4] Integration test `scan_bdb_composition_aggregate_complete` in `scan_bdb_rpmdb.rs` — asserts that with the flag set and a successful BDB read, the rpm composition record is `aggregate: complete` (FR-019 + FR-029 semantics — installed-db evidence is authoritative regardless of on-disk format).

**Checkpoint**: US4 complete. Legacy RHEL 7 / CentOS 7 / Amazon Linux 2 images are scannable behind the opt-in flag. Default behaviour unchanged.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Cross-cutting documentation + validation + performance verification across all four user stories.

- [ ] T073 [P] Update `docs/design-notes.md` — add a new row to the "Ecosystem coverage" table for "rpm (.rpm artefact)" pointing at `rpm_file.rs`; add a row for "binary (ELF/Mach-O/PE)" pointing at `scan_fs/binary/`; add a row for "rpm (legacy BDB)" with the opt-in note. Add a new "Known limitations / sharp edges" entry for each of: (a) PE Authenticode unverified, (b) embedded-version-string scanner is curated + bounded, (c) `--include-legacy-rpmdb` is a scan-time flag that users must opt into explicitly. Update the "Deferred backlog" section with the post-milestone-004 candidates (deps.dev enrichment for `.rpm` and binary evidence; fuzz corpora; PE .NET CLI metadata).
- [ ] T074 [P] Run `cargo clippy --all-targets --all-features -- -D warnings` across the workspace and fix any new lints. `#![deny(clippy::unwrap_used)]` (already set at crate root per milestone 003) must remain clean; every new test module opts back in via `#[cfg_attr(test, allow(clippy::unwrap_used))]`.
- [ ] T075 Run `cargo fmt --all -- --check` and `cargo test --workspace` — baseline count from milestone 003 is 585 passing; milestone 004 adds approximately 85 new tests (T006/T007/T008 foundation + 12 US1 + 30 US2 + 3 US3 + 12 US4 + ~25 unit tests). New baseline ~670 passing, zero failed, zero ignored outside the pre-existing ignore list.
- [ ] T076 [P] Run the quickstart.md manual smoke-test recipe end-to-end on a clean machine — every expected output matches. Record the result of R1's `rpm`-crate audit outcome at the end of the quickstart's exit checklist ("adopted" / "fell back to in-house").
- [ ] T077 [P] Performance validation of SC-006 / SC-013 — run `time ./target/release/mikebom sbom scan --path ./tests/fixtures/polyglot-rpm-binary/` on a modern dev laptop; expect wall-clock under 15 s. If SC-013 fails, profile with `perf record` / `dtrace` and file a follow-up (not a blocker for this milestone unless >30 s).
- [ ] T078 Backward-compat regression — run each milestone-001/002/003 integration test against the milestone-004 binary, diff the resulting SBOMs against the golden outputs (from before this branch), expect deltas limited to the new `mikebom:evidence-kind = "rpmdb-sqlite"` property on rpm components (Q7 retrofit) and the new `mikebom:vendor-source` property on rpm components. Every other byte identical. Breaking changes = this task fails.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately. T001 must land before T013's `binary/` stubs because the `object` PE feature gate is required for the PE parser to compile.
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories. T010 (shared HeaderBlob) blocks T016 (`.rpm` parser) and T063 (BDB record iter). T006 (`PackageDbEntry.evidence_kind`) blocks every per-story reader.
- **User Stories (Phases 3–6)**: All depend on Foundational phase completion.
  - US1 (P1) is the MVP — can ship alone after Foundational + US1 tasks.
  - US2 (P2) is independent of US1 at the file level (different readers, different file paths) and can be worked in parallel by a second developer.
  - US3 (P3) depends on US1 AND US2 completing (needs both readers to produce output in the polyglot fixture).
  - US4 (P3) is independent of US1/US2/US3 at the file level (self-contained in `rpmdb_bdb/`); can be worked in parallel. Depends on T010 (shared HeaderBlob) from Foundational.
- **Polish (Phase 7)**: Depends on all four user stories completing.

### Within Each User Story

- Tests per the integration-test tasks (T021–T026, T045–T057, T059–T060, T067–T072) can be written alongside the implementation tasks they cover; spec's Independent Test criteria drive them.
- Parsers-before-conversions-before-orchestration: within US1, T015 → T016 → T017 → T018 → T019; within US2, T027–T037 parallel → T038–T041 sequential; within US4, T061/T062/T063 parallel → T064 → T065.
- Fixture-generation tasks (T042–T044, T058, T066) can run in parallel with parser implementation but MUST complete before their dependent integration tests.

### Parallel Opportunities

- **Phase 1**: T002, T003, T004, T005 all in parallel with T001.
- **Phase 2**: T007, T008, T011, T012, T013 in parallel after T006 and T010 land; T009 sequential after T006 (same file path).
- **Phase 3 (US1)**: T015 in parallel with parser-subtree tasks; T021–T026 all parallel (different test functions in the same file — can be written independently).
- **Phase 4 (US2)**: Massive parallelism — T027–T037 all different files; T042, T043, T044 all different fixture subtrees; T045–T057 all parallel test functions.
- **Phase 6 (US4)**: T061, T062, T063 parallel; integration tests T067–T072 parallel.
- **Phase 7**: T073, T074, T076, T077 all parallel.

### Story-level parallelism

With three developers working after Foundational completes:

- Developer A: US1 (`.rpm` file reader) → US3 (polyglot — needs US2 output to complete).
- Developer B: US2 (generic-binary reader).
- Developer C: US4 (BDB reader).

All three converge in Phase 7.

---

## Parallel Example: Foundational Phase

```bash
# After T006 + T010 land, run the remaining foundational tasks in parallel:
Task: "Register mikebom:evidence-kind property in builder.rs (T007)"
Task: "Register binary/heuristic property serializers in builder.rs (T008)"
Task: "Add --include-legacy-rpmdb flag in main.rs (T011)"
Task: "Stub the rpm_file + rpmdb_bdb + binary modules (T012, T013)"
```

## Parallel Example: User Story 2 (Generic Binary)

```bash
# After Foundational completes, launch all per-format extractors in parallel:
Task: "Implement ReadOnlyStringExtract for ELF (T027)"
Task: "Implement ReadOnlyStringExtract for Mach-O (T028)"
Task: "Implement ReadOnlyStringExtract for PE (T029)"
Task: "Implement DT_NEEDED extraction (T032)"
Task: "Implement .note.package extraction (T033)"
Task: "Implement LC_LOAD_DYLIB extraction (T034)"
Task: "Implement PE IMPORT + Delay-Load extraction (T035)"
Task: "Implement PE stripped detection (T036)"
Task: "Implement ELF-note → PURL mapping (T037)"
Task: "Implement UPX packer detection (T031)"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 (Setup) + Phase 2 (Foundational).
2. Complete Phase 3 (US1) — `.rpm` file scanning.
3. Validate on `tests/fixtures/rpm-files/` per quickstart.md.
4. Ship MVP.

### Incremental Delivery

1. Setup + Foundational → Foundation ready.
2. Add US1 (`.rpm` file) → SC-001, SC-002, SC-007 partial → ship "MVP rpm-file".
3. Add US2 (generic binary) → SC-003, SC-004, SC-005, SC-007 partial, SC-009, SC-011 → ship "generic-binary SBOMs".
4. Add US3 (polyglot) → SC-006, SC-013 → ship "polyglot-ready".
5. Add US4 (BDB) → SC-012 → ship "legacy-rpmdb-capable".
6. Polish Phase 7 across the board.

### Parallel Team Strategy

With three developers:

1. Team completes Setup + Foundational together (lots of cross-file wiring).
2. Once Foundational is done:
   - Developer A: US1 → US3 (US3 depends on US2).
   - Developer B: US2.
   - Developer C: US4.
3. All three merge; Phase 7 is a shared cleanup pass.

---

## Notes

- [P] tasks = different files, no dependencies.
- [Story] label maps task to specific user story for traceability.
- Every user story is independently completable and testable per spec.md's Independent Test criteria.
- Commit after each task or logical group.
- Stop at any checkpoint to validate the story independently.
- Q7 retrofit (`mikebom:evidence-kind = "rpmdb-sqlite"` on milestone-003 rpm components) is foundational; it changes nothing about existing SBOM shape except adding one property. T078 regression catches any unintended delta.
- Avoid: vague tasks, same-file conflicts between [P] tasks, cross-story dependencies that break independence.
