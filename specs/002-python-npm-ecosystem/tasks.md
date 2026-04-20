---

description: "Task list for Python + npm Ecosystem Support implementation"
---

# Tasks: Python + npm Ecosystem Support

**Input**: Design documents from `/specs/002-python-npm-ecosystem/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Included. SC-010 in the spec requires ≥30 new tests, so every parser task pairs implementation with inline unit tests; fixture-based integration tests live in their own tasks.

**Organization**: Tasks are grouped by user story (US1–US5) to enable independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Maps the task to a user story from spec.md (US1, US2, US3, US4, US5)
- File paths are absolute from the repo root unless otherwise noted

## Path Conventions

- mikebom is a three-crate Cargo workspace. Most new code lives under `mikebom-cli/src/`. One additive schema change touches `mikebom-common/src/resolution.rs`. Fixtures live under `tests/fixtures/` at the repo root.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization — dependency additions and fixture scaffolding.

- [X] T001 Add `toml = "0.8"` and `serde_yaml = "0.9"` to `[dependencies]` in mikebom-cli/Cargo.toml; run `cargo build --workspace` to confirm compile
- [X] T002 [P] Create fixture skeletons at tests/fixtures/python/ (subdirs: simple-venv/, poetry-project/, pipfile-project/, requirements-only/, pyproject-only/) — empty placeholder READMEs only; fixture bodies land in US1 tasks
- [X] T003 [P] Create fixture skeletons at tests/fixtures/npm/ (subdirs: lockfile-v3/, lockfile-v1-refused/, pnpm-v8/, node-modules-walk/, package-json-only/, scoped-package/) — empty placeholder READMEs only; fixture bodies land in US2 tasks

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Pipeline extensions that every user story depends on — `is_dev` field, global `--include-dev` flag, dedup merge rule for dev flag, CycloneDX property emission.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T004 Add `is_dev: Option<bool>` field to `PackageDbEntry` struct in mikebom-cli/src/scan_fs/package_db/mod.rs with doc comment per data-model.md §1.1. Backfill `is_dev: None` at every existing construction site in mikebom-cli/src/scan_fs/package_db/dpkg.rs and mikebom-cli/src/scan_fs/package_db/apk.rs so the workspace still compiles. Add unit test in dpkg.rs confirming its entries emit `is_dev == None`.
- [X] T005 [P] Add `requirement_range: Option<String>` and `source_type: Option<String>` fields to `PackageDbEntry` in mikebom-cli/src/scan_fs/package_db/mod.rs for the fallback-tier + non-registry-source metadata (per data-model.md §1.1 and contracts/component-output.md §5). Backfill `None` in dpkg.rs + apk.rs. Unit test: existing dpkg fixture round-trip still passes.
- [X] T006 Add a global `--include-dev` flag to the root `Cli` struct in mikebom-cli/src/main.rs (clap `#[arg(long, global = true)]`). Thread through: `sbom_cmd::execute(cmd, offline, include_dev)` in mikebom-cli/src/cli/sbom_cmd.rs → `scan_cmd::execute(args, offline, include_dev)` in mikebom-cli/src/cli/scan_cmd.rs → new `include_dev: bool` parameter on `scan_fs::scan_path`. Update every existing call site (test fixtures pass `false`). Unit test: clap parser accepts `--include-dev`; `false` by default.
- [X] T007 [P] Extend the deduplicator in mikebom-cli/src/resolve/deduplicator.rs with an `is_dev` merge rule per research.md R8: when grouping components with the same PURL, `Some(false)` wins over `Some(true)`; `None` merges with either without overriding. Add unit test covering all three combinations.
- [X] T008 Extend `ResolvedComponent` in mikebom-common/src/resolution.rs with three optional fields, matching the existing extension pattern used for `cpes: Vec<String>` and `occurrences: Vec<FileOccurrence>` (both use `#[serde(default, skip_serializing_if = "...")]` so attestation JSON stays backward-compatible):

    ```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_dev: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirement_range: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    ```

    Then extend the CycloneDX component builder in mikebom-cli/src/generate/cyclonedx/builder.rs to emit corresponding `component.properties[]` entries: `mikebom:dev-dependency = "true"` when `is_dev == Some(true)` AND `--include-dev` is set (the flag is on `CycloneDxConfig` — extend the config); `mikebom:requirement-range = "<range>"` when present; `mikebom:source-type = "<kind>"` when present. Add builder unit tests per data-model.md §6 (one test per property + a combined test confirming all three coexist on a single component). Backfill `None` at every existing `ResolvedComponent` construction site in the workspace so the crate compiles.
- [X] T008a Add SBOM-tier emission (traceability ladder — research.md R13). Extend `ResolvedComponent` in mikebom-common/src/resolution.rs with one more optional field (same serde attributes as T008):

    ```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom_tier: Option<String>,
    ```

    Permitted values: `"build"`, `"deployed"`, `"analyzed"`, `"source"`, `"design"`. Consider introducing a `SbomTier` enum in mikebom-common/src/resolution.rs with these variants plus serde `rename_all = "lowercase"`; store as `Option<SbomTier>` on `ResolvedComponent`. Extend the CycloneDX builder to emit a `mikebom:sbom-tier = "<value>"` property per component when the field is populated. At the envelope level, aggregate the union of observed tiers and emit `metadata.lifecycles[]` using the CycloneDX 1.5+ native lifecycle phase mapping per research.md R13 (`build → build`, `deployed → operations`, `analyzed → post-build`, `source → pre-build`, `design → design`). Retrofit existing readers in mikebom-cli/src/scan_fs/package_db/dpkg.rs and mikebom-cli/src/scan_fs/package_db/apk.rs to set `sbom_tier = Some(SbomTier::Deployed)` on their entries (one-line addition each). Unit tests: each tier value emits the expected property; envelope `metadata.lifecycles[]` contains the correct union for a mixed-tier scan; existing dpkg + apk fixture round-trips still pass with the new property present.
- [X] T009 [P] Extend `ScanResult.complete_ecosystems` doc comment in mikebom-cli/src/scan_fs/mod.rs to mention `"pypi"` and `"npm"` as valid values. No logic change yet — readers populate this in their own tasks.

**Checkpoint**: Foundation ready — US1 and US2 can begin in parallel.

---

## Phase 3: User Story 1 — Scan a Python project directory (Priority: P1) 🎯 MVP

**Goal**: mikebom sbom scan --path . on a Python project produces a CycloneDX SBOM with pypi components from a venv (0.85), lockfile (0.85), or requirements.txt (0.70), with reference-impl-conformant PURLs, populated licenses, and evidence pointing back to source files.

**Independent Test**: Scan the tests/fixtures/python/simple-venv fixture; assert 5+ pypi components, every PURL round-trips through packageurl-python byte-for-byte, licenses populated on ≥95% of components.

### Implementation for User Story 1

- [X] T010 [US1] Create mikebom-cli/src/scan_fs/package_db/pip.rs with module skeleton: public `read(rootfs: &Path, include_dev: bool) -> Vec<PackageDbEntry>` entry point, private struct scaffolds for `PipDistInfoEntry`, `PoetryLockEntry`, `PipfileLockEntry`, `RequirementsTxtEntry`, `PyprojectTomlProjectName` per data-model.md §2. Register the module in mikebom-cli/src/scan_fs/package_db/mod.rs and add a `pip::read(root, include_dev)` call inside `package_db::read_all()`. Unit test: module compiles, `read_all` signature unchanged externally.
- [X] T011 [P] [US1] Implement the PEP-639-aware license precedence helper in mikebom-cli/src/scan_fs/package_db/pip.rs: `fn extract_license(m: &PipDistInfoEntry) -> Vec<SpdxExpression>` consulting `license_expression`, then `license_raw` (via the `copyright.rs::map_shorthand_token` helper), then the `Classifier: License ::` trove list. Include a ~20-entry classifier-to-SPDX lookup table in the same file. Unit tests for each precedence tier + edge cases (empty, malformed, classifier-only).
- [X] T012 [P] [US1] Implement `PipDistInfoEntry` RFC-822 parser in pip.rs with continuation-line support. Handles `Name`, `Version`, `License`, `License-Expression`, `Classifier`, `Requires-Dist`, `Author`, `Author-email`, `Home-page`. Unit tests: single-package METADATA, multi-line continuations, missing-license fallback, non-UTF-8 author name with lossy decode.
- [X] T013 [P] [US1] Implement PEP 508 Requires-Dist tokenizer in pip.rs: strip `[extras]`, version specs `(>= 1.2)`, environment markers (`; python_version < "3.10"`). Emit bare names only. Honor env markers against the scanner's current python version (log the chosen version). Unit tests: bare name, name-with-extras, name-with-version, env-marker-false path, comma-separated multi-requirement lines.
- [X] T014 [P] [US1] Implement `PoetryLockEntry` parser in pip.rs using `toml` crate, dispatching on `[metadata] lock-version` for v1 vs v2 shape per research.md R3. Extract `name`, `version`, `category` (v1) / `groups` (v2), `[[package.files]] hash = ...`, nested `[package.dependencies]` keys. Unit tests: v1 `category = "dev"` case, v2 `groups = ["main"]` case, v2 with custom group `"test"`, hashes extraction.
- [X] T015 [P] [US1] Implement `PipfileLockEntry` parser in pip.rs using `serde_json`. Handles the two top-level sections `"default"` (prod) and `"develop"` (dev). Emit one entry per package with the right `is_dev` flag. Unit tests: default-only, develop-only, mixed, hashes preservation.
- [X] T016 [P] [US1] Implement `RequirementsTxtEntry` parser in pip.rs — line-at-a-time, tolerant of `#` comments, `-r <other.txt>` includes (follow one level), URL refs, `--hash=sha256:...` flags (preserve, don't parse). Unit tests: pinned (`==`), ranged (`>=,<`), bare name (versionless), URL ref, git-URL ref, commented line.
- [X] T017 [US1] Implement the conversion `PipDistInfoEntry | PoetryLockEntry | PipfileLockEntry | RequirementsTxtEntry → PackageDbEntry` in pip.rs. Confidence assignment per data-model.md §2 (0.85 for dist-info / lockfile, 0.70 for requirements). `source_path` populated from the path that produced the entry. `is_dev` populated per-source per research.md R8. `sbom_tier` populated per research.md R13: dist-info → `Deployed`; poetry.lock / Pipfile.lock → `Source`; requirements.txt (any form — pinned or ranged) → `Design`. PURL built via `Purl::new(&format!("pkg:pypi/{name}@{version}"))` with the declared name (see research.md R7; feed through `encode_purl_segment`). Unit tests: each source produces correct PURL, correct confidence, correct is_dev, correct sbom_tier.
- [X] T018 [US1] Implement venv / lockfile / requirements discovery in pip.rs `pub fn read(rootfs, include_dev)`: walk candidate paths from data-model.md / plan.md §Project-Structure; for each venv/`dist-info` found, parse; for each lockfile found without venv, parse; for each requirements.txt found without lockfile and without venv, parse. Apply drift resolution (venv wins) per research.md R8. Append `"pypi"` to `complete_ecosystems` only when an authoritative source (venv OR lockfile) was read; the requirements-only tier does NOT mark pypi complete. Unit tests: venv-only, lockfile-only, requirements-only, venv+lockfile drift case.
- [X] T019 [US1] Skip rule for pyproject.toml-only projects (FR-005) in pip.rs: detect project marker (pyproject.toml exists with `[project]` table, no venv, no lockfile, no requirements.txt). Return empty and emit `tracing::info!("python project detected but no venv, lockfile, or requirements.txt — skipping")`. Unit tests: pyproject-only detection, pyproject-plus-requirements doesn't skip.
- [X] T020 [P] [US1] Extend mikebom-cli/src/resolve/path_resolver.rs with `resolve_pip_path()` matching `*.whl` cache paths (`~/.cache/pip/http/*`, `/var/cache/pip/*`, and any `.whl` in the scan root). Emit `pkg:pypi/<name>@<version>` PURLs at confidence 0.70. Unit tests: common wheel naming patterns (hyphen vs underscore, abi tags), sdist `.tar.gz` pattern, negative test for non-wheel `.tar.gz`.
- [X] T021 [P] [US1] Verify or extend the pypi branch in mikebom-cli/src/generate/cpe.rs: `synthesize_cpes` must emit both `cpe:2.3:a:<name>:<name>:<version>:*:...` and `cpe:2.3:a:python-<name>:<name>:<version>:*:...`. If only one is currently produced, add the missing candidate. Unit tests: reference case + escaping case for `+` in version (reference-impl encoding).
- [X] T022 [US1] Populate fixtures under tests/fixtures/python/: simple-venv with 5+ real `.dist-info/METADATA` files (hand-curated, small, mixed licenses — MIT, Apache-2.0, BSD-3-Clause, GPL-3.0-only); poetry-project with a v2 `poetry.lock` + `pyproject.toml`; pipfile-project with a `Pipfile.lock` carrying both default + develop sections; requirements-only with pinned, ranged, and URL-ref entries; pyproject-only with just a `pyproject.toml`.
- [X] T023 [US1] Integration test `scan_python_fixtures_emits_conformant_sboms` in mikebom-cli/tests/scan_python.rs — for each fixture under tests/fixtures/python/, run `scan_path()` and assert: (a) expected component count; (b) every PURL round-trips through the `packageurl` Rust crate via `Purl::new(raw).as_str() == raw`; (c) license coverage on simple-venv ≥95% (SC-005); (d) pyproject-only emits zero components and logs the skip message; (e) requirements-only components have `confidence == 0.70` and carry `mikebom:requirement-range` property; (f) every emitted component carries `mikebom:sbom-tier` with the expected value per R13 mapping (simple-venv → `deployed`, poetry-project → `source`, pipfile-project → `source`, requirements-only → `design`); (g) envelope `metadata.lifecycles[]` contains the correct union.

**Checkpoint**: US1 fully functional. Scanning a Python project produces the expected SBOM shape; MVP-ready.

---

## Phase 4: User Story 2 — Scan a Node.js project directory (Priority: P1)

**Goal**: `mikebom sbom scan --path .` on a Node.js project produces a CycloneDX SBOM with prod-only components by default (npm + Poetry + Pipfile dev-deps hidden), SHA-512 hashes from lockfile integrity, scoped PURL encoding, v1-lockfile refusal, and `package.json`-only fallback at confidence 0.70.

**Independent Test**: Scan tests/fixtures/npm/lockfile-v3; assert prod-only component count matches expected (~N minus devs); scoped PURL like `pkg:npm/%40angular/core@...` present; SHA-512 hashes populated. Scan tests/fixtures/npm/lockfile-v1-refused; assert non-zero exit + stderr message.

### Implementation for User Story 2

- [X] T024 [US2] Create mikebom-cli/src/scan_fs/package_db/npm.rs with module skeleton: public `read(rootfs: &Path, include_dev: bool) -> Result<Vec<PackageDbEntry>, NpmError>` (note `Result` — v1 refusal returns an error). Private structs per data-model.md §3. Register in `package_db::mod.rs` dispatcher. Unit test: module compiles.
- [X] T025 [P] [US2] Implement `NpmIntegrity` SRI decoder in npm.rs: parse `sha512-<base64>` / `sha384-<b64>` / `sha256-<b64>` / `sha1-<b64>` into `(algorithm: String, hex: String)` tuple. Base64 → hex conversion preserves the algorithm prefix. Unit tests: each of the four SHA variants, malformed input (missing hyphen, wrong base64), empty input.
- [X] T026 [P] [US2] Implement `NpmLockfileV3Entry` parser for `package-lock.json` v2/v3 in npm.rs using `serde_json`. Iterate the top-level `"packages"` object; for each key, extract path-as-pkg-name (last `node_modules/<name>` segment), version, integrity, `dev: true` flag, `optional: true`, `resolved:` URL. Root entry (`""`) is skipped. Workspace sub-packages (detected via `link: true`) are skipped. Unit tests: single-package lockfile, nested `node_modules/foo/node_modules/bar`, scoped `@scope/pkg`, `dev: true` propagation, optional flag.
- [X] T027 [US2] Implement v1 lockfile refusal in npm.rs: detect `"lockfileVersion": 1` early in the parse function; return a typed `NpmError::LockfileV1Unsupported { path }`. Wire scan_cmd::execute to convert this error into a non-zero exit with the stderr message `"error: package-lock.json v1 not supported; regenerate with npm ≥7"` per contracts/cli-interface.md. Unit tests: v1 detection triggers the error; v2 and v3 parse normally.
- [X] T028 [P] [US2] Implement `PnpmLockfileEntry` parser in npm.rs using `serde_yaml` for `pnpm-lock.yaml`. Dispatch on `lockfileVersion` top-level field: v6/v7 use the `packages:` key-per-package shape, v9 uses `snapshots:` for resolved versions + `packages:` for registry metadata. Join on package key. Unit tests: v6, v7, v9 samples.
- [X] T029 [P] [US2] Implement `NpmPackageJsonEntry` walker in npm.rs for the flat `node_modules/` case. Walk `node_modules/<scope>?/<pkg>/package.json` (scoped packages nested one level), extract `name`, `version`, `license`, `dependencies` keys. Unit tests: unscoped pkg, scoped pkg, missing license field, nested node_modules.
- [X] T030 [P] [US2] Implement `RootPackageJsonFallbackEntry` parser in npm.rs (FR-007a fallback): when no lockfile AND no populated `node_modules/` exist, read the root `package.json`, extract `dependencies` always and `devDependencies` when `include_dev == true`. Each dep becomes a `PackageDbEntry` with `version = ""`, `requirement_range = Some("<range>")`, `is_dev = Some(true_or_false_per_section)`, confidence 0.70. Emit `mikebom:source-type` property for non-registry entries (`file:`, `git+`, `http(s):`, `github:`-style) via the new `source_type` field. Unit tests: dependencies only, dependencies + devDependencies, file: path, git+ URL, https URL, github: shorthand.
- [X] T031 [US2] Implement npm source-selection + drift resolution in npm.rs `read()`: prefer lockfile when present, fall back to `node_modules/` walk, fall back to root-`package.json` fallback. When lockfile AND `node_modules/` disagree on a package's version, prefer `node_modules/` per research.md R8; suppress the lockfile entry with a debug-level drift note. Mark `"npm"` in `complete_ecosystems` only when lockfile v2/v3 OR `pnpm-lock.yaml` v6+ was read in full (not for the fallback tier). Unit tests: lockfile-present, node_modules-only, root-pkgjson-only, drift.
- [X] T032 [US2] Implement the conversion `NpmLockfileV3Entry | PnpmLockfileEntry | NpmPackageJsonEntry | RootPackageJsonFallbackEntry → PackageDbEntry` in npm.rs. PURL: unscoped `pkg:npm/<name>@<version>`, scoped `pkg:npm/%40<scope>/<name>@<version>` with `@` encoded. Route name + version through `encode_purl_segment` to handle `+` edge cases. `integrity` SRI → `ContentHash` (algorithm + hex). `is_dev` populated per source. `sbom_tier` populated per research.md R13: `NpmLockfileV3Entry` / `PnpmLockfileEntry` → `Source` when the corresponding `node_modules/` is absent on the scanned rootfs, `Deployed` when `node_modules/` is present (because the lockfile then mirrors installed state); `NpmPackageJsonEntry` (node_modules walk) → `Deployed`; `RootPackageJsonFallbackEntry` → `Design`. The npm `path_resolver` `.tgz` cache matches (T033) → `Analyzed`. Unit tests: each source + scoped + unscoped + each tier combination produces correct PURL, hash, flag, tier.
- [X] T033 [P] [US2] Extend mikebom-cli/src/resolve/path_resolver.rs with `resolve_npm_path()` matching `*.tgz` entries under `~/.npm/_cacache/content-v2/sha512/*/`, `node_modules/.registry.npmjs.org/*`, and general `.tgz` cache paths. Emit `pkg:npm/<name>@<version>` at confidence 0.70. Unit tests: tarball name patterns, `@scope-name-<version>.tgz` format.
- [X] T034 [P] [US2] Verify or extend the npm branch in mikebom-cli/src/generate/cpe.rs: `synthesize_cpes` must emit the product-as-vendor candidate (`cpe:2.3:a:<name>:<name>:<version>:*:...`) AND, for scoped packages, the scope-as-vendor candidate (`cpe:2.3:a:<scope>:<name>:<version>:*:...`). If the scope candidate is missing, add it. Unit tests: unscoped + scoped cases.
- [X] T035 [US2] Populate fixtures under tests/fixtures/npm/: lockfile-v3/ (a real-ish `package-lock.json` with ~10 packages, mix of prod + dev, at least one scoped package, one optional package); lockfile-v1-refused/ (a valid-syntax v1 `package-lock.json`); pnpm-v8/ (a real `pnpm-lock.yaml` v9 sample); node-modules-walk/ (a flat `node_modules/` with 5+ packages, no lockfile); package-json-only/ (a `package.json` with dependencies + devDependencies, no lockfile, no node_modules); scoped-package/ (lockfile containing only `@org/pkg`).
- [X] T036 [US2] Integration test `scan_npm_fixtures_emits_conformant_sboms` in mikebom-cli/tests/scan_npm.rs — for each fixture, run `scan_path()` and assert: (a) expected component count (prod-only default, prod+dev with `--include-dev`); (b) every PURL round-trips via `Purl::new(raw).as_str() == raw`; (c) SHA-512 hashes populated on ≥80% of lockfile components; (d) scoped PURL has `%40`; (e) dev components carry `mikebom:dev-dependency = true` property when `--include-dev` was set; (f) range fallback emits `mikebom:requirement-range`; (g) every emitted component carries `mikebom:sbom-tier` with the expected value per R13 mapping (lockfile-v3 with no node_modules → `source`, node-modules-walk → `deployed`, pnpm-v8 with no node_modules → `source`, package-json-only → `design`, scoped-package → same as its source); (h) envelope `metadata.lifecycles[]` contains the correct union.
- [X] T037 [US2] Integration test `scan_npm_v1_lockfile_refuses_with_actionable_error` — run scan on lockfile-v1-refused/; assert process exit code non-zero, stderr contains `"package-lock.json v1 not supported; regenerate with npm ≥7"`, no SBOM file written.

**Checkpoint**: US2 fully functional. Node.js projects scan end-to-end with dev/prod scoping and v1 refusal. With US1 + US2 complete, mikebom now covers 4/10 ecosystems (deb, apk, pypi, npm).

---

## Phase 5: User Story 3 — Container-image scan with Python / npm workloads (Priority: P2)

**Goal**: `mikebom sbom scan --image <tar>` on a container image produces OS-level (deb/apk) components AND Python site-packages / npm `node_modules/` components in one SBOM, with separate per-ecosystem `aggregate: complete` composition records.

**Independent Test**: `docker save python:3.12-slim -o /tmp/py.tar && mikebom sbom scan --image /tmp/py.tar` emits both deb + pypi components with a `complete`-aggregate composition for each that was read in full.

### Implementation for User Story 3

- [X] T038 [US3] Extend mikebom-cli/src/scan_fs/mod.rs `scan_path()` to call `package_db::pip::read()` with the image-mode walk path candidates per research.md R10: `<rootfs>/usr/lib/python3*/dist-packages/`, `<rootfs>/usr/lib/python3*/site-packages/`, `<rootfs>/usr/local/lib/python3*/site-packages/`, `<rootfs>/opt/app/.venv/lib/python3*/site-packages/`, plus a bounded-depth (8-level) recursive walk for other `site-packages/` locations. Unit tests: a synthetic rootfs containing `site-packages/` at each candidate location is walked.
- [X] T039 [US3] Extend scan_path() to call `package_db::npm::read()` with the image-mode walk paths: `<rootfs>/usr/lib/node_modules/`, `<rootfs>/usr/local/lib/node_modules/`, `<rootfs>/opt/app/node_modules/`. Add a bounded-depth recursive fallback. The explicit image-config `WORKDIR` hint is a follow-up TODO per research.md R10; add a TODO comment referencing it. Unit tests: synthetic rootfs with `node_modules/` at each candidate location.
- [X] T040 [US3] Integration test `scan_python_image_emits_mixed_sbom` — scan tests/fixtures/images/python-app.tar (small docker-save tarball of `python:3.12-slim` with a FastAPI dep pre-installed, committed as LFS or regenerated at test time). Assert: deb components present; pypi components present; compositions has ≥2 `aggregate: complete` records (one for `deb`, one for `pypi`); no PURL collisions.
- [X] T041 [US3] Integration test `scan_node_image_emits_mixed_sbom` — similar pattern for `node:20-alpine` + a small Express dep. Assert: apk + npm components; `aggregate: complete` for both.

**Checkpoint**: US3 done. Container-image scans cover Python + npm alongside the OS layer.

---

## Phase 6: User Story 4 — Dependency tree for Python and npm components (Priority: P2)

**Goal**: CycloneDX output contains `dependencies[]` edges for Python (from `Requires-Dist:`) and npm (from lockfile nested tree / node_modules walks / pnpm), filtered to observed components only; unsatisfied requirements dropped silently. Edge provenance tagged per source.

**Independent Test**: Scan a fixture containing `requests` + its transitive deps; assert `requests` depends-on `urllib3`, `certifi`, `charset-normalizer`, `idna` — exact pinned versions, not ranges.

### Implementation for User Story 4

- [X] T042 [US4] Extend mikebom-cli/src/scan_fs/package_db/pip.rs to emit `Relationship` edges: after collecting all pypi `PackageDbEntry` records, iterate each entry's `Requires-Dist` tokens and emit one `Relationship { from: parent_purl, to: child_purl, type: DependsOn, provenance: "dist-info-requires-dist" }` per token that resolves to another observed pypi component. Drop unresolved names silently. Unit tests: resolved + unresolved targets; multi-level chain.
- [X] T043 [US4] Extend pip.rs to emit `Relationship` edges from poetry.lock (provenance `"poetry-lock"`) and Pipfile.lock (provenance `"pipfile-lock"`) dep tables. Unit tests per source.
- [X] T044 [US4] Extend mikebom-cli/src/scan_fs/package_db/npm.rs to emit `Relationship` edges: for `package-lock.json` v2/v3, walk each entry's `dependencies:` nested object; for pnpm, walk the per-snapshot `dependencies:` key; for `node_modules` walk entries, use the parsed `package.json` `dependencies` field. Provenance values per data-model.md §4. Filter unresolved. Unit tests: lockfile chain, pnpm chain, walk chain.
- [X] T045 [US4] Integration test `python_dependency_tree_resolves_transitively` — scan a venv fixture containing `requests` (pin 2.31.0) + the four standard transitive deps; assert the SBOM's `dependencies[]` section contains a record `{ ref: "pkg:pypi/requests@2.31.0", dependsOn: [urllib3, certifi, charset-normalizer, idna at their observed versions] }`.
- [X] T046 [US4] Integration test `npm_dependency_tree_reflects_lockfile` — scan lockfile-v3 fixture containing `express` with pinned transitive deps (body-parser, cookie-signature, etc.); assert `dependencies[]` record for express lists its direct deps at the exact lockfile-resolved versions.

**Checkpoint**: US4 done. Dependency-tree edges emit for Python + npm; SC-006 is verifiable.

---

## Phase 7: User Story 5 — Offline / air-gapped operation (Priority: P3)

**Goal**: `mikebom --offline sbom scan` produces a valid SBOM for Python + npm projects with no outbound network calls. Licenses sourced from local `METADATA` / `package.json` only; deps.dev enrichment silently skipped. Online run differs only by added deps.dev license entries and `evidence.identity.tools[]` refs.

**Independent Test**: Run the same pypi scan twice — once online, once `--offline`. Same component count, same purls. `evidence.identity.tools[].ref` containing `deps.dev:` appears only in the online run.

### Implementation for User Story 5

- [ ] T047 [US5] Integration test `pypi_offline_parity` in mikebom-cli/tests/offline_parity.rs — run a pypi scan with `--offline` and again without; assert `len(components) == len(components)`; assert zero `deps.dev` tool-refs in offline output; assert ≥95% of components still have a populated `licenses[]` offline (from local METADATA).
- [ ] T048 [US5] Integration test `npm_offline_parity` — same pattern for npm. Assert that SHA-512 hashes are preserved in both modes (they come from the lockfile, not deps.dev).
- [ ] T049 [US5] Verify that `enrich::depsdev_source::enrich_components` already correctly skips when `offline = true` for the new pypi + npm components (both ecosystems are already in `deps_dev_system_for()`). No new code expected; add a unit test asserting offline mode short-circuits before any HTTP call.

**Checkpoint**: US5 done. `--offline` is a first-class mode for Python + npm too.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Documentation, benchmarks, regression safeguards, and cross-tool comparison.

- [ ] T050 [P] Update EVALUATION.md with Python + npm coverage rows in the metadata comparison tables vs syft + trivy on a reference set (python:3.12-slim and node:20-alpine). Include per-metric counts (components found, licenses, hashes, dev-scope). Record the cross-tool comparison from research R6 for the FR-007a fallback shape.
- [ ] T051 [P] Run `cargo test --workspace --all-targets` locally; confirm green; record the new test count and verify it's ≥30 added (SC-010). Fix any regressions before merge.
- [ ] T052 [P] Run `cargo clippy --all-targets --all-features -- -D warnings`; fix any new warnings; record confirmation in the PR description.
- [ ] T053 [P] Performance benchmark: on a 500-package Python venv (checked-in fixture) and a 1000-package `node_modules/` tree, time `mikebom sbom scan --path .` with `--offline`. Assert wall-clock ≤10 s on a modern dev laptop (SC-007). If over budget, profile the hot path and file a follow-up TODO; do NOT ship performance regressions.
- [ ] T054 Run the end-to-end quickstart.md scenarios (except ones requiring pulling large containers — document those as manual-smoke). Record command outputs and expected values in a new mikebom-cli/tests/quickstart_smoke.rs if feasible; otherwise attach to the PR description.
- [ ] T055 [P] Add a fixture-based cross-tool comparison: `mikebom sbom scan`, `trivy fs`, and `syft` on the same Python venv + the same Node project. Store both the mikebom output and expected deltas (component counts, PURL conformance) as part of EVALUATION.md refresh in T050. No CI integration (trivy/syft aren't checked-in binaries) — human-driven verification at release time.
- [ ] T056 Final constitution gate: re-read `.specify/memory/constitution.md`; confirm all 12 principles still pass on the resulting code. Specifically verify: (I) no C introduced, (II) scan-mode SBOMs correctly stamp `GenerationContext::FilesystemScan` or `ContainerImageScan` (never `BuildTimeTrace`), (III) the v1 refusal is the one sanctioned hard-fail, (IV) no `.unwrap()` in production paths (run `rg '\.unwrap\(\)' mikebom-cli/src/ mikebom-common/src/ | rg -v '#\[cfg\(test'`), (V) `packageurl-python` round-trip holds for every new component. Document the check in the PR description.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies; start immediately.
- **Foundational (Phase 2)**: depends on Setup; BLOCKS all user stories.
- **US1 + US2 (Phases 3–4)**: both unblock after Foundational. They can run fully in parallel by different developers — no cross-story file ownership.
- **US3 (Phase 5)**: depends on BOTH US1 and US2 (wires each ecosystem's reader into image-mode walk paths).
- **US4 (Phase 6)**: depends on US1 and US2 (extends each reader with edge emission).
- **US5 (Phase 7)**: depends on US1 and US2 (offline behaviour tested against both ecosystems); orthogonal to US3/US4.
- **Polish (Phase 8)**: depends on all desired user stories complete.

### User Story Dependencies (detail)

- **US1 (P1)**: blocked only by Foundational. Fully independent. MVP candidate.
- **US2 (P1)**: blocked only by Foundational. Fully independent. Parallel with US1. MVP candidate.
- **US3 (P2)**: blocked by US1 and US2 (needs both readers to demonstrate mixed output).
- **US4 (P2)**: blocked by US1 and US2. Can run parallel with US3.
- **US5 (P3)**: blocked by US1 and US2. Can run parallel with US3 + US4.

### Within each user story

- Parser implementation tasks (marked `[P]` where they touch independent files) can run in parallel once the module skeleton task completes.
- Integration test tasks depend on the related implementation tasks being merged.
- Conversion tasks (source struct → `PackageDbEntry`) depend on all source-struct parsers for that ecosystem.

### Parallel opportunities

- All Setup tasks marked `[P]` (T002, T003) run in parallel.
- All Foundational `[P]` tasks (T005, T007, T009) run in parallel; T004, T006, T008 are sequential-ish due to touching central types.
- US1 parser bodies: T011–T016 are all `[P]` (independent parsers in separate functions within pip.rs — use separate draft commits, rebase into pip.rs at end).
- US2 parser bodies: T025, T026, T028–T030, T033, T034 are all `[P]`.
- US1 and US2 can run completely in parallel across developers.
- US3, US4, US5 can run in parallel once US1 + US2 land.
- Polish tasks T050–T053, T055 are all `[P]`.

---

## Parallel Example: User Story 1 (kickoff after Foundational)

```bash
# After T010 creates the pip.rs skeleton, six parsers can draft in parallel:
Task: "Implement license precedence helper in pip.rs (T011)"
Task: "Implement PipDistInfoEntry parser in pip.rs (T012)"
Task: "Implement PEP 508 Requires-Dist tokenizer in pip.rs (T013)"
Task: "Implement PoetryLockEntry parser in pip.rs (T014)"
Task: "Implement PipfileLockEntry parser in pip.rs (T015)"
Task: "Implement RequirementsTxtEntry parser in pip.rs (T016)"

# Once merged, conversion + discovery can proceed:
Task: "Implement source-struct-to-PackageDbEntry conversion (T017)"
Task: "Implement venv/lockfile/requirements discovery orchestrator (T018)"
```

## Parallel Example: User Story 2 (kickoff after Foundational)

```bash
# After T024 creates the npm.rs skeleton:
Task: "Implement NpmIntegrity SRI decoder in npm.rs (T025)"
Task: "Implement NpmLockfileV3Entry parser in npm.rs (T026)"
Task: "Implement PnpmLockfileEntry parser in npm.rs (T028)"
Task: "Implement NpmPackageJsonEntry walker in npm.rs (T029)"
Task: "Implement RootPackageJsonFallbackEntry parser in npm.rs (T030)"
```

---

## Implementation Strategy

### MVP (User Story 1 only — Python)

1. Phase 1: Setup (T001–T003).
2. Phase 2: Foundational (T004–T009) — CRITICAL, blocks everything.
3. Phase 3: User Story 1 (T010–T023).
4. **STOP + VALIDATE**: run T023 integration test; scan a real Python project; compare against trivy.
5. Deploy/demo: "mikebom now scans Python" release.

### Incremental delivery

1. Ship MVP (US1) → Python support announced.
2. Add US2 (npm) → announce npm support.
3. Add US3 → announce container-image Python + npm parity.
4. Add US4 → dependency-tree output reaches trivy parity.
5. Add US5 → offline parity.
6. Polish (Phase 8) → release 0.3.0 (or whatever version matches the roadmap cadence).

### Parallel team strategy

- Developer A: Setup + Foundational (T001–T009) → US1 (T010–T023).
- Developer B: waits for Foundational completion, then US2 (T024–T037) in parallel with US1.
- Once both land: Developer A takes US3 + US4, Developer B takes US5, or split differently.
- Polish is shared.

---

## Notes

- `[P]` tasks touch different files OR different functions in the same file with no implicit ordering. Co-authored commits to the same file are fine via rebase, but prefer landing independent file changes as separate PRs when possible.
- Every ecosystem reader's output must round-trip through `Purl::new` — this is a Constitution V gate, not a per-task assertion.
- Add `#[cfg(test)] mod tests {}` blocks colocated with implementation, matching the project convention established in dpkg.rs + apk.rs. Integration tests live under `mikebom-cli/tests/*.rs`.
- Don't mark a parser task complete without its unit tests green. TDD-first is optional; ship-with-tests is mandatory per SC-010.
- Commit after each task or logical group. Stop at any checkpoint to validate story-level acceptance before proceeding.
- Avoid: adding a new workspace crate (Constitution VI), introducing `.unwrap()` (Constitution IV), bypassing `encode_purl_segment` for PURL construction (Constitution V), emitting components without evidence (Principle X).
