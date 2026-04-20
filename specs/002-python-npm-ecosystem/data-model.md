# Phase 1 Data Model — Python + npm Ecosystem Support

All new types and all modifications to existing types. New readers emit `PackageDbEntry` records so they flow through the existing dedup → CPE → compositions → deps.dev-enrichment pipeline unchanged. The schema changes here are therefore small and additive.

## 1. Existing types — extensions

### 1.1 `PackageDbEntry` (in `mikebom-cli/src/scan_fs/package_db/mod.rs`)

Add one field:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `is_dev` | `Option<bool>` | NEW | `Some(false)` = source declared this a prod dep; `Some(true)` = dev-only; `None` = source doesn't carry the distinction (venv dist-info, requirements.txt). Drives `mikebom:dev-dependency = true` property emission and `--include-dev` filtering. |

No other fields touched. Existing usages backfill `is_dev: None` when constructing the struct (unchanged-by-policy behavior for dpkg + apk readers).

### 1.2 `ResolvedComponent` (in `mikebom-common/src/resolution.rs`)

Already has `cpes`, `supplier`, `occurrences`, `licenses`, `advisories`, `hashes`. Adds four optional fields this milestone (all `#[serde(default, skip_serializing_if = "...")]` for backward-compat with existing attestations):

| Field | Type | Notes |
|-------|------|-------|
| `is_dev` | `Option<bool>` | Dev/prod scope flag surfaced through `mikebom:dev-dependency` property. |
| `requirement_range` | `Option<String>` | Original range spec string from fallback-tier entries. Surfaced via `mikebom:requirement-range` property. |
| `source_type` | `Option<String>` | `"local"` / `"git"` / `"url"` for non-registry npm/pypi source specs. Surfaced via `mikebom:source-type` property. |
| `sbom_tier` | `Option<SbomTier>` | Traceability ladder tier per research.md R13 (`Build`, `Deployed`, `Analyzed`, `Source`, `Design`). Surfaced via `mikebom:sbom-tier` property. Serialised lowercase. |

These four fields carry per-component metadata that drives CycloneDX property emission; they do not add new top-level CycloneDX schema surface.

### 1.3 `ScanResult.complete_ecosystems` (in `mikebom-cli/src/scan_fs/mod.rs`)

`Vec<String>`. Append `"pypi"` when a Python venv or authoritative lockfile is read in full; append `"npm"` when a `package-lock.json` v2/v3 or `pnpm-lock.yaml` v6+ is read in full. Values for this milestone become `["deb", "apk", "pypi", "npm"]` (intersection of whatever the scan actually encountered).

Validation: values are lowercase ecosystem slugs matching `Purl::ecosystem()` output. No duplicates. Order preserved per-scan for determinism.

### 1.4 `ResolutionTechnique` enum

No new variant this milestone. Python and npm components use the existing `PackageDatabase` variant (confidence 0.85 for manifest-analysis) or `FilePathPattern` (confidence 0.70 for filename / requirements-range fallback).

---

## 2. New entity types — Python

All Python types are internal to `mikebom-cli/src/scan_fs/package_db/pip.rs`. They convert to `PackageDbEntry` at the module boundary; nothing below leaks out.

### 2.1 `PipDistInfoEntry`

A parsed `<site-packages>/<name>-<version>.dist-info/METADATA` record.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | `String` | yes | Declared `METADATA::Name:` value, not PEP-503-normalised. |
| `version` | `String` | yes | Declared `METADATA::Version:`. |
| `license_expression` | `Option<String>` | — | PEP 639 `License-Expression:`. Preferred over `License:` if present. |
| `license_raw` | `Option<String>` | — | Legacy `License:` field (free-form). |
| `classifiers` | `Vec<String>` | — | `Classifier: License :: ...` entries for fallback license inference. |
| `requires_dist` | `Vec<String>` | — | Raw PEP 508 requirement strings. Tokenised to bare names on emit. |
| `author` | `Option<String>` | — | `Author` / `Author-email`; concatenated into supplier string. |
| `home_page` | `Option<String>` | — | Used only for supplier provenance; not emitted. |
| `source_path` | `String` | yes | Absolute path to the `METADATA` file for `evidence.source_file_paths`. |

**Confidence when converted to `PackageDbEntry`**: `0.85` (manifest-analysis).

### 2.2 `PoetryLockEntry`

A parsed `[[package]]` block from `poetry.lock`.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | `String` | yes | TOML `name = "..."`. |
| `version` | `String` | yes | TOML `version = "..."`. |
| `category` | `Option<String>` | — | v1 `category = "main" \| "dev"`. v2 carries group info in a nested table. |
| `groups` | `Vec<String>` | — | v2 groups; contains `"main"` when prod, `"dev"` / `"test"` / custom otherwise. |
| `hashes` | `Vec<String>` | — | Raw SRI strings from `[[package.files]] hash = "sha256:..."`. |
| `dependencies` | `Vec<String>` | — | Nested `[package.dependencies]` table keys. |
| `source_path` | `String` | yes | Absolute path to `poetry.lock`. |

**Dev detection**: `true` if `category == "dev"` (v1) OR no group in `groups` equals `"main"` (v2). Otherwise `false`.

### 2.3 `PipfileLockEntry`

A parsed entry from `Pipfile.lock` — two top-level sections: `"default"` (prod) and `"develop"` (dev).

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | `String` | yes | JSON object key. |
| `version` | `String` | yes | `version` field; strip leading `==`. |
| `hashes` | `Vec<String>` | — | `hashes:` array (base64 or hex SHA-256 typically). |
| `section` | `PipfileSection` | yes | `Default` or `Develop`. Drives dev-flag. |
| `source_path` | `String` | yes | Absolute path to `Pipfile.lock`. |

### 2.4 `RequirementsTxtEntry`

A parsed line from `requirements.txt`.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | `String` | yes | Left of the operator (`==`, `>=`, `~=`, `!=`). |
| `version` | `Option<String>` | — | The specific version when operator is `==` (pinned); `None` for range specs. |
| `range_spec` | `Option<String>` | — | The full original line when unpinned (e.g. `requests>=2,<3`). Drives `mikebom:requirement-range` property emission. |
| `url_ref` | `Option<String>` | — | When entry is URL-based (`https://...` or `file://...`), the raw URL; emits a `pkg:generic/...` component per Edge Cases. |
| `source_path` | `String` | yes | Absolute path to the requirements file. |

**Confidence**: `0.70` (filename / requirements fallback).

### 2.5 `PyprojectTomlProjectName` (metadata-only)

Helper type extracted from the root `pyproject.toml` `[project] name = "..."` field only, used to populate the scan target name. Does NOT read `[project.dependencies]` (per FR-005). One field: `name: String`.

---

## 3. New entity types — npm

All npm types are internal to `mikebom-cli/src/scan_fs/package_db/npm.rs`.

### 3.1 `NpmLockfileV3Entry`

A parsed entry from the `packages` object of `package-lock.json` v2 or v3.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `path` | `String` | yes | JSON object key: `""` (root project) or `node_modules/foo` or `node_modules/@scope/bar` or nested paths. |
| `name` | `Option<String>` | — | Declared name from the entry's `name:` field; fall back to the last `node_modules/<name>` segment of `path`. |
| `version` | `String` | yes | Resolved version. |
| `integrity` | `Option<NpmIntegrity>` | — | SRI-decoded struct — `algorithm` (e.g. `SHA-512`, `SHA-384`) + hex-encoded digest. |
| `is_dev` | `bool` | yes | Set from the lockfile's `dev: true` field; `false` when absent. |
| `is_optional` | `bool` | yes | Set from `optional: true`; used to exclude optionals by default (FR-008). |
| `resolved_url` | `Option<String>` | — | The registry URL; preserved only for provenance in `evidence`. |
| `source_path` | `String` | yes | Absolute path to `package-lock.json`. |

Validation:
- `version` MUST be non-empty.
- The root entry (`path == ""`) is NEVER emitted as a component — it's the project itself.
- Workspace roots (where `workspaces: [...]` is set on the root) and their sub-workspace entries are skipped per Edge Cases.

### 3.2 `NpmIntegrity`

Decoded from the lockfile's `integrity: "sha512-<base64>"` field.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `algorithm` | `String` | yes | Uppercase SHA-256 / SHA-384 / SHA-512 / SHA-1, per the prefix. |
| `hex` | `String` | yes | Lowercase hex. Converted from the lockfile's base64 on parse so it matches `ContentHash::value`. |

### 3.3 `PnpmLockfileEntry`

A parsed entry from `pnpm-lock.yaml` (v6 / v7 / v9).

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | `String` | yes | From the lockfile's `packages/<key>/name:` OR parsed from the key (`/foo@1.0.0`). |
| `version` | `String` | yes | Resolved version. |
| `integrity` | `Option<NpmIntegrity>` | — | Optional; same shape as npm's. |
| `is_dev` | `bool` | yes | Derived from `dev: true` on the entry. |
| `source_path` | `String` | yes | Absolute path to `pnpm-lock.yaml`. |

### 3.4 `NpmPackageJsonEntry` (from `node_modules/<name>/package.json`)

When the scanner walks `node_modules/` instead of (or in addition to) a lockfile.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | `String` | yes | `name:` field. |
| `version` | `String` | yes | `version:` field. |
| `license` | `Option<String>` | — | `license:` SPDX string when present. |
| `dependencies` | `Vec<String>` | — | Keys of the `dependencies:` object. |
| `source_path` | `String` | yes | Path to the sub-`package.json`. |

Dev scope on node_modules entries isn't trivially recoverable (the flat tree doesn't carry it), so entries get `is_dev: None` in conversion to `PackageDbEntry`. Drift-detection runs against the lockfile's `NpmLockfileV3Entry` (when both exist); drift wins per R8.

### 3.5 `RootPackageJsonFallbackEntry` (FR-007a, "uninstalled project" tier)

Parsed from the scanned root's `package.json` when no lockfile AND no `node_modules/` is present.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | `String` | yes | Dependency key. |
| `range_spec` | `String` | yes | Dependency value (the range — `^1.2.3`, `~2.0`, `git+...`, `file:...`, etc.). Preserved verbatim for the `mikebom:requirement-range` property. |
| `is_dev` | `bool` | yes | `false` for entries from `dependencies`, `true` for `devDependencies` (only parsed when `--include-dev` is set). |
| `source_path` | `String` | yes | Path to the root `package.json`. |

**Confidence**: `0.70` (filename fallback tier).

---

## 4. Relationship / dependency-edge schema

No new type. Existing `mikebom_common::resolution::Relationship { from, to, relationship_type, provenance }` handles the new edges.

Provenance values added in this milestone:
- `"dist-info-requires-dist"` — Python edge sourced from `METADATA::Requires-Dist:`.
- `"poetry-lock"` — Python edge from `poetry.lock` dependencies table.
- `"pipfile-lock"` — Python edge from `Pipfile.lock`.
- `"npm-lockfile"` — npm edge from `package-lock.json` nested tree.
- `"pnpm-lockfile"` — npm edge from `pnpm-lock.yaml`.
- `"npm-package-json"` — npm edge from node_modules walk.

Existing provenance (deb/apk) unchanged.

---

## 5. CLI arg surface (data shape only — full contract in `contracts/cli-interface.md`)

Extension to the existing CLI root struct:

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `include_dev` | `bool` | `false` | Global flag; threads through to `scan_cmd` and downstream readers. |

Existing `offline: bool` unchanged.

---

## 6. CycloneDX property additions (component-level)

All new properties emitted at `component.properties[]`:

| Property name | Value shape | Condition |
|---------------|-------------|-----------|
| `mikebom:dev-dependency` | `"true"` (string) | Component has `is_dev == Some(true)` after dedup AND `--include-dev` was set. |
| `mikebom:requirement-range` | Original range string (e.g. `^1.2.3`, `requests>=2,<3`) | Component resolved via requirements-fallback tier (FR-004 or FR-007a). |
| `mikebom:source-type` | `"local"` / `"git"` / `"url"` | Component came from a non-registry npm spec (`file:`, `git+ssh://`, `https://…`). |

Existing properties (`mikebom:source-files`, `mikebom:cpe-candidates`, `mikebom:layer-digests`) unchanged.

---

## 7. Determinism requirements

For byte-reproducible SBOMs (already a milestone-001 invariant that new ecosystems must preserve):

- Walker enumeration order: sort `site-packages/*.dist-info/` entries lexicographically before emission.
- Lockfile entry iteration: sort `NpmLockfileV3Entry.path` keys lexicographically before emission.
- Multi-value fields (`requires_dist`, `classifiers`, range specs): preserve source order if the source is ordered (lockfile); sort lexicographically if unordered (JSON object keys).
- Dedup winner stability: when multiple sources produce the same PURL, the comparator tie-breaks by (confidence desc, source_path ascending) — same as today's dpkg/apk code.

---

## 8. Schema-change summary (what other specs might care about)

- `PackageDbEntry` gains `is_dev: Option<bool>`. Existing dpkg/apk call sites backfill `None`. Schema is backwards-compatible at the Rust-type level but not at the attestation-JSON level (the field is private to scan_fs — it drives property emission but isn't serialised directly).
- `ScanResult.complete_ecosystems` grows to include `"pypi"` and `"npm"` when applicable.
- No CycloneDX envelope changes. Three new component-level property names.
- Two new reader modules (`pip.rs`, `npm.rs`) alongside `dpkg.rs` + `apk.rs`. Dispatcher in `mod.rs` adds them.

This is the minimum schema drift needed to ship Python and npm support. Everything else piggybacks on the existing infrastructure.
