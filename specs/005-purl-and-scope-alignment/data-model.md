# Phase 1 Data Model: PURL & Scope Alignment

**Feature**: `005-purl-and-scope-alignment`
**Date**: 2026-04-20

This feature introduces one new enum (`ScanMode`), one new struct (`ScanDiagnostics`), and adds two optional fields to the existing `PackageDbEntry`. It does not introduce persistent state, database tables, or network-visible schemas.

## Existing types (reference only — not changed)

- `PackageDbEntry` — lives in `mikebom-cli/src/scan_fs/package_db/mod.rs`. Represents a single component discovered by any of the per-ecosystem readers (dpkg/apk/pip/npm/rpm/etc.). Currently has fields including `purl: Purl`, `name: String`, `version: String`, `arch: Option<String>`, `source_path: String`, `depends: Vec<String>`, `evidence_kind: Option<String>`, etc.
- `Purl` — newtype in `mikebom-common/src/types/purl.rs`. Validates PURL-spec compliance at construction.

## New: `ScanMode`

Location: `mikebom-cli/src/scan_fs/mod.rs` (near `scan_path`).

```rust
/// How the caller invoked mikebom — image-tarball extraction vs.
/// plain directory. Drives scan-mode-aware scoping decisions like
/// npm-internals inclusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanMode {
    /// `mikebom sbom scan --path <dir>` — the target IS the application,
    /// not a runtime environment. Tool-internal packages (npm's own
    /// packages, future analogues in other ecosystems) are out of scope.
    Path,

    /// `mikebom sbom scan --image <tarball>` — the target IS the full
    /// filesystem of a container. Everything present in the image is in
    /// scope, including tool-internal packages, because a CVE in any of
    /// them is exploitable.
    Image,
}
```

**Validation rules**: none — enum is exhaustive.

**State transitions**: set once at CLI-argument parse time; never mutated.

## New: `ScanDiagnostics`

Location: `mikebom-cli/src/scan_fs/package_db/mod.rs` (alongside `DbScanResult`).

```rust
/// Non-fatal diagnostics collected during `read_all`. Surfaced into
/// the SBOM's `metadata.properties` so consumers can detect degraded
/// output without needing the scanner's log stream.
///
/// Intentionally open-ended so future scan-time diagnostics can be
/// added without cross-module churn.
#[derive(Default, Debug, Clone)]
pub struct ScanDiagnostics {
    /// Fields from `/etc/os-release` that were absent or empty. Each
    /// entry is a string naming the missing field (e.g. "ID",
    /// "VERSION_ID"). Deduplicated; order is insertion order.
    pub os_release_missing_fields: Vec<String>,
}

impl ScanDiagnostics {
    /// Record a missing os-release field. No-op if already recorded.
    pub fn record_missing_os_release_field(&mut self, field: &str) {
        if !self.os_release_missing_fields.iter().any(|f| f == field) {
            self.os_release_missing_fields.push(field.to_string());
        }
    }
}
```

**Validation rules**:

- `os_release_missing_fields` entries MUST be uppercase os-release field names (`ID`, `VERSION_ID`) matching the case used in `/etc/os-release` files. Helper guarantees dedup.

**State transitions**: populated during `read_all`; read-only after that; threaded to the CycloneDX metadata builder.

**Emission rule** (in `generate/cyclonedx/metadata.rs::build_metadata`): if `os_release_missing_fields` is non-empty, append `{ name: "mikebom:os-release-missing-fields", value: <comma-joined, no spaces> }`. If empty, omit the property entirely.

## Extended: `PackageDbEntry`

Two new optional fields. Both default to `None` on existing readers; populated only by readers that have the necessary context.

```rust
pub struct PackageDbEntry {
    // ... existing fields unchanged ...

    /// Preserves the raw `%{VERSION}-%{RELEASE}` string from the rpmdb
    /// header (or the `.rpm` artefact's equivalent), unmangled. Emitted
    /// as a CycloneDX component property `mikebom:raw-version` when
    /// set. Lets consumers round-trip back to the package manager's
    /// native representation even when purl-spec encoding rules
    /// transform the PURL version segment.
    ///
    /// Set by: rpm.rs::assemble_entry, rpm_file.rs::parse_rpm_file.
    /// None for all other readers.
    pub raw_version: Option<String>,

    /// Role marker for packages that are part of a package-manager's
    /// own toolchain rather than an application's dependencies (e.g.
    /// packages under node_modules/npm/node_modules/). When set, the
    /// value appears as the CycloneDX component property
    /// `mikebom:npm-role` (currently only the literal "internal" is
    /// used; additional roles may be defined in future).
    ///
    /// Set by: npm.rs::walk_node_modules when inside the npm-internals
    /// glob. None otherwise.
    pub npm_role: Option<String>,
}
```

**Validation rules**:

- `raw_version`: when set, MUST be non-empty. Character set: whatever the rpmdb header / `.rpm` artefact contained — no mikebom-side re-encoding.
- `npm_role`: when set, MUST be the literal string `"internal"` in this release. Future values are a non-breaking additive change.

**Serialization**: both fields serialize to CycloneDX component properties at CycloneDX-builder time. They are not part of the PURL — they're informational side-band data.

## Updated: existing function signatures (data-flow level, not code)

### `scan_path` (file `mikebom-cli/src/scan_fs/mod.rs`)

Gains a `scan_mode: ScanMode` parameter. Threaded from `cli/scan_cmd.rs`.

### `package_db::read_all` (file `mikebom-cli/src/scan_fs/package_db/mod.rs`)

- Gains a `scan_mode: ScanMode` parameter — passed to `npm::read`.
- Returns `ScanDiagnostics` alongside the existing `DbScanResult` (either as an extra tuple element or as a new field on `DbScanResult` — the latter is preferred to avoid changing every call site's destructuring).

### `dpkg::read` + `dpkg::build_deb_purl`

- `read` gains a `namespace: &str` parameter (the lowercased `/etc/os-release::ID` value from the scanned rootfs, or `"debian"` on fallback).
- `read` drops the old `deb_codename: Option<&str>` parameter.
- `read` gains a `distro_version: Option<&str>` parameter (the `/etc/os-release::VERSION_ID` value, or `None` if absent).
- `build_deb_purl` signature mirrors this: `fn build_deb_purl(name: &str, version: &str, arch: Option<&str>, namespace: &str, distro_version: Option<&str>) -> String`.

### `npm::read`

Gains a `scan_mode: ScanMode` parameter. When `ScanMode::Path`, the `walk_node_modules` helper skips descent into directories matching the npm-internals glob. When `ScanMode::Image`, it walks them, and every component found inside gets `npm_role = Some("internal".to_string())`.

### `rpm::assemble_entry` + `rpm_file::parse_rpm_file`

Populate `raw_version = Some(format!("{version}-{release}"))` on the returned entry. No signature change.

## Relationships

```text
CLI args (--image|--path)
    │
    ▼
ScanMode::{Image,Path}
    │
    └──▶ scan_path(rootfs, scan_mode)
            │
            └──▶ package_db::read_all(rootfs, scan_mode, ...)
                    │
                    ├──▶ npm::read(rootfs, scan_mode, ...)
                    │         └─ sets entry.npm_role when scan_mode == Image
                    │            and path matches glob
                    │
                    ├──▶ dpkg::read(rootfs, namespace, distro_version, ...)
                    │         └─ uses namespace + distro_version in PURL
                    │
                    ├──▶ rpm::read(rootfs, ...)
                    │         └─ sets entry.raw_version
                    │
                    └──▶ collects ScanDiagnostics.os_release_missing_fields
                            │
                            ▼
                    cyclonedx::metadata::build_metadata(&diagnostics)
                            │
                            └─ emits `mikebom:os-release-missing-fields`
                               when non-empty
```

## Invariants

- **No field deletion**: existing `PackageDbEntry` fields are unchanged. All additions are optional.
- **Byte-stability for alpine + rpm PURLs** (SC-004): a test at the end of Phase 3 verifies that every PURL previously emitted for alpine and rpm fixtures is byte-equal to the post-change emission. Any difference is a regression.
- **No new cross-crate dependencies**: all changes stay in `mikebom-cli`; the `PackageDbEntry` struct is defined there per current-state audit.
- **ScanMode plumbing is single-direction**: CLI → scan_path → readers. Readers never read ScanMode from ambient state; it's always passed.
