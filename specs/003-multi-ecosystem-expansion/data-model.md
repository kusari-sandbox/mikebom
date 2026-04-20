# Data Model — Milestone 003

All new ecosystems reuse `PackageDbEntry` (in `mikebom-cli/src/scan_fs/package_db/mod.rs`) and `ResolvedComponent` (in `mikebom-common/src/resolution.rs`) without schema additions. This milestone only introduces **internal** intermediate structs local to each ecosystem reader, plus one new file-level diagnostic property. No changes to `mikebom-common` types are required, so attestation-format consumers remain unaffected.

---

## 1. `PackageDbEntry` field mapping (per ecosystem)

| Field | Go source | Go binary | RPM | Maven pom | Maven JAR | Cargo | Gem |
|---|---|---|---|---|---|---|---|
| `purl` | `pkg:golang/<module>@<ver>` | same | `pkg:rpm/<vendor>/<name>@<epoch>:<ver>-<rel>?arch=<arch>` | `pkg:maven/<groupId>/<artifactId>@<ver>` | same | `pkg:cargo/<name>@<ver>` | `pkg:gem/<name>@<ver>` |
| `name` | module path | same | name | `<artifactId>` | same | crate name | gem name |
| `version` | go.sum version | BuildInfo version | `<epoch>:<ver>-<rel>` | pom `<version>` | MANIFEST-derived | Cargo.lock version | Gemfile.lock version |
| `arch` | `None` | `None` | rpmdb `arch` column | `None` | `None` | `None` | `None` |
| `source_path` | absolute path to go.sum | absolute path to binary | absolute path to rpmdb.sqlite | absolute path to pom.xml | absolute path to JAR | absolute path to Cargo.lock | absolute path to Gemfile.lock |
| `depends` | go.mod `require` names | BuildInfo `dep` lines | rpmdb `REQUIRES` tokens | pom `<dependencies>` artifactId | same | `[[package]].dependencies` names | Gemfile.lock `DEPENDENCIES` block names |
| `maintainer` | `None` | `None` | rpmdb `PACKAGER` column | pom `<developers>` (optional) | MANIFEST `Bundle-Vendor` (optional) | `None` | `None` |
| `is_dev` | `None` | `None` | `None` (RPM has no dev/prod) | `Some(true)` if `<scope>test</scope>`, else `Some(false)` | `None` | `None` (Cargo distinguishes via `[dev-dependencies]` in Cargo.toml, not Cargo.lock) | `None` |
| `requirement_range` | `None` | `None` | `None` | `Some("<raw-placeholder>")` for unresolved property refs | `None` | `None` | `None` |
| `source_type` | `None` for registry; `Some("git")` for `+incompatible`/replace-local | `None` | `None` | `None` | `None` | `Some("git"/"path"/"registry")` per Cargo.lock `source =` field | `Some("git"/"path")` for GIT/PATH sections |
| `licenses` | populated if deps.dev online | same | rpmdb `LICENSE` column (validated through `SpdxExpression::try_canonical`) | pom `<licenses>` (optional) | MANIFEST `Bundle-License` / `License` (optional) | empty (Cargo.lock doesn't carry license) | empty (Gemfile.lock doesn't carry license) |
| `sbom_tier` | `Some("source")` | `Some("analyzed")` | `Some("deployed")` | `Some("source")` resolved, `Some("design")` if unresolved | `Some("analyzed")` | `Some("source")` | `Some("source")` |

**Dedup behaviour** (reused from milestone 002): entries with identical PURLs merge across ecosystems' output; the higher-tier entry wins (`deployed > source > analyzed > design`). For Go specifically, when a source scan (`source`) and binary scan (`analyzed`) observe the same module at the same version, the source entry wins per FR-014; evidence paths merge.

---

## 2. Ecosystem-specific internal structs

These live in their respective reader modules. They are NOT exposed in `mikebom-common` and never serialized to the SBOM directly — they are intermediate representations that convert into `PackageDbEntry` at the end of each reader's `read()` entry point.

### 2.1 `GoModEntry` (in `scan_fs/package_db/golang.rs`)

```rust
pub(crate) struct GoModEntry {
    pub module_path: String,  // e.g. "github.com/spf13/cobra"
    pub version: String,      // e.g. "v1.7.0" or "v0.0.0-20230101000000-abcdef"
    pub hash: Option<String>, // go.sum h1: hash when available
    pub require_kind: RequireKind,
}

pub(crate) enum RequireKind {
    Direct,                // in go.mod `require` block
    Indirect,              // go.sum only (transitive)
    Replaced { target: String, target_version: String }, // replace directive resolved
}
```

### 2.2 `GoBinaryInfo` (in `scan_fs/package_db/go_binary.rs`)

```rust
pub(crate) struct GoBinaryInfo {
    pub binary_path: PathBuf,
    pub format: BinaryFormat, // ELF | MachO
    pub main_module: String,  // from BuildInfo `path` line
    pub go_version: String,   // from BuildInfo `build -compiler=` or `mod` header
    pub modules: Vec<GoBinaryModule>,
    pub status: BuildInfoStatus,
}

pub(crate) struct GoBinaryModule {
    pub module_path: String,
    pub version: String,
    pub h1_hash: Option<String>,
}

pub(crate) enum BuildInfoStatus {
    Ok,           // parsed successfully
    Missing,      // file looks like a Go binary but no BuildInfo — emit mikebom:buildinfo-status="missing"
    Unsupported,  // Go <1.18 format not handled
}
```

### 2.3 `RpmPackageRow` (in `scan_fs/package_db/rpm.rs`)

```rust
pub(crate) struct RpmPackageRow {
    pub name: String,
    pub epoch: Option<u32>,  // None when zero (canonical PURL omits)
    pub version: String,
    pub release: String,
    pub arch: String,
    pub license: Option<String>,
    pub packager: Option<String>,
    pub requires: Vec<String>, // REQUIRES column tokenised to bare names
    pub vendor: String,         // derived from /etc/os-release::ID per R8
}
```

### 2.4 `MavenCoordinate` (in `scan_fs/package_db/maven.rs`)

```rust
pub(crate) struct MavenCoordinate {
    pub group_id: String,
    pub artifact_id: String,
    pub version: MavenVersion,
    pub scope: Option<String>, // "test", "compile", "provided", etc. — None outside pom.xml
    pub origin: MavenOrigin,
    pub licenses: Vec<String>, // raw strings from pom <licenses> or MANIFEST Bundle-License
}

pub(crate) enum MavenVersion {
    Resolved(String),
    Placeholder(String), // e.g. "${project.version}"
}

pub(crate) enum MavenOrigin {
    PomXml { path: PathBuf },
    JarManifest { jar_path: PathBuf },
    JarPomProperties { jar_path: PathBuf, inner_path: String },
}
```

### 2.5 `CargoPackage` (in `scan_fs/package_db/cargo.rs`)

```rust
pub(crate) struct CargoPackage {
    pub name: String,
    pub version: String,
    pub source: CargoSource,
    pub checksum: Option<String>, // hex SHA-256 when source is registry
    pub dependencies: Vec<String>,
}

pub(crate) enum CargoSource {
    Registry(String),     // e.g. "registry+https://github.com/rust-lang/crates.io-index"
    Git { url: String, rev: Option<String> },
    Path(PathBuf),
    Local,                // workspace-local package
}
```

### 2.6 `GemEntry` (in `scan_fs/package_db/gem.rs`)

```rust
pub(crate) struct GemEntry {
    pub name: String,
    pub version: String,
    pub source_section: GemSourceSection,
    pub nested_deps: Vec<String>, // from the indented dep lines in GEM/GIT/PATH sections
}

pub(crate) enum GemSourceSection {
    Gem(String),  // URL, e.g. "https://rubygems.org/"
    Git { url: String, ref_: Option<String> },
    Path(PathBuf),
}
```

---

## 3. `rpmdb_sqlite` module internals (R1 implementation)

Pure-Rust SQLite file-format reader scoped to read-only iteration over a known table. Living in `mikebom-cli/src/scan_fs/package_db/rpmdb_sqlite/`.

```rust
pub(crate) struct SqliteFile {
    pub header: FileHeader,       // 100 bytes
    pub pages: PageReader,         // indexes pages by number
}

pub(crate) struct FileHeader {
    pub page_size: u32,
    pub text_encoding: TextEncoding,
}

pub(crate) enum PageKind {
    InteriorTable,
    LeafTable,
    InteriorIndex,
    LeafIndex,
}

pub(crate) struct Record {
    pub rowid: i64,
    pub columns: Vec<Value>,
}

pub(crate) enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}
```

**Supported scope:**

- Header parsing (page size, text encoding — UTF-8 only; UTF-16LE/BE error out).
- `sqlite_schema` table walk to locate target tables by name.
- Interior + leaf table B-tree iteration (index trees not needed).
- Record format serial types 0 (null), 1-6 (integer widths), 7 (real), 8-9 (zero/one), 12 (blob), 13+ (text).
- Size-capped reads per FR-009: per-page read bounded by `header.page_size`; per-record read bounded by one page (no overflow page support — oversized records return `Err(RpmdbError::RecordTooLarge)`).
- Per-query timeout: enforced by a `tokio::time::timeout` wrapper around the top-level `iter_rows()` call in `rpm.rs`.

**Explicitly out of scope** for this implementation:

- WAL (write-ahead log) files.
- Overflow pages (spec'd but not needed for rpmdb's packaged rows).
- Index B-trees.
- `WITHOUT ROWID` tables.
- UTF-16 text.

---

## 4. New SBOM property keys (per FR-015)

| Key | Attached to | Values | Purpose |
|---|---|---|---|
| `mikebom:buildinfo-status` | Component for a file-level Go binary when BuildInfo extraction failed | `"missing"` \| `"unsupported"` | Operator diagnostic — distinguishes "no modules" from "scan failed". |

Existing property keys reused without change:

- `mikebom:sbom-tier` (every new component)
- `mikebom:source-type` (Cargo git/path, Gem GIT/PATH)
- `mikebom:requirement-range` (Maven unresolved property placeholders)
- `mikebom:dev-dependency` (Maven `<scope>test</scope>` entries when `--include-dev`)

---

## 5. No changes to `mikebom-common`

- `ResolvedComponent` — no new fields.
- `PackageDbEntry` — no new fields.
- `Relationship` — no new fields. Provenance data_type strings per R9 reuse the existing `EnrichmentProvenance` struct.
- `ScanError` / `PackageDbError` — extended by one new variant each for Cargo v1/v2 refusal mirroring the npm v1 pattern:

```rust
// in scan_fs/package_db/mod.rs
pub enum PackageDbError {
    Npm(#[from] npm::NpmError),
    Cargo(#[from] cargo::CargoError),  // NEW in 003
}

// in scan_fs/package_db/cargo.rs
pub enum CargoError {
    LockfileUnsupportedVersion { path: PathBuf, version: u64 },
}
```
