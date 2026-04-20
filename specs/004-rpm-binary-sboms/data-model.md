# Phase 1 Data Model — Milestone 004

Defines every new entity, existing-struct extension, and `mikebom:*` property vocabulary introduced by this milestone. All types live in `mikebom-cli` (Principle VI — no new crates). No `mikebom-common` schema changes are required.

---

## Existing-struct extensions

### `PackageDbEntry` (`mikebom-cli/src/scan_fs/package_db/mod.rs`)

ADDS one optional field:

| Field | Type | Purpose |
|---|---|---|
| `evidence_kind` | `Option<String>` | Canonical evidence-kind value per FR-004. Set by every reader that emits a `PackageDbEntry` for serialization via `mikebom:evidence-kind`. `None` during transition on readers not yet retrofitted. |

Backward-compatible: `None` is the safe default; all existing construction sites keep compiling. Milestone 004 updates the three RPM paths (sqlite, bdb, `.rpm`-file) to set this field explicitly.

No other `PackageDbEntry` fields change. No `mikebom-common` changes. No CycloneDX schema changes (property is additive).

---

## New entities — RPM path

### `RpmPackageFile`

Single-value representation of a `.rpm` artefact on disk.

```rust
pub struct RpmPackageFile {
    pub path: PathBuf,                  // Absolute path to the .rpm file
    pub lead_valid: bool,               // Magic match \xED\xAB\xEE\xDB at offset 0
    pub name: String,                   // From header tag NAME (1000)
    pub epoch: u32,                     // From header tag EPOCH (1003), default 0
    pub version: String,                // From header tag VERSION (1001)
    pub release: String,                // From header tag RELEASE (1002)
    pub arch: String,                   // From header tag ARCH (1022); "src" for SRPMs
    pub license: Option<SpdxExpression>,// From header tag LICENSE (1014), SPDX-canonicalised
    pub vendor_header: Option<String>,  // From header tag VENDOR (1011), raw
    pub packager: Option<String>,       // From header tag PACKAGER (1015)
    pub summary: Option<String>,        // From header tag SUMMARY (1004)
    pub description: Option<String>,    // From header tag DESCRIPTION (1005)
    pub requires: Vec<String>,          // From header tag REQUIRENAME (1049), tokenised
    pub provides: Vec<String>,          // From header tag PROVIDENAME (1047)
    pub vendor_source: VendorSource,    // Which source populated the PURL vendor slug
}

pub enum VendorSource {
    Header,        // Vendor tag mapped via R9 table
    OsRelease,     // Fallback to /etc/os-release::ID (R9 fallback)
    Fallback,      // Hardcoded "rpm" slug
}
```

**Conversion to `PackageDbEntry`**: straightforward. PURL is built per FR-012 / FR-013; `depends = requires` (tokenised); `licenses = [license]`; `maintainer = vendor_header`; `sbom_tier = Some("source".into())`; `evidence_kind = Some("rpm-file".into())`.

**Fail-graceful contract**: malformed-header input (bad magic, truncated, header-index count > cap) → return `None` from the reader; caller emits zero `PackageDbEntry` rows + single WARN line (FR-017).

---

### `BdbRpmdb`

Represents a Berkeley-DB rpmdb observed at `/var/lib/rpm/Packages`. Parsed only when `--include-legacy-rpmdb` is set (FR-018).

```rust
pub struct BdbRpmdb {
    pub path: PathBuf,
    pub page_size: u32,                 // From BDB metadata page
    pub db_magic: u32,                  // Validates BDB file identity
    pub kind: BdbKind,                  // Hash or BTree (both seen in real rpmdbs)
    pub record_count: usize,            // Observed HeaderBlob count
}

pub enum BdbKind { Hash, BTree }
```

**Per-record parsing**: each HeaderBlob value in the DB is parsed using the shared `rpm_header::HeaderBlob::parse` (newly extracted from `rpmdb_sqlite::record` per R2) and converted to `PackageDbEntry` with `evidence_kind = Some("rpmdb-bdb".into())`, `sbom_tier = Some("deployed".into())`. Identical field shape to the sqlite path.

**Defense-in-depth limits** (FR-019b):

- File size cap: 200 MB (same as sqlite).
- Iteration budget: 2 s wall clock.
- Page-count cap: 100,000 pages (derived from 200 MB / 2 KB default page size; guards against page-layout malice).

**Sqlite-wins conflict rule** (FR-019c): when both `rpmdb.sqlite` and `Packages` exist, `BdbRpmdb::read` returns empty and logs an INFO line noting the transitional config.

---

## New entities — Binary-analysis path

### `BinaryFileComponent`

The file-level component emitted per binary (regardless of format). Replaces the implicit file-level component emitted today by the Go-binary reader.

```rust
pub struct BinaryFileComponent {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub hashes: Vec<ContentHash>,       // SHA-256 + SHA-1 per Principle XI
    pub binary_class: BinaryClass,      // elf / macho / pe
    pub stripped: bool,                 // Per-format signal; see R5 for PE
    pub linkage_kind: LinkageKind,      // dynamic / static / mixed
    pub packed: Option<PackerKind>,     // Some(UPX) if UPX signature hit
    pub detected_go: bool,              // True when Go BuildInfo succeeded on this file
    pub parse_limit_hit: Option<String>,// Populated when defense-in-depth cap fired
}

pub enum BinaryClass { Elf, Macho, Pe }
pub enum LinkageKind { Dynamic, Static, Mixed }
pub enum PackerKind { Upx }
```

---

### `ElfBinary`

Per-ELF parsed representation, used by the generic-binary reader's ELF arm.

```rust
pub struct ElfBinary {
    pub class: ElfClass,                // 32 / 64
    pub endianness: Endianness,         // LittleEndian / BigEndian
    pub elf_type: ElfType,              // Exec / Dyn / Rel
    pub machine: u16,                   // e_machine
    pub needed: Vec<String>,            // DT_NEEDED entries (FR-022)
    pub dynamic_linker: Option<String>, // PT_INTERP contents
    pub note_package: Option<ElfNotePackage>, // FR-024
    pub has_symtab: bool,               // .symtab / .dynsym presence
    pub rodata_extract: ReadOnlyStringExtract,
}

pub enum ElfClass { Elf32, Elf64 }
pub enum Endianness { Little, Big }
pub enum ElfType { Exec, Dyn, Rel, Other }
```

---

### `MachoBinary`

Per-Mach-O parsed representation. For fat (universal) binaries, slices are iterated and results merged (dedup on install-name).

```rust
pub struct MachoBinary {
    pub is_fat: bool,
    pub slices: Vec<MachoSlice>,        // One entry for non-fat; N entries for fat
}

pub struct MachoSlice {
    pub cpu_arch: String,               // e.g. "x86_64", "arm64"
    pub magic: u32,
    pub load_dylib: Vec<String>,        // LC_LOAD_DYLIB install-names (FR-023)
    pub install_name: Option<String>,   // If this slice is a dylib
    pub has_symtab: bool,
    pub rodata_extract: ReadOnlyStringExtract,
}
```

---

### `PeBinary`

Per-PE parsed representation.

```rust
pub struct PeBinary {
    pub machine: u16,                   // COFF header Machine
    pub characteristics: u16,           // COFF header Characteristics
    pub import_dlls: Vec<String>,       // IMPORT + Delay-Load IMPORT merged, dedup'd (FR-023a)
    pub has_pdata: bool,                // .pdata section present
    pub has_debug_dir: bool,            // IMAGE_DEBUG_DIRECTORY present
    pub has_version_resource: bool,     // VS_VERSION_INFO block present
    pub has_debug_stripped_bit: bool,   // IMAGE_FILE_DEBUG_STRIPPED characteristic set
    pub rdata_extract: ReadOnlyStringExtract,
}
```

`PeBinary::is_stripped()` returns true iff all four debug signals are negative (R5 four-AND rule).

---

### `ReadOnlyStringExtract`

Shared type across all three binary formats. Produced by the format-specific parser, consumed by `version_strings.rs`.

```rust
pub struct ReadOnlyStringExtract {
    /// Concatenated bytes of all read-only string sections in a stable
    /// order, with NUL-terminated records preserved. For ELF: `.rodata`
    /// + `.data.rel.ro`. For Mach-O: `__TEXT,__cstring` + `__TEXT,__const`.
    /// For PE: `.rdata`. Capped at 16 MB per binary (defense-in-depth).
    pub bytes: Vec<u8>,
    pub section_names: Vec<String>,     // Which sections contributed
    pub total_size: u64,                // Uncapped size for diagnostics
}
```

---

### `LinkageEvidence`

Emitted one-per-unique-soname-globally (FR-028a dedup rule from Q5).

```rust
pub struct LinkageEvidence {
    pub purl: Purl,                     // pkg:generic/<soname-or-install-name-or-dll-name>
    pub name: String,                   // The raw linkage identifier
    pub format_hint: BinaryClass,       // Which format produced the first observation
    pub occurrences: Vec<LinkageOccurrence>,
}

pub struct LinkageOccurrence {
    pub parent_binary_path: PathBuf,
    pub parent_binary_bom_ref: String,  // BOM-ref of the parent's BinaryFileComponent
    pub directive: LinkageDirective,    // DtNeeded / LcLoadDylib / PeImport / PeDelayLoadImport
}

pub enum LinkageDirective { DtNeeded, LcLoadDylib, PeImport, PeDelayLoadImport }
```

**Dedup implementation**: `scan_fs/binary/linkage.rs` maintains a `HashMap<Purl, LinkageEvidence>` across the scan; per-binary `needed` / `load_dylib` / `import_dlls` vectors are merged in via `entry().or_insert_with(...)` with new `LinkageOccurrence`s pushed onto the existing vector.

---

### `ElfNotePackage`

Parsed `.note.package` payload (R4).

```rust
pub struct ElfNotePackage {
    pub note_type: String,              // "rpm" / "deb" / "apk" / "alpm" / ...
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub distro: Option<String>,         // "Fedora" / "Debian" / "Arch Linux" / ...
    pub os_cpe: Option<String>,
    pub raw_bytes: Vec<u8>,             // Original JSON payload for transparency
}
```

**PURL mapping** (FR-024):

| `note_type` | PURL form | Vendor derivation |
|---|---|---|
| `"rpm"` | `pkg:rpm/<vendor>/<name>@<version>?arch=<arch>` | `distro` → R9 table (or `rpm` fallback) |
| `"deb"` | `pkg:deb/<vendor>/<name>@<version>?arch=<arch>` | `distro` lowercased |
| `"apk"` | `pkg:apk/<vendor>/<name>@<version>?arch=<arch>` | `distro` lowercased (usually `alpine`) |
| `"alpm"` / `"pacman"` | `pkg:alpm/arch/<name>@<version>?arch=<arch>` | Hardcoded `arch` (the distro is always Arch) |
| other | `pkg:generic/<name>@<version>` + `mikebom:elf-note-package-type = <note_type>` | n/a |

---

### `EmbeddedVersionMatch`

Emitted by the curated string scanner (R6). Always tagged `confidence = "heuristic"`.

```rust
pub struct EmbeddedVersionMatch {
    pub library: CuratedLibrary,
    pub version: String,                // Matched version string as-is
    pub offset: u64,                    // Byte offset within the extracted-string region
    pub parent_binary_path: PathBuf,
    pub parent_binary_bom_ref: String,
}

pub enum CuratedLibrary { OpenSsl, BoringSsl, Zlib, Sqlite, Curl, Pcre, Pcre2 }
```

**PURL emission**: `pkg:generic/<library-lowered>@<version>` (e.g. `pkg:generic/openssl@3.0.11`). Dedup by PURL across the scan (multiple binaries that embed the same OpenSSL version produce one component with merged occurrences).

---

## Property vocabulary

Complete list of `mikebom:*` properties introduced or retrofitted by this milestone. All emitted at CycloneDX component serialization time in `generate/cyclonedx/builder.rs`.

| Property | Appears on | Values | FR reference |
|---|---|---|---|
| `mikebom:evidence-kind` | Every new component, AND retrofit onto milestone-003 rpm-sqlite components | `rpm-file`, `rpmdb-sqlite`, `rpmdb-bdb`, `dynamic-linkage`, `elf-note-package`, `embedded-version-string` | FR-004, Q7 |
| `mikebom:sbom-tier` | Every new component (inherited from milestone 002) | `source`, `analyzed`, `deployed` | FR-003 |
| `mikebom:binary-class` | BinaryFileComponent | `elf`, `macho`, `pe` | FR-021 |
| `mikebom:binary-stripped` | BinaryFileComponent | `true` / `false` (bool-as-string per CycloneDX property convention) | FR-027 |
| `mikebom:linkage-kind` | BinaryFileComponent | `dynamic`, `static`, `mixed` | FR-021 |
| `mikebom:binary-packed` | BinaryFileComponent (when detected) | `upx` | FR-021 |
| `mikebom:binary-parse-limit` | BinaryFileComponent (when cap fired) | Short reason string (`"size-cap"`, `"section-count-cap"`, `"string-region-cap"`) | FR-007 |
| `mikebom:detected-go` | BinaryFileComponent (when BuildInfo succeeded) | `true` | R8 / FR-026 |
| `mikebom:vendor-source` | RPM components | `header`, `os-release`, `fallback` | FR-013 |
| `mikebom:elf-note-package-type` | ElfNotePackage-derived components with non-standard `type` | Raw `type` value | FR-024 |
| `mikebom:confidence` | EmbeddedVersionMatch components | `heuristic` | FR-025 |

Inherited from milestones 001–003 (unchanged): `mikebom:generation-context`, `mikebom:cpe-candidates`, `mikebom:source-files`, `mikebom:dev-dependency`, `mikebom:requirement-range`, `mikebom:source-type`, `mikebom:buildinfo-status`, `mikebom:ring-buffer-overflows`, `mikebom:events-dropped`, `mikebom:uprobe-attach-failures`, `mikebom:kprobe-attach-failures`.

---

## State transitions

The scanner is stateless end-to-end — no entity has a lifecycle beyond the single scan. Every entity above is constructed per-scan and serialized into one CycloneDX SBOM document. No persistence.

---

## Validation rules

1. **PURL round-trip (FR-002, SC-007)**: Every PURL emitted by every new evidence-kind MUST round-trip through `packageurl-python`. Enforced at integration-test time via the same probe used in milestones 002 / 003.
2. **Evidence-kind enumeration (FR-004)**: Any value outside the six-variant enum is a spec violation; serializer rejects unknown values with `debug_assert!` at test time.
3. **Tier/evidence-kind consistency**: `sbom-tier` and `evidence-kind` are independent axes, but certain combinations are invalid — e.g., `evidence-kind = rpm-file` with `tier = deployed` is wrong (a `.rpm` file is source-tier). A unit test asserts the expected pairings:
   - `rpm-file` → `source`
   - `rpmdb-sqlite` → `deployed`
   - `rpmdb-bdb` → `deployed`
   - `dynamic-linkage` → `analyzed`
   - `elf-note-package` → `source`
   - `embedded-version-string` → `analyzed`
4. **Dedup invariant**: after a scan, no two components in `components[]` share the same PURL. Existing milestone-002/003 invariant extended to cover new evidence-kinds.
5. **Occurrence sanity**: every `evidence.occurrences[]` entry for a linkage-evidence component references a BOM-ref that exists in the same SBOM (no dangling parent refs).
