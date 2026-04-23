# Phase 1 Data Model: Polyglot FP Cleanup

This feature extends existing scan-mode types; it introduces no persistent storage and no new cross-crate types. All state is per-scan, in-memory.

## Existing types reused (no changes)

- `PackageDbEntry` (in `mikebom-cli/src/scan_fs/package_db/mod.rs`) — the aggregated per-scan entry with fields `purl`, `name`, `version`, `sbom_tier`, `source_files`, `relationships`, `co_owned_by`, etc.
- `Purl` (in `mikebom-common/src/`) — PURL newtype. Used unchanged.
- `ContentHash` — unchanged.
- `PomXmlDocument`, `PomDependency`, `EffectivePom` (in `maven.rs`) — POM parser output types. Used unchanged for the sidecar path.

## New types (scoped to `mikebom-cli`)

### `FedoraSidecarIndex` (new, in `maven_sidecar.rs`)

Per-scan in-memory index of `/usr/share/maven-poms/` contents.

```rust
pub(crate) struct FedoraSidecarIndex {
    /// Keyed by the filename basename without the `JPP-` prefix and
    /// without the `.pom` suffix. E.g., `/usr/share/maven-poms/JPP-guice.pom`
    /// and `/usr/share/maven-poms/guice.pom` both key as `"guice"`.
    by_basename: HashMap<String, PathBuf>,
}
```

**Lifecycle**: Built once at the start of `maven::read()` by walking `<rootfs>/usr/share/maven-poms/`. Passed to the JAR-processing code as a read-only reference. Dropped at the end of the scan.

**Invariants**:
- Keys are ASCII-lowercase (Fedora POM filenames are ASCII).
- An empty index (no `maven-poms/` dir on the rootfs) is a legal state; all lookups return `None`, and the sidecar code path is a full no-op.

### `GoProductionImportSet` (new, in `golang.rs`)

Per-scan set of module paths reachable from non-`_test.go` imports across all Go source trees on the rootfs.

```rust
pub(crate) struct GoProductionImportSet {
    /// Set of Go module paths whose import paths appear in at least one
    /// non-`_test.go` file anywhere on the rootfs. Stored as canonical
    /// module paths (no trailing path components).
    modules: HashSet<String>,
}
```

**Lifecycle**: Built during `golang::read()` while walking Go source trees. Returned alongside the `Vec<PackageDbEntry>` so `package_db::read_all()` can use it in the aggregation filter. Dropped after the aggregation filter runs.

**Invariants**:
- A module path appears in `modules` only if at least one `.go` file (excluding `_test.go`) imports a path that resolves to that module via longest-prefix match.
- Vendored modules (path under `vendor/<module>/`) appear here IFF at least one non-`_test.go` file imports them.
- The empty set is a legal state (source tree with only `_test.go` files); the filter no-ops with respect to source imports when empty.

### `GoMainModuleSet` (new, in `golang.rs` — or shared with `go_binary.rs`)

Per-scan set of "this project is the main module" paths.

```rust
pub(crate) struct GoMainModuleSet {
    paths: HashSet<String>,
}
```

**Lifecycle**: Populated incrementally as `golang::read()` finds `module` directives in go.mod and as `go_binary::read()` finds `mod` lines in BuildInfo. Merged in `package_db::read_all()` before the main-module filter runs.

**Invariants**:
- The main-module filter only consults this set; it never inspects individual entry metadata.
- Empty set is legal (rootfs contains Go deps but no Go source/binary that declares a main module, e.g., a Go dep-cache directory only). Filter no-ops.

## Validation rules

- **Sidecar POM coordinate extraction**: (groupId, artifactId, version) MUST all be non-empty after parent-resolution. If any component is missing, skip emission for that JAR (fall back to generic-binary emission; FR-005).
- **Go source-import canonicalization**: The module path prefix-matched against an import path MUST be the exact match of a module name known to the scan (from go.mod or BuildInfo). Unknown module paths — e.g., imports that don't match any known module — are ignored (they're either stdlib or foreign to the scanned set).
- **Main-module exclusion scope**: Applies only to entries whose `purl.ecosystem()` is `golang`. Never filters cross-ecosystem.

## State transitions

None. All new types are constructed once and consumed; no mutable state machines.
