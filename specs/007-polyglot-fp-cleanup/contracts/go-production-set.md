# Contract: Go Production Set Filter (Intersection Semantics)

**Scope**: Internal filter in `mikebom-cli/src/scan_fs/package_db/mod.rs`, alongside the existing `apply_go_linked_filter` (G3).
**Consumers**: `package_db::read_all()` aggregation pass.

## Functional contract

**Given** the per-scan `Vec<PackageDbEntry>` (post-G3) and a `GoProductionImportSet` built during `golang::read()`,

**When** `apply_go_production_set_filter(&mut entries, &import_set)` runs,

**Then**:
1. If `import_set` is empty (no `.go` files were parsed, e.g., pure binary scan with no source tree), the filter is a no-op.
2. Otherwise, for each entry with `purl.ecosystem() == "golang"` AND `sbom_tier == Some("source")`:
   - If the entry's `name` (the module path) is in `import_set.modules`, keep it.
   - Otherwise, drop it.
3. Entries with any other ecosystem or any other tier pass through unchanged.

A structured INFO log line is emitted naming the filter (`"G4 filter"`), the number of dropped entries, and the production-set size.

## API surface

```rust
pub(crate) fn apply_go_production_set_filter(
    entries: &mut Vec<PackageDbEntry>,
    import_set: &GoProductionImportSet,
);
```

## Invariants

- The filter NEVER touches cross-ecosystem entries (cargo, gem, rpm, etc.).
- The filter NEVER promotes entries (e.g., changing `sbom_tier`); it only drops.
- Order of entries is preserved for kept entries (uses `Vec::retain`).
- Running the filter twice with the same inputs is idempotent.

## Composition with G3

G3 runs first: it drops go.sum source-tier entries not confirmed by BuildInfo. The new G4 runs second: it further drops BuildInfo-confirmed entries that are not reachable from a non-`_test.go` import. The two filters compose as an intersection:

- Kept = (in BuildInfo when BuildInfo present, else all go.sum) ∩ (in a non-`_test.go` import when source present, else all)

Which is exactly the semantics required by FR-007a.

## Edge cases

- **Source tree with no production imports at all** (every `.go` file is `_test.go`): `import_set.modules` is empty → filter drops all source-tier Go entries → zero Go components in output. Legitimate per the Story 2 acceptance scenarios.
- **Source tree with vendored deps only** (`vendor/` directory, no `_test.go` imports of some vendored module): The vendored module's path is imported by the code under non-`_test.go`, so it appears in `import_set`. Retained.
- **Binary-only rootfs** (BuildInfo present, no `.go` source): `import_set` is empty → this filter no-ops → BuildInfo-only set passes through.
- **Source-only rootfs** (no Go binary anywhere): G3 is a no-op (already documented); G4 alone drives the filter; import analysis is authoritative.

## Test cases (normative)

1. Module `A` imported from `main.go`, module `B` imported from `main_test.go` only → `A` retained, `B` dropped.
2. Module `C` imported from both `main.go` and `something_test.go` → `C` retained (production import dominates).
3. Binary-present scan, BuildInfo contains `testify`, no `.go` file in source imports `testify` → `testify` dropped.
4. Pure source-tree scan (no binary) with `import_set={"A"}` and go.sum entries `{A, B}` → only `A` retained.
5. Empty `import_set` (no Go source found) → filter no-ops; output identical to input.
