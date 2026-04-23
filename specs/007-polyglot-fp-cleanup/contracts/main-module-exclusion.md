# Contract: Go Main Module Exclusion Filter

**Scope**: Internal filter in `mikebom-cli/src/scan_fs/package_db/mod.rs`, after G3 and G4.
**Consumers**: `package_db::read_all()` aggregation pass.

## Functional contract

**Given** the per-scan `Vec<PackageDbEntry>` (post-G3 and post-G4) and a `GoMainModuleSet` populated by both `golang::read()` (from go.mod `module` directives) and `go_binary::read()` (from BuildInfo `mod` lines),

**When** `apply_go_main_module_filter(&mut entries, &main_modules)` runs,

**Then**:
1. If `main_modules` is empty, the filter is a no-op.
2. Otherwise, for each entry with `purl.ecosystem() == "golang"`:
   - If the entry's `name` (the module path) is in `main_modules.paths`, drop it.
   - Otherwise, keep it.
3. Entries with any other ecosystem pass through unchanged.

A structured INFO log line is emitted naming the filter (`"G5 filter"`) and the number of dropped entries.

## API surface

```rust
pub(crate) fn apply_go_main_module_filter(
    entries: &mut Vec<PackageDbEntry>,
    main_modules: &GoMainModuleSet,
);
```

## Invariants

- Applies to ALL tiers (both `source` and `analyzed`). Unlike G3 and G4 which only act on source-tier entries, G5 drops the main module regardless of tier because the project is never its own dependency from any perspective.
- Case-sensitive module path comparison (Go module paths are canonical).
- The filter's main-module set is the UNION of sources: go.mod declarations + BuildInfo declarations. If a rootfs has multiple Go projects with distinct main modules, all are excluded.

## Semantic guarantee

After this filter runs, no emitted Go component has a `purl` whose name equals any known main-module path on the rootfs. The project is not emitted as its own dependency.

## Non-goals

- This filter does NOT suppress the main module from appearing elsewhere in the SBOM (e.g., as the document subject or a top-level metadata component). Those representations are handled by different parts of the SBOM generator and are out of scope.
- This filter does NOT attempt to disambiguate coincidental name collisions between main modules and published external modules. The go.mod / BuildInfo declaration is authoritative (FR-012).

## Test cases (normative)

1. go.mod declares `module example.com/polyglot-fixture`; go.sum includes `example.com/polyglot-fixture v0.0.0` → dropped from output.
2. BuildInfo `mod example.com/myapp (devel)`; no other Go entry with that name → no-op (main module wasn't emitted in the first place).
3. Two Go projects on the same rootfs: `/srv/app1` declares `module a.example.com/app1`, `/srv/app2` declares `module b.example.com/app2` → both are in the main-module set; neither appears in the output.
4. go.mod's main module coincidentally matches a published module name (contrived case) → the local declaration wins; the coincidentally-named published module is also excluded (accepted per FR-012).
5. Empty main-module set (no Go source or binary) → filter no-ops.
