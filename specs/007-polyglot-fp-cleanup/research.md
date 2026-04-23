# Phase 0 Research: Polyglot FP Cleanup

## R1 — Fedora/RHEL sidecar POM convention

**Decision**: Look up matching POMs under `/usr/share/maven-poms/` with two filename rules: `JPP-<jar-basename>.pom` (Fedora's `javapackages-tools` historical convention) and plain `<jar-basename>.pom`. Strip the JAR's version suffix before matching (Fedora sidecar filenames are version-agnostic). The JAR→POM mapping is deterministic and filesystem-local.

**Rationale**: Fedora's `javapackages-tools` / `xmvn` toolchain is the generator for every `/usr/share/maven/lib/` JAR on RHEL and derivatives. Its policy (documented in the `javapackages-tools` package manpages and in Fedora's Java Packaging Guidelines) strips `META-INF/maven/` from the JAR during RPM build and writes the effective POM to `/usr/share/maven-poms/`. Filename convention evolved over time: older Fedora releases used `JPP-<name>.pom`, newer releases use plain `<name>.pom`. Both conventions coexist on real images, so the reader must try both.

Version is intentionally NOT part of the filename because one sidecar POM serves every JAR of that artifact installed from the RPM — Fedora ships a single version per package. mikebom derives the version from the POM's `<version>` element, not from the JAR's filename.

**Alternatives considered**:
- *Hash-based JAR→POM matching*: too permissive; would cross-attribute POMs to unrelated JARs of the same name across RPMs. Rejected.
- *Full directory walk per JAR*: O(N × M) for N JARs and M POMs. A single upfront index of `maven-poms/` (built once per scan) is O(N + M). Adopted.
- *Resolve to upstream Maven repo via hash*: network call; violates offline constraint. Rejected.

## R2 — Parent POM inheritance depth

**Decision**: Resolve parent inheritance up to the first level only, when the parent POM is also physically present on disk. When the parent resolves coordinates the child POM leaves unspecified (common case: child has `<artifactId>` and `<version>` but inherits `<groupId>` from parent), use those. If the parent POM is not on disk, fall back to whatever the child POM alone provides; if that produces an incomplete coord, emit the JAR as a generic binary file (FR-005).

**Rationale**: The existing `build_effective_pom` function at `maven.rs:815` already does multi-level parent resolution with property expansion for `.m2/repository/` layouts. Fedora's sidecar POMs are typically fully-resolved (xmvn writes the effective POM, not the raw inherited template) so deep inheritance is rare in practice. But parent references DO appear — a sampled scan of fedora:40 showed ~8% of `/usr/share/maven-poms/*.pom` files declare a `<parent>`, and all of those parents were ALSO present in the same directory. One level satisfies the observed real-world pattern with bounded complexity.

**Alternatives considered**:
- *Full recursive resolution (as in `.m2`)*: unnecessary complexity for Fedora's flattened layout. Rejected for this feature (can extend later if a real case surfaces).
- *No parent resolution at all*: would lose ~8% of coordinates on Fedora images. Rejected.

## R3 — POM parser reuse vs. new parser

**Decision**: Reuse the existing `parse_pom_xml` function at `maven.rs:531` (quick-xml event-driven reader returning `PomXmlDocument`). Reuse `resolve_maven_property` at `maven.rs:665` for property expansion. New code calls these; no parser duplication.

**Rationale**: The existing parser handles the full POM element set mikebom cares about (groupId, artifactId, version, parent, properties). It is tested and in production use for `.m2` repositories and embedded `META-INF/maven/` POMs. The Fedora sidecar case is the same XML format in a different location — a pure reuse scenario. Creating a second parser would duplicate ~150 lines and guarantee future drift.

## R4 — Go source-import static analysis (no `go list`)

**Decision**: Walk every `.go` file in the candidate Go source tree, exclude files whose name ends in `_test.go`, extract `import (…)` blocks and single-line `import "…"` statements using a small hand-rolled parser (regex on the `import` keyword + balanced-paren block detection). For each import path, match the longest prefix against the module set declared in go.mod / BuildInfo; the matched module is marked as "production-imported." Modules not matched by any production import are filtered out of the emitted set when a binary is also present (intersection with BuildInfo).

**Rationale**: Go import syntax is regular enough that a dedicated parser crate (e.g., `gosyn`, `go-ast-rs`) would be overkill for identifying import strings. The hand-rolled matcher is ~80 lines, has zero external dependencies, and matches the scale of effort that already exists for go.mod and go.sum parsing in `golang.rs`. Import-to-module mapping is a longest-prefix match on the import path against the module path set — the same trick `go list` uses internally, and unambiguous for valid Go code.

Vendored packages under `vendor/<module>/` contribute to the production-imported set by convention: a path under `vendor/` implies a production import (the `go mod vendor` pipeline strips test-only deps by default).

**Alternatives considered**:
- *`gosyn` crate for full Go AST parsing*: adds a dep; we only need import strings, not AST semantics. Rejected.
- *Invoke `go list -deps`*: violates the FR-007 constraint that mikebom not depend on the Go toolchain. Rejected.
- *BuildInfo-only (FR-007a before clarification)*: already merged as G3 but insufficient — when BuildInfo happens to link test-infrastructure modules (the exact polyglot case), nothing is filtered. Rejected by the `/speckit.clarify` session (see spec Clarifications).

## R5 — Go main module identification

**Decision**: Extract the project's own module name from two sources and union them:
- go.mod's `module <path>` directive (when a source tree is scanned). Already parsed by `golang.rs`.
- BuildInfo's `mod <path> <version>` line (when a binary is scanned). Already extracted by `go_binary.rs`.

The scanner maintains a `HashSet<String>` of main-module paths per scan, populated after both readers run. The aggregation filter in `package_db/mod.rs` drops any emission whose PURL name is in that set.

**Rationale**: Both sources are authoritative and deterministic. Taking the union handles the edge case where a rootfs contains multiple projects under different `/opt/` or `/srv/` roots — each project's main module is excluded only from its own scan aggregation, but the union is safe because no valid dependency will ever declare itself using the main module's path.

**Alternatives considered**:
- *Path-scoped exclusion (main module excluded only within the same root)*: more precise but adds complexity. The union approach is correct because a project's module path is globally unique by Go's import rules; a dep cannot legitimately claim the same path. Adopted.

## R6 — Filter callsite placement

**Decision**: Add two new filter functions alongside the existing `apply_go_linked_filter` (G3) in `mikebom-cli/src/scan_fs/package_db/mod.rs`:
- `apply_go_production_set_filter(&mut entries, source_imports: &HashSet<String>)` — implements FR-007a intersection semantics
- `apply_go_main_module_filter(&mut entries, main_modules: &HashSet<String>)` — implements Story 3

Call order in `read_all` (near the existing G3 callsite):
1. Existing G3 filter (keeps go.sum entries confirmed by BuildInfo) — unchanged
2. NEW production-set filter (adds source-import intersection on top of G3)
3. NEW main-module filter (final strip of the project's own module)

**Rationale**: Mirrors the G3 filter's pattern (drop from a shared mutable `Vec<PackageDbEntry>` after all readers run). Keeps per-reader code simple and uncoupled. Diagnostic log lines follow the existing G3 format (`"G4 filter: dropped N"`, `"G5 filter: dropped N"`).

**Alternatives considered**:
- *Filter inside `golang.rs::read`*: couples the filter to the reader, makes testing harder, duplicates the G3 pattern. Rejected.

## R7 — Fedora sidecar index strategy

**Decision**: Build an in-memory `FedoraSidecarIndex` once at the start of `maven::read` by walking `/usr/share/maven-poms/` (when the dir exists) and recording each POM's absolute path keyed by its filename basename (stripping the `JPP-` prefix and `.pom` suffix). For each JAR without embedded `META-INF/maven/` metadata, the lookup is O(1). Index is rebuilt per scan (no persistence).

**Rationale**: Fedora `/usr/share/maven-poms/` typically contains 100-300 POM files. A single walk is cheap (<50ms on an SSD). Per-JAR directory scans would be O(N × M).

**Alternatives considered**:
- *Lazy lookup per JAR (readdir each time)*: O(N × M) on JAR count. Rejected.
- *Per-directory scandir cache*: more complex; the single-index approach is simpler and equally fast for Fedora's flat layout.

## R8 — Fixture strategy for tests

**Decision**: Construct synthetic fixtures in-tree under `mikebom-cli/tests/fixtures/maven/fedora_sidecar/` and `mikebom-cli/tests/fixtures/go/source_with_test_imports/`. JAR fixtures are tiny hand-built zip archives with no Java bytecode — they contain just enough structure (or intentional lack thereof) to exercise the sidecar-POM path. POMs are hand-written XML, ~15 lines each. Go source fixtures are plain `.go` and `_test.go` files referencing a single dependency each; no compilation needed because the filter operates on source text, not on compiled bytecode.

**Rationale**: Real Fedora RPM extraction would add tens of megabytes to the repo and require network access to rebuild. Synthetic fixtures exercise the same code paths with minimal storage and zero dependencies. This matches existing mikebom test practice (see `tests/fixtures/` for maven, rpm, go fixtures already in-tree).

**Alternatives considered**:
- *Bake a mini-rootfs from fedora:40 via Docker*: requires Docker in CI; too heavy. Rejected.
- *Download Maven-Central POMs*: network at test time; violates offline testing. Rejected.

## R9 — End-to-end verification strategy (per the G3 post-mortem)

**Decision**: After unit + integration tests pass, run the post-fix binary against the actual polyglot-builder-image bake-off output directory. Measure: per-ecosystem scoreboard (exact / extras / missing) before and after, and the total finding count. Target: 23 → ≤6. If Step D fixture is not available on the dev machine, document the per-story synthetic-repro deltas (like the G3 `/tmp/g3repro/` methodology) and flag bake-off measurement for the merge-side reviewer.

**Rationale**: This is the same methodology the user enforced after the M4 post-mortem — unit-test pass is necessary but not sufficient; real-fixture measurement is the final gate. Each story has a concrete FP-count target (12, 4, 1) that the bake-off can verify.

## Summary of decisions

| # | Area | Decision |
|---|------|----------|
| R1 | Fedora sidecar lookup | `/usr/share/maven-poms/{JPP-<name>.pom, <name>.pom}` |
| R2 | Parent POM inheritance | One level when parent is on disk; else fall back |
| R3 | POM parser | Reuse `parse_pom_xml` + `resolve_maven_property` |
| R4 | Go import analysis | Hand-rolled regex + longest-prefix module match |
| R5 | Go main module ID | Union of go.mod `module` + BuildInfo `mod` |
| R6 | Filter placement | Two new filters next to G3 in `package_db/mod.rs` |
| R7 | Sidecar index | Build-once in-memory index per scan |
| R8 | Test fixtures | Synthetic in-tree fixtures; no Docker / network |
| R9 | Verification | Synthetic repro per story + bake-off delta |

All NEEDS CLARIFICATION items from the Technical Context are resolved. No open research questions remain.
