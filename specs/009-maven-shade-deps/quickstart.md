# Quickstart: Emit Shade-Relocated Maven Dependencies

Single-slice feature. Can be implemented, tested, and shipped as one PR.

## Prerequisites

- Branch: `009-maven-shade-deps`
- Main at or above commit where 008 US3 merged (currently `701ea50`)
- No external dependencies — all fixtures are synthetic

## Slice 1 (P1): Implementation

### Step-by-step

1. **Extend `PackageDbEntry`** (in `mikebom-cli/src/scan_fs/package_db/mod.rs`):
   ```rust
   #[serde(default, skip_serializing_if = "Option::is_none")]
   pub shade_relocation: Option<bool>,
   ```
   Mirror the existing `detected_go: Option<bool>` field pattern. Default `None` everywhere the struct is constructed.

2. **Extend `ResolvedComponent`** (in `mikebom-common/src/resolution.rs`):
   Same `Option<bool>` field. Threaded from `PackageDbEntry` at the aggregation site in `scan_fs/mod.rs` (search for `detected_go:` to find the existing threading pattern — match it).

3. **Wire property emission** in the CycloneDX serializer:
   Find the existing `mikebom:detected-go` property emission pattern in `mikebom-cli/src/generate/cyclonedx/builder.rs`; add an identical branch for `shade_relocation` → `mikebom:shade-relocation = "true"`.

4. **Add `ShadeAncestor` struct** in `maven.rs` (private).

5. **Add `parse_dependencies_file(bytes: &[u8]) -> Vec<ShadeAncestor>`** in `maven.rs`:
   - Iterate lines via `std::str::from_utf8` + `lines()`; bail to empty vec on non-UTF-8.
   - Regex-match coord lines (R2 from research.md).
   - On match, peek ahead for the next non-blank line; if it starts with `License:` (trimmed), strip the prefix + URL parenthetical, call `SpdxExpression::try_canonical`, store result.

6. **Add `emit_shade_relocation_entries(...)` in `maven.rs`** (signature from contract):
   - Per-JAR `seen_ancestor_keys: HashSet<String>` dedup.
   - Self-reference guard compares against `enclosing_primary_purl`.
   - Builds `PackageDbEntry` with all fields set per contract.

7. **Wire into the JAR loop** (in `read_with_claims`):
   - After `walk_jar_maven_meta(jar_path)` returns, also read `META-INF/DEPENDENCIES` from the same zip archive (open once, reuse).
   - When present and the primary coord is identifiable, call `parse_dependencies_file` + `emit_shade_relocation_entries`.
   - Log INFO `"shade-relocation ancestors emitted"` with count on successful emission.

### Test steps

1. **Unit tests** for `parse_dependencies_file` covering all 8 normative cases in the contract.

2. **Unit tests** for `emit_shade_relocation_entries` covering the 6 contract cases.

3. **Integration test** `mikebom-cli/tests/scan_maven_shade_deps.rs`:
   - **Test A** (canonical shade): build a synthetic JAR with primary coord `com.example:outer:1.0.0` + `META-INF/DEPENDENCIES` listing three ancestors (one with valid SPDX license, one with free-form license text, one with no License line). Assert:
     - Outer primary coord present in SBOM at tier=analyzed
     - Three ancestor coords present with `parent_purl` pointing at outer
     - `mikebom:shade-relocation = true` property on each ancestor
     - Valid-SPDX ancestor has populated `licenses[]`
     - Free-form-license ancestor has empty `licenses[]` (fail-soft)
     - No-license ancestor has empty `licenses[]`
   - **Test B** (classifier variant): JAR with DEPENDENCIES entry `com.example:tools:jar:tests:2.0.0` → PURL contains `?classifier=tests`.
   - **Test C** (regression — no DEPENDENCIES): JAR with only primary coord, no DEPENDENCIES file → SBOM output matches pre-feature behavior (no shade-relocation entries). Verify by snapshotting the relevant components.
   - **Test D** (self-reference guard): JAR's DEPENDENCIES contains its own coord → the self-entry is NOT re-emitted.
   - **Test E** (co_owned_by inheritance): JAR under `/usr/share/java/<name>.jar` gets `co_owned_by = "rpm"` → shade-relocation ancestors inherit the tag.

### Verification

1. `cargo +stable clippy --workspace --all-targets` — clean.
2. `cargo +stable test --workspace` — 1128 → 1128 + N passing, 0 failing (N = unit + integration count; roughly +14).
3. End-to-end on polyglot rootfs:
   ```bash
   cargo build --release -p mikebom
   ./target/release/mikebom --offline sbom scan \
     --path /tmp/008-polyglot-rootfs \
     --output /tmp/009-test.cdx.json
   jq '[.components[] | select(.purl | contains("commons-compress@1.23"))]' /tmp/009-test.cdx.json
   ```
   Expected: post-fix output contains `pkg:maven/org.apache.commons/commons-compress@1.23.0` with `parent_purl = pkg:maven/org.apache.maven.surefire/surefire-shared-utils@3.2.2` and the shade-relocation property.

### Ship

Commit + push `feat/009-maven-shade-deps`; open PR with:
- Pre-fix vs post-fix end-to-end diff
- `cargo +stable clippy` and `cargo +stable test --workspace` output (constitution v1.2.1 evidence)
- A table of which polyglot FPs (now FNs) close

## Slice 2 (P3): Documentation

Extend `docs/design-notes.md` with a "Shade-relocation coverage" subsection:

- What mikebom detects (META-INF/DEPENDENCIES present)
- What it doesn't (silent shading — reduced-pom.xml parsing as future work)
- Naming convention for the property marker + forward-compatibility with CycloneDX `pedigree.ancestors`

Docs-only PR. Can land same slice or separate.

## Cumulative success criteria

1. `cargo +stable clippy --workspace --all-targets` clean.
2. `cargo +stable test --workspace` passing; no regressions in any existing suite.
3. Polyglot bake-off scoreboard: Maven improves or stays at perfect; other ecosystems unchanged.
4. The specific `commons-compress@1.23.0` finding closes with the shade-relocation entry present.

## Rollback

Single PR, single-file focus for the implementation. If regression appears, revert the single commit. The `shade_relocation` field on `PackageDbEntry` / `ResolvedComponent` is `Option<bool>` with serde `skip_serializing_if = "Option::is_none"` — unused on revert, no serialization change for non-shade entries.
