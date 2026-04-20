# Research — Milestone 003 (Multi-Ecosystem Expansion)

Resolves every `NEEDS CLARIFICATION` / open-question item in [`plan.md`](./plan.md) §Technical Context. Each entry is terse on purpose: rationale + rejected alternatives, not a tutorial.

---

## R1 — Pure-Rust SQLite reader for `rpmdb.sqlite`

**Decision:** Hand-parse the SQLite file format directly in a new scoped module `mikebom-cli/src/scan_fs/package_db/rpmdb_sqlite/`. Read-only. Covers: 100-byte header, varint, `sqlite_schema` walk to find the rpmdb-relevant table(s), B-tree interior + leaf pages, record format serial types 0-9 + 12+/13+ (blob/text), UTF-8 only. Skips: WAL, overflow pages (bounded size-cap per FR-009), indexes, `WITHOUT ROWID` (rpmdb uses rowid).

**Rationale:** No pure-Rust SQLite reader is production-ready on crates.io. `prsqlite` (kawasin73) is an unreleased hobby project with a force-pushed main branch; `sqlite-rs` (afsec) is not viable. `rusqlite`, `sqlite`, and `sqlx` all pull `libsqlite3-sys` (C) which violates Principle I. `gluesql` has pluggable storage but no foreign-SQLite-file reader and would need custom storage plumbing anyway. Since rpmdb's query surface is trivial (one SELECT-equivalent over a known table), a focused custom reader is smaller and safer than pulling a half-finished general engine.

**LOC estimate:** ~800 LOC total — ~600 LOC for the reader (page decoder, varint, record, schema walker, B-tree iteration) + ~200 LOC for rpmdb-specific glue. Placed under `scan_fs/package_db/rpmdb_sqlite/` as an internal helper; not a new crate, so no amendment to Principle VI.

**Alternatives rejected:**
- `rusqlite` / `sqlite` / `sqlx`: bundle or link libsqlite3 — Principle I violation.
- `gluesql`: storage backends don't read foreign SQLite files.
- `sqlparser-rs`: parser only, no storage engine.
- `prsqlite`: unreleased, unstable force-pushed main; not viable for a supply-chain tool.
- Shelling out to `rpm -qa`: requires the `rpm` CLI on the host running the scan — violates self-contained constraint, breaks in any container-scan pipeline.

---

## R2 — Go `runtime/debug.BuildInfo` extraction

**Decision:** Use the `object` crate (0.36.x) for ELF + Mach-O section location; add a ~250-LOC hand-rolled BuildInfo decoder in a new module `mikebom-cli/src/scan_fs/package_db/go_binary.rs`. Lookup priority: named section first (`.go.buildinfo` on ELF, `__DATA,__go_buildinfo` on Mach-O), memmem scan for the magic string `\xff Go buildinf:` as fallback for stripped-but-recoverable binaries. Decoder handles the Go 1.18+ inline format (`path`, `mod`, `dep`, `build` lines).

**Rationale:** No dedicated Go-BuildInfo Rust crate exists on crates.io — `go-parser` is a Goscript frontend, `gomod-parser` only reads `go.mod`. The BuildInfo format is small and stable; writing it is cheaper than depending on an experimental crate. `object` is preferred over `goblin` — better maintained (gimli / rustc-team ownership), lower unsafe surface, handles stripped binaries cleanly (section iteration returns `None` without panic). Since `object` is already transitively available in many Rust tool dep trees, the cost of adding it is minimal.

**LOC estimate:** ~250 LOC — 50 for section lookup + magic fallback, 150 for the varint/length-prefixed string decoder + `dep` line tokeniser, 50 for stripped-binary diagnostic property emission.

**Alternatives rejected:**
- `goblin`: works but `object` has stronger maintenance.
- Shelling out to `go version -m`: violates offline constraint + requires Go toolchain at scan time.
- Checked-in third-party BuildInfo crate: none exist that are maintained.

---

## R3 — Go `go.mod` / `go.sum` grammar scope

**Decision:** Support `go.sum` as the authoritative list of modules (every `<module> <version> h1:<sum>` triple produces one component). `go.mod` is read purely to identify the main module + direct-requires edges (the `require` block). `replace` directives are honoured by updating the target `(module, version)` pair before PURL construction. `exclude` directives filter entries. Toolchain versions Go 1.17+ supported (go.mod / go.sum format stable since then; Go 1.17 introduced the pruned module graph).

**Rationale:** `go.sum` is the ground truth for what was actually fetched; `go.mod` declarations can be stale relative to `go.sum`. Using `go.sum` for discovery + `go.mod` for graph topology matches how trivy and syft handle it. Pseudo-versions like `v0.0.0-20230101000000-abcdef` round-trip through packageurl-python cleanly — nothing special needed.

**LOC estimate:** ~300 LOC for both files combined.

**Alternatives rejected:**
- Use `go.mod` alone: misses indirect deps that `go.sum` records.
- Use `go list -m all` via subprocess: violates offline + requires Go toolchain.

---

## R4 — Cargo.lock v3 vs v4 schema deltas

**Decision:** Parse both v3 and v4 via a single `toml`-based parser that branches on the top-level `version = 3` vs `version = 4` field. v4 adds an explicit `[[package]].dependencies]` list reference format (e.g. `"name"` vs `"name version"` vs `"name version source"`) but the canonical package table `[[package]]` shape (name, version, source, checksum, dependencies) is unchanged. v1 / v2 return an actionable diagnostic per the FR-040 refusal semantics.

**Rationale:** The v3→v4 change is small and well-documented in the Cargo book. Supporting both is ~30 LOC of branch logic.

**LOC estimate:** ~250 LOC total (parser) + ~150 LOC (tests across v1 refusal, v2 refusal, v3 + v4 with mixed registry / git / path sources).

**Alternatives rejected:**
- Use `cargo-lock` crate (third-party): would add a dependency for something we can do with the existing `toml` crate in <300 LOC.
- Support v1 / v2: covered in clarification Q1 — regenerate via `cargo generate-lockfile` is a deterministic fix.

---

## R5 — Maven `pom.xml` property resolution

**Decision:** Resolve the three types of property references that `pom.xml` commonly uses:
1. `${project.version}` → read from `<project>/<version>` or `<project>/<parent>/<version>`.
2. `${project.groupId}` → same pattern.
3. Literal `${<custom>}` references that resolve via the `<properties>` block in the same POM.

If a reference remains unresolved after these passes (e.g. inherited from a parent POM not present in the scan root), emit the component with `version = ""`, `requirement_range = Some("<raw placeholder>")`, and tier = `design`. Do NOT recurse into parent POMs in this milestone — parent POM resolution requires a resolver and is stretch scope per FR-033.

**Rationale:** Covers the ~90% of declared deps that use inline properties without pulling in a full Maven resolver. The remaining 10% gracefully degrade to design-tier with a traceable range string.

**LOC estimate:** ~500 LOC for the parser + property resolver + tests.

**Alternatives rejected:**
- Full Maven property inheritance (parent POM traversal): stretch; not a milestone-003 success criterion.
- Ignore unresolved placeholders: violates Principle VIII (completeness without transparency = silent omission).

---

## R6 — JAR archive reading strategy

**Decision:** In-memory `zip` crate reads only. No tempfile extraction. For each JAR, iterate entries; read `META-INF/MANIFEST.MF` + any `META-INF/maven/<group>/<artifact>/pom.properties` directly from the archive stream. Apply the zip-slip guard on every entry path (`..` components rejected; reject entries whose canonical path escapes the synthetic root). Size cap: reject entries >64 MB (huge single files inside a JAR are never coordinate metadata).

**Rationale:** Reading in-memory eliminates disk-write attack surface (no zip-slip bypass possible if we never touch the filesystem). Per FR-009 clarification: zip-slip is the #1 JAR parsing CVE category; the guard is table stakes.

**LOC estimate:** ~350 LOC — JAR walker (100) + MANIFEST parser (80) + pom.properties parser (70) + tests (100).

**Alternatives rejected:**
- Extract to tempdir then re-scan: introduces zip-slip risk + disk I/O overhead.
- Use `zip-rs` fork: stock `zip` is adequate and widely maintained.

---

## R7 — `Gemfile.lock` grammar

**Decision:** Hand-written line-parser. Recognises four section types: `GEM`, `GIT`, `PATH`, `PLATFORMS`, `DEPENDENCIES`, `BUNDLED WITH`. Each non-DEPENDENCIES section uses an indented list like `    name (version)` with optional nested dep lines `      nested-dep (version-spec)`. `DEPENDENCIES` at the top level of the project is the direct-deps list.

**Rationale:** Gemfile.lock is not standard YAML/TOML/JSON — it's bundler's own format. Writing a ~200-LOC parser is simpler than attempting to coerce any existing parser. trivy's Ruby reader uses the same hand-parse approach.

**LOC estimate:** ~300 LOC including tests (bundler v2+ format plus a compatibility path for v1 with degraded parsing per the FR-050 edge case).

**Alternatives rejected:**
- Shell out to `bundle list`: violates offline + requires Ruby toolchain.
- Pre-parse via `serde_yaml`: Gemfile.lock's indentation isn't YAML.

---

## R8 — RPM vendor mapping (clarification-session follow-up)

**Decision:** Honour the clarification answer verbatim: explicit 9-entry map (rhel→redhat, rocky→rocky, fedora→fedora, amzn→amazon, centos→centos, ol→oracle, almalinux→almalinux, opensuse-leap→opensuse, sles→suse); unmapped `/etc/os-release::ID` values pass through as the raw `ID` string in the PURL vendor segment. Implementation reuses `scan_fs::os_release::read_id()` (add new helper) alongside the existing `read_version_codename()` used by the deb flow.

**Rationale:** Matches trivy's behaviour on RHEL-family distros and keeps the door open for ecosystems mikebom hasn't seen yet without silent fallback. Empirically verified against packageurl-python that `pkg:rpm/<any-literal-string>/name@...` round-trips.

**LOC estimate:** ~30 LOC for the map + ~50 LOC tests (one per listed ID + one verbatim-fallback case).

**Alternatives rejected:** documented in the clarification session.

---

## R9 — Dependency-tree edge provenance per ecosystem

**Decision:** Use these `EnrichmentProvenance.data_type` strings (mirrors the existing `package-database-depends` and milestone-002 `dist-info-requires-dist`):

| Ecosystem | provenance data_type |
|---|---|
| Go go.mod require | `go-mod-require` |
| Go go.sum indirect | `go-sum-indirect` |
| Go binary BuildInfo `dep` | `go-buildinfo-dep` |
| RPM rpmdb REQUIRES | `rpmdb-requires` |
| Maven pom.xml dependencies | `pom-xml-dependency` |
| Maven JAR embedded pom | `jar-pom-properties-dependency` |
| Cargo.lock dependencies | `cargo-lock-dependency` |
| Gemfile.lock DEPENDENCIES | `gemfile-lock-dependency` |

**Rationale:** One string per (ecosystem, source) pair so downstream tooling can filter edges by their observation source. Consistent with how milestone 002 named its pypi / npm provenance strings.

---

## R10 — `#[deny(clippy::unwrap_used)]` CI gate

**Decision:** Add `#![deny(clippy::unwrap_used)]` to `mikebom-cli/src/lib.rs` (create a lib entry point if one doesn't yet exist — `mikebom-cli` is currently bin-only) OR, if keeping bin-only, add it to `mikebom-cli/src/main.rs` and let it cascade across modules. Exempt `#[cfg(test)]` modules and `/tests/` integration tests via module-scoped `#![cfg_attr(test, allow(clippy::unwrap_used))]`. Run `cargo clippy --all-targets --all-features -- -D warnings` in CI as the gate.

**Rationale:** Principle IV mandates zero `.unwrap()` in production. The clippy lint catches any regression at build time. Exempting tests preserves test readability.

**LOC estimate:** ~5 LOC of lint config + 1 CI step.

---

## R11 — Fuzz-testing seed corpus (FR-009 follow-up)

**Decision:** Stage seed corpora for four parsers (`go_binary`, `rpmdb_sqlite`, `zip`-backed JAR inspector, `rpm.rs`) as checked-in test fixtures. The actual fuzz harness (cargo-fuzz / libfuzzer integration) is deferred to a follow-up spec per the clarification. Seeds:
- Go binary: 5–10 hand-chosen `/hello-world` builds across Go 1.17, 1.19, 1.21, 1.23 + stripped variants.
- rpmdb.sqlite: 2–3 real-world samples extracted from RHEL 8, 9, and Rocky 9 images; one intentionally-truncated sample.
- JAR: one fat JAR + one crafted zip-slip attempt.
- ELF with malformed section headers: one crafted sample.

**Rationale:** Baseline parsers ship first (milestone 003); fuzz infrastructure lands in a follow-up once we have stable target surfaces.

---

## R12 — Performance budgets per ecosystem

**Decision:** The SC-003 / SC-009 / SC-010 bars hold. Additional internal guardrails (not user-visible SCs):

| Ecosystem | Input size | Target time | Notes |
|---|---|---|---|
| Go source | 500 modules in go.sum | <500 ms | pure string parsing |
| Go binary | 200 MB binary | <2 s | SC-009 mandate |
| rpmdb.sqlite | 1000 packages | <500 ms | B-tree iteration |
| JAR | 100 fat JARs at 10 MB each | <15 s | in-memory ZIP |
| pom.xml | 50-dep pom.xml | <50 ms | quick-xml parse |
| Cargo.lock | 500-crate workspace | <200 ms | toml parse |
| Gemfile.lock | 200 gems | <100 ms | line parse |

These feed into tasks.md as perf-regression gates.

**Rationale:** Giving each parser a concrete target prevents the aggregate SC-010 (<10 s polyglot scan) from being met by slow parsers offsetting fast ones.

---

## Out of research

Items deliberately NOT resolved here — they are either clarification-complete (Cargo v1/v2 refusal Q1, RPM vendor mapping Q2, defense-in-depth Q3) or planning-phase details that tasks.md will surface:

- Exact `compositions[]` ordering for five new ecosystems (covered in contracts/schema.md).
- Per-ecosystem CycloneDX component-property key set (covered in contracts/component-output.md).
- EVALUATION.md refresh columns (a polish-phase deliverable).
