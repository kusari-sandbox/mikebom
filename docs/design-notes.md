# mikebom design notes

Running reference for architectural decisions, tradeoffs, and known
limitations across ecosystems. Intended as a pickup point for future
sessions — skim the ecosystem-status table first, drill into the
sections that matter for the task at hand.

---

## Ecosystem coverage

| Ecosystem | Component discovery | Dep-graph completeness | Notes |
|---|---|---|---|
| **deb** | `/var/lib/dpkg/status` | Full (via `Depends:`) | Always complete when db present |
| **apk** | `/lib/apk/db/installed` | Partial (direct `D:` only; no transitive encoded by apk) | |
| **rpm** | `/var/lib/rpm/rpmdb.sqlite` (pure-Rust reader) | Full (via `REQUIRES`) | BDB `Packages` format diagnosed, not parsed |
| **pypi** | venv `dist-info/METADATA`, poetry/pipfile locks, requirements.txt | Partial: venv `Requires-Dist:` is flat; locks encode tree | |
| **npm** | `package-lock.json` v2/v3, `pnpm-lock.yaml`, `node_modules/` | Full (locks encode tree) | v1 locks refused |
| **cargo** | `Cargo.lock` v3/v4 | Full (lockfile encodes tree) | v1/v2 refused |
| **gem** | `Gemfile.lock` indent structure + `specifications/*.gemspec` walker | Full (indent-6 lines = per-gem edges); gemspecs have no edges | Gemspec walker catches Ruby stdlib/default gems invisible to Gemfile.lock |
| **golang (source)** | `go.sum` + `go.mod` + `$GOMODCACHE/cache/download/<escaped>/@v/<v>.mod` walker | Full when module cache warm; root → directs when cold | |
| **golang (binary)** | `runtime/debug.BuildInfo` (inline format, Go 1.18+) | Module list but **no edges** — BuildInfo doesn't encode them | Pre-1.18 format flagged as `buildinfo-status = unsupported` |
| **maven** | Project pom.xml, JAR `META-INF/maven/.../{pom.properties,pom.xml}`, `~/.m2/repository/.../*.pom`, deps.dev fallback | Full when cache warm or network available; see layered strategy below | |

---

## Dep-graph resolution strategy (Maven)

Maven is the most complex — transitive versions can live in parent
POMs' `<dependencyManagement>` or be supplied by BOM imports. The
scanner layers sources in this order:

1. **Scanned project `pom.xml`** — direct deps, declared versions.
2. **JAR-embedded `META-INF/maven/<g>/<a>/pom.xml`** — identity from
   pom.properties; edges from the embedded pom.xml. Works for
   deployed containers. Fat/shaded JARs yield one
   `EmbeddedMavenMeta` per vendored artifact.
3. **`~/.m2/repository/` cache walker** (BFS) — for each observed
   coord, fetch its cached `.pom`, extract `<dependencies>`, recurse.
4. **Parent-POM chain** (`build_effective_pom` in `maven.rs`) —
   merges `<properties>` and `<dependencyManagement>` up the
   `<parent>` chain. Required for guava (parent POM declares
   `jsr305`, `checker-qual`, etc. versions) and jackson-databind
   (`${jackson.version.core}` resolved in parent). BOM imports
   (`<type>pom</type><scope>import</scope>`) flattened into the
   effective `dependencyManagement`. Memoized, cycle-guarded.
5. **deps.dev `:dependencies` endpoint** (`deps_dev_graph.rs`) —
   online fallback. Fills shaded-transitive gaps + cold-cache gaps.
   Tagged `source_type = "declared-not-cached"` distinct from
   locally-observed coords.
6. **Empty edges** — final graceful degradation.

### deps.dev policy (critical)

- deps.dev is authoritative for **edge topology** ("A depends on B").
- deps.dev is **not** authoritative for **versions**. Local `.m2`
  wins. When deps.dev reports `foo@1.0` and local has `foo@1.5`, the
  emitted edge target is `foo@1.5` — what's actually on disk.
- When a deps.dev-reported coord has no local version at all, it's
  emitted as a new component tagged `source_type = "declared-not-cached"`.
- Offline mode (`--offline`) skips the entire deps.dev pass.
- Concurrency capped at 8 in-flight requests (`tokio::task::JoinSet`).

### Why deps.dev is only wired for Maven

Other ecosystems have local signals that are complete:
- **Cargo**: `Cargo.lock` encodes the full tree.
- **Go source**: `go.sum` + module cache reconstructs the tree.
- **Ruby**: `Gemfile.lock` indent-6 lines encode transitives.
- **npm**: lockfiles encode tree.

deps.dev could be wired for these later (e.g. for Go binaries where
BuildInfo doesn't encode edges), but isn't today.

---

## Source-type markers glossary

The `mikebom:source-type` property on each CycloneDX component
distinguishes how a coord was discovered:

| Value | Meaning |
|---|---|
| `workspace` | Declared in the scanned project's own manifest (pom.xml, Cargo.toml, etc.). Highest trust — the user directly wrote this dep. |
| `transitive` | BFS-discovered via local cache / JAR walk. Strong trust — the coord is on-disk locally, its own manifest says it declares these deps. |
| `declared-not-cached` | deps.dev says this coord is part of the declared tree, but it's not present locally at any version. Lower trust — may not actually be installed. |
| `analyzed` | JAR walker emitted this from `META-INF/maven/.../pom.properties`. Strong trust — the JAR is on disk. |
| `git`, `path`, `workspace`, `local` | Cargo/Gem source-kind markers for non-registry packages. |

`mikebom:sbom-tier` is a separate axis (`source` / `analyzed` / `deployed` / `design` / `build`) — see `mikebom-common/src/resolution.rs` for the full ladder.

---

## Known limitations / sharp edges

### Maven
- **`<exclusions>`** not parsed. If a project excludes a transitive via `<exclusions>` in its pom, mikebom still emits the excluded coord as a dep.
- **Version ranges** (`[1.0,2.0)`) not resolved. Maven picks a specific version at build time; mikebom treats the range string as-is.
- **`<profiles>`** ignored. Profile-conditional deps never emit.
- **Plugin-section deps** (`<build><plugins>`) ignored — not runtime deps.
- **POM-less JARs** (older Gradle outputs, OSGi bundles) can't be inspected via `META-INF/maven/` — coord + deps invisible.
- **Same artifactId across groups** — `scan_fs/mod.rs::normalize_dep_name` keys edges on `(ecosystem, name)` only, so two unrelated artifacts both named `commons` in different groups would conflate. Pre-existing; not made worse by any recent work.
- **Compositions-level transparency** — currently the `maven` composition is marked `complete` whenever any source-tier Maven coord is seen. Should probably downgrade to `incomplete_first_party_only` when any BFS cache-miss or deps.dev failure occurred during the scan. Deferred.

### Go
- **Binary scans have no edges.** `runtime/debug.BuildInfo` encodes module list but not module→module relationships. Source-tree scans get the graph via the module cache walker.
- **Scratch / distroless images with a single Go binary** produce a flat component list. That's the accurate answer — the binary doesn't know the graph.
- **Private module proxies / `vendor/` directory component extraction** out of scope.

### RPM
- **Berkeley DB rpmdb** (`/var/lib/rpm/Packages` pre-RHEL 8) is detected but not parsed. Diagnostic logged, zero rpm components emitted.
- **rpmdb.sqlite size cap** is 200 MB — defense-in-depth. Real rpmdbs are ~5 MB.
- **Pure-Rust SQLite reader** only handles leaf-table + interior-table pages; overflow pages refused. RHEL rpmdbs don't use overflow pages in practice.

### Ruby
- Only `--include-dev` gating is on gems under `test` scope in the declaration tree; bundler's full scope semantics not modeled.
- **Gemspec walker** (added 2026-04-20 for sbom-conformance bug 3) parses name + version from `specifications/*.gemspec` files via a line-scanner for `s.name = "..."` / `s.version = "..."`. Interpolated versions (`"#{FOO_VERSION}"`) produce garbage strings — downstream PURL construction will typically reject them. In practice, gemspec versions are always literal strings so this is a theoretical edge case.

### Binary scanner
- **Version-string scanner is gated on `skip_file_level_and_linkage`** (added 2026-04-20 for conformance bug 6a). Claimed binaries no longer emit `pkg:generic/<library>@<version>` from the curated scanner. Trade-off: static-library version detection inside claimed binaries (e.g. statically-linked OpenSSL in a dpkg-owned binary) is lost. Accepted because the FP flood from self-identifying claimed binaries (curl reporting libcurl from /usr/bin/curl) was the larger correctness problem.
- **Linkage aggregator probes standard library dirs** (added 2026-04-20 for conformance bug 6b) via `add_with_claim_check`. Sonames resolving to a claimed library path (e.g. libc.so.6 → /lib/x86_64-linux-gnu/libc.so.6 owned by libc6 deb) are skipped.
- **ELF-note-package emission is claim-gated + OS-context-aware** (added 2026-04-20 for conformance bug 1). Previously unconditional — a claimed Fedora binary would emit both `pkg:rpm/fedora/<subpackage>@<ver>` (from rpmdb) AND a ghost `pkg:rpm/rpm/<source-package>@<ver>` (from the ELF `.note.package` section). Now the ELF-note emission is gated on `skip_file_level_and_linkage` (drops ghosts for claimed binaries). For unclaimed binaries, the signature of `note_package_to_entry` takes the scan's `/etc/os-release` `ID` and `VERSION_ID` — precedence is `note.distro` > os-release ID > hardcoded type default (rpm/debian/alpine). When VERSION_ID is known, a `distro=<vendor>-<version>` qualifier is appended. Trade-off: for claimed binaries we lose the ELF note's source-package identity; recovery is via rpm's `SOURCERPM` header if needed.
- **Curated version-string scanner is a 7-library list** (OpenSSL/BoringSSL/zlib/SQLite/curl/PCRE/PCRE2). Binaries installed outside the package manager without matching patterns emit file-level only (hash-only PURL). Extending the list is case-by-case; see backlog item #12.

### OS-release reader
- **Rootfs-aware fallback** (added 2026-04-20 for conformance bug 1): tries `<rootfs>/etc/os-release` first, falls back to `<rootfs>/usr/lib/os-release`. Fixes Ubuntu images where /etc/os-release is a relative symlink that can dangle after container-layer tar extraction.

### PURL canonicalization
- **Qualifiers sorted alphabetically** (added 2026-04-20): `Purl::new` re-canonicalizes the qualifier section so `?epoch=1&arch=x86_64&distro=fedora-40` becomes `?arch=x86_64&distro=fedora-40&epoch=1`. Required by purl-spec `docs/how-to-build.md` ("Sort this list of qualifier strings lexicographically"). Affects every ecosystem uniformly. Already-sorted inputs pass through unchanged (preserves caller-side `encode_purl_segment` work).
- **RPM `epoch=0` omitted** (added 2026-04-20): treats `Some(0)` as semantically "no epoch" and drops the qualifier. RPM treats absent and 0 as equivalent for version comparison; `rpm -qa` default display omits; purl-spec rpm example never shows `epoch=0`. Reverses the milestone-005 round-trip-`rpm -qa` decision (see `specs/005-purl-and-scope-alignment/research.md` for the trade-off).

### CycloneDX 1.6 serialization
- **`evidence.identity` is an array** (added 2026-04-20 for sbomqs parse failure): the single-object form was deprecated in CDX 1.5→1.6. Every component emits `identity: [{...}]` with exactly one identity object.
- **`evidence.identity[].tools` is never emitted**: per CDX 1.6 that field must contain bom-refs to items declared in the BOM (metadata/tools/services/formulation). mikebom's previous payload (TLS connection IDs + deps.dev markers) are not tools and don't exist elsewhere in the BOM. Both now land on the component as properties `mikebom:source-connection-ids` (comma-joined) and `mikebom:deps-dev-match` (`<system>:<name>@<version>`). The `pkg:generic/...` provenance semantics are preserved, just in the CDX-conformant location.
- **License shape**: components emit `{"license": {"id": "<SPDX-id>"}}` for single-identifier licenses (via `SpdxExpression::as_spdx_id`) and `{"expression": "<expr>"}` for compound expressions. Required for sbomqs's `comp_with_valid_licenses` check.
- **Component hashes from manifests**: npm's `package-lock.json::integrity` (sha256/sha384/sha512) and Cargo.lock's `checksum` (sha256) flow through `PackageDbEntry.hashes` → `ResolvedComponent.hashes` → `components[].hashes[]`. Other ecosystems (gem/maven/pypi/go) defer for now — see TODO.
- **`metadata.component` carries synthetic `purl` + `cpe`**: scan subjects emit `pkg:generic/<name>@<version>` and `cpe:2.3:a:mikebom:<name>:<version>:*:*:*:*:*:*:*`. Required for sbomqs schema validity (the validator rejects empty cpe/purl on metadata.component even though the spec doesn't require them).
- **`metadata.authors`, `metadata.supplier`, `metadata.licenses` (CC0-1.0)**: hardcoded SBOM-producer identity + dataLicense.
- **Trace-integrity counters on `metadata.properties`**: `mikebom:trace-integrity-{ring-buffer-overflows,events-dropped,uprobe-attach-failures,kprobe-attach-failures}` instead of attached to a composition (CDX 1.6 compositions schema sets `additionalProperties: false`).
- **Compositions emit both `assemblies` and `dependencies`** for each `complete` ecosystem record. Plus a separate dep-completeness composition listing the primary's bom-ref under `dependencies` when no integrity issues — needed for sbomqs's `comp_with_dependencies` to credit the primary.
- **Primary-dependency fallback in `build_dependencies`**: when the scanned project's root entry was filtered out (npm path_key=="", cargo source=None) and no explicit edges connect the metadata.component to anything, synthesize edges from the primary to every "root" component (those nothing else depends on). Without this, sbomqs reports "no dependency graph present" even when transitive edges are populated.

### sbomqs scoring baseline (2026-04-20, post-CD pass)
After the ClearlyDefined enrichment integration, source-scan SBOMs reach **8.8/10 (Grade B)** on npm fixtures, **7.0–7.8 (C)** on cargo / gem / polyglot, **6.1 (D)** on RPM image scans (Integrity 0/10 still — rpmdb has no per-package hashes mikebom can use). Remaining deferred work (separate milestone):
- `comp_with_strong_checksums` for gem/maven/pypi/go/rpm (need ecosystem-specific hash sources)
- `comp_no_deprecated_licenses` / `comp_no_restrictive_licenses` (the spdx crate has the data; needs threading through)
- `comp_with_supplier` (needs walking node_modules / .m2 cache for author info; lockfiles alone don't carry it)
- `comp_with_source_code` (needs VCS URL extraction per ecosystem)
- `sbom_signature` (needs key/signing infra)
- `sbom_completeness_declared` for gem (currently lockfile gem composition isn't tagged complete)

### ClearlyDefined enrichment (added 2026-04-20)
- Post-scan enricher mirroring the `deps.dev` pattern. Lives at `mikebom-cli/src/enrich/clearly_defined_{client,coord,source}.rs`.
- Queries `https://api.clearlydefined.io/definitions/{type}/{provider}/{ns}/{name}/{rev}` per supported component (npm, cargo, gem, pypi, maven, golang). CD's `licensed.declared` becomes mikebom's `acknowledgement: "concluded"` license entry.
- Honors the existing `--offline` flag (no HTTP when set).
- In-memory cache (per-scan, not persistent). 5s timeout per request.
- Sequential per-component (matches deps.dev). Bounded concurrency deferred until profiling shows it matters.
- Unsupported ecosystems (deb / apk / rpm / generic / alpm) skipped silently.
- When CD has no entry for a package, no concluded entry emitted (declared remains). `NOASSERTION` is intentionally never emitted — sbomqs's `ValidateLicenseText` rejects it, so it would add cost without unlocking score.

### General
- **Same-artifact-different-group edge conflation** (see Maven note).
- **`#[deny(clippy::unwrap_used)]` at crate root** — production code cannot use `.unwrap()`. Test modules opt back in via `#[cfg_attr(test, allow(clippy::unwrap_used))]`.

---

## Testing layout

| Fixture type | Where | Shape |
|---|---|---|
| Unit tests | Inline in each `mikebom-cli/src/scan_fs/package_db/*.rs` | Synthetic via `tempfile::tempdir()`; helpers like `write_cached_pom`, `write_jar` |
| Integration tests | `mikebom-cli/tests/scan_<ecosystem>.rs` | Shell out to the compiled binary via `CARGO_BIN_EXE_mikebom`; parse resulting JSON SBOM |
| Real fixtures | `tests/fixtures/<ecosystem>/` | Real go.mod/go.sum + real Go binaries, real Gemfile.lock, hand-crafted rpmdb.sqlite (via Python sqlite3), synthetic JARs |
| Cache-warm tests | Synthetic `<rootfs>/root/.m2/repository/...` inside tempdirs | Avoids dependency on user's host `~/.m2` |
| Online tests | Unit tests involving deps.dev are unit-tested only for name-formatting / URL construction; no HTTP roundtrips in CI | Integration tests that would need network are gated behind env-present checks |

Full-suite regression: `cargo test --workspace` — 854 passing, 0 failed as of ClearlyDefined enrichment pass (2026-04-20). Baseline was 585 at milestone 003.

---

## Key code landmarks

### Maven (most complex)
- `mikebom-cli/src/scan_fs/package_db/maven.rs`
  - `parse_pom_xml` — XML traversal; captures self/parent coords, properties, dependencies, dependencyManagement
  - `EffectivePom`, `build_effective_pom` — parent-chain walker with memo + cycle guard
  - `resolve_dep_version`, `resolve_dep_group` — use effective POM for placeholder resolution
  - `bfs_transitive_poms` — BFS over M2 cache driven from direct-dep seeds
  - `walk_jar_maven_meta` — JAR-embedded pom walker
  - `MavenRepoCache::discover` — probes `$HOME/.m2`, `<rootfs>/root/.m2`, etc.

### deps.dev enrichment
- `mikebom-cli/src/enrich/deps_dev_client.rs` — HTTP client; `get_dependency_graph` hits `:dependencies` endpoint
- `mikebom-cli/src/enrich/deps_dev_system.rs` — PURL-ecosystem→system mapping + Maven-aware `deps_dev_package_name`
- `mikebom-cli/src/enrich/deps_dev_graph.rs` — post-scan enricher; substitutes local versions, tags declared-not-cached
- `mikebom-cli/src/enrich/depsdev_source.rs` — existing license enricher (now using the Maven-aware name format)

### Go
- `mikebom-cli/src/scan_fs/package_db/golang.rs`
  - `GoModCache::discover` — cache-root discovery for source scans
  - `build_entries_from_go_module` + `cache_lookup_depends` — walks `<cache>/@v/*.mod` files
  - `escape_module_path` — capital letters → `!x` for cache path lookup
- `mikebom-cli/src/scan_fs/package_db/go_binary.rs`
  - `decode_buildinfo` — reads inline-format BuildInfo from Go 1.18+ binaries
  - `detect_is_go` — section lookup via `object` crate, fallback memmem for stripped binaries

### Cache / SQLite
- `mikebom-cli/src/scan_fs/package_db/rpmdb_sqlite/` — pure-Rust SQLite subset reader

### Orchestration
- `mikebom-cli/src/cli/scan_cmd.rs` — wires scan_fs → enrichment → SBOM serialization
- `mikebom-cli/src/scan_fs/mod.rs` — `scan_path` entry, relationship resolution + dangling-target filter

---

## Deferred backlog

Ordered rough priority (highest-value first):

1. **Maven `<exclusions>`** — needed for correctness when projects deliberately exclude transitives.
2. **Maven version ranges** — `[1.0,2.0)` resolution; low-priority since published artifacts rarely use ranges.
3. **Parent-POM inheritance for ancestral `<parent>` chains** — basic case works; deeply nested parents (e.g. Spring's hierarchy) may still produce unresolved placeholders if a grandparent's properties aren't found. Verify in practice.
4. **Compositions degradation** — downgrade ecosystem composition from `complete` to `incomplete_first_party_only` when cache-miss or deps.dev-miss occurred. Requires threading a miss counter through scan_fs.
5. **JAR-embedded pom.xml for Maven transitive edges in container scans** — when a shaded JAR is the only artifact and deps.dev is offline, we currently emit the top-level coord with empty edges. Could fall back to reading the shade plugin's dependency-reduced-pom.xml if present.
6. **Go: deps.dev fallback for binary scans** — `runtime/debug.BuildInfo` emits coords but no edges. deps.dev could fill in the graph. Trade-off: network dependency for a scan mode that today is fully offline.
7. **npm scoped names** — deps.dev formatter now handles `@scope/name`; dep-graph enricher only wired for Maven. Could extend if npm lockfile scans ever need supplementation.
8. **POM-less JARs** (OSGi bundles, older Gradle artifacts) — would need OSGi manifest (`Import-Package`, `Require-Bundle`) parsing.
9. **Same-artifactId-different-groupId edge conflation** — pre-existing. Fix would require keying edges on `(ecosystem, namespace, name)` not just `(ecosystem, name)`.
10. **Multiple cached versions of the same `(g, a)` in `~/.m2`** — the JAR walker's `coord_index` currently keeps the first-observed version. Good enough for most cases; a project-specific resolution would require reading the project's pom + running Maven's "nearest wins" algorithm.
11. **Go source-tree scope** — investigate switching from go.sum-driven to `go.mod Require`-driven component enumeration for Go 1.17+ sources. Would align with trivy's default behavior (syft default uses `packages.Load` which is even more inclusive). Full context in `docs/research/go-binary-scope.md`.
12. **Binary-scanner jq detection** — `version_strings.rs` has a curated 7-library scanner (OpenSSL/BoringSSL/zlib/SQLite/curl/PCRE/PCRE2). Unmanaged binaries like a curl'd `/usr/local/bin/jq` emit only as `pkg:generic/jq?file-sha256=...` (hash, no version). Options: (a) add jq-specific pattern to the curated list — doesn't scale; (b) generic version-string heuristic (`<name>-<ver>` / `<name> version <ver>`) — high FP surface; (c) investigate trivy's `binaries` analyzer and port the subset that has low FP risk.

### Deferred: sbomqs score lift

Tracked separately because each item has its own design depth. Current source-scan baseline is 7.0–8.8/10 depending on fixture (post-CD enrichment, 2026-04-20).

13. **CDX `comp_no_deprecated_licenses` + `comp_no_restrictive_licenses`** — sbomqs reads these off `concluded_licenses[]`. The `spdx` crate exposes `is_deprecated()` and OSI/copyleft classifications; need to thread that through `SpdxExpression` (e.g. `as_spdx_id_info() -> Option<{id, deprecated, restrictive}>`) so the CDX serializer can emit `properties` flagging each. ~6.4% in Licensing for npm/cargo fixtures.
14. **Component supplier extraction** — npm `package.json::author.name`, cargo `Cargo.toml::package.authors[0]`, maven `pom.xml::organization`. Lockfile scans currently miss these because lockfiles don't carry author info; adding a node_modules / .m2 walk for the supplier field would unlock `comp_with_supplier` (2.2%). Heuristic for npm scoped packages: treat `@scope` as supplier when `author` absent.
15. **Component VCS URL externalReferences** — emit `externalReferences[{type: "vcs", url: ...}]` from each ecosystem's manifest (cargo `repository`, npm `repository.url`, maven `<scm>`). Unlocks `comp_with_source_code` (2.2%). Most ecosystems have this in the manifest so it's mostly extraction work.
16. **SBOM signature** (`sbom_signature` 1.8%) — sign the emitted CDX BOM in-place (CycloneDX defines a `signature` block). Needs key management story (CLI flag for key path? KMS?). Separate from this effort.
17. **Per-ecosystem manifest hashes** — gem/maven/pypi/go currently emit no per-component hashes. gem: defer (Gemfile.lock has no hashes). maven: SHA-1 sidecar files (`.jar.sha1`) accompany each artifact in `~/.m2`. pypi: `requirements.txt --hash=` form + dist-info `RECORD` file. go: `go.sum` H1 hashes are Merkle trie roots (NOT file SHA-256) — would need a custom CDX hash type.
18. **ClearlyDefined ecosystem expansion** — current scope is npm/cargo/gem/pypi/maven/golang. CD also has `deb` (Debian src), `composer`, `pod`, `conda`, `nuget`. Add coord mappers + verify CD coverage is non-trivial before turning each on.
19. **ClearlyDefined bounded concurrency** — current implementation is sequential per-component (matches `deps.dev`). For scans of 100+ components this can be 10–30 seconds. Concrete optimization: `tokio::task::JoinSet` with 8 in-flight + reqwest connection pool reuse. Deferred until profiling shows it dominates scan time.
20. **ClearlyDefined harvest endpoint** — CD has `/notices`, `/curations`, search APIs that could enrich provenance further (license texts, attributions, copyright statements). Out of scope for this milestone but unlock more sbomqs categories if added.

---

## Relevant specs

- `specs/001-build-trace-pipeline/` — original eBPF build-trace mode
- `specs/002-python-npm-ecosystem/` — Python + npm ecosystem expansion
- `specs/003-multi-ecosystem-expansion/` — Go / RPM / Maven / Cargo / Gem + foundational work
- `.specify/memory/constitution.md` — 12-principle constitution; notable constraints: no C dependencies, no `.unwrap()` in production, generation context always stamped, packageurl-python conformance

---

## Session journal pointers

Major work milestones (for context in future sessions):

- Foundational phase (T001–T014): workspace deps, module stubs, clippy gate, pure-Rust SQLite scaffolding.
- US1 Go source + binary: `go.mod`/`go.sum` parser, BuildInfo inline decoder, module-path escaping for cache walker.
- US2 RPM: pure-Rust SQLite reader (page/record/schema), vendor ID→PURL slug mapping.
- US3 Maven: pom.xml parser with property resolution, JAR walker with embedded pom.xml support.
- US4 Cargo: v3/v4 lockfile parser, v1/v2 refusal, source-kind classification.
- US5 Gem: Gemfile.lock section parser with indent-6 transitive edge capture.
- Post-US work (what the user called "get better results"):
  - Ruby transitive edges via indent-6 parsing.
  - Go transitive tree via module cache `@v/*.mod` walker.
  - Maven M2 cache BFS walker.
  - Maven JAR-embedded pom.xml walker (non-shaded).
  - Maven parent-POM chain resolution (`EffectivePom` with `<properties>` + `<dependencyManagement>` inheritance + BOM imports).
  - Maven deps.dev `:dependencies` fallback (edge-authoritative, version-deferential).
