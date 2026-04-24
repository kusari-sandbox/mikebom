# Changelog

All notable changes to mikebom are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/) once it exits
`0.1.x` alpha.

## [Unreleased]

### Added
- **Feature 009 refinement — bytecode-presence gating for Maven
  shade-relocation.** Shade-relocation entries are now emitted only when
  an ancestor's bytecode is verifiably present in the enclosing JAR
  (either at its original group path or at a shade-relocated path whose
  leaf matches a distinctive artifact-id fragment). Apache's
  `maven-dependency-plugin` emits `META-INF/DEPENDENCIES` into any JAR
  it is configured on, not only shade fat-jars, so the pre-gating
  emission path reported ancestors as "present in" JARs whose bytecode
  was never relocated there. New unit + integration tests exercise
  every disposition. See `specs/009-maven-shade-deps/spec.md` FR-002b.

### Removed
- **`mikebom sbom compare` subcommand** and the `demos/` directory.
  The head-to-head comparison story is now owned by a separate test
  suite outside this repo; keeping the in-tree version invited drift
  between the two. Any workflow that depended on `sbom compare`
  should move to the external suite.

## [0.1.0-alpha.3] — 2026-04-23

### Added
- **Feature 009 US1 — shade-relocation ancestor emission.** When a JAR
  contains `META-INF/DEPENDENCIES`, mikebom emits one nested
  `pkg:maven/...` component per declared ancestor, nested under the
  enclosing JAR's primary coord and tagged with
  `mikebom:shade-relocation = true`. Ancestor licenses are parsed from
  the adjacent `License:` lines. Classifier-bearing coords preserve
  `?classifier=<value>` in the PURL. Self-references are dropped
  (`com.example:outer` cannot shade itself). Commit `cdf29b0`.
- **Feature 008 US3 — Maven target/-dir path heuristic** for
  suppressing `target/`-staged development artifacts from image scans.
  Commit `701ea50` (#14).
- **Feature 008 US2 — cache-ZIP Go component filter.** Emissions from
  Go module-cache ZIPs are cross-checked against the linked binary's
  `runtime/debug.BuildInfo`, suppressing ZIPs that never made it into
  the shipped binary. Commit `db6fbab` (#13).
- **Feature 007 US1 — Fedora sidecar POM reading.** JARs installed by
  `dnf` that have stripped embedded `META-INF/maven/` metadata now
  fall back to `/usr/share/maven-poms/` sidecar POMs (JPP-prefixed
  and plain). Commit `a06b7ff` (#8).
- **Feature 007 US2+US3 — Go test-scope and main-module filters.**
  go.sum and BuildInfo emissions are filtered against non-`_test.go`
  import closure and against the primary module's self-coord. Commit
  `b06eda8` (#10).
- **Feature 007 US4 — Main-Class executable-JAR self-reference
  suppression.** JARs whose `META-INF/MANIFEST.MF` names a `Main-Class`
  no longer re-emit their own primary coord as a generic-binary
  `pkg:generic/...` entry. Commit `89a334f` (#11).
- **Feature 006 US5 — SBOM enrichment (`mikebom sbom enrich`).**
  RFC 6902 JSON Patch applier with per-patch provenance recorded as
  `mikebom:enrichment-patch[N]` properties on the BOM metadata. Replaces
  a previously stubbed bail.
- **Feature 006 US4 — in-toto policy layouts (`mikebom policy init`
  and `mikebom sbom verify --layout`).** Single-step functionary-keyed
  layouts. Multi-step deferred.
- **Feature 006 US3 — real artifact subjects.** Attestation subjects
  are resolved via a 5-stage resolver (operator override → artifact-dir
  walk → suffix match → magic-byte detect for ELF / Mach-O / PE →
  synthetic fallback).
- **Feature 006 US2 — DSSE signing + verification** via `sigstore-rs`
  0.10 (pinned below 0.13 to stay off `aws-lc-rs` per Constitution
  Principle I). `mikebom sbom verify` replaces the never-shipped `sbom
  validate` stub; exit contract: 0 pass / 1 crypto / 2 envelope /
  3 layout.
- **Feature 006 foundation — DSSE verify MVP + witness-v0.1 emission.**
  `mikebom trace run` emits in-toto statements compatible with
  `go-witness` / `sbomit generate`.
- **ClearlyDefined license enrichment.** Post-scan enricher querying
  `api.clearlydefined.io` for `npm`, `cargo`, `gem`, `pypi`, `maven`,
  `golang` components. CD's `licensed.declared` becomes an
  `acknowledgement: "concluded"` license entry. `--offline` disables.
- **Per-ecosystem manifest hashes.** Maven sidecar hashes
  (`.jar.sha512` > `.sha256` > `.sha1`) and PyPI `requirements.txt
  --hash=alg:hex` flags now thread through to `components[].hashes[]`.
- **`metadata.component` carries synthetic `purl` + `cpe`** for sbomqs
  schema validity (`pkg:generic/<name>@<version>` +
  `cpe:2.3:a:mikebom:<name>:<version>:...`).
- **`--include-legacy-rpmdb` flag** (feature 004 US4) enables reading
  legacy Berkeley-DB `/var/lib/rpm/Packages` on pre-RHEL-8 /
  CentOS-7 / Amazon-Linux-2 rootfs. Off by default; also configurable
  via `MIKEBOM_INCLUDE_LEGACY_RPMDB=1`.

### Changed
- **`mikebom trace` reclassified as experimental.** Primary SBOM
  surface is now `mikebom sbom scan`. Trace-mode output format
  (witness-v0.1 + DSSE envelope) remains stable; the capture pipeline
  itself is opt-in, Linux-only (kernel ≥ 5.8), and adds 2–3× wall-clock
  overhead on syscall-heavy builds. Commit `45da74d`.
- **Artifact vs. manifest SBOM scope** is now explicit.
  `sbom scan --image` defaults to artifact scope (on-disk presence
  required). `sbom scan --path` defaults to manifest scope (declared
  deps included). `--include-declared-deps` is the explicit override.
  Gated in three Maven emission paths: deps.dev graph enricher,
  pom.xml direct-dep loop, and the `.m2` BFS cache-miss branch.
- **Dual-identity Maven coords.** JARs at `/usr/share/java/*` owned by
  an OS package-db reader (RPM / dpkg / apk) now emit both identities:
  the `pkg:rpm/...` NEVRA (for distro CVE feeds) and the
  `pkg:maven/<g>/<a>@<v>` GAV (for Maven Central advisories). The
  Maven coord is tagged `mikebom:co-owned-by = rpm` (or equivalent);
  `archive_sha256` is dropped since the archive bytes belong to the
  owning OS component. Pre-fix, the Maven coord was skipped entirely
  under a claim-based heuristic, which cost 53 polyglot GT matches.
- **CycloneDX 1.6 conformance pass.** `evidence.identity` is now an
  array (single-object form deprecated in 1.5→1.6);
  `evidence.identity[].tools` is no longer emitted (the previous
  payload wasn't `tools` by the spec's definition); `mikebom:
  source-connection-ids` + `mikebom:deps-dev-match` now land on the
  component as properties. License shape emits
  `{"license": {"id": "<SPDX-id>"}}` for simple IDs and
  `{"expression": "..."}` for compound expressions.
- **PURL canonicalization.** Qualifiers are now sorted
  lexicographically per purl-spec. `+` is percent-encoded across
  every ecosystem. RPM `epoch=0` is dropped (semantically equivalent
  to no epoch; `rpm -qa` omits it).
- **Compositions emit both `assemblies` and `dependencies`** for each
  `complete` ecosystem record, plus a dep-completeness composition so
  sbomqs's `comp_with_dependencies` credits the primary component.
- **Primary-dependency fallback.** When the scanned project's root
  entry was filtered out (npm `path_key == ""`, cargo `source = None`)
  mikebom now synthesizes edges from the primary metadata.component to
  every orphan root. Without this, sbomqs reported "no dependency
  graph present" even when transitives were populated.
- **OS-release reader** prefers `<rootfs>/etc/os-release`, falls back
  to `<rootfs>/usr/lib/os-release` — fixes Ubuntu images where
  `/etc/os-release` is a relative symlink that dangles after
  tar-extraction.
- **Binary-scanner version-string scanner gated on
  `skip_file_level_and_linkage`** to suppress claimed-binary
  self-identification (curl reporting libcurl from `/usr/bin/curl`).
  Trade-off: static-library version detection inside claimed binaries
  is lost; see `docs/design-notes.md`.

### Fixed
- **Pre-PR verification gate** (Constitution v1.2.1). CI runs
  `cargo +stable clippy --workspace --all-targets` and
  `cargo +stable test --workspace`; skipping either locally before
  opening a PR now yields a reject cycle. Commit `6ec1cf3` (#9).
- **Cross-source deduplication + scan-target filter.** Resolves
  duplicate emissions when the same coord surfaces via multiple
  readers (e.g. Maven JAR walker + `.m2` cache + deps.dev). Commit
  `5c98ed2` (#3).
- **Go `go.sum` vs. BuildInfo divergence.** `go.sum` emissions are
  filtered against the companion binary's BuildInfo so dev-only
  transitives don't surface as runtime components. Commit `5b38b98`
  (#7).
- **Go component name alignment** across the source-tree and binary
  emission paths. Commit `ffa7d9f` (#6).
- **Maven version-aware artifact-presence gate** (M6). Commit
  `b4a9041` (#5).
- **Fat-jar heuristic gated on `co_owned_by.is_none()`** to avoid
  double-reporting. Commit `cb7f14e` (#4).
- **ELF-note ghost emissions.** Previously unconditional — a claimed
  Fedora binary emitted both `pkg:rpm/fedora/<subpackage>` (from
  rpmdb) and a ghost `pkg:rpm/rpm/<source-package>` (from the ELF
  `.note.package` section). Now gated on
  `skip_file_level_and_linkage`; unclaimed binaries respect a
  precedence `note.distro > os-release ID > hardcoded default`.
  Commit `3e5ab91`.
- **Cargo workspace-root false positive.** Commit `3e5ab91`.
- **`declared-not-cached` components dropped from `components[]` by
  default.** They remain in the dependency graph as references but are
  no longer materialized as standalone components. Commit `7688ddb`.
- **sbom-conformance findings + CDX 1.6 evidence serialization.**
  Commit `3cd55e3`.

## [0.1.0-alpha.2] and earlier

Earlier alpha milestones landed as a bootstrap commit
(`b0f31c1 feat: bootstrap mikebom + milestones 001-005`) and ship the
foundational work below. CHANGELOG entries below are a roll-up, not a
per-release breakdown.

### Feature 005 — PURL & scope alignment
- Distro qualifier shape standardized as `distro=<ID>-<VERSION_ID>`
  (matches packageurl-python reference tests); codename-required
  claims dropped from docs + tests.
- npm internals scoping: image scans include
  `node_modules/npm/node_modules/**`; path scans exclude.
  Always-on; not user-gated.
- RPM version-string normalization for canonical round-trip.

### Feature 004 — RPM binary SBOMs
- Standalone `.rpm` file scanning (feature 004 US1/US2).
- Generic binary reader for ELF / Mach-O / PE: linkage
  (`DT_NEEDED`, `LC_LOAD_DYLIB`, PE `IMPORT`) plus embedded
  version-string scanning for a curated 7-library list
  (OpenSSL / BoringSSL / zlib / SQLite / curl / PCRE / PCRE2).
- Legacy Berkeley-DB rpmdb parsing gated behind
  `--include-legacy-rpmdb` (feature 004 US4). Default-off.

### Feature 003 — multi-ecosystem expansion
- Go source + binary readers (`go.mod`, `go.sum`, module cache,
  `runtime/debug.BuildInfo` inline format).
- RPM rpmdb.sqlite pure-Rust reader (page/record/schema).
- Maven pom.xml parser with `<properties>` + `<dependencyManagement>`
  + BOM import resolution (`EffectivePom`, cycle-guarded memo).
- Cargo v3/v4 lockfile parser; v1/v2 refused.
- Gem `Gemfile.lock` indent-6 parser; `specifications/*.gemspec`
  walker catches Ruby stdlib/default gems invisible to Gemfile.lock.

### Feature 002 — Python + npm
- Python venv `dist-info/METADATA` reader; `poetry.lock`,
  `Pipfile.lock`, `requirements.txt` support with dev/prod
  distinction.
- npm `package-lock.json` v2/v3 + `pnpm-lock.yaml` + `node_modules/`
  tree walker. v1 lockfiles refused.

### Feature 001 — build-trace pipeline (experimental)
- eBPF capture of syscall + network events during a build. Requires
  CAP_BPF + CAP_PERFMON and Linux kernel ≥ 5.8. Produces in-toto
  attestations bound to the build event.

---

[Unreleased]: https://github.com/mlieberman85/mikebom/compare/v0.1.0-alpha.3...HEAD
[0.1.0-alpha.3]: https://github.com/mlieberman85/mikebom/releases/tag/v0.1.0-alpha.3
