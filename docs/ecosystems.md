# Ecosystems

Per-ecosystem coverage for all nine ecosystems mikebom supports. Use this
page to answer *"does mikebom see my packages the way I expect"* before
diving into the [architecture docs](architecture/overview.md).

## Coverage matrix

| Ecosystem | Detection source | Dep-graph source | Hash source | Enrichment (deps.dev / CD) | Status |
|---|---|---|---|---|---|
| [apk](#apk) | `/lib/apk/db/installed` | DB (direct `D:` only) | — | — / — | Implemented |
| [cargo](#cargo) | `Cargo.lock` v3/v4 | Lockfile (full tree) | Lockfile `checksum` | ✓ / ✓ | Implemented |
| [deb](#deb) | `/var/lib/dpkg/status` + `.list` files | DB (`Depends:`) | Per-file SHA-256 (deep hash) or `.md5sums` fallback | — / Planned | Implemented |
| [gem](#gem) | `Gemfile.lock` + `specifications/*.gemspec` | Lockfile indent-6 | — | — / ✓ | Implemented |
| [golang](#golang) | `go.mod` / `go.sum` + module cache; `runtime/debug.BuildInfo` for binaries | Cache walker (source); **none** (binaries) | `go.sum` H1 (Merkle trie, not CDX) | ✓ / ✓ | Implemented |
| [maven](#maven) | Project `pom.xml` + JAR `META-INF/maven` + `~/.m2` + deps.dev fallback | Layered: local → JAR → `~/.m2` BFS → parent POM chain → deps.dev | JAR sidecar `.sha512` > `.sha256` > `.sha1` | ✓ / ✓ | Implemented |
| [npm](#npm) | `package-lock.json` v2/v3, `pnpm-lock.yaml`, `node_modules/` | Lockfile (full tree) | Lockfile `integrity` | ✓ / ✓ | Implemented |
| [pip](#pip) | venv `dist-info/METADATA` + Poetry/Pipfile + `requirements.txt` | Lockfile (Poetry/Pipfile), flat (venv) | `--hash=alg:hex` flags | ✓ / ✓ | Implemented |
| [rpm](#rpm) | `/var/lib/rpm/rpmdb.sqlite` (pure-Rust reader) | DB (`REQUIRES`) | — (rpmdb has none) | — / — | Implemented (BDB format detected, not parsed) |

"Enrichment" columns mark whether deps.dev version info and ClearlyDefined
concluded licenses apply to the ecosystem. Both honour the global
`--offline` flag.

---

## apk

**Module:** `mikebom-cli/src/scan_fs/package_db/apk.rs`

**Detection:** stanza parser over `/lib/apk/db/installed`. Reads `P:`
(name), `V:` (version), `A:` (arch), `D:` (direct dependencies).

**PURL format:** `pkg:apk/alpine/<name>@<version>?arch=<arch>&distro=alpine-<VERSION_ID>`
(e.g., `distro=alpine-3.19`). Same `<namespace>-<VERSION_ID>` shape as
deb and rpm.

**Evidence:** `PackageDatabase` / `manifest-analysis` at confidence 0.85.

**Dep graph:** direct dependencies only. apk's installed DB doesn't encode
transitive graph — it records only what each package declares.

**Hashes:** none. apk's installed DB doesn't carry per-package content
hashes mikebom can use.

**Enrichment:**
- deps.dev: skipped (not in deps.dev's supported ecosystems).
- ClearlyDefined: skipped (not curated).

**Known limitations:**
- apk's DB doesn't carry copyright pointers like dpkg does, so apk
  components ship with empty `licenses[]`.

---

## cargo

**Module:** `mikebom-cli/src/scan_fs/package_db/cargo.rs`

**Detection:** `Cargo.lock` v3 and v4 parser. v1/v2 are refused (they
pre-date the reproducible-lockfile guarantee).

**PURL format:** `pkg:cargo/<name>@<version>`. No namespace (crates.io is
flat).

**Evidence:** `PackageDatabase` for lockfile entries; `FilePathPattern`
for `.crate` files in `~/.cargo/registry/cache`.

**Dep graph:** full tree. Cargo.lock's `[[package]].dependencies` array
encodes every edge.

**Hashes:** `Cargo.lock` `[[package]].checksum` (SHA-256) flows through to
CycloneDX `components[].hashes[]`.

**Enrichment:**
- deps.dev: fetches declared licenses and VCS URLs. Without deps.dev,
  cargo license coverage drops to zero (crates.io doesn't publish licenses
  into `Cargo.lock`, only into `Cargo.toml`).
- ClearlyDefined: concluded licenses from CD's cratesio provider.

**Source-type markers:**
- `workspace` — workspace-local crates (no `source`).
- `git`, `path`, `url` — non-registry sources.
- `(none)` — normal registry crates.

---

## deb

**Module:** `mikebom-cli/src/scan_fs/package_db/dpkg.rs`, with DEP-5
copyright parsing in `scan_fs/package_db/copyright.rs` and per-file deep
hashing in `scan_fs/package_db/file_hashes.rs`.

**Detection:** stanza parser over `/var/lib/dpkg/status`, plus per-package
`/var/lib/dpkg/info/<pkg>.list` manifests for deep-hash occurrences.

**PURL format:** `pkg:deb/debian/<name>@<version>?arch=<arch>&distro=<namespace>-<ver>`
(e.g., `distro=debian-12`, `distro=ubuntu-24.04`, `distro=kali-rolling`).

Canonicalization (strict — reference-implementation-conformant):

- `+` in name and version → `%2B`.
- `:` in version (epoch separator) → literal, inside `@<version>`, not as
  a qualifier.
- `~` in version → literal.
- `distro=<namespace>-<VERSION_ID>` is the canonical form across deb, rpm,
  and apk — one shape so downstream consumers don't need per-ecosystem
  branching. Namespace is the debian/ubuntu/kali/etc. slug; `VERSION_ID`
  is the numeric or codename value from `/etc/os-release`.
- Auto-detected from `<rootfs>/etc/os-release` (`ID` + `VERSION_ID`);
  overridable via `--deb-codename <value>` which stamps the full
  qualifier value verbatim.

See [purls-and-cpes.md](architecture/purls-and-cpes.md) for the full
rationale.

**Evidence:** `PackageDatabase` / `manifest-analysis` at confidence 0.85.

**Dep graph:** full tree from dpkg `Depends:` fields. `Provides:` and
virtual packages are not currently modeled (dangling edges to virtual
packages are dropped by the resolve-stage guard rail).

**Hashes:**
- **Deep hash mode (default):** every file listed in the package's
  `.list` manifest is stream-hashed (SHA-256). Results emit as
  `evidence.occurrences[]` with per-file SHA-256 + dpkg MD5 cross-reference
  in `additionalContext`.
- **`--no-deep-hash`:** SHA-256 of the dpkg `.md5sums` file itself as a
  per-package fingerprint. Microseconds per package; component-level
  identity only; no per-file occurrences.
- Component `hashes[]` is populated in both modes (deep hash yields a
  per-component Merkle root over the listed files; fast mode yields the
  `.md5sums` hash).

**Licenses:** DEP-5 `/usr/share/doc/<pkg>/copyright` parsing, plus
standalone `License:` stanzas, modern `SPDX-License-Identifier:` tag, and a
multi-line recogniser for canonical FSF license-grant prose (catches
`debian-archive-keyring`, `libcrypt1`, `libsemanage2`, `libgcc-s1`, GCC
base libs that ship license grants verbatim).

**Enrichment:**
- deps.dev: skipped (not in deps.dev's supported ecosystems).
- ClearlyDefined: **Planned (next priority).** CD's `deb` type curates
  licenses from Debian's upstream copyright-file server and would fill the
  gap for images that strip `/usr/share/doc/<pkg>/copyright`. See
  [design-notes deferred item 18](design-notes.md#deferred-sbomqs-score-lift).

---

## gem

**Module:** `mikebom-cli/src/scan_fs/package_db/gem.rs`

**Detection:** `Gemfile.lock` indent-structure parser + walker over
`specifications/*.gemspec` files. The gemspec walker catches Ruby stdlib
and default gems that are invisible to `Gemfile.lock`.

**PURL format:** `pkg:gem/<name>@<version>`.

**Evidence:** `PackageDatabase` / `manifest-analysis` for lockfile entries;
gemspec-sourced entries also use `PackageDatabase`.

**Dep graph:** full tree. `Gemfile.lock`'s indent-6 lines encode per-gem
edges; gemspecs themselves carry no dep edges.

**Hashes:** none currently. Bundler 2.5+ emits `CHECKSUMS` sections in
`Gemfile.lock`; the parser for them is tracked as deferred
work — see the sbomqs-score-lift items in
[`design-notes.md`](design-notes.md) (Deferred #17).

**Enrichment:**
- deps.dev: skipped (not in deps.dev's supported ecosystems).
- ClearlyDefined: fetches concluded licenses from CD's rubygems provider.

**Known limitations:**
- Only `--include-dev` gates gems under `test` scope in the declaration
  tree; bundler's full scope semantics (`:development`, `:production`,
  grouped) aren't modeled.
- Interpolated gemspec versions (`"#{FOO_VERSION}"`) produce garbage
  strings — downstream PURL construction rejects them. Theoretical edge
  case; in practice gemspec versions are always literal strings.

---

## golang

**Modules:** `mikebom-cli/src/scan_fs/package_db/golang.rs` (source scans),
`mikebom-cli/src/scan_fs/package_db/go_binary.rs` (binary scans).

### Source scans

**Detection:** `go.mod` + `go.sum` + walker over
`$GOMODCACHE/cache/download/<escaped-module-path>/@v/<version>.mod` files.
Module paths with capital letters escape as `!x` for the cache lookup
(e.g. `Microsoft/go-winio` → `!microsoft/go-winio`).

**PURL format:** `pkg:golang/<module-prefix>/<final-segment>@v<version>`.

**Dep graph:** full tree when the module cache is warm (the walker
traverses `@v/*.mod` files to discover transitive edges). When the cache
is cold, edges are populated for root → direct deps only.

**Hashes:** `go.sum` H1 hashes are Merkle-trie roots, not file SHA-256s,
so they don't fit CDX's hash-algorithm enum. Component-level `hashes[]` is
empty today; see
[design-notes sbomqs deferred item 17](design-notes.md#deferred-sbomqs-score-lift)
for the plan.

### Binary scans

**Detection:** `runtime/debug.BuildInfo` inline-format decoder. Works for
Go 1.18+ binaries. Pre-1.18 binaries are flagged with
`mikebom:buildinfo-status = unsupported` and emit a file-level component
only.

**PURL format:** same as source scans.

**Dep graph:** **none.** `runtime/debug.BuildInfo` encodes the module
list but not module-to-module relationships.

**Hashes:** the binary itself gets hashed (`ResolutionTechnique::FilePathPattern`
at 0.70 confidence with file-level evidence); individual modules don't.

**Known limitations:**
- Stripped binaries where BuildInfo extraction fails get
  `mikebom:buildinfo-status = missing` and emit only as a file-level
  component with hash-only PURL.
- Scratch / distroless images with a single Go binary produce a flat
  component list. That's the accurate answer — the binary doesn't know the
  graph.
- Private module proxies and `vendor/` directory extraction are out of
  scope today.

**Enrichment:**
- deps.dev: fetches licenses and VCS URLs using the full module path
  (`github.com/sirupsen/logrus`), not the short name.
- ClearlyDefined: concluded licenses via CD's `golang` / `github`
  provider.

---

## maven

**Module:** `mikebom-cli/src/scan_fs/package_db/maven.rs`

Maven is the most complex ecosystem. Transitive versions can live in
parent POMs' `<dependencyManagement>` or be supplied by BOM imports. See
[design-notes §Dep-graph resolution strategy (Maven)](design-notes.md#dep-graph-resolution-strategy-maven)
for the full six-layer strategy.

**Detection (layered):**
1. Scanned project's `pom.xml` (direct deps).
2. JAR-embedded `META-INF/maven/<g>/<a>/{pom.xml, pom.properties}`
   (identity + edges for deployed containers; fat/shaded JARs yield one
   `EmbeddedMavenMeta` per vendored artifact).
3. `~/.m2/repository/` cache walker (BFS over cached `.pom` files).
4. Parent-POM chain (`build_effective_pom`) with
   `<properties>` + `<dependencyManagement>` inheritance + BOM-import
   flattening.
5. deps.dev `:dependencies` endpoint (online fallback for shaded-transitive
   and cold-cache gaps).
6. Empty edges (graceful degradation).

**PURL format:** `pkg:maven/<groupId>/<artifactId>@<version>`. Reverse-DNS
groupId is part of the identity.

**Dep graph:** deps.dev is **authoritative for edge topology** but never
for versions — local `.m2` always wins on the version dimension. See the
[deps.dev policy](design-notes.md#depsdev-policy-critical).

**Hashes:** JAR sidecar `.sha512` > `.sha256` > `.sha1` (Maven Central
mostly ships SHA-1; sbomqs penalizes for `comp_with_strong_checksums`).
Direct-JAR SHA-256 computation when the cache has the JAR but no sidecar
is deferred.

**Enrichment:**
- deps.dev: license + VCS + `:dependencies` graph. Package name is
  `groupId:artifactId` (raw artifactId alone isn't unique).
- ClearlyDefined: concluded licenses via CD's `mavencentral` provider.

**Source-type markers:**
- `workspace` — scanned project's pom.xml.
- `analyzed` — JAR walker's `META-INF/maven` pom.properties.
- `transitive` — BFS-discovered via local cache / JAR walk.
- `declared-not-cached` — deps.dev says it's a declared dep but not
  present locally at any version.

**Shade-plugin fat-jars (feature 009):**
When a JAR contains `META-INF/DEPENDENCIES` (the Apache
`maven-dependency-plugin`'s declared-transitive manifest), mikebom
parses it into ancestor coords and emits one nested component per
ancestor under the enclosing JAR's primary coord, tagged
`mikebom:shade-relocation = true`. Emission is gated on
**bytecode-presence verification**: an ancestor is retained only when a
`.class` entry in the JAR matches either its original group path
(UNSHADED) or a shade-relocated path containing the ancestor's
distinctive artifact-id leaf (SHADED, generic leaves like `io`, `api`,
`util`, `core` excluded). The UNSHADED check is suppressed when
ancestor and primary share a reactor group namespace, since sibling
reactor artifacts cannot be distinguished from the primary's own
classes under the shared namespace. Full rules in
[`specs/009-maven-shade-deps/spec.md`](../specs/009-maven-shade-deps/spec.md)
FR-002b.

**Known limitations:**
- `<exclusions>` not parsed. If a project excludes a transitive via
  `<exclusions>`, mikebom still emits the excluded coord.
- Version ranges (`[1.0,2.0)`) not resolved.
- `<profiles>` ignored — profile-conditional deps never emit.
- Plugin-section deps (`<build><plugins>`) ignored — not runtime deps.
- POM-less JARs (older Gradle outputs, OSGi bundles) can't be inspected
  via `META-INF/maven/` — coord + deps invisible.

---

## npm

**Module:** `mikebom-cli/src/scan_fs/package_db/npm.rs`

**Detection:** `package-lock.json` v2/v3, `pnpm-lock.yaml`, or flat walk
of `node_modules/` as tertiary fallback. `package-lock.json` v1 is
**refused** — its format doesn't give enough info for reproducible
dependency graphs.

**PURL format:**
- Unscoped: `pkg:npm/<name>@<version>`.
- Scoped: `pkg:npm/<@scope>/<name>@<version>` (e.g. `pkg:npm/@angular/core@17.0.0`).

**Evidence:** `PackageDatabase` / `manifest-analysis` at 0.85.

**Dep graph:** full tree from `package-lock.json` `packages` entries.

**Hashes:** `package-lock.json` `integrity` field (SRI format). Supports
sha256, sha384, sha512; flows through to CycloneDX `components[].hashes[]`.

**Enrichment:**
- deps.dev: licenses + VCS. Package name is `@org/name` for scoped.
- ClearlyDefined: concluded licenses. Namespace for scoped packages
  strips the leading `@` (`@angular` → `angular`).

**npm internals filtering (scope-by-mode, always on):**
- In `--image` scans, components discovered inside npm's own bundled tree
  (`**/node_modules/npm/node_modules/**`) are marked
  `mikebom:npm-role = internal` and retained — the image contains
  npm's own install, so those bytes are legitimately present.
- In `--path` scans, internals are filtered out before resolution on
  the assumption that a path-mode scan targets the application's
  `node_modules/`, not a tool cache.
- This is not user-gated — there is no flag to toggle it. See
  feature 005 (`specs/005-purl-and-scope-alignment/`) for rationale.

---

## pip

**Module:** `mikebom-cli/src/scan_fs/package_db/pip.rs`

**Detection:** three parallel paths:
1. Installed venvs: walk `<venv>/lib/python*/site-packages/*.dist-info/METADATA`.
2. Lockfiles: Poetry `pyproject.toml` + `poetry.lock`, Pipfile +
   `Pipfile.lock`.
3. Flat declarations: `requirements.txt`. Captures `--hash=alg:hex` flags
   per requirement.

**PURL format:** `pkg:pypi/<name>@<version>`. Name is PEP 503–normalized
(lowercase, runs of non-alphanum collapsed to `-`).

**Evidence:** `PackageDatabase` / `manifest-analysis` at 0.85 for venv
`METADATA` and lockfiles; `FilePathPattern` at 0.70 for loose `.whl` files.

**Dep graph:**
- Poetry / Pipfile: full tree.
- Venv: flat (venv `Requires-Dist:` lines are captured but not
  transitively expanded; venv installs are "deployed" tier evidence).
- requirements.txt: flat.

**Hashes:** `requirements.txt --hash=alg:hex` flags become
`PackageDbEntry.hashes` → `components[].hashes[]`. Multiple hashes per
requirement are supported. Other sources (venv METADATA, Poetry, Pipfile)
don't carry per-component hashes yet.

**Enrichment:**
- deps.dev: licenses + VCS.
- ClearlyDefined: concluded licenses via CD's `pypi` provider.

---

## rpm

**Modules:** `mikebom-cli/src/scan_fs/package_db/rpm.rs`,
`mikebom-cli/src/scan_fs/package_db/rpmdb_sqlite/`

**Detection:** pure-Rust SQLite reader over
`/var/lib/rpm/rpmdb.sqlite`. No C dependency on librpm (per the project
constitution: no C deps in production).

**PURL format:** `pkg:rpm/<vendor>/<name>@<version>-<release>?arch=<arch>&distro=<vendor>-<ver>`.

Canonicalization:

- Vendor is the distro slug (`redhat`, `rocky`, `fedora`, `suse`,
  `opensuse`, `amzn`).
- `epoch=0` omitted (RPM treats absent and 0 equivalently; `rpm -qa`
  default display omits). See the
  [RPM canonicalization note in design-notes](design-notes.md#purl-canonicalization).

**Evidence:** `PackageDatabase` / `manifest-analysis` at 0.85, with
`mikebom:evidence-kind = rpmdb-sqlite`.

**Dep graph:** full tree from rpmdb `REQUIRES` tags.

**Hashes:** **none.** rpmdb doesn't record per-package content hashes
mikebom can use. This is why rpm scans score 6.1/10 on sbomqs (Integrity
0/10) — the ecosystem itself doesn't provide the data.

**Enrichment:**
- deps.dev: skipped (not in deps.dev's supported ecosystems).
- ClearlyDefined: skipped (CD's rpm coverage is thin).

**Known limitations:**
- **Berkeley DB rpmdb** (`/var/lib/rpm/Packages`, pre-RHEL 8) is
  **detected but not parsed.** Diagnostic logged, zero rpm components
  emitted. The `--include-legacy-rpmdb` flag (or
  `MIKEBOM_INCLUDE_LEGACY_RPMDB=1`) threads through to
  `rpmdb_bdb::read`, which is a stub pending the concrete Hash/BTree
  page parser (milestone 004 US4 tasks T061–T065). Until those land,
  flipping the flag changes nothing about scan output.
- **rpmdb.sqlite size cap** is 200 MB (defense-in-depth; real rpmdbs are
  ~5 MB).
- **Pure-Rust SQLite reader** handles leaf-table + interior-table pages
  only. Overflow pages are refused. RHEL rpmdbs don't use overflow pages
  in practice.

---

## Further reading

- [Scanning architecture](architecture/scanning.md) — how the scan layer
  dispatches to each of these modules.
- [PURLs and CPEs](architecture/purls-and-cpes.md) — the canonicalization
  rules and CPE candidate strategy.
- [Enrichment](architecture/enrichment.md) — deps.dev + ClearlyDefined
  wiring.
- [design-notes.md](design-notes.md) — dated changelog, sharp edges, the
  deferred backlog including per-ecosystem ClearlyDefined expansions and
  sbomqs score-lift items.
