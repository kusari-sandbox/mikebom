# Feature Specification: Multi-Ecosystem Expansion — Go, RPM, Maven, Cargo, Gem

**Feature Branch**: `003-multi-ecosystem-expansion`
**Created**: 2026-04-17
**Status**: Draft
**Input**: User description — expand mikebom scan coverage to five new ecosystems. Go is the highest-priority addition because it enables distroless/scratch-image SBOMs via `runtime/debug.BuildInfo` binary analysis (the lone capability that currently restricts distroless scanning to syft and trivy). RPM covers RHEL/Rocky/Fedora/Amazon Linux. Maven/Java, Cargo/Rust, and Gem/Ruby fill out the enterprise-backend stack and close several trivy/scalibr benchmark gaps in one pass.

## Clarifications

### Session 2026-04-17

- Q: Which Cargo.lock versions must v1 of the Cargo reader support? → A: v3 + v4 only; v1/v2 emit a diagnostic (mirrors npm v1 refusal pattern).
- Q: How should the scanner handle `/etc/os-release::ID` values not in the explicit RPM vendor map? → A: Explicit top-9 map (rhel→redhat, rocky→rocky, fedora→fedora, amzn→amazon, centos→centos, ol→oracle, almalinux→almalinux, opensuse-leap→opensuse, sles→suse); unmapped IDs use the raw `ID` string as the PURL vendor segment (verbatim fallback) so PURLs stay canonical and round-trippable.
- Q: What safety posture should the scanner apply to untrusted JAR / rpmdb / ELF inputs? → A: Defense-in-depth baseline — in-memory ZIP reads with zip-slip guards, read-only SQLite with per-query timeout + per-file size cap, bounded ELF parsing with explicit header-length validation. Future follow-up TODOs: (a) add fuzz testing per parser, (b) explore subprocess sandboxing (seccomp on Linux / sandbox-exec on macOS) as a hardening option once a baseline exists.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Scan a Go project and a Go binary (Priority: P1) 🎯 MVP

A platform engineer maintains a fleet of Go services deployed as distroless/scratch container images. Source scans of the Go repos must surface the full module graph, and image scans of the compiled binaries (including in scratch images where no package manager exists) must produce the same module graph by reading `runtime/debug.BuildInfo` embedded in the ELF/Mach-O binary. The engineer runs `mikebom sbom scan --path ./service/` for source-tree scans and `mikebom sbom scan --image ./service.tar` for compiled-image scans; both yield a CycloneDX SBOM listing every Go module with a valid `pkg:golang/...` PURL, per-module version, and a dependency graph.

**Why this priority**: Go binary analysis is the single biggest competitive gap. Distroless base images are standard in production; they strip every package manager but still embed `runtime/debug.BuildInfo`. Only syft and trivy currently surface modules from those images. Adding this capability takes mikebom from "produces empty SBOMs for distroless" to parity with the two leaders on what has become the canonical modern deployment target. Source-scan parity is the table stakes that makes binary analysis demonstrable.

**Independent Test**: Scan a known Go source tree (a fixture with a `go.mod` declaring ~20 modules + the corresponding `go.sum`) and a known Go binary (a fixture binary compiled with `go build -ldflags="-s"`); verify the SBOM lists every module in both cases, that module sets match, that every PURL round-trips through the reference packageurl implementation, and that an `aggregate: complete` composition record exists for the `golang` ecosystem.

**Acceptance Scenarios**:

1. **Given** a Go project directory with `go.mod` (declaring ≥5 modules) and `go.sum` (hashes for each), **When** the user runs `mikebom sbom scan --path <project>`, **Then** the SBOM contains one `pkg:golang/<module>@<version>` component per module in `go.sum`, every PURL matches the packageurl reference encoding, and the SBOM carries a dependency record for the main module listing its direct requires.
2. **Given** a compiled Go binary (ELF or Mach-O) with `runtime/debug.BuildInfo` intact, **When** the user runs `mikebom sbom scan --path <binary-path>` or `mikebom sbom scan --image <image-tarball>`, **Then** the SBOM contains one `pkg:golang/<module>@<version>` component per module recorded in BuildInfo.
3. **Given** a stripped Go binary where the BuildInfo magic has been removed, **When** the user scans it, **Then** the scan completes without error and the SBOM documents the attempted-but-failed extraction via a diagnostic property rather than silently omitting the module.
4. **Given** a scratch container image containing only a compiled Go binary (no package manager), **When** the user runs `mikebom sbom scan --image <image>`, **Then** the SBOM lists the Go modules from BuildInfo AND carries a composition record marking the container as `aggregate: complete` for the `golang` ecosystem.

---

### User Story 2 — Scan a RHEL / Rocky / Fedora / Amazon Linux image (Priority: P2)

A security engineer scans a RHEL UBI-based production container. Today, mikebom finds zero components because the deb/apk readers don't match. The engineer needs mikebom to read `/var/lib/rpm/rpmdb.sqlite`, emit a `pkg:rpm/...` component per installed package with the correct distro + epoch + arch qualifiers, and surface the `REQUIRES:` field as a dependency graph mirroring how dpkg `Depends:` already works.

**Why this priority**: RHEL UBI is the default base in regulated environments (financial services, defence, healthcare). Without RPM support, mikebom is not an option for those users. This is a compliance unlock, not a nice-to-have. Scalibr can't read rpmdb either, so closing this gap leapfrogs scalibr on another dimension while matching trivy/syft.

**Independent Test**: Scan a rootfs snapshot of a minimal RHEL UBI image (pre-extracted or synthesised in-test) and verify that the component count matches what `rpm -qa` would report, that PURLs are canonical (`pkg:rpm/redhat/<name>@<epoch>:<version>-<release>?arch=<arch>`), that every component carries a license from the rpmdb's license column, and that a dependency graph exists.

**Acceptance Scenarios**:

1. **Given** a rootfs containing `/var/lib/rpm/rpmdb.sqlite` populated with ≥10 installed packages, **When** the user runs `mikebom sbom scan --path <rootfs>` or `mikebom sbom scan --image <image>`, **Then** the SBOM emits one `pkg:rpm/<vendor>/<name>@<epoch>:<version>-<release>?arch=<arch>` component per installed package.
2. **Given** the rootfs also contains `/etc/os-release` with `ID=rhel`, **When** the scan runs, **Then** the PURL vendor segment is `redhat` (per packageurl-python canonical form) and CPE synthesis attaches a candidate with `vendor=redhat`.
3. **Given** an installed package with a `REQUIRES:` field listing five other observed packages, **When** the scan runs, **Then** the resulting SBOM's `dependencies[]` section contains an edge from the parent to each observed requirement and drops dangling references silently.

---

### User Story 3 — Scan a Maven / Java project or JAR-bearing image (Priority: P3)

A Java platform team wants SBOMs for both their source repositories (declared dependencies in `pom.xml`) and their deployment artefacts (fat-jar images where the source tree no longer exists at runtime). The tool must parse `pom.xml` for declared coordinates, then, when scanning an image or any directory containing `*.jar` / `*.war` / `*.ear`, open each archive, read `META-INF/MANIFEST.MF`, and when present, the embedded `META-INF/maven/<group>/<artifact>/pom.properties` for authoritative coordinates.

**Why this priority**: Java is a major enterprise footprint. Adding pom.xml + JAR analysis makes mikebom usable for the JVM shop. Trivy resolves more transitive Maven deps than syft today because it reads the resolver output; mikebom must at least match declared-dep coverage and can optionally exceed it later via a deps.dev lookup that already knows Maven.

**Independent Test**: Scan a Maven project directory with a `pom.xml` declaring ≥3 direct dependencies, verify those appear as `pkg:maven/<groupId>/<artifactId>@<version>` components; separately scan a fat-jar containing several vendored dependencies and verify each `META-INF/maven/*/pom.properties`-sourced coordinate appears.

**Acceptance Scenarios**:

1. **Given** a project directory containing `pom.xml` with `<dependencies>` listing `com.google.guava:guava:32.1.3-jre`, `org.apache.commons:commons-lang3:3.14.0`, `junit:junit:4.13.2`, **When** the user scans it, **Then** the SBOM emits three `pkg:maven/<groupId>/<artifactId>@<version>` components.
2. **Given** a fat JAR containing three vendored libraries each with their own `META-INF/maven/<group>/<artifact>/pom.properties`, **When** the user scans the JAR, **Then** the SBOM emits one component per vendored library.
3. **Given** a `pom.xml` using Maven property substitution (`${project.version}`), **When** the scanner can't resolve the placeholder, **Then** it emits the component with the raw placeholder as the requirement range and tags it design-tier rather than inventing a version.

---

### User Story 4 — Scan a Rust / Cargo project (Priority: P4)

A Rust developer runs `mikebom sbom scan --path <workspace>` on a Cargo workspace. The scan reads `Cargo.lock`, emits one `pkg:cargo/<name>@<version>` component per locked crate including the SHA-256 checksum where `Cargo.lock` provides it, and marks the cargo ecosystem `aggregate: complete` because the lockfile is authoritative.

**Why this priority**: Rust is growing fast; Cargo.lock is one of the cleanest lockfile formats to parse. Scalibr can't read it at all today, so this extends mikebom's lead on Rust without much work. Lower priority than Go / RPM / Maven because the addressable user base is smaller and the urgency (distroless / enterprise compliance / JVM footprint) is less acute.

**Independent Test**: Scan a workspace fixture whose `Cargo.lock` declares ~10 `[[package]]` tables with mixed registry + git + path sources; verify all registry crates surface with canonical PURLs + SHA-256 from the `checksum` field, and that git/path sources are tagged via a `mikebom:source-type` property (reusing the mechanism introduced for npm in milestone 002).

**Acceptance Scenarios**:

1. **Given** a workspace with `Cargo.lock`, **When** the user scans the directory, **Then** every registry-sourced `[[package]]` in the lockfile surfaces as a `pkg:cargo/<name>@<version>` component.
2. **Given** a `Cargo.lock` entry carrying a `checksum = "<hex-sha256>"` field, **When** the scan runs, **Then** the resulting component's `hashes[]` array contains a SHA-256 entry matching the checksum.
3. **Given** a `Cargo.lock` entry with `source = "git+https://..."`, **When** the scan runs, **Then** the component carries `mikebom:source-type = "git"` and no false checksum (the git sources don't have them in Cargo.lock).

---

### User Story 5 — Scan a Ruby / Bundler project (Priority: P5)

A Ruby developer or DevOps engineer scans a Ruby project or a Ruby-tooling image (Chef, Puppet, Vagrant workstations). The tool reads `Gemfile.lock` and emits one `pkg:gem/<name>@<version>` component per locked gem, with the ecosystem marked `aggregate: complete`.

**Why this priority**: Ruby is widely used for DevOps tooling (Chef, Puppet, Vagrant) and still common in web apps. Gemfile.lock is straightforward. Scalibr can't read it. Priority is lowest because the active user base is flat/declining and the other four ecosystems unlock more users.

**Independent Test**: Scan a fixture with a realistic `Gemfile.lock` (~15 gems including transitive dependencies); verify every gem surfaces with a canonical `pkg:gem/<name>@<version>` PURL and that the GEM / PATH / GIT / BUNDLED sections are all distinguishable via the `mikebom:source-type` property where non-GEM.

**Acceptance Scenarios**:

1. **Given** a directory with `Gemfile.lock` listing gems from `GEM`, `GIT`, and `PATH` sections, **When** the user runs `mikebom sbom scan --path <dir>`, **Then** the SBOM emits every gem as `pkg:gem/<name>@<version>` and tags non-GEM entries with the appropriate `mikebom:source-type` property.
2. **Given** a `Gemfile.lock` containing a `DEPENDENCIES` block declaring direct deps, **When** the scan runs, **Then** the SBOM includes a `dependencies[]` record for the root project listing those direct gems.

### Edge Cases

- **Stripped Go binary** (no BuildInfo magic): scan completes; emits a `mikebom:buildinfo-status = "missing"` property on the binary's file component so operators can distinguish "no modules found" from "scan failed".
- **Go binary with partial BuildInfo** (older Go versions <1.18 or explicitly disabled build info): same handling — surface the problem, don't fake data.
- **RPM epoch = 0** (the default when no epoch is declared): canonical PURL omits the `epoch:` prefix (packageurl-python behaviour). Epoch ≠ 0 is kept literal in the version segment.
- **rpmdb.sqlite locked by another process** (rare in scan mode, common on a running host): scan degrades gracefully, logs a warning, and emits zero RPM components rather than erroring out.
- **Legacy Berkeley-DB rpmdb** (RHEL 7, CentOS 7 pre-EOL, very old images): out of scope for this milestone; we only handle the sqlite-backed rpmdb used by RHEL 8+. A diagnostic is emitted when `Packages` (BDB) is present but `rpmdb.sqlite` is not.
- **Fat JAR with duplicate `pom.properties`** (two vendored libs with the same GAV coordinates): emit once, dedup by PURL.
- **Maven `<version>` using a property reference that isn't in the visible `pom.xml`** (inherited from a parent POM not present in the scan root): emit the component with an empty version + the raw property text in `mikebom:requirement-range`; mark design-tier.
- **Cargo workspace with per-member `Cargo.toml` but one root `Cargo.lock`**: treat the workspace root as one project — `Cargo.lock` is authoritative for the whole workspace.
- **Cargo.lock v1 or v2** (pre-2020 Rust ≤1.38 or 1.39–1.52 respectively): diagnostic logged, zero components emitted for that root; user regenerates via `cargo generate-lockfile`. v3 and v4 are both supported because they're the only formats Rust has defaulted to in the past five years.
- **Gemfile.lock with a `BUNDLED WITH` older than 2.0**: parse what we can; emit warnings for entries that don't fit the modern shape.
- **A project with BOTH a `go.mod` and a committed binary**: scan emits both sources' modules; dedup by PURL keeps the higher-confidence source (source tree tier = `source`; binary analysis tier = `analyzed`). Source wins when present.

## Requirements *(mandatory)*

### Functional Requirements

#### Common to every ecosystem in this milestone

- **FR-001**: The scanner MUST discover project roots for each new ecosystem via the same bounded recursive walk introduced in milestone 002 (`candidate_project_roots` / `candidate_python_project_roots` pattern), so Go / Maven / Cargo / Gem projects are found anywhere in the scanned root — monorepos, service directories, and image layouts.
- **FR-002**: Every PURL produced MUST match the canonical encoding of the packageurl reference implementation (`packageurl-python`). A round-trip conformance test is mandatory per ecosystem.
- **FR-003**: Every new ecosystem MUST populate `ResolvedComponent.sbom_tier` per the R13 ladder introduced in milestone 002 — `source` for lockfile-authoritative entries, `deployed` for installed-tree or rpmdb entries, `analyzed` for file- or binary-analysis hits, `design` for manifest-only ranges.
- **FR-004**: When the scan reads an ecosystem's authoritative state (lockfile OR installed-package db OR binary-analysis view of a whole image), the ecosystem MUST appear in `compositions[]` with `aggregate: complete`.
- **FR-005**: Each ecosystem's per-component dep graph (where available) MUST emit `Relationship` edges via the same `(ecosystem, normalized_name) → PURL` lookup used by deb / apk / pypi / npm in milestones 001–002. Unresolved names drop silently.
- **FR-006**: Every new ecosystem MUST be a no-op when invoked against a filesystem root that contains none of its markers. An empty scan is never an error.
- **FR-007**: Every new ecosystem reader MUST respect the existing global `--offline` flag. No ecosystem requires network access to emit a valid SBOM.
- **FR-008**: Every new ecosystem reader MUST also respect the existing global `--include-dev` flag where the ecosystem distinguishes dev dependencies. Ecosystems that don't distinguish (Go modules, RPM) ignore the flag.
- **FR-009**: Every new reader that opens binary or archive input MUST apply the defense-in-depth baseline for untrusted content:
    - **ZIP archives** (JAR / WAR / EAR): read entries in memory only; never write to disk during inspection; reject any entry whose path contains `..` components or resolves outside the archive (zip-slip guard); cap per-entry size read.
    - **SQLite databases** (rpmdb.sqlite): open read-only; set a per-query timeout (recommended ≤2 s); enforce a per-file size cap above which the reader logs a warning and emits zero components rather than locking up.
    - **ELF / Mach-O binaries** (Go BuildInfo): bound reads by an explicit size cap; validate section-header lengths before dereferencing; fail closed on any structural anomaly.
    - Hardening beyond this baseline (fuzz testing per parser, subprocess sandboxing via seccomp on Linux / sandbox-exec on macOS) is tracked as a post-milestone follow-up, not a milestone-003 requirement.

#### Go (US1)

- **FR-010**: The Go reader MUST parse `go.mod` + `go.sum` at every discovered project root. Modules listed in `go.sum` that also appear in `go.mod` become `source`-tier components; modules only in `go.sum` (indirect transitive closure) become `source`-tier as well — `go.sum` is authoritative.
- **FR-011**: The Go reader MUST extract `runtime/debug.BuildInfo` from every ELF or Mach-O file encountered during a scan that matches the Go binary signature. Each module reported by BuildInfo becomes an `analyzed`-tier component.
- **FR-012**: Go binary analysis MUST work against scratch / distroless images (no package manager, no filesystem metadata beyond the binary itself).
- **FR-013**: The Go PURL MUST follow the canonical form `pkg:golang/<module-path>@<version>` where `<module-path>` may contain slashes (`github.com/spf13/cobra` → `pkg:golang/github.com/spf13/cobra@v1.7.0`).
- **FR-014**: When Go source and Go binary analyses observe the same module, the scanner MUST emit a single component deduplicated by PURL; the higher-confidence tier (source > analyzed) wins in `sbom_tier`, with both source paths merged into evidence.
- **FR-015**: When BuildInfo extraction fails for a file that looks like a Go binary (e.g. stripped binary), the scanner MUST emit a diagnostic via a property (e.g. `mikebom:buildinfo-status`) on the binary's file-level component, not silently omit it.

#### RPM (US2)

- **FR-020**: The RPM reader MUST parse `/var/lib/rpm/rpmdb.sqlite` when present. RHEL 7 Berkeley-DB rpmdb (`/var/lib/rpm/Packages`) is explicitly out of scope for this milestone; presence-but-missing-sqlite emits a single diagnostic log entry, not a per-package error.
- **FR-021**: The RPM PURL MUST follow the canonical form `pkg:rpm/<vendor>/<name>@<epoch>:<version>-<release>?arch=<arch>` where `<vendor>` derives from `/etc/os-release::ID` via an explicit map: `rhel→redhat`, `rocky→rocky`, `fedora→fedora`, `amzn→amazon`, `centos→centos`, `ol→oracle`, `almalinux→almalinux`, `opensuse-leap→opensuse`, `sles→suse`. When the scanned rootfs presents an `ID` not in the map, the scanner MUST use the raw `ID` string verbatim as the vendor segment so the resulting PURL remains canonical and round-trippable through the packageurl reference implementation. Epoch `0` is omitted per packageurl-python canonical form.
- **FR-022**: The RPM reader MUST populate `PackageDbEntry.depends` from the `REQUIRES` field of the rpmdb, tokenised to bare package names (drop version constraints). The scan_fs pipeline's existing edge emitter then produces `Relationship` edges for every requirement that resolves to an observed RPM component.
- **FR-023**: The RPM reader MUST populate `PackageDbEntry.licenses` from the rpmdb's license column, validated through the existing SPDX expression canonicaliser.
- **FR-024**: The RPM reader MUST populate `PackageDbEntry.maintainer` from the rpmdb's `PACKAGER` field so `component.supplier.name` is non-empty for RPM components (parity with the deb maintainer flow).
- **FR-025**: The RPM reader MUST mark the `rpm` ecosystem in `complete_ecosystems` when rpmdb.sqlite was read in full.

#### Maven / Java (US3)

- **FR-030**: The Maven reader MUST parse `pom.xml` at every discovered project root. Direct `<dependencies>` become components with `source` tier when version is resolved literally, `design` tier when version resolves only to an unsubstituted property placeholder.
- **FR-031**: The Maven reader MUST walk `*.jar`, `*.war`, `*.ear` files in the scan root (and inside extracted image rootfs) and, for each, extract `META-INF/MANIFEST.MF` and, when present, `META-INF/maven/<groupId>/<artifactId>/pom.properties`. The latter is authoritative for coordinates when both are present.
- **FR-032**: The Maven PURL MUST follow the canonical form `pkg:maven/<groupId>/<artifactId>@<version>`. The groupId goes in the namespace segment; slashes inside the groupId are retained (not encoded).
- **FR-033**: The Maven reader MUST, when available from pom.xml + deps.dev (online mode), emit the direct declared dependencies as `dependencies[]` edges. Transitive resolution via deps.dev enrichment is a stretch goal — the minimum bar is declared-dep coverage.

#### Cargo / Rust (US4)

- **FR-040**: The Cargo reader MUST parse `Cargo.lock` v3 and v4 at every discovered project root (workspace root only — not per-member Cargo.toml files). Every `[[package]]` entry becomes a `source`-tier component. v1 and v2 lockfiles emit an actionable diagnostic and produce zero components for that project root (mirroring the npm v1 refusal pattern from milestone 002); the user's fix is deterministic — regenerate via `cargo generate-lockfile` on Rust ≥1.53.
- **FR-041**: The Cargo PURL MUST follow the canonical form `pkg:cargo/<name>@<version>`.
- **FR-042**: When a `[[package]]` entry has a `checksum = "<hex-sha256>"` field, the reader MUST attach a SHA-256 `ContentHash` to the component. Git- and path-sourced packages carry no checksum and emit no hash.
- **FR-043**: The Cargo reader MUST tag git / path / registry sources via the `mikebom:source-type` property reusing the mechanism introduced for npm in milestone 002.
- **FR-044**: The Cargo reader MUST mark the `cargo` ecosystem `aggregate: complete` when `Cargo.lock` was parsed in full.

#### Gem / Ruby (US5)

- **FR-050**: The Gemfile.lock reader MUST parse the `GEM`, `GIT`, `PATH`, and `BUNDLED WITH` sections. Every listed gem becomes a `source`-tier component.
- **FR-051**: The Gem PURL MUST follow the canonical form `pkg:gem/<name>@<version>`.
- **FR-052**: The Gem reader MUST tag git / path sources via `mikebom:source-type` property.
- **FR-053**: The `DEPENDENCIES` section of `Gemfile.lock` MUST produce direct-dep edges from the project root to the listed gems. Per-gem transitive trees are NOT emitted (Gemfile.lock doesn't carry them in the `GEM` block).
- **FR-054**: The Gem reader MUST mark the `gem` ecosystem `aggregate: complete` when `Gemfile.lock` was parsed in full.

### Key Entities

- **GoModule**: A Go module observed in `go.mod` / `go.sum` or via BuildInfo. Attributes: module path (namespace + name), version (semver or pseudo-version like `v0.0.0-20230101000000-abcdef`), hash (from go.sum or BuildInfo), tier (`source` / `analyzed`).
- **GoBinary**: A file on disk identified as a Go binary. Attributes: format (ELF / Mach-O), main module path, go compiler version, build flags, and the list of embedded modules.
- **RpmPackage**: A row from `/var/lib/rpm/rpmdb.sqlite`. Attributes: name, epoch, version, release, arch, license, packager, requires (list), vendor (derived from os-release).
- **MavenCoordinate**: A (groupId, artifactId, version) tuple discovered from `pom.xml`, `MANIFEST.MF`, or `pom.properties`. Attributes: source (`pom.xml` / `jar-manifest` / `jar-pom-properties`), declared-vs-resolved version.
- **CargoPackage**: A `[[package]]` entry in `Cargo.lock`. Attributes: name, version, source (registry / git / path), checksum (sha256), dependencies.
- **Gem**: A gem entry from `Gemfile.lock`. Attributes: name, version, source section (GEM / GIT / PATH), dependencies (from the `DEPENDENCIES` list).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For every Go source project scanned, the count of `pkg:golang/...` components MUST match the count of `Module`-kind entries in that project's `go.sum` (minus at most one for pathological edge cases such as `replace` directives pointing at a local filesystem path). Verified on fixtures across at least three scales: ≥5, ≥20, ≥100 modules.
- **SC-002**: `mikebom sbom scan --image <distroless-go-binary>.tar` produces ≥90% of the modules embedded in the binary's BuildInfo, demonstrating parity with syft / trivy on the scratch-image use case.
- **SC-003**: `mikebom sbom scan` on a RHEL UBI minimal image returns a component count within 2% of what `rpm -qa | wc -l` reports, with every component carrying a license from the rpmdb.
- **SC-004**: For every ecosystem added, 100% of emitted PURLs round-trip through `packageurl-python` (reference-implementation conformance) as verified by an integration test per ecosystem.
- **SC-005**: For every ecosystem that distinguishes dev deps, `--include-dev` off excludes dev entries; `--include-dev` on includes them with `mikebom:dev-dependency = true`.
- **SC-006**: Every new ecosystem's authoritative source (go.sum, rpmdb.sqlite, pom.xml, Cargo.lock, Gemfile.lock) emits one `aggregate: complete` composition record that correctly references its PURLs.
- **SC-007**: A single `mikebom sbom scan` invocation on a polyglot repo containing Go + Rust + Ruby projects (no image, no container) produces one SBOM with components from all three ecosystems in the correct proportions.
- **SC-008**: A single `mikebom sbom scan --image` invocation on a RHEL-based image with an installed Go binary produces both `pkg:rpm/...` components (from rpmdb) AND `pkg:golang/...` components (from BuildInfo) in the same SBOM.
- **SC-009**: For a Go binary with stripped BuildInfo, the scan succeeds, emits the binary's file-level component with `mikebom:buildinfo-status = "missing"`, and completes in <2 s for a binary up to 200 MB.
- **SC-010**: On a modern dev laptop, scanning a directory with one project from each of the five new ecosystems completes in <10 s (matches the milestone-002 benchmark).

## Assumptions

- **Authoritative source priority**: For every ecosystem, the lockfile / installed-package db is the ground truth. Design-tier fallbacks apply when only a manifest is present.
- **Berkeley-DB rpmdb out of scope**: `/var/lib/rpm/Packages` (classic BDB format used by RHEL 7 pre-EOL) is not supported in this milestone. Scans of such rootfs emit a diagnostic; BDB support is a future spec.
- **Go pseudo-versions are valid versions**: Entries like `v0.0.0-20230101000000-abcdef` are accepted as-is and produce canonical PURLs (they round-trip cleanly through packageurl-python).
- **Go binary analysis is best-effort against stripping**: Binaries stripped beyond BuildInfo recovery are documented, not fixed. This is an upstream Go toolchain limitation.
- **Maven transitive resolution via deps.dev is stretch, not core**: The core bar is declared-dep coverage via `pom.xml` + JAR-embedded `pom.properties`. The deps.dev enrichment path already exists for Maven and will be reused opportunistically; hitting trivy's transitive depth is not a milestone-003 success criterion.
- **Ruby gem transitive trees are not emitted per-gem**: `Gemfile.lock` doesn't carry a per-gem dependencies graph in the standard sections — only the top-level `DEPENDENCIES` list. The output reflects what the lockfile declares, not more.
- **Cargo workspaces are single projects from the scanner's POV**: The workspace root's `Cargo.lock` is authoritative for every member. Per-member `Cargo.toml` files are not separately parsed.
- **Minimal new third-party Rust crates**: `rusqlite` for rpmdb, `zip` for JAR inspection, `toml` (already present) for Cargo.lock, a small new parser for Gemfile.lock. Go binary analysis likely needs one crate (`gosym`-style) or in-house parsing of the `go:buildinfo` magic string (~200 LOC).
- **Compositions/tier ladder reuses milestone 002 types**: No new schema in `mikebom-common`; existing `PackageDbEntry` and `ResolvedComponent` fields are sufficient. Any new field is additive and backward-compatible.
- **`sbom scan` subcommand is the only entry point**: Mode-1 eBPF trace capture is unchanged by this milestone; Go binary analysis is invoked exclusively from the scan pipeline.

## Dependencies

- Milestone 002 (Python + npm) infrastructure: `candidate_project_roots` walker pattern, `(ecosystem, normalized_name)` dep-tree lookup, `sbom_tier` ladder, `complete_ecosystems` aggregation, `mikebom:source-type` / `mikebom:requirement-range` / `mikebom:dev-dependency` properties — all reused as-is.
- `packageurl-python` reference implementation — required at test time (already used in milestone 002 for PURL conformance probes).
- `/etc/os-release` reader — already present from milestone 001; extended to emit `ID=rhel` / `ID=fedora` / `ID=rocky` / `ID=amzn` signals for the RPM PURL vendor selection.

## Out of Scope

- **Berkeley-DB rpmdb**: pre-RHEL-8 images use BDB; diagnose and move on. Future spec.
- **Maven transitive resolution against Maven Central**: trivy does this; we explicitly do not. deps.dev enrichment fills in what it can opportunistically. Adding a full Maven resolver is a separate effort.
- **Go `vendor/` directory walking**: the reader trusts `go.sum`; it does not separately walk `vendor/`. Future spec.
- **Go CGo linker evidence**: modules linked via CGo don't appear in BuildInfo; out of scope.
- **Rust binary analysis**: Cargo binaries don't embed a module graph the way Go binaries do. Rust source scans only in this milestone.
- **pnpm workspaces / Rush / Lerna**: npm workspaces already handled via the per-root walk introduced in milestone 002; this milestone does not extend it further.
- **JavaScript / TypeScript in a Maven or Cargo project**: each ecosystem reader is independent; cross-ecosystem shims are out of scope.
- **Registry-pull for images (TODO-3)** and **running-container scan (TODO-4)**: still future work; unchanged by this milestone.
- **Fuzz-testing harness for new parsers** (JAR / rpmdb / ELF): FR-009 locks in the defense-in-depth baseline but does not require a continuous fuzz corpus. Post-milestone TODO: add per-parser fuzz targets under `cargo fuzz` or similar, seeded with real-world failing inputs.
- **Subprocess-sandbox execution mode** (seccomp on Linux, sandbox-exec on macOS, job objects on Windows): explored as a future hardening path once the baseline parsers ship and we have a concrete threat model. Would likely gate behind an opt-in `--sandbox` flag. Out of scope for milestone 003.
