# Feature Specification: Close Remaining Polyglot Bake-Off False Positives

**Feature Branch**: `007-polyglot-fp-cleanup`
**Created**: 2026-04-23
**Status**: Draft
**Input**: User description: "Close remaining polyglot bake-off FPs: sidecar POM reading for Fedora-shipped JARs, Go test-scope filter via BuildInfo, and Go project-self filter"

## Clarifications

### Session 2026-04-23

- Q: Which distributions should the sidecar-POM reader handle in this feature? → A: Fedora/RHEL only (`/usr/share/maven-poms/` + `JPP-*.pom` and plain `<name>.pom` filenames); Debian and Alpine deferred to a follow-up feature.
- Q: When both a compiled Go binary and Go source files are present on the same rootfs, which signal governs the Go test-scope filter? → A: Intersection — emit only if the module is in BuildInfo AND reachable from a non-`_test.go` import. When only one signal is available, fall back to that signal alone.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Identify Fedora-shipped JARs via sidecar POM files (Priority: P1)

When mikebom scans a container image or root filesystem built on a Fedora/RHEL base, it encounters Java Archive (JAR) files under `/usr/share/maven/lib/` and adjacent paths that do not contain Maven metadata inside the archive. Fedora's packaging policy strips `META-INF/maven/` during the RPM build and places the corresponding POM file at a predictable sidecar path under `/usr/share/maven-poms/` (or similar distribution-specific directory). Today, mikebom does not read the sidecar file, so these JARs appear in the output only as generic binary files — their Maven coordinates (groupId, artifactId, version) are never recovered. As a result, the final SBOM under-reports the Maven components actually present on the image, and ground-truth benchmarks show a systematic gap.

After this story lands, mikebom consults the sidecar POM directory whenever a JAR lacks embedded Maven metadata, matches the JAR to its sidecar POM by filename convention, extracts the coordinates, and emits a `pkg:maven/<g>/<a>@<v>` component that is properly related to the JAR file.

**Why this priority**: This is the largest single bucket of remaining false negatives on the polyglot-builder-image bake-off — 12 of the 23 open findings. Closing it moves mikebom from "parity with most tools" to "parity on Fedora/RHEL images," which is a distinctive and important differentiator. RPM-based distributions dominate enterprise and CI/CD infrastructure; missing their Maven components in SBOMs is a correctness gap with downstream vulnerability-matching consequences.

**Independent Test**: Construct a test fixture containing one JAR under `/usr/share/maven/lib/` that has no `META-INF/maven/` entries inside, and a matching sidecar POM at `/usr/share/maven-poms/<name>.pom` declaring its groupId, artifactId, and version. Scan the fixture and confirm that the output contains a Maven component with the coordinates from the sidecar POM, related to the JAR file. The feature can be validated in isolation without touching any other ecosystem reader.

**Acceptance Scenarios**:

1. **Given** a root filesystem containing a JAR at `/usr/share/maven/lib/guice-5.1.0.jar` without `META-INF/maven/` entries **and** a sidecar POM at `/usr/share/maven-poms/JPP-guice.pom` declaring the Maven coordinates, **When** mikebom scans the root filesystem, **Then** the output contains a single Maven component `pkg:maven/com.google.inject/guice@5.1.0` related to the JAR file, and the JAR is not emitted as an unidentified binary.
2. **Given** a JAR in a directory outside of the Fedora sidecar-POM search scope **and** a matching-filename POM that is unrelated to the JAR, **When** mikebom scans, **Then** the output does not falsely attribute the unrelated POM's coordinates to the JAR.
3. **Given** a JAR that has BOTH embedded `META-INF/maven/` metadata AND a sidecar POM, **When** mikebom scans, **Then** the embedded metadata is preferred (authoritative from the archive itself) and a single, de-duplicated Maven component is emitted.
4. **Given** multiple JARs in the same `/usr/share/maven/lib/` directory, each with distinct sidecar POMs, **When** mikebom scans, **Then** each JAR produces its own correctly-attributed Maven component with no cross-attribution errors.
5. **Given** a sidecar POM that declares a `<parent>` whose groupId or version must be inherited, **When** mikebom reads the sidecar, **Then** the emitted coordinates resolve the inheritance correctly, or fall back to generic-binary emission when the parent POM is not present on the root filesystem.

---

### User Story 2 - Suppress Go test-scope modules from source-tree emissions (Priority: P2)

When mikebom scans a Go project's source tree (go.mod + go.sum, optionally with a compiled binary present), its current source-tier emissions include every module listed in go.sum. This set is a superset of the modules actually linked into the production binary: it includes modules imported only by `_test.go` files (test-scope), plus indirect resolver artifacts. On the polyglot bake-off, this produces four false positives (`github.com/davecgh/go-spew`, `github.com/pmezard/go-difflib`, `github.com/stretchr/testify`, `gopkg.in/yaml.v3`) that appear in the mikebom output but are not in the ground truth because they are only referenced by test files in the fixture source, not by the shipped binary.

After this story lands, mikebom distinguishes "modules required at production runtime" from "modules required only by tests" and suppresses the test-scope modules from source-tier emissions when a Go source tree is scanned. The user has specified that mikebom must not depend on invoking the Go toolchain (`go list -deps -test=false`) at scan time, so the same goal must be achieved by reading static signals already available to mikebom: the set of modules linked into any compiled Go binary in the root filesystem (authoritative when present), and/or static analysis of `.go` source-file import graphs excluding `_test.go` files.

**Why this priority**: This closes four specific false positives on the bake-off and, more importantly, establishes the source-tree filtering pattern for any future Go scans where a compiled binary is or isn't present. It is secondary to Story 1 because the absolute FP count is smaller and because the G3 filter already merged on main handles the "binary-present" case for a broad subset of scenarios — this story closes the residual four that G3 alone does not.

**Independent Test**: Build a fixture with a Go source tree whose go.mod declares a production dependency and whose go.sum additionally declares a module referenced only from a `_test.go` file. Scan the fixture without any compiled binary present and confirm that the test-only module is not emitted. Repeat with a compiled binary present (using the existing BuildInfo path) and confirm identical output.

**Acceptance Scenarios**:

1. **Given** a Go source tree whose go.mod/go.sum declares a production dependency `A` and a test-only dependency `B` (where `B` is imported only from `_test.go` files), **When** mikebom scans, **Then** the output contains a Go component for `A` but does NOT contain a component for `B`.
2. **Given** a Go source tree with both go.sum test-scope entries AND a compiled binary whose BuildInfo happens to include a test-only module (e.g., the fixture's own test infrastructure compiled it in), **When** mikebom scans, **Then** the test-only module is NOT emitted because the intersection filter requires both a BuildInfo presence AND a non-`_test.go` production import, and the test-only import does not satisfy the second condition.
3. **Given** a Go source tree with go.mod + go.sum but no parseable `.go` source files and no compiled Go binary on the rootfs, **When** mikebom scans, **Then** the emitted component set is exactly the go.mod `require` directives (not the full go.sum transitive closure), each tagged with `sbom-tier=source-unverified`; go.sum-only transitives are suppressed.
4. **Given** a Go source tree where a module is imported from BOTH a production `.go` file AND a `_test.go` file, **When** mikebom scans, **Then** the module IS emitted (production use dominates; the test import is incidental).

---

### User Story 3 - Exclude the project's own module from its dependency list (Priority: P3)

When mikebom scans a Go source tree, the `module` directive in go.mod names the project itself. The current emission path treats this as just another module and emits it as a dependency component of the scan. On the polyglot bake-off, this surfaces as a spurious `polyglot-fixture@(devel)` entry in the mikebom output that the ground truth does not include because a project is not its own dependency.

After this story lands, mikebom recognizes the project's own module (by reading go.mod's `module` directive when a source tree is scanned, or by reading BuildInfo's `mod` line when a binary is scanned) and excludes that module from the dependency emissions. The project's own identity may still be represented elsewhere in the SBOM (for example, as the document's top-level subject or metadata component) where the distinction between "what is being described" and "what it depends on" is semantically appropriate.

**Why this priority**: This closes only one bake-off finding, and in some conventions this self-entry is benign, so it is the lowest priority of the three. It is included because closing it brings the final polyglot bake-off result down to the absolute floor of two findings (a single real version disagreement plus one case-specific artifact), which is a clean, communicable number.

**Independent Test**: Scan a Go project whose go.mod declares `module example.com/myproject` (or equivalent) and confirm that no dependency component in the output has a PURL whose name matches `example.com/myproject`. Repeat with a compiled binary where the main module is named similarly in BuildInfo; confirm the same exclusion.

**Acceptance Scenarios**:

1. **Given** a Go source tree with `module example.com/myproject` in go.mod and at least one dependency, **When** mikebom scans, **Then** the emitted dependency components include the dependency but do NOT include a component for `example.com/myproject`.
2. **Given** a compiled Go binary whose BuildInfo `mod` line names the main module, **When** mikebom scans, **Then** the main module does not appear as an emitted dependency component.
3. **Given** a Go project where the main module's name coincidentally matches a published external module name, **When** mikebom scans, **Then** the main module is still excluded (the go.mod or BuildInfo declaration is authoritative for "this is the project").

---

### Edge Cases

- **Sidecar POM missing on disk despite expected convention**: A JAR lives in `/usr/share/maven/lib/` but no matching sidecar file exists anywhere on the root filesystem. Expected behavior: the JAR is still emitted as a generic binary file; no Maven coordinates are fabricated; no error halts the scan.
- **Sidecar POM exists at the expected path but is syntactically invalid XML**: Expected behavior: the JAR falls back to generic-binary emission; a warning is logged; the scan continues for all other components.
- **JAR filename convention differs between Fedora variants (e.g., `JPP-<name>.pom` vs `<name>.pom`)**: The lookup strategy handles the documented filename mappings for the Fedora/RHEL ecosystem; lookups that do not match fall back to generic-binary emission.
- **Go source tree where every dependency is test-only**: After filtering, no Go component is emitted. Expected behavior: the empty result is legitimate; no error is raised; the document's Go section is omitted or empty.
- **Go project with vendored dependencies under `vendor/`**: The vendor directory is a production-scope signal. Modules present in vendor/ are treated as production even if they also appear in go.sum test-scope.
- **Multiple Go binaries in the same root filesystem with divergent BuildInfo**: The union of all BuildInfo sets defines the BuildInfo signal side of the intersection; a module is emitted if it's in the union AND in a non-`_test.go` import.
- **Binary's BuildInfo includes a module only used for tests**: This is the specific polyglot case. BuildInfo alone is not sufficient — a module linked into the binary for test-helper purposes but never imported from a non-`_test.go` file fails the intersection and is suppressed.
- **Go main module with the same name as the project subject**: When the SBOM has a top-level subject that matches the Go main module, the main module is still excluded from the dependency list to avoid double-listing.

## Requirements *(mandatory)*

### Functional Requirements

**Sidecar POM reading (Story 1)**

- **FR-001**: The scanner MUST discover JAR files on disk that do not contain `META-INF/maven/<groupId>/<artifactId>/pom.properties` inside the archive.
- **FR-002**: For each such JAR, the scanner MUST search the Fedora/RHEL sidecar POM directory (`/usr/share/maven-poms/`) for a POM file whose filename matches the JAR by the documented naming convention (`JPP-<name>.pom` and plain `<name>.pom`). Non-Fedora distribution layouts (Debian `/usr/share/maven-repo/`, Alpine equivalents) are explicitly deferred to a follow-up feature.
- **FR-003**: When a matching sidecar POM is found and is well-formed, the scanner MUST extract the Maven coordinates (groupId, artifactId, version) from the POM, resolving parent inheritance where the parent POM is available on disk, and emit a `pkg:maven/<g>/<a>@<v>` component related to the JAR file.
- **FR-004**: When a JAR has BOTH embedded `META-INF/maven/` metadata AND a matching sidecar POM, the embedded metadata MUST take precedence; no duplicate component is emitted.
- **FR-005**: When a JAR has no embedded metadata and no matching sidecar POM, the scanner MUST continue to emit the JAR as a generic binary file and MUST NOT fabricate Maven coordinates.

**Go test-scope filter (Story 2)**

- **FR-006**: When a Go source tree is present (go.mod and/or go.sum), the scanner MUST distinguish modules required at production runtime from modules referenced only by `_test.go` files and MUST suppress test-only modules from the emitted component set.
- **FR-007**: The scanner MUST NOT depend on invoking the Go toolchain (e.g., `go list`) at scan time. The production-versus-test distinction MUST be derived from static signals already accessible to mikebom: compiled binary BuildInfo and static analysis of Go source-file imports (excluding `_test.go` files).
- **FR-007a**: When BOTH a compiled Go binary AND Go source files are present on the same rootfs, the production set is the INTERSECTION of the two signals: a module is emitted only if it appears in BuildInfo AND is reachable from a non-`_test.go` import in the source tree. When only one signal is available, the filter falls back to that signal alone.
- **FR-008**: When a module is imported from both production `.go` files and `_test.go` files, the scanner MUST emit it (production import dominates).
- **FR-009**: When no compiled Go binary is present and no Go source files can be parsed (e.g., a stripped source tree with only go.sum), the scanner MUST emit only go.mod `require` directive entries (direct dependencies, not the full go.sum transitive closure) and MUST tag them with the `sbom-tier` value `"source-unverified"` to indicate that neither BuildInfo nor source-import analysis confirmed the set. go.sum entries that do not appear in go.mod `require` directives MUST NOT be emitted in this fallback mode.

**Go project-self filter (Story 3)**

- **FR-010**: When scanning a Go source tree with a `module` directive in go.mod, or a Go binary with a `mod` line in BuildInfo, the scanner MUST exclude that module from the emitted dependency components.
- **FR-011**: The project's own module MAY still appear elsewhere in the SBOM (e.g., as the document subject or metadata component); the exclusion applies specifically to the dependency/component listing.
- **FR-012**: The exclusion MUST apply regardless of whether the project's module path coincidentally matches a published external module name; the declaration in go.mod or BuildInfo is authoritative.

**Cross-cutting**

- **FR-013**: All three filters MUST preserve existing sbomqs/sbom-conformance quality scores for the other scanned ecosystems (cargo, gem, pypi, rpm, binary); no regression is acceptable.
- **FR-014**: Regression tests MUST be added for each of the three filters covering at minimum the representative polyglot bake-off cases plus the edge cases enumerated above.
- **FR-015**: When filters drop entries, the scanner MUST log a structured diagnostic (level INFO) naming the filter, the number of dropped entries, and enough context for an operator to verify the filter behaved correctly.

### Key Entities

- **JAR file**: A binary archive on disk, uniquely identified by its absolute path and content hash. May or may not contain `META-INF/maven/` metadata.
- **Sidecar POM**: A Maven project descriptor file on disk at a distribution-specific path, conventionally named so that it can be matched to a specific JAR. Declares `groupId`, `artifactId`, `version`, and optionally a `<parent>` that refers to a separate POM.
- **Maven component**: An emitted SBOM entry with a PURL of the form `pkg:maven/<groupId>/<artifactId>@<version>`, related to the JAR file(s) it describes.
- **Go module**: An entry derived from go.mod, go.sum, or binary BuildInfo, represented as `(name, version)` with a tier indicating the source of the evidence (`source` for go.sum/go.mod, `analyzed` for BuildInfo).
- **Production set**: The subset of Go modules that are linked into a compiled binary, OR (in source-only scans) reachable from the import graph of non-`_test.go` files in the source tree.
- **Main module**: The project's own Go module declared by the `module` directive in go.mod or the `mod` line in a binary's BuildInfo. Distinct from all dependency modules.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: After this feature lands, the polyglot-builder-image bake-off finding count drops from 23 to at most 6 (Story 1 unblocks 12, Story 2 unblocks 4, Story 3 unblocks 1 — the remaining 6 are outside mikebom's scope: 5 are ground-truth gaps and 1 is a real version disagreement).
- **SC-002**: After Story 1 lands, the per-ecosystem Maven scoreboard on polyglot improves from 101/114 exact matches to at least 113/114 exact matches.
- **SC-003**: After Story 2 lands, the per-ecosystem Go scoreboard on polyglot reports zero test-scope false positives (down from 4).
- **SC-004**: After Story 3 lands, the per-ecosystem Go scoreboard on polyglot reports zero project-self false positives (down from 1).
- **SC-005**: No regression in cargo, gem, pypi, rpm, or binary ecosystem scoreboards — each remains at its current perfect-match rate on the polyglot bake-off.
- **SC-006**: All existing mikebom test suites (unit + integration) pass unchanged; new regression tests for each filter pass; total pass count increases by at least one test per acceptance scenario enumerated above.
- **SC-007**: A reviewer inspecting the mikebom output for a Fedora-based image can verify, for any JAR under `/usr/share/maven/lib/`, whether the scanner identified it by Maven coordinates or emitted it as a generic binary — and the reason is deterministically derivable from the presence or absence of a sidecar POM.
- **SC-008**: A reviewer inspecting the mikebom output for a Go source-tree scan can verify that every emitted Go module is confirmed either by a compiled binary's BuildInfo or by a non-test import in the source tree; no emitted module is reachable only via `_test.go` imports.

## Assumptions

- Story 1 targets Fedora/RHEL images only. Debian's `/usr/share/maven-repo/` GAV layout and Alpine's equivalents are explicitly deferred to a follow-up feature and are NOT part of the success criteria for this work. The Fedora/RHEL convention (dir: `/usr/share/maven-poms/`; filenames: `JPP-<name>.pom` and plain `<name>.pom`) is stable enough that the single-distribution code path will not need refactoring when Debian/Alpine are added later.
- The ground-truth SBOM used as the reference on the polyglot bake-off is trustworthy for the specific findings enumerated (the user's analysis has already confirmed this). "Missing" ground-truth entries (the `gt_gap` bucket) are not addressed by this feature — those require changes to the ground-truth generator, not to mikebom.
- The version disagreement on `commons-compress` (mikebom reports 1.21, ground truth reports 1.23.0) is a real disagreement that requires case-by-case investigation and is explicitly out of scope here.
- The `sbom-fixture@1.0.0` project-self case on the Maven side follows a convention that the ground truth may or may not choose to model; scope of Story 3 is Go project-self only, because that is the specific FP on mikebom's side.
- The scanner already correctly emits all relevant JARs as generic binary files when no Maven metadata is found; Story 1 enriches these with Maven coordinates but does not change the binary-file emission path.
- The existing G3 filter (filter go.sum against Go binary BuildInfo, merged on main) covers the "binary-present" case for the broad set of Go scans. Story 2 closes the residual gap where G3 alone is insufficient because the binary's BuildInfo includes test-imported modules or because no binary is present at all.
- Sidecar-POM reading works offline; no network calls are made to resolve Maven coordinates. Parent POM inheritance is resolved only when the parent POM is physically present on the root filesystem.
- Log output format and level conventions match existing mikebom practice; INFO-level diagnostics with structured fields are consistent with the G3 filter's logging style already on main.
