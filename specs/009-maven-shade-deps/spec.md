# Feature Specification: Emit Shade-Relocated Maven Dependencies

**Feature Branch**: `009-maven-shade-deps`
**Created**: 2026-04-23
**Status**: Draft
**Input**: User description: "Emit shade-relocated Maven dependencies from embedded META-INF/DEPENDENCIES metadata with a mikebom:shade-relocation=true property marker and parent_purl pointing at the enclosing JAR"

## Clarifications

### Session 2026-04-23

- Q: Should shade-relocation entries carry license info extracted from the DEPENDENCIES file? → A: **Extract and emit.** Parse the `License: <spdx-id>` line that follows each coord, populate the emitted component's `licenses[]` field with the SPDX expression. Unrecognized license text is logged and skipped for that entry only; emission continues.
- Q: How should the parser handle classifier-bearing coord lines (5-part `<g>:<a>:jar:<classifier>:<v>`)? → A: **Parse and preserve.** Accept the 5-part form; emit PURL with `?classifier=<value>` qualifier per the PURL spec. Two classifier variants of the same coord remain distinct CDX components.
- Q: Should shade-relocation entries be emitted for every `META-INF/DEPENDENCIES` ancestor, or gated on bytecode presence? → A: **Gate on bytecode presence.** Emit an ancestor only when a `.class` entry in the enclosing JAR proves its bytecode is actually bundled — either at the ancestor's original group path (UNSHADED) or at a shade-relocated path whose leaf fragment matches the ancestor's distinctive artifact-id suffix (SHADED). Apache's maven-dependency-plugin emits `DEPENDENCIES` as a declared-transitive manifest into any JAR it's configured on, not only into shade fat-jars; emitting every ancestor would claim bytecode presence that isn't there and produce false-positive vulnerability matches. The UNSHADED check is suppressed when ancestor and primary share a reactor group namespace, since we cannot then distinguish ancestor bytecode from the primary's own classes. The SHADED check is skipped for generic leaves (`io`, `api`, `util`, `core`, etc.) to avoid spurious substring matches.

## Context: Why this feature is needed

Feature 008 closed the polyglot-builder-image bake-off to 1 finding — `commons-compress` version disagreement between mikebom (reports 1.21) and the ground truth (reports 1.21 AND 1.23.0). During investigation (see PR #14 follow-up discussion), we discovered this is NOT a ground-truth authoring error:

- On disk, `commons-compress@1.21` exists as a standalone JAR in the Maven cache — what mikebom currently emits.
- On disk, `surefire-shared-utils-3.2.2.jar` contains `org/apache/maven/surefire/shared/compress/*` relocated classes (maven-shade-plugin renaming) — these ARE `commons-compress@1.23.0`'s bytecode, just under a different package namespace.
- The JAR's embedded `META-INF/DEPENDENCIES` text file explicitly declares the shaded source:

  ```
  - Apache Commons Compress ... org.apache.commons:commons-compress:jar:1.23.0
  - Apache Commons IO ... commons-io:commons-io:jar:2.12.0
  - Apache Commons Lang ... org.apache.commons:commons-lang3:jar:3.12.0
  ```

Both versions are legitimately "present in the image" but for different meanings of present:

- `commons-compress@1.21` — linkable as `org.apache.commons.compress.*`
- `commons-compress@1.23.0` — NOT linkable under that name, but CVE-bearing bytecode is physically in the image under the relocated namespace

Most SBOM tooling today (mikebom, syft, trivy, cdxgen) emits only the enclosing shaded JAR and silently loses the ancestor-dep provenance. This under-reports to vulnerability scanners: if a CVE affects `ArchiveInputStream`'s buffer handling, that CVE-bearing code IS in the image regardless of the package it's labelled under, and a scanner that ignores shade-relocated ancestors will miss the risk.

CycloneDX 1.6's spec-native answer is `component.pedigree.ancestors[]` — but no mainstream tool populates this today, and emitting shade-relocated deps as top-level `components[]` entries with a distinguishing property marker is a pragmatic, forward-compatible intermediate: vulnerability scanners see the ancestor coords; link-check consumers can filter by the marker property.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Emit shaded ancestor dependencies with provenance marker (Priority: P1)

A security engineer scanning a container image that contains a shade-relocated JAR (e.g., surefire-shared-utils, many Spring Boot executable JARs, shade-packaged fat-jars) needs every ancestor dependency referenced in the shaded JAR to appear in the SBOM. Today mikebom emits only the outer shaded JAR's primary coord; the ancestor deps are invisible. After this story lands, mikebom parses the embedded `META-INF/DEPENDENCIES` manifest inside the JAR and emits one component per ancestor dep, nested under the enclosing JAR via CycloneDX's `component.components[]` + `parent_purl` mechanism, tagged with a distinguishing property so downstream consumers can filter shade-relocated entries in either direction.

**Why this priority**: This is the whole feature. All other stories derive from or complement this one. Without Story 1 the feature ships nothing; with just Story 1 the feature closes the remaining polyglot-bake-off gap and gives vulnerability scanners the provenance they need.

**Independent Test**: Construct a synthetic fat-jar with a `META-INF/DEPENDENCIES` file listing three ancestor Maven deps (matching the Apache Maven Dependency Plugin's text output format). Scan the fixture and confirm the SBOM contains four Maven components: the enclosing JAR's primary coord plus one nested component per declared ancestor, each with a `mikebom:shade-relocation = true` property and `parent_purl` pointing at the enclosing coord.

**Acceptance Scenarios**:

1. **Given** a JAR on disk whose `META-INF/DEPENDENCIES` lists `org.apache.commons:commons-compress:jar:1.23.0` as a transitive dependency and whose primary coord is `org.apache.maven.surefire/surefire-shared-utils@3.2.2`, **When** mikebom scans the rootfs, **Then** the SBOM contains a Maven component `pkg:maven/org.apache.commons/commons-compress@1.23.0` with `parent_purl = "pkg:maven/org.apache.maven.surefire/surefire-shared-utils@3.2.2"` and a property `mikebom:shade-relocation = true`.
2. **Given** a JAR with both an embedded `META-INF/maven/<g>/<a>/pom.properties` (one vendored ancestor) AND a `META-INF/DEPENDENCIES` that names additional ancestors, **When** mikebom scans, **Then** all vendored-ancestor + DEPENDENCIES-ancestor coords are emitted; each is a child of the enclosing JAR's primary coord; both sources' provenance is distinguishable (only DEPENDENCIES-derived entries carry the shade-relocation marker).
3. **Given** a JAR with a malformed `META-INF/DEPENDENCIES` (truncated mid-line, non-UTF-8 bytes, unrecognized format), **When** mikebom scans, **Then** the scan completes without failure; the enclosing JAR's primary coord is still emitted; a warning is logged; no partial/fabricated ancestor coords are emitted.
4. **Given** an ordinary (non-shaded) Maven JAR without a `META-INF/DEPENDENCIES` file, **When** mikebom scans, **Then** the output is identical to the pre-feature behavior — no shade-relocation entries added, no property markers on pre-existing components.
5. **Given** a JAR whose `META-INF/DEPENDENCIES` lists an ancestor that ALSO exists as a standalone JAR elsewhere on the rootfs (e.g., both `commons-compress-1.23.0.jar` in `.m2/` AND shaded into surefire), **When** mikebom scans, **Then** both emissions are preserved: one top-level (from the standalone JAR) and one nested under the surefire coord (with the shade-relocation marker). The deduplicator's existing `parent_purl`-aware key keeps them distinct.

---

### User Story 2 - Known-limitation documentation for unparseable shading (Priority: P3)

Not every shaded JAR ships a `META-INF/DEPENDENCIES` file. Some tooling uses `maven-shade-plugin`'s default config which doesn't emit that file (only `reduced-pom.xml` survives), and some projects shade without recording provenance at all. For those JARs, mikebom will have no signal to derive ancestor coords from and MUST NOT fabricate them. After this story lands, `docs/design-notes.md` documents the coverage boundary: which shading patterns mikebom detects (META-INF/DEPENDENCIES present), which it doesn't (silent shading), and where future work could extend coverage (class-path regex heuristics, reduced-pom.xml parsing).

**Why this priority**: Low. Pure documentation. Keeps the feature honest about its coverage without blocking the fix.

**Independent Test**: A reader of `docs/design-notes.md` can explain in their own words which shaded JARs mikebom models and which it doesn't.

**Acceptance Scenarios**:

1. **Given** an operator sees a shaded JAR in their image whose ancestor deps are NOT emitted by mikebom, **When** they consult the design notes, **Then** they find the coverage boundary documented and understand that silent shading (no META-INF/DEPENDENCIES) is a known limitation with a named future-work item.

---

### Edge Cases

- **META-INF/DEPENDENCIES declares itself as an ancestor** (circular — the JAR's primary coord listed inside its own DEPENDENCIES): mikebom MUST NOT emit the self-coord twice. A shade-relocation child entry whose coord equals the enclosing JAR's primary coord is filtered.
- **META-INF/DEPENDENCIES lists the same coord twice** (edge of the text-format's tolerance for duplicates): mikebom emits only one child entry per unique coord, even within a single JAR.
- **Ancestor dep with incomplete version** (e.g., `org.apache.commons:commons-compress:jar:`): skip — do not fabricate a zero-version coord.
- **JAR is OS-claimed** (`co_owned_by = "rpm"`): shade-relocation extraction still runs; the resulting ancestor-coord entries inherit the `co_owned_by` tag from the enclosing JAR. Fedora-shipped shaded JARs under `/usr/share/java/` legitimately have ancestor deps too.
- **Same ancestor coord appears across multiple shaded JARs on the rootfs**: each enclosing JAR emits its own nested child; the CDX nested-components model preserves distinctness via `parent_purl` in the dedup key (mirroring feature 007 US1's pattern for fat-jar vendored coords).
- **Artifact walker emits a cache-ZIP for the same coord** (interaction with feature 008 US2 / G6): the cache-ZIP emission is analyzed-tier and unrelated to shade-relocation; they remain distinct CDX entries.

## Requirements *(mandatory)*

> **Note on FR numbering**: Feature 009's FR identifiers are local to this feature. Where earlier-feature FRs are referenced, they are cited explicitly (e.g., "feature 007 FR-004").

### Functional Requirements

**Parsing (Story 1)**

- **FR-001**: When a JAR being processed by the Maven reader contains a `META-INF/DEPENDENCIES` file, the scanner MUST parse that file for lines matching the Apache Maven Dependency Plugin's canonical `- <Human-Name> (<url>) <groupId>:<artifactId>:<type>:<version>` format (with permissive whitespace handling before the dash and around the coord triple).
- **FR-002**: For each parseable line, the scanner MUST extract the `(groupId, artifactId, version)` triple. Only the `jar` type is recognized as a coord source; other types (`pom`, `test-jar`, etc.) are skipped. The parser MUST accept both the canonical 4-part form `<g>:<a>:jar:<v>` and the 5-part classifier form `<g>:<a>:jar:<classifier>:<v>`; when a classifier is present, it is preserved in the emitted PURL as a `?classifier=<value>` qualifier per the PURL specification. Two classifier variants of the same base coord remain distinct CDX components.
- **FR-002a**: Following each coord line, the scanner MUST also parse the conventional `License: <spdx-id> (<url>)` continuation line (typically indented on the line immediately after the coord) and extract the SPDX identifier. The extracted identifier populates the emitted component's `licenses[]` field. Multi-license expressions (`License: A or B`, `License: A and B`) are parsed as SPDX OR / AND expressions. When the license text is unrecognized or malformed, the scanner MUST log a warning and emit the component with an empty `licenses[]` (skipping only the license for that entry, not the entry itself).
- **FR-002b**: Before emission, each parsed ancestor MUST be filtered by bytecode-presence verification against the enclosing JAR. The scanner enumerates every `.class` entry in the JAR and retains an ancestor only when one of the following holds:
  - **UNSHADED**: at least one class path starts with the ancestor's original group path (`org.apache.commons.compress` → any entry under `org/apache/commons/compress/`) AND the ancestor's group_id does not share a reactor namespace with the enclosing JAR's primary group_id. Shared-namespace ancestors cannot be distinguished from the primary's own classes via this check and MUST NOT be accepted on UNSHADED evidence alone.
  - **SHADED**: at least one class path contains the ancestor's distinctive artifact-id trailing fragment wrapped in slashes (`commons-compress` → `/compress/`), AND that fragment is not a member of the generic-leaf set {`io`, `api`, `util`, `utils`, `core`, `impl`, `common`, `commons`, `base`, `main`, `lib`, `shared`, `plugin`, `plugins`, `ext`} — these fragments are too unspecific to prove shade relocation.

  Ancestors failing both checks MUST be dropped with a DEBUG log. Apache's maven-dependency-plugin emits `META-INF/DEPENDENCIES` as a declared-transitive manifest for any JAR it's configured on, not only for shade-plugin fat-jars; emitting every declared ancestor would claim bytecode presence that isn't there and produce false-positive vulnerability matches.
- **FR-003**: When parsing fails for any reason (malformed line, non-UTF-8 bytes, absent file, unreadable entry), the scanner MUST continue processing the JAR's other emissions (primary coord, embedded META-INF/maven/, etc.) without failure.

**Emission (Story 1)**

- **FR-004**: For each successfully extracted ancestor coord, the scanner MUST emit a `PackageDbEntry` with purl `pkg:maven/<g>/<a>@<v>`, `parent_purl` set to the enclosing JAR's primary coord PURL, and a property `mikebom:shade-relocation = true`.
- **FR-005**: A shade-relocation entry whose `(groupId, artifactId, version)` equals the enclosing JAR's primary coord MUST be dropped (self-reference guard).
- **FR-006**: Within a single JAR, duplicate ancestor coords MUST be collapsed to a single emission.
- **FR-007**: The `sbom_tier` of shade-relocation entries is `"analyzed"` — they are derived from bytecode-presence evidence, not from a lockfile.
- **FR-008**: `co_owned_by` on shade-relocation entries MUST be inherited from the enclosing JAR (so Fedora-shipped shaded JARs' ancestors are tagged rpm/deb/apk appropriately).

**Interaction with existing filters**

- **FR-009**: Shade-relocation entries MUST NOT trigger the scan-subject suppression heuristics (target-name-match, classic fat-jar, Main-Class, target-dir — from features 007 US4 + 008 US3). Only the enclosing JAR's primary coord is subject to those heuristics.
- **FR-010**: Shade-relocation entries MUST pass through the feature 008 US2 (G6) cache-ZIP filter unchanged; they're Maven entries, not golang cache-ZIP-sourced.

**Regression guards (cross-cutting)**

- **FR-011**: A JAR without `META-INF/DEPENDENCIES`, or a JAR with `META-INF/DEPENDENCIES` whose declared ancestors all fail the FR-002b bytecode-presence check, MUST produce output identical to the pre-feature behavior — no shade-relocation entries added. This is the expected outcome for the common case of non-fat-jar Maven artifacts (most `surefire-*.jar`, `maven-resolver-*.jar`, etc.) that embed a DEPENDENCIES manifest purely for declared-transitive provenance.
- **FR-012**: All existing feature 007 US1 + US4 + feature 008 US3 integration tests MUST remain passing unchanged.
- **FR-013**: Pre-PR verification per constitution v1.2.1 (`cargo +stable clippy --workspace --all-targets` + `cargo +stable test --workspace`) MUST be evidenced in the PR description.

**Documentation (Story 2)**

- **FR-014**: `docs/design-notes.md` MUST document the coverage boundary: `META-INF/DEPENDENCIES`-based extraction is the sole shading-detection signal in this feature; silent shading (no manifest file) is a documented known limitation.
- **FR-015**: The documentation MUST name at least one named future-work item for extending coverage (reduced-pom.xml parsing, class-path regex heuristics, or CycloneDX `pedigree.ancestors` field emission).

### Key Entities

- **Shaded JAR**: a JAR whose `META-INF/DEPENDENCIES` file declares ancestor Maven coords that were relocated into the archive via `maven-shade-plugin` or an equivalent tool.
- **Ancestor coord**: a `(groupId, artifactId, version)` triple extracted from a shaded JAR's `META-INF/DEPENDENCIES`. Represents bytecode physically present in the JAR under a renamed package namespace.
- **Shade-relocation entry**: a `PackageDbEntry` emitted from an ancestor coord, carrying `mikebom:shade-relocation = true`, `parent_purl` = enclosing primary coord, `sbom_tier = "analyzed"`, and `licenses[]` populated from the DEPENDENCIES file's `License:` continuation line when present.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: After this feature lands, the polyglot-builder-image bake-off's `commons-compress@1.23.0` finding closes: the shaded ancestor surfaces as a CDX component nested under `surefire-shared-utils-3.2.2` with the shade-relocation marker.
- **SC-002**: Per-ecosystem scoreboards for cargo/gem/pypi/rpm/binary/golang remain at perfect-match after this feature — no regression. Maven scoreboard either improves or stays at its post-008 state, depending on GT alignment.
- **SC-003**: A CycloneDX 1.6 consumer can programmatically distinguish shade-relocation entries from direct dependencies by filtering on `properties[].name == "mikebom:shade-relocation"`.
- **SC-004**: A vulnerability scanner walking the SBOM's `components[]` sees the 1.23.0 coord and can match CVEs that affect that version, even though the classes are namespace-relocated in the image.
- **SC-005**: `cargo +stable test --workspace` baseline of 1128 (post-008 US3) MUST be preserved or increased. No regressions.
- **SC-006**: All existing feature 007 + 008 integration tests pass unchanged (regression guard per FR-012).

## Assumptions

- Not every shaded JAR ships a `META-INF/DEPENDENCIES` file. This feature detects the subset that does. Silent shading is a named known limitation (Story 2) with a future-work pointer for operators who need broader coverage.
- The Apache Maven Dependency Plugin's `DEPENDENCIES` text format is deliberately stable and human-readable; parsing it with a simple line-based regex is sufficient for the real-world cases mikebom encounters. Exotic variants (bundled from other shaders) may not match; when they don't, the parse fails cleanly per FR-003.
- CycloneDX 1.6's `component.pedigree.ancestors[]` is the spec-ideal modeling, but (a) no mainstream tool populates it today and (b) no mainstream consumer (vuln scanner, license checker) consults it. Emitting as nested `components[]` with a distinguishing property is a pragmatic bridge that downstream consumers already handle correctly.
- The `mikebom:shade-relocation = true` property is authored by this feature. It is not part of the CycloneDX spec or any standard property namespace. Its intent is documented inline here and in the design notes (Story 2) so consumers know what to filter on.
- The feature is default-on — no CLI flag to disable. Rationale: shade-relocation emissions carry a distinguishing property, so consumers who don't want them can filter; adding a flag for an additive-only feature is over-engineering.
- The enclosing JAR's primary coord must be identifiable via existing `walk_jar_maven_meta` machinery (either as `is_primary` meta or via the 008 US3 target-dir heuristic, etc.) for the `parent_purl` to be set. When no primary coord can be derived for the enclosing JAR, shade-relocation emissions are skipped for that JAR; logged as warning. This is consistent with the existing nested-components model for fat-jar vendored children (feature 007 US1).
