# Phase 0 Research: Shade-Relocated Maven Dependency Emission

Unlike feature 008, the investigation for this feature was front-loaded into the conversation preceding `/speckit.specify`. Direct evidence from the extracted polyglot rootfs (`/tmp/008-polyglot-rootfs/`) confirmed:

1. `surefire-shared-utils-3.2.2.jar` carries `META-INF/DEPENDENCIES`
2. The file's canonical format is the Apache Maven Dependency Plugin's `dependency:list` output
3. The same shaded JAR's `unzip -l` shows relocated class files under `org/apache/maven/surefire/shared/compress/`

This document consolidates the concrete research items the plan needs to nail down.

## R1 — Canonical `META-INF/DEPENDENCIES` format

**Decision**: Parse line-by-line looking for `- <Name> (<url>) <groupId>:<artifactId>:<type>:<version>` with an optional `License: <spdx-id> (<url>)` continuation on the line directly following (conventionally indented).

**Evidence**: Literal excerpt from `surefire-shared-utils-3.2.2.jar`:

```
// ------------------------------------------------------------------
// Transitive dependencies of this project determined from the
// maven pom organized by organization.
// ------------------------------------------------------------------

Surefire Shared Utils


From: 'The Apache Software Foundation' (https://www.apache.org/)

  - Apache Commons IO (https://commons.apache.org/proper/commons-io/) commons-io:commons-io:jar:2.12.0
    License: Apache-2.0  (https://www.apache.org/licenses/LICENSE-2.0.txt)

  - Apache Commons Compress (https://commons.apache.org/proper/commons-compress/) org.apache.commons:commons-compress:jar:1.23.0
    License: Apache-2.0  (https://www.apache.org/licenses/LICENSE-2.0.txt)

  - Apache Commons Lang (https://commons.apache.org/proper/commons-lang/) org.apache.commons:commons-lang3:jar:3.12.0
    License: Apache License, Version 2.0  (https://www.apache.org/licenses/LICENSE-2.0.txt)
```

**Parser strategy**: Iterate lines. When a line matches the coord regex, start an in-progress `ShadeAncestor`. On the next non-blank line, if it starts with `License:` (trimmed), extract the license text; otherwise finalize the entry with no license. Reset parser state on blank lines between entries.

**Rationale**: Regex-based line matching is sufficient because the Apache plugin's output is deliberately line-stable. No need for a full parser.

**Alternatives considered**:
- *Full state machine*: overkill for a 3-line-per-entry record.
- *Stream parser using `nom`*: adds a crate for negligible benefit.

## R2 — Coord regex handling 4-part and 5-part forms

**Decision**: One regex with an optional classifier capture group:

```
(?x)
  ^ \s* - \s*                                # leading dash + space
  [^(]+ \s*                                  # human-readable name
  (?: \([^)]*\) \s+ )?                       # optional (url)
  ([a-zA-Z0-9._-]+) : ([a-zA-Z0-9._-]+)      # group : artifact
  : jar                                      # type must be `jar`
  (?: : ([a-zA-Z0-9._-]+) )?                 # optional classifier
  : ([a-zA-Z0-9._+-]+)                       # version
  \s* $
```

Capture groups: (groupId, artifactId, classifier?, version). When classifier is present, the emitted PURL carries `?classifier=<value>`.

**Alternatives considered**:
- *Split-by-colon heuristic (no regex)*: fragile for version strings that might contain colons (none in practice for Maven but risky).

## R3 — License parsing strategy

**Decision**: Strip `License:` prefix, strip URL parenthetical suffix (common pattern: `License: Apache-2.0 (https://...)`), pass the remaining text to existing `SpdxExpression::try_canonical`. On success → store; on error → log `"shade-relocation license not parseable"` at WARN level and emit the component with empty `licenses[]`.

**Evidence** from the surefire file: `License: Apache-2.0  (https://www.apache.org/licenses/LICENSE-2.0.txt)` — after URL stripping yields `Apache-2.0`, which passes `SpdxExpression::try_canonical` cleanly.

Free-form license text like `License: Apache License, Version 2.0  (...)` (the commons-lang3 entry in the same file) is NOT a canonical SPDX identifier — `try_canonical` returns `Err`. The fail-soft path logs and emits empty licenses. Acceptable per FR-002a.

**Alternatives considered**:
- *Map commonly-misnamed licenses to canonical IDs (`"Apache License, Version 2.0"` → `"Apache-2.0"`)*: future enrichment; not in scope for this feature.
- *Use `SpdxExpression::new` (permissive) instead of `try_canonical`*: would accept garbage as "valid licenses" — rejected because CycloneDX license fields are expected to carry SPDX identifiers, and lax acceptance would pollute downstream scoring.

## R4 — Integration point in `maven.rs`

**Decision**: Insert parsing + emission inside the existing `for jar_path in &jar_files` loop in `read_with_claims`, between `walk_jar_maven_meta` and the sidecar-POM fallback branch. The loop already iterates every JAR, has `co_owned_by` resolved, and determines the primary coord — exactly the state shade-relocation emission needs.

**Alternatives considered**:
- *Post-process `jar_meta` after the loop*: requires a second JAR-open per entry or carrying bytes through the data structure. Rejected for complexity.
- *Separate top-level walker*: duplicates JAR discovery and loses `co_owned_by` resolution. Rejected.

## R5 — Parent PURL resolution when primary coord is not yet identifiable

**Decision**: Shade-relocation emission requires a parent_purl; when `walk_jar_maven_meta` returns no meta entries AND no sidecar POM resolves the coord, the JAR has no primary and shade-relocation is skipped with a WARN log. This matches the Assumptions-section behavior in spec.

**Evidence**: every shaded JAR on the polyglot rootfs has a recognizable primary coord (either embedded or sidecar). Edge case of "shaded JAR with no primary" hasn't been observed in real-world images.

**Alternatives considered**:
- *Fabricate a synthetic parent_purl*: violates FR-003 (no fabrication).
- *Emit shade-relocation entries flat with no parent_purl*: loses the nesting semantic. Rejected.

## R6 — Dedup with standalone JARs (spec FR ambiguity check)

**Confirmed**: when the same coord appears BOTH as a standalone `<m2>/<g>/<a>/<v>/<a>-<v>.jar` AND as a shade-relocation child of a different JAR, both emissions are preserved by the existing dedup key `(ecosystem, name, version, parent_purl)` — the standalone has `parent_purl = None`, the shade-relocation child has `parent_purl = Some(enclosing)`. No code change needed to the deduplicator.

**Evidence**: reviewed `mikebom-cli/src/resolve/deduplicator.rs` — the key tuple includes `parent_purl`; two entries with the same coord but different `parent_purl` do NOT collapse.

## R7 — Property marker wiring

**Decision**: Add a new boolean-like field to `PackageDbEntry` (`shade_relocation: Option<bool>`) that's `Some(true)` on emitted shade children and `None` elsewhere. The CDX serializer already has a pattern for surfacing `Option<bool>` fields as `mikebom:*` properties (compare `detected_go`, `is_dev`). Wire identically.

**Alternatives considered**:
- *Carry the property as a string in a new free-form metadata map*: violates the existing typed-field pattern; rejected.
- *Piggyback on `source_type`*: conflates orthogonal concerns (`source_type` is for local/git/url tagging). Rejected.

## R8 — Test fixture strategy

**Decision**: Synthetic JARs built at test time via the same `zip::ZipWriter` pattern US4's test fixture uses (see `mikebom-cli/tests/scan_maven_executable_jar.rs::build_ordinary_maven_jar`). No real class files needed — the parser only reads the manifest text. Two fixtures:

1. **Canonical shade**: primary coord + `META-INF/DEPENDENCIES` listing three ancestor deps, each with a `License:` continuation.
2. **Classifier variant**: primary coord + `META-INF/DEPENDENCIES` with one 5-part classifier entry.

Plus a regression fixture: a JAR WITHOUT `META-INF/DEPENDENCIES` to verify FR-011 (non-shaded output unchanged).

**Rationale**: synthetic fixtures are fast, deterministic, and byte-reproducible — same philosophy as feature 007 US1's Fedora sidecar tests.

## Summary of decisions

| # | Area | Decision |
|---|------|----------|
| R1 | DEPENDENCIES file format | Line-based parsing with coord regex + optional License continuation |
| R2 | Coord regex | Single regex with optional classifier capture group (PURL qualifier) |
| R3 | License parsing | `SpdxExpression::try_canonical`; fail-soft on unrecognized text |
| R4 | Integration point | Inside existing `read_with_claims` JAR loop |
| R5 | No-primary-coord JARs | Skip shade-relocation emission; WARN log |
| R6 | Dedup with standalone JARs | No code change — existing `parent_purl`-aware key handles it |
| R7 | Property marker wiring | New `Option<bool>` field on `PackageDbEntry` + existing CDX serializer pattern |
| R8 | Test fixtures | Synthetic JARs built at test time via `zip::ZipWriter` |

No NEEDS CLARIFICATION items remain. Implementation plan is fully scoped.
