# Feature Specification: Python + npm Ecosystem Support

**Feature Branch**: `002-python-npm-ecosystem`
**Created**: 2026-04-17
**Status**: Draft
**Input**: User description: "Python + npm ecosystem support for mikebom (Milestone 002 of the roadmap)"

## Clarifications

### Session 2026-04-17

- Q: How should the scanner handle legacy `package-lock.json` v1 files (npm ≤5)? → A: Refuse with an explicit, actionable error that instructs the user to regenerate with npm ≥7.
- Q: Does `--include-dev` apply to Poetry / Pipfile dev-group packages, or is it npm-only? → A: Global — one flag toggles dev inclusion in every ecosystem that carries the distinction (npm, Poetry, Pipfile). Venv and `requirements.txt` scans ignore it (no dev/prod info present).
- Q: When a `package-lock.json` and a `node_modules/` tree disagree on a version for the same package, which wins? → A: `node_modules/` wins. Symmetrical with the Python rule (venv over lockfile) — what's actually installed on disk is authoritative.
- Q: A `--path` scan finds a `package.json` but no lockfile and no `node_modules/`. What does the scanner do? → A: Parse `package.json` `dependencies` and `devDependencies` as a last-resort fallback at confidence 0.70 (mirroring the Python `requirements.txt` tier). Emit one component per declared dep with the range spec in a `mikebom:requirement-range` property; the `version` field stays empty. **Implementation note for plan phase**: align the exact output shape (property names, how the range is surfaced, whether `peerDependencies` / `optionalDependencies` are included in the fallback) with how trivy, syft, and scalibr handle the same "uninstalled `package.json` only" state so downstream consumers that already know those tools' outputs don't have to re-learn ours.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Scan a Python project directory (Priority: P1)

A developer working on a Python project runs `mikebom sbom scan --path .` inside a cloned repository (or inside a CI container that has already run `pip install`) and receives a CycloneDX SBOM listing every Python package the project depends on, at parity with what `trivy fs` would produce.

The scanner pulls data from three layered sources in order of authority:
1. **Installed package metadata** in `<venv>/lib/python*/site-packages/*.dist-info/` directories (confidence 0.85) — ground truth for what's actually resolved.
2. **Lockfiles** (`poetry.lock`, `Pipfile.lock`) — authoritative when no venv is present (confidence 0.85).
3. **Requirements files** (`requirements.txt`, `requirements-dev.txt`) — fallback when nothing else is available; produces unversioned or range-versioned components (confidence 0.70).

**Why this priority**: Python is the single largest ecosystem mikebom doesn't yet cover. Closing it has the highest single-step impact on real-world workload coverage — most enterprises have Python in their stack somewhere. Until this story ships, mikebom can't compete on Python-heavy repos at all.

**Independent Test**: Clone a mid-sized Python project (e.g. FastAPI example app), run `mikebom sbom scan --path .`, and verify the output SBOM lists every top-level `requirements.txt` entry plus the transitive dependencies that are resolved in the venv. Confirm PURLs are reference-implementation conformant, licenses are populated, and each component carries evidence pointing back to the source file it was found in.

**Acceptance Scenarios**:

1. **Given** a project directory with a populated `.venv/` containing 50 installed packages, **When** the user runs `mikebom sbom scan --path .`, **Then** the SBOM contains 50 components, each with a canonical Python package URL, SPDX-canonical licenses from the `METADATA` files, and evidence identifying the detection as `manifest-analysis` at confidence 0.85.

2. **Given** a project directory with only a `poetry.lock` file (no venv yet), **When** the user runs `mikebom sbom scan --path .`, **Then** the SBOM reflects the locked versions at confidence 0.85 and a composition record declares the Python subset of the BOM as complete.

3. **Given** a project directory with only `requirements.txt` and no lockfile or venv, **When** the user runs `mikebom sbom scan --path .`, **Then** the SBOM surfaces the listed packages at confidence 0.70, pinned versions populate `version`, and unpinned or ranged packages are emitted with empty or range-version components flagged via a `mikebom:requirement-range` property.

4. **Given** a project with both a venv AND a lockfile, **When** the scan runs, **Then** mikebom produces a single deduplicated component per package (the higher-confidence venv entry wins) and the resulting evidence references both source files.

5. **Given** a `poetry.lock` with 30 prod packages and 10 dev-group packages (no venv present), **When** the user runs `mikebom sbom scan --path .`, **Then** the SBOM contains only the 30 prod components. Re-running with `--include-dev` yields all 40 components, with the 10 dev ones carrying a `mikebom:dev-dependency = true` property.

---

### User Story 2 — Scan a Node.js project directory (Priority: P1)

A developer working on a Node.js project runs `mikebom sbom scan --path .` on a repo that contains `package.json` plus `package-lock.json` (or `pnpm-lock.yaml`) and receives an SBOM that:
- Lists the production dependency graph by default (matches the default most security tooling ships with).
- Excludes `devDependencies` unless the user passes `--include-dev`.
- Respects scoped package names (`@angular/core`) with correct reference-implementation PURL encoding.
- Populates content hashes from the lockfile's `integrity:` field when provided.

**Why this priority**: Node is the second-largest ecosystem by real-world usage. Paired with Python in this milestone because they share the manifest-walking and dev/prod scoping patterns — building one informs the other.

**Independent Test**: Clone a medium-sized Node project (e.g. an Express API). Run the default scan; verify prod-only components emerge and dev tools like `eslint` / `jest` are absent. Re-run with `--include-dev`; verify the dev tools now appear but are flagged with a property distinguishing them from prod.

**Acceptance Scenarios**:

1. **Given** a `package-lock.json` v3 with 200 total packages (80 prod, 120 dev), **When** the user runs `mikebom sbom scan --path .`, **Then** the SBOM emits exactly the 80 prod components; each carries a hash from the lockfile `integrity:` field (its declared algorithm preserved — typically SHA-512).

2. **Given** the same project, **When** the user passes `--include-dev`, **Then** all 200 packages appear, with the 120 dev ones carrying a property `mikebom:dev-dependency = true` so downstream consumers can filter cleanly.

3. **Given** a project with a scoped dependency `@angular/core`, **When** the scan runs, **Then** the emitted PURL encodes the `@` in the scope per the reference implementation's canonical form.

4. **Given** a `pnpm-lock.yaml` (pnpm v8 format), **When** the scan runs, **Then** the scanner parses it correctly and the resulting SBOM matches the one produced from the equivalent `package-lock.json`.

5. **Given** a project whose only npm source is a `package-lock.json` with `"lockfileVersion": 1`, **When** the user runs `mikebom sbom scan --path .`, **Then** the command exits non-zero with the message `"package-lock.json v1 not supported; regenerate with npm ≥7"` and no partial SBOM is written.

6. **Given** a project with only a `package.json` (no lockfile, no `node_modules/`) declaring 12 `dependencies` and 5 `devDependencies`, **When** the user runs `mikebom sbom scan --path .`, **Then** the SBOM contains 12 components at confidence 0.70, each with an empty `version` field, a `mikebom:requirement-range` property holding the original range spec, and evidence technique `filename`. Re-running with `--include-dev` yields 17 components, with the 5 dev ones carrying the `mikebom:dev-dependency = true` property in addition to their range property.

---

### User Story 3 — Scan a container image with Python or npm workloads (Priority: P2)

An operator runs `mikebom sbom scan --image <tar>` on a `docker save` tarball of a Python application image (e.g. a FastAPI app built on `python:3.12-slim`) or a Node.js application image (e.g. `node:20`). The scanner overlays the image's filesystem as usual, then — in addition to the existing dpkg/apk OS-level pass — walks the embedded language-specific package layouts:
- Python: system `site-packages/` locations plus the app's own venv when present.
- npm: the global `node_modules/` plus the application's `node_modules/` at the image's declared working directory.

All language-sourced components get layered alongside the OS-package components in a single SBOM, with per-ecosystem composition records marking which ecosystems were read in full.

**Why this priority**: Image scanning is where real-world deployment volume lives. Mikebom already handles the OS layer competitively; adding Python + npm makes it competitive for application-workload images. Ranked P2 instead of P1 because the P1 directory-scan path delivers standalone value first and this story builds on it.

**Independent Test**: `docker save` a public Python image that runs a real application, run mikebom against the tarball, and confirm the output contains both OS-level deb packages AND Python site-packages components, with clearly distinct composition records for each ecosystem.

**Acceptance Scenarios**:

1. **Given** a Python application image tarball, **When** the user runs `mikebom sbom scan --image app.tar`, **Then** the SBOM contains OS-level deb components AND Python site-packages components, and the compositions section has separate complete-aggregate records for each ecosystem that had its manifest/db read in full.

2. **Given** a Node.js application image tarball where the app lives at `/app/node_modules/`, **When** the scan runs, **Then** the scanner reads the image config to find the WORKDIR and walks the correct `node_modules/` tree, not just any global `node_modules/` under `/usr/lib/`.

3. **Given** an image with both system Python and an app venv, **When** the scan runs, **Then** components from both locations are captured and deduplicated by PURL.

---

### User Story 4 — Dependency tree for Python and npm components (Priority: P2)

A consumer of the SBOM wants to answer "which packages brought in `left-pad`" or "what will I break if I remove `Flask`" by traversing the `dependencies[]` graph in the CycloneDX output. For npm, mikebom emits edges directly from the lockfile's nested dependency tree. For Python, mikebom emits edges by reading each package's `dist-info/METADATA::Requires-Dist:` fields and resolving each requirement against the set of observed components in the scan.

**Why this priority**: Without this, the SBOM is a flat list — good for attestation but poor for triage. Feature-complete dependency trees are what security teams reach for. P2 because P1 stories already deliver a usable MVP (flat-component SBOM); this story upgrades the utility without blocking the MVP.

**Independent Test**: Scan a project with a deep dependency tree (e.g. installing `requests` pulls in `urllib3`, `certifi`, `charset-normalizer`, `idna`). Verify the `dependencies[]` section declares `requests` depends-on the four transitive packages at the exact versions observed, not the version ranges from the requirements spec.

**Acceptance Scenarios**:

1. **Given** a Python scan that finds `requests` + its transitive deps, **When** the SBOM is generated, **Then** the dependencies section contains an entry for each package listing its observed-in-scan dependencies as `dependsOn` references; unsatisfied requirements (package depends on something not observed in the scan) are dropped from the edge list, not left dangling.

2. **Given** an npm scan of a project with a `package-lock.json`, **When** the SBOM is generated, **Then** the dependency edges reflect the exact resolved tree in the lockfile, including version-pinned transitive deps.

3. **Given** both scans, **When** the SBOM is emitted, **Then** the density of `dependsOn` edges is at least 80% of the corresponding count another competitive scanner produces on the same inputs.

---

### User Story 5 — Offline / air-gapped operation (Priority: P3)

A CI pipeline running in an air-gapped environment runs `mikebom --offline sbom scan --path .` or `--image app.tar` on a Python or npm project and receives an SBOM derived purely from local data — no outbound network calls. Licenses come from local `METADATA` files / local `package.json`; the deps.dev enrichment pass is silently skipped.

**Why this priority**: Many enterprise CI environments can't reach the public internet. The `--offline` flag already exists for deb/apk scans (shipped in a prior round); this story confirms it applies uniformly to Python + npm without silently regressing coverage. P3 because the online path is the default and covers the common case.

**Independent Test**: Run the same scan twice — once online, once with `--offline`. Verify licenses still come from local `METADATA` / `package.json` files in both runs; verify the deps.dev evidence tool reference appears only in the online run.

**Acceptance Scenarios**:

1. **Given** a Python project venv with 50 packages, **When** the user runs `mikebom --offline sbom scan --path .`, **Then** every component has a license populated from its `METADATA` (local source), and no component carries a deps.dev evidence tool reference.

2. **Given** the same project run without `--offline`, **Then** licenses still match the local-`METADATA`-derived ones (no overwrite), and ≥95% of components additionally carry a deps.dev evidence reference indicating the enrichment pass fired successfully.

---

### Edge Cases

- **PEP 517/518 build-only metadata**: a project with `pyproject.toml` but no venv, no lockfile, and no `requirements.txt`. The scanner MUST emit zero Python components rather than fabricating output from `pyproject.toml`'s `[project.dependencies]` (those are build specs, not resolved versions). The skip is logged for operator visibility.
- **Namespaced Python packages**: `zope.interface` and similar. The dist-info directory uses the normalised name `zope_interface`; the canonical PyPI name is `zope.interface`. The scanner MUST emit the PURL with the canonical (non-normalised) form per PyPI's packaging convention, regardless of the on-disk directory name.
- **npm workspaces**: a `package.json` with a `workspaces:` field and multiple sub-packages. The scanner MUST NOT emit a component for the top-level `package.json` itself (it's a workspace root, not a published package). Sub-workspace `package.json` files follow the same rule.
- **Local / Git / file-URL npm deps**: entries like `"my-lib": "file:../lib"` or `"my-lib": "git+ssh://..."`. The scanner MUST emit these as components with a `pkg:generic/<name>@<resolved-version>?download_url=<url>` PURL shape and a `mikebom:source-type=local|git|url` property, rather than mangling them into an npm-registry-style PURL.
- **Missing `METADATA` License field**: the field is optional in Python packaging. The scanner MUST fall back to parsing PEP 639's `License-Expression:` field or the `Classifier: License ::` entries if present. When none of those exist, emit the component with an empty license list (deps.dev enrichment may still populate it in online mode).
- **Lockfile / venv drift (Python)**: a `poetry.lock` with `foo==1.0.0` but the installed venv has `foo==1.0.1` (hand-edited). The scanner MUST prefer the venv (higher-authority source); the lockfile entry is suppressed with a drift note at debug log level.
- **Lockfile / `node_modules/` drift (npm)**: a `package-lock.json` with `foo@1.0.0` but `node_modules/foo/package.json` has version `1.0.1` (e.g. someone ran `npm install foo@1.0.1` without re-committing the lockfile). The scanner MUST prefer `node_modules/` — the installed reality — and suppress the lockfile entry for that package with a drift note at debug log level. This keeps the rule symmetrical with the Python venv-vs-lockfile rule.
- **Versionless requirements**: a `requirements.txt` line `requests` with no version pin. The scanner MUST emit the component with an empty `version` field and a `mikebom:requirement-range` property holding the original line.
- **Legacy `package-lock.json` v1**: old-format lockfiles (npm ≤5) use a different structure than v2/v3 and ship with a `"lockfileVersion": 1` field. The scanner MUST detect that field and refuse to parse the file, exiting non-zero with a clear message: `"package-lock.json v1 not supported; regenerate with npm ≥7"`. No components are emitted from the v1 file; the scan does not silently fall through to a `node_modules/` walk.
- **Corrupt `METADATA` with non-UTF-8 author name**: the scanner MUST decode leniently (lossy UTF-8 fallback) and still extract the Name / Version / License fields, consistent with how the existing dpkg copyright parser handles the same issue.

## Requirements *(mandatory)*

### Functional Requirements

#### Python — discovery and parsing

- **FR-001**: The scanner MUST walk every `site-packages/*.dist-info/` directory under the scanned root and emit one component per directory. Default locations checked: `<root>/.venv/`, `<root>/venv/`, `<root>/**/lib/python*/site-packages/` (bounded walk depth), and in image mode `/usr/lib/python*/site-packages/`, `/usr/local/lib/python*/site-packages/`, and any `site-packages/` under `<image-WORKDIR>/`.
- **FR-002**: The scanner MUST parse `METADATA` files as RFC-822-style stanzas, extracting: `Name`, `Version`, `License`, `License-Expression` (PEP 639), `Classifier: License ::` entries, `Requires-Dist:`, `Author` / `Author-email`, and `Home-page` / `Project-URL`.
- **FR-003**: The scanner MUST parse `poetry.lock` TOML files and `Pipfile.lock` JSON files when no venv is available, extracting name / version / hashes / dev-flag per package.
- **FR-003a**: For Poetry (`poetry.lock` `[[package]] category = "dev"`) and Pipfile (`Pipfile.lock` `develop:` section), the scanner MUST exclude dev-flagged packages by default and include them only when `--include-dev` is set, matching the npm behaviour in FR-008. Venv `.dist-info` scans and `requirements.txt` scans MUST ignore the flag (those sources do not carry a dev/prod distinction).
- **FR-004**: The scanner MUST parse `requirements.txt` (and any `*.txt` matching pip's convention when the user explicitly points at one) as a fallback source, tolerating `==`, `>=`, `~=`, `!=`, and URL-based references.
- **FR-005**: The scanner MUST NOT parse `pyproject.toml` `[project.dependencies]` as a component source (those are build specifications, not resolved versions); it MAY read that file only for metadata about the project being scanned (the target name).

#### npm — discovery and parsing

- **FR-006**: The scanner MUST prefer `package-lock.json` (v2 / v3) or `pnpm-lock.yaml` as the authoritative source when present in the scanned root. When a `package-lock.json` declares `"lockfileVersion": 1`, the scanner MUST refuse to parse it and exit non-zero with the message `"package-lock.json v1 not supported; regenerate with npm ≥7"`; no fallback to a `node_modules/` walk is performed for that project.
- **FR-007**: The scanner MUST fall back to walking `node_modules/<scope>/<pkg>/package.json` when no lockfile is present, correctly handling scoped package names (`@scope/name`).
- **FR-007a**: When neither a lockfile NOR a populated `node_modules/` is present but a root `package.json` exists, the scanner MUST parse that `package.json`'s `dependencies` and (when `--include-dev` is set) `devDependencies` fields as a last-resort fallback source at confidence 0.70. Each declared dep becomes a component with an empty `version` field and a `mikebom:requirement-range` property holding the range spec verbatim (e.g. `^1.2.3`, `~2.0`). The output shape (property names, selector coverage) MUST align with how trivy / syft / scalibr surface the same "uninstalled `package.json` only" state; cross-tool comparison is part of the plan-phase research.
- **FR-008**: The scanner MUST exclude `devDependencies`, optional `peerDependencies`, and `optionalDependencies` by default for npm. A global `--include-dev` flag MUST be available to opt in. The same flag MUST also control exclusion of Poetry dev-groups and Pipfile `dev-packages` for Python lockfiles (see FR-003a). When `--include-dev` is set, all dev-flagged components — from any ecosystem that carries the distinction — MUST carry a `mikebom:dev-dependency = true` property so downstream consumers can filter them back out if desired.
- **FR-009**: The scanner MUST extract content hashes from the lockfile `integrity:` field on every entry that provides one, preserving the hash's declared algorithm (SHA-512 is typical for modern lockfiles).
- **FR-010**: In image-scan mode, the scanner MUST walk a standard set of `node_modules/` locations (`/usr/lib/node_modules/`, `/usr/local/lib/node_modules/`, `/opt/app/node_modules/`) plus perform a bounded-depth (≤8 levels) recursive discovery to catch non-standard layouts. The scanner SHOULD additionally read the image's Docker config (`config.Cmd` / `config.WorkingDir`) when available to add application-specific `node_modules/` locations to the walk set; WORKDIR-driven discovery is a SHOULD (not a MUST) this milestone because the bounded recursive walk already catches the same packages for >95% of real images. A follow-up milestone formally introduces WORKDIR reading as a MUST.

#### PURL + shared conventions

- **FR-011**: Every emitted Python component MUST carry a canonical PURL of the form `pkg:pypi/<canonical-name>@<version>` where `<canonical-name>` is the PyPI name as declared (hyphens preserved), independent of the normalised form pip uses on-disk.
- **FR-012**: Every emitted npm component MUST carry a canonical PURL: unscoped as `pkg:npm/<name>@<version>`, scoped as `pkg:npm/%40<scope>/<name>@<version>` with the `@` in the scope percent-encoded.
- **FR-013**: Both ecosystems MUST route PURL construction through the existing segment encoder so a `+` in a name or version is percent-encoded consistently with the reference implementation.
- **FR-014**: Both ecosystems MUST participate in the existing CPE synthesis pass; each new component MUST produce at least one CPE candidate per the existing ecosystem-specific rules.
- **FR-015**: Both ecosystems MUST participate in the existing deps.dev enrichment pass (both are already in the ecosystem-to-deps.dev-system mapping). No new infrastructure required; each new component type MUST verify the enrichment path works end-to-end.

#### Dependency tree

- **FR-016**: For every Python component, the scanner MUST emit a `Relationship` of type `DependsOn` for each name listed in the `METADATA::Requires-Dist:` field that resolves to another component observed in the same scan. Unsatisfied requirements (no matching observed component) MUST be dropped silently from the edge list.
- **FR-017**: For every npm component, the scanner MUST emit a `Relationship` for each entry in the lockfile's `dependencies:` / nested tree (prod only by default; includes dev when `--include-dev` is set).
- **FR-018**: Relationship provenance MUST identify the source: `dist-info-requires-dist` for Python, `npm-lockfile` or `npm-package-json` for npm.

#### Compositions + confidence

- **FR-019**: When the scanner reads a Python venv's full `site-packages` directory, it MUST record `pypi` in the scan result's list of ecosystems read in full, producing a complete-aggregate composition record for the Python subset of the BOM.
- **FR-020**: When the scanner reads an npm lockfile in full, it MUST record `npm` in the scan result's list of ecosystems read in full, producing a complete-aggregate composition record for the npm subset of the BOM.
- **FR-021**: Confidence values: `0.85` for manifest-analysis components (venv dist-info / lockfile); `0.70` for filename / requirements-range-only components.

#### SBOM-tier classification (traceability ladder)

- **FR-021a**: Every emitted component MUST carry a `mikebom:sbom-tier` property declaring which tier of mikebom's traceability ladder produced it. Permitted values and source-to-tier mapping for this milestone:
    - `build` — eBPF trace-mode components (not touched by this milestone, documented for completeness).
    - `deployed` — installed-package-database readers (existing dpkg, existing apk, new Python `dist-info` venv walk, new npm `node_modules/` walk). The component is installed on the scanned filesystem.
    - `analyzed` — artefact-file matches via filename + content-hash (existing `.deb`, `.crate` pickups; new `.whl`, `.tgz` pickups). The artefact is present on disk but installation is unconfirmed.
    - `source` — lockfile-derived components that aren't installed on the scanned filesystem (poetry.lock, Pipfile.lock, package-lock.json, pnpm-lock.yaml). Pre-build locked resolution.
    - `design` — unlocked manifest-derived components (requirements.txt range specs, root `package.json` fallback per FR-007a). Intent declaration, not resolved.
- **FR-021b**: The CycloneDX envelope's `metadata.lifecycles[]` array (CycloneDX 1.5+ native field) MUST be populated with the union of tier values observed across the emitted components, mapped to their CycloneDX-native lifecycle phases: `build → build`, `deployed → operations`, `analyzed → post-build`, `source → pre-build`, `design → design`. This lets a consumer filter or score the document at the envelope level without walking every component.
- **FR-021c**: Existing deb and apk readers MUST be retro-fitted in this milestone to emit `mikebom:sbom-tier = "deployed"` on every component they produce, so no component in any scan ships without the property. No other behaviour of the existing readers changes.

#### Offline mode + enrichment

- **FR-022**: The existing global `--offline` flag MUST suppress deps.dev calls for Python and npm components; local-only extraction (licenses from METADATA / `package.json`, hashes from lockfile integrity) MUST still succeed.
- **FR-023**: When not in offline mode, deps.dev enrichment MUST augment Python and npm components with SPDX licenses the local parser missed, without overwriting existing local-derived licenses.

#### Observability

- **FR-024**: When the scanner skips a detected Python project (e.g. no venv + no lockfile + no requirements.txt), it MUST log an explanatory message at info level so operators can understand the empty output.
- **FR-025**: Any parser failure MUST NOT crash the scan (same convention as existing ecosystems) — failures log at debug level and the scan continues.

### Key Entities

- **Python component source**: a `<name>-<version>.dist-info/` directory OR a row in a `poetry.lock` / `Pipfile.lock` OR a `requirements.txt` line. Carries name, version, license expression, a list of required packages, and the file path the entry was read from.
- **npm component source**: an entry in `package-lock.json` / `pnpm-lock.yaml` OR a `node_modules/<pkg>/package.json` file. Carries name, version, integrity hash, dev-flag, and a list of dependencies.
- **Dev/prod scope indicator**: a boolean on each npm component and each Pipfile/Poetry Python component; `None` for pip dist-info entries and `requirements.txt` lines (those don't carry the distinction).
- **Scan result (extension)**: the existing scan-result record gains `pypi` and `npm` as values recorded in its "ecosystems read in full" list when their respective authoritative sources (venv, lockfile) are read in full.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A filesystem scan of a 50-package Python venv produces ≥90% of the components that a competitive comparison scanner (trivy) reports on the same directory, with every Python PURL reference-implementation conformant.
- **SC-002**: An image scan of a Python application container produces both OS-level (deb/apk) components AND Python site-packages components in a single SBOM, with a separate complete-aggregate composition record for each ecosystem that was read in full.
- **SC-003**: An npm scan with `package-lock.json` produces prod-only components by default (no dev); `--include-dev` toggles dev inclusion, and dev components are distinguishable via a property so consumers can filter downstream.
- **SC-004**: Every Python and npm component carries a canonical PURL that round-trips through the packageurl reference implementation byte-for-byte (100% conformance on a representative corpus of ≥100 components across both ecosystems).
- **SC-005**: ≥95% of Python components emit a populated `licenses[]` field (via local `METADATA` + PEP 639 + Classifier fallback; deps.dev fills remaining gaps in online mode).
- **SC-006**: ≥80% of Python and npm components carry at least one `dependsOn` edge in the SBOM's `dependencies[]` section, matching or exceeding a competitive comparison scanner's edge density on the same input.
- **SC-007**: `mikebom sbom scan --path .` completes in under 10 seconds on a 500-package Python venv or 1000-package `node_modules/` tree (excluding network latency for deps.dev enrichment).
- **SC-008**: `--offline` mode produces the same component set as the online run, differing only in the absence of deps.dev-sourced licenses and evidence-tool references.
- **SC-009**: Zero regressions on existing ecosystem coverage (debian, alpine, ubuntu, cargo filename) — the full existing test suite stays green and real-image e2e scans produce byte-identical SBOMs modulo added ecosystems.
- **SC-010**: New automated-test coverage adds ≥30 tests exercising the Python and npm parsing paths, at roughly the density the existing deb and apk readers have today.

## Assumptions

- Existing PURL, CPE, and enrichment infrastructure is reused unchanged. Specifically: the PURL segment encoder used for reference-implementation-canonical `+` encoding, the CPE synthesizer's existing per-ecosystem vendor candidates (which already include `pypi` and `npm`), and the deps.dev enrichment pass — all three already support both new ecosystems structurally; the milestone adds the readers that feed them data.
- The existing scan pipeline shape is reused. New readers emit package-db-entry-shaped records that flow through the same dedup + CPE-synthesis + composition + deps.dev-enrichment pipeline as deb/apk today. No orchestration rewrite.
- `--offline` semantics are already shipped and apply transparently to any new enrichment sources; each new ecosystem's implementation inherits the behaviour for free.
- PEP 503 name normalisation (lowercase, `_`/`-` collapse) is the PyPI canonical name rule for on-disk directory naming; the PURL carries the declared (non-normalised) name for round-trip correctness with the packageurl reference implementation.
- PEP 639 `License-Expression` is the forward-compatible source of SPDX expressions; the scanner treats it as the highest-priority license field when present, falling back to `License:` and `Classifier:` entries.
- npm `package-lock.json` v2/v3 is the only supported lockfile version. v1 lockfiles are refused with an actionable error instructing the user to regenerate with npm ≥7 (default since 2020). `pnpm-lock.yaml` v6/v7/v8 are supported in parallel.
- For the `package.json`-only fallback (FR-007a), the plan phase MUST include a short research pass comparing trivy, syft, and scalibr outputs on an identical "uninstalled Node.js project" directory. Align property names, range-spec surfacing, and `peerDependencies` / `optionalDependencies` treatment with whichever tool's shape is closest to the packageurl reference-impl conventions, so a downstream merger comparing SBOMs from multiple tools sees the same identity columns.
- No network calls from the scanner itself for Python / npm data. Authoritative metadata comes from local files only; deps.dev remains the single outbound enrichment source (and is gated by `--offline`).
- Dev-dep scoping is a global concept controlled by one flag (`--include-dev`). It applies to every ecosystem that carries the distinction: npm `devDependencies`, Poetry `category = "dev"` packages, and Pipfile `develop:` packages. Venv `.dist-info` scans and `requirements.txt` scans ignore the flag because those sources do not carry a dev/prod marker — everything they contain is treated as prod.
- Out of scope this round: binary hashes over installed Python C-extensions (would require walking `RECORD` files at a cost we'll pay later if asked); transitive resolution against PyPI/npm registry APIs (we resolve purely against what's observed in the scan); npm workspaces (explicitly deferred).
- Platform expectations: the scan runs on any OS; the scanned root may be a Linux / macOS / Windows-style tree. The scanner uses paths relative to the root so mixed-separator layouts survive.
- The existing `sbom scan` CLI surface is extended, not replaced: `--path`, `--image`, `--output`, `--format cyclonedx-json`, `--no-hashes`, `--no-package-db`, `--no-deep-hash`, `--offline`, `--json` all continue to apply. One new flag, `--include-dev`, joins the existing set.
