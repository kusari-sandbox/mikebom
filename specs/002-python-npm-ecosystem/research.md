# Phase 0 Research — Python + npm Ecosystem Support

Status decisions, rationales, and rejected alternatives for the design questions surfaced in `spec.md` and `plan.md`. This document closes out every "NEEDS CLARIFICATION" slot and underpins the entities in `data-model.md` and the contracts in `contracts/`.

## R1 — Constitutional scope of scan-mode lockfile reads

**Decision**: Scan mode (`FilesystemScan` + `ContainerImageScan` generation contexts) MAY read Python and npm lockfiles as authoritative discovery sources. Trace mode (`BuildTimeTrace`) MUST NOT.

**Rationale**: Constitution Principle II and Strict Boundary #1 forbid *static lockfile parsing as a dependency-discovery source*. The v1.2.0 amendment clarified the boundary applies to eBPF-traced builds: a component appearing in a lockfile but NOT observed in an eBPF trace must not enter a trace-mode SBOM. Scan mode is a separate code path with its own sanctioned `GenerationContext`, established in milestone 001; the scanned filesystem (including its lockfiles and installed-package databases) IS the observation source for that mode. The deb + apk readers already consume `/var/lib/dpkg/status` and `/lib/apk/db/installed` under this interpretation. Extending the same pattern to Python venvs / lockfiles and npm lockfiles / `node_modules/` is consistent with the shipped precedent.

**Distinguishing markers in output**: Every SBOM emitted from this milestone's new code paths carries `metadata.properties[] → mikebom:generation-context` with value `filesystem-scan` or `container-image-scan`. Trace-mode SBOMs have `build-time-trace`. Confidence values diverge too: 0.95 for trace, 0.85 for manifest-analysis (lockfile / dist-info / package-lock), 0.70 for filename fallback.

**Alternatives considered**:
- *Refuse scan-mode lockfile reads and demand a trace-mode build*: unworkable. Users scan cold filesystems (uploaded images, cloned repos) where no build is available to trace. Milestone 001 already rejected this stance.
- *Annotate lockfile-sourced components as `inferred = true` and downgrade confidence further*: over-engineered. The `GenerationContext` + confidence tier already carries this signal; adding a third axis duplicates information.

---

## R2 — Python `METADATA` field parsing rules

**Decision**: Parse `dist-info/METADATA` files as RFC-822-style stanzas with continuation lines (leading whitespace continues the previous key). Extract the fields listed in FR-002 in this precedence order for license:
1. `License-Expression:` (PEP 639; canonical SPDX when present).
2. `License:` (free-form; fall back to shorthand normaliser used for deb copyright files).
3. `Classifier: License :: ...` entries (map the trove classifier to SPDX via a small lookup table — 20 entries covers >95% of real-world classifiers).

For `Requires-Dist:`, parse the PEP 508 requirement specifier (`name [extras] (version-spec) ; marker`) and emit only the bare `name` for dependency-tree edges. Environment markers (`; python_version < "3.10"`) are respected: markers evaluating to false in the scanner's current environment suppress the edge.

**Rationale**: The license precedence list matches PEP 639's forward-compatible intent (Expression is the new canonical form) while keeping fallbacks for packages that ship only legacy fields. Emitting bare names for dep-tree edges matches `dpkg.rs::parse_depends` behaviour — consumers of the graph don't need version constraints, they need identity keys to cross-reference.

**Alternatives considered**:
- *Require `License-Expression:`, skip packages that don't have it*: would drop ~70% of existing Python packages. Too aggressive.
- *Store the full PEP 508 requirement string as edge metadata*: useful but out of scope — the existing `Relationship` shape carries `from` / `to` / `type` and no version qualifier.

---

## R3 — `poetry.lock` TOML schema (v1 vs v2)

**Decision**: Support both `poetry.lock` v1 (`lock-version = "1.1"` / `"1.2"`) and v2 (`lock-version = "2.0"`). Both structures put per-package entries under `[[package]]` with `name`, `version`, and `category = "main" | "dev"` (v1) or `[package.dependencies.groups]` metadata (v2). Parse both into a common `PoetryLockEntry` struct (see `data-model.md`). The lock version is read from the top-level `[metadata] lock-version` field for parser dispatch.

**Rationale**: Poetry 1.5+ defaults to v2, Poetry ≤1.4 ships v1. Both are live in the wild. The dev-flag lookup is straightforward in both formats; the only material difference is where the flag lives.

**Alternatives considered**:
- *Support v2 only, refuse v1 like `package-lock.json` v1*: would be inconsistent with the user's clarification answer, which only refused npm v1. Poetry v1 is the default in many older LTS environments (Ubuntu 22.04 ships Poetry 1.2.x).
- *Ignore the lock-version and heuristically extract `category` everywhere*: works on all files in practice but can't catch malformed inputs. Prefer explicit version dispatch.

---

## R4 — `package-lock.json` v2/v3 nested structure

**Decision**: Parse `package-lock.json` via the `"packages"` top-level object (present in v2 and v3; v1 uses the older `"dependencies"` tree which is refused per Q1 clarification). Each key in `packages` is a path like `node_modules/foo` or `node_modules/@scope/bar/node_modules/baz`; the first-segment `node_modules/<name>` path is prod unless the entry's `dev: true` flag is set (propagated through transitive trees). `integrity` is a lockfile-native SRI string (`sha512-abc...=` base64); preserve the algorithm hint.

**Rationale**: The v2/v3 format is stable and documented. The `"packages"` object carries everything the scanner needs — version, integrity, dev flag, resolved URL — without requiring a recursive descent through `"dependencies"`. The `dev: true` flag handles the edge case where a prod-used transitive dep gets marked dev because a dev-only package pulls it in.

**Alternatives considered**:
- *Parse the older `"dependencies"` tree*: required for v1 compatibility; rejected by Q1 clarification (explicit refusal).
- *Re-resolve dev/prod by walking from the project's own `package.json` dependencies*: loses fidelity when the lockfile has already resolved the transitive classification. Trust the lockfile.

---

## R5 — `pnpm-lock.yaml` v6 / v7 / v8 schema

**Decision**: Support v6, v7, and v8. Dispatch on the top-level `lockfileVersion: "6.0"` / `"7.0"` / `"9.0"` (v8 bumped internal format to 9). All three share the `importers` + `packages` structure; v8/v9 uses `snapshots` for resolved metadata while `packages` holds the registry-level info. Parse both sections and join on the key.

**Rationale**: pnpm's three versions cover every pnpm release from 2022-04 onward (v6). Older pnpm is a long tail — document as best-effort, exit non-zero with actionable message if we detect `lockfileVersion < 6`.

**Alternatives considered**:
- *v9 only*: too aggressive; v6/v7 are still the default on LTS systems.
- *Support all versions back to v5*: v5 used a significantly different top-level shape. Out of scope for this milestone; follow-up TODO.

---

## R6 — Per-tool output comparison for the `package.json`-only fallback (FR-007a)

**Decision**: Align our fallback output shape with trivy's, as it is the closest to the packageurl-python reference-implementation conventions. Specifically:
- Emit one component per entry in `dependencies` (and in `devDependencies` when `--include-dev` is set).
- Leave `version` empty.
- Include a CycloneDX `properties[]` entry `mikebom:requirement-range = "<original range>"` (e.g. `^1.2.3`, `~2.0.0`, `>=1.0 <2`).
- For `--include-dev` components, add the `mikebom:dev-dependency = true` property in addition to the range.
- Do NOT emit `peerDependencies` or `optionalDependencies` in the fallback tier (out of scope; follow-up TODO if a user asks).

**Rationale (tool comparison)**:

| Tool | "uninstalled `package.json`" behavior |
|------|--------------------------------------|
| trivy | Emits one `package` per `dependencies` entry with the range spec in a `SrcVersion` / `SrcEpoch` field set, empty resolved `Version`. Skips `devDependencies` by default. |
| syft  | Refuses to catalog a `package.json` without a lockfile — emits zero components from that project. |
| scalibr | Parses `dependencies` + `devDependencies` together into a flat list, no dev/prod distinction. Uses pnpm conventions for ranges. |

trivy's shape is closest to our existing deb / apk pattern (empty version + property carrying the extra info) and preserves the dev/prod distinction we already commit to via Q2. Syft's "refuse" behavior is too aggressive for our three-tier-authority model. Scalibr's flatten-everything behavior loses information.

**Alternatives considered**:
- *Scan `package.json` peerDependencies + optionalDependencies too*: deferred. Those are rarely what consumers care about; add later if a user requests.
- *Match syft's "refuse" behavior and emit empty*: rejected by Q4 clarification (user chose A — parse the fallback).

---

## R7 — Python canonical name normalisation

**Decision**: PURLs carry the **declared** Python package name (`METADATA::Name:` field, hyphens preserved, case preserved). PEP 503 name normalisation (lowercase + collapse `[-_.]+` to a single `-`) is used ONLY for matching: e.g., when resolving `Requires-Dist: Zope.Interface` against the observed set, normalise both sides before compare. The PURL emits the declared form (`pkg:pypi/zope.interface@...`) because that's what round-trips through the packageurl reference implementation.

**Rationale**: packageurl-python's canonical output for pypi PURLs preserves the `.` and mixed case of the declared name. Normalising to PEP 503 form in the PURL would cause round-trip divergence (we'd emit `pkg:pypi/zope-interface@...` which packageurl-python then re-serialises as-is, but other tools that compare against packageurl-python output would see mismatched identities).

**Alternatives considered**:
- *Use PEP 503 form in the PURL*: most other scanners do this. But we committed to reference-impl conformance in prior rounds; the packageurl reference impl preserves the declared form.
- *Emit both forms*: introduces ambiguity; no downstream consumer expects this.

---

## R8 — Dev-flag propagation across sources

**Decision**: `PackageDbEntry` gets a new optional `is_dev: Option<bool>` field:
- `Some(false)` — observed as a prod dep (npm root `dependencies`, poetry/Pipfile non-dev group).
- `Some(true)` — observed as a dev dep.
- `None` — source doesn't carry the distinction (venv `.dist-info` entries, `requirements.txt` lines).

The dedup path (`resolve/deduplicator.rs`) treats `Some(false)` as winning over `Some(true)` when the same PURL appears in both groups (a prod pull shadows any dev-only pull). `None` merges with either without changing the flag. The CycloneDX emitter surfaces `mikebom:dev-dependency = true` only when the final, deduped entry has `is_dev = Some(true)`.

**Rationale**: One lockfile can list a package as dev and another as prod (common in monorepos with shared `node_modules/`). The "prod wins" rule matches npm's own semantic — a prod dep is never really "dev-only". Venv / requirements entries with `None` don't pollute the flag.

**Alternatives considered**:
- *Default `is_dev = false` when unknown*: would silently treat venv entries as explicit prod, which is misleading for consumers who want to know "which ones did you have no dev/prod info for".
- *Emit both forms (prod and dev) as separate components when sources disagree*: would double-count components in the SBOM and break dedup.

---

## R9 — Crate choices for new dependencies

**Decision**:
- `toml 0.8` — for `poetry.lock` + `pyproject.toml` target-name read. Pure Rust, MIT/Apache-2.0, widely used (cargo's own format).
- `serde_yaml 0.9` — for `pnpm-lock.yaml`. Pure Rust, MIT/Apache-2.0, maintained by dtolnay. `serde_yaml_ng` (a fork) is newer but less battle-tested; defer.
- `serde_json` — already a workspace dep; reused for `package-lock.json` + `Pipfile.lock`.
- Range parsing (semver, pep508) — NONE. We preserve range strings verbatim and never evaluate them. No semver crate needed.

**Rationale**: The three crates cover the full new surface with no new foreign-function boundary. Preserving ranges as strings keeps the tool's scope tight; range evaluation is a downstream concern (trivy's vulnerability matcher evaluates ranges; mikebom's attestation-first model does not).

**Alternatives considered**:
- *Add the `semver` / `pep508_rs` / `nodejs-semver` crates to normalize or compare ranges*: mission creep. Range comparison belongs in a vulnerability scanner, not an SBOM generator.
- *Write a hand-rolled TOML/YAML parser to avoid the dep*: no material safety/performance win for the scope of what we parse (small lockfiles, well-structured key/value shapes).

---

## R10 — Image-mode Python and npm walk paths

**Decision**:

For Python (image mode):
- `<rootfs>/usr/lib/python3*/dist-packages/` (Debian/Ubuntu system Python)
- `<rootfs>/usr/lib/python3*/site-packages/`
- `<rootfs>/usr/local/lib/python3*/site-packages/`
- `<rootfs>/opt/app/.venv/lib/python3*/site-packages/` (common app venv)
- Any `site-packages/` discovered under the image's declared `WORKDIR` (read from the image config JSON — support added in a follow-up TODO, the milestone-001 extractor already exposes the rootfs root; this milestone falls back to a bounded recursive walk for `site-packages` when no WORKDIR hint is available).

For npm (image mode):
- `<rootfs>/usr/lib/node_modules/` (global install)
- `<rootfs>/usr/local/lib/node_modules/`
- `<rootfs>/opt/app/node_modules/` (common app location)
- Any `node_modules/` under `<image-WORKDIR>/` when available.

**Rationale**: These cover the standard install locations for the top-5 base images (`python:3.N-slim`, `python:3.N`, `node:N-alpine`, `node:N`, distroless). Bounded-depth recursive walk catches non-standard layouts at a small perf cost (capped per-directory depth at 8 levels below rootfs).

**Alternatives considered**:
- *Walk the entire rootfs unbounded*: too slow on large images (minutes for a multi-GB Node image).
- *Require explicit paths via CLI flag*: violates principle of least surprise; discovered locations should Just Work.

---

## R11 — Observability requirements mapping

**Decision**: Follow the convention established by dpkg/apk in milestone 001:
- `tracing::info!(pkg=%name, "…")` — human-visible events (scan complete, ecosystem detected).
- `tracing::debug!(pkg=%name, error=%err, "…")` — parser failures, skipped entries, drift notes.
- `tracing::trace!(…)` — per-file internals (parse steps).

The FR-024 info-level log for "Python project detected but no venv/lockfile/requirements" uses a stable message string: `"python project detected but no venv, lockfile, or requirements.txt — skipping"`. The FR-006 v1-lockfile refusal prints to stderr AND emits `tracing::error!`.

**Rationale**: Existing convention; no new observability story needed.

---

## R12 — Testing strategy

**Decision**:

- **Unit tests** (per SC-010, ≥30 tests): colocated with each new module. Cover each parser (METADATA, poetry.lock, Pipfile.lock, requirements.txt, package-lock.json v2, v3, pnpm-lock v6/7/8, node_modules walk, package.json fallback), the PURL canonicalisation for each ecosystem, the dev/prod flag round-trip, the v1-refusal error path, the Python / npm drift rules, and the range-version property emission.
- **Integration tests**: scan a small real venv + a real `node_modules/` tree shipped as a checked-in fixture. Assert SBOM component count, PURL conformance (round-trip through the packageurl crate's serializer), license coverage percentage.
- **E2E (manual, not CI)**: scan `python:3.12-slim` + a FastAPI demo image + `node:20-alpine` + an Express demo image. Compare component counts against trivy output; compute SC-001 and SC-006 ratios.

**Rationale**: Mirrors the test approach from milestones 001-conformance rounds. All new tests are unit-level by default (Principle VII); integration tests consume fixtures rather than network / registry access.

---

## R13 — Traceability ladder (mikebom's 4+1 SBOM-type model)

**Decision**: Adopt a five-tier traceability ladder as mikebom's canonical framing for "how was this component observed?". Every component emitted by any mode, by any ecosystem, carries a `mikebom:sbom-tier` property with one of the five values below, and the envelope declares the union via CycloneDX 1.5+ `metadata.lifecycles[]`.

| Tier | Source type | `mikebom:sbom-tier` | CycloneDX `lifecycles[].phase` | Confidence today | SBOM-type (industry term) |
|------|-------------|---------------------|--------------------------------|------------------|---------------------------|
| 1 | eBPF trace of a live build | `build` | `build` | 0.95 | Build SBOM |
| 2a | Installed-package-DB entry (dpkg, apk, Python dist-info, npm `node_modules/`) | `deployed` | `operations` | 0.85 | Deployed / Operations SBOM |
| 2b | Artefact file on disk with content hash (`.deb`, `.whl`, `.crate`, `.tgz` cache) | `analyzed` | `post-build` | 0.70 | Analyzed SBOM |
| 3 | Lockfile-derived (poetry.lock, Pipfile.lock, package-lock.json, pnpm-lock.yaml) NOT also installed | `source` | `pre-build` | 0.85 | Source SBOM |
| 4 | Manifest-only (requirements.txt ranged, root package.json fallback) | `design` | `design` | 0.70 | Design SBOM |

**Why this matters**: Downstream consumers (vulnerability matchers, attestation validators, procurement reviewers) need to answer "was this component actually installed and running, or is it a declared intent?" in a single query. Without a categorical tier label, the numeric confidence (0.85/0.70) conflates distinct lifecycle states — an installed dpkg entry and a committed `poetry.lock` entry both read 0.85 today despite representing fundamentally different claims.

**Why we keep both axes**: The numeric confidence (`evidence.identity.confidence`) answers "how sure are we about this component's identity?". The categorical tier answers "at what point in the lifecycle did we observe it?". Both are independently useful and neither subsumes the other. A lockfile with an integrity hash is high-confidence identity but pre-build lifecycle; a filename-matched `.deb` with a SHA-256 is lower-confidence identity but post-build lifecycle.

**Scope of the decision for this milestone**:
- Emit the `mikebom:sbom-tier` property on every new Python + npm component per the source-to-tier mapping above.
- Retrofit the existing deb + apk readers to emit `deployed` — a one-line change per reader and a test update — so no scan output has an unlabeled component after this milestone ships.
- Populate `metadata.lifecycles[]` at the envelope level with the union of observed tiers for the scan.
- Numeric confidence values are NOT changed this milestone. The 0.85 conflation between `deployed` and `source` is documented as acceptable — the new `mikebom:sbom-tier` property is the precise signal; confidence is the approximate one.

**Alternatives considered**:
- *Replace numeric confidence with the categorical tier*: would break consumers that depend on the 0.95 / 0.85 / 0.70 ladder shipped in milestone 001. Also loses the fine-grained "how sure about identity" axis.
- *Defer the categorical label to a later cross-ecosystem milestone*: creates a window where Python + npm ship without the label and later milestones have to back-fill the retrofit. Cheaper to land the property + retrofit in one place (this milestone) since we're already touching the component-building path.
- *Emit only the envelope-level `metadata.lifecycles[]` without per-component tags*: loses the ability to filter by tier within a single SBOM. Rejected — mixed-tier outputs (e.g. installed dpkg + unlocked package.json fallback in one scan) need per-component granularity.

**Follow-up milestones**:
- Cargo/go/RPM/maven/Ruby ecosystems (roadmap milestones 003 and 005) inherit this mapping without re-litigation — each new reader declares its tier at `PackageDbEntry` construction time.
- A possible future milestone reviews the numeric-confidence ladder alongside the categorical tier and considers either (a) collapsing confidence into the tier system, or (b) tightening the 0.85 value into 0.85 (deployed) / 0.80 (source) / 0.70 (design / analyzed-by-filename). Deferred until real consumer feedback points at the conflation as an actual pain.

---

## Open questions, deferred to follow-up TODOs

None that block this milestone. Follow-ups noted in the plan's Complexity Tracking and in individual sections above:
- npm `peerDependencies` + `optionalDependencies` in the `package.json`-only fallback (R6).
- pnpm lockfile `< v6` best-effort support (R5).
- Image-mode Python / npm walks using `config.WorkingDir` from the image config JSON (R10) — the existing extractor's API could expose this without much work; track as a small follow-up.
- PEP 639 classifier fallback lookup table tuning (R2) — the 20-entry table should cover >95%, but real-world scans will surface missing mappings. Log-and-continue each miss; iterate the table as the gaps accumulate.
