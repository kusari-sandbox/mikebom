# Phase 0 Research: Holistic Cross-Format Output Parity

**Branch**: `013-format-parity-enforcement` | **Date**: 2026-04-25 | **Plan**: [plan.md](plan.md)

## R1 — Diagnostic CLI surface: subcommand `mikebom sbom parity-check`

**Decision**: A subcommand on the existing `sbom` noun — `mikebom sbom parity-check --scan-dir <dir>`. Flags: `--scan-dir` (required, path to directory containing emitted format outputs), `--format` (optional, output shape: `table` default, `json` for machine-readable). Exit codes: `0` = all datums accounted for, `1` = at least one universal-parity datum missing from at least one format (gap detected), `2` = input error (missing files, unreadable directory).

**Rationale**:

- `sbom scan` produces outputs; `sbom parity-check` inspects already-produced outputs. Keeping them separate nouns — verbs on the same noun — keeps each command's help text tight and each command's flags focused on its own job.
- `sbom scan --parity-report` would conflate "run a scan" with "inspect cross-format coverage" — the diagnostic is useful against ANY three-format scan output (including outputs from a previous mikebom run, or someone else's run), not just the scan that just happened.
- Pattern matches the project's existing `sbom scan` subcommand pattern; same clap derive-style parsing already in place.
- Exit codes follow standard CLI convention (0 pass / 1 gap / 2 misuse) — matches the `sbomqs` tool's behavior for a similar diagnostic.

**Alternatives considered**:

- *`--parity-report` flag on `sbom scan`*: rejected — conflates two concerns.
- *Separate top-level command `mikebom parity`*: rejected — the functionality is scoped to SBOM outputs, which live under the `sbom` noun.
- *Always-on parity check as part of `sbom scan`*: rejected — turns every scan into a triple-format emit even when the user only requested one. Scope creep; the diagnostic is an opt-in inspection, not a pipeline gate.

## R2 — Container-image fixture choice: reuse `build_benchmark_fixture`

**Decision**: Reuse the synthetic docker-save tarball built by `mikebom-cli/tests/dual_format_perf.rs::build_benchmark_fixture` (500 deb packages + 1500 npm packages, ~6 MB of package.json content). No new fixture code — promote the helper to `pub(crate)` and import it from `holistic_parity.rs`. The same tarball is already used by `triple_format_perf.rs`, so the promotion is a net simplification (three test files sharing one fixture-builder instead of each open-coding their own).

**Rationale**:

- Gives scale-realism coverage (~2000 components — similar order of magnitude to real container images like `debian:12-slim` / `alpine:3.19`) without checking a 60-MB image tarball into git.
- Exercises both deb and npm ecosystems in one fixture, which is the closest thing to a "polyglot" scan in the standard matrix. CPE candidates, license expressions, and supplier metadata are all produced by the deb path; component counts exercise the npm path's scale.
- Builds deterministically from Rust code — no cross-platform tarball-generation issues, no external download dependencies.

**Alternatives considered**:

- *Commit a real `debian:12-slim.tar` fixture*: rejected — the project's `.gitignore` and Cargo workspace don't track large binary fixtures; the existing perf-test pattern of "build synthetic from code" is the established convention.
- *Add a NEW synthetic fixture specifically for parity testing*: rejected — duplicates existing code; the existing fixture already covers the scale-realism goal.
- *Skip the container-image fixture entirely, use 9-ecosystem-matrix only*: rejected for R2 but partially accepted in practice — the 9 ecosystem fixtures are the primary enforcement surface; the container-image fixture is a tenth test case for scale-realism coverage (spec FR-011).

## R3 — Extracting CycloneDX property/field names from mapping-doc rows

**Decision**: A three-pattern regex over the `CycloneDX 1.6 location` column of each catalog row, returning zero-or-more CDX property/field names per row.

```text
Pattern 1 — property rows (mikebom-namespaced):
  /components/{i}/properties[name="mikebom:<foo>"]
   → name="([^"]+)"
   → capture: mikebom:<foo>

Pattern 2 — direct JSON paths (native fields):
  /components/{i}/purl
  /components/{i}/version
   → last path segment after the final /
   → capture: purl, version (etc.)

Pattern 3 — relationship / document-level markers:
  /dependencies[]/dependsOn[]
  /metadata/component
   → whole-string identifier used as a catalog-row tag
```

**Rationale**:

- Covers every existing catalog-row shape in Sections A–H of `sbom-format-mapping.md` (45 rows total as of milestone 012).
- Rows with `omitted —` / `defer —` in the CDX column are skipped entirely for reverse-direction checks — the auto-discovery walk of emitted CDX output never sees these entries, so there's nothing to reconcile.
- The regex approach is fragile IF the mapping doc's row format changes; mitigation is a unit test in `tests/common/parity_catalog.rs` that asserts every current catalog row parses cleanly. When a new row shape is introduced, that unit test fires and the parser gets extended.

**Alternatives considered**:

- *JSON-path-based extraction with full JSONPath semantics*: rejected — overkill for a 45-row static catalog; adds a JSONPath-parser dependency (or hand-roll).
- *Rename mapping-doc columns to machine-readable format*: rejected — breaks the doc's human readability; the whole point of clarification Q1's decision was to leave the doc structure unchanged.
- *Sidecar file mapping row-ID → property-name*: rejected — second source of truth (same reason Q1 Option C was rejected).

## R4 — Extractor-table pattern for universal-parity assertions

**Decision**: A single Rust-side `static` table in `tests/common/parity_extractors.rs` keyed by catalog row id (`"A1"`, `"A2"`, …, `"H1"`). Each value is:

```rust
pub struct ParityExtractor {
    pub row_id: &'static str,
    pub label: &'static str,
    pub cdx: fn(&serde_json::Value) -> BTreeSet<String>,
    pub spdx23: fn(&serde_json::Value) -> BTreeSet<String>,
    pub spdx3: fn(&serde_json::Value) -> BTreeSet<String>,
    pub directional: Directionality,
}

pub enum Directionality {
    /// CDX, SPDX 2.3, and SPDX 3 sets must all be equal.
    SymmetricEqual,
    /// CDX set ⊆ SPDX 2.3 set ⊆ SPDX 3 set (or equivalent subset
    /// rule). The "container" format may carry additional values.
    /// Milestone 012's A12 CPE case: CDX primary only; SPDX 3 all
    /// fully-resolved candidates.
    CdxSubsetOfSpdx { spdx_can_exceed: bool },
}
```

**Rationale**:

- One Rust place where "how to check this datum in each format" lives. The catalog doc stays human-readable markdown; the table is executable spec.
- When a new catalog row is added to the mapping doc, a corresponding table entry is required — missing = universal parity test fails with a clear "no extractor registered for row Xn" setup error. This is the catalog-to-Rust contract.
- Symmetric-equal is the common case (~40 of ~45 rows). Directional is the exception (CPE-style). The enum makes the exception visible; a new contributor can't accidentally miss the directionality by writing a symmetric check for an asymmetric datum.
- The extractors return `BTreeSet<String>` so set operations (subset, equality, difference-for-error-messages) are one-liners and the test's failure output is human-readable.

**Alternatives considered**:

- *Trait-object based extractors with `Box<dyn Fn>`*: rejected — adds allocations, obscures the ordering; `fn` pointers are simpler + strictly-typed.
- *Macro-generated extractor definitions*: rejected — 45 entries is small enough that hand-written definitions are legible; macros obscure the set operations.
- *Inline extractors in `holistic_parity.rs` without a shared table*: rejected — US3's diagnostic needs the same extractors; duplicating breaks the "one source of truth for extraction logic" principle.
- *Extract-from-markdown at runtime (reflect the JSON path listed in the mapping doc's column)*: rejected — the JSON paths in the doc are human-readable references, not full JSONPath; some rows have multiple paths (e.g., A11 "downloadLocation and/or externalRefs"), and the test would still need hand-written extraction logic to normalize across them.

## R5 — Directional-containment rows (which rows need the exception)

**Decision**: Three catalog rows today require `Directionality::CdxSubsetOfSpdx { spdx_can_exceed: true }`:

| Row | Reason |
|-----|--------|
| A12 CPE | CDX `component.cpe` is single-valued (primary candidate); SPDX 2.3 + SPDX 3 emit all fully-resolved candidates (milestone 012 finding). |
| C19 `mikebom:cpe-candidates` | Asymmetric: CDX emits the full candidate list as a property; SPDX 3 splits fully-resolved into ExternalIdentifier + residual into Annotation. The set equality holds per-candidate but not per-list-cardinality. |
| B3 nested containment | CDX nests via `component.components[]`; SPDX 2.3 / SPDX 3 flatten. The set of (parent, child) pairs is equal; the *presentation* differs. This is more "nesting vs flattening" than "container exceeds contents," and could be handled by flattening CDX in the extractor. Going with explicit directional marker for now. |

Every other row uses `SymmetricEqual`. This keeps the common case simple; the exceptions are enumerated + reviewed.

**Rationale**: Same as milestone 012 R2 (CDX nests, SPDX flattens) and 012 R3 (CPE single-vs-multi). The directionality enum makes these asymmetric rows explicit rather than hiding the asymmetry in bespoke per-row code.

## R6 — Omitted rows and parity check interaction

**Decision**: `omitted — <reason>` / `defer — <reason>` in a format column causes the parity test to **skip** that format's extractor for that row. The other formats' extractors still run. The test's per-row report distinguishes "skipped by format-restriction" (informational, no fail) from "extractor returned empty on universal-parity row" (FAIL).

For the auto-discovery forward direction (emitter → catalog): the check only scans emitted CDX output's distinct property names, so an SPDX-3-only row (CDX column = `omitted —`) doesn't trigger the check at all — the property name was never emitted in CDX, so there's nothing to discover.

For the reverse direction (catalog → emitter): format-restricted rows are skipped for the restricted formats; universal-parity rows must have their CDX property present in at least one ecosystem's output.

**Rationale**: Preserves the spec clarification Q1 + Q2 semantics without special-case code paths. The parser's Classification enum carries the restriction markers; the test's core loop treats `SymmetricEqual` + Restricted on one format as "skip that format's extractor, assert parity on the remaining two."

---

**All NEEDS CLARIFICATION items resolved.** Phase 1 proceeds with `data-model.md` and `quickstart.md`.
